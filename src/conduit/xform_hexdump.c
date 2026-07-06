/*
 * xform_hexdump.c — Hexdump conduit transform.
 *
 * Transforms n00b_buffer_t * -> n00b_plane_t *, producing an
 * incrementally-growing hex dump plane.  Partial lines are shown
 * immediately and overwritten when the line completes.
 */

#include "conduit/xform_hexdump.h"
#include "core/alloc.h"
#include "core/string.h"
#include "internal/display/hexdump_contracts.h"
#include "text/strings/string_style.h"

#include <string.h>

// ============================================================================
// Internal constants
// ============================================================================

#define HEXDUMP_INITIAL_ROWS 64
#define HEXDUMP_GROW_ROWS    64

// ============================================================================
// Helpers
// ============================================================================

static void
ensure_plane_rows(n00b_hexdump_xform_state_t *st, n00b_isize_t needed_rows)
{
    if (needed_rows <= st->plane_cap) return;

    n00b_isize_t new_cap = st->plane_cap;
    while (new_cap < needed_rows)
        new_cap += HEXDUMP_GROW_ROWS;

    // Draw list grows dynamically; just update capacity tracking.
    st->plane_cap = new_cap;
}

// ============================================================================
// Transform callback
// ============================================================================

static void
emit_line(n00b_hexdump_xform_state_t *st, n00b_hexdump_t *hd,
          uint32_t nbytes, bool complete)
{
    char *line_out = n00b_alloc_array(char, hd->line_width + 1);
    n00b_hexdump_format_line(hd, hd->line_buf, nbytes, line_out);

    int64_t len = (int64_t)hd->line_width - 1;
    n00b_string_t *s = n00b_string_from_raw(line_out, len);

    // Build style info with 2 deferred-tag records.
    n00b_string_style_info_t *info =
        n00b_alloc_flex(n00b_string_style_info_t, n00b_style_record_t, 2);
    info->num_styles = 2;
    info->base_style = nullptr;

    n00b_hexdump_line_regions_t regions = {};
    n00b_hexdump_describe_line_regions(hd, nbytes, &regions);

    // Record 0: offset column.
    info->styles[0].info  = nullptr;
    info->styles[0].tag   = "hexdump.offset";
    info->styles[0].start = (size_t)regions.offset_start;
    info->styles[0].end   = n00b_option_set(size_t, (size_t)regions.offset_end);

    // Record 1: ASCII sidebar.
    info->styles[1].info  = nullptr;
    info->styles[1].tag   = "hexdump.ascii";
    info->styles[1].start = (size_t)regions.ascii_start;
    info->styles[1].end   = n00b_option_set(size_t, (size_t)regions.ascii_end);

    s->styling = info;

    ensure_plane_rows(st, st->current_row + 1);
    int32_t lh = n00b_plane_line_height(st->plane, nullptr);
    n00b_plane_draw_text(st->plane, 0, (int32_t)st->current_row * lh, s);

    if (complete) {
        st->current_row++;
        st->has_partial = false;
        hd->display_offset += hd->cpl;
        hd->line_offset = 0;
    }
    else {
        st->has_partial = true;
    }
}

static n00b_option_t(n00b_plane_t *)
hexdump_transform(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *) *xf,
    n00b_buffer_t *input)
{
    n00b_hexdump_xform_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_plane_t *, xf);

    if (!input || n00b_buffer_len(input) == 0)
        return n00b_option_none(n00b_plane_t *);

    n00b_hexdump_t *hd = st->hd;

    int64_t  in_len  = 0;
    char    *in_data = n00b_buffer_to_c(input, &in_len);
    if (in_len <= 0)
        return n00b_option_none(n00b_plane_t *);

    const uint8_t *p   = (const uint8_t *)in_data;
    const uint8_t *end = p + in_len;

    while (p < end) {
        uint32_t need  = hd->cpl - hd->line_offset;
        uint32_t avail = (uint32_t)(end - p);
        uint32_t take  = (avail < need) ? avail : need;

        memcpy(hd->line_buf + hd->line_offset, p, take);
        hd->line_offset += take;
        p += take;

        if (hd->line_offset == hd->cpl) {
            emit_line(st, hd, hd->cpl, true);
        }
    }

    // Handle partial line.
    if (hd->line_offset > 0) {
        emit_line(st, hd, hd->line_offset, false);
    }

    return n00b_option_set(n00b_plane_t *, st->plane);
}

// ============================================================================
// Flush callback
// ============================================================================

static void
hexdump_flush(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *) *xf)
{
    n00b_hexdump_xform_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_plane_t *, xf);

    // If there's a partial line, it's already displayed on the plane.
    // Just emit the final plane state.
    if (st->has_partial || st->current_row > 0) {
        n00b_conduit_xform_emit(n00b_buffer_t *, n00b_plane_t *,
                                 xf, st->plane);
    }
}

// ============================================================================
// Ops vtable
// ============================================================================

static n00b_string_t _kind_hexdump = {
    .data = "hexdump", .u8_bytes = 7, .codepoints = 7, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_xform_ops_t(n00b_buffer_t *, n00b_plane_t *)
    hexdump_ops = {
    .transform = hexdump_transform,
    .flush     = hexdump_flush,
    .kind      = &_kind_hexdump,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *) *)
n00b_conduit_hexdump_new(
    n00b_conduit_t                        *c,
    n00b_conduit_topic_t(n00b_buffer_t *) *upstream)
    _kargs {
        uint32_t width        = 0;
        int64_t  start_offset = 0;
    }
{
    auto r = n00b_conduit_xform_new(
        n00b_buffer_t *, n00b_plane_t *,
        c, upstream, &hexdump_ops,
        sizeof(n00b_hexdump_xform_state_t));

    if (n00b_result_is_ok(r)) {
        auto xf = n00b_result_get(r);
        n00b_hexdump_xform_state_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_plane_t *, xf);

        st->hd = n00b_hexdump_new(.width = width,
                                   .start_offset = start_offset);

        st->plane_cols = (n00b_isize_t)st->hd->line_width;
        st->plane_cap  = HEXDUMP_INITIAL_ROWS;
        st->plane      = n00b_new_kargs(n00b_plane_t, plane);
        st->plane->width = st->plane_cols;
        st->plane->height = st->plane_cap;
        st->current_row = 0;
        st->has_partial = false;
    }

    return r;
}

// ============================================================================
// Chain spec
// ============================================================================

static n00b_conduit_xform_base_t *
hexdump_create_from_spec(n00b_conduit_t            *c,
                          n00b_conduit_topic_base_t *upstream,
                          const void                *spec)
{
    const n00b_conduit_hexdump_spec_t *s = spec;
    auto r = n00b_conduit_hexdump_new(
        c, (n00b_conduit_topic_t(n00b_buffer_t *) *)upstream,
        .width = s->width, .start_offset = s->start_offset);
    if (n00b_result_is_err(r)) return nullptr;
    return (n00b_conduit_xform_base_t *)n00b_result_get(r);
}

const n00b_conduit_hexdump_spec_t n00b_conduit_hexdump_default_spec = {
    .base = {
        .create      = hexdump_create_from_spec,
        .cookie_size = sizeof(n00b_hexdump_xform_state_t),
    },
    .width        = 0,
    .start_offset = 0,
};

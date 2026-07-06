/*
 * xform_linebuf.c — Line-buffering transform implementation.
 */

#include "conduit/xform_linebuf.h"
#include "core/alloc.h"

#include <string.h>

// ============================================================================
// Transform callback
// ============================================================================

static n00b_option_t(n00b_buffer_t *)
linebuf_transform(n00b_conduit_filter_t(n00b_buffer_t *) *xf,
                  n00b_buffer_t *input)
{
    n00b_linebuf_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_buffer_t *, xf);

    if (!input) return n00b_option_none(n00b_buffer_t *);

    int64_t  in_len  = 0;
    char    *in_data = n00b_buffer_to_c(input, &in_len);
    if (in_len == 0) {
        if (st->consume) {
            n00b_free(input);
        }
        return n00b_option_none(n00b_buffer_t *);
    }

    n00b_allocator_t *alloc = xf->conduit ? xf->conduit->allocator : nullptr;
    char    *scan = in_data;
    char    *end  = in_data + in_len;

    while (scan < end) {
        // Find next delimiter.
        char *found = memchr(scan, st->delimiter, (size_t)(end - scan));

        if (!found) {
            // No delimiter — accumulate remainder.
            size_t tail_len = (size_t)(end - scan);
            if (!st->partial) {
                st->partial = n00b_buffer_from_bytes(scan, (int64_t)tail_len,
                                                     .allocator = alloc);
            } else {
                n00b_buffer_t *piece =
                    n00b_buffer_from_bytes(scan, (int64_t)tail_len,
                                           .allocator = alloc);
                n00b_buffer_t *merged = n00b_buffer_add(st->partial, piece,
                                                        .allocator = alloc);
                st->partial = merged;
            }
            break;
        }

        // Found delimiter.  Compute line boundaries.
        size_t line_len = (size_t)(found - scan);
        if (st->include_delimiter) line_len++;

        // If we have a partial, prepend it.
        n00b_buffer_t *line;
        if (st->partial) {
            n00b_buffer_t *piece =
                n00b_buffer_from_bytes(scan, (int64_t)line_len,
                                       .allocator = alloc);
            line = n00b_buffer_add(st->partial, piece, .allocator = alloc);
            st->partial = nullptr;
        } else {
            line = n00b_buffer_from_bytes(scan, (int64_t)line_len,
                                          .allocator = alloc);
        }

        // Apply max_line_len truncation.
        if (st->max_line_len > 0 &&
            (size_t)n00b_buffer_len(line) > st->max_line_len) {
            n00b_buffer_resize(line, st->max_line_len);
        }

        // Emit the complete line.
        n00b_conduit_filter_emit(n00b_buffer_t *, xf, line);

        // Advance past the delimiter.
        scan = found + 1;
    }

    if (st->consume) {
        n00b_free(input);
    }

    return n00b_option_none(n00b_buffer_t *);
}

// ============================================================================
// Flush callback — emit remaining partial data
// ============================================================================

static void
linebuf_flush(n00b_conduit_filter_t(n00b_buffer_t *) *xf)
{
    n00b_linebuf_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_buffer_t *, xf);

    if (st->partial && n00b_buffer_len(st->partial) > 0) {
        n00b_conduit_filter_emit(n00b_buffer_t *, xf, st->partial);
        st->partial = nullptr;
    }
}

// ============================================================================
// Ops vtable
// ============================================================================

static n00b_string_t _kind_linebuf = {
    .data = "linebuf", .u8_bytes = 7, .codepoints = 7, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_filter_ops_t(n00b_buffer_t *) linebuf_ops = {
    .transform = linebuf_transform,
    .flush     = linebuf_flush,
    .kind      = &_kind_linebuf,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_conduit_filter_t(n00b_buffer_t *) *)
n00b_conduit_linebuf_new(n00b_conduit_t                        *c,
                         n00b_conduit_topic_t(n00b_buffer_t *)  *upstream)
    _kargs {
        uint8_t delimiter         = '\n';
        size_t  max_line_len      = 0;
        bool    include_delimiter = false;
        bool    consume           = false;
    }
{
    auto r = n00b_conduit_filter_new(n00b_buffer_t *, c, upstream,
                                     &linebuf_ops,
                                     sizeof(n00b_linebuf_state_t));

    if (n00b_result_is_ok(r)) {
        n00b_conduit_filter_t(n00b_buffer_t *) *xf = n00b_result_get(r);
        n00b_linebuf_state_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_buffer_t *, xf);
        st->delimiter         = delimiter;
        st->max_line_len      = max_line_len;
        st->include_delimiter = include_delimiter;
        st->consume           = consume;
        st->partial           = nullptr;
    }

    return r;
}

// ============================================================================
// Chain spec
// ============================================================================

static n00b_conduit_xform_base_t *
linebuf_create_from_spec(n00b_conduit_t            *c,
                         n00b_conduit_topic_base_t *upstream,
                         const void                *spec)
{
    const n00b_conduit_linebuf_spec_t *ls = spec;

    auto r = n00b_conduit_linebuf_new(
        c,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)upstream,
        .delimiter         = ls->delimiter,
        .max_line_len      = ls->max_line_len,
        .include_delimiter = ls->include_delimiter);

    if (n00b_result_is_err(r)) return nullptr;
    return (n00b_conduit_xform_base_t *)n00b_result_get(r);
}

const n00b_conduit_linebuf_spec_t n00b_conduit_linebuf_default_spec = {
    .base = {
        .create      = linebuf_create_from_spec,
        .cookie_size = sizeof(n00b_linebuf_state_t),
    },
    .delimiter         = '\n',
    .max_line_len      = 0,
    .include_delimiter = false,
};

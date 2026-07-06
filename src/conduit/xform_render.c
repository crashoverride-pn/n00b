/*
 * xform_render.c — Render system transforms for conduit pipelines.
 *
 * render_out: n00b_plane_t * -> n00b_buffer_t *
 *   Renders a plane through a canvas/backend, captures output as buffer.
 *
 * render_in: n00b_buffer_t * -> n00b_plane_t *
 *   Writes buffer bytes into a fresh plane as text content.
 */

#include "conduit/xform_render.h"
#include "core/alloc.h"
#include "core/string.h"
#include "display/backend_stream_internal.h"

#include <string.h>

// ============================================================================
// render_out: n00b_plane_t * -> n00b_buffer_t *
// ============================================================================

typedef struct {
    n00b_canvas_t                *canvas;
    const n00b_renderer_vtable_t *backend;
    int32_t                       width;
    int32_t                       height;
} render_out_state_t;

static n00b_option_t(n00b_buffer_t *)
render_out_transform(
    n00b_conduit_xform_t(n00b_plane_t *, n00b_buffer_t *) *xf,
    n00b_plane_t *input)
{
    render_out_state_t *st = n00b_conduit_xform_cookie(
        n00b_plane_t *, n00b_buffer_t *, xf);

    if (!input)
        return n00b_option_none(n00b_buffer_t *);

    // Add the plane, render, capture, remove.
    n00b_canvas_add_plane(st->canvas, input);
    n00b_canvas_invalidate(st->canvas);
    n00b_canvas_render(st->canvas);

    n00b_string_t *captured = n00b_stream_backend_get_buffer(st->canvas->backend_ctx);

    n00b_canvas_remove_plane(st->canvas, input);

    if (!captured || captured->u8_bytes == 0)
        return n00b_option_none(n00b_buffer_t *);

    n00b_allocator_t *alloc = xf->conduit ? xf->conduit->allocator : nullptr;
    n00b_buffer_t *out = n00b_buffer_from_bytes(captured->data,
                                                (int64_t)captured->u8_bytes,
                                                .allocator = alloc);
    return n00b_option_set(n00b_buffer_t *, out);
}

static void
render_out_teardown(
    n00b_conduit_xform_t(n00b_plane_t *, n00b_buffer_t *) *xf)
{
    render_out_state_t *st = n00b_conduit_xform_cookie(
        n00b_plane_t *, n00b_buffer_t *, xf);

    if (st->canvas) {
        n00b_canvas_destroy(st->canvas);
        st->canvas = nullptr;
    }
}

static n00b_string_t _kind_render_out = {
    .data = "render_out", .u8_bytes = 10, .codepoints = 10, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_xform_ops_t(n00b_plane_t *, n00b_buffer_t *)
    render_out_ops = {
    .transform = render_out_transform,
    .teardown  = render_out_teardown,
    .kind      = &_kind_render_out,
};

n00b_result_t(n00b_conduit_xform_t(n00b_plane_t *, n00b_buffer_t *) *)
n00b_conduit_render_out_new(
    n00b_conduit_t                       *c,
    n00b_conduit_topic_t(n00b_plane_t *) *upstream)
    _kargs {
        const n00b_renderer_vtable_t *backend = nullptr;
        int32_t                       width   = 80;
        int32_t                       height  = 25;
    }
{
    if (!backend)
        backend = &n00b_renderer_stream;

    auto r = n00b_conduit_xform_new(
        n00b_plane_t *, n00b_buffer_t *,
        c, upstream, &render_out_ops, sizeof(render_out_state_t));

    if (n00b_result_is_ok(r)) {
        auto xf = n00b_result_get(r);
        render_out_state_t *st = n00b_conduit_xform_cookie(
            n00b_plane_t *, n00b_buffer_t *, xf);

        st->backend = backend;
        st->width   = width;
        st->height  = height;

        // Always use stream backend for buffer capture.
        st->canvas = n00b_new_kargs(n00b_canvas_t, canvas, .vtable = &n00b_renderer_stream);
        n00b_canvas_resize(st->canvas, height, width);
        n00b_stream_backend_set_size(st->canvas->backend_ctx, height, width);
    }

    return r;
}

// ============================================================================
// render_in: n00b_buffer_t * -> n00b_plane_t *
// ============================================================================

typedef struct {
    int32_t            width;
    int32_t            height;
    n00b_text_style_t *style;
} render_in_state_t;

static n00b_option_t(n00b_plane_t *)
render_in_transform(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *) *xf,
    n00b_buffer_t *input)
{
    render_in_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_plane_t *, xf);

    if (!input || n00b_buffer_len(input) == 0)
        return n00b_option_none(n00b_plane_t *);

    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t, plane,
                                          .style = st->style);
    plane->width  = st->width;
    plane->height = st->height;

    // Convert buffer to string and write to plane.
    int64_t len  = 0;
    char   *data = n00b_buffer_to_c(input, &len);

    // Count codepoints (assume UTF-8; approximate with byte count for now).
    n00b_string_t *str = n00b_string_from_raw(data, len);
    n00b_plane_draw_text(plane, 0, 0, str);

    return n00b_option_set(n00b_plane_t *, plane);
}

static n00b_string_t _kind_render_in = {
    .data = "render_in", .u8_bytes = 9, .codepoints = 9, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_xform_ops_t(n00b_buffer_t *, n00b_plane_t *)
    render_in_ops = {
    .transform = render_in_transform,
    .kind      = &_kind_render_in,
};

n00b_result_t(n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *) *)
n00b_conduit_render_in_new(
    n00b_conduit_t                        *c,
    n00b_conduit_topic_t(n00b_buffer_t *) *upstream)
    _kargs {
        int32_t            width  = 80;
        int32_t            height = 25;
        n00b_text_style_t *style  = nullptr;
    }
{

    auto r = n00b_conduit_xform_new(
        n00b_buffer_t *, n00b_plane_t *,
        c, upstream, &render_in_ops, sizeof(render_in_state_t));

    if (n00b_result_is_ok(r)) {
        auto xf = n00b_result_get(r);
        render_in_state_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_plane_t *, xf);

        st->width  = width;
        st->height = height;
        st->style  = style;
    }

    return r;
}

// ============================================================================
// Chain specs
// ============================================================================

typedef struct {
    n00b_conduit_xform_spec_base_t base;
    const n00b_renderer_vtable_t  *backend;
    int32_t                        width;
    int32_t                        height;
} n00b_conduit_render_out_spec_t;

static n00b_conduit_xform_base_t *
render_out_create_from_spec(n00b_conduit_t            *c,
                             n00b_conduit_topic_base_t *upstream,
                             const void                *spec)
{
    const n00b_conduit_render_out_spec_t *s = spec;
    auto r = n00b_conduit_render_out_new(
        c, (n00b_conduit_topic_t(n00b_plane_t *) *)upstream,
        .backend = s->backend, .width = s->width, .height = s->height);
    if (n00b_result_is_err(r)) return nullptr;
    return (n00b_conduit_xform_base_t *)n00b_result_get(r);
}

typedef struct {
    n00b_conduit_xform_spec_base_t base;
    int32_t                        width;
    int32_t                        height;
    n00b_text_style_t             *style;
} n00b_conduit_render_in_spec_t;

static n00b_conduit_xform_base_t *
render_in_create_from_spec(n00b_conduit_t            *c,
                            n00b_conduit_topic_base_t *upstream,
                            const void                *spec)
{
    const n00b_conduit_render_in_spec_t *s = spec;
    auto r = n00b_conduit_render_in_new(
        c, (n00b_conduit_topic_t(n00b_buffer_t *) *)upstream,
        .width = s->width, .height = s->height, .style = s->style);
    if (n00b_result_is_err(r)) return nullptr;
    return (n00b_conduit_xform_base_t *)n00b_result_get(r);
}

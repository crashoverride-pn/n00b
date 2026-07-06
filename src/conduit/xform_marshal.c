/*
 * xform_marshal.c - Object graph marshal/unmarshal conduit transforms.
 */

#include "conduit/xform_marshal.h"
#include "core/alloc.h"

// ============================================================================
// Marshal transform: object -> buffer
// ============================================================================

static n00b_option_t(n00b_buffer_t *)
marshal_transform(
    n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *xf,
    n00b_marshal_object_t input)
{
    n00b_conduit_marshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_marshal_object_t, n00b_buffer_t *, xf);

    if (!input) {
        st->status = N00B_MARSHAL_ERR_NULL_ARG;
        st->error  = r"marshal transform received a null object";
        return n00b_option_none(n00b_buffer_t *);
    }

    n00b_marshal_ctx_t *ctx = n00b_marshal_ctx_new(
        .flags        = st->flags,
        .base_address = st->base_address);
    n00b_buffer_t *buf = n00b_marshal_incremental(ctx, input);

    st->status = n00b_marshal_ctx_status(ctx);
    st->error  = n00b_marshal_ctx_error(ctx);
    n00b_marshal_ctx_destroy(ctx);

    if (!buf || st->status != N00B_MARSHAL_OK) {
        return n00b_option_none(n00b_buffer_t *);
    }

    return n00b_option_set(n00b_buffer_t *, buf);
}

// Runs before the worker frees the cookie (see the xform thread body): copy the
// terminal status/error out of the cookie so n00b_conduit_marshal_status/_error
// remain queryable after join, when xf->cookie is already nullptr.
static void
marshal_teardown(
    n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *xf)
{
    n00b_conduit_marshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_marshal_object_t, n00b_buffer_t *, xf);
    if (st) {
        xf->terminal_status = (uint32_t)st->status;
        xf->terminal_error  = st->error;
    }
}

static n00b_string_t _kind_marshal = {
    .data = "marshal", .u8_bytes = 7, .codepoints = 7, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_xform_ops_t(n00b_marshal_object_t, n00b_buffer_t *)
    marshal_ops = {
    .transform = marshal_transform,
    .teardown  = marshal_teardown,
    .kind      = &_kind_marshal,
};

n00b_result_t(n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *)
n00b_conduit_marshal_new(
    n00b_conduit_t                              *c,
    n00b_conduit_topic_t(n00b_marshal_object_t) *upstream)
    _kargs {
        uint32_t flags        = N00B_MARSHAL_F_NONE;
        uint32_t base_address = 0;
    }
{
    auto r = n00b_conduit_xform_new(
        n00b_marshal_object_t,
        n00b_buffer_t *,
        c,
        upstream,
        &marshal_ops,
        sizeof(n00b_conduit_marshal_state_t));

    if (n00b_result_is_err(r)) {
        return r;
    }

    auto xf = n00b_result_get(r);
    n00b_conduit_marshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_marshal_object_t, n00b_buffer_t *, xf);

    st->flags           = flags;
    st->base_address    = base_address;
    st->status          = N00B_MARSHAL_OK;
    st->error           = nullptr;
    xf->terminal_status = (uint32_t)N00B_MARSHAL_OK;
    xf->terminal_error  = nullptr;

    return r;
}

n00b_marshal_status_t
n00b_conduit_marshal_status(
    n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *xf)
{
    if (!xf) return N00B_MARSHAL_ERR_NULL_ARG;
    // After the worker exits it frees the cookie; the terminal status was
    // snapshotted into the xform in marshal_teardown.
    if (!xf->cookie) return (n00b_marshal_status_t)xf->terminal_status;

    n00b_conduit_marshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_marshal_object_t, n00b_buffer_t *, xf);
    return st->status;
}

n00b_string_t *
n00b_conduit_marshal_error(
    n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *xf)
{
    if (!xf) return r"null marshal transform";
    if (!xf->cookie) return (n00b_string_t *)xf->terminal_error;

    n00b_conduit_marshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_marshal_object_t, n00b_buffer_t *, xf);
    return st->error;
}

// ============================================================================
// Unmarshal transform: buffer -> object(s)
// ============================================================================

static n00b_option_t(n00b_marshal_object_t)
unmarshal_transform(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf,
    n00b_buffer_t *input)
{
    n00b_conduit_unmarshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_marshal_object_t, xf);

    if (!st->ctx) {
        st->ctx = n00b_unmarshal_ctx_new(.target_arena = st->target_arena);
    }

    if (!input) {
        st->status = N00B_MARSHAL_ERR_NULL_ARG;
        st->error  = r"unmarshal transform received a null buffer";
        return n00b_option_none(n00b_marshal_object_t);
    }

    n00b_list_t(void *) roots = n00b_unmarshal_incremental(st->ctx, input);
    st->status               = n00b_unmarshal_ctx_status(st->ctx);
    st->error                = n00b_unmarshal_ctx_error(st->ctx);

    uint64_t n = n00b_list_len(roots);
    for (uint64_t i = 0; i < n; i++) {
        n00b_marshal_object_t root = n00b_list_get(roots, i);
        n00b_conduit_xform_emit(
            n00b_buffer_t *, n00b_marshal_object_t, xf, root);
    }

    return n00b_option_none(n00b_marshal_object_t);
}

static void
unmarshal_flush(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf)
{
    n00b_conduit_unmarshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_marshal_object_t, xf);

    if (st->status == N00B_MARSHAL_ERR_INCOMPLETE_STREAM && !st->error) {
        st->error = r"upstream closed with an incomplete marshal stream";
    }
}

static void
unmarshal_teardown(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf)
{
    n00b_conduit_unmarshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_marshal_object_t, xf);

    if (st) {
        // Snapshot the terminal result before the worker frees the cookie, so
        // n00b_conduit_unmarshal_status/_error remain queryable after join.
        xf->terminal_status = (uint32_t)st->status;
        xf->terminal_error  = st->error;
        if (st->ctx) {
            n00b_unmarshal_ctx_destroy(st->ctx);
            st->ctx = nullptr;
        }
    }
}

static n00b_string_t _kind_unmarshal = {
    .data = "unmarshal", .u8_bytes = 9, .codepoints = 9, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_xform_ops_t(n00b_buffer_t *, n00b_marshal_object_t)
    unmarshal_ops = {
    .transform = unmarshal_transform,
    .flush     = unmarshal_flush,
    .teardown  = unmarshal_teardown,
    .kind      = &_kind_unmarshal,
};

n00b_result_t(n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *)
n00b_conduit_unmarshal_new(
    n00b_conduit_t                        *c,
    n00b_conduit_topic_t(n00b_buffer_t *) *upstream)
    _kargs {
        n00b_arena_t *target_arena = nullptr;
    }
{
    auto r = n00b_conduit_xform_new(
        n00b_buffer_t *,
        n00b_marshal_object_t,
        c,
        upstream,
        &unmarshal_ops,
        sizeof(n00b_conduit_unmarshal_state_t));

    if (n00b_result_is_err(r)) {
        return r;
    }

    auto xf = n00b_result_get(r);
    n00b_conduit_unmarshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_marshal_object_t, xf);

    st->ctx             = n00b_unmarshal_ctx_new(.target_arena = target_arena);
    st->target_arena    = target_arena;
    st->status          = N00B_MARSHAL_OK;
    st->error           = nullptr;
    xf->terminal_status = (uint32_t)N00B_MARSHAL_OK;
    xf->terminal_error  = nullptr;

    return r;
}

n00b_marshal_status_t
n00b_conduit_unmarshal_status(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf)
{
    if (!xf) return N00B_MARSHAL_ERR_NULL_ARG;
    if (!xf->cookie) return (n00b_marshal_status_t)xf->terminal_status;

    n00b_conduit_unmarshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_marshal_object_t, xf);
    return st->status;
}

n00b_string_t *
n00b_conduit_unmarshal_error(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf)
{
    if (!xf) return r"null unmarshal transform";
    if (!xf->cookie) return (n00b_string_t *)xf->terminal_error;

    n00b_conduit_unmarshal_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_marshal_object_t, xf);
    return st->error;
}

/*
 * xform_json.c — JSON parse and encode conduit transforms.
 *
 * json_parse:  n00b_buffer_t * -> n00b_json_node_t *
 * json_encode: n00b_json_node_t * -> n00b_buffer_t *
 */

#include "conduit/xform_json.h"
#include "core/alloc.h"
#include "core/buffer.h"

#include <string.h>

// ============================================================================
// Parse transform: buffer -> node
// ============================================================================

static void
parse_buf_ensure(n00b_json_parse_state_t *st, size_t needed)
{
    size_t required = st->buf_len + needed;
    if (required <= st->buf_cap) return;

    size_t new_cap = st->buf_cap ? st->buf_cap * 2 : 256;
    while (new_cap < required) new_cap *= 2;

    uint8_t *new_buf = n00b_alloc_array(uint8_t, new_cap);
    if (st->buf && st->buf_len > 0) {
        memcpy(new_buf, st->buf, st->buf_len);
    }
    st->buf     = new_buf;
    st->buf_cap = new_cap;
}

static void
json_parse_try_emit(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_json_node_t *) *xf,
    n00b_json_parse_state_t *st)
{
    if (st->buf_len == 0) return;

    const char *err = nullptr;
    n00b_json_node_t *val = n00b_json_parse(
        (const char *)st->buf, st->buf_len, &err);

    if (!val) return; // incomplete or error — wait for more data

    // Emit the parsed value.
    n00b_conduit_xform_emit(
        n00b_buffer_t *, n00b_json_node_t *, xf, val);

    // Check for remaining data (multiple JSON values in stream).
    // Re-parse to find where the first value ended.
    // We need a simple approach: try to find trailing content.
    // Since n00b_json_parse consumed trailing whitespace, the entire
    // buffer was consumed.
    st->buf_len = 0;
}

static n00b_option_t(n00b_json_node_t *)
json_parse_transform(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_json_node_t *) *xf,
    n00b_buffer_t *input)
{
    n00b_json_parse_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_json_node_t *, xf);

    if (!input || n00b_buffer_len(input) == 0)
        return n00b_option_none(n00b_json_node_t *);

    int64_t  in_len  = 0;
    char    *in_data = n00b_buffer_to_c(input, &in_len);
    if (in_len <= 0)
        return n00b_option_none(n00b_json_node_t *);

    // Check max_size limit.
    if (st->max_size > 0 &&
        st->buf_len + (size_t)in_len > st->max_size) {
        return n00b_option_none(n00b_json_node_t *);
    }

    // Accumulate input.
    parse_buf_ensure(st, (size_t)in_len);
    memcpy(st->buf + st->buf_len, in_data, (size_t)in_len);
    st->buf_len += (size_t)in_len;

    // Try to parse complete value(s).
    json_parse_try_emit(xf, st);

    return n00b_option_none(n00b_json_node_t *);
}

static void
json_parse_flush(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_json_node_t *) *xf)
{
    n00b_json_parse_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_json_node_t *, xf);

    if (st->buf_len > 0) {
        json_parse_try_emit(xf, st);
    }
}

static n00b_string_t _kind_json_parse = {
    .data = "json_parse", .u8_bytes = 10, .codepoints = 10, .styling = nullptr
};

static const n00b_conduit_xform_ops_t(n00b_buffer_t *, n00b_json_node_t *)
    json_parse_ops = {
    .transform = json_parse_transform,
    .flush     = json_parse_flush,
    .kind      = &_kind_json_parse,
};

n00b_result_t(n00b_conduit_xform_t(n00b_buffer_t *, n00b_json_node_t *) *)
n00b_conduit_json_parse_new(
    n00b_conduit_t                        *c,
    n00b_conduit_topic_t(n00b_buffer_t *) *upstream)
{
    auto r = n00b_conduit_xform_new(
        n00b_buffer_t *, n00b_json_node_t *,
        c, upstream, &json_parse_ops,
        sizeof(n00b_json_parse_state_t));

    if (n00b_result_is_ok(r)) {
        auto xf = n00b_result_get(r);
        n00b_json_parse_state_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_json_node_t *, xf);
        st->max_depth = 256;
        st->max_size  = 0;
    }

    return r;
}

// ============================================================================
// Encode transform: node -> buffer
// ============================================================================

static n00b_option_t(n00b_buffer_t *)
json_encode_transform(
    n00b_conduit_xform_t(n00b_json_node_t *, n00b_buffer_t *) *xf,
    n00b_json_node_t *input)
{
    n00b_json_encode_state_t *st = n00b_conduit_xform_cookie(
        n00b_json_node_t *, n00b_buffer_t *, xf);

    if (!input)
        return n00b_option_none(n00b_buffer_t *);

    char *json_text = n00b_json_encode(input,
                                        .pretty = st->pretty,
                                        .indent = st->indent);
    if (!json_text)
        return n00b_option_none(n00b_buffer_t *);

    size_t json_len = strlen(json_text);
    n00b_allocator_t *alloc = xf->conduit ? xf->conduit->allocator : nullptr;
    n00b_buffer_t *buf = n00b_buffer_from_bytes(json_text, (int64_t)json_len,
                                                .allocator = alloc);
    n00b_free(json_text);

    return n00b_option_set(n00b_buffer_t *, buf);
}

static n00b_string_t _kind_json_encode = {
    .data = "json_encode", .u8_bytes = 11, .codepoints = 11, .styling = nullptr
};

static const n00b_conduit_xform_ops_t(n00b_json_node_t *, n00b_buffer_t *)
    json_encode_ops = {
    .transform = json_encode_transform,
    .kind      = &_kind_json_encode,
};

n00b_result_t(n00b_conduit_xform_t(n00b_json_node_t *, n00b_buffer_t *) *)
n00b_conduit_json_encode_new(
    n00b_conduit_t                             *c,
    n00b_conduit_topic_t(n00b_json_node_t *)  *upstream)
    _kargs {
        bool pretty = false;
        int  indent = 2;
    }
{
    auto r = n00b_conduit_xform_new(
        n00b_json_node_t *, n00b_buffer_t *,
        c, upstream, &json_encode_ops,
        sizeof(n00b_json_encode_state_t));

    if (n00b_result_is_ok(r)) {
        auto xf = n00b_result_get(r);
        n00b_json_encode_state_t *st = n00b_conduit_xform_cookie(
            n00b_json_node_t *, n00b_buffer_t *, xf);
        st->pretty = pretty;
        st->indent = indent > 0 ? indent : 2;
    }

    return r;
}

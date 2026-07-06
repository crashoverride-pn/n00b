/*
 * xform_http.c — HTTP/1.1 parser transform conduit.
 *
 * Incremental state-machine parser for HTTP/1.1 request and response
 * messages.  Consumes n00b_buffer_t * and emits n00b_http_parse_event_t *.
 */

#include "conduit/xform_http.h"
#include "core/alloc.h"
#include "core/buffer.h"

#include <string.h>

#define HTTP_ACCUM_INIT 1024

static bool
ascii_case_equal(const char *a, const char *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];

        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return false;
    }

    return true;
}

// ============================================================================
// Accumulation buffer helpers
// ============================================================================

static void
accum_ensure(n00b_http_parse_cookie_t *st, size_t needed)
{
    size_t required = st->accum_len + needed;
    if (required <= st->accum_cap) return;

    size_t new_cap = st->accum_cap ? st->accum_cap * 2 : HTTP_ACCUM_INIT;
    while (new_cap < required) new_cap *= 2;

    uint8_t *new_buf = n00b_alloc_array(uint8_t, new_cap);
    if (st->accum && st->accum_len > 0) {
        memcpy(new_buf, st->accum, st->accum_len);
    }
    st->accum     = new_buf;
    st->accum_cap = new_cap;
}

static void
accum_reset(n00b_http_parse_cookie_t *st)
{
    st->accum_len = 0;
}

static void
accum_append(n00b_http_parse_cookie_t *st,
             const uint8_t *data, size_t len)
{
    accum_ensure(st, len);
    memcpy(st->accum + st->accum_len, data, len);
    st->accum_len += len;
}

// ============================================================================
// Event emission
// ============================================================================

static void
emit_event(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_http_parse_event_t *evt)
{
    n00b_allocator_t *alloc = xf && xf->conduit ? xf->conduit->allocator : nullptr;

    n00b_http_parse_event_t *heap_evt =
        n00b_alloc_with_opts(
            n00b_http_parse_event_t,
            &(n00b_alloc_opts_t){.allocator = alloc});
    *heap_evt = *evt;

    switch (evt->selector) {
    case typehash(n00b_http_request_line_t): {
        n00b_http_request_line_t rl = n00b_variant_get(*evt,
                                                       n00b_http_request_line_t);
        char *method = n00b_alloc_array(char,
                                        rl.method_len + 1,
                                        .allocator = alloc);
        char *uri = n00b_alloc_array(char,
                                     rl.uri_len + 1,
                                     .allocator = alloc);
        memcpy(method, rl.method, rl.method_len);
        memcpy(uri, rl.uri, rl.uri_len);
        method[rl.method_len] = '\0';
        uri[rl.uri_len]       = '\0';
        rl.method             = method;
        rl.uri                = uri;
        *heap_evt = n00b_variant_set(n00b_http_parse_event_t,
                                     n00b_http_request_line_t, rl);
        break;
    }

    case typehash(n00b_http_response_line_t): {
        n00b_http_response_line_t rl =
            n00b_variant_get(*evt, n00b_http_response_line_t);
        char *reason = n00b_alloc_array(char,
                                        rl.reason_len + 1,
                                        .allocator = alloc);
        memcpy(reason, rl.reason, rl.reason_len);
        reason[rl.reason_len] = '\0';
        rl.reason             = reason;
        *heap_evt = n00b_variant_set(n00b_http_parse_event_t,
                                     n00b_http_response_line_t, rl);
        break;
    }

    case typehash(n00b_http_header_t): {
        n00b_http_header_t h = n00b_variant_get(*evt, n00b_http_header_t);
        char *name = n00b_alloc_array(char,
                                      h.name_len + 1,
                                      .allocator = alloc);
        char *value = n00b_alloc_array(char,
                                       h.value_len + 1,
                                       .allocator = alloc);
        memcpy(name, h.name, h.name_len);
        memcpy(value, h.value, h.value_len);
        name[h.name_len]   = '\0';
        value[h.value_len] = '\0';
        h.name             = name;
        h.value            = value;
        *heap_evt = n00b_variant_set(n00b_http_parse_event_t,
                                     n00b_http_header_t, h);
        break;
    }

    case typehash(n00b_http_body_chunk_t): {
        n00b_http_body_chunk_t bc =
            n00b_variant_get(*evt, n00b_http_body_chunk_t);
        uint8_t *data = n00b_alloc_array(uint8_t,
                                         bc.len + 1,
                                         .allocator = alloc);
        memcpy(data, bc.data, bc.len);
        data[bc.len] = 0;
        bc.data      = data;
        *heap_evt = n00b_variant_set(n00b_http_parse_event_t,
                                     n00b_http_body_chunk_t, bc);
        break;
    }

    case typehash(n00b_http_error_t): {
        n00b_http_error_t e = n00b_variant_get(*evt, n00b_http_error_t);
        size_t len = strlen(e.reason);
        char  *reason = n00b_alloc_array(char, len + 1, .allocator = alloc);
        memcpy(reason, e.reason, len);
        reason[len] = '\0';
        e.reason    = reason;
        *heap_evt = n00b_variant_set(n00b_http_parse_event_t,
                                     n00b_http_error_t, e);
        break;
    }

    default:
        // headers_done / complete: no payload to copy.
        break;
    }

    n00b_conduit_xform_emit(
        n00b_buffer_t *, n00b_http_parse_event_t *, xf, heap_evt);
}

static void
emit_error(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_http_parse_cookie_t *st,
    const char *reason)
{
    st->state = N00B_HTTP_STATE_ERROR;

    n00b_http_parse_event_t evt = n00b_variant_set(
        n00b_http_parse_event_t,
        n00b_http_error_t,
        ((n00b_http_error_t){.reason = reason}));
    emit_event(xf, &evt);
}

// ============================================================================
// Line scanning
// ============================================================================

static size_t
find_eol(const uint8_t *data, size_t start, size_t len)
{
    for (size_t i = start; i < len; i++) {
        if (data[i] == '\n') return i;
    }
    return (size_t)-1;
}

static uint8_t *
extract_line(
    n00b_http_parse_cookie_t *st,
    const uint8_t *data, size_t data_len, size_t *data_pos,
    size_t *line_len)
{
    size_t eol = find_eol(data, *data_pos, data_len);
    if (eol == (size_t)-1) {
        accum_append(st, data + *data_pos, data_len - *data_pos);
        *data_pos = data_len;
        return nullptr;
    }

    size_t chunk_len = eol - *data_pos;
    size_t total     = st->accum_len + chunk_len;

    // Strip trailing \r.
    size_t trim = total;
    if (chunk_len > 0 && data[eol - 1] == '\r') {
        trim = total - 1;
    }
    else if (st->accum_len > 0 && chunk_len == 0 &&
             st->accum[st->accum_len - 1] == '\r') {
        trim = total - 1;
    }

    uint8_t *line = n00b_alloc_array(uint8_t, trim + 1);

    size_t off = 0;
    if (st->accum_len > 0) {
        size_t copy = st->accum_len;
        if (copy > trim) copy = trim;
        memcpy(line, st->accum, copy);
        off = copy;
    }
    if (chunk_len > 0 && off < trim) {
        size_t copy = chunk_len;
        if (off + copy > trim) copy = trim - off;
        memcpy(line + off, data + *data_pos, copy);
    }
    line[trim] = '\0';

    *line_len = trim;
    *data_pos = eol + 1;
    accum_reset(st);
    return line;
}

// ============================================================================
// Request line parsing
// ============================================================================

static bool
parse_request_line(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_http_parse_cookie_t *st,
    const uint8_t *line, size_t len)
{
    size_t i = 0;
    while (i < len && line[i] != ' ') i++;
    if (i == 0 || i >= len) {
        emit_error(xf, st, "invalid request line: no method");
        return false;
    }
    size_t method_end = i;
    i++;

    size_t uri_start = i;
    while (i < len && line[i] != ' ') i++;
    if (i >= len) {
        emit_error(xf, st, "invalid request line: no URI");
        return false;
    }
    size_t uri_end = i;
    i++;

    if (i + 5 > len || memcmp(line + i, "HTTP/", 5) != 0) {
        emit_error(xf, st, "invalid request line: bad version");
        return false;
    }
    i += 5;
    uint8_t major = 0, minor = 0;
    if (i < len && line[i] >= '0' && line[i] <= '9') {
        major = line[i] - '0';
        i++;
    }
    if (i < len && line[i] == '.') i++;
    if (i < len && line[i] >= '0' && line[i] <= '9') {
        minor = line[i] - '0';
    }

    n00b_http_parse_event_t evt = n00b_variant_set(
        n00b_http_parse_event_t,
        n00b_http_request_line_t,
        ((n00b_http_request_line_t){
            .method        = (const char *)line,
            .method_len    = method_end,
            .uri           = (const char *)line + uri_start,
            .uri_len       = uri_end - uri_start,
            .version_major = major,
            .version_minor = minor,
        }));
    emit_event(xf, &evt);
    return true;
}

// ============================================================================
// Response line parsing
// ============================================================================

static bool
parse_response_line(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_http_parse_cookie_t *st,
    const uint8_t *line, size_t len)
{
    if (len < 12 || memcmp(line, "HTTP/", 5) != 0) {
        emit_error(xf, st, "invalid response line");
        return false;
    }
    size_t i = 5;
    uint8_t major = 0, minor = 0;
    if (i < len && line[i] >= '0' && line[i] <= '9') {
        major = line[i] - '0';
        i++;
    }
    if (i < len && line[i] == '.') i++;
    if (i < len && line[i] >= '0' && line[i] <= '9') {
        minor = line[i] - '0';
        i++;
    }

    if (i >= len || line[i] != ' ') {
        emit_error(xf, st, "invalid response line: no space after version");
        return false;
    }
    i++;

    if (i + 3 > len) {
        emit_error(xf, st, "invalid response line: no status code");
        return false;
    }
    uint16_t status = 0;
    for (int d = 0; d < 3; d++) {
        if (line[i + d] < '0' || line[i + d] > '9') {
            emit_error(xf, st, "invalid response line: bad status code");
            return false;
        }
        status = status * 10 + (line[i + d] - '0');
    }
    i += 3;

    const char *reason     = "";
    size_t      reason_len = 0;
    if (i < len && line[i] == ' ') {
        i++;
        reason     = (const char *)line + i;
        reason_len = len - i;
    }

    n00b_http_parse_event_t evt = n00b_variant_set(
        n00b_http_parse_event_t,
        n00b_http_response_line_t,
        ((n00b_http_response_line_t){
            .status        = status,
            .reason        = reason,
            .reason_len    = reason_len,
            .version_major = major,
            .version_minor = minor,
        }));
    emit_event(xf, &evt);
    return true;
}

// ============================================================================
// Header line parsing
// ============================================================================

static bool
parse_header_line(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_http_parse_cookie_t *st,
    const uint8_t *line, size_t len)
{
    if (len == 0) {
        n00b_http_parse_event_t evt = n00b_variant_set(
            n00b_http_parse_event_t,
            n00b_http_headers_done_t,
            ((n00b_http_headers_done_t){0}));
        emit_event(xf, &evt);

        if (st->chunked) {
            st->state = N00B_HTTP_STATE_CHUNK_SIZE;
        }
        else if (st->has_content_length) {
            if (st->content_length == 0) {
                st->state = N00B_HTTP_STATE_COMPLETE;
                n00b_http_parse_event_t complete = n00b_variant_set(
                    n00b_http_parse_event_t,
                    n00b_http_complete_t,
                    ((n00b_http_complete_t){0}));
                emit_event(xf, &complete);
            }
            else {
                st->body_remaining = st->content_length;
                st->state = N00B_HTTP_STATE_BODY_IDENTITY;
            }
        }
        else {
            st->state = N00B_HTTP_STATE_COMPLETE;
            n00b_http_parse_event_t complete = n00b_variant_set(
                n00b_http_parse_event_t,
                n00b_http_complete_t,
                ((n00b_http_complete_t){0}));
            emit_event(xf, &complete);
        }
        return true;
    }

    if (st->max_headers > 0 && st->header_count >= st->max_headers) {
        emit_error(xf, st, "too many headers");
        return false;
    }

    size_t colon = 0;
    while (colon < len && line[colon] != ':') colon++;
    if (colon >= len) {
        if (st->strict) {
            emit_error(xf, st, "header line missing colon");
            return false;
        }
        return true;
    }

    const char *name     = (const char *)line;
    size_t      name_len = colon;

    size_t val_start = colon + 1;
    while (val_start < len &&
           (line[val_start] == ' ' || line[val_start] == '\t')) {
        val_start++;
    }

    size_t val_end = len;
    while (val_end > val_start &&
           (line[val_end - 1] == ' ' || line[val_end - 1] == '\t')) {
        val_end--;
    }

    const char *value     = (const char *)line + val_start;
    size_t      value_len = val_end - val_start;

    st->header_count++;
    st->header_bytes += len;

    if (name_len == 17 &&
        ascii_case_equal(name, "Transfer-Encoding", 17)) {
        if (value_len >= 7) {
            for (size_t i = 0; i + 7 <= value_len; i++) {
                if (ascii_case_equal(value + i, "chunked", 7)) {
                    st->chunked = true;
                    break;
                }
            }
        }
    }

    if (name_len == 14 &&
        ascii_case_equal(name, "Content-Length", 14)) {
        size_t cl = 0;
        for (size_t i = 0; i < value_len; i++) {
            if (value[i] < '0' || value[i] > '9') break;
            cl = cl * 10 + (value[i] - '0');
        }
        st->content_length     = cl;
        st->has_content_length = true;
    }

    n00b_http_parse_event_t evt = n00b_variant_set(
        n00b_http_parse_event_t,
        n00b_http_header_t,
        ((n00b_http_header_t){
            .name      = name,
            .name_len  = name_len,
            .value     = value,
            .value_len = value_len,
        }));
    emit_event(xf, &evt);
    return true;
}

// ============================================================================
// Main state machine
// ============================================================================

static void
http_process(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_http_parse_cookie_t *st,
    const uint8_t *data, size_t data_len)
{
    size_t pos = 0;

    while (pos < data_len) {
        if (st->state == N00B_HTTP_STATE_ERROR ||
            st->state == N00B_HTTP_STATE_COMPLETE) {
            break;
        }

        switch (st->state) {
        case N00B_HTTP_STATE_START: {
            size_t line_len;
            uint8_t *line = extract_line(st, data, data_len, &pos, &line_len);
            if (!line) return;

            st->header_bytes += line_len;
            if (st->max_header_size > 0 &&
                st->header_bytes > st->max_header_size) {
                emit_error(xf, st, "request/status line too large");
                return;
            }

            if (st->mode == N00B_HTTP_MODE_AUTO) {
                if (line_len >= 5 && memcmp(line, "HTTP/", 5) == 0) {
                    st->mode = N00B_HTTP_MODE_RESPONSE;
                }
                else {
                    st->mode = N00B_HTTP_MODE_REQUEST;
                }
            }

            bool ok;
            if (st->mode == N00B_HTTP_MODE_RESPONSE) {
                ok = parse_response_line(xf, st, line, line_len);
            }
            else {
                ok = parse_request_line(xf, st, line, line_len);
            }

            if (ok) st->state = N00B_HTTP_STATE_HEADER_LINE;
            break;
        }

        case N00B_HTTP_STATE_HEADER_LINE: {
            size_t line_len;
            uint8_t *line = extract_line(st, data, data_len, &pos, &line_len);
            if (!line) return;

            st->header_bytes += line_len;
            if (st->max_header_size > 0 &&
                st->header_bytes > st->max_header_size) {
                emit_error(xf, st, "headers too large");
                return;
            }

            parse_header_line(xf, st, line, line_len);
            break;
        }

        case N00B_HTTP_STATE_BODY_IDENTITY: {
            size_t avail   = data_len - pos;
            size_t consume = avail;
            if (consume > st->body_remaining) {
                consume = st->body_remaining;
            }

            if (st->max_body_size > 0 &&
                st->body_bytes + consume > st->max_body_size) {
                emit_error(xf, st, "body too large");
                return;
            }

            n00b_http_parse_event_t evt = n00b_variant_set(
                n00b_http_parse_event_t,
                n00b_http_body_chunk_t,
                ((n00b_http_body_chunk_t){
                    .data = data + pos,
                    .len  = consume,
                }));
            emit_event(xf, &evt);

            st->body_bytes    += consume;
            st->body_remaining -= consume;
            pos += consume;

            if (st->body_remaining == 0) {
                st->state = N00B_HTTP_STATE_COMPLETE;
                n00b_http_parse_event_t complete = n00b_variant_set(
                    n00b_http_parse_event_t,
                    n00b_http_complete_t,
                    ((n00b_http_complete_t){0}));
                emit_event(xf, &complete);
            }
            break;
        }

        case N00B_HTTP_STATE_CHUNK_SIZE: {
            size_t line_len;
            uint8_t *line = extract_line(st, data, data_len, &pos, &line_len);
            if (!line) return;

            size_t chunk_size = 0;
            for (size_t i = 0; i < line_len; i++) {
                uint8_t ch = line[i];
                if (ch >= '0' && ch <= '9') {
                    chunk_size = chunk_size * 16 + (ch - '0');
                }
                else if (ch >= 'a' && ch <= 'f') {
                    chunk_size = chunk_size * 16 + (ch - 'a' + 10);
                }
                else if (ch >= 'A' && ch <= 'F') {
                    chunk_size = chunk_size * 16 + (ch - 'A' + 10);
                }
                else {
                    break;
                }
            }

            if (chunk_size == 0) {
                st->state = N00B_HTTP_STATE_TRAILER;
            }
            else {
                st->chunk_remaining = chunk_size;
                st->state = N00B_HTTP_STATE_CHUNK_DATA;
            }
            break;
        }

        case N00B_HTTP_STATE_CHUNK_DATA: {
            size_t avail   = data_len - pos;
            size_t consume = avail;
            if (consume > st->chunk_remaining) {
                consume = st->chunk_remaining;
            }

            if (st->max_body_size > 0 &&
                st->body_bytes + consume > st->max_body_size) {
                emit_error(xf, st, "body too large");
                return;
            }

            n00b_http_parse_event_t evt = n00b_variant_set(
                n00b_http_parse_event_t,
                n00b_http_body_chunk_t,
                ((n00b_http_body_chunk_t){
                    .data = data + pos,
                    .len  = consume,
                }));
            emit_event(xf, &evt);

            st->body_bytes      += consume;
            st->chunk_remaining -= consume;
            pos += consume;

            if (st->chunk_remaining == 0) {
                st->state = N00B_HTTP_STATE_CHUNK_TRAILER;
            }
            break;
        }

        case N00B_HTTP_STATE_CHUNK_TRAILER: {
            size_t line_len;
            uint8_t *line = extract_line(st, data, data_len, &pos, &line_len);
            if (!line) return;
            st->state = N00B_HTTP_STATE_CHUNK_SIZE;
            break;
        }

        case N00B_HTTP_STATE_TRAILER: {
            size_t line_len;
            uint8_t *line = extract_line(st, data, data_len, &pos, &line_len);
            if (!line) return;

            if (line_len == 0) {
                st->state = N00B_HTTP_STATE_COMPLETE;
                n00b_http_parse_event_t complete = n00b_variant_set(
                    n00b_http_parse_event_t,
                    n00b_http_complete_t,
                    ((n00b_http_complete_t){0}));
                emit_event(xf, &complete);
            }
            else {
                parse_header_line(xf, st, line, line_len);
            }
            break;
        }

        case N00B_HTTP_STATE_COMPLETE:
        case N00B_HTTP_STATE_ERROR:
            return;

        default:
            emit_error(xf, st, "internal parser error: unknown state");
            return;
        }
    }
}

// ============================================================================
// Transform callback
// ============================================================================

static n00b_option_t(n00b_http_parse_event_t *)
http_parse_transform(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf,
    n00b_buffer_t *input)
{
    n00b_http_parse_cookie_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_http_parse_event_t *, xf);

    if (!input || n00b_buffer_len(input) == 0)
        return n00b_option_none(n00b_http_parse_event_t *);

    if (!st->init) {
        st->init  = true;
        st->state = N00B_HTTP_STATE_START;
    }

    int64_t  in_len  = 0;
    char    *in_data = n00b_buffer_to_c(input, &in_len);
    if (in_len <= 0)
        return n00b_option_none(n00b_http_parse_event_t *);

    http_process(xf, st, (const uint8_t *)in_data, (size_t)in_len);

    return n00b_option_none(n00b_http_parse_event_t *);
}

static void
http_parse_flush(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *xf)
{
    n00b_http_parse_cookie_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_http_parse_event_t *, xf);

    if (st->state != N00B_HTTP_STATE_COMPLETE &&
        st->state != N00B_HTTP_STATE_ERROR &&
        st->state != N00B_HTTP_STATE_START) {
        emit_error(xf, st, "unexpected end of data");
    }
}

// ============================================================================
// Ops vtable
// ============================================================================

static n00b_string_t _kind_http_parse = {
    .data = "http_parse", .u8_bytes = 10, .codepoints = 10, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_xform_ops_t(n00b_buffer_t *, n00b_http_parse_event_t *)
    http_parse_ops = {
    .transform = http_parse_transform,
    .flush     = http_parse_flush,
    .kind      = &_kind_http_parse,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *) *)
n00b_conduit_http_parse_new(
    n00b_conduit_t                        *c,
    n00b_conduit_topic_t(n00b_buffer_t *) *upstream)
    _kargs {
        n00b_http_mode_t mode            = N00B_HTTP_MODE_REQUEST;
        size_t           max_header_size = 8192;
        size_t           max_headers     = 100;
        size_t           max_body_size   = 0;
        bool             strict          = false;
    }
{
    auto r = n00b_conduit_xform_new(
        n00b_buffer_t *, n00b_http_parse_event_t *,
        c, upstream, &http_parse_ops,
        sizeof(n00b_http_parse_cookie_t));

    if (n00b_result_is_ok(r)) {
        auto xf = n00b_result_get(r);
        n00b_http_parse_cookie_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_http_parse_event_t *, xf);

        st->mode            = mode;
        st->max_header_size = max_header_size;
        st->max_headers     = max_headers;
        st->max_body_size   = max_body_size;
        st->strict          = strict;
        st->state           = N00B_HTTP_STATE_START;
        st->init            = true;
    }

    return r;
}

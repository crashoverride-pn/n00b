/*
 * test_xform_http.c — Tests for the HTTP parser conduit transform.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/xform_http.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/atomic.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_topic_t(n00b_buffer_t *) *
make_buf_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 7000;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri =
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, id);
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_buffer_t *)));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_buffer_t *) *topic =
        (n00b_conduit_topic_t(n00b_buffer_t *) *)
            n00b_result_get(tr);
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *,
                      .allocator = c->allocator);
    topic->inbox = nullptr;
    return topic;
}

static void
push_buf(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
         const char *data, size_t len)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_alloc_with_opts(
            n00b_conduit_message_t(n00b_buffer_t *),
            &(n00b_alloc_opts_t){.allocator =
                ((n00b_conduit_topic_base_t *)topic)->conduit->allocator});
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = n00b_buffer_from_bytes(
        (char *)data, (int64_t)len,
        .allocator = ((n00b_conduit_topic_base_t *)topic)->conduit->allocator);
    n00b_conduit_topic_deliver_msg(n00b_buffer_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static n00b_http_parse_event_t *
pop_event(n00b_conduit_inbox_t(n00b_http_parse_event_t *) *inbox)
{
    n00b_conduit_message_t(n00b_http_parse_event_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_http_parse_event_t *, inbox);
    if (!msg) return nullptr;
    return msg->payload;
}

typedef struct {
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_http_parse_event_t *)  *xf;
    n00b_conduit_inbox_t(n00b_http_parse_event_t *)                    *inbox;
} http_ctx_t;

static http_ctx_t
setup_http(n00b_conduit_t *c,
           n00b_conduit_topic_t(n00b_buffer_t *) *src,
           n00b_http_mode_t mode)
{
    auto r = n00b_conduit_http_parse_new(c, src, .mode = mode);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(
        n00b_buffer_t *, n00b_http_parse_event_t *, xf);
    out->subscriptions =
        n00b_list_new(
            n00b_conduit_subscription_t(n00b_http_parse_event_t *) *,
            .allocator = c->allocator);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_http_parse_event_t *) *inbox =
        n00b_alloc_with_opts(
            n00b_conduit_inbox_t(n00b_http_parse_event_t *),
            &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_http_parse_event_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_http_parse_event_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    return (http_ctx_t){ .xf = xf, .inbox = inbox };
}

// ============================================================================
// Tests
// ============================================================================

static void
test_http_parse_request(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    http_ctx_t ctx = setup_http(c, src, N00B_HTTP_MODE_REQUEST);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    const char *req = "GET /index.html HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "\r\n";
    push_buf(src, req, strlen(req));
    usleep(150000);

    // Should get: REQUEST_LINE, HEADER, HEADERS_DONE, COMPLETE.
    n00b_http_parse_event_t *evt;

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_REQUEST_LINE);
    assert(evt->request_line.method_len == 3);
    assert(memcmp(evt->request_line.method, "GET", 3) == 0);
    assert(evt->request_line.version_major == 1);
    assert(evt->request_line.version_minor == 1);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADER);
    assert(evt->header.name_len == 4);
    assert(strncmp(evt->header.name, "Host", 4) == 0);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADERS_DONE);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_COMPLETE);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] http parse request\n");
}

static void
test_http_parse_response(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    http_ctx_t ctx = setup_http(c, src, N00B_HTTP_MODE_RESPONSE);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    const char *resp = "HTTP/1.1 200 OK\r\n"
                       "Content-Length: 5\r\n"
                       "\r\n"
                       "hello";
    push_buf(src, resp, strlen(resp));
    usleep(150000);

    n00b_http_parse_event_t *evt;

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_RESPONSE_LINE);
    assert(evt->response_line.status == 200);
    assert(evt->response_line.version_major == 1);
    assert(evt->response_line.version_minor == 1);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADER);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADERS_DONE);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_BODY_CHUNK);
    assert(evt->body_chunk.len == 5);
    assert(memcmp(evt->body_chunk.data, "hello", 5) == 0);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_COMPLETE);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] http parse response\n");
}

static void
test_http_parse_chunked(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    http_ctx_t ctx = setup_http(c, src, N00B_HTTP_MODE_RESPONSE);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    const char *resp = "HTTP/1.1 200 OK\r\n"
                       "Transfer-Encoding: chunked\r\n"
                       "\r\n"
                       "5\r\n"
                       "hello\r\n"
                       "6\r\n"
                       " world\r\n"
                       "0\r\n"
                       "\r\n";
    push_buf(src, resp, strlen(resp));
    usleep(150000);

    n00b_http_parse_event_t *evt;

    // RESPONSE_LINE
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_RESPONSE_LINE);
    assert(evt->response_line.status == 200);

    // HEADER (Transfer-Encoding)
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADER);

    // HEADERS_DONE
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADERS_DONE);

    // First chunk: "hello"
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_BODY_CHUNK);
    assert(evt->body_chunk.len == 5);

    // Second chunk: " world"
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_BODY_CHUNK);
    assert(evt->body_chunk.len == 6);

    // COMPLETE
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_COMPLETE);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] http parse chunked\n");
}

static void
test_http_parse_streaming(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    http_ctx_t ctx = setup_http(c, src, N00B_HTTP_MODE_REQUEST);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Split the request across two buffers.
    const char *part1 = "GET / HTTP/1.1\r\nHost: ex";
    const char *part2 = "ample.com\r\n\r\n";

    push_buf(src, part1, strlen(part1));
    usleep(100000);

    // At this point the request line should have been parsed.
    n00b_http_parse_event_t *evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_REQUEST_LINE);

    // Push the rest.
    push_buf(src, part2, strlen(part2));
    usleep(150000);

    // Should see HEADER, HEADERS_DONE, COMPLETE.
    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADER);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_HEADERS_DONE);

    evt = pop_event(ctx.inbox);
    assert(evt != nullptr);
    assert(evt->type == N00B_HTTP_EVENT_COMPLETE);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] http parse streaming\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform_http:\n");
    fflush(stdout);

    test_http_parse_request();   fflush(stdout);
    test_http_parse_response();  fflush(stdout);
    test_http_parse_chunked();   fflush(stdout);
    test_http_parse_streaming(); fflush(stdout);

    printf("All HTTP transform tests passed.\n");
    n00b_shutdown();
    return 0;
}

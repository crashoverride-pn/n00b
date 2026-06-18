/* test_http_service_unix.c — exercise n00b_http_service over an AF_UNIX
 * socket (the conduit-based listener) together with the conduit-based
 * unix HTTP client n00b_http_request_unix_sync().
 *
 * Covers the WP-028 Phase-1 contract:
 *   1. A service bound to a unix socket serves a GET route round-trip.
 *   2. A POST with a body reaches the handler intact and the JSON
 *      response comes back.
 *   3. An unknown path returns 404.
 *   4. n00b_http_service_socket_path() reports the bound path and
 *      n00b_http_service_port() is 0 for the unix transport.
 *
 * No raw sockets, no pthreads — the conduit machinery is the target.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/file.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "net/http/http_client.h"
#include "net/http/http_service.h"
#include "util/path.h"

typedef struct {
    int            call_count;
    n00b_string_t *last_body;
} echo_state_t;

static void
status_handler(n00b_http_request_t         *req,
               n00b_http_response_writer_t *resp,
               void                        *user_data)
{
    (void)req;
    (void)user_data;
    n00b_http_response_writer_status(resp, 200);
    n00b_http_response_writer_text(resp,
                                   r"{\"status\":\"ok\"}",
                                   .content_type = r"application/json");
}

static void
echo_handler(n00b_http_request_t         *req,
             n00b_http_response_writer_t *resp,
             void                        *user_data)
{
    echo_state_t  *state = user_data;
    n00b_buffer_t *body  = n00b_http_request_body(req);

    state->call_count++;
    state->last_body = nullptr;
    if (body && body->byte_len > 0) {
        state->last_body = n00b_buffer_to_string(body);
    }

    n00b_http_response_writer_status(resp, 202);
    n00b_http_response_writer_text(resp,
                                   r"{\"ok\":true}",
                                   .content_type = r"application/json");
}

static n00b_string_t *
unique_socket_path(void)
{
    n00b_string_t *prefix = n00b_string_from_cstr("libn00b-http-unix-");
    n00b_string_t *suffix = n00b_string_from_cstr(".sock");
    n00b_string_t *path   = n00b_new_temp_path(prefix, suffix);
    (void)n00b_file_unlink(path, .ignore_missing = true);
    return path;
}

static void
test_unix_service_roundtrip(void)
{
    echo_state_t   state = {};
    n00b_string_t *sock  = unique_socket_path();

    n00b_http_service_t *svc = n00b_http_service_new(.socket_path = sock,
                                                     .socket_mode = 0600);
    assert(n00b_result_is_ok(
        n00b_http_service_route(svc, r"GET", r"/v1/status",
                                status_handler, nullptr)));
    assert(n00b_result_is_ok(
        n00b_http_service_route(svc, r"POST", r"/echo",
                                echo_handler, &state)));
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    // Transport identity: unix path is reported, TCP port is 0.
    n00b_option_t(n00b_string_t *) sp_opt = n00b_http_service_socket_path(svc);
    assert(n00b_option_is_set(sp_opt));
    assert(n00b_option_get(sp_opt) == sock);
    assert(n00b_http_service_port(svc) == 0);

    // 1. GET round-trip.
    auto gr = n00b_http_request_unix_sync(sock, r"/v1/status");
    assert(n00b_result_is_ok(gr));
    n00b_http_response_t *gresp = n00b_result_get(gr);
    assert(n00b_http_response_status(gresp) == 200);
    n00b_buffer_t *gbody = n00b_http_response_body(gresp);
    assert(gbody != nullptr);
    assert(gbody->byte_len == (int64_t)strlen("{\"status\":\"ok\"}"));
    assert(memcmp(gbody->data, "{\"status\":\"ok\"}",
                  (size_t)gbody->byte_len)
           == 0);
    printf("  [PASS] unix GET round-trip\n");

    // 2. POST with a body.
    n00b_buffer_t *body = n00b_buffer_from_cstr("{\"hello\":\"world\"}");
    auto pr = n00b_http_request_unix_sync(sock, r"/echo",
                                          .method       = r"POST",
                                          .body         = body,
                                          .content_type = r"application/json");
    assert(n00b_result_is_ok(pr));
    n00b_http_response_t *presp = n00b_result_get(pr);
    assert(n00b_http_response_status(presp) == 202);
    assert(state.call_count == 1);
    assert(state.last_body != nullptr);
    assert(n00b_unicode_str_eq(state.last_body,
                               n00b_string_from_cstr("{\"hello\":\"world\"}"),
                               .case_sensitive = true));
    printf("  [PASS] unix POST body round-trip\n");

    // 3. Unknown path → 404.
    auto nr = n00b_http_request_unix_sync(sock, r"/nope");
    assert(n00b_result_is_ok(nr));
    assert(n00b_http_response_status(n00b_result_get(nr)) == 404);
    printf("  [PASS] unix unknown path → 404\n");

    n00b_http_service_stop(svc);
    (void)n00b_file_unlink(sock, .ignore_missing = true);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    printf("Running http_service unix-socket tests...\n");
    test_unix_service_roundtrip();
    printf("All http_service unix-socket tests passed.\n");

    n00b_shutdown();
    return 0;
}

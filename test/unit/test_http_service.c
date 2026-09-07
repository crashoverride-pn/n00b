/*
 * test_http_service.c — local HTTP/1 service/router tests.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include "internal/win32_sockets.h"
#define TSOCK SOCKET
#define TBAD  INVALID_SOCKET
#define TCLOSE(s) closesocket((SOCKET)(s))
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define TSOCK int
#define TBAD  (-1)
#define TCLOSE(s) close(s)
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "net/http/http_service.h"

typedef struct {
    int seen;
} handler_state_t;

static bool
s_eq(n00b_string_t *s, const char *c)
{
    size_t n = strlen(c);
    return s != nullptr && s->u8_bytes == n
        && (n == 0 || memcmp(s->data, c, n) == 0);
}

static bool
b_eq(n00b_buffer_t *b, const char *c)
{
    size_t n = strlen(c);
    return b != nullptr && b->byte_len == n
        && (n == 0 || memcmp(b->data, c, n) == 0);
}

static bool
send_all(TSOCK fd, const char *p, size_t n)
{
    size_t off = 0;
    while (off < n) {
#ifdef _WIN32
        int rc = send(fd, p + off, (int)(n - off), 0);
#else
        ssize_t rc = send(fd, p + off, n - off, 0);
#endif
        if (rc <= 0) return false;
        off += (size_t)rc;
    }
    return true;
}

static char *
http_round_trip(uint16_t port, const char *request)
{
    TSOCK fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd != TBAD);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(send_all(fd, request, strlen(request)));

    size_t cap = 4096;
    size_t len = 0;
    char  *buf = n00b_alloc_array(char, cap + 1);
    while (true) {
        if (len + 1024 >= cap) {
            cap *= 2;
            char *next = n00b_alloc_array(char, cap + 1);
            memcpy(next, buf, len);
            buf = next;
        }
#ifdef _WIN32
        int rc = recv(fd, buf + len, 1024, 0);
#else
        ssize_t rc = recv(fd, buf + len, 1024, 0);
#endif
        if (rc <= 0) break;
        len += (size_t)rc;
    }
    TCLOSE(fd);
    buf[len] = '\0';
    return buf;
}

static int
status_code(char *resp)
{
    int code = 0;
    assert(sscanf(resp, "HTTP/1.1 %d", &code) == 1);
    return code;
}

static char *
body_ptr(char *resp)
{
    char *p = strstr(resp, "\r\n\r\n");
    assert(p != nullptr);
    return p + 4;
}

static n00b_http_service_t *
start_service(void)
{
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto sr = n00b_http_service_start(svc);
    if (n00b_result_is_err(sr)) {
        fprintf(stderr, "http service start failed: err=%d\n",
                n00b_result_get_err(sr));
    }
    assert(n00b_result_is_ok(sr));
    assert(n00b_http_service_port(svc) != 0);
    return svc;
}

static void
hello_handler(n00b_http_request_t *req,
              n00b_http_response_writer_t *resp,
              void *user_data)
{
    handler_state_t *state = user_data;
    state->seen++;
    assert(s_eq(n00b_http_request_method(req), "GET"));
    assert(s_eq(n00b_http_request_path(req), "/hello"));
    n00b_http_response_writer_text(resp, r"hello");
}

static void
echo_handler(n00b_http_request_t *req,
             n00b_http_response_writer_t *resp,
             void *user_data)
{
    handler_state_t *state = user_data;
    state->seen++;
    assert(s_eq(n00b_http_request_method(req), "POST"));
    assert(s_eq(n00b_http_request_path(req), "/echo"));
    assert(s_eq(n00b_http_request_header(req, r"x-test"), "yes"));
    n00b_http_response_writer_body(resp, n00b_http_request_body(req));
    n00b_http_response_writer_header(resp, r"content-type", r"text/plain");
}

static void
meta_handler(n00b_http_request_t *req,
             n00b_http_response_writer_t *resp,
             void *user_data)
{
    handler_state_t *state = user_data;
    state->seen++;
    assert(s_eq(n00b_http_request_method(req), "GET"));
    assert(s_eq(n00b_http_request_path(req), "/meta"));
    n00b_http_response_writer_text(resp,
                                   r"{\"ok\":true}",
                                   .content_type = r"application/json");
}

static void
test_get_route(void)
{
    handler_state_t state = {};
    n00b_http_service_t *svc = start_service();
    auto rr = n00b_http_service_route(svc, r"GET", r"/hello",
                                      hello_handler, &state);
    assert(n00b_result_is_err(rr));
    n00b_http_service_stop(svc);

    svc = n00b_http_service_new(.bind_port = 0);
    rr = n00b_http_service_route(svc, r"GET", r"/hello",
                                 hello_handler, &state);
    assert(n00b_result_is_ok(rr));
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "GET /hello HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "\r\n");
    assert(status_code(resp) == 200);
    assert(strcmp(body_ptr(resp), "hello") == 0);
    assert(state.seen == 1);
    n00b_http_service_stop(svc);
    printf("  [PASS] GET route on ephemeral port\n");
}

static void
test_post_body_and_header(void)
{
    handler_state_t state = {};
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto rr = n00b_http_service_route(svc, r"POST", r"/echo",
                                      echo_handler, &state);
    assert(n00b_result_is_ok(rr));
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "POST /echo?x=1 HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "X-Test: yes\r\n"
                                 "Content-Length: 7\r\n"
                                 "\r\n"
                                 "payload");
    assert(status_code(resp) == 200);
    assert(strcmp(body_ptr(resp), "payload") == 0);
    assert(state.seen == 1);
    n00b_http_service_stop(svc);
    printf("  [PASS] POST body and header extraction\n");
}

static void
test_404_and_405(void)
{
    handler_state_t state = {};
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto rr = n00b_http_service_route(svc, r"GET", r"/hello",
                                      hello_handler, &state);
    assert(n00b_result_is_ok(rr));
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "GET /missing HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "\r\n");
    assert(status_code(resp) == 404);

    resp = http_round_trip(n00b_http_service_port(svc),
                           "POST /hello HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n");
    assert(status_code(resp) == 405);
    n00b_http_service_stop(svc);
    printf("  [PASS] 404 and 405 routing\n");
}

static void
test_header_limit(void)
{
    n00b_http_service_t *svc =
        n00b_http_service_new(.bind_port = 0, .max_header_bytes = 16);
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "GET /too-long HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "\r\n");
    assert(status_code(resp) == 431);
    n00b_http_service_stop(svc);
    printf("  [PASS] header limit\n");
}

static void
test_body_limit(void)
{
    n00b_http_service_t *svc =
        n00b_http_service_new(.bind_port = 0, .max_body_bytes = 3);
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "POST /x HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "Content-Length: 4\r\n"
                                 "\r\n"
                                 "test");
    assert(status_code(resp) == 413);
    n00b_http_service_stop(svc);
    n00b_http_service_stop(svc);
    printf("  [PASS] body limit and repeat shutdown\n");
}

static void
test_content_length_overflow(void)
{
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "POST /x HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "Content-Length: 18446744073709551616\r\n"
                                 "\r\n");
    assert(status_code(resp) == 400);
    n00b_http_service_stop(svc);
    printf("  [PASS] content-length overflow rejected\n");
}

static void
test_route_metadata_and_discovery(void)
{
    handler_state_t state = {};

    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto rr = n00b_http_get(svc,
                            (n00b_http_endpoint_t){
                                .path = r"/meta",
                                .handler = meta_handler,
                                .user_data = &state,
                                .id = r"getMeta",
                                .summary = r"Get metadata",
                                .tags = n00b_http_tags(r"metadata"),
                                .query = n00b_http_params(
                                    n00b_http_query_param(
                                        r"verbose",
                                        .schema_json = r"{\"type\":\"boolean\"}",
                                        .description = r"include optional details")),
                                .responses = n00b_http_responses(
                                    n00b_http_json_response(
                                        200,
                                        .description = r"metadata response",
                                        .schema_json = r"{\"type\":\"object\",\"required\":[\"ok\"]}")),
                            });
    assert(n00b_result_is_ok(rr));
    rr = n00b_http_service_route(svc, r"GET", r"/legacy",
                                 hello_handler, nullptr);
    assert(n00b_result_is_ok(rr));

    auto dr = n00b_http_discover(svc,
                                 (n00b_http_discovery_doc_t){
                                     .service_id = r"test-service",
                                     .name = r"Test Service",
                                     .version = r"1.2.3",
                                     .api_version = r"v1",
                                     .schemas = n00b_http_schemas(
                                         r"/schemas/test.json"),
                                     .capabilities = n00b_http_capabilities(
                                         r"metadata.read"),
                                 });
    assert(n00b_result_is_ok(dr));
    auto sr = n00b_http_service_start(svc);
    assert(n00b_result_is_ok(sr));

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 "GET /meta?verbose=true HTTP/1.1\r\n"
                                 "Host: 127.0.0.1\r\n"
                                 "\r\n");
    assert(status_code(resp) == 200);
    assert(strstr(body_ptr(resp), "\"ok\":true") != nullptr);
    assert(state.seen == 1);

    resp = http_round_trip(n00b_http_service_port(svc),
                           "GET /openapi.json HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\n"
                           "\r\n");
    assert(status_code(resp) == 200);
    assert(strstr(body_ptr(resp), "\"openapi\":\"3.1.0\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"/meta\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"/legacy\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"/openapi.json\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"/.well-known/openapi.json\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"/.well-known/test-service\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"operationId\":\"getMeta\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"operationId\":\"getOpenAPI\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"operationId\":\"getWellKnownService\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"verbose\"") != nullptr);

    resp = http_round_trip(n00b_http_service_port(svc),
                           "GET /.well-known/openapi.json HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\n"
                           "\r\n");
    assert(status_code(resp) == 200);
    assert(strstr(body_ptr(resp), "\"/meta\"") != nullptr);

    resp = http_round_trip(n00b_http_service_port(svc),
                           "GET /.well-known/test-service HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\n"
                           "\r\n");
    assert(status_code(resp) == 200);
    assert(strstr(body_ptr(resp), "\"service\":\"test-service\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"openapi\":\"/openapi.json\"") != nullptr);
    assert(strstr(body_ptr(resp), "\"metadata.read\"") != nullptr);

    n00b_http_service_stop(svc);
    printf("  [PASS] route metadata and discovery\n");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

#ifdef _WIN32
    WSADATA wsa;
    assert(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#endif

    printf("test_http_service:\n");
    test_get_route();
    test_post_body_and_header();
    test_404_and_405();
    test_header_limit();
    test_body_limit();
    test_content_length_overflow();
    test_route_metadata_and_discovery();
    n00b_shutdown();
    return 0;
}

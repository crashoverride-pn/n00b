/* test_http_leaks.c: per-request memory of the conduit stream reader, the
 * fd-owner bulk read, and the HTTP clients and service built on them.
 *
 * Each case runs a few warm-up requests that move a 256 KiB payload, then
 * counts how many bytes the conduit and system pools map across a batch of
 * further requests. Neither pool is swept by the GC, so anything a request
 * leaves allocated there stays mapped; a request that frees what it allocates
 * reuses the same pages. The bound is a quarter of the payload per request:
 * leaking even one copy of the payload exceeds it, while the fixed per-
 * connection state (fd owner, topics) fits far under it.
 *
 * Peers that are not under test are raw sockets, so they allocate nothing in
 * n00b and every counted byte belongs to the code being measured.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/pool.h"
#include "core/string.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/fd_managed.h"
#include "text/strings/format.h"
#include "net/http/http_client.h"
#include "net/http/http_service.h"

#define PAYLOAD_BYTES (256 * 1024)
#define LINE_BYTES    64
#define WARMUP        3
#define ROUNDS        12
#define LEAK_BOUND    ((int64_t)PAYLOAD_BYTES / 4)

static char g_payload[PAYLOAD_BYTES];
static char g_lines[PAYLOAD_BYTES];
static int  g_failures;

static void
payload_init(void)
{
    for (size_t i = 0; i < PAYLOAD_BYTES; i++) {
        g_payload[i] = (char)('a' + i % 26);
    }
    for (size_t i = 0; i < PAYLOAD_BYTES; i++) {
        g_lines[i] = (i % LINE_BYTES == LINE_BYTES - 1) ? '\n'
                                                        : (char)('a' + i % 26);
    }
}

static uint64_t
pool_mapped_bytes(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    return n00b_pool_mapped_bytes(&rt->conduit_pool)
         + n00b_pool_mapped_bytes(&rt->system_pool);
}

static int64_t
live_pool_count(void)
{
    n00b_pool_global_stats_t st = n00b_pool_global_stats();
    return (int64_t)st.total_init_count - (int64_t)st.total_destroy_count;
}

// Run `one` WARMUP times, then ROUNDS times between two snapshots, and fail
// when the pools grow by more than LEAK_BOUND per request or a pool created
// during a request outlives it.
static void
measure(const char *name, void (*one)(void *), void *ctx)
{
    for (int i = 0; i < WARMUP; i++) {
        one(ctx);
    }

    uint64_t before       = pool_mapped_bytes();
    int64_t  pools_before = live_pool_count();
    for (int i = 0; i < ROUNDS; i++) {
        one(ctx);
    }
    int64_t per_request = ((int64_t)pool_mapped_bytes() - (int64_t)before)
                        / ROUNDS;
    int64_t pools_left  = live_pool_count() - pools_before;

    printf("  %-28s %8lld bytes/request, %lld pools left\n",
           name,
           (long long)per_request,
           (long long)pools_left);
    if (per_request > LEAK_BOUND || pools_left != 0) {
        fprintf(stderr,
                "test_http_leaks: FAIL %s: %lld bytes/request (bound %lld), "
                "%lld pools left\n",
                name,
                (long long)per_request,
                (long long)LEAK_BOUND,
                (long long)pools_left);
        g_failures++;
    }
}

// ---------------------------------------------------------------------------
// Raw-socket helpers
// ---------------------------------------------------------------------------

static int
loopback_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in sa = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    assert(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    return fd;
}

static void
send_all(int fd, const char *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, data + off, len - off, 0);
        assert(n > 0);
        off += (size_t)n;
    }
}

// Read until the peer closes; returns the byte count.
static size_t
drain(int fd)
{
    char   buf[16384];
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return total;
        }
        total += (size_t)n;
    }
}

// ---------------------------------------------------------------------------
// The service under test
// ---------------------------------------------------------------------------

static void
blob_handler(n00b_http_request_t         *req,
             n00b_http_response_writer_t *resp,
             void                        *user_data)
{
    (void)req;
    (void)user_data;
    n00b_http_response_writer_status(resp, 200);
    n00b_http_response_writer_body(resp,
                                   n00b_buffer_from_bytes(g_payload,
                                                          PAYLOAD_BYTES));
}

static void
upload_handler(n00b_http_request_t         *req,
               n00b_http_response_writer_t *resp,
               void                        *user_data)
{
    (void)user_data;
    n00b_buffer_t *body = n00b_http_request_body(req);
    bool           ok   = body != nullptr && body->byte_len == PAYLOAD_BYTES
                 && memcmp(body->data, g_payload, PAYLOAD_BYTES) == 0;
    n00b_http_response_writer_status(resp, ok ? 200 : 400);
    n00b_http_response_writer_text(resp, ok ? r"ok" : r"bad");
}

static void
lines_handler(n00b_http_request_t         *req,
              n00b_http_response_writer_t *resp,
              void                        *user_data)
{
    (void)req;
    (void)user_data;
    n00b_http_response_writer_stream_begin(resp, 200, r"application/x-ndjson");
    (void)n00b_http_response_writer_stream_write(resp, g_lines, PAYLOAD_BYTES);
}

static n00b_http_service_t *
start_service(void)
{
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    assert(n00b_result_is_ok(
        n00b_http_service_route(svc, r"GET", r"/blob", blob_handler, nullptr)));
    assert(n00b_result_is_ok(
        n00b_http_service_route(svc, r"POST", r"/upload", upload_handler,
                                nullptr)));
    assert(n00b_result_is_ok(
        n00b_http_service_route(svc, r"GET", r"/lines", lines_handler,
                                nullptr)));
    assert(n00b_result_is_ok(n00b_http_service_start(svc)));
    return svc;
}

// ---------------------------------------------------------------------------
// 1. Service request side: a raw client uploads the payload.
// ---------------------------------------------------------------------------

static void
service_upload_once(void *ctx)
{
    uint16_t port = *(uint16_t *)ctx;
    int      fd   = loopback_connect(port);
    char     head[256];
    int      n = snprintf(head,
                          sizeof(head),
                          "POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                          "Content-Length: %d\r\nConnection: close\r\n\r\n",
                          PAYLOAD_BYTES);
    send_all(fd, head, (size_t)n);
    send_all(fd, g_payload, PAYLOAD_BYTES);
    char   status[12];
    size_t got = 0;
    while (got < sizeof(status)) {
        ssize_t r = recv(fd, status + got, sizeof(status) - got, 0);
        assert(r > 0);
        got += (size_t)r;
    }
    assert(memcmp(status, "HTTP/1.1 200", sizeof(status)) == 0);
    (void)drain(fd);
    close(fd);
}

// ---------------------------------------------------------------------------
// 2. n00b_fd_owner_read_all over a pipe.
// ---------------------------------------------------------------------------

static void *
pipe_writer(void *arg)
{
    int fd = *(int *)arg;
    size_t off = 0;
    while (off < PAYLOAD_BYTES) {
        ssize_t n = write(fd, g_payload + off, PAYLOAD_BYTES - off);
        assert(n > 0);
        off += (size_t)n;
    }
    close(fd);
    return nullptr;
}

static void
read_all_once(void *ctx)
{
    (void)ctx;
    n00b_conduit_t *c      = n00b_get_runtime()->default_conduit;
    auto            io_opt = n00b_conduit_default_backend(c);
    assert(n00b_option_is_set(io_opt));

    int fds[2];
    assert(pipe(fds) == 0);
    auto owner_r = n00b_conduit_fd_manage(c, n00b_option_get(io_opt), fds[0],
                                          true);
    assert(n00b_result_is_ok(owner_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(owner_r);

    pthread_t writer;
    assert(pthread_create(&writer, nullptr, pipe_writer, &fds[1]) == 0);
    auto rr = n00b_fd_owner_read_all(owner);
    pthread_join(writer, nullptr);

    assert(n00b_result_is_ok(rr));
    n00b_buffer_t *got = n00b_result_get(rr);
    assert(got->byte_len == PAYLOAD_BYTES);
    assert(memcmp(got->data, g_payload, PAYLOAD_BYTES) == 0);
    n00b_conduit_fd_owner_close(owner);
}

// ---------------------------------------------------------------------------
// 3. n00b_http_request_sync (plain HTTP) against a raw server.
// ---------------------------------------------------------------------------

typedef struct {
    int listen_fd;
    int connections;
} raw_server_t;

static void *
raw_server_main(void *arg)
{
    raw_server_t *srv = arg;
    char          head[128];
    int           n = snprintf(head,
                               sizeof(head),
                               "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                               "Connection: close\r\n\r\n",
                               PAYLOAD_BYTES);
    for (int i = 0; i < srv->connections; i++) {
        int fd = accept(srv->listen_fd, nullptr, nullptr);
        assert(fd >= 0);
        char   req[4096];
        size_t have = 0;
        while (have < 4 || memcmp(req + have - 4, "\r\n\r\n", 4) != 0) {
            ssize_t r = recv(fd, req + have, 1, 0);
            assert(r == 1);
            have++;
            assert(have < sizeof(req));
        }
        send_all(fd, head, (size_t)n);
        send_all(fd, g_payload, PAYLOAD_BYTES);
        close(fd);
    }
    return nullptr;
}

static void
request_sync_once(void *ctx)
{
    n00b_string_t *url = ctx;
    auto rr = n00b_http_request_sync(url, .allow_plain_http = true);
    assert(n00b_result_is_ok(rr));
    n00b_http_response_t *resp = n00b_result_get(rr);
    assert(n00b_http_response_status(resp) == 200);
    n00b_buffer_t *body = n00b_http_response_body(resp);
    assert(body->byte_len == PAYLOAD_BYTES);
    assert(memcmp(body->data, g_payload, PAYLOAD_BYTES) == 0);
}

static void
test_request_sync(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in sa = {
        .sin_family      = AF_INET,
        .sin_port        = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t len = sizeof(sa);
    assert(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    assert(listen(fd, 16) == 0);
    assert(getsockname(fd, (struct sockaddr *)&sa, &len) == 0);

    raw_server_t srv = {.listen_fd = fd, .connections = WARMUP + ROUNDS};
    pthread_t    server;
    assert(pthread_create(&server, nullptr, raw_server_main, &srv) == 0);

    n00b_string_t *url = n00b_cformat("http://127.0.0.1:[|#|]/blob",
                                      (int64_t)ntohs(sa.sin_port));
    measure("request_sync (plain)", request_sync_once, url);

    pthread_join(server, nullptr);
    close(fd);
}

// ---------------------------------------------------------------------------
// 4. n00b_http_request_tcp_sync and 5. n00b_http_request_tcp_stream against
//    the service, so both ends are n00b.
// ---------------------------------------------------------------------------

static void
tcp_sync_once(void *ctx)
{
    uint16_t port = *(uint16_t *)ctx;
    auto     rr   = n00b_http_request_tcp_sync(r"127.0.0.1", port, r"/blob");
    assert(n00b_result_is_ok(rr));
    n00b_http_response_t *resp = n00b_result_get(rr);
    assert(n00b_http_response_status(resp) == 200);
    n00b_buffer_t *body = n00b_http_response_body(resp);
    assert(body->byte_len == PAYLOAD_BYTES);
    assert(memcmp(body->data, g_payload, PAYLOAD_BYTES) == 0);
}

static bool
count_line(void *ctx, n00b_string_t *line)
{
    (void)line;
    (*(int *)ctx)++;
    return true;
}

static void
tcp_stream_once(void *ctx)
{
    uint16_t port  = *(uint16_t *)ctx;
    int      lines = 0;
    auto     rr    = n00b_http_request_tcp_stream(r"127.0.0.1", port,
                                                  r"/lines", count_line,
                                                  &lines);
    assert(n00b_result_is_ok(rr));
    assert(n00b_result_get(rr) == 200);
    assert(lines == PAYLOAD_BYTES / LINE_BYTES);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);
    payload_init();

    printf("Running http leak tests...\n");

    n00b_http_service_t *svc  = start_service();
    uint16_t             port = n00b_http_service_port(svc);

    measure("service upload", service_upload_once, &port);
    measure("fd_owner_read_all", read_all_once, nullptr);
    test_request_sync();
    measure("tcp_sync", tcp_sync_once, &port);
    measure("tcp_stream", tcp_stream_once, &port);

    n00b_http_service_stop(svc);

    if (g_failures != 0) {
        fprintf(stderr, "test_http_leaks: %d case(s) failed\n", g_failures);
        n00b_shutdown();
        return 1;
    }
    printf("All http leak tests passed.\n");
    n00b_shutdown();
    return 0;
}

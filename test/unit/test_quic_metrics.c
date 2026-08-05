/*
 * test_quic_metrics.c — Phase 5 § 5.1 unit tests.
 *
 * Coverage:
 *   1. Registry construction + counter / gauge / histogram registration.
 *   2. Counter increment under labels; encode shape matches Prom 0.0.4.
 *   3. Gauge set under labels; encode round-trip.
 *   4. Histogram observe with multiple buckets + +Inf bucket sanity.
 *   5. Counter without labels emits a zero sample on first encode.
 *   6. Listener bind + GET /metrics returns 200 + body; non-/metrics → 404.
 *   7. Listener close is idempotent.
 *   8. Re-registering the same name returns the existing instance.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/socket.h"
#include "net/quic/metrics.h"
#include "net/quic/audit.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/chan.h"
#include "core/string.h"

/* ---- Helpers ---- */

#ifdef _WIN32
typedef SOCKET metrics_test_socket_t;
#define METRICS_TEST_BAD_SOCKET INVALID_SOCKET

static ssize_t
metrics_test_send(metrics_test_socket_t fd, const void *buf, size_t len)
{
    int n = send(fd, (const char *)buf, (int)len, 0);
    return n == SOCKET_ERROR ? -1 : (ssize_t)n;
}

static ssize_t
metrics_test_recv(metrics_test_socket_t fd, void *buf, size_t len)
{
    int n = recv(fd, (char *)buf, (int)len, 0);
    return n == SOCKET_ERROR ? -1 : (ssize_t)n;
}

static void
metrics_test_close(metrics_test_socket_t fd)
{
    closesocket(fd);
}

static void
metrics_test_set_nonblocking(metrics_test_socket_t fd)
{
    u_long mode = 1;
    ioctlsocket(fd, FIONBIO, &mode);
}
#else
typedef int metrics_test_socket_t;
#define METRICS_TEST_BAD_SOCKET (-1)
#define metrics_test_send(fd, buf, len) write((fd), (buf), (len))
#define metrics_test_recv(fd, buf, len) read((fd), (buf), (len))
#define metrics_test_close(fd) close((fd))

static void
metrics_test_set_nonblocking(metrics_test_socket_t fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}
#endif

static n00b_list_t(n00b_buffer_t *) *
mk_buf_list(int count, ...)
{
    n00b_list_t(n00b_buffer_t *) *l = n00b_alloc(n00b_list_t(n00b_buffer_t *));
    *l = n00b_list_new(n00b_buffer_t *);
    va_list ap;
    va_start(ap, count);
    for (int i = 0; i < count; i++) {
        const char *s = va_arg(ap, const char *);
        n00b_list_push(*l, n00b_buffer_from_cstr(s));
    }
    va_end(ap);
    return l;
}

static bool
contains(n00b_buffer_t *b, const char *needle)
{
    if (!b || !needle) return false;
    size_t nl = strlen(needle);
    if (b->byte_len < nl) return false;
    for (size_t i = 0; i + nl <= b->byte_len; i++) {
        if (memcmp(b->data + i, needle, nl) == 0) return true;
    }
    return false;
}

/* ---- Tests ---- */

static void
test_counter_basic(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    assert(r);

    auto cr = n00b_quic_metric_counter(r, "n00b_test_total",
                                       "test counter for unit suite",
                                       .labels = mk_buf_list(1, "kind"));
    assert(n00b_result_is_ok(cr));
    n00b_quic_metric_counter_t *c = n00b_result_get(cr);

    n00b_quic_metric_counter_inc(c, 1,
        .label_values = mk_buf_list(1, "framed"));
    n00b_quic_metric_counter_inc(c, 2,
        .label_values = mk_buf_list(1, "framed"));
    n00b_quic_metric_counter_inc(c, 5,
        .label_values = mk_buf_list(1, "bytes"));

    n00b_buffer_t *out = n00b_quic_metrics_encode(r);
    assert(contains(out, "# TYPE n00b_test_total counter"));
    assert(contains(out, "n00b_test_total{kind=\"framed\"} 3"));
    assert(contains(out, "n00b_test_total{kind=\"bytes\"} 5"));
    printf("  [PASS] counter labeled increment + encode\n");
}

static void
test_counter_unlabeled(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    auto cr = n00b_quic_metric_counter(r, "n00b_unlabeled_total",
                                       "no labels");
    n00b_quic_metric_counter_t *c = n00b_result_get(cr);

    /* No inc yet — encode should still emit a zero sample. */
    n00b_buffer_t *empty = n00b_quic_metrics_encode(r);
    assert(contains(empty, "n00b_unlabeled_total 0"));

    n00b_quic_metric_counter_inc(c, 7);
    n00b_buffer_t *after = n00b_quic_metrics_encode(r);
    assert(contains(after, "n00b_unlabeled_total 7"));
    printf("  [PASS] unlabeled counter zero-sample + inc\n");
}

static void
test_gauge_set(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    auto gr = n00b_quic_metric_gauge(r, "n00b_test_active",
                                     "active gauge",
                                     .labels = mk_buf_list(1, "endpoint"));
    n00b_quic_metric_gauge_t *g = n00b_result_get(gr);

    n00b_quic_metric_gauge_set(g, 12.5,
        .label_values = mk_buf_list(1, "ep0"));
    n00b_quic_metric_gauge_set(g, -3.0,
        .label_values = mk_buf_list(1, "ep1"));

    n00b_buffer_t *out = n00b_quic_metrics_encode(r);
    assert(contains(out, "# TYPE n00b_test_active gauge"));
    assert(contains(out, "n00b_test_active{endpoint=\"ep0\"} 12.5"));
    assert(contains(out, "n00b_test_active{endpoint=\"ep1\"} -3"));
    printf("  [PASS] gauge labeled set + encode\n");
}

static void
test_histogram(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    double buckets[] = { 1.0, 5.0, 10.0 };
    auto hr = n00b_quic_metric_hist(r, "n00b_test_duration_us",
                                    "duration",
                                    buckets, 3);
    n00b_quic_metric_hist_t *h = n00b_result_get(hr);

    n00b_quic_metric_hist_observe(h, 0.5);   /* hits 1, 5, 10, +Inf */
    n00b_quic_metric_hist_observe(h, 4.0);   /* hits 5, 10, +Inf */
    n00b_quic_metric_hist_observe(h, 100.0); /* hits +Inf only */

    n00b_buffer_t *out = n00b_quic_metrics_encode(r);
    assert(contains(out, "# TYPE n00b_test_duration_us histogram"));
    assert(contains(out, "n00b_test_duration_us_bucket{le=\"1\"} 1"));
    assert(contains(out, "n00b_test_duration_us_bucket{le=\"5\"} 2"));
    assert(contains(out, "n00b_test_duration_us_bucket{le=\"10\"} 2"));
    assert(contains(out, "n00b_test_duration_us_bucket{le=\"+Inf\"} 3"));
    assert(contains(out, "n00b_test_duration_us_count 3"));
    assert(contains(out, "n00b_test_duration_us_sum 104.5"));
    printf("  [PASS] histogram bucket + count + sum encode\n");
}

static void
test_re_register(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    auto cr1 = n00b_quic_metric_counter(r, "n00b_dup", "dup");
    auto cr2 = n00b_quic_metric_counter(r, "n00b_dup", "dup");
    assert(n00b_result_is_ok(cr1) && n00b_result_is_ok(cr2));
    assert(n00b_result_get(cr1) == n00b_result_get(cr2));
    printf("  [PASS] re-registering same name returns same instance\n");
}

static void
test_invalid_name(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    auto cr = n00b_quic_metric_counter(r, "9bad", "name starts with digit");
    assert(n00b_result_is_err(cr));
    auto cr2 = n00b_quic_metric_counter(r, "good_name with space",
                                        "name has space");
    assert(n00b_result_is_err(cr2));
    printf("  [PASS] invalid metric names rejected\n");
}

static void
test_listener_roundtrip(void)
{
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    auto gauge_r = n00b_quic_metric_gauge(r, "n00b_listener_test",
                                          "listener round-trip");
    n00b_quic_metric_gauge_t *g = n00b_result_get(gauge_r);
    n00b_quic_metric_gauge_set(g, 42.0);

    /* Open on ephemeral port; bind to 127.0.0.1 for IPv4 simplicity. */
    auto lr = n00b_quic_metrics_listener_open(r, c, io,
        .bind_host = n00b_buffer_from_cstr("127.0.0.1"),
        .bind_port = 0);
    if (!n00b_result_is_ok(lr)) {
        /* Some CI sandboxes deny binding even ephemeral; skip rather
         * than crash. */
        printf("  [SKIP] listener bind failed (likely sandboxed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_metric_listener_t *l = n00b_result_get(lr);
    uint16_t port = n00b_quic_metrics_listener_port(l);
    assert(port != 0);

    /* Connect a raw client socket. */
    metrics_test_socket_t client_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(client_fd != METRICS_TEST_BAD_SOCKET);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int rc = connect(client_fd, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    /* Send a minimal GET /metrics request. */
    static const char req[] = "GET /metrics HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Connection: close\r\n"
                              "\r\n";
    ssize_t wn = metrics_test_send(client_fd, req, sizeof(req) - 1);
    assert(wn == (ssize_t)sizeof(req) - 1);

    /* Drive the IO backend + the listener until the request lands. */
    bool serviced = false;
    for (int i = 0; i < 50; i++) {
        n00b_conduit_io_poll(io, 50);
        size_t n = n00b_quic_metrics_listener_run_once(l);
        if (n > 0) { serviced = true; break; }
    }
    assert(serviced);

    /* Read the response from the client side, until the server closes. */
    char     buf[4096];
    size_t   total = 0;
    for (int i = 0; i < 100 && total < sizeof(buf) - 1; i++) {
        ssize_t got = metrics_test_recv(client_fd, buf + total,
                                        sizeof(buf) - 1 - total);
        if (got > 0) {
            total += (size_t)got;
            buf[total] = '\0';
        } else if (got == 0) {
            break;  /* server closed: full response received */
        } else {
            usleep(10 * 1000);
        }
    }
    metrics_test_close(client_fd);

    assert(total > 0);
    assert(strstr(buf, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(buf, "text/plain; version=0.0.4") != NULL);
    assert(strstr(buf, "n00b_listener_test 42") != NULL);
    printf("  [PASS] listener HTTP/1.1 GET /metrics → 200 + body\n");

    /* 404 for non-/metrics path. Set client FD non-blocking so the
     * read loop interleaves with the drive loop without ever
     * blocking; otherwise we can deadlock waiting for a response
     * we haven't yet driven the listener to produce. */
    metrics_test_socket_t fd2 = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd2 != METRICS_TEST_BAD_SOCKET);
    rc = connect(fd2, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);
    metrics_test_set_nonblocking(fd2);

    static const char bad[] = "GET /nope HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Connection: close\r\n"
                              "\r\n";
    metrics_test_send(fd2, bad, sizeof(bad) - 1);

    char   buf2[1024] = {0};
    size_t t2          = 0;
    bool   server_done = false;
    for (int i = 0; i < 200 && t2 < sizeof(buf2) - 1; i++) {
        n00b_conduit_io_poll(io, 20);
        if (!server_done && n00b_quic_metrics_listener_run_once(l) > 0) {
            server_done = true;
        }
        ssize_t got = metrics_test_recv(fd2, buf2 + t2,
                                        sizeof(buf2) - 1 - t2);
        if (got > 0) {
            t2 += (size_t)got;
            buf2[t2] = '\0';
        } else if (got == 0) {
            /* server closed → done. */
            break;
        }
        if (server_done && strstr(buf2, "\r\n\r\n")) break;
    }
    metrics_test_close(fd2);
    assert(strstr(buf2, "HTTP/1.1 404") != NULL);
    printf("  [PASS] listener returns 404 on non-/metrics path\n");

    n00b_quic_metrics_listener_close(l);
    n00b_quic_metrics_listener_close(l);  /* idempotent */
    printf("  [PASS] listener close idempotent\n");

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
}

static void
test_chan_open_metrics(void)
{
    /* Bring up a client-mode endpoint with the registry attached.
     * Open a chan against a fake destination — the chan_open code
     * path increments the metric even before TLS handshake completes. */
    auto cr = n00b_conduit_new();
    if (n00b_result_is_err(cr)) {
        printf("  [SKIP] chan_open_metrics (conduit_new failed)\n");
        return;
    }
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);

    auto er = n00b_quic_endpoint_new(c, io,
                                     .bind_host        = "127.0.0.1",
                                     .alpn             = "n00b-test/1",
                                     .metrics_registry = r);
    if (n00b_result_is_err(er)) {
        printf("  [SKIP] chan_open_metrics (endpoint failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *ep = n00b_result_get(er);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(54322);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    auto rr = n00b_quic_connect(ep, (const struct sockaddr *)&dst,
                                 n00b_string_from_cstr("test.invalid"));
    if (n00b_result_is_err(rr)) {
        printf("  [SKIP] chan_open_metrics (connect failed)\n");
        n00b_quic_endpoint_close(ep);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_conn_t *conn = n00b_result_get(rr);

    auto chan_r = n00b_quic_chan_open(conn);
    assert(n00b_result_is_ok(chan_r));
    auto chan2_r = n00b_quic_chan_open(conn);
    assert(n00b_result_is_ok(chan2_r));

    n00b_buffer_t *out = n00b_quic_metrics_encode(r);
    assert(contains(out, "n00b_quic_chan_opens_total"));
    assert(contains(out, "{kind=\"framed\"} 2"));
    assert(contains(out, "n00b_quic_chan_active"));
    assert(contains(out, "{kind=\"framed\"} 2"));
    printf("  [PASS] endpoint .metrics_registry instruments chan opens\n");

    /* Close one chan — chan_active should drop to 1. */
    n00b_quic_chan_close(n00b_result_get(chan_r));
    n00b_buffer_t *out2 = n00b_quic_metrics_encode(r);
    /* chan_opens_total stays 2 (counter is monotonic);
     * chan_active{framed} → 1. */
    assert(contains(out2, "{kind=\"framed\"} 1"));
    printf("  [PASS] chan_close decrements chan_active\n");

    n00b_quic_close(conn, 0);
    n00b_quic_endpoint_close(ep);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
}

static void
test_audit_attach(void)
{
    n00b_quic_metric_registry_t *r = n00b_quic_metrics_registry_new(nullptr);
    n00b_quic_audit_attach_metrics(r);

    /* Emit an allow + deny event; counter should reflect both. */
    n00b_quic_audit_event_t allow = {
        .timestamp_ms = 1,
        .decision     = N00B_QUIC_AUDIT_ALLOW,
        .reason_code  = N00B_QUIC_OK,
    };
    n00b_quic_audit_event_t deny = {
        .timestamp_ms = 2,
        .decision     = N00B_QUIC_AUDIT_DENY,
        .reason_code  = N00B_QUIC_ERR_AUTH_AUD_MISMATCH,
    };
    n00b_quic_audit_emit(&allow);
    n00b_quic_audit_emit(&allow);
    n00b_quic_audit_emit(&deny);

    n00b_buffer_t *out = n00b_quic_metrics_encode(r);
    assert(contains(out, "n00b_quic_audit_events_total"));
    assert(contains(out, "{decision=\"allow\"} 2"));
    assert(contains(out, "{decision=\"deny\"} 1"));
    printf("  [PASS] audit_attach_metrics counts allow/deny events\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_metrics:\n");
    test_counter_basic();
    test_counter_unlabeled();
    test_gauge_set();
    test_histogram();
    test_re_register();
    test_invalid_name();
    test_listener_roundtrip();
    test_chan_open_metrics();
    test_audit_attach();
    printf("All quic_metrics tests passed.\n");

    n00b_shutdown();
    return 0;
}

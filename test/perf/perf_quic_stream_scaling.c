/*
 * test/perf/perf_quic_stream_scaling.c — Measure per-stream cost.
 *
 * Per `docs/quic/stream_budgets.md`, this harness sweeps N in
 * {10, 50, 100, 500, 1000} concurrent bidi channels on a single
 * connection between two in-process endpoints over loopback.  For
 * each N it records:
 *
 *   - process RSS delta from baseline (bytes per stream, very rough)
 *   - wall-clock time to open + echo + close all N streams
 *   - p50 / p99 per-stream echo round-trip latency (microseconds)
 *
 * Output is a human-readable table on stdout plus a small block at
 * the bottom that can be copy-pasted into
 * `docs/quic/stream_budgets.md` § Currently measured numbers.
 *
 * Run:
 *
 *     bash build.sh
 *     ./build_debug/perf_quic_stream_scaling
 *
 * Caveats:
 *
 *   - Loopback measurements only.  Real-network latency dominates RTT,
 *     not stream count, so this harness specifically isolates the
 *     stream-table cost.
 *   - macOS reports `ru_maxrss` in bytes; Linux in kilobytes.  We
 *     normalize to bytes.
 *   - For N ≥ 1000 we crank picoquic's transport parameters so the
 *     server actually allows that many concurrent streams.  The
 *     defaults (100/100) are deliberately tight for production
 *     server endpoints; this harness is the place to measure where
 *     the cost curves bend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/resource.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/time.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/chan.h"
#include "internal/net/quic/endpoint_internal.h"

#include "picoquic.h"

#include "../fixtures/quic_test_pki.h"

/* ===========================================================================
 * Resident-set-size helper, normalized to bytes.
 * =========================================================================== */
static size_t
rss_bytes(void)
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc = {0};
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              (PROCESS_MEMORY_COUNTERS *)&pmc,
                              sizeof(pmc))) {
        return 0;
    }
    return (size_t)pmc.WorkingSetSize;
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0;
#if defined(__APPLE__)
    return (size_t)ru.ru_maxrss;            /* macOS: already in bytes */
#else
    return (size_t)ru.ru_maxrss * 1024u;    /* Linux: KiB → bytes */
#endif
#endif
}

/* ===========================================================================
 * Per-stream echo callback (server side).
 *
 * We use the n00b API on the server: subscribe to accept topic, then
 * walk channels and echo received bytes.  Same as the echo example.
 * =========================================================================== */

static void
server_echo_walk(n00b_quic_conn_t *conn)
{
    n00b_quic_chan_t *c;
    for (c = n00b_quic_conn_first_chan(conn);
         c != NULL;
         c = n00b_quic_chan_next_in_conn(c)) {
        if (!n00b_quic_chan_has_data(c) && !n00b_quic_chan_recv_fin(c)) continue;
        uint8_t buf[2048];
        size_t  pulled = 0;
        while (n00b_quic_chan_has_data(c)) {
            auto rr = n00b_quic_chan_recv(c, buf + pulled,
                                          sizeof(buf) - pulled);
            if (n00b_result_is_err(rr)) break;
            size_t n = n00b_result_get(rr);
            if (n == 0) break;
            pulled += n;
            if (pulled == sizeof(buf)) break;
        }
        bool send_fin =
            n00b_quic_chan_recv_fin(c)
            && n00b_quic_chan_state(c) != N00B_QUIC_CHAN_STATE_SEND_HALF_CLOSED
            && n00b_quic_chan_state(c) != N00B_QUIC_CHAN_STATE_CLOSED;
        if (pulled > 0 || send_fin) {
            (void)n00b_quic_chan_send(c, buf, pulled, .fin = send_fin);
        }
    }
}

/* ===========================================================================
 * One sweep at fixed N.
 * =========================================================================== */

typedef struct {
    int    n;
    size_t rss_delta;
    uint64_t wall_us;
    uint64_t p50_us;
    uint64_t p99_us;
    bool   ok;
} measurement_t;

static int
cmp_u64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static measurement_t
sweep(int n_streams)
{
    measurement_t m = {.n = n_streams};

    char *key_pem_path = n00b_quic_test_write_key_pem();
    if (!key_pem_path) return m;

    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    /* Server. */
    auto sr = n00b_quic_endpoint_new(c, io,
                                     .listen         = true,
                                     .bind_host      = "127.0.0.1",
                                     .alpn           = "n00b-perf/1",
                                     .cert_der_bytes = n00b_quic_test_cert_der,
                                     .cert_der_len   = n00b_quic_test_cert_der_len,
                                     .key_pem_path   = key_pem_path);
    if (n00b_result_is_err(sr)) {
        unlink(key_pem_path); free(key_pem_path);
        n00b_conduit_io_destroy(io); n00b_conduit_destroy(c);
        return m;
    }
    n00b_quic_endpoint_t *server = n00b_result_get(sr);

    /* Crank stream limits high enough.  Default is 100; we want
     * room for our N + headroom. */
    uint64_t max_streams = (uint64_t)(n_streams + 100);
    picoquic_set_default_tp_value(server->quic,
                                  picoquic_tp_initial_max_streams_bidi,
                                  max_streams);

    n00b_option_t(n00b_conduit_topic_base_t *) atopic_opt =
        n00b_quic_endpoint_accept_topic(server);
    assert(n00b_option_is_set(atopic_opt));
    n00b_conduit_topic_base_t *atopic = n00b_option_get(atopic_opt);
    n00b_quic_accept_inbox_t *ainbox = n00b_quic_accept_inbox_new(c);
    n00b_quic_accept_subscribe(atopic, ainbox,
                               .operations = N00B_CONDUIT_OP_ALL);

    /* Client. */
    auto cur = n00b_quic_endpoint_new(c, io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = "n00b-perf/1");
    n00b_quic_endpoint_t *client = n00b_result_get(cur);
    picoquic_set_default_tp_value(client->quic,
                                  picoquic_tp_initial_max_streams_bidi,
                                  max_streams);
    picoquic_set_null_verifier(client->quic);

    uint16_t           sport = n00b_quic_endpoint_local_port(server);
    struct sockaddr_in dst   = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(sport);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    n00b_quic_conn_t *conn = n00b_result_get(
        n00b_quic_connect(client,
                          (const struct sockaddr *)&dst,
                          n00b_string_from_cstr("quic-test.n00b.local")));

    /* Drive handshake. */
    for (int i = 0; i < 200; i++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);
        if (n00b_quic_conn_state(conn) == N00B_QUIC_CONN_STATE_CONNECTED) break;
    }
    if (n00b_quic_conn_state(conn) != N00B_QUIC_CONN_STATE_CONNECTED) {
        goto cleanup;
    }

    /* Drain the server's accept event so we have its conn handle. */
    n00b_quic_conn_t *server_conn = NULL;
    for (int i = 0; i < 50 && !server_conn; i++) {
        n00b_quic_endpoint_run_once(server, 5);
        while (n00b_quic_accept_inbox_has_messages(ainbox)) {
            n00b_quic_accept_msg_t *am = n00b_quic_accept_inbox_pop(ainbox);
            if (am) server_conn = am->payload.conn;
        }
    }
    if (!server_conn) goto cleanup;

    size_t rss_before = rss_bytes();
    uint64_t wall_start = (uint64_t)n00b_us_timestamp();

    /* Open N channels and send a small payload + FIN on each. */
    n00b_quic_chan_t **chans  = calloc((size_t)n_streams,
                                       sizeof(*chans));
    uint64_t          *t_open = calloc((size_t)n_streams, sizeof(uint64_t));
    uint64_t          *t_recv = calloc((size_t)n_streams, sizeof(uint64_t));

    for (int i = 0; i < n_streams; i++) {
        auto chr = n00b_quic_chan_open(conn);
        if (n00b_result_is_err(chr)) {
            /* Out of stream IDs? */
            n_streams = i;
            break;
        }
        chans[i] = n00b_result_get(chr);
        t_open[i] = (uint64_t)n00b_us_timestamp();

        /* Tiny payload — we're measuring stream-table cost, not
         * goodput. */
        char msg[32];
        int  mlen = snprintf(msg, sizeof(msg), "stream-%d", i);
        n00b_quic_chan_send(chans[i], (const uint8_t *)msg, (size_t)mlen,
                            .fin = true);
    }

    /* Drive both sides until every channel has its echo back. */
    int    completed = 0;
    bool  *done      = calloc((size_t)n_streams, sizeof(bool));
    for (int iter = 0; iter < 10000 && completed < n_streams; iter++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);
        server_echo_walk(server_conn);

        for (int i = 0; i < n_streams; i++) {
            if (done[i]) continue;
            n00b_quic_chan_t *ch = chans[i];
            if (n00b_quic_chan_has_data(ch)) {
                uint8_t tmp[64];
                (void)n00b_quic_chan_recv(ch, tmp, sizeof(tmp));
            }
            if (n00b_quic_chan_recv_fin(ch)) {
                t_recv[i] = (uint64_t)n00b_us_timestamp() - t_open[i];
                done[i] = true;
                completed++;
            }
        }
    }

    uint64_t wall_end = (uint64_t)n00b_us_timestamp();
    size_t rss_after = rss_bytes();

    if (completed == n_streams) {
        m.ok = true;
        m.wall_us = wall_end - wall_start;
        m.rss_delta = (rss_after >= rss_before) ? (rss_after - rss_before) : 0;
        qsort(t_recv, (size_t)n_streams, sizeof(uint64_t), cmp_u64);
        m.p50_us = t_recv[n_streams / 2];
        m.p99_us = t_recv[(int)((double)n_streams * 0.99)];
    }

    free(chans); free(t_open); free(t_recv); free(done);

cleanup:
    n00b_quic_close(conn, 0);
    n00b_quic_endpoint_close(client);
    n00b_quic_endpoint_close(server);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    unlink(key_pem_path); free(key_pem_path);
    return m;
}

/* =========================================================================== */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    static const int sizes[] = {10, 50, 100, 500, 1000};
    static const size_t n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    measurement_t results[sizeof(sizes)/sizeof(sizes[0])] = {0};

    printf("perf_quic_stream_scaling\n");
    printf("%-8s %-10s %-12s %-12s %-12s %-10s\n",
           "N", "ok", "wall_ms", "p50_us", "p99_us", "rss_delta");
    fflush(stdout);

    for (size_t i = 0; i < n_sizes; i++) {
        results[i] = sweep(sizes[i]);
        printf("%-8d %-10s %-12llu %-12llu %-12llu %-10zu\n",
               results[i].n,
               results[i].ok ? "ok" : "FAIL",
               (unsigned long long)(results[i].wall_us / 1000),
               (unsigned long long)results[i].p50_us,
               (unsigned long long)results[i].p99_us,
               results[i].rss_delta);
        fflush(stdout);
    }

    /* Summary block, ready to paste into stream_budgets.md. */
    printf("\n--- copy into docs/quic/stream_budgets.md ---\n");
    for (size_t i = 0; i < n_sizes; i++) {
        if (results[i].ok && results[i].n > 0) {
            size_t per_stream =
                results[i].rss_delta / (size_t)results[i].n;
            printf("| %d | %zu B | %llu us | %llu us |\n",
                   results[i].n,
                   per_stream,
                   (unsigned long long)results[i].p50_us,
                   (unsigned long long)results[i].p99_us);
        }
    }

    n00b_shutdown();
    return 0;
}

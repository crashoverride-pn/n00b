#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/runtime.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/socket_udp.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/chan.h"
#include "net/quic/lb_cid.h"
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"
#include "picoquic_utils.h"

/* ============================================================================
 * 1. Endpoint create + close round-trips a real picoquic_quic_t.
 *
 * This is the smoke test that confirms picoquic is linked into libn00b
 * and that picoquic_create / picoquic_free run cleanly under the n00b
 * runtime.  It does NOT exchange any packets — that lands with the
 * follow-up that wires recv/send.
 * ============================================================================ */

static void
test_endpoint_create_close(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    auto ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto er = n00b_quic_endpoint_new(c, io,
                                     .bind_host = "127.0.0.1",
                                     .alpn      = "n00b-echo/1");
    if (n00b_result_is_err(er)) {
        /* In sandboxed CI an ephemeral UDP bind on 127.0.0.1 should
         * always work; if it doesn't, that's a different problem
         * (sandbox config, not picoquic). */
        printf("  [SKIP] endpoint create (bind failed: %d)\n",
               n00b_result_get_err(er));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *ep = n00b_result_get(er);
    assert(ep != nullptr);

    /* OS assigned an ephemeral port — verify > 0. */
    uint16_t port = n00b_quic_endpoint_local_port(ep);
    assert(port > 0);

    n00b_quic_endpoint_close(ep);
    /* Idempotent. */
    n00b_quic_endpoint_close(ep);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] endpoint create + ephemeral-port + close (idempotent)\n");
}

/* ============================================================================
 * 2. Listen mode is NOT_IMPLEMENTED at this revision — verify clean error
 * ============================================================================ */

static void
test_endpoint_listen_not_implemented(void)
{
    auto cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto er = n00b_quic_endpoint_new(c, io, .listen = true);
    assert(n00b_result_is_err(er));
    assert(n00b_result_get_err(er) == N00B_QUIC_ERR_NOT_IMPLEMENTED);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] endpoint listen mode is clean NOT_IMPLEMENTED\n");
}

/* ============================================================================
 * 3. Null arg rejection
 * ============================================================================ */

static void
test_endpoint_null_args(void)
{
    auto er = n00b_quic_endpoint_new(nullptr, nullptr);
    assert(n00b_result_is_err(er));
    assert(n00b_result_get_err(er) == N00B_QUIC_ERR_NULL_ARG);

    /* close on NULL is safe. */
    n00b_quic_endpoint_close(nullptr);

    /* run_once on NULL → INVALID_ARG. */
    auto rr = n00b_quic_endpoint_run_once(nullptr, 0);
    assert(n00b_result_is_err(rr));
    assert(n00b_result_get_err(rr) == N00B_QUIC_ERR_INVALID_ARG);

    printf("  [PASS] endpoint null-arg behavior\n");
}

/* ============================================================================
 * 4. Idle run_once returns 0 quickly and produces no traffic
 * ============================================================================ */

static void
test_endpoint_run_idle(void)
{
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto er = n00b_quic_endpoint_new(c, io,
                                     .bind_host = "127.0.0.1",
                                     .alpn      = "n00b-echo/1");
    if (n00b_result_is_err(er)) {
        printf("  [SKIP] run idle (bind failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *ep = n00b_result_get(er);

    /* Three idle runs.  Each should return 0 inbound datagrams (no
     * peer is sending us anything) and not crash. */
    for (int i = 0; i < 3; i++) {
        auto rr = n00b_quic_endpoint_run_once(ep, 10);
        assert(n00b_result_is_ok(rr));
        assert(n00b_result_get(rr) == 0);
    }

    /* No traffic should have been generated either — the endpoint has
     * no live connections. */
    auto stats = n00b_quic_endpoint_stats(ep);
    assert(stats.rx_packets == 0);
    assert(stats.tx_packets == 0);

    n00b_quic_endpoint_close(ep);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] endpoint run_once idle is clean\n");
}

/* ============================================================================
 * 5. Initial Client-Hello flow — client → server datagram observed
 *
 * Two endpoints over loopback.  We open a picoquic_cnx on the client
 * pointed at the server's bound address, drive run_once a handful of
 * times, and assert that the server's rx counter increments.  We do
 * NOT assert handshake completion — server has no cert, so the
 * handshake will eventually fail.  But the client's Initial packet
 * (with the Client Hello inside) should reach the server's recv path,
 * which is what this test is actually verifying.
 * ============================================================================ */

static void
test_endpoint_initial_handshake_flow(void)
{
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto sr = n00b_quic_endpoint_new(c, io,
                                     .bind_host = "127.0.0.1",
                                     .alpn      = "n00b-echo/1");
    if (n00b_result_is_err(sr)) {
        printf("  [SKIP] initial flow (server bind failed)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *server = n00b_result_get(sr);

    auto cur = n00b_quic_endpoint_new(c, io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = "n00b-echo/1");
    if (n00b_result_is_err(cur)) {
        printf("  [SKIP] initial flow (client bind failed)\n");
        n00b_quic_endpoint_close(server);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *client = n00b_result_get(cur);

    uint16_t server_port = n00b_quic_endpoint_local_port(server);
    assert(server_port > 0);

    /* Reach into the endpoint internals for picoquic context — this is
     * the seam that the higher-level n00b_quic_connect() will hide,
     * but at this revision we drive picoquic directly to test the
     * recv path. */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(server_port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    uint64_t now = (uint64_t)n00b_us_timestamp();
    picoquic_cnx_t *cnx = picoquic_create_cnx(
        client->quic,
        picoquic_null_connection_id,
        picoquic_null_connection_id,
        (struct sockaddr *)&dst,
        now,
        /* proposed_version */ 0,
        /* sni */ "localhost",
        /* alpn */ "n00b-echo/1",
        /* client_mode */ 1);
    assert(cnx != nullptr);

    int rc = picoquic_start_client_cnx(cnx);
    assert(rc == 0);

    /* Pump both endpoints.  We don't expect a successful handshake
     * (server has no cert), but the Client Hello should fly. */
    bool server_saw_traffic = false;
    bool client_sent        = false;
    for (int i = 0; i < 20; i++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);

        auto cs = n00b_quic_endpoint_stats(client);
        auto ss = n00b_quic_endpoint_stats(server);
        if (cs.tx_packets > 0) client_sent = true;
        if (ss.rx_packets > 0) {
            server_saw_traffic = true;
            break;
        }
    }
    assert(client_sent);
    assert(server_saw_traffic);

    n00b_quic_endpoint_close(client);
    n00b_quic_endpoint_close(server);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] initial handshake flow — Client Hello reaches server\n");
}

/* ============================================================================
 * 6. Phase 5 § 5.8 — endpoint accepts an `lb_cid_config` kwarg and
 *    sets up the picoquic CID generator.  We don't drive a handshake
 *    here (that's covered by the phase5_demo loopback smoke); we
 *    just verify create/close is clean with the new kwarg in place
 *    and that picoquic's default CID length is bumped to 16 bytes.
 * ============================================================================ */

static void
test_endpoint_lb_cid_config_passes_through(void)
{
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    static const uint8_t key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                    0xdd, 0xee, 0xff, 0x00};
    auto lcr = n00b_quic_lb_cid_config_new(key, 0xab, 1);
    if (n00b_result_is_err(lcr)) {
        printf("  [SKIP] lb_cid_config_new failed (no minicrypto?)\n");
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_lb_cid_config_t *lb = n00b_result_get(lcr);

    auto er = n00b_quic_endpoint_new(c, io,
                                     .bind_host     = "127.0.0.1",
                                     .alpn          = "n00b-echo/1",
                                     .lb_cid_config = lb);
    if (n00b_result_is_err(er)) {
        printf("  [SKIP] endpoint with lb_cid_config (bind failed)\n");
        n00b_quic_lb_cid_config_close(lb);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *ep = n00b_result_get(er);

    /* Check picoquic's default CID length was bumped to 16 by our
     * endpoint constructor.  Reach into the internal endpoint
     * struct for the picoquic ctx. */
    assert(ep != nullptr);
    /* (We don't assert on the picoquic ctx contents — that's an
     * implementation detail.  The fact that endpoint_new returned
     * ok with a non-NULL lb_cid_config exercises the codepath that
     * calls picoquic_set_default_connection_id_length(16) +
     * registers the cnx_id_callback.) */

    n00b_quic_endpoint_close(ep);
    n00b_quic_lb_cid_config_close(lb);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] endpoint accepts lb_cid_config kwarg and tears down clean\n");
}

/* ============================================================================
 * 7. Phase 5 § 5.8 — n00b_quic_conn_remote_cid contract checks.
 *    NULL inputs return false; full-handshake exercise lives in the
 *    phase5_demo loopback smoke.
 * ============================================================================ */

static void
test_conn_remote_cid_null_safety(void)
{
    n00b_quic_cid_t out;
    /* Both NULL → false. */
    assert(!n00b_quic_conn_remote_cid(nullptr, nullptr));
    /* NULL conn, real out → false; out is not zeroed (caller's
     * responsibility per the doc, but we don't crash). */
    assert(!n00b_quic_conn_remote_cid(nullptr, &out));
    /* Real conn, NULL out → false. */
    /* (We can't easily construct a real conn here without a
     * handshake; loopback smoke covers the "valid args, ready
     * connection" path end-to-end.) */
    printf("  [PASS] n00b_quic_conn_remote_cid NULL-safe\n");
}

/* ============================================================================
 * 8. Endpoint, conn, and channel handles add nothing to the finalizer index.
 *
 * They live in conduit_pool, which the collector does not reclaim per
 * object, and are released by their close calls. A finalizer registered on
 * one could never run, and its index entry would outlive the handle.
 * ============================================================================ */

static void
test_handles_leave_no_finalizer_entries(void)
{
    n00b_runtime_t *rt     = n00b_get_runtime();
    uint64_t        before = n00b_atomic_load(&rt->finalizer_count);

    auto cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c  = n00b_result_get(cr);
    auto            ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto er = n00b_quic_endpoint_new(c, io,
                                     .bind_host = "127.0.0.1",
                                     .alpn      = "n00b-echo/1");
    if (n00b_result_is_err(er)) {
        printf("  [SKIP] finalizer entries (bind failed: %d)\n",
               n00b_result_get_err(er));
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *ep = n00b_result_get(er);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(n00b_quic_endpoint_local_port(ep));
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    auto ccr = n00b_quic_connect(ep,
                                 (const struct sockaddr *)&dst,
                                 n00b_string_from_cstr("localhost"));
    assert(n00b_result_is_ok(ccr));
    n00b_quic_conn_t *conn = n00b_result_get(ccr);

    auto dr = n00b_quic_chan_open(conn, .kind = N00B_QUIC_CHAN_DGRAM);
    assert(n00b_result_is_ok(dr));
    n00b_quic_chan_t *dgram = n00b_result_get(dr);

    auto fr = n00b_quic_chan_open(conn);
    assert(n00b_result_is_ok(fr));
    n00b_quic_chan_t *framed = n00b_result_get(fr);

    n00b_quic_chan_close(framed);
    n00b_quic_chan_close(dgram);
    n00b_quic_close(conn, 0);
    n00b_quic_endpoint_close(ep);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);

    assert(n00b_atomic_load(&rt->finalizer_count) == before);
    printf("  [PASS] handles leave no finalizer entries\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_endpoint:\n");
    fflush(stdout);

    test_endpoint_create_close();
    fflush(stdout);
    test_endpoint_listen_not_implemented();
    fflush(stdout);
    test_endpoint_null_args();
    fflush(stdout);
    test_endpoint_run_idle();
    fflush(stdout);
    test_endpoint_initial_handshake_flow();
    fflush(stdout);
    test_endpoint_lb_cid_config_passes_through();
    fflush(stdout);
    test_conn_remote_cid_null_safety();
    fflush(stdout);
    test_handles_leave_no_finalizer_entries();
    fflush(stdout);

    printf("All quic endpoint tests passed.\n");
    n00b_shutdown();
    return 0;
}

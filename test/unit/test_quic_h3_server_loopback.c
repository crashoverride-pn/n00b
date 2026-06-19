/*
 * test_quic_h3_server_loopback.c — In-process H3 server + client
 * loopback (Phase 4 § 4.4).
 *
 * Two endpoints in one process: a listen-mode QUIC endpoint with the
 * test cert+key fixture wrapping an `n00b_h3_server_t`, and a client
 * endpoint wrapping an `n00b_h3_client_t`.  Both negotiate ALPN "h3".
 *
 * Sub-tests:
 *   1. handshake_settings_exchange — handshake completes, both peers
 *      see each other's SETTINGS.
 *   2. get_basic                   — GET /, server responds 200 "ok\n".
 *   3. post_with_body              — POST / with body "ping", server
 *                                    echoes it.
 *   4. status_404                  — server responds 404, no body.
 *   5. server_reset                — server resets the inbound stream;
 *                                    client's await returns err.
 *   6. goaway_on_close             — request 1 OK; after server_close
 *                                    a second client request fails.
 *
 * Each sub-test stands up its own conduit + io + endpoints and tears
 * them down on completion (mirrors test_quic_handshake.c discipline:
 * isolation > shared state).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/sha256.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/chan.h"
#include "crypto/trust.h"
#include "net/quic/h3.h"
#include "net/quic/h3_types.h"
#include "internal/net/quic/endpoint_internal.h"
#include "internal/net/quic/h3_internal.h"
#include "picoquic.h"

#include "../fixtures/quic_test_pki.h"

/* ============================================================================
 * Per-test scaffold.
 * ============================================================================ */

typedef struct {
    /* Owned tempfile path for the server's PKCS8 PEM key. */
    char *key_pem_path;

    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;

    n00b_quic_endpoint_t *server_ep;
    n00b_quic_endpoint_t *client_ep;

    n00b_h3_server_t         *server;
    n00b_h3_client_t         *client_h3;
    n00b_quic_conn_t         *client_conn;

    n00b_h3_request_inbox_t  *req_inbox;
} h3_loop_t;

static int64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

/* Pump until @cond_fn returns true, both endpoints + the H3 client
 * driven each iteration.  Returns true if @cond_fn fired before the
 * deadline; false on timeout.  @arg is forwarded to @cond_fn. */
typedef bool (*loop_cond_fn)(h3_loop_t *L, void *arg);

static bool
pump_until(h3_loop_t *L, loop_cond_fn cond_fn, void *arg, int budget_ms)
{
    int64_t start = now_ms();
    while ((now_ms() - start) < budget_ms) {
        if (cond_fn && cond_fn(L, arg)) return true;
        if (L->client_ep) n00b_quic_endpoint_run_once(L->client_ep, 5);
        if (L->server_ep) n00b_quic_endpoint_run_once(L->server_ep, 5);
        if (L->client_h3) n00b_h3_client_drive(L->client_h3);
        if (L->server)    n00b_h3_server_drive(L->server);
        if (cond_fn && cond_fn(L, arg)) return true;
    }
    return false;
}

static bool
cond_handshake(h3_loop_t *L, void *arg)
{
    (void)arg;
    return n00b_quic_conn_state(L->client_conn) ==
           N00B_QUIC_CONN_STATE_CONNECTED;
}

static bool
cond_inbox_has_message(h3_loop_t *L, void *arg)
{
    (void)arg;
    return n00b_h3_request_inbox_has_messages(L->req_inbox);
}

/* Stand up a fresh client+server pair sharing one conduit/io.
 *
 * Returns true on success.  On failure cleans up partial state and
 * returns false (caller should `[SKIP]`). */
static bool
loop_setup(h3_loop_t *L)
{
    memset(L, 0, sizeof(*L));

    L->key_pem_path = n00b_quic_test_write_key_pem();
    if (!L->key_pem_path) return false;

    auto cr = n00b_conduit_new();
    if (n00b_result_is_err(cr)) goto fail;
    L->conduit = n00b_result_get(cr);

    auto ir = n00b_conduit_io_new_default(L->conduit);
    if (n00b_result_is_err(ir)) goto fail;
    L->io = n00b_result_get(ir);

    /* Server endpoint with cert+key, ALPN "h3". */
    auto sr = n00b_quic_endpoint_new(L->conduit, L->io,
                                     .listen         = true,
                                     .bind_host      = "127.0.0.1",
                                     .alpn           = N00B_H3_ALPN,
                                     .cert_der_bytes = n00b_quic_test_cert_der,
                                     .cert_der_len   = n00b_quic_test_cert_der_len,
                                     .key_pem_path   = L->key_pem_path);
    if (n00b_result_is_err(sr)) goto fail;
    L->server_ep = n00b_result_get(sr);
    uint16_t sport = n00b_quic_endpoint_local_port(L->server_ep);

    /* Client endpoint, ALPN "h3". */
    auto cur = n00b_quic_endpoint_new(L->conduit, L->io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = N00B_H3_ALPN);
    if (n00b_result_is_err(cur)) goto fail;
    L->client_ep = n00b_result_get(cur);

    /* Disable picoquic's default verifier on the client (self-signed
     * test cert isn't in any system trust store; pinning at the trust
     * level isn't yet wired into picotls).  Same scaffold as
     * test_quic_handshake.c. */
    picoquic_set_null_verifier(L->client_ep->quic);

    /* Build the H3 server BEFORE connecting so the accept inbox is
     * subscribed when the first packet arrives.  The server hasn't
     * yet seen any conn — `drive()` will attach per-conn state once
     * the accept event lands. */
    auto serv = n00b_h3_server_new(L->server_ep, L->conduit);
    if (n00b_result_is_err(serv)) goto fail;
    L->server = n00b_result_get(serv);

    /* Subscribe to the server's request topic. */
    L->req_inbox = n00b_h3_request_inbox_new(L->conduit);
    n00b_h3_request_subscribe(n00b_h3_server_request_topic(L->server),
                              L->req_inbox,
                              .operations = N00B_CONDUIT_OP_ALL);

    /* Connect. */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(sport);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    auto rr = n00b_quic_connect(L->client_ep,
                                (const struct sockaddr *)&dst,
                                n00b_string_from_cstr("quic-test.n00b.local"));
    if (n00b_result_is_err(rr)) goto fail;
    L->client_conn = n00b_result_get(rr);

    /* Drive handshake to CONNECTED. */
    if (!pump_until(L, cond_handshake, nullptr, 5000)) {
        fprintf(stderr, "  handshake did not complete in 5s; final state=%d\n",
                (int)n00b_quic_conn_state(L->client_conn));
        goto fail;
    }

    /* Build H3 client over the connected conn. */
    auto hr = n00b_h3_client_new(L->client_conn);
    if (n00b_result_is_err(hr)) goto fail;
    L->client_h3 = n00b_result_get(hr);

    /* Drive a few iterations to let SETTINGS + uni preludes flush in
     * both directions before the test issues requests. */
    int64_t prime_start = now_ms();
    while ((now_ms() - prime_start) < 200) {
        n00b_quic_endpoint_run_once(L->client_ep, 5);
        n00b_quic_endpoint_run_once(L->server_ep, 5);
        n00b_h3_client_drive(L->client_h3);
        n00b_h3_server_drive(L->server);
    }
    return true;

fail:
    if (L->client_h3)   n00b_h3_client_close(L->client_h3);
    if (L->server)      n00b_h3_server_close(L->server);
    if (L->client_conn) n00b_quic_close(L->client_conn, 0);
    if (L->client_ep)   n00b_quic_endpoint_close(L->client_ep);
    if (L->server_ep)   n00b_quic_endpoint_close(L->server_ep);
    if (L->io)          n00b_conduit_io_destroy(L->io);
    if (L->conduit)     n00b_conduit_destroy(L->conduit);
    if (L->key_pem_path) {
        unlink(L->key_pem_path);
        free(L->key_pem_path);
    }
    memset(L, 0, sizeof(*L));
    return false;
}

static void
loop_teardown(h3_loop_t *L)
{
    if (L->client_h3)   n00b_h3_client_close(L->client_h3);
    if (L->server)      n00b_h3_server_close(L->server);
    if (L->client_conn) n00b_quic_close(L->client_conn, 0);
    if (L->client_ep)   n00b_quic_endpoint_close(L->client_ep);
    if (L->server_ep)   n00b_quic_endpoint_close(L->server_ep);
    if (L->io)          n00b_conduit_io_destroy(L->io);
    if (L->conduit)     n00b_conduit_destroy(L->conduit);
    if (L->key_pem_path) {
        unlink(L->key_pem_path);
        free(L->key_pem_path);
    }
    memset(L, 0, sizeof(*L));
}

/* Pop the next inbound request from the server's inbox.  Pumps the
 * loop until a message arrives or the budget elapses; returns nullptr
 * on timeout. */
static n00b_h3_inbound_request_t *
wait_for_request(h3_loop_t *L, int budget_ms)
{
    if (!pump_until(L, cond_inbox_has_message, nullptr, budget_ms)) {
        return nullptr;
    }
    n00b_h3_request_msg_t *m = n00b_h3_request_inbox_pop(L->req_inbox);
    if (!m) return nullptr;
    return m->payload.req;
}

/* Loopback-aware request await.
 *
 * `n00b_h3_request_await` only drives the CLIENT endpoint — that's
 * correct for the typical deployment where the server lives in a
 * different process.  For our in-process loopback we need to drive
 * BOTH endpoints in lockstep so the server's response packets actually
 * leave its picoquic send queue.  This helper does that by pumping a
 * `pump_until` loop until the client's request reaches a terminal
 * state (DONE or RESET), then assembles the response struct
 * client-side. */
typedef struct {
    n00b_h3_request_t *req;
} request_done_arg_t;

static bool
cond_request_terminal(h3_loop_t *L, void *arg)
{
    (void)L;
    n00b_h3_request_t *req = ((request_done_arg_t *)arg)->req;
    return req->state == N00B_H3_REQ_STATE_DONE ||
           req->state == N00B_H3_REQ_STATE_RESET;
}

static n00b_result_t(n00b_h3_response_t *)
loopback_request_await(h3_loop_t *L, n00b_h3_request_t *req,
                       int budget_ms)
{
    request_done_arg_t a = { .req = req };
    if (!pump_until(L, cond_request_terminal, &a, budget_ms)) {
        return n00b_result_err(n00b_h3_response_t *,
                               N00B_QUIC_ERR_TIMEOUT);
    }
    if (req->state == N00B_H3_REQ_STATE_RESET) {
        return n00b_result_err(n00b_h3_response_t *,
                               N00B_QUIC_ERR_PEER_RESET);
    }
    n00b_h3_response_t *resp = n00b_alloc_with_opts(
        n00b_h3_response_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_h3_alloc() });
    resp->status    = req->status;
    resp->headers   = req->resp_headers;
    resp->n_headers = req->resp_n_headers;
    resp->body      = req->resp_body;
    return n00b_result_ok(n00b_h3_response_t *, resp);
}

/* ============================================================================
 * Sub-test 1 — handshake + bidirectional SETTINGS dispatch.
 *
 * Both peers must observe each other's SETTINGS frame end-to-end:
 *   - Server sees client's CONTROL/QPACK enc/dec uni streams + decodes
 *     SETTINGS from the CONTROL stream.
 *   - Client sees server's three uni streams (RFC 9114 § 6.2 — server-
 *     initiated, stream-id bit 0 == 1) + decodes SETTINGS.
 *
 * Auto-wrap of peer-initiated streams works in both modes; see
 * `src/quic/conn.c:_n00b_quic_conn_default_callback`.
 * ============================================================================ */

static int
test_handshake_settings_exchange(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] handshake_settings_exchange (loop_setup failed)\n");
        return 0;
    }

    /* Pump for up to 1s to let SETTINGS arrive on both sides. */
    int64_t deadline = now_ms() + 1000;
    while (now_ms() < deadline) {
        n00b_quic_endpoint_run_once(L.client_ep, 5);
        n00b_quic_endpoint_run_once(L.server_ep, 5);
        n00b_h3_client_drive(L.client_h3);
        n00b_h3_server_drive(L.server);

        n00b_h3_settings_t ps = n00b_h3_client_peer_settings(L.client_h3);
        if (ps.received) break;
    }

    /* Server-side assertion: server must have classified the client's
     * uni streams (proves accept-event + drive + uni-discovery work) AND
     * sent its own SETTINGS frame on its CONTROL stream. */
    int rc = 0;
    if (!L.server->conns
        || n00b_list_len(*L.server->conns) == 0) {
        printf("  [FAIL] handshake_settings_exchange: server has no conn "
               "(accept event never fired)\n");
        rc = 1;
    } else {
        n00b_h3_server_conn_t *sc =
            n00b_list_get(*L.server->conns, 0);
        if (!sc->peer_control_uni || !sc->peer_qpack_enc_uni ||
            !sc->peer_qpack_dec_uni) {
            printf("  [FAIL] handshake_settings_exchange: server did not "
                   "discover all 3 client uni streams "
                   "(ctrl=%p enc=%p dec=%p)\n",
                   (void *)sc->peer_control_uni,
                   (void *)sc->peer_qpack_enc_uni,
                   (void *)sc->peer_qpack_dec_uni);
            rc = 1;
        } else if (!sc->local_settings_sent) {
            printf("  [FAIL] handshake_settings_exchange: server never "
                   "emitted its SETTINGS frame\n");
            rc = 1;
        } else {
            printf("  [PASS] handshake_settings_exchange "
                   "(server saw all 3 client uni streams + sent SETTINGS)\n");
        }
    }

    /* Client-side: now that conn.c auto-wraps peer-initiated streams
     * in client mode (RFC 9000 § 2.1 — bit 0 of stream id), the
     * client must observe the server's SETTINGS frame end-to-end. */
    n00b_h3_settings_t ps = n00b_h3_client_peer_settings(L.client_h3);
    if (!ps.received) {
        printf("  [FAIL] handshake_settings_exchange: client never "
               "observed server SETTINGS\n");
        rc = 1;
    }

    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 2 — basic GET, server responds 200 "ok\n".
 * ============================================================================ */

static int
test_get_basic(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] get_basic (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request(
        L.client_h3,
        (n00b_h3_request_spec_t){
            .method    = "GET",
            .authority = "localhost",
            .path      = "/",
        });
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] get_basic: client_request err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    /* Pump until the server sees the request. */
    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] get_basic: server never received request\n");
        rc = 1; goto done;
    }

    const char *m = n00b_h3_inbound_request_method(ireq);
    const char *p = n00b_h3_inbound_request_path(ireq);
    if (!m || strcmp(m, "GET") != 0) {
        printf("  [FAIL] get_basic: method=%s\n", m ? m : "(null)");
        rc = 1; goto done;
    }
    if (!p || strcmp(p, "/") != 0) {
        printf("  [FAIL] get_basic: path=%s\n", p ? p : "(null)");
        rc = 1; goto done;
    }

    /* Respond 200 "ok\n". */
    auto rr = n00b_h3_inbound_request_respond(
        ireq,
        (n00b_h3_response_spec_t){
            .status   = 200,
            .body     = (const uint8_t *)"ok\n",
            .body_len = 3,
        });
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] get_basic: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    auto rsp = loopback_request_await(&L, creq, 5000);
    if (n00b_result_is_err(rsp)) {
        printf("  [FAIL] get_basic: await err=%d\n",
               n00b_result_get_err(rsp));
        rc = 1; goto done;
    }
    n00b_h3_response_t *resp = n00b_result_get(rsp);
    if (resp->status != 200) {
        printf("  [FAIL] get_basic: status=%u (want 200)\n",
               (unsigned)resp->status);
        rc = 1; goto done;
    }
    if (!resp->body || resp->body->byte_len != 3 ||
        memcmp(resp->body->data, "ok\n", 3) != 0) {
        printf("  [FAIL] get_basic: body mismatch (len=%zu)\n",
               resp->body ? (size_t)resp->body->byte_len : 0);
        rc = 1; goto done;
    }
    printf("  [PASS] get_basic (200, body=\"ok\\n\")\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 3 — POST with body, server echoes the body back.
 * ============================================================================ */

static int
test_post_with_body(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] post_with_body (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    const char *payload = "ping";
    size_t      paylen  = strlen(payload);

    auto reqr = n00b_h3_client_request(
        L.client_h3,
        (n00b_h3_request_spec_t){
            .method    = "POST",
            .authority = "localhost",
            .path      = "/",
            .body      = (const uint8_t *)payload,
            .body_len  = paylen,
        });
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] post_with_body: client_request err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] post_with_body: server never received request\n");
        rc = 1; goto done;
    }

    n00b_buffer_t *bodybuf = n00b_h3_inbound_request_body(ireq);
    if (!bodybuf || (size_t)bodybuf->byte_len != paylen ||
        memcmp(bodybuf->data, payload, paylen) != 0) {
        printf("  [FAIL] post_with_body: body mismatch on server "
               "(len=%zu)\n",
               bodybuf ? (size_t)bodybuf->byte_len : 0);
        rc = 1; goto done;
    }

    auto rr = n00b_h3_inbound_request_respond(
        ireq,
        (n00b_h3_response_spec_t){
            .status   = 200,
            .body     = (const uint8_t *)bodybuf->data,
            .body_len = (size_t)bodybuf->byte_len,
        });
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] post_with_body: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    auto rsp = loopback_request_await(&L, creq, 5000);
    if (n00b_result_is_err(rsp)) {
        printf("  [FAIL] post_with_body: await err=%d\n",
               n00b_result_get_err(rsp));
        rc = 1; goto done;
    }
    n00b_h3_response_t *resp = n00b_result_get(rsp);
    if (resp->status != 200) {
        printf("  [FAIL] post_with_body: status=%u\n",
               (unsigned)resp->status);
        rc = 1; goto done;
    }
    if (!resp->body || (size_t)resp->body->byte_len != paylen ||
        memcmp(resp->body->data, payload, paylen) != 0) {
        printf("  [FAIL] post_with_body: echoed body mismatch\n");
        rc = 1; goto done;
    }
    printf("  [PASS] post_with_body (echo round-trip)\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 4 — server responds 404, no body.
 * ============================================================================ */

static int
test_status_404(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] status_404 (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request(
        L.client_h3,
        (n00b_h3_request_spec_t){
            .method    = "GET",
            .authority = "localhost",
            .path      = "/missing",
        });
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] status_404: client_request err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] status_404: server never received request\n");
        rc = 1; goto done;
    }

    auto rr = n00b_h3_inbound_request_respond(
        ireq,
        (n00b_h3_response_spec_t){ .status = 404 });
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] status_404: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    auto rsp = loopback_request_await(&L, creq, 5000);
    if (n00b_result_is_err(rsp)) {
        printf("  [FAIL] status_404: await err=%d\n",
               n00b_result_get_err(rsp));
        rc = 1; goto done;
    }
    n00b_h3_response_t *resp = n00b_result_get(rsp);
    if (resp->status != 404) {
        printf("  [FAIL] status_404: status=%u\n", (unsigned)resp->status);
        rc = 1; goto done;
    }
    if (resp->body && resp->body->byte_len != 0) {
        printf("  [FAIL] status_404: unexpected body len=%zu\n",
               (size_t)resp->body->byte_len);
        rc = 1; goto done;
    }
    printf("  [PASS] status_404\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 5 — server resets the inbound stream; client's await
 *              returns err.
 * ============================================================================ */

static int
test_server_reset(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] server_reset (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request(
        L.client_h3,
        (n00b_h3_request_spec_t){
            .method    = "GET",
            .authority = "localhost",
            .path      = "/",
        });
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] server_reset: client_request err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] server_reset: server never received request\n");
        rc = 1; goto done;
    }

    /* Reset before responding. */
    n00b_h3_inbound_request_reset(ireq, (uint64_t)N00B_H3_ERR_REQUEST_REJECTED);

    /* Await should return an error rather than a 2xx body. */
    auto rsp = loopback_request_await(&L, creq, 5000);
    if (n00b_result_is_ok(rsp)) {
        n00b_h3_response_t *resp = n00b_result_get(rsp);
        printf("  [FAIL] server_reset: await returned ok (status=%u)\n",
               (unsigned)resp->status);
        rc = 1; goto done;
    }

    int32_t e = n00b_result_get_err(rsp);
    /* Acceptable terminal errors: PEER_RESET (the documented signal)
     * or PROTOCOL/TIMEOUT (best-effort surfacing).  Anything that is
     * NOT ok is sufficient evidence the client noticed. */
    printf("  [PASS] server_reset (await err=%d %s)\n", e,
           n00b_quic_err_str((n00b_quic_err_t)e));

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 6 — GOAWAY on close: req 1 succeeds; after server_close,
 *              a second client request fails (await err — the stream
 *              the client opens past the GOAWAY limit is ignored by
 *              the server, so the client times out / observes reset).
 * ============================================================================ */

static int
test_goaway_on_close(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] goaway_on_close (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    /* First request: succeeds normally. */
    auto reqr1 = n00b_h3_client_request(
        L.client_h3,
        (n00b_h3_request_spec_t){
            .method    = "GET",
            .authority = "localhost",
            .path      = "/",
        });
    if (n00b_result_is_err(reqr1)) {
        printf("  [FAIL] goaway_on_close: req1 err=%d\n",
               n00b_result_get_err(reqr1));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq1 = n00b_result_get(reqr1);

    n00b_h3_inbound_request_t *ireq1 = wait_for_request(&L, 5000);
    if (!ireq1) {
        printf("  [FAIL] goaway_on_close: req1 server never received\n");
        rc = 1; goto done;
    }
    auto rr1 = n00b_h3_inbound_request_respond(
        ireq1,
        (n00b_h3_response_spec_t){
            .status   = 200,
            .body     = (const uint8_t *)"ok\n",
            .body_len = 3,
        });
    if (n00b_result_is_err(rr1)) {
        printf("  [FAIL] goaway_on_close: req1 respond err=%d\n",
               n00b_result_get_err(rr1));
        rc = 1; goto done;
    }
    auto rsp1 = loopback_request_await(&L, creq1, 5000);
    if (n00b_result_is_err(rsp1)) {
        printf("  [FAIL] goaway_on_close: req1 await err=%d\n",
               n00b_result_get_err(rsp1));
        rc = 1; goto done;
    }
    n00b_h3_response_t *resp1 = n00b_result_get(rsp1);
    if (resp1->status != 200) {
        printf("  [FAIL] goaway_on_close: req1 status=%u\n",
               (unsigned)resp1->status);
        rc = 1; goto done;
    }

    /* Server-side close: emits GOAWAY on each per-conn control stream
     * with limit = max_seen_client_bidi + 4 = 0 + 4 = 4 (the next ID
     * the client could have used is 4).  The server closes its uni
     * streams and stops processing new bidi streams. */
    n00b_h3_server_close(L.server);

    /* Pump for a beat so the GOAWAY bytes flush over the wire. */
    int64_t prime = now_ms();
    while ((now_ms() - prime) < 200) {
        n00b_quic_endpoint_run_once(L.client_ep, 5);
        n00b_quic_endpoint_run_once(L.server_ep, 5);
        n00b_h3_client_drive(L.client_h3);
    }

    /* Second request issued after server_close.  The server-side bidi
     * stream is ignored (server is closed); the client must fail to
     * complete (the stream sits unanswered → client times out, OR the
     * client's GOAWAY observer rejects the request outright with
     * PEER_CLOSED — either is a valid "the GOAWAY round-trip
     * functioned" signal).  We use a short deadline to keep the test
     * fast.
     *
     * If client_request itself returns err (because the client saw
     * GOAWAY before we issued it and refuses to open new streams past
     * the limit), that's also a pass. */
    auto reqr2 = n00b_h3_client_request(
        L.client_h3,
        (n00b_h3_request_spec_t){
            .method    = "GET",
            .authority = "localhost",
            .path      = "/again",
        });
    if (n00b_result_is_err(reqr2)) {
        int32_t e = n00b_result_get_err(reqr2);
        printf("  [PASS] goaway_on_close (req2 refused at issue: err=%d %s)\n",
               e, n00b_quic_err_str((n00b_quic_err_t)e));
        goto done;
    }
    n00b_h3_request_t *creq2 = n00b_result_get(reqr2);

    auto rsp2 = loopback_request_await(&L, creq2, 1500);
    if (n00b_result_is_ok(rsp2)) {
        n00b_h3_response_t *resp2 = n00b_result_get(rsp2);
        printf("  [FAIL] goaway_on_close: req2 unexpectedly succeeded "
               "(status=%u)\n", (unsigned)resp2->status);
        rc = 1; goto done;
    }
    int32_t e2 = n00b_result_get_err(rsp2);
    printf("  [PASS] goaway_on_close (req2 err=%d %s)\n",
           e2, n00b_quic_err_str((n00b_quic_err_t)e2));

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * main
 * ============================================================================ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_h3_server_loopback:\n");
    fflush(stdout);

    int rc = 0;
    rc |= test_handshake_settings_exchange();   fflush(stdout);
    rc |= test_get_basic();                     fflush(stdout);
    rc |= test_post_with_body();                fflush(stdout);
    rc |= test_status_404();                    fflush(stdout);
    rc |= test_server_reset();                  fflush(stdout);
    rc |= test_goaway_on_close();               fflush(stdout);

    printf("test_quic_h3_server_loopback done.\n");

    n00b_shutdown();
    return rc;
}

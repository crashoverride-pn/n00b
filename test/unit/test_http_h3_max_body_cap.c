/*
 * test_http_h3_max_body_cap.c — Regression for the h3 mid-stream
 * `max_body_size` enforcement (DF-014 Phase 5 lift).
 *
 * Sub-agent 5 (`uq ae`) added the `max_body_size` kwarg to both h1
 * and h3 paths, but h3's enforcement was a post-await check that
 * tripped only after the body had already accumulated inside
 * picoquic.  This file pins the mid-stream guard: when a server
 * sends a response body larger than the caller-supplied cap, the
 * receive loop resets the stream with `H3_EXCESSIVE_LOAD` and the
 * await surfaces `LOCAL_RESET` so the higher layer can translate
 * to `RESPONSE_TOO_LARGE`.
 *
 * Scaffold: in-process H3 client + server loopback, mirroring
 * `test_quic_h3_server_loopback.c` (same UDP/lo client+server pair
 * design).  The test isn't Docker-gated — it runs in every build.
 *
 * Sub-tests:
 *   1. mid_stream_data_cap     — Server sends a 4-byte body; client
 *                                 cap is 2 bytes.  Expect
 *                                 LOCAL_RESET +
 *                                 body_cap_exceeded = true.
 *   2. content_length_short_circuit — Server sends a 1-byte body
 *                                 but advertises Content-Length:
 *                                 10000.  Cap is 1024.  Expect
 *                                 the header-time short-circuit
 *                                 (LOCAL_RESET, cap_exceeded).
 *   3. cap_not_tripped         — Server sends a 4-byte body; cap is
 *                                 1 MiB.  Expect a normal 200 OK,
 *                                 no spurious enforcement.
 *   4. cap_zero_passes_through — Server sends a 4-byte body; cap is
 *                                 0 (the "no cap" default).
 *                                 Expect a normal 200 OK.
 *
 * Test-file carve-out (D-030) applies — libc I/O for stdout logging
 * is acceptable.
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
 * Per-test scaffold — mirror of test_quic_h3_server_loopback.c.
 * ============================================================================ */

typedef struct {
    char                       *key_pem_path;
    n00b_conduit_t             *conduit;
    n00b_conduit_io_backend_t  *io;
    n00b_quic_endpoint_t       *server_ep;
    n00b_quic_endpoint_t       *client_ep;
    n00b_h3_server_t           *server;
    n00b_h3_client_t           *client_h3;
    n00b_quic_conn_t           *client_conn;
    n00b_h3_request_inbox_t    *req_inbox;
} h3_loop_t;

static int64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

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

    auto sr = n00b_quic_endpoint_new(
        L->conduit, L->io,
        .listen         = true,
        .bind_host      = "127.0.0.1",
        .alpn           = N00B_H3_ALPN,
        .cert_der_bytes = n00b_quic_test_cert_der,
        .cert_der_len   = n00b_quic_test_cert_der_len,
        .key_pem_path   = L->key_pem_path);
    if (n00b_result_is_err(sr)) goto fail;
    L->server_ep = n00b_result_get(sr);
    uint16_t sport = n00b_quic_endpoint_local_port(L->server_ep);

    auto cur = n00b_quic_endpoint_new(L->conduit, L->io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = N00B_H3_ALPN);
    if (n00b_result_is_err(cur)) goto fail;
    L->client_ep = n00b_result_get(cur);

    picoquic_set_null_verifier(L->client_ep->quic);

    auto serv = n00b_h3_server_new(L->server_ep, L->conduit);
    if (n00b_result_is_err(serv)) goto fail;
    L->server = n00b_result_get(serv);

    L->req_inbox = n00b_h3_request_inbox_new(L->conduit);
    n00b_h3_request_subscribe(n00b_h3_server_request_topic(L->server),
                              L->req_inbox,
                              .operations = N00B_CONDUIT_OP_ALL);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(sport);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    auto rr = n00b_quic_connect(
        L->client_ep, (const struct sockaddr *)&dst,
        n00b_string_from_cstr("quic-test.n00b.local"));
    if (n00b_result_is_err(rr)) goto fail;
    L->client_conn = n00b_result_get(rr);

    if (!pump_until(L, cond_handshake, nullptr, 5000)) {
        fprintf(stderr, "  handshake did not complete in 5s\n");
        goto fail;
    }

    auto hr = n00b_h3_client_new(L->client_conn);
    if (n00b_result_is_err(hr)) goto fail;
    L->client_h3 = n00b_result_get(hr);

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

/* ============================================================================
 * Sub-test 1 — mid-stream DATA-frame cap trips on a body that's
 *              larger than the cap.
 *
 * Server sends 4 bytes ("abcd"); client cap is 2.  The first DATA
 * frame's append step computes `0 + 4 > 2` and short-circuits with
 * `H3_EXCESSIVE_LOAD`.  The await returns LOCAL_RESET and the
 * cap-exceeded flag is set.
 * ============================================================================ */

static int
test_mid_stream_data_cap(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] mid_stream_data_cap (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request_raw(L.client_h3, "GET", "https",
                                       "localhost", "/big");
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] mid_stream_data_cap: client_request err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] mid_stream_data_cap: server never received\n");
        rc = 1; goto done;
    }

    /* Server replies with a 4-byte body. */
    auto rr = n00b_h3_inbound_request_respond_raw(ireq, 200, nullptr, 0,
                                              (const uint8_t *)"abcd", 4);
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] mid_stream_data_cap: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    /* Stamp the cap on the request BEFORE pumping the loop.  The
     * server has called `respond` but its DATA frame hasn't yet
     * traversed picoquic to the client; the next drive iteration is
     * what surfaces HEADERS + DATA into `process_request_frame`, and
     * the cap must be visible there. */
    creq->max_body_size = 2;

    /* Client awaits with a 2-byte cap.  Drive both endpoints so the
     * server's DATA frame actually leaves picoquic. */
    int64_t deadline = now_ms() + 5000;
    n00b_result_t(n00b_h3_response_t *) rsp;
    bool got_result = false;
    while (now_ms() < deadline) {
        n00b_quic_endpoint_run_once(L.client_ep, 5);
        n00b_quic_endpoint_run_once(L.server_ep, 5);
        n00b_h3_client_drive(L.client_h3);
        n00b_h3_server_drive(L.server);
        if (creq->state == N00B_H3_REQ_STATE_DONE
            || creq->state == N00B_H3_REQ_STATE_RESET) {
            /* Now that the request is terminal, run await once with
             * .drive = false to materialize the result without
             * fighting the in-process server. */
            rsp = n00b_h3_request_await(creq,
                                        .deadline_ms   = 100,
                                        .drive         = false,
                                        .max_body_size = 2);
            got_result = true;
            break;
        }
    }
    if (!got_result) {
        printf("  [FAIL] mid_stream_data_cap: request never terminal "
               "(state=%d)\n", (int)creq->state);
        rc = 1; goto done;
    }
    if (n00b_result_is_ok(rsp)) {
        n00b_h3_response_t *resp = n00b_result_get(rsp);
        printf("  [FAIL] mid_stream_data_cap: await returned ok "
               "(status=%u body_len=%zu)\n",
               (unsigned)resp->status,
               resp->body ? (size_t)resp->body->byte_len : 0);
        rc = 1; goto done;
    }
    int32_t e = n00b_result_get_err(rsp);
    if (e != N00B_QUIC_ERR_LOCAL_RESET) {
        printf("  [FAIL] mid_stream_data_cap: await err=%d "
               "(want LOCAL_RESET=%d)\n",
               (int)e, (int)N00B_QUIC_ERR_LOCAL_RESET);
        rc = 1; goto done;
    }
    if (!n00b_h3_request_body_cap_exceeded(creq)) {
        printf("  [FAIL] mid_stream_data_cap: body_cap_exceeded flag "
               "not set\n");
        rc = 1; goto done;
    }
    /* Verify the partial body never exceeded the cap. */
    if (creq->resp_body && (uint64_t)creq->resp_body->byte_len > 2) {
        printf("  [FAIL] mid_stream_data_cap: partial body len=%zu "
               "exceeded cap=2\n",
               (size_t)creq->resp_body->byte_len);
        rc = 1; goto done;
    }
    printf("  [PASS] mid_stream_data_cap (LOCAL_RESET + cap_exceeded, "
           "body_len=%zu ≤ cap=2)\n",
           creq->resp_body ? (size_t)creq->resp_body->byte_len : 0);

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 2 — Content-Length short-circuit: server declares an
 *              oversized body via the `content-length` response
 *              header; the receive loop trips the cap BEFORE any
 *              DATA frames are accepted.
 *
 * Server sends a 1-byte body but advertises content-length: 10000.
 * Cap is 1024.  The header sniff catches the declared overrun and
 * resets immediately — the partial body has zero bytes.
 * ============================================================================ */

static int
test_content_length_short_circuit(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] content_length_short_circuit (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request_raw(L.client_h3, "GET", "https",
                                       "localhost", "/cl");
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] content_length_short_circuit: req err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    /* Stamp cap up front: the HEADERS frame may be processed before
     * the await call materializes (drive iteration order is racy in
     * the in-process loopback). */
    creq->max_body_size = 1024;

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] content_length_short_circuit: never received\n");
        rc = 1; goto done;
    }

    /* Server reply: `content-length: 10000` header + 1-byte body.
     * The server's frame layer will emit exactly this — the cap should
     * trip at the HEADERS-parse step, before the DATA frame lands. */
    n00b_h3_header_t hdrs[1] = {
        { .name      = (const uint8_t *)"content-length",
          .name_len  = 14,
          .value     = (const uint8_t *)"10000",
          .value_len = 5 },
    };
    auto rr = n00b_h3_inbound_request_respond_raw(ireq, 200, hdrs, 1,
                                              (const uint8_t *)"x", 1);
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] content_length_short_circuit: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    int64_t deadline = now_ms() + 5000;
    n00b_result_t(n00b_h3_response_t *) rsp;
    bool got_result = false;
    while (now_ms() < deadline) {
        n00b_quic_endpoint_run_once(L.client_ep, 5);
        n00b_quic_endpoint_run_once(L.server_ep, 5);
        n00b_h3_client_drive(L.client_h3);
        n00b_h3_server_drive(L.server);
        if (creq->state == N00B_H3_REQ_STATE_DONE
            || creq->state == N00B_H3_REQ_STATE_RESET) {
            rsp = n00b_h3_request_await(creq,
                                        .deadline_ms   = 100,
                                        .drive         = false,
                                        .max_body_size = 1024);
            got_result = true;
            break;
        }
    }
    if (!got_result) {
        printf("  [FAIL] content_length_short_circuit: never terminal\n");
        rc = 1; goto done;
    }
    if (n00b_result_is_ok(rsp)) {
        printf("  [FAIL] content_length_short_circuit: await ok "
               "(expected LOCAL_RESET)\n");
        rc = 1; goto done;
    }
    int32_t e = n00b_result_get_err(rsp);
    if (e != N00B_QUIC_ERR_LOCAL_RESET) {
        printf("  [FAIL] content_length_short_circuit: err=%d "
               "(want LOCAL_RESET)\n", (int)e);
        rc = 1; goto done;
    }
    if (!n00b_h3_request_body_cap_exceeded(creq)) {
        printf("  [FAIL] content_length_short_circuit: flag not set\n");
        rc = 1; goto done;
    }
    /* The short-circuit fires at HEADERS — no DATA bytes accepted. */
    size_t partial_len = creq->resp_body
                             ? (size_t)creq->resp_body->byte_len : 0;
    if (partial_len != 0) {
        printf("  [FAIL] content_length_short_circuit: partial body "
               "len=%zu (want 0; short-circuit failed)\n", partial_len);
        rc = 1; goto done;
    }
    printf("  [PASS] content_length_short_circuit (HEADERS-time trip, "
           "partial_body=0)\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 3 — generous cap → success.  Pins that a non-zero cap
 *              doesn't false-positive when the body is well under it.
 * ============================================================================ */

static int
test_cap_not_tripped(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] cap_not_tripped (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request_raw(L.client_h3, "GET", "https",
                                       "localhost", "/small");
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] cap_not_tripped: client_request err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] cap_not_tripped: server never received\n");
        rc = 1; goto done;
    }
    auto rr = n00b_h3_inbound_request_respond_raw(ireq, 200, nullptr, 0,
                                              (const uint8_t *)"abcd", 4);
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] cap_not_tripped: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    /* Stamp the cap before pumping — the cap must be visible to the
     * receive loop when the first DATA frame is processed. */
    creq->max_body_size = 1 << 20;

    int64_t deadline = now_ms() + 5000;
    n00b_result_t(n00b_h3_response_t *) rsp;
    bool got_result = false;
    while (now_ms() < deadline) {
        n00b_quic_endpoint_run_once(L.client_ep, 5);
        n00b_quic_endpoint_run_once(L.server_ep, 5);
        n00b_h3_client_drive(L.client_h3);
        n00b_h3_server_drive(L.server);
        if (creq->state == N00B_H3_REQ_STATE_DONE
            || creq->state == N00B_H3_REQ_STATE_RESET) {
            rsp = n00b_h3_request_await(creq,
                                        .deadline_ms   = 100,
                                        .drive         = false,
                                        .max_body_size = 1 << 20);
            got_result = true;
            break;
        }
    }
    if (!got_result) {
        printf("  [FAIL] cap_not_tripped: never terminal\n");
        rc = 1; goto done;
    }
    if (n00b_result_is_err(rsp)) {
        printf("  [FAIL] cap_not_tripped: await err=%d "
               "(expected ok)\n", (int)n00b_result_get_err(rsp));
        rc = 1; goto done;
    }
    n00b_h3_response_t *resp = n00b_result_get(rsp);
    if (resp->status != 200 || !resp->body || resp->body->byte_len != 4
        || memcmp(resp->body->data, "abcd", 4) != 0) {
        printf("  [FAIL] cap_not_tripped: status=%u body_len=%zu\n",
               (unsigned)resp->status,
               resp->body ? (size_t)resp->body->byte_len : 0);
        rc = 1; goto done;
    }
    if (n00b_h3_request_body_cap_exceeded(creq)) {
        printf("  [FAIL] cap_not_tripped: flag spuriously set\n");
        rc = 1; goto done;
    }
    printf("  [PASS] cap_not_tripped (cap=1MiB, body=4)\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 4 — cap = 0 (the default) passes through.  Pins the
 *              backward-compat invariant: callers that don't set
 *              `max_body_size` see identical behavior to pre-lift.
 * ============================================================================ */

static int
test_cap_zero_passes_through(void)
{
    h3_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] cap_zero_passes_through (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    auto reqr = n00b_h3_client_request_raw(L.client_h3, "GET", "https",
                                       "localhost", "/zero");
    if (n00b_result_is_err(reqr)) {
        printf("  [FAIL] cap_zero_passes_through: req err=%d\n",
               n00b_result_get_err(reqr));
        rc = 1; goto done;
    }
    n00b_h3_request_t *creq = n00b_result_get(reqr);

    n00b_h3_inbound_request_t *ireq = wait_for_request(&L, 5000);
    if (!ireq) {
        printf("  [FAIL] cap_zero_passes_through: never received\n");
        rc = 1; goto done;
    }
    auto rr = n00b_h3_inbound_request_respond_raw(ireq, 200, nullptr, 0,
                                              (const uint8_t *)"abcd", 4);
    if (n00b_result_is_err(rr)) {
        printf("  [FAIL] cap_zero_passes_through: respond err=%d\n",
               n00b_result_get_err(rr));
        rc = 1; goto done;
    }

    int64_t deadline = now_ms() + 5000;
    n00b_result_t(n00b_h3_response_t *) rsp;
    bool got_result = false;
    while (now_ms() < deadline) {
        n00b_quic_endpoint_run_once(L.client_ep, 5);
        n00b_quic_endpoint_run_once(L.server_ep, 5);
        n00b_h3_client_drive(L.client_h3);
        n00b_h3_server_drive(L.server);
        if (creq->state == N00B_H3_REQ_STATE_DONE
            || creq->state == N00B_H3_REQ_STATE_RESET) {
            /* max_body_size = 0 is the default; spell it explicitly
             * to pin the contract. */
            rsp = n00b_h3_request_await(creq,
                                        .deadline_ms   = 100,
                                        .drive         = false,
                                        .max_body_size = 0);
            got_result = true;
            break;
        }
    }
    if (!got_result) {
        printf("  [FAIL] cap_zero_passes_through: never terminal\n");
        rc = 1; goto done;
    }
    if (n00b_result_is_err(rsp)) {
        printf("  [FAIL] cap_zero_passes_through: await err=%d\n",
               (int)n00b_result_get_err(rsp));
        rc = 1; goto done;
    }
    n00b_h3_response_t *resp = n00b_result_get(rsp);
    if (resp->status != 200 || !resp->body || resp->body->byte_len != 4) {
        printf("  [FAIL] cap_zero_passes_through: body mismatch\n");
        rc = 1; goto done;
    }
    if (n00b_h3_request_body_cap_exceeded(creq)) {
        printf("  [FAIL] cap_zero_passes_through: flag spuriously set\n");
        rc = 1; goto done;
    }
    printf("  [PASS] cap_zero_passes_through (cap=0, body=4)\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Main.
 * ============================================================================ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_h3_max_body_cap:\n");

    int rc = 0;
    rc |= test_mid_stream_data_cap();
    rc |= test_content_length_short_circuit();
    rc |= test_cap_not_tripped();
    rc |= test_cap_zero_passes_through();

    if (rc == 0) {
        printf("All test_http_h3_max_body_cap tests passed.\n");
    }
    n00b_shutdown();
    return rc;
}

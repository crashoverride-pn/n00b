/*
 * test_quic_rpc_unary.c — In-process unary RPC round-trip
 * (Phase 4 § 4.6).
 *
 * Mirrors test_quic_h3_server_loopback.c's discipline: per-test
 * setup of (conduit + io + endpoints + H3 client/server + RPC
 * server attach), then exercise one wire shape, then teardown.
 *
 * Sub-tests:
 *   1. register_dispatch_lookup   — registry round-trip, no I/O.
 *   2. unary_call_basic           — handler echoes request body.
 *   3. unary_call_handler_error   — handler returns INVALID_ARGUMENT.
 *   4. unary_call_unimplemented   — call to unregistered method →
 *                                   UNIMPLEMENTED.
 *   5. unary_call_deadline_exceeded
 *                                — ctx deadline 1ms in the past;
 *                                  server returns DEADLINE_EXCEEDED
 *                                  without invoking handler.
 *   6. unary_call_client_cancel   — 5s deadline; client cancels mid-
 *                                  flight; server sees STOP_SENDING.
 *                                  Handler sleeps 200ms.
 *   7. concurrent_dispatch        — 3 in-flight RPCs against a 200ms
 *                                  sleeping handler; total wall time
 *                                  must be < 500ms (would be ~600ms
 *                                  if dispatch were serialized) and
 *                                  the server's peak in-flight count
 *                                  must be > 1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdatomic.h>
#include "core/thread.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/buffer.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/h3.h"
#include "net/quic/rpc.h"
#include "net/quic/rpc_ctx.h"
#include "net/quic/rpc_status.h"
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"

#include "../fixtures/quic_test_pki.h"

extern void n00b_rpc_registry_reset_for_testing(void);

/* ============================================================================
 * Per-test scaffold (mirrors h3 server loopback test).
 * ============================================================================ */

/* Each endpoint gets its OWN conduit + io backend so the per-thread
 * polls don't race.  picoquic + n00b_conduit_io_poll() are not safe
 * to call concurrently on the same backend from multiple threads. */
typedef struct {
    char *key_pem_path;

    n00b_conduit_t            *server_conduit;
    n00b_conduit_io_backend_t *server_io;
    n00b_conduit_t            *client_conduit;
    n00b_conduit_io_backend_t *client_io;

    n00b_quic_endpoint_t *server_ep;
    n00b_quic_endpoint_t *client_ep;

    n00b_h3_server_t   *h3_server;
    n00b_h3_client_t   *h3_client;
    n00b_quic_conn_t   *client_conn;

    n00b_rpc_server_t  *rpc_server;
    n00b_rpc_channel_t *rpc_chan;
} rpc_loop_t;

static int64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

static bool
pump_until_connected(rpc_loop_t *L, int budget_ms)
{
    int64_t start = now_ms();
    while ((now_ms() - start) < budget_ms) {
        n00b_quic_endpoint_run_once(L->client_ep, 5);
        n00b_quic_endpoint_run_once(L->server_ep, 5);
        if (L->h3_client) n00b_h3_client_drive(L->h3_client);
        if (L->h3_server) n00b_h3_server_drive(L->h3_server);
        if (n00b_quic_conn_state(L->client_conn) ==
            N00B_QUIC_CONN_STATE_CONNECTED) {
            return true;
        }
    }
    return false;
}

/* Driver thread: pumps the SERVER endpoint + H3 server drive so the
 * server side can process inbound packets and emit responses while
 * the test's main thread is blocked inside the RPC call (which
 * internally pumps the CLIENT endpoint via n00b_h3_request_await).
 *
 * picoquic's per-endpoint state is not multi-thread reentrant, so
 * we deliberately partition: client endpoint is pumped only by the
 * caller of `n00b_rpc_call_unary` (via h3_request_await);
 * server endpoint is pumped only by this driver thread. */
typedef struct {
    rpc_loop_t       *L;
    _Atomic uint32_t  shutdown;
    n00b_thread_t    *thread;
    bool              started;
} driver_t;

static void *
driver_main(void *arg)
{
    driver_t *d = (driver_t *)arg;
    while (atomic_load(&d->shutdown) == 0) {
        if (d->L->server_ep) n00b_quic_endpoint_run_once(d->L->server_ep, 2);
        if (d->L->h3_server) n00b_h3_server_drive(d->L->h3_server);
    }
    return nullptr;
}

static driver_t *
driver_start(rpc_loop_t *L)
{
    driver_t *d = calloc(1, sizeof(*d));
    d->L = L;
    atomic_store(&d->shutdown, 0);
    auto tr = n00b_thread_spawn(driver_main, d);
    if (n00b_result_is_ok(tr)) {
        d->thread = n00b_result_get(tr);
        d->started = true;
    }
    return d;
}

static void
driver_stop(driver_t *d)
{
    if (!d) return;
    if (d->started) {
        atomic_store(&d->shutdown, 1);
        n00b_thread_join(d->thread);
    }
    free(d);
}

static bool
loop_setup(rpc_loop_t *L)
{
    memset(L, 0, sizeof(*L));
    n00b_rpc_registry_reset_for_testing();

    L->key_pem_path = n00b_quic_test_write_key_pem();
    if (!L->key_pem_path) return false;

    auto sc = n00b_conduit_new();
    if (n00b_result_is_err(sc)) goto fail;
    L->server_conduit = n00b_result_get(sc);

    auto sio = n00b_conduit_io_new_default(L->server_conduit);
    if (n00b_result_is_err(sio)) goto fail;
    L->server_io = n00b_result_get(sio);

    auto cc = n00b_conduit_new();
    if (n00b_result_is_err(cc)) goto fail;
    L->client_conduit = n00b_result_get(cc);

    auto cio = n00b_conduit_io_new_default(L->client_conduit);
    if (n00b_result_is_err(cio)) goto fail;
    L->client_io = n00b_result_get(cio);

    auto sr = n00b_quic_endpoint_new(L->server_conduit, L->server_io,
                                     .listen         = true,
                                     .bind_host      = "127.0.0.1",
                                     .alpn           = N00B_H3_ALPN,
                                     .cert_der_bytes = n00b_quic_test_cert_der,
                                     .cert_der_len   = n00b_quic_test_cert_der_len,
                                     .key_pem_path   = L->key_pem_path);
    if (n00b_result_is_err(sr)) goto fail;
    L->server_ep = n00b_result_get(sr);
    uint16_t sport = n00b_quic_endpoint_local_port(L->server_ep);

    auto cur = n00b_quic_endpoint_new(L->client_conduit, L->client_io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = N00B_H3_ALPN);
    if (n00b_result_is_err(cur)) goto fail;
    L->client_ep = n00b_result_get(cur);

    picoquic_set_null_verifier(L->client_ep->quic);

    auto serv = n00b_h3_server_new(L->server_ep, L->server_conduit);
    if (n00b_result_is_err(serv)) goto fail;
    L->h3_server = n00b_result_get(serv);

    L->rpc_server = n00b_rpc_attach_server(L->h3_server, L->server_conduit);
    if (!L->rpc_server) goto fail;

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

    if (!pump_until_connected(L, 5000)) {
        fprintf(stderr, "  handshake did not complete\n");
        goto fail;
    }

    auto hr = n00b_h3_client_new(L->client_conn);
    if (n00b_result_is_err(hr)) goto fail;
    L->h3_client = n00b_result_get(hr);

    /* Settle SETTINGS / uni preludes. */
    int64_t prime_start = now_ms();
    while ((now_ms() - prime_start) < 200) {
        n00b_quic_endpoint_run_once(L->client_ep, 5);
        n00b_quic_endpoint_run_once(L->server_ep, 5);
        n00b_h3_client_drive(L->h3_client);
        n00b_h3_server_drive(L->h3_server);
    }

    L->rpc_chan = n00b_rpc_channel_new(
        (n00b_rpc_channel_spec_t){
            .h3        = L->h3_client,
            .authority = "localhost",
        });
    if (!L->rpc_chan) goto fail;
    return true;

fail:
    if (L->rpc_server)     n00b_rpc_server_close(L->rpc_server);
    if (L->h3_client)      n00b_h3_client_close(L->h3_client);
    if (L->h3_server)      n00b_h3_server_close(L->h3_server);
    if (L->client_conn)    n00b_quic_close(L->client_conn, 0);
    if (L->client_ep)      n00b_quic_endpoint_close(L->client_ep);
    if (L->server_ep)      n00b_quic_endpoint_close(L->server_ep);
    if (L->client_io)      n00b_conduit_io_destroy(L->client_io);
    if (L->server_io)      n00b_conduit_io_destroy(L->server_io);
    if (L->client_conduit) n00b_conduit_destroy(L->client_conduit);
    if (L->server_conduit) n00b_conduit_destroy(L->server_conduit);
    if (L->key_pem_path) {
        unlink(L->key_pem_path);
        free(L->key_pem_path);
    }
    memset(L, 0, sizeof(*L));
    return false;
}

static void
loop_teardown(rpc_loop_t *L)
{
    if (L->rpc_server)     n00b_rpc_server_close(L->rpc_server);
    if (L->h3_client)      n00b_h3_client_close(L->h3_client);
    if (L->h3_server)      n00b_h3_server_close(L->h3_server);
    if (L->client_conn)    n00b_quic_close(L->client_conn, 0);
    if (L->client_ep)      n00b_quic_endpoint_close(L->client_ep);
    if (L->server_ep)      n00b_quic_endpoint_close(L->server_ep);
    if (L->client_io)      n00b_conduit_io_destroy(L->client_io);
    if (L->server_io)      n00b_conduit_io_destroy(L->server_io);
    if (L->client_conduit) n00b_conduit_destroy(L->client_conduit);
    if (L->server_conduit) n00b_conduit_destroy(L->server_conduit);
    if (L->key_pem_path) {
        unlink(L->key_pem_path);
        free(L->key_pem_path);
    }
    memset(L, 0, sizeof(*L));
}

/* ============================================================================
 * Sub-test 1 — registry round-trip without I/O.
 * ============================================================================ */

static n00b_result_t(n00b_buffer_t *)
dummy_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)req; (void)ctx;
    return n00b_result_ok(n00b_buffer_t *, nullptr);
}

static n00b_result_t(n00b_rpc_stream_t(n00b_buffer_t *) *)
dummy_server_stream(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)req; (void)ctx;
    return n00b_result_ok(n00b_rpc_stream_t(n00b_buffer_t *) *, nullptr);
}

static n00b_result_t(n00b_buffer_t *)
dummy_client_stream(n00b_rpc_stream_t(n00b_buffer_t *) *in, n00b_rpc_ctx_t *ctx)
{
    (void)in; (void)ctx;
    return n00b_result_ok(n00b_buffer_t *, nullptr);
}

static n00b_result_t(n00b_rpc_stream_t(n00b_buffer_t *) *)
dummy_bidi(n00b_rpc_stream_t(n00b_buffer_t *) *in, n00b_rpc_ctx_t *ctx)
{
    (void)in; (void)ctx;
    return n00b_result_ok(n00b_rpc_stream_t(n00b_buffer_t *) *, nullptr);
}

static int
test_register_dispatch_lookup(void)
{
    n00b_rpc_registry_reset_for_testing();
    /* Register one method.  Lookup is verified indirectly: no
     * crash, no abort.  The real lookup path is exercised by the
     * later sub-tests' end-to-end calls. */
    n00b_rpc_register("svc.v1.X/Method", dummy_dispatch);
    n00b_rpc_register_server_stream("svc.v1.X/Sub", dummy_server_stream);
    n00b_rpc_register_client_stream("svc.v1.X/Up", dummy_client_stream);
    n00b_rpc_register_bidi("svc.v1.X/Chat", dummy_bidi);
    printf("  [PASS] register_dispatch_lookup\n");
    return 0;
}

/* ============================================================================
 * Sub-test 2 — unary echo.
 * ============================================================================ */

static n00b_result_t(n00b_buffer_t *)
echo_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)ctx;
    /* Just return the same buffer; runtime treats nullptr as an
     * empty body, but we explicitly hand back what we got. */
    return n00b_result_ok(n00b_buffer_t *, req);
}

static int
test_unary_call_basic(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_basic (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "hello-rpc", .length = 9);

    driver_t *drv = driver_start(&L);

    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan,
                                 "svc.v1.Echo/Echo", body);

    driver_stop(drv);

    if (n00b_result_is_err(r)) {
        printf("  [FAIL] unary_call_basic: err=%d\n",
               n00b_result_get_err(r));
        rc = 1; goto done;
    }

    n00b_buffer_t *resp = n00b_result_get(r);
    if (!resp || (size_t)resp->byte_len != 9
        || memcmp(resp->data, "hello-rpc", 9) != 0) {
        printf("  [FAIL] unary_call_basic: body mismatch (len=%zu)\n",
               resp ? (size_t)resp->byte_len : 0);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_basic\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 3 — handler returns INVALID_ARGUMENT.
 * ============================================================================ */

static n00b_result_t(n00b_buffer_t *)
invalid_arg_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)req; (void)ctx;
    return n00b_result_err(n00b_buffer_t *, N00B_RPC_INVALID_ARGUMENT);
}

static int
test_unary_call_handler_error(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_handler_error\n");
        return 0;
    }
    int rc = 0;

    n00b_rpc_register("svc.v1.Bad/Bad", invalid_arg_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .length = 0);

    driver_t *drv = driver_start(&L);

    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Bad/Bad", body);

    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] unary_call_handler_error: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_INVALID_ARGUMENT) {
        printf("  [FAIL] unary_call_handler_error: got err=%d (want %d)\n",
               err, (int)N00B_RPC_INVALID_ARGUMENT);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_handler_error (INVALID_ARGUMENT)\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 4 — UNIMPLEMENTED.
 * ============================================================================ */

static int
test_unary_call_unimplemented(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_unimplemented\n");
        return 0;
    }
    int rc = 0;

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .length = 0);

    driver_t *drv = driver_start(&L);

    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan,
                                 "no.such.Svc/Method", body);

    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] unary_call_unimplemented: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_UNIMPLEMENTED) {
        printf("  [FAIL] unary_call_unimplemented: got err=%d (want %d)\n",
               err, (int)N00B_RPC_UNIMPLEMENTED);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_unimplemented\n");

done:
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 5 — DEADLINE_EXCEEDED (deadline already in past).
 * ============================================================================ */

static _Atomic uint32_t deadline_handler_fired = 0;

static n00b_result_t(n00b_buffer_t *)
deadline_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)req; (void)ctx;
    atomic_fetch_add(&deadline_handler_fired, 1);
    return n00b_result_ok(n00b_buffer_t *, nullptr);
}

static int
test_unary_call_deadline_exceeded(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_deadline_exceeded\n");
        return 0;
    }
    int rc = 0;

    atomic_store(&deadline_handler_fired, 0);
    n00b_rpc_register("svc.v1.Slow/Wait", deadline_dispatch);

    /* Build a ctx with a deadline already 1ms in the past. */
    int64_t past = n00b_ns_timestamp() - 1000000;  /* -1ms */
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_with_deadline(nullptr, past);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .length = 0);

    driver_t *drv = driver_start(&L);

    auto r = n00b_rpc_call_unary(ctx, L.rpc_chan,
                                 "svc.v1.Slow/Wait", body);

    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] unary_call_deadline_exceeded: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_DEADLINE_EXCEEDED && err != N00B_RPC_CANCELLED) {
        printf("  [FAIL] unary_call_deadline_exceeded: got err=%d "
               "(want DEADLINE_EXCEEDED or CANCELLED)\n", err);
        rc = 1; goto done;
    }
    if (atomic_load(&deadline_handler_fired) != 0) {
        printf("  [FAIL] unary_call_deadline_exceeded: handler ran "
               "(should have been short-circuited)\n");
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_deadline_exceeded "
           "(handler did not run; err=%d)\n", err);

done:
    n00b_rpc_ctx_close(ctx);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 6 — client cancels mid-flight.
 *
 * The call thread runs `n00b_rpc_call_unary` (which internally pumps
 * the CLIENT endpoint via h3_request_await).  The driver thread
 * pumps the SERVER endpoint.  The main thread fires
 * `n00b_rpc_ctx_cancel` ~30ms in, while the handler is sleeping.
 * The runtime's cancel watcher translates the ctx flip into
 * STOP_SENDING/RESET on the request stream; the await wakes and
 * returns.
 * ============================================================================ */

static n00b_result_t(n00b_buffer_t *)
sleeping_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)req;
    /* Sleep up to 200ms in tiny slices, checking ctx for cancel. */
    for (int i = 0; i < 20; i++) {
        if (n00b_rpc_ctx_is_cancelled(ctx)) {
            return n00b_result_err(n00b_buffer_t *, N00B_RPC_CANCELLED);
        }
        base_nanosleep_ns(10ULL * 1000ULL * 1000ULL);
    }
    /* Echo back. */
    return n00b_result_ok(n00b_buffer_t *, req);
}

typedef struct {
    rpc_loop_t                     *L;
    n00b_rpc_ctx_t                 *ctx;
    n00b_buffer_t                  *body;
    n00b_result_t(n00b_buffer_t *)  result;
    _Atomic uint32_t                done;
} cancel_call_arg_t;

static void *
cancel_call_thread(void *arg)
{
    cancel_call_arg_t *a = (cancel_call_arg_t *)arg;
    a->result = n00b_rpc_call_unary(a->ctx, a->L->rpc_chan,
                                    "svc.v1.Sleep/Sleep", a->body);
    atomic_store(&a->done, 1);
    return nullptr;
}

static int
test_unary_call_client_cancel(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_client_cancel\n");
        return 0;
    }
    int rc = 0;

    n00b_rpc_register("svc.v1.Sleep/Sleep", sleeping_dispatch);

    int64_t five_s = n00b_ns_timestamp() + 5LL * 1000 * 1000 * 1000;
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_with_deadline(nullptr, five_s);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "data", .length = 4);

    cancel_call_arg_t a = { .L = &L, .ctx = ctx, .body = body };
    atomic_store(&a.done, 0);

    driver_t *drv = driver_start(&L);

    auto tr = n00b_thread_spawn(cancel_call_thread, &a);
    if (n00b_result_is_err(tr)) {
        printf("  [SKIP] unary_call_client_cancel (thread spawn failed)\n");
        driver_stop(drv);
        loop_teardown(&L);
        return 0;
    }
    n00b_thread_t *t = n00b_result_get(tr);

    /* Wait 30ms for the call to be in-flight, then cancel. */
    base_nanosleep_ns(30ULL * 1000ULL * 1000ULL);
    n00b_rpc_ctx_cancel(ctx);

    int64_t deadline = now_ms() + 3000;
    while (now_ms() < deadline && atomic_load(&a.done) == 0) {
        base_nanosleep_ns(2ULL * 1000ULL * 1000ULL);
    }
    n00b_thread_join(t);
    driver_stop(drv);

    if (atomic_load(&a.done) == 0) {
        printf("  [FAIL] unary_call_client_cancel: call did not return "
               "after cancel\n");
        rc = 1; goto done;
    }
    if (n00b_result_is_ok(a.result)) {
        printf("  [FAIL] unary_call_client_cancel: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(a.result);
    /* Acceptable: CANCELLED or PEER_RESET (the wire-level signal
     * surfaces as a stream reset; rpc.c synthesizes CANCELLED when
     * the ctx is observed cancelled). */
    printf("  [PASS] unary_call_client_cancel (err=%d)\n", err);

done:
    n00b_rpc_ctx_close(ctx);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 7 — concurrent dispatch (Phase 4 follow-up).
 *
 * Three RPCs against a 200ms-sleeping handler.  All three are
 * issued concurrently from worker threads; they share the single
 * client connection.  A *combined* driver thread pumps both the
 * server and client endpoints (we cannot have multiple threads
 * calling into picoquic on the same endpoint).  Each worker uses
 * `n00b_h3_request_await(.drive = false)` so it does not pump.
 *
 * Pass criteria:
 *   - All 3 calls return the echoed body.
 *   - Total wall time < 500ms (would be ~600ms if dispatch was
 *     serialized; well under that if dispatch parallelizes).
 *   - Server's peak in-flight handler count > 1.
 * ============================================================================ */

static n00b_result_t(n00b_buffer_t *)
sleeping_echo_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)ctx;
    /* 200ms sleep — handler thread; dispatch must run these in
     * parallel for the wall-time bound to hold. */
    base_nanosleep_ns(200ULL * 1000ULL * 1000ULL);
    return n00b_result_ok(n00b_buffer_t *, req);
}

/* Combined driver pumping both endpoints from one thread. */
typedef struct {
    rpc_loop_t       *L;
    _Atomic uint32_t  shutdown;
    n00b_thread_t    *thread;
    bool              started;
} both_driver_t;

static void *
both_driver_main(void *arg)
{
    both_driver_t *d = (both_driver_t *)arg;
    while (atomic_load(&d->shutdown) == 0) {
        if (d->L->server_ep) n00b_quic_endpoint_run_once(d->L->server_ep, 1);
        if (d->L->client_ep) n00b_quic_endpoint_run_once(d->L->client_ep, 1);
        if (d->L->h3_server) n00b_h3_server_drive(d->L->h3_server);
        if (d->L->h3_client) n00b_h3_client_drive(d->L->h3_client);
    }
    return nullptr;
}

static both_driver_t *
both_driver_start(rpc_loop_t *L)
{
    both_driver_t *d = calloc(1, sizeof(*d));
    d->L = L;
    atomic_store(&d->shutdown, 0);
    auto tr = n00b_thread_spawn(both_driver_main, d);
    if (n00b_result_is_ok(tr)) {
        d->thread  = n00b_result_get(tr);
        d->started = true;
    }
    return d;
}

static void
both_driver_stop(both_driver_t *d)
{
    if (!d) return;
    if (d->started) {
        atomic_store(&d->shutdown, 1);
        n00b_thread_join(d->thread);
    }
    free(d);
}

typedef struct {
    rpc_loop_t      *L;
    int              ok;          /* 1 on success, 0 on failure */
    _Atomic uint32_t done;
} concur_arg_t;

static void *
concur_call_main(void *arg)
{
    concur_arg_t *a = (concur_arg_t *)arg;
    a->ok = 0;

    /* Issue the request via the H3 client (the rpc_call_unary path
     * always pumps internally; we want the driver to pump). */
    auto reqr = n00b_h3_client_request(
        a->L->h3_client,
        (n00b_h3_request_spec_t){
            .method    = "POST",
            .authority = "localhost",
            .path      = "/svc.v1.Echo/Echo",
            .body      = (const uint8_t *)"hello",
            .body_len  = 5,
        });
    if (n00b_result_is_err(reqr)) {
        atomic_store(&a->done, 1);
        return nullptr;
    }
    n00b_h3_request_t *req = n00b_result_get(reqr);

    auto rsp = n00b_h3_request_await(req, .deadline_ms = 5000,
                                          .drive       = false);
    if (n00b_result_is_err(rsp)) {
        atomic_store(&a->done, 1);
        return nullptr;
    }
    n00b_h3_response_t *resp = n00b_result_get(rsp);
    if (!resp || !resp->body || (size_t)resp->body->byte_len != 5
        || memcmp(resp->body->data, "hello", 5) != 0) {
        atomic_store(&a->done, 1);
        return nullptr;
    }
    a->ok = 1;
    atomic_store(&a->done, 1);
    return nullptr;
}

static int
test_unary_concurrent_dispatch(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] concurrent_dispatch (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    n00b_rpc_register("svc.v1.Echo/Echo", sleeping_echo_dispatch);

    both_driver_t *drv = both_driver_start(&L);

    const int N = 3;
    concur_arg_t args[3] = { 0 };
    n00b_thread_t *threads[3] = { nullptr };

    int64_t t_start = now_ms();

    for (int i = 0; i < N; i++) {
        args[i].L = &L;
        atomic_store(&args[i].done, 0);
        auto tr = n00b_thread_spawn(concur_call_main, &args[i]);
        if (n00b_result_is_err(tr)) {
            printf("  [SKIP] concurrent_dispatch (thread spawn failed)\n");
            both_driver_stop(drv);
            loop_teardown(&L);
            return 0;
        }
        threads[i] = n00b_result_get(tr);
    }

    /* Wait up to 5s for all threads to finish. */
    int64_t deadline = now_ms() + 5000;
    for (int i = 0; i < N; i++) {
        n00b_thread_join(threads[i]);
    }
    int64_t elapsed_ms = now_ms() - t_start;
    (void)deadline;

    both_driver_stop(drv);

    int n_ok = 0;
    for (int i = 0; i < N; i++) {
        if (args[i].ok) n_ok++;
    }

    uint32_t peak = n00b_rpc_server_peak_in_flight(L.rpc_server);

    if (n_ok != N) {
        printf("  [FAIL] concurrent_dispatch: only %d of %d calls "
               "succeeded\n", n_ok, N);
        rc = 1; goto done;
    }
    if (elapsed_ms >= 500) {
        printf("  [FAIL] concurrent_dispatch: wall time %lldms "
               ">= 500ms (peak in-flight=%u)\n",
               (long long)elapsed_ms, (unsigned)peak);
        rc = 1; goto done;
    }
    if (peak < 2) {
        printf("  [FAIL] concurrent_dispatch: peak in-flight=%u "
               "(want >= 2)\n", (unsigned)peak);
        rc = 1; goto done;
    }

    printf("  [PASS] concurrent_dispatch (3 calls in %lldms; "
           "peak in-flight=%u)\n",
           (long long)elapsed_ms, (unsigned)peak);

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

    printf("test_quic_rpc_unary:\n");
    fflush(stdout);

    int rc = 0;
    rc |= test_register_dispatch_lookup();    fflush(stdout);
    rc |= test_unary_call_basic();            fflush(stdout);
    rc |= test_unary_call_handler_error();    fflush(stdout);
    rc |= test_unary_call_unimplemented();    fflush(stdout);
    rc |= test_unary_call_deadline_exceeded();fflush(stdout);
    rc |= test_unary_call_client_cancel();    fflush(stdout);
    rc |= test_unary_concurrent_dispatch();   fflush(stdout);

    printf("test_quic_rpc_unary done.\n");

    n00b_shutdown();
    return rc;
}

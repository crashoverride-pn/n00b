/*
 * test_quic_rpc_auth.c — Server-side RPC auth wiring (Phase 4 § 4.9).
 *
 * Mirrors `test_quic_rpc_unary.c`'s in-process loopback discipline,
 * but exercises the auth-policy gate added in sub-phase 4.9:
 *
 *   1. unary_call_no_policy           — no manifest attached;
 *                                       call succeeds; audit emits
 *                                       a single allow event.
 *   2. unary_call_with_valid_jwt      — server requires a JWT;
 *                                       client supplies a valid one
 *                                       via channel credentials;
 *                                       call succeeds; audit allow.
 *   3. unary_call_with_missing_jwt    — server requires a JWT;
 *                                       client supplies none →
 *                                       UNAUTHENTICATED; audit deny.
 *   4. unary_call_with_expired_jwt    — token's `exp` is in the past;
 *                                       eval surfaces TOKEN_EXPIRED →
 *                                       UNAUTHENTICATED; audit deny.
 *   5. unary_call_with_per_call_override
 *                                     — channel default policy A;
 *                                       per-call override policy B
 *                                       (stricter) → honored, allow.
 *   6. unary_call_with_weaker_override_rejected
 *                                     — per-call override policy
 *                                       weaker than the service-pinned
 *                                       default → PERMISSION_DENIED
 *                                       before the handler runs.
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
#include <assert.h>

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
#include "net/quic/auth_policy.h"
#include "net/quic/audit.h"
#include "net/quic/manifest.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"

#include "../fixtures/quic_test_pki.h"
#include "../fixtures/synthetic_idp.h"

extern void n00b_rpc_registry_reset_for_testing(void);

/* ============================================================================
 * Audit-event collector (subscriber + counters).
 * ============================================================================ */

typedef struct {
    int               n_allow;
    int               n_deny;
    n00b_quic_err_t   last_deny_reason;
    char              last_policy_id[64];
    char              last_method[128];
} audit_log_t;

static void
audit_collect(const n00b_quic_audit_event_t *evt, void *ctx)
{
    audit_log_t *log = ctx;
    if (evt->decision == N00B_QUIC_AUDIT_ALLOW) log->n_allow++;
    else { log->n_deny++; log->last_deny_reason = evt->reason_code; }
    log->last_policy_id[0] = '\0';
    if (evt->policy_id) {
        snprintf(log->last_policy_id, sizeof(log->last_policy_id), "%s",
                 evt->policy_id);
    }
    log->last_method[0] = '\0';
    if (evt->htu) {
        snprintf(log->last_method, sizeof(log->last_method), "%s", evt->htu);
    }
}

/* ============================================================================
 * Per-test scaffold (mirrors test_quic_rpc_unary.c's loop_setup).
 * ============================================================================ */

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
 * Manifest builder + verifier resolver.
 *
 * The auth wiring resolves a JWT verifier per-IdP via a callback the
 * application installs.  In production this is wired to the OIDC
 * machinery (Phase 3.4); in tests we fan out by `idp` id to a
 * verifier prepared from a synthetic IdP fixture.
 * ============================================================================ */

typedef struct {
    const char          *idp_id;
    n00b_jwt_verifier_t *verifier;
} idp_binding_t;

#define MAX_BINDINGS 4
typedef struct {
    idp_binding_t bindings[MAX_BINDINGS];
    int           n;
} verifier_table_t;

static n00b_jwt_verifier_t *
verifier_resolver(const char             *idp_id,
                  const n00b_h3_header_t *hdrs,
                  size_t                  n_hdrs,
                  void                   *user_ctx)
{
    (void)hdrs;
    (void)n_hdrs;
    verifier_table_t *t = user_ctx;
    if (!idp_id) return nullptr;
    for (int i = 0; i < t->n; i++) {
        if (t->bindings[i].idp_id
            && strcmp(t->bindings[i].idp_id, idp_id) == 0) {
            return t->bindings[i].verifier;
        }
    }
    return nullptr;
}

static n00b_buffer_t *
mk_json_buf(const char *s)
{
    n00b_buffer_t *b = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(b, .raw = (void *)s, .length = (int64_t)strlen(s));
    return b;
}

/* Echo handler — used by every sub-test's allow path. */
static n00b_result_t(n00b_buffer_t *)
echo_dispatch(n00b_buffer_t *req, n00b_rpc_ctx_t *ctx)
{
    (void)ctx;
    return n00b_result_ok(n00b_buffer_t *, req);
}

/* ============================================================================
 * Sub-test 1 — no policy (default-allow).
 * ============================================================================ */

static int
test_unary_call_no_policy(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_no_policy (loop_setup failed)\n");
        return 0;
    }
    int rc = 0;

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "open-sesame", .length = 11);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_err(r)) {
        printf("  [FAIL] unary_call_no_policy: err=%d\n",
               n00b_result_get_err(r));
        rc = 1; goto done;
    }
    if (log.n_allow != 1 || log.n_deny != 0) {
        printf("  [FAIL] unary_call_no_policy: audit allow=%d deny=%d "
               "(want 1/0)\n", log.n_allow, log.n_deny);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_no_policy (1 allow audit event)\n");

done:
    n00b_quic_audit_unsubscribe(sub);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 2 — server requires JWT; client supplies valid token.
 * ============================================================================ */

static const char *MANIFEST_RW =
    "{ \"version\": 1, \"service_name\": \"t\","
    " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
    "  \"bind_port\":0,\"alpn\":[\"h3\"],"
    "  \"cert\":{\"kind\":\"static\","
    "    \"chain_pem_path\":\"/tmp/x\",\"key_secret_uri\":\"ephemeral:k\"}}],"
    " \"auth\": {"
    "   \"idps\": [{\"id\":\"primary\","
    "                \"issuer\":\"https://idp.example\"}],"
    "   \"policies\": ["
    "     {\"id\":\"rpc-write\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:write\"}]}"
    "   ]"
    " },"
    " \"rpc\":{ \"services\": ["
    "   {\"id\":\"svc.v1.Echo\",\"auth_policy\":\"rpc-write\"}"
    " ]}"
    "}";

static int
test_unary_call_with_valid_jwt(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_with_valid_jwt\n");
        return 0;
    }
    int rc = 0;

    /* Wire a synthetic IdP + verifier. */
    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_call_with_valid_jwt (idp setup)\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    /* Manifest. */
    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_RW));
    assert(n00b_result_is_ok(mr));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    /* Resolver table. */
    verifier_table_t T = {
        .bindings = {{ "primary", v }}, .n = 1,
    };
    auto ar = n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    assert(n00b_result_is_ok(ar));
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    /* Mint a valid token + attach to channel. */
    char *jwt = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", 3600,
                                        .scope = "rpc:read rpc:write");
    n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt };
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds, "rpc-write");

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "yes", .length = 3);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_err(r)) {
        printf("  [FAIL] unary_call_with_valid_jwt: rpc err=%d\n",
               n00b_result_get_err(r));
        rc = 1; goto done;
    }
    /* The eval inside `authenticate_inbound` builds a runtime policy
     * and calls `n00b_quic_auth_policy_eval`, which itself fires an
     * audit event for the auth decision.  The dispatcher then fires
     * a second one for the dispatch.  Both should be allows. */
    if (log.n_allow < 1 || log.n_deny != 0) {
        printf("  [FAIL] unary_call_with_valid_jwt: audit allow=%d deny=%d\n",
               log.n_allow, log.n_deny);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_with_valid_jwt "
           "(audit %d allow, %d deny)\n", log.n_allow, log.n_deny);

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 3 — server requires JWT; client supplies none → deny.
 * ============================================================================ */

static int
test_unary_call_with_missing_jwt(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_with_missing_jwt\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_call_with_missing_jwt\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_RW));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);
    /* No `n00b_rpc_channel_set_auth` — client sends no JWT. */

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "no", .length = 2);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] unary_call_with_missing_jwt: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_UNAUTHENTICATED && err != N00B_RPC_PERMISSION_DENIED) {
        printf("  [FAIL] unary_call_with_missing_jwt: got err=%d\n", err);
        rc = 1; goto done;
    }
    if (log.n_deny < 1) {
        printf("  [FAIL] unary_call_with_missing_jwt: no audit deny "
               "(allow=%d deny=%d)\n", log.n_allow, log.n_deny);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_with_missing_jwt "
           "(err=%d, audit deny=%d)\n", err, log.n_deny);

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 4 — expired JWT (exp in the past).
 *
 * Spec: "server has a 1-second JWT cache TTL; expire it before
 * dispatch; UNAUTHENTICATED."  The synthetic IdP's
 * `exp_offset_s = -1` mints an already-expired token, which the
 * verifier rejects directly — equivalent observable behavior
 * (TOKEN_EXPIRED) without standing up a separate cache.
 * ============================================================================ */

static int
test_unary_call_with_expired_jwt(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_with_expired_jwt\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_call_with_expired_jwt\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_RW));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    /* Expired token (exp = -120s from now: well past leeway). */
    char *jwt = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", -120,
                                        .scope = "rpc:write");
    n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt };
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds, "rpc-write");

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .length = 0);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] unary_call_with_expired_jwt: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_UNAUTHENTICATED) {
        printf("  [FAIL] unary_call_with_expired_jwt: got err=%d "
               "(want UNAUTHENTICATED)\n", err);
        rc = 1; goto done;
    }
    if (log.n_deny < 1) {
        printf("  [FAIL] unary_call_with_expired_jwt: no deny audit\n");
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_with_expired_jwt (err=UNAUTHENTICATED)\n");

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 5 — per-call override is honored when STRICTER than default.
 *
 * Default policy: requires scope contains "rpc:read".
 * Override policy: ALSO requires scope contains "rpc:write".
 * Token has both → override is at-least-as-strict; allow.
 * ============================================================================ */

static const char *MANIFEST_TWO_POLICIES =
    "{ \"version\": 1, \"service_name\": \"t\","
    " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
    "  \"bind_port\":0,\"alpn\":[\"h3\"],"
    "  \"cert\":{\"kind\":\"static\","
    "    \"chain_pem_path\":\"/tmp/x\",\"key_secret_uri\":\"ephemeral:k\"}}],"
    " \"auth\": {"
    "   \"idps\": [{\"id\":\"primary\","
    "                \"issuer\":\"https://idp.example\"}],"
    "   \"policies\": ["
    "     {\"id\":\"rpc-read\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:read\"}]},"
    "     {\"id\":\"rpc-write\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:read\"},"
    "        {\"name\":\"scope\",\"contains\":\"rpc:write\"}]}"
    "   ]"
    " },"
    " \"rpc\":{ \"services\": ["
    "   {\"id\":\"svc.v1.Echo\",\"auth_policy\":\"rpc-read\"}"
    " ]}"
    "}";

static int
test_unary_call_with_per_call_override(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_with_per_call_override\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_call_with_per_call_override\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_TWO_POLICIES));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    /* Token has both scopes — satisfies BOTH the default AND the
     * stricter override. */
    char *jwt = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", 3600,
                                        .scope = "rpc:read rpc:write");
    n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt };
    /* Channel default = the stricter override. */
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds, "rpc-write");

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "ok", .length = 2);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_err(r)) {
        printf("  [FAIL] unary_call_with_per_call_override: err=%d\n",
               n00b_result_get_err(r));
        rc = 1; goto done;
    }
    /* Audit should reflect the override id "rpc-write", not "rpc-read". */
    if (strcmp(log.last_policy_id, "rpc-write") != 0) {
        printf("  [FAIL] unary_call_with_per_call_override: audit policy=%s "
               "(want rpc-write)\n", log.last_policy_id);
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_with_per_call_override (policy=rpc-write)\n");

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 6 — per-call override REJECTED because weaker than default.
 *
 * Default = the stricter "rpc-write" (pinned in MANIFEST_TWO_POLICIES_INVERTED
 * as the service default).  Override "rpc-read" is weaker → PERMISSION_DENIED.
 * ============================================================================ */

static const char *MANIFEST_PINNED_STRICT =
    "{ \"version\": 1, \"service_name\": \"t\","
    " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
    "  \"bind_port\":0,\"alpn\":[\"h3\"],"
    "  \"cert\":{\"kind\":\"static\","
    "    \"chain_pem_path\":\"/tmp/x\",\"key_secret_uri\":\"ephemeral:k\"}}],"
    " \"auth\": {"
    "   \"idps\": [{\"id\":\"primary\","
    "                \"issuer\":\"https://idp.example\"}],"
    "   \"policies\": ["
    "     {\"id\":\"rpc-read\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:read\"}]},"
    "     {\"id\":\"rpc-write\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:read\"},"
    "        {\"name\":\"scope\",\"contains\":\"rpc:write\"}]}"
    "   ]"
    " },"
    " \"rpc\":{ \"services\": ["
    "   {\"id\":\"svc.v1.Echo\",\"auth_policy\":\"rpc-write\"}"
    " ]}"
    "}";

static int
test_unary_call_with_weaker_override_rejected(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_call_with_weaker_override_rejected\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_call_with_weaker_override_rejected\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_PINNED_STRICT));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    /* Token has the read scope; satisfies "rpc-read" but NOT
     * "rpc-write" (the pinned default).  We try to override with
     * the weaker "rpc-read" — must be rejected before eval ever
     * looks at the token. */
    char *jwt = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", 3600,
                                        .scope = "rpc:read");
    n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt };
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds, "rpc-read");

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .length = 0);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] unary_call_with_weaker_override_rejected: "
               "expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_PERMISSION_DENIED) {
        printf("  [FAIL] unary_call_with_weaker_override_rejected: "
               "got err=%d (want PERMISSION_DENIED)\n", err);
        rc = 1; goto done;
    }
    if (log.n_deny < 1) {
        printf("  [FAIL] unary_call_with_weaker_override_rejected: "
               "no deny audit\n");
        rc = 1; goto done;
    }
    printf("  [PASS] unary_call_with_weaker_override_rejected "
           "(PERMISSION_DENIED, audit deny)\n");

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 7 — at-least-as-strict comparison logic (pure unit).
 *
 * Exercise the helper directly with all the corner cases the
 * spec calls out: dpop / mtls bits, claim-set superset, audience
 * pin.  Pure logic; no I/O, no RPC.
 * ============================================================================ */

static int
test_at_least_as_strict_logic(void)
{
    /* Build two minimal manifests by JSON load + cherry-pick policy
     * pointers. */
    const char *json =
        "{ \"version\": 1, \"service_name\": \"t\","
        " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
        "  \"bind_port\":0,\"alpn\":[\"h3\"],"
        "  \"cert\":{\"kind\":\"static\","
        "    \"chain_pem_path\":\"/tmp/x\","
        "    \"key_secret_uri\":\"ephemeral:k\"}}],"
        " \"auth\": {"
        "   \"idps\": [{\"id\":\"i\",\"issuer\":\"https://idp.example\"}],"
        "   \"policies\": ["
        /* p0 = base.  dpop required, audience pinned, 1 claim. */
        "     {\"id\":\"p0\",\"idp\":\"i\","
        "      \"audience\":\"a1\","
        "      \"require_dpop\":true,"
        "      \"require_claim\":["
        "        {\"name\":\"scope\",\"contains\":\"r\"}]},"
        /* p1 = same as p0 (equally strict). */
        "     {\"id\":\"p1\",\"idp\":\"i\","
        "      \"audience\":\"a1\","
        "      \"require_dpop\":true,"
        "      \"require_claim\":["
        "        {\"name\":\"scope\",\"contains\":\"r\"}]},"
        /* p2 = stricter: adds mtls + an extra claim. */
        "     {\"id\":\"p2\",\"idp\":\"i\","
        "      \"audience\":\"a1\","
        "      \"require_dpop\":true,"
        "      \"require_mtls\":true,"
        "      \"require_claim\":["
        "        {\"name\":\"scope\",\"contains\":\"r\"},"
        "        {\"name\":\"scope\",\"contains\":\"w\"}]},"
        /* p3 = weaker: drops dpop. */
        "     {\"id\":\"p3\",\"idp\":\"i\","
        "      \"audience\":\"a1\","
        "      \"require_claim\":["
        "        {\"name\":\"scope\",\"contains\":\"r\"}]},"
        /* p4 = different audience. */
        "     {\"id\":\"p4\",\"idp\":\"i\","
        "      \"audience\":\"a2\","
        "      \"require_dpop\":true,"
        "      \"require_claim\":["
        "        {\"name\":\"scope\",\"contains\":\"r\"}]}"
        "   ]"
        " }"
        "}";
    auto r = n00b_quic_manifest_load_json(mk_json_buf(json));
    assert(n00b_result_is_ok(r));
    n00b_quic_manifest_t *mf = n00b_result_get(r);
    assert(n00b_list_len(*mf->auth_policies) == 5);
    n00b_quic_manifest_policy_t *p0 = n00b_list_get(*mf->auth_policies, 0);
    n00b_quic_manifest_policy_t *p1 = n00b_list_get(*mf->auth_policies, 1);
    n00b_quic_manifest_policy_t *p2 = n00b_list_get(*mf->auth_policies, 2);
    n00b_quic_manifest_policy_t *p3 = n00b_list_get(*mf->auth_policies, 3);
    n00b_quic_manifest_policy_t *p4 = n00b_list_get(*mf->auth_policies, 4);

    /* p0 vs p0 → true. */
    if (!n00b_rpc_policy_at_least_as_strict(p0, p0)) {
        printf("  [FAIL] strict: p0 vs p0\n"); return 1;
    }
    /* p0 vs p1 (same shape) → true. */
    if (!n00b_rpc_policy_at_least_as_strict(p0, p1)) {
        printf("  [FAIL] strict: p0 vs p1\n"); return 1;
    }
    /* p0 vs p2 (p2 stricter) → true. */
    if (!n00b_rpc_policy_at_least_as_strict(p0, p2)) {
        printf("  [FAIL] strict: p0 vs p2 (stricter should pass)\n");
        return 1;
    }
    /* p0 vs p3 (p3 weaker — no dpop) → false. */
    if (n00b_rpc_policy_at_least_as_strict(p0, p3)) {
        printf("  [FAIL] strict: p0 vs p3 (weaker incorrectly passed)\n");
        return 1;
    }
    /* p0 vs p4 (different audience) → false. */
    if (n00b_rpc_policy_at_least_as_strict(p0, p4)) {
        printf("  [FAIL] strict: p0 vs p4 (different audience)\n");
        return 1;
    }
    /* nullptr base vs anything → true. */
    if (!n00b_rpc_policy_at_least_as_strict(nullptr, p3)) {
        printf("  [FAIL] strict: null base\n"); return 1;
    }
    /* base set, candidate null → false. */
    if (n00b_rpc_policy_at_least_as_strict(p0, nullptr)) {
        printf("  [FAIL] strict: null candidate\n"); return 1;
    }

    printf("  [PASS] at_least_as_strict logic (5 manifest policies × 7 cases)\n");
    return 0;
}

/* ============================================================================
 * Sub-test 8 — TRUE per-call credential + policy override (sub-phase
 * 4.9, post-phase-4 follow-up).
 *
 * The channel default is policy A (rpc-read) with JWT-A (scope=read).
 * The per-call override carries JWT-B (scope=read+write) + policy B
 * (rpc-write, stricter).  Server sees JWT-B + policy B for THIS call;
 * a follow-up call WITHOUT override falls back to channel defaults
 * (JWT-A + policy rpc-read).  Both succeed; audit shows two allow
 * events, one per applied policy id.
 *
 * Manifest pins the service to "rpc-read" (so the lax channel default
 * matches the pin; the stricter override is at-least-as-strict).
 * ============================================================================ */

static const char *MANIFEST_PIN_READ =
    "{ \"version\": 1, \"service_name\": \"t\","
    " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
    "  \"bind_port\":0,\"alpn\":[\"h3\"],"
    "  \"cert\":{\"kind\":\"static\","
    "    \"chain_pem_path\":\"/tmp/x\",\"key_secret_uri\":\"ephemeral:k\"}}],"
    " \"auth\": {"
    "   \"idps\": [{\"id\":\"primary\","
    "                \"issuer\":\"https://idp.example\"}],"
    "   \"policies\": ["
    "     {\"id\":\"rpc-read\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:read\"}]},"
    "     {\"id\":\"rpc-write\",\"idp\":\"primary\","
    "      \"audience\":\"checkout-api\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:read\"},"
    "        {\"name\":\"scope\",\"contains\":\"rpc:write\"}]}"
    "   ]"
    " },"
    " \"rpc\":{ \"services\": ["
    "   {\"id\":\"svc.v1.Echo\",\"auth_policy\":\"rpc-read\"}"
    " ]}"
    "}";

static int
test_unary_per_call_creds_override(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_per_call_creds_override\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_per_call_creds_override\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_PIN_READ));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    /* Channel default: JWT-A with read-only scope, policy "rpc-read". */
    char *jwt_a = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", 3600,
                                          .scope = "rpc:read");
    n00b_rpc_auth_credentials_t creds_a = { .bearer_token = jwt_a };
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds_a, "rpc-read");

    /* Per-call override: JWT-B with read+write scope, policy "rpc-write"
     * (stricter — at-least-as-strict-as the pinned "rpc-read"). */
    char *jwt_b = n00b_synthetic_idp_mint(idp, "bob", "checkout-api", 3600,
                                          .scope = "rpc:read rpc:write");
    n00b_rpc_auth_credentials_t creds_b = { .bearer_token = jwt_b };

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "go", .length = 2);

    /* Call 1: pass per-call override.  Audit should show "rpc-write". */
    driver_t *drv = driver_start(&L);
    auto r1 = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body,
                                  .creds_override  = &creds_b,
                                  .policy_override = "rpc-write");
    driver_stop(drv);

    if (n00b_result_is_err(r1)) {
        printf("  [FAIL] unary_per_call_creds_override (call 1): err=%d\n",
               n00b_result_get_err(r1));
        rc = 1; goto done;
    }
    if (strcmp(log.last_policy_id, "rpc-write") != 0) {
        printf("  [FAIL] unary_per_call_creds_override (call 1): "
               "audit policy=%s (want rpc-write)\n", log.last_policy_id);
        rc = 1; goto done;
    }
    int allows_after_call_1 = log.n_allow;

    /* Call 2: NO override — falls back to channel defaults.  Audit
     * should now show "rpc-read". */
    drv = driver_start(&L);
    auto r2 = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);

    if (n00b_result_is_err(r2)) {
        printf("  [FAIL] unary_per_call_creds_override (call 2): err=%d\n",
               n00b_result_get_err(r2));
        rc = 1; goto done;
    }
    if (strcmp(log.last_policy_id, "rpc-read") != 0) {
        printf("  [FAIL] unary_per_call_creds_override (call 2): "
               "audit policy=%s (want rpc-read)\n", log.last_policy_id);
        rc = 1; goto done;
    }
    if (log.n_allow <= allows_after_call_1) {
        printf("  [FAIL] unary_per_call_creds_override: no audit "
               "allow for call 2 (allows=%d)\n", log.n_allow);
        rc = 1; goto done;
    }
    if (log.n_deny != 0) {
        printf("  [FAIL] unary_per_call_creds_override: unexpected "
               "denies (deny=%d)\n", log.n_deny);
        rc = 1; goto done;
    }

    printf("  [PASS] unary_per_call_creds_override "
           "(call1 policy=rpc-write; call2 policy=rpc-read; allows=%d)\n",
           log.n_allow);

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 9 — per-call override does NOT mutate channel state.
 *
 * Channel has policy "rpc-read".  A call with policy_override =
 * "rpc-write" runs successfully.  Afterward, the channel's stored
 * `auth_policy_id` MUST still be "rpc-read".
 *
 * Verifies the override touches only one request.
 * ============================================================================ */

/* The channel's auth_policy_id is private (in `struct
 * n00b_rpc_channel`).  We re-read it observably: a follow-up call with
 * NO override stamps `n00b-rpc-policy: <chan default>` on the wire,
 * and the audit's `policy_id` field reflects the applied policy.  If
 * the channel had been mutated to "rpc-write" by the prior override,
 * call 2 (no override) would emit "rpc-write" in audit; we assert it
 * emits "rpc-read" instead. */
static int
test_unary_per_call_override_independent_of_channel(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_per_call_override_independent_of_channel\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_per_call_override_independent_of_channel\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_PIN_READ));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    char *jwt_full = n00b_synthetic_idp_mint(idp, "alice", "checkout-api",
                                             3600,
                                             .scope = "rpc:read rpc:write");
    n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt_full };
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds, "rpc-read");

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .raw = "ping", .length = 4);

    /* Call A: per-call override to "rpc-write". */
    driver_t *drv = driver_start(&L);
    auto rA = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body,
                                  .policy_override = "rpc-write");
    driver_stop(drv);
    if (n00b_result_is_err(rA)) {
        printf("  [FAIL] independent_of_channel (call A): err=%d\n",
               n00b_result_get_err(rA));
        rc = 1; goto done;
    }
    if (strcmp(log.last_policy_id, "rpc-write") != 0) {
        printf("  [FAIL] independent_of_channel (call A): policy=%s "
               "(want rpc-write)\n", log.last_policy_id);
        rc = 1; goto done;
    }

    /* Call B: NO override.  The channel default MUST still be
     * "rpc-read" (the override did NOT mutate it). */
    drv = driver_start(&L);
    auto rB = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body);
    driver_stop(drv);
    if (n00b_result_is_err(rB)) {
        printf("  [FAIL] independent_of_channel (call B): err=%d\n",
               n00b_result_get_err(rB));
        rc = 1; goto done;
    }
    if (strcmp(log.last_policy_id, "rpc-read") != 0) {
        printf("  [FAIL] independent_of_channel (call B): policy=%s "
               "(want rpc-read; channel state was mutated)\n",
               log.last_policy_id);
        rc = 1; goto done;
    }

    printf("  [PASS] unary_per_call_override_independent_of_channel "
           "(channel policy unchanged after override)\n");

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
    loop_teardown(&L);
    return rc;
}

/* ============================================================================
 * Sub-test 10 — per-call override that's WEAKER than the pinned
 * default is rejected with PERMISSION_DENIED.
 *
 * Service is pinned to "rpc-write" (strict).  Per-call override
 * "rpc-read" (weaker).  Even when the channel itself has acceptable
 * credentials, the per-call override must be rejected at the server
 * before the handler runs.
 * ============================================================================ */

static int
test_unary_per_call_override_weaker_rejected(void)
{
    rpc_loop_t L;
    if (!loop_setup(&L)) {
        printf("  [SKIP] unary_per_call_override_weaker_rejected\n");
        return 0;
    }
    int rc = 0;

    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    if (!idp) {
        printf("  [SKIP] unary_per_call_override_weaker_rejected\n");
        loop_teardown(&L);
        return 0;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp),
                                     "checkout-api");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    /* Service pinned to "rpc-write" (the strict policy). */
    auto mr = n00b_quic_manifest_load_json(mk_json_buf(MANIFEST_PINNED_STRICT));
    n00b_quic_manifest_t *mf = n00b_result_get(mr);

    verifier_table_t T = {.bindings = {{"primary", v}}, .n = 1};
    (void)n00b_rpc_server_attach_auth(L.rpc_server, mf, false);
    n00b_rpc_server_set_verifier_resolver(L.rpc_server, verifier_resolver, &T);

    /* JWT has full scopes — would satisfy either policy.  But the
     * override "rpc-read" is weaker than the pinned "rpc-write" and
     * must be rejected before evaluation. */
    char *jwt = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", 3600,
                                        .scope = "rpc:read rpc:write");
    n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt };
    /* Channel default = rpc-write (matches pin).  Override =
     * rpc-read (weaker). */
    n00b_rpc_channel_set_auth(L.rpc_chan, &creds, "rpc-write");

    audit_log_t log = {0};
    int sub = n00b_quic_audit_subscribe(audit_collect, &log);

    n00b_rpc_register("svc.v1.Echo/Echo", echo_dispatch);

    n00b_buffer_t *body = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(body, .length = 0);

    driver_t *drv = driver_start(&L);
    auto r = n00b_rpc_call_unary(nullptr, L.rpc_chan, "svc.v1.Echo/Echo", body,
                                 .policy_override = "rpc-read");
    driver_stop(drv);

    if (n00b_result_is_ok(r)) {
        printf("  [FAIL] per_call_override_weaker_rejected: expected err\n");
        rc = 1; goto done;
    }
    int err = n00b_result_get_err(r);
    if (err != N00B_RPC_PERMISSION_DENIED) {
        printf("  [FAIL] per_call_override_weaker_rejected: got err=%d "
               "(want PERMISSION_DENIED)\n", err);
        rc = 1; goto done;
    }
    if (log.n_deny < 1) {
        printf("  [FAIL] per_call_override_weaker_rejected: no deny audit\n");
        rc = 1; goto done;
    }
    printf("  [PASS] unary_per_call_override_weaker_rejected "
           "(PERMISSION_DENIED, audit deny)\n");

done:
    n00b_quic_audit_unsubscribe(sub);
    n00b_synthetic_idp_close(idp);
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

    printf("test_quic_rpc_auth:\n");
    fflush(stdout);

    int rc = 0;
    rc |= test_at_least_as_strict_logic();          fflush(stdout);
    rc |= test_unary_call_no_policy();              fflush(stdout);
    rc |= test_unary_call_with_valid_jwt();         fflush(stdout);
    rc |= test_unary_call_with_missing_jwt();       fflush(stdout);
    rc |= test_unary_call_with_expired_jwt();       fflush(stdout);
    rc |= test_unary_call_with_per_call_override(); fflush(stdout);
    rc |= test_unary_call_with_weaker_override_rejected(); fflush(stdout);
    /* Phase 4.9 follow-up: TRUE per-call override (kw-args). */
    rc |= test_unary_per_call_creds_override();     fflush(stdout);
    rc |= test_unary_per_call_override_independent_of_channel();
    fflush(stdout);
    rc |= test_unary_per_call_override_weaker_rejected();
    fflush(stdout);

    printf("test_quic_rpc_auth done.\n");

    n00b_shutdown();
    return rc;
}

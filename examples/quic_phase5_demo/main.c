/*
 * main.c — Phase 5 multi-tenant demo entry + loopback driver.
 *
 * Modes:
 *   --loopback                 — server + client in one process
 *
 * The loopback brings up:
 *   1. Two synthetic IdPs (`alpha` + `beta`).
 *   2. A QUIC + H3 + RPC server with the manifest installed.
 *   3. A `n00b_quic_metric_registry_t` threaded through endpoint +
 *      audit + RPC server, plus a `/metrics` listener on an ephemeral
 *      port.
 *   4. A tenant resolver that reads `X-Tenant` (or falls back to
 *      `idp_id`) from inbound H3 headers.
 *
 * The driver mints tokens via each tenant's IdP, opens an RPC
 * channel, exercises all five services, scrapes `/metrics`, and
 * asserts the expected counters fired.
 *
 * The synthetic-IdP loopback covers the non-mTLS / non-DPoP-jkt
 * paths.  Production deployments swap in real Keycloak/ZITADEL via
 * the manifest's `auth.idps[].issuer` (Phase 5.5 / 5.11).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/thread.h"
#include "core/sha256.h"
#include "core/time.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/h3.h"
#include "net/quic/cbor.h"
#include "net/quic/rpc.h"
#include "net/quic/rpc_ctx.h"
#include "net/quic/rpc_status.h"
#include "crypto/trust.h"
#include "net/quic/audit.h"
#include "net/quic/manifest.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"
#include "crypto/dpop.h"
#include "net/quic/auth_policy.h"
#include "crypto/secret.h"
#include "net/quic/metrics.h"
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"

#include "../../test/fixtures/quic_test_pki.h"
#include "../../test/fixtures/synthetic_idp.h"

#include "services.h"
#include "tenant_resolver.h"

/* ============================================================================
 * Time helpers + cert pinning.
 * ============================================================================ */

static int64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

static void
sha256_be32(const void *data, size_t len, uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(data, len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i*4    ] = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >>  8);
        out[i*4 + 3] = (uint8_t)(w      );
    }
}

static n00b_quic_trust_t *
build_pinned_trust_for_test_cert(void)
{
    uint8_t fp[32];
    sha256_be32(n00b_quic_test_cert_der, n00b_quic_test_cert_der_len, fp);
    return n00b_quic_trust_pinned(fp);
}

static n00b_buffer_t *
mk_json_buf(const char *s)
{
    n00b_buffer_t *b = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(b, .raw = (void *)s, .length = (int64_t)strlen(s));
    return b;
}

/* ============================================================================
 * Audit subscriber — one stderr line per dispatch.
 * ============================================================================ */

static void
audit_stderr(const n00b_quic_audit_event_t *evt, void *ctx)
{
    (void)ctx;
    const char *dec = (evt->decision == N00B_QUIC_AUDIT_ALLOW) ? "ALLOW" : "DENY";
    fprintf(stderr, "[audit] %s %s policy=%s sub=%s aud=%s\n",
            dec,
            evt->htu       ? evt->htu       : "?",
            evt->policy_id ? evt->policy_id : "-",
            evt->sub       ? evt->sub       : "-",
            evt->aud       ? evt->aud       : "-");
}

/* ============================================================================
 * Manifest.  Two IdPs, five services, five matching policies.
 *
 * Each policy sets `idp` to its tenant's id; the tenant resolver routes
 * by either the X-Tenant header (when present) or the `idp_id` argument
 * passed in by the runtime.
 * ============================================================================ */

static const char *PHASE5_MANIFEST_JSON =
    "{ \"version\": 1, \"service_name\": \"quic_phase5_demo\","
    " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
    "  \"bind_port\":0,\"alpn\":[\"h3\"],"
    "  \"cert\":{\"kind\":\"static\","
    "    \"chain_pem_path\":\"/tmp/x\","
    "    \"key_secret_uri\":\"ephemeral:k\"}}],"
    " \"auth\": {"
    "   \"idps\": ["
    "     {\"id\":\"alpha\",\"issuer\":\"https://idp.alpha.example\"},"
    "     {\"id\":\"beta\", \"issuer\":\"https://idp.beta.example\"}"
    "   ],"
    "   \"policies\": ["
    "     {\"id\":\"greeter-default\",\"idp\":\"alpha\","
    "      \"audience\":\"phase5-alpha\"},"
    "     {\"id\":\"vault-read\",\"idp\":\"alpha\","
    "      \"audience\":\"phase5-alpha\"},"
    "     {\"id\":\"vault-write\",\"idp\":\"alpha\","
    "      \"audience\":\"phase5-alpha\","
    "      \"require_claim\":["
    "        {\"name\":\"role\",\"equals\":\"admin\"}]},"
    "     {\"id\":\"mtls-echo\",\"idp\":\"beta\","
    "      \"audience\":\"phase5-beta\"}"
    "   ]"
    " },"
    " \"rpc\":{ \"services\": ["
    "   {\"id\":\"phase5.v1.Greeter\",\"auth_policy\":\"greeter-default\"},"
    "   {\"id\":\"phase5.v1.Vault\",  \"auth_policy\":\"vault-read\"},"
    "   {\"id\":\"phase5.v1.MTls\",   \"auth_policy\":\"mtls-echo\"}"
    " ]}"
    "}";

/* ============================================================================
 * Server bring-up.
 * ============================================================================ */

typedef struct {
    n00b_synthetic_idp_t *alpha_idp;
    n00b_synthetic_idp_t *beta_idp;
    n00b_jwt_verifier_t  *alpha_verifier;
    n00b_jwt_verifier_t  *beta_verifier;

    phase5_tenant_table_t tenants;

    n00b_quic_metric_registry_t *metrics;
    n00b_quic_metric_listener_t *metrics_listener;

    char *key_pem_path;

    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;
    n00b_quic_endpoint_t      *ep;
    n00b_h3_server_t          *h3;
    n00b_rpc_server_t         *rpc;
    n00b_quic_manifest_t      *manifest;

    _Atomic uint32_t shutdown;
    n00b_thread_t   *driver;

    uint16_t ephemeral_port;
    uint16_t metrics_port;

    /* Phase 5 § 5.8 — LB-CID encoding (block-cipher mode).  When
     * lb_cid_cfg is non-NULL the server's CID generator emits
     * AES-128-encrypted `<server_id>||<nonce>` so a downstream LB
     * can route follow-up packets to this exact instance.  The
     * shared key + this instance's server_id are loaded at
     * server_setup() time. */
    n00b_quic_lb_cid_config_t *lb_cid_cfg;
    uint64_t                   lb_cid_server_id;
} demo_server_t;

static void *
server_driver_main(void *arg)
{
    demo_server_t *s = arg;
    while (atomic_load(&s->shutdown) == 0) {
        if (s->ep)               n00b_quic_endpoint_run_once(s->ep, 5);
        if (s->h3)               n00b_h3_server_drive(s->h3);
        if (s->metrics_listener) n00b_quic_metrics_listener_run_once(s->metrics_listener);
    }
    return nullptr;
}

static bool
server_setup(demo_server_t *s)
{
    /* 1. Two synthetic IdPs (one per tenant). */
    s->alpha_idp = n00b_synthetic_idp_new("https://idp.alpha.example",
                                          "alpha-key-1");
    s->beta_idp  = n00b_synthetic_idp_new("https://idp.beta.example",
                                          "beta-key-1");
    if (!s->alpha_idp || !s->beta_idp) {
        fprintf(stderr, "server: synthetic IdP construction failed\n");
        return false;
    }

    /* Each tenant has its own audience; two verifiers, one per audience.
     * For the vault-read / vault-write policies (also alpha) we re-use
     * the alpha verifier — Phase 3 audience-pinning happens against
     * the JWT claims at policy_eval time, not at verifier construction. */
    auto vra = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(s->alpha_idp),
                                       "phase5-alpha");
    if (n00b_result_is_err(vra)) return false;
    s->alpha_verifier = n00b_result_get(vra);

    auto vrb = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(s->beta_idp),
                                       "phase5-beta");
    if (n00b_result_is_err(vrb)) return false;
    s->beta_verifier = n00b_result_get(vrb);

    /* 2. Tenant table. */
    s->tenants.n = 2;
    s->tenants.routes[0] = (phase5_tenant_route_t){
        .tenant_id = "alpha",
        .idp_id    = "alpha",
        .verifier  = s->alpha_verifier,
    };
    s->tenants.routes[1] = (phase5_tenant_route_t){
        .tenant_id = "beta",
        .idp_id    = "beta",
        .verifier  = s->beta_verifier,
    };

    /* 3. Metrics registry + audit hook. */
    s->metrics = n00b_quic_metrics_registry_new(nullptr);
    n00b_quic_audit_attach_metrics(s->metrics);

    /* 4. Parse manifest. */
    auto mr = n00b_quic_manifest_load_json(mk_json_buf(PHASE5_MANIFEST_JSON));
    if (n00b_result_is_err(mr)) {
        fprintf(stderr, "server: manifest load failed err=%d\n",
                (int)n00b_result_get_err(mr));
        return false;
    }
    s->manifest = n00b_result_get(mr);

    /* 5. Test PKI key on disk + conduit + endpoint. */
    s->key_pem_path = n00b_quic_test_write_key_pem();
    if (!s->key_pem_path) return false;

    auto cc = n00b_conduit_new();
    if (n00b_result_is_err(cc)) return false;
    s->conduit = n00b_result_get(cc);
    auto ci = n00b_conduit_io_new_default(s->conduit);
    if (n00b_result_is_err(ci)) return false;
    s->io = n00b_result_get(ci);

    n00b_quic_trust_t *trust = build_pinned_trust_for_test_cert();

    /* Phase 5 § 5.8 — LB-CID setup.  Hardcoded fixture key (16 zero
     * bytes) + a server_id derived from POD_INDEX (default 1).
     * Every replica in a multi-replica deployment should share the
     * key but pick a distinct server_id.  Production operators
     * generate the key with `openssl rand 16` and provision it via
     * a shared K8s Secret. */
    s->lb_cid_server_id = 1;
    const char *pod_index = getenv("LB_CID_SERVER_ID");
    if (pod_index) {
        s->lb_cid_server_id = (uint64_t)strtoull(pod_index, NULL, 10);
    }
    static const uint8_t fixture_lb_cid_key[16] = {0};
    auto cfg_r = n00b_quic_lb_cid_config_new(fixture_lb_cid_key,
                                             s->lb_cid_server_id, 1);
    if (n00b_result_is_err(cfg_r)) {
        fprintf(stderr, "server: lb_cid_config_new err=%d\n",
                (int)n00b_result_get_err(cfg_r));
        return false;
    }
    s->lb_cid_cfg = n00b_result_get(cfg_r);

    auto er = n00b_quic_endpoint_new(s->conduit, s->io,
        .listen           = true,
        .bind_host        = "127.0.0.1",
        .bind_port        = 0,
        .alpn             = N00B_H3_ALPN,
        .trust            = trust,
        .cert_der_bytes   = n00b_quic_test_cert_der,
        .cert_der_len     = n00b_quic_test_cert_der_len,
        .key_pem_path     = s->key_pem_path,
        .metrics_registry = s->metrics,
        .lb_cid_config    = s->lb_cid_cfg);
    if (n00b_result_is_err(er)) {
        fprintf(stderr, "server: endpoint_new err=%d\n",
                (int)n00b_result_get_err(er));
        return false;
    }
    s->ep = n00b_result_get(er);
    s->ephemeral_port = n00b_quic_endpoint_local_port(s->ep);

    /* 6. H3 + RPC. */
    auto h3r = n00b_h3_server_new(s->ep, s->conduit, .early_publish = true);
    if (n00b_result_is_err(h3r)) return false;
    s->h3 = n00b_result_get(h3r);

    s->rpc = n00b_rpc_attach_server(s->h3, s->conduit);
    if (!s->rpc) return false;

    auto ar = n00b_rpc_server_attach_auth(s->rpc, s->manifest, false);
    if (n00b_result_is_err(ar)) return false;
    n00b_rpc_server_set_verifier_resolver(s->rpc,
                                          phase5_tenant_resolver,
                                          &s->tenants);
    n00b_rpc_server_attach_metrics(s->rpc, s->metrics);

    n00b_quic_audit_subscribe(audit_stderr, nullptr);

    /* 7. Metrics listener on an ephemeral port. */
    auto lr = n00b_quic_metrics_listener_open(s->metrics, s->conduit, s->io,
        .bind_host = n00b_buffer_from_cstr("127.0.0.1"),
        .bind_port = 0);
    if (n00b_result_is_err(lr)) {
        fprintf(stderr, "server: metrics listener bind failed\n");
        return false;
    }
    s->metrics_listener = n00b_result_get(lr);
    s->metrics_port = n00b_quic_metrics_listener_port(s->metrics_listener);

    /* 8. Driver thread. */
    atomic_store(&s->shutdown, 0);
    auto tr = n00b_thread_spawn(server_driver_main, s);
    if (n00b_result_is_err(tr)) return false;
    s->driver = n00b_result_get(tr);
    return true;
}

static void
server_teardown(demo_server_t *s)
{
    atomic_store(&s->shutdown, 1);
    if (s->driver) n00b_thread_join(s->driver);
    if (s->metrics_listener) {
        n00b_quic_metrics_listener_close(s->metrics_listener);
    }
    if (s->rpc) n00b_rpc_server_close(s->rpc);
    if (s->h3)  n00b_h3_server_close(s->h3);
    if (s->ep)  n00b_quic_endpoint_close(s->ep);
    if (s->lb_cid_cfg) n00b_quic_lb_cid_config_close(s->lb_cid_cfg);
    if (s->io)  n00b_conduit_io_destroy(s->io);
    if (s->conduit) n00b_conduit_destroy(s->conduit);
    if (s->alpha_idp) n00b_synthetic_idp_close(s->alpha_idp);
    if (s->beta_idp)  n00b_synthetic_idp_close(s->beta_idp);
}

/* ============================================================================
 * Client side.
 * ============================================================================ */

typedef struct {
    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;
    n00b_quic_endpoint_t      *ep;
    n00b_quic_conn_t          *conn;
    n00b_h3_client_t          *h3;
    n00b_rpc_channel_t        *chan;
    /* DPoP signer for vault calls. */
    n00b_quic_secret_t        *dpop_signer;
} demo_client_t;

static bool
client_setup(demo_client_t *c, uint16_t server_port)
{
    auto cc = n00b_conduit_new();
    if (n00b_result_is_err(cc)) return false;
    c->conduit = n00b_result_get(cc);
    auto ci = n00b_conduit_io_new_default(c->conduit);
    if (n00b_result_is_err(ci)) return false;
    c->io = n00b_result_get(ci);

    n00b_quic_trust_t *trust = build_pinned_trust_for_test_cert();
    auto er = n00b_quic_endpoint_new(c->conduit, c->io,
        .alpn  = N00B_H3_ALPN,
        .trust = trust);
    if (n00b_result_is_err(er)) return false;
    c->ep = n00b_result_get(er);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(server_port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    auto rr = n00b_quic_connect(c->ep, (const struct sockaddr *)&dst,
                                 n00b_string_from_cstr("test.invalid"));
    if (n00b_result_is_err(rr)) return false;
    c->conn = n00b_result_get(rr);

    auto hcr = n00b_h3_client_new(c->conn);
    if (n00b_result_is_err(hcr)) return false;
    c->h3 = n00b_result_get(hcr);

    /* Pump until handshake completes. */
    int64_t deadline = now_ms() + 2000;
    while (now_ms() < deadline) {
        n00b_quic_endpoint_run_once(c->ep, 10);
        n00b_h3_client_drive(c->h3);
        if (n00b_quic_conn_state(c->conn) == N00B_QUIC_CONN_STATE_CONNECTED) {
            break;
        }
    }
    if (n00b_quic_conn_state(c->conn) != N00B_QUIC_CONN_STATE_CONNECTED) {
        fprintf(stderr, "client: handshake didn't complete\n");
        return false;
    }
    c->chan = n00b_rpc_channel_new(
        (n00b_rpc_channel_spec_t){
            .h3        = c->h3,
            .authority = "127.0.0.1",
        });
    if (!c->chan) return false;

    /* DPoP signer for the vault calls. */
    auto dr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:phase5-dpop"));
    if (n00b_result_is_err(dr)) return false;
    c->dpop_signer = n00b_result_get(dr);
    return true;
}

static void
client_teardown(demo_client_t *c)
{
    if (c->conn) n00b_quic_close(c->conn, 0);
    if (c->ep)   n00b_quic_endpoint_close(c->ep);
    if (c->io)   n00b_conduit_io_destroy(c->io);
    if (c->conduit) n00b_conduit_destroy(c->conduit);
    if (c->dpop_signer) n00b_quic_secret_close(c->dpop_signer);
}

/* ============================================================================
 * RPC drivers — exercise each service.
 * ============================================================================ */

static int
exercise_hello(demo_server_t *s, demo_client_t *c)
{
    char *token = n00b_synthetic_idp_mint(s->alpha_idp, "alice",
                                          "phase5-alpha", 3600,
                                          .scope = "rpc:read");
    n00b_rpc_auth_credentials_t creds = {
        .bearer_token = token,
        .jwt_verifier = s->alpha_verifier,
    };
    n00b_rpc_channel_set_auth(c->chan, &creds, nullptr);
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_new();
    HelloRequest req = { .name = n00b_string_from_cstr("phase5") };
    auto r = n00b_rpc_call_phase5_v1_Greeter__Hello(ctx, c->chan, &req);
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "Hello: ERR %d\n", (int)n00b_result_get_err(r));
        return 1;
    }
    HelloReply *rep = n00b_result_get(r);
    printf("Hello reply: %s\n",
           rep && rep->message ? (const char *)rep->message->data : "?");
    return 0;
}

static int
exercise_vault_read(demo_server_t *s, demo_client_t *c)
{
    char *token = n00b_synthetic_idp_mint(s->alpha_idp, "alice",
                                          "phase5-alpha", 3600,
                                          .scope = "rpc:read");
    auto dpr = n00b_dpop_create(c->dpop_signer, "POST",
                                 "https://127.0.0.1/phase5.v1.Vault/Read");
    char *dpop = n00b_result_is_ok(dpr) ? n00b_result_get(dpr) : nullptr;
    n00b_rpc_auth_credentials_t creds = {
        .bearer_token = token,
        .dpop_proof   = dpop,
        .jwt_verifier = s->alpha_verifier,
    };
    n00b_rpc_channel_set_auth(c->chan, &creds, nullptr);
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_new();
    VaultReadRequest req = { .key = n00b_string_from_cstr("api_key") };
    auto r = n00b_rpc_call_phase5_v1_Vault__Read(ctx, c->chan, &req);
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "Vault.Read: ERR %d\n", (int)n00b_result_get_err(r));
        return 1;
    }
    VaultReadReply *rep = n00b_result_get(r);
    printf("Vault.Read reply: %s\n",
           rep && rep->value ? (const char *)rep->value->data : "?");
    return 0;
}

static int
exercise_vault_write(demo_server_t *s, demo_client_t *c)
{
    char *token = n00b_synthetic_idp_mint(s->alpha_idp, "alice",
                                          "phase5-alpha", 3600,
                                          .scope = "rpc:write",
                                          .role  = "admin");
    auto dpr = n00b_dpop_create(c->dpop_signer, "POST",
                                 "https://127.0.0.1/phase5.v1.Vault/Write");
    char *dpop = n00b_result_is_ok(dpr) ? n00b_result_get(dpr) : nullptr;
    n00b_rpc_auth_credentials_t creds = {
        .bearer_token = token,
        .dpop_proof   = dpop,
        .jwt_verifier = s->alpha_verifier,
    };
    n00b_rpc_channel_set_auth(c->chan, &creds, "vault-write");
    /* Vault/Write needs the override policy because the manifest's
     * service-level pinned policy for `phase5.v1.Vault` is the read
     * variant; write requires the stricter `vault-write` policy. */
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_new();
    VaultWriteRequest req = {
        .key   = n00b_string_from_cstr("api_key"),
        .value = n00b_string_from_cstr("hunter2"),
    };
    auto r = n00b_rpc_call_phase5_v1_Vault__Write(ctx, c->chan, &req);
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "Vault.Write: ERR %d\n", (int)n00b_result_get_err(r));
        return 1;
    }
    VaultWriteReply *rep = n00b_result_get(r);
    printf("Vault.Write reply: bytes=%lld\n",
           rep ? (long long)rep->bytes : 0LL);
    return 0;
}

static int
exercise_mtls_echo(demo_server_t *s, demo_client_t *c)
{
    /* MTls.Echo's policy uses idp=beta + audience=phase5-mtls.  In the
     * loopback (no real client cert), the policy doesn't enforce
     * `require_mtls=true` — the demo just exercises the routing path
     * (X-Tenant=beta resolves to beta_verifier). */
    char *token = n00b_synthetic_idp_mint(s->beta_idp, "alice",
                                          "phase5-beta", 3600,
                                          .scope = "rpc:read");
    n00b_rpc_auth_credentials_t creds = {
        .bearer_token = token,
        .jwt_verifier = s->beta_verifier,
    };
    n00b_rpc_channel_set_auth(c->chan, &creds, nullptr);
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_new();
    EchoRequest req = { .payload = n00b_string_from_cstr("hello-mtls") };
    auto r = n00b_rpc_call_phase5_v1_MTls__Echo(ctx, c->chan, &req);
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "MTls.Echo: ERR %d\n", (int)n00b_result_get_err(r));
        return 1;
    }
    EchoReply *rep = n00b_result_get(r);
    printf("MTls.Echo reply: %s\n",
           rep && rep->payload ? (const char *)rep->payload->data : "?");
    return 0;
}

static int
exercise_stream(demo_server_t *s, demo_client_t *c)
{
    char *token = n00b_synthetic_idp_mint(s->alpha_idp, "alice",
                                          "phase5-alpha", 3600,
                                          .scope = "rpc:read");
    n00b_rpc_auth_credentials_t creds = {
        .bearer_token = token,
        .jwt_verifier = s->alpha_verifier,
    };
    n00b_rpc_channel_set_auth(c->chan, &creds, nullptr);
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_new();
    StreamRequest req = { .count = 3 };
    auto r = n00b_rpc_call_phase5_v1_Greeter__Stream(ctx, c->chan, &req);
    if (n00b_result_is_err(r)) {
        fprintf(stderr, "Stream: ERR %d\n", (int)n00b_result_get_err(r));
        return 1;
    }
    n00b_rpc_stream_t(StreamItem) *typed = n00b_result_get(r);
    n00b_rpc_stream_t(n00b_buffer_t *) *wire =
        (n00b_rpc_stream_t(n00b_buffer_t *) *)typed;
    extern n00b_result_t(StreamItem *)
        typeid("cbor_decode", StreamItem *)(n00b_buffer_t *);
    int n = 0;
    for (;;) {
        auto rr = n00b_rpc_buffer_stream_recv(wire);
        if (n00b_result_is_err(rr)) {
            int err = (int)n00b_result_get_err(rr);
            /* NEED_MORE_DATA means "stream open + empty, poll again"
               per the recv contract — it's not a terminal error.
               The recv internal spin only waits ~50ms; on a loaded
               container that's not always enough for the next frame
               to land.  Bound the outer poll loop generously
               (3 s total) so the demo doesn't hang forever if the
               server actually wedged. */
            if (err == N00B_QUIC_ERR_NEED_MORE_DATA) {
                static int total_polls = 0;
                if (++total_polls > 60) {
                    fprintf(stderr,
                            "Stream recv: timed out after 3s waiting "
                            "for next frame\n");
                    return 1;
                }
                continue;
            }
            fprintf(stderr, "Stream recv ERR %d\n", err);
            return 1;
        }
        n00b_buffer_t *frame = n00b_result_get(rr);
        if (!frame) break;  /* clean EOS */
        auto dr = typeid("cbor_decode", StreamItem *)(frame);
        if (n00b_result_is_err(dr)) {
            fprintf(stderr, "Stream decode ERR\n");
            return 1;
        }
        StreamItem *it = n00b_result_get(dr);
        printf("Stream item: i=%lld text=%s\n",
               (long long)it->i,
               it->text ? (const char *)it->text->data : "?");
        n++;
    }
    if (n != 3) {
        fprintf(stderr, "Stream: expected 3 items, got %d\n", n);
        return 1;
    }
    return 0;
}

/* ============================================================================
 * Metrics scrape.
 * ============================================================================ */

#ifdef _WIN32
typedef SOCKET demo_metrics_socket_t;
#define DEMO_METRICS_BAD_SOCKET INVALID_SOCKET

static ssize_t
demo_metrics_send(demo_metrics_socket_t fd, const void *buf, size_t len)
{
    int n = send(fd, (const char *)buf, (int)len, 0);
    return n == SOCKET_ERROR ? -1 : (ssize_t)n;
}

static ssize_t
demo_metrics_recv(demo_metrics_socket_t fd, void *buf, size_t len)
{
    int n = recv(fd, (char *)buf, (int)len, 0);
    return n == SOCKET_ERROR ? -1 : (ssize_t)n;
}

static void
demo_metrics_close(demo_metrics_socket_t fd)
{
    closesocket(fd);
}
#else
typedef int demo_metrics_socket_t;
#define DEMO_METRICS_BAD_SOCKET (-1)
#define demo_metrics_send(fd, buf, len) write((fd), (buf), (len))
#define demo_metrics_recv(fd, buf, len) read((fd), (buf), (len))
#define demo_metrics_close(fd) close((fd))
#endif

static int
scrape_metrics(uint16_t port, const char **expected, size_t n_expected)
{
    demo_metrics_socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == DEMO_METRICS_BAD_SOCKET) return 1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        demo_metrics_close(fd); return 1;
    }
    static const char req[] = "GET /metrics HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Connection: close\r\n\r\n";
    demo_metrics_send(fd, req, sizeof(req) - 1);

    char body[16384];
    size_t total = 0;
    for (int i = 0; i < 200 && total < sizeof(body) - 1; i++) {
        ssize_t got = demo_metrics_recv(fd, body + total,
                                        sizeof(body) - 1 - total);
        if (got > 0) { total += (size_t)got; body[total] = '\0'; }
        else if (got == 0) break;
        else usleep(10 * 1000);
    }
    demo_metrics_close(fd);
    int missing = 0;
    for (size_t i = 0; i < n_expected; i++) {
        if (!strstr(body, expected[i])) {
            fprintf(stderr, "metrics: missing substring %s\n", expected[i]);
            missing++;
        }
    }
    return missing;
}

/* ============================================================================
 * Loopback driver.
 * ============================================================================ */

static int
run_loopback(void)
{
    demo_server_t s = {0};
    if (!server_setup(&s)) {
        fprintf(stderr, "loopback: server_setup failed\n");
        server_teardown(&s);
        return 1;
    }
    printf("loopback: server up on 127.0.0.1:%u, /metrics on :%u\n",
           s.ephemeral_port, s.metrics_port);

    demo_client_t c = {0};
    if (!client_setup(&c, s.ephemeral_port)) {
        fprintf(stderr, "loopback: client_setup failed\n");
        client_teardown(&c);
        server_teardown(&s);
        return 1;
    }

    int rc = 0;
    rc |= exercise_hello(&s, &c);
    rc |= exercise_stream(&s, &c);
    rc |= exercise_vault_read(&s, &c);
    rc |= exercise_vault_write(&s, &c);
    rc |= exercise_mtls_echo(&s, &c);

    /* Phase 5 § 5.8 — verify the server's wire CID is LB-CID-encoded
     * with this server's server_id.  After the connection is up
     * (handshake complete + first roundtrip done), the client's
     * remote_cid is the server-issued CID.  Decode with the shared
     * key + server_id_len, assert the embedded server_id is what
     * we configured for this replica.  In a multi-replica
     * deployment fronted by an LB-CID-aware load balancer (Envoy
     * contrib QUIC LB filter / HAProxy 3.x QUIC + lb-cid), this
     * encoding is what lets the LB route follow-up packets to the
     * exact replica that owns the connection. */
    static const uint8_t fixture_lb_cid_key[16] = {0};
    auto vcfg_r = n00b_quic_lb_cid_config_new(fixture_lb_cid_key,
                                              s.lb_cid_server_id, 1);
    if (n00b_result_is_ok(vcfg_r)) {
        n00b_quic_lb_cid_config_t *vcfg = n00b_result_get(vcfg_r);
        n00b_quic_cid_t cid;
        if (!n00b_quic_conn_remote_cid(c.conn, &cid)) {
            fprintf(stderr,
                    "loopback: remote CID unavailable (handshake not "
                    "complete?)\n");
            rc |= 1;
        } else if (cid.len != N00B_QUIC_LB_CID_LEN) {
            fprintf(stderr, "loopback: remote CID is %zu bytes, expected %d\n",
                    cid.len, N00B_QUIC_LB_CID_LEN);
            rc |= 1;
        } else {
            uint64_t decoded = 0;
            auto dr = n00b_quic_lb_cid_decode(vcfg, cid.bytes, &decoded);
            if (!n00b_result_is_ok(dr) || decoded != s.lb_cid_server_id) {
                fprintf(stderr,
                        "loopback: LB-CID decode mismatch: got %llu, "
                        "expected %llu\n",
                        (unsigned long long)decoded,
                        (unsigned long long)s.lb_cid_server_id);
                rc |= 1;
            } else {
                printf("loopback: LB-CID OK (server_id=%llu decoded "
                       "from remote CID)\n",
                       (unsigned long long)s.lb_cid_server_id);
            }
        }
        n00b_quic_lb_cid_config_close(vcfg);
    }

    /* Give the server a beat to flush its audit + metrics increments. */
    usleep(100 * 1000);

    const char *expected[] = {
        "n00b_quic_chan_opens_total",
        "n00b_quic_audit_events_total",
        "n00b_quic_rpc_calls_total",
        "n00b_quic_rpc_call_duration_us",
    };
    int missing = scrape_metrics(s.metrics_port, expected,
                                 sizeof(expected) / sizeof(expected[0]));
    if (missing > 0) {
        fprintf(stderr, "loopback: %d expected metrics missing\n", missing);
        rc |= 1;
    } else {
        printf("loopback: metrics surface OK\n");
    }

    client_teardown(&c);
    server_teardown(&s);
    return rc;
}

/* ============================================================================
 * Entry.
 * ============================================================================ */

int
main(int argc, char **argv)
{
    /* Containers don't give us a TTY, so glibc block-buffers stdout
       and any printf() lines emitted just before the process exits
       are lost from `kubectl logs` output.  Force line buffering so
       the demo's "Hello reply: ..." / "metrics surface OK" / etc.
       markers reliably reach the captured pod log.  Cheap; doesn't
       affect the macOS/TTY case. */
#ifdef _WIN32
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
#else
    setvbuf(stdout, nullptr, _IOLBF, 0);
    setvbuf(stderr, nullptr, _IOLBF, 0);
#endif

    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    bool loopback = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--loopback")) loopback = true;
        else {
            fprintf(stderr,
                    "usage: %s --loopback\n", argv[0]);
            return 2;
        }
    }
    if (!loopback) {
        fprintf(stderr, "usage: %s --loopback\n", argv[0]);
        return 2;
    }
    int rc = run_loopback();
    n00b_shutdown();
    return rc;
}

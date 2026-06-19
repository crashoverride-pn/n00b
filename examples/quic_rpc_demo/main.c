/*
 * quic_rpc_demo — End-to-end H3+CBOR+@rpc demo (Phase 4 § 4.12).
 *
 * Modes:
 *   --server [--bind 127.0.0.1:4433]  — stand up the H3+RPC server.
 *   --client [--target 127.0.0.1:4433] — open a channel + call both RPCs.
 *   --loopback                         — run server + client in one
 *                                        process (for the smoke test +
 *                                        a one-command demo run).
 *
 * The two annotated RPCs (`greet.v1.Greeter/Hello` unary,
 * `greet.v1.Greeter/Stream` server-stream) are defined in greet.c and
 * are wired into the global RPC registry by ncc-emitted constructors at
 * process start.
 *
 * Auth: the demo uses the in-process synthetic IdP fixture
 * (`test/fixtures/synthetic_idp.c`) so it boots WITHOUT real OIDC
 * infrastructure.  In production you'd construct a real
 * `n00b_oidc_t` via `n00b_oidc_open(issuer)` and resolve verifiers
 * out of that — see the README for the swap.
 *
 * Trust: a SHA-256-pinned trust store wrapping the static test cert
 * from `test/fixtures/quic_test_pki.h`.  This presents a real cert
 * chain on the wire and verifies it via fingerprint match — no
 * `--insecure` mode.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
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
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"

#include "../../test/fixtures/quic_test_pki.h"
#include "../../test/fixtures/synthetic_idp.h"

#include "greet.h"

/* ============================================================================
 * Time helpers + cert fingerprint pinning.
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

/* ============================================================================
 * Audit pretty-printer — one stderr line per RPC dispatch decision.
 * ============================================================================ */

static void
audit_stderr(const n00b_quic_audit_event_t *evt, void *ctx)
{
    (void)ctx;
    const char *dec = (evt->decision == N00B_QUIC_AUDIT_ALLOW) ? "ALLOW" : "DENY";
    fprintf(stderr,
            "[audit] %s %s policy=%s sub=%s aud=%s\n",
            dec,
            evt->htu ? evt->htu : "?",
            evt->policy_id ? evt->policy_id : "-",
            evt->sub ? evt->sub : "-",
            evt->aud ? evt->aud : "-");
}

/* ============================================================================
 * Parse "host:port" → sockaddr_in.
 * ============================================================================ */

static bool
parse_addr(const char *s, struct sockaddr_in *out)
{
    if (!s) return false;
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", s);
    char *colon = strrchr(buf, ':');
    if (!colon) return false;
    *colon = '\0';
    const char *host = buf;
    int         port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &out->sin_addr) != 1) return false;
    return true;
}

/* ============================================================================
 * Auth scaffolding (synthetic IdP — see README for the real-OIDC swap).
 *
 * The demo defines a single policy ("rpc-default") that requires a JWT
 * with `aud = "n00b-rpc-demo"` and the `scope` claim containing
 * `rpc:write`.  Server side enforces it via manifest-driven auth wiring;
 * client side stamps every call with a freshly minted token.
 * ============================================================================ */

static const char *DEMO_MANIFEST_JSON =
    "{ \"version\": 1, \"service_name\": \"quic_rpc_demo\","
    " \"endpoints\": [{\"id\":\"e\",\"bind_host\":\"127.0.0.1\","
    "  \"bind_port\":0,\"alpn\":[\"h3\"],"
    "  \"cert\":{\"kind\":\"static\","
    "    \"chain_pem_path\":\"/tmp/x\","
    "    \"key_secret_uri\":\"ephemeral:k\"}}],"
    " \"auth\": {"
    "   \"idps\": [{\"id\":\"primary\","
    "                \"issuer\":\"https://idp.example\"}],"
    "   \"policies\": ["
    "     {\"id\":\"rpc-default\",\"idp\":\"primary\","
    "      \"audience\":\"n00b-rpc-demo\","
    "      \"require_claim\":["
    "        {\"name\":\"scope\",\"contains\":\"rpc:write\"}]}"
    "   ]"
    " },"
    " \"rpc\":{ \"services\": ["
    "   {\"id\":\"greet.v1.Greeter\",\"auth_policy\":\"rpc-default\"}"
    " ]}"
    "}";

/* Single-entry table mapping idp-id → verifier; resolver looks up by id. */
typedef struct {
    const char          *idp_id;
    n00b_jwt_verifier_t *verifier;
} idp_binding_t;

static n00b_jwt_verifier_t *
idp_resolver(const char             *idp_id,
             const n00b_h3_header_t *hdrs,
             size_t                  n_hdrs,
             void                   *ctx)
{
    (void)hdrs;
    (void)n_hdrs;
    idp_binding_t *b = ctx;
    if (!idp_id || !b || !b->idp_id) return nullptr;
    if (strcmp(b->idp_id, idp_id) == 0) return b->verifier;
    return nullptr;
}

static n00b_buffer_t *
mk_json_buf(const char *s)
{
    n00b_buffer_t *b = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(b, .raw = (void *)s, .length = (int64_t)strlen(s));
    return b;
}

/* ============================================================================
 * Server-mode plumbing.
 *
 * Builds a listening QUIC endpoint (UDP/127.0.0.1), an H3 server, an RPC
 * dispatcher, and wires the manifest + synthetic IdP for auth.
 * ============================================================================ */

typedef struct {
    /* Inputs. */
    const char           *bind_host;
    uint16_t              bind_port;

    /* Synthetic IdP + manifest (also used by the loopback client side). */
    n00b_synthetic_idp_t *idp;
    n00b_quic_manifest_t *manifest;
    n00b_jwt_verifier_t  *verifier;
    idp_binding_t         binding;

    /* Server resources. */
    char                      *key_pem_path;
    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;
    n00b_quic_endpoint_t      *ep;
    n00b_h3_server_t          *h3;
    n00b_rpc_server_t         *rpc;

    /* Driver. */
    _Atomic uint32_t  shutdown;
    n00b_thread_t    *driver;
    bool              running;

    /* For client-side pinned-trust setup. */
    uint16_t  ephemeral_port;
} demo_server_t;

static void *
server_driver_main(void *arg)
{
    demo_server_t *s = arg;
    while (atomic_load(&s->shutdown) == 0) {
        if (s->ep) n00b_quic_endpoint_run_once(s->ep, 5);
        if (s->h3) n00b_h3_server_drive(s->h3);
    }
    return nullptr;
}

static bool
server_setup(demo_server_t *s)
{
    /* 1. Synthetic IdP + verifier. */
    s->idp = n00b_synthetic_idp_new("https://idp.example", "demo-key");
    if (!s->idp) {
        fprintf(stderr, "server: failed to construct synthetic IdP\n");
        return false;
    }
    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(s->idp),
                                     "n00b-rpc-demo");
    if (n00b_result_is_err(vr)) {
        fprintf(stderr, "server: jwt verifier ctor failed err=%d\n",
                (int)n00b_result_get_err(vr));
        return false;
    }
    s->verifier = n00b_result_get(vr);
    s->binding.idp_id   = "primary";
    s->binding.verifier = s->verifier;

    /* 2. Parse the demo manifest. */
    auto mr = n00b_quic_manifest_load_json(mk_json_buf(DEMO_MANIFEST_JSON));
    if (n00b_result_is_err(mr)) {
        fprintf(stderr, "server: manifest load failed err=%d\n",
                (int)n00b_result_get_err(mr));
        return false;
    }
    s->manifest = n00b_result_get(mr);

    /* 3. Materialize the test PKI on disk (key only — cert rides DER). */
    s->key_pem_path = n00b_quic_test_write_key_pem();
    if (!s->key_pem_path) {
        fprintf(stderr, "server: write key.pem failed\n");
        return false;
    }

    /* 4. Conduit + io backend. */
    auto cc = n00b_conduit_new();
    if (n00b_result_is_err(cc)) return false;
    s->conduit = n00b_result_get(cc);

    auto ci = n00b_conduit_io_new_default(s->conduit);
    if (n00b_result_is_err(ci)) return false;
    s->io = n00b_result_get(ci);

    /* 5. Listening endpoint.  Pin the test cert via SHA-256 fingerprint
     *    (real production would hold a CA-issued chain + system trust). */
    n00b_quic_trust_t *trust = build_pinned_trust_for_test_cert();
    auto er = n00b_quic_endpoint_new(s->conduit, s->io,
        .listen         = true,
        .bind_host      = s->bind_host,
        .bind_port      = s->bind_port,
        .alpn           = N00B_H3_ALPN,
        .trust          = trust,
        .cert_der_bytes = n00b_quic_test_cert_der,
        .cert_der_len   = n00b_quic_test_cert_der_len,
        .key_pem_path   = s->key_pem_path);
    if (n00b_result_is_err(er)) {
        fprintf(stderr, "server: endpoint_new err=%d\n",
                (int)n00b_result_get_err(er));
        return false;
    }
    s->ep = n00b_result_get(er);
    s->ephemeral_port = n00b_quic_endpoint_local_port(s->ep);

    /* 6. H3 server + RPC dispatcher. */
    auto h3r = n00b_h3_server_new(s->ep, s->conduit, .early_publish = true);
    if (n00b_result_is_err(h3r)) {
        fprintf(stderr, "server: h3_server_new err=%d\n",
                (int)n00b_result_get_err(h3r));
        return false;
    }
    s->h3 = n00b_result_get(h3r);

    s->rpc = n00b_rpc_attach_server(s->h3, s->conduit);
    if (!s->rpc) {
        fprintf(stderr, "server: rpc_attach_server failed\n");
        return false;
    }

    /* 7. Auth wiring: bind the manifest + verifier resolver. */
    auto ar = n00b_rpc_server_attach_auth(s->rpc, s->manifest, false);
    if (n00b_result_is_err(ar)) {
        fprintf(stderr, "server: attach_auth err=%d\n",
                (int)n00b_result_get_err(ar));
        return false;
    }
    n00b_rpc_server_set_verifier_resolver(s->rpc, idp_resolver, &s->binding);

    /* 8. Audit subscriber — one stderr line per dispatch. */
    n00b_quic_audit_subscribe(audit_stderr, nullptr);

    /* 9. Spawn the driver thread. */
    atomic_store(&s->shutdown, 0);
    auto tr = n00b_thread_spawn(server_driver_main, s);
    if (n00b_result_is_err(tr)) {
        fprintf(stderr, "server: thread_spawn err=%d\n",
                (int)n00b_result_get_err(tr));
        return false;
    }
    s->driver  = n00b_result_get(tr);
    s->running = true;
    return true;
}

static void
server_teardown(demo_server_t *s)
{
    if (s->running) {
        atomic_store(&s->shutdown, 1);
        n00b_thread_join(s->driver);
        s->running = false;
    }
    if (s->rpc)     n00b_rpc_server_close(s->rpc);
    if (s->h3)      n00b_h3_server_close(s->h3);
    if (s->ep)      n00b_quic_endpoint_close(s->ep);
    if (s->io)      n00b_conduit_io_destroy(s->io);
    if (s->conduit) n00b_conduit_destroy(s->conduit);
    if (s->key_pem_path) {
        unlink(s->key_pem_path);
        free(s->key_pem_path);
    }
    if (s->idp) n00b_synthetic_idp_close(s->idp);
}

/* ============================================================================
 * Client-mode plumbing.
 *
 * For the standalone-client mode (without --loopback) the client mints
 * its own token using a fresh synthetic IdP — but that won't validate
 * against a separately-running --server's verifier.  The demo's
 * standalone client mode is therefore informational; the canonical
 * integration test is `--loopback`, which shares one IdP between the
 * server's verifier and the client's token minter.
 * ============================================================================ */

typedef struct {
    /* Inputs. */
    struct sockaddr_in    target;

    /* Resources. */
    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;
    n00b_quic_endpoint_t      *ep;
    n00b_quic_conn_t          *conn;
    n00b_h3_client_t          *h3;
    n00b_rpc_channel_t        *chan;
} demo_client_t;

static bool
pump_until_connected(demo_client_t *c, int budget_ms)
{
    int64_t start = now_ms();
    while ((now_ms() - start) < budget_ms) {
        n00b_quic_endpoint_run_once(c->ep, 5);
        if (c->h3) n00b_h3_client_drive(c->h3);
        if (n00b_quic_conn_state(c->conn)
            == N00B_QUIC_CONN_STATE_CONNECTED) {
            return true;
        }
    }
    return false;
}

static bool
client_setup(demo_client_t *c, n00b_synthetic_idp_t *idp)
{
    /* Conduit + io. */
    auto cc = n00b_conduit_new();
    if (n00b_result_is_err(cc)) return false;
    c->conduit = n00b_result_get(cc);

    auto ci = n00b_conduit_io_new_default(c->conduit);
    if (n00b_result_is_err(ci)) return false;
    c->io = n00b_result_get(ci);

    /* Pinned trust against the same test cert the server presents. */
    n00b_quic_trust_t *trust = build_pinned_trust_for_test_cert();
    auto er = n00b_quic_endpoint_new(c->conduit, c->io,
        .bind_host = "127.0.0.1",
        .alpn      = N00B_H3_ALPN,
        .trust     = trust);
    if (n00b_result_is_err(er)) {
        fprintf(stderr, "client: endpoint_new err=%d\n",
                (int)n00b_result_get_err(er));
        return false;
    }
    c->ep = n00b_result_get(er);

    /* Connect — the H3 ALPN was set on the endpoint above. */
    auto rr = n00b_quic_connect(c->ep,
                                (const struct sockaddr *)&c->target,
                                n00b_string_from_cstr("quic-test.n00b.local"));
    if (n00b_result_is_err(rr)) {
        fprintf(stderr, "client: connect err=%d\n",
                (int)n00b_result_get_err(rr));
        return false;
    }
    c->conn = n00b_result_get(rr);

    if (!pump_until_connected(c, 5000)) {
        fprintf(stderr, "client: handshake timeout\n");
        return false;
    }

    auto h3r = n00b_h3_client_new(c->conn);
    if (n00b_result_is_err(h3r)) {
        fprintf(stderr, "client: h3_client_new err=%d\n",
                (int)n00b_result_get_err(h3r));
        return false;
    }
    c->h3 = n00b_result_get(h3r);

    /* Settle SETTINGS exchange. */
    int64_t prime = now_ms();
    while ((now_ms() - prime) < 200) {
        n00b_quic_endpoint_run_once(c->ep, 5);
        n00b_h3_client_drive(c->h3);
    }

    c->chan = n00b_rpc_channel_new(
        (n00b_rpc_channel_spec_t){
            .h3        = c->h3,
            .authority = "quic-test.n00b.local",
        });
    if (!c->chan) {
        fprintf(stderr, "client: rpc_channel_new failed\n");
        return false;
    }

    /* Mint a token + stamp the channel.  When the same `idp` is used by
     * the server's verifier (loopback mode), the token validates and
     * the call succeeds. */
    if (idp) {
        char *jwt = n00b_synthetic_idp_mint(idp, "alice", "n00b-rpc-demo",
                                            3600,
                                            .scope = "rpc:read rpc:write");
        n00b_rpc_auth_credentials_t creds = { .bearer_token = jwt };
        n00b_rpc_channel_set_auth(c->chan, &creds, "rpc-default");
    }
    return true;
}

static void
client_teardown(demo_client_t *c)
{
    if (c->h3)      n00b_h3_client_close(c->h3);
    if (c->conn)    n00b_quic_close(c->conn, 0);
    if (c->ep)      n00b_quic_endpoint_close(c->ep);
    if (c->io)      n00b_conduit_io_destroy(c->io);
    if (c->conduit) n00b_conduit_destroy(c->conduit);
}

/* Drive the two RPCs.  Returns 0 on success, non-zero on failure. */
static int
client_run_calls(demo_client_t *c)
{
    /* 1. Hello — unary, with a 5s deadline. */
    int64_t five_s_ns = n00b_ns_timestamp() + 5LL * 1000 * 1000 * 1000;
    n00b_rpc_ctx_t *ctx = n00b_rpc_ctx_with_deadline(nullptr, five_s_ns);

    GreetRequest req = { .name = n00b_string_from_cstr("alice") };
    auto hr = n00b_rpc_call_greet_v1_Greeter__Hello(ctx, c->chan, &req);
    if (n00b_result_is_err(hr)) {
        fprintf(stderr, "client: Hello err=%d\n",
                (int)n00b_result_get_err(hr));
        n00b_rpc_ctx_close(ctx);
        return 1;
    }
    GreetReply *rep = n00b_result_get(hr);
    printf("Hello reply: %.*s\n",
           (int)(rep->message ? rep->message->u8_bytes : 0),
           rep->message ? rep->message->data : "");

    /* 2. Stream(N=5) — server-stream. */
    StreamRequest sreq = { .count = 5 };
    auto sr = n00b_rpc_call_greet_v1_Greeter__Stream(ctx, c->chan, &sreq);
    if (n00b_result_is_err(sr)) {
        fprintf(stderr, "client: Stream err=%d\n",
                (int)n00b_result_get_err(sr));
        n00b_rpc_ctx_close(ctx);
        return 1;
    }
    n00b_rpc_stream_t(StreamItem) *typed = n00b_result_get(sr);

    /* The demo's `rpc_stream_decode` is an alias-cast (see greet.c),
     * so we drain the underlying buffer stream + decode each item by
     * hand.  This keeps the wire path explicit without an extra pump
     * thread. */
    n00b_rpc_stream_t(n00b_buffer_t *) *wire =
        (n00b_rpc_stream_t(n00b_buffer_t *) *)typed;

    int64_t deadline = now_ms() + 5000;
    int     n_got    = 0;
    while (now_ms() < deadline) {
        auto rr = n00b_rpc_buffer_stream_recv(wire);
        if (n00b_result_is_err(rr)) {
            int e = n00b_result_get_err(rr);
            if (e == N00B_QUIC_ERR_NEED_MORE_DATA) {
                struct timespec sl = { 0, 5 * 1000 * 1000 };
                nanosleep(&sl, nullptr);
                continue;
            }
            fprintf(stderr, "client: Stream recv err=%d\n", e);
            n00b_rpc_ctx_close(ctx);
            return 1;
        }
        n00b_buffer_t *b = n00b_result_get(rr);
        if (!b) break;  /* clean EOS */

        extern n00b_result_t(StreamItem *)
            typeid("cbor_decode", StreamItem *)(n00b_buffer_t *);
        auto dr = typeid("cbor_decode", StreamItem *)(b);
        if (n00b_result_is_err(dr)) {
            fprintf(stderr, "client: Stream item decode err=%d\n",
                    (int)n00b_result_get_err(dr));
            n00b_rpc_ctx_close(ctx);
            return 1;
        }
        StreamItem *it = n00b_result_get(dr);
        printf("Stream item %lld: %.*s\n",
               (long long)it->i,
               (int)(it->text ? it->text->u8_bytes : 0),
               it->text ? it->text->data : "");
        n_got++;
    }
    if (n_got != 5) {
        fprintf(stderr, "client: expected 5 stream items, got %d\n", n_got);
        n00b_rpc_ctx_close(ctx);
        return 1;
    }

    /* 3. Upload — client-stream.  Push 4 small chunks, FIN, await one
     *    UploadReply.  Because the typed↔wire mapping is an alias-cast
     *    for ChunkRequest, we push pre-encoded CBOR buffers directly. */
    extern n00b_buffer_t *
        typeid("cbor_encode", ChunkRequest *)(ChunkRequest *);

    n00b_rpc_stream_t(n00b_buffer_t *) *up_wire = n00b_rpc_buffer_stream_new();
    int64_t expected_bytes = 0;
    for (int i = 1; i <= 4; i++) {
        char tmp[32];
        int  n = snprintf(tmp, sizeof(tmp), "log-line-%d", i);
        if (n < 0) n = 0;
        if ((size_t)n >= sizeof(tmp)) n = (int)sizeof(tmp) - 1;
        tmp[n] = '\0';
        ChunkRequest c = { .data = n00b_string_from_cstr(tmp) };
        expected_bytes += (int64_t)c.data->u8_bytes;
        n00b_buffer_t *enc = typeid("cbor_encode", ChunkRequest *)(&c);
        (void)n00b_rpc_buffer_stream_send(up_wire, enc);
    }
    n00b_rpc_buffer_stream_close(up_wire);

    auto ur = n00b_rpc_call_greet_v1_Greeter__Upload(
        ctx, c->chan,
        (n00b_rpc_stream_t(ChunkRequest) *)up_wire);
    if (n00b_result_is_err(ur)) {
        fprintf(stderr, "client: Upload err=%d\n",
                (int)n00b_result_get_err(ur));
        n00b_rpc_ctx_close(ctx);
        return 1;
    }
    UploadReply *up = n00b_result_get(ur);
    printf("Upload: chunks=%lld bytes=%lld\n",
           (long long)(up ? up->chunks : 0),
           (long long)(up ? up->bytes_total : 0));
    if (!up || up->chunks != 4 || up->bytes_total != expected_bytes) {
        fprintf(stderr,
                "client: Upload mismatch (got chunks=%lld bytes=%lld, "
                "want chunks=4 bytes=%lld)\n",
                (long long)(up ? up->chunks : -1),
                (long long)(up ? up->bytes_total : -1),
                (long long)expected_bytes);
        n00b_rpc_ctx_close(ctx);
        return 1;
    }

    /* 4. Chat — bidi.  Push 3 ChatMessages with seq=1..3, close our
     *    outbound side; concurrently drain server replies.  The server
     *    echoes each inbound message with seq+1 and FINs after we FIN. */
    extern n00b_buffer_t *
        typeid("cbor_encode", ChatMessage *)(ChatMessage *);
    extern n00b_result_t(ChatMessage *)
        typeid("cbor_decode", ChatMessage *)(n00b_buffer_t *);

    n00b_rpc_stream_t(n00b_buffer_t *) *chat_in = n00b_rpc_buffer_stream_new();
    for (int64_t i = 1; i <= 3; i++) {
        char tmp[32];
        int  n = snprintf(tmp, sizeof(tmp), "ping-%lld", (long long)i);
        if (n < 0) n = 0;
        if ((size_t)n >= sizeof(tmp)) n = (int)sizeof(tmp) - 1;
        tmp[n] = '\0';
        ChatMessage m = { .text = n00b_string_from_cstr(tmp), .seq = i };
        n00b_buffer_t *enc = typeid("cbor_encode", ChatMessage *)(&m);
        (void)n00b_rpc_buffer_stream_send(chat_in, enc);
    }
    n00b_rpc_buffer_stream_close(chat_in);

    auto cr = n00b_rpc_call_greet_v1_Greeter__Chat(
        ctx, c->chan,
        (n00b_rpc_stream_t(ChatMessage) *)chat_in);
    if (n00b_result_is_err(cr)) {
        fprintf(stderr, "client: Chat err=%d\n",
                (int)n00b_result_get_err(cr));
        n00b_rpc_ctx_close(ctx);
        return 1;
    }
    n00b_rpc_stream_t(ChatMessage) *chat_out = n00b_result_get(cr);
    n00b_rpc_stream_t(n00b_buffer_t *) *chat_wire =
        (n00b_rpc_stream_t(n00b_buffer_t *) *)chat_out;

    int64_t chat_deadline = now_ms() + 5000;
    int     chat_got = 0;
    while (now_ms() < chat_deadline) {
        auto rr = n00b_rpc_buffer_stream_recv(chat_wire);
        if (n00b_result_is_err(rr)) {
            int e = n00b_result_get_err(rr);
            if (e == N00B_QUIC_ERR_NEED_MORE_DATA) {
                struct timespec sl = { 0, 5 * 1000 * 1000 };
                nanosleep(&sl, nullptr);
                continue;
            }
            fprintf(stderr, "client: Chat recv err=%d\n", e);
            n00b_rpc_ctx_close(ctx);
            return 1;
        }
        n00b_buffer_t *b = n00b_result_get(rr);
        if (!b) break;  /* clean EOS */

        auto dr = typeid("cbor_decode", ChatMessage *)(b);
        if (n00b_result_is_err(dr)) {
            fprintf(stderr, "client: Chat decode err=%d\n",
                    (int)n00b_result_get_err(dr));
            n00b_rpc_ctx_close(ctx);
            return 1;
        }
        ChatMessage *m = n00b_result_get(dr);
        printf("Chat reply: %.*s seq=%lld\n",
               (int)(m->text ? m->text->u8_bytes : 0),
               m->text ? m->text->data : "",
               (long long)m->seq);
        chat_got++;
    }
    if (chat_got != 3) {
        fprintf(stderr, "client: expected 3 Chat replies, got %d\n", chat_got);
        n00b_rpc_ctx_close(ctx);
        return 1;
    }

    n00b_rpc_ctx_close(ctx);
    return 0;
}

/* ============================================================================
 * CLI dispatch.
 * ============================================================================ */

static int
usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --server [--bind 127.0.0.1:4433]\n"
            "       %s --client [--target 127.0.0.1:4433]\n"
            "       %s --loopback\n",
            argv0, argv0, argv0);
    return 2;
}

static int
run_server_mode(const char *bind_str)
{
    char        host[64] = "127.0.0.1";
    uint16_t    port     = 4433;
    if (bind_str) {
        struct sockaddr_in tmp;
        if (!parse_addr(bind_str, &tmp)) {
            fprintf(stderr, "invalid --bind: %s\n", bind_str);
            return 2;
        }
        snprintf(host, sizeof(host), "%s", inet_ntoa(tmp.sin_addr));
        port = ntohs(tmp.sin_port);
    }

    demo_server_t s = {0};
    s.bind_host = host;
    s.bind_port = port;
    if (!server_setup(&s)) {
        server_teardown(&s);
        return 1;
    }
    printf("listening on %s:%u (alpn=h3)\n", host, s.ephemeral_port);
    fflush(stdout);

    /* Block until SIGINT (Ctrl-C).  We keep this simple and rely on the
     * driver thread to do all the work. */
    while (atomic_load(&s.shutdown) == 0) {
        struct timespec sl = { 0, 100 * 1000 * 1000 };
        nanosleep(&sl, nullptr);
    }
    server_teardown(&s);
    return 0;
}

static int
run_client_mode(const char *target_str)
{
    struct sockaddr_in target;
    if (!parse_addr(target_str ? target_str : "127.0.0.1:4433", &target)) {
        fprintf(stderr, "invalid --target: %s\n", target_str);
        return 2;
    }

    /* Standalone client mode: we have no shared IdP with whatever's
     * running on the other side, so we stamp no auth headers.  Calls
     * will be denied if the server has auth enabled — see README for
     * the production swap that wires real OIDC. */
    demo_client_t c = {0};
    c.target = target;
    if (!client_setup(&c, nullptr)) {
        client_teardown(&c);
        return 1;
    }
    int rc = client_run_calls(&c);
    client_teardown(&c);
    return rc;
}

static int
run_loopback(void)
{
    /* Single-process server + client.  Shares one synthetic IdP between
     * the server's verifier and the client's token minter, so auth
     * succeeds without any external infrastructure.  This is the smoke
     * mode driven by `test_quic_rpc_demo_smoke.c`. */
    demo_server_t s = {0};
    s.bind_host = "127.0.0.1";
    s.bind_port = 0;  /* ephemeral */
    if (!server_setup(&s)) {
        server_teardown(&s);
        return 1;
    }
    printf("loopback: server up on 127.0.0.1:%u\n", s.ephemeral_port);
    fflush(stdout);

    /* Build the client side. */
    demo_client_t c = {0};
    memset(&c.target, 0, sizeof(c.target));
    c.target.sin_family = AF_INET;
    c.target.sin_port   = htons(s.ephemeral_port);
    inet_pton(AF_INET, "127.0.0.1", &c.target.sin_addr);

    if (!client_setup(&c, s.idp)) {
        client_teardown(&c);
        server_teardown(&s);
        return 1;
    }

    int rc = client_run_calls(&c);

    client_teardown(&c);
    server_teardown(&s);
    return rc;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    bool        is_server   = false;
    bool        is_client   = false;
    bool        is_loopback = false;
    const char *bind_str    = nullptr;
    const char *target_str  = nullptr;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--server"))   is_server   = true;
        else if (!strcmp(a, "--client"))   is_client   = true;
        else if (!strcmp(a, "--loopback")) is_loopback = true;
        else if (!strcmp(a, "--bind") && i + 1 < argc)   bind_str   = argv[++i];
        else if (!strcmp(a, "--target") && i + 1 < argc) target_str = argv[++i];
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            (void)usage(argv[0]); return 0;
        }
        else { fprintf(stderr, "unknown arg: %s\n", a); return usage(argv[0]); }
    }

    int n_modes = (int)is_server + (int)is_client + (int)is_loopback;
    if (n_modes != 1) return usage(argv[0]);

    int rc = 0;
    if      (is_server)   rc = run_server_mode(bind_str);
    else if (is_client)   rc = run_client_mode(target_str);
    else                  rc = run_loopback();

    n00b_shutdown();
    return rc;
}

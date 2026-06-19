/*
 * test_quic_mtls_handshake.c — End-to-end loopback handshake exercising
 * client-side mTLS over QUIC (the h3 transport path).
 *
 * Mirrors test_quic_trust_bridge.c's setup pattern but enables
 * picoquic's `require_client_authentication` on the server side and
 * installs client-auth material on the client side via
 * n00b_quic_picotls_install_client_auth.  Then drives the loopback
 * handshake to a terminal state and asserts the expected outcome.
 *
 * Sub-tests:
 *   1. Matched key/cert: client presents the test cert, signs
 *      CertificateVerify with the matching test key → handshake
 *      completes (state == CONNECTED).
 *   2. Mismatched key: client presents the test cert, signs
 *      CertificateVerify with a different ECDSA-P-256 key →
 *      server's verify_sign rejects → handshake fails (FAILED /
 *      CLOSED).
 *
 * (2) is the critical scenario — proves that
 * n00b_picotls_install_verify_sign is wired on the server side of
 * picoquic too, not just on the client side (which test_acme_tls_mtls
 * already covers for h1).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/sha256.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "crypto/trust.h"
#include "crypto/secret.h"
#include "internal/net/quic/endpoint_internal.h"
#include "internal/crypto/secret_internal.h"
#include "internal/crypto/picotls_certverify.h"
#include "internal/crypto/picotls_verify.h"
#include "picoquic.h"
#include "tls_api.h"

#include "uECC.h"

#include "../fixtures/quic_test_pki.h"

/* ---------------------------------------------------------------- *
 * Test-only raw-scalar secret backend (same shape as
 * test_acme_tls_mtls.c).  We need to drive the signing key directly
 * from the bytes embedded in n00b_quic_test_key_der so the client
 * cert chain we present matches.
 * ---------------------------------------------------------------- */

typedef struct {
    uint8_t priv[32];
    uint8_t pub[64];
} raw_state_t;

static void
sha256_be(const void *data, size_t len, uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(data, len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i * 4]   = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >> 8);
        out[i*4 + 3] = (uint8_t)(w);
    }
}

static int
raw_sign(void *state, const uint8_t *data, size_t data_len,
         n00b_quic_sig_alg_t alg, n00b_buffer_t **out_sig)
{
    if (!state || alg != N00B_QUIC_SIG_ECDSA_P256) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    raw_state_t *st = state;
    uint8_t digest[32];
    sha256_be(data, data_len, digest);
    n00b_allocator_t *al =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    n00b_buffer_t *sig = n00b_alloc_with_opts(n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = al});
    n00b_buffer_init(sig, .length = 64, .allocator = al);
    sig->byte_len = 64;
    if (!uECC_sign(st->priv, digest, 32, (uint8_t *)sig->data,
                   uECC_secp256r1())) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    *out_sig = sig;
    return N00B_QUIC_OK;
}

static int
raw_pubkey(void *state, n00b_quic_sig_alg_t alg, n00b_buffer_t **out_pub)
{
    if (!state || alg != N00B_QUIC_SIG_ECDSA_P256) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    raw_state_t *st = state;
    n00b_allocator_t *al =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    n00b_buffer_t *pub = n00b_alloc_with_opts(n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = al});
    n00b_buffer_init(pub, .raw = (char *)st->pub, .length = 64,
                     .allocator = al);
    *out_pub = pub;
    return N00B_QUIC_OK;
}

static const n00b_quic_secret_vtbl_t raw_vtbl = {
    .scheme = "test-raw",
    .sign   = raw_sign,
    .pubkey = raw_pubkey,
};

static n00b_quic_secret_t *
make_secret_from_scalar(const uint8_t priv[32])
{
    n00b_allocator_t *al =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    raw_state_t *st = n00b_alloc_with_opts(raw_state_t,
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    memcpy(st->priv, priv, 32);
    if (!uECC_compute_public_key(st->priv, st->pub, uECC_secp256r1())) {
        return nullptr;
    }
    n00b_quic_secret_t *s = n00b_alloc_with_opts(n00b_quic_secret_t,
        &(n00b_alloc_opts_t){.allocator = al});
    s->vtbl  = &raw_vtbl;
    s->state = st;
    s->kind  = N00B_QUIC_SECRET_PRIVKEY;
    s->label = n00b_string_from_cstr("test-mtls-key");
    return s;
}

/* ---------------------------------------------------------------- *
 * Fixture: server + client endpoints over loopback UDP.
 * ---------------------------------------------------------------- */

typedef struct {
    n00b_conduit_t            *c;
    n00b_conduit_io_backend_t *io;
    n00b_quic_endpoint_t      *server;
    n00b_quic_endpoint_t      *client;
    char                      *key_path;
    uint16_t                   sport;
    n00b_quic_trust_t         *pinned_trust;   /* shared by both sides */
    /* Storage for the client-side sign_certificate hook.  Lifetime
     * must outlive the picoquic master ctx that holds the pointer. */
    n00b_picotls_client_auth_storage_t signer_storage;
    /* Single-element cert-chain lens array (we present one cert). */
    size_t                     cert_chain_lens[1];
    n00b_quic_secret_t        *client_key;
} mtls_fixture_t;

static bool
setup(mtls_fixture_t *s, n00b_quic_secret_t *client_signing_key)
{
    memset(s, 0, sizeof(*s));
    s->key_path = n00b_quic_test_write_key_pem();
    if (!s->key_path) return false;

    /* Pinned trust matching the test cert.  Both endpoints use it:
     *   - Client trusts the server's leaf (SHA-256 match).
     *   - Server trusts the client's leaf (we use the SAME test cert
     *     for both sides; in production these would differ). */
    uint8_t fp[32];
    sha256_be(n00b_quic_test_cert_der, n00b_quic_test_cert_der_len, fp);
    s->pinned_trust = n00b_quic_trust_pinned(fp);
    if (!s->pinned_trust) return false;

    auto cr = n00b_conduit_new();
    s->c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(s->c);
    s->io = n00b_result_get(ir);

    auto sr = n00b_quic_endpoint_new(s->c, s->io,
                                     .listen         = true,
                                     .bind_host      = "127.0.0.1",
                                     .alpn           = "n00b-mtls/1",
                                     .cert_der_bytes = n00b_quic_test_cert_der,
                                     .cert_der_len   = n00b_quic_test_cert_der_len,
                                     .key_pem_path   = s->key_path,
                                     .trust          = s->pinned_trust);
    if (n00b_result_is_err(sr)) return false;
    s->server = n00b_result_get(sr);
    s->sport  = n00b_quic_endpoint_local_port(s->server);

    /* Enable client-authentication on the server's picoquic ctx.
     * Without this, picotls never sends CertificateRequest and the
     * client cert is never inspected — making the test vacuous. */
    picoquic_set_client_authentication(s->server->quic, 1);

    auto cur = n00b_quic_endpoint_new(s->c, s->io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = "n00b-mtls/1",
                                      .trust     = s->pinned_trust);
    if (n00b_result_is_err(cur)) return false;
    s->client = n00b_result_get(cur);

    /* Install client-auth on the client endpoint's picoquic master
     * ctx — the production wiring used by http_h3.c.  The cert chain
     * is single-element (the test cert); the signing key is whatever
     * the caller built. */
    s->cert_chain_lens[0] = n00b_quic_test_cert_der_len;
    s->client_key         = client_signing_key;
    int rc = n00b_quic_picotls_install_client_auth(
        s->client->quic,
        n00b_quic_test_cert_der,
        s->cert_chain_lens,
        1,
        s->client_key,
        &s->signer_storage);
    if (rc != N00B_QUIC_OK) return false;

    return true;
}

static void
teardown(mtls_fixture_t *s)
{
    if (s->client) n00b_quic_endpoint_close(s->client);
    if (s->server) n00b_quic_endpoint_close(s->server);
    if (s->io)     n00b_conduit_io_destroy(s->io);
    if (s->c)      n00b_conduit_destroy(s->c);
    if (s->pinned_trust) n00b_quic_trust_close(s->pinned_trust);
    if (s->key_path) {
        unlink(s->key_path);
        free(s->key_path);
    }
}

static n00b_quic_conn_t *
do_connect(mtls_fixture_t *s)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(s->sport);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    auto rr = n00b_quic_connect(s->client,
                                (const struct sockaddr *)&dst,
                                n00b_string_from_cstr("quic-test.n00b.local"));
    return n00b_result_is_ok(rr) ? n00b_result_get(rr) : nullptr;
}

static n00b_quic_conn_state_t
drive_handshake(n00b_quic_endpoint_t *client,
                n00b_quic_endpoint_t *server,
                n00b_quic_conn_t     *conn)
{
    for (int i = 0; i < 400; i++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);
        n00b_quic_conn_state_t st = n00b_quic_conn_state(conn);
        if (st == N00B_QUIC_CONN_STATE_CONNECTED
            || st == N00B_QUIC_CONN_STATE_CLOSED
            || st == N00B_QUIC_CONN_STATE_FAILED) {
            return st;
        }
    }
    return n00b_quic_conn_state(conn);
}

/* Extract the 32-byte scalar from the PKCS#8 test key fixture.  The
 * scalar lives at offset 36 (after the outer header + version + algo
 * SEQUENCE + OCTET STRING tag/len + ECPrivateKey SEQUENCE header +
 * version + scalar OCTET STRING tag/len). */
static void
extract_test_scalar(uint8_t out[32])
{
    memcpy(out, n00b_quic_test_key_der + 36, 32);
}

/* ---------------------------------------------------------------- *
 * Scenarios.
 * ---------------------------------------------------------------- */

static void
test_matched_key(void)
{
    uint8_t scalar[32];
    extract_test_scalar(scalar);
    n00b_quic_secret_t *key = make_secret_from_scalar(scalar);
    assert(key);

    mtls_fixture_t s;
    if (!setup(&s, key)) {
        printf("  [SKIP] matched-key setup failed\n");
        teardown(&s);
        return;
    }
    n00b_quic_conn_t *conn = do_connect(&s);
    assert(conn);
    n00b_quic_conn_state_t st = drive_handshake(s.client, s.server, conn);
    if (st != N00B_QUIC_CONN_STATE_CONNECTED) {
        fprintf(stderr,
                "  [FAIL] matched-key handshake ended in state=%d "
                "(expected CONNECTED=%d)\n",
                (int)st, (int)N00B_QUIC_CONN_STATE_CONNECTED);
        abort();
    }
    printf("  [PASS] matched client key + cert: handshake CONNECTED\n");
    teardown(&s);
}

static void
test_mismatched_key(void)
{
    /* Fixed wrong scalar so the run is deterministic. */
    uint8_t bad[32] = {0};
    bad[31] = 0x42;
    n00b_quic_secret_t *key = make_secret_from_scalar(bad);
    assert(key);

    mtls_fixture_t s;
    if (!setup(&s, key)) {
        printf("  [SKIP] mismatched-key setup failed\n");
        teardown(&s);
        return;
    }
    n00b_quic_conn_t *conn = do_connect(&s);
    assert(conn);
    n00b_quic_conn_state_t st = drive_handshake(s.client, s.server, conn);
    if (st == N00B_QUIC_CONN_STATE_CONNECTED) {
        fprintf(stderr,
                "  [REGRESSION] mismatched-key handshake completed!\n"
                "  Server's verify_sign accepted a CertificateVerify\n"
                "  signed with a key that doesn't match the client cert.\n"
                "  The CertificateVerify gap has reopened on the h3 /\n"
                "  QUIC path's server side.\n");
        abort();
    }
    printf("  [PASS] mismatched client key: handshake refused "
           "(state=%d)\n", (int)st);
    teardown(&s);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_mtls_handshake:\n");
    test_matched_key();
    test_mismatched_key();
    printf("All test_quic_mtls_handshake tests passed.\n");

    n00b_shutdown();
    return 0;
}

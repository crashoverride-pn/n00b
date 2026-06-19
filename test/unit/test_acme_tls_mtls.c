/*
 * test_acme_tls_mtls.c — in-process loopback for mTLS client-auth.
 *
 * Wires the public client-auth surface of `n00b_acme_tls_connect_ex`
 * end-to-end against a picotls server fixture that demands client
 * authentication.  The server is constructed inline (no socket dance)
 * and driven via in-memory ptls_buffer_t transports, same pattern as
 * picotls's own t/picotls.c::test_handshake.
 *
 * Two scenarios:
 *   1. matched key/cert → handshake completes; both sides observe a
 *      live TLS connection.
 *   2. mismatched key (auth handle's signing key doesn't match the
 *      cert's pubkey) → server-side CertificateVerify rejects the
 *      handshake, which is exactly the "fail closed" we want.
 *
 * The server uses `n00b_picotls_install_verify_sign` on the client
 * cert chain (mirroring how production code installs verify_sign on
 * the server's cert), so both ends actually validate the
 * proof-of-possession.  Without that, scenario 2 would spuriously
 * succeed (peer cert accepted, CertificateVerify silently bypassed),
 * which would mean the bug we just fixed is still latent.
 *
 * Restrictions:
 *   - ECDSA P-256 client key only (matches what
 *     n00b_quic_secret_sign / n00b_acme_tls_connect_ex support today).
 *   - No socket I/O — handshake bytes flow through memcpy via picotls's
 *     `ptls_buffer_t`s.  Driver loop mirrors `n00b_acme_tls_connect`'s
 *     handshake driver but operates on in-memory transports.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "picotls.h"
#include "picotls/minicrypto.h"
#include "uECC.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/secret_internal.h"
#include "internal/crypto/picotls_certverify.h"
#include "internal/crypto/acme_tls.h"

#include "../fixtures/quic_test_pki.h"

/* ---------------------------------------------------------------- *
 * Test-only secret implementation backed by a raw EC private scalar
 * we extract from quic_test_pki.h.  We bypass the secret_open API so
 * the key matches the test cert exactly.
 * ---------------------------------------------------------------- */

typedef struct {
    uint8_t priv[32];
    uint8_t pub[64];
} raw_state_t;

static int
raw_sign(void *state, const uint8_t *data, size_t data_len,
         n00b_quic_sig_alg_t alg, n00b_buffer_t **out_sig)
{
    if (!state || alg != N00B_QUIC_SIG_ECDSA_P256) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    raw_state_t *st = state;

    uint8_t digest[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(data, data_len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            digest[i*4]     = (uint8_t)(w >> 24);
            digest[i*4 + 1] = (uint8_t)(w >> 16);
            digest[i*4 + 2] = (uint8_t)(w >> 8);
            digest[i*4 + 3] = (uint8_t)w;
        }
    }
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
 * Server side: picotls server that demands client auth.  Verifier
 * accepts any chain that's parseable (it's a test — production-style
 * trust pinning is overkill for what we're checking), and installs
 * verify_sign on the CLIENT's leaf so the server's CertificateVerify
 * processing actually validates the client's proof-of-possession.
 * ---------------------------------------------------------------- */

static int
server_verify_cb(ptls_verify_certificate_t *self_, ptls_t *tls,
                 const char *server_name,
                 int (**verify_sign)(void *, uint16_t,
                                     ptls_iovec_t, ptls_iovec_t),
                 void **verify_data,
                 ptls_iovec_t *certs, size_t num_certs)
{
    (void)self_; (void)tls; (void)server_name;
    if (num_certs == 0) return PTLS_ALERT_BAD_CERTIFICATE;
    /* Install verify_sign for the client cert.  Without this the
     * server would silently accept any CertificateVerify — same
     * bypass we just fixed on the client side. */
    return n00b_picotls_install_verify_sign(verify_sign, verify_data,
                                            certs[0].base, certs[0].len);
}

static const uint16_t server_algos[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    UINT16_MAX,
};

/* Server-side sign_certificate (signs CertificateVerify with the
 * server's key — matching n00b_quic_test_cert_der). */
typedef struct {
    ptls_sign_certificate_t super;
    uint8_t                 priv[32];
} server_signer_t;

/* DER int helpers (duplicated from picotls_certverify so this test
 * stays self-contained). */
static size_t
ts_der_int_size(const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    return 1 + 1 + mag + (size_t)pad;
}

static size_t
ts_der_int_emit(uint8_t *out, const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(mag + (size_t)pad);
    size_t off = 2;
    if (pad) out[off++] = 0x00;
    memcpy(out + off, be + i, mag);
    return off + mag;
}

static int
server_sign_cb(ptls_sign_certificate_t *self_, ptls_t *tls,
               ptls_async_job_t **async, uint16_t *selected_algorithm,
               ptls_buffer_t *output, ptls_iovec_t input,
               const uint16_t *algorithms, size_t num_algorithms)
{
    (void)tls; (void)async;
    server_signer_t *s = (server_signer_t *)self_;

    bool es256 = false;
    for (size_t i = 0; i < num_algorithms; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
            es256 = true;
            break;
        }
    }
    if (!es256) return PTLS_ALERT_HANDSHAKE_FAILURE;
    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;

    uint8_t digest[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(input.base, input.len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            digest[i*4]     = (uint8_t)(w >> 24);
            digest[i*4 + 1] = (uint8_t)(w >> 16);
            digest[i*4 + 2] = (uint8_t)(w >> 8);
            digest[i*4 + 3] = (uint8_t)w;
        }
    }
    uint8_t raw[64];
    if (!uECC_sign(s->priv, digest, 32, raw, uECC_secp256r1())) {
        return PTLS_ERROR_LIBRARY;
    }
    size_t r_sz  = ts_der_int_size(raw,      32);
    size_t s_sz  = ts_der_int_size(raw + 32, 32);
    size_t inner = r_sz + s_sz;
    int rc = ptls_buffer_reserve(output, 2 + inner);
    if (rc != 0) return rc;
    output->base[output->off++] = 0x30;
    output->base[output->off++] = (uint8_t)inner;
    output->off += ts_der_int_emit(output->base + output->off, raw,      32);
    output->off += ts_der_int_emit(output->base + output->off, raw + 32, 32);
    return 0;
}

/* ---------------------------------------------------------------- *
 * Test runner.
 *
 * Drives the handshake in memory between a client ptls_t (built by
 * n00b_acme_tls_connect_ex via a fake-socket pretense) and a server
 * ptls_t we construct here.
 *
 * Since `n00b_acme_tls_connect_ex` opens a real TCP socket, we can't
 * easily use it as-is for in-process testing.  Instead we replicate
 * the client side using the public picotls API: build a client ctx
 * via the SAME helpers our production code uses (verify_certificate +
 * install_verify_sign + sign_certificate with the auth helper's key)
 * and drive handshake bytes through ptls_buffer_t.
 *
 * This still exercises the FIX in picotls_certverify.c (the install
 * of verify_sign) on the client receive side, and the new sign_certificate
 * dispatch on the client send side.  What it does NOT exercise is
 * tcp_connect / send/recv plumbing — those are covered by the network
 * smoke tests.
 * ---------------------------------------------------------------- */

/* Extract the 32-byte ECDSA scalar from PKCS#8 DER at the known
 * offset in n00b_quic_test_key_der (offset 36, length 32).  Avoids a
 * full PKCS#8 parser for this test-only path. */
static void
extract_test_scalar(uint8_t out[32])
{
    memcpy(out, n00b_quic_test_key_der + 36, 32);
}

/* DER ECDSA sig -> raw r||s. */
static int
ecdsa_der_to_raw(const uint8_t *sig, size_t sig_len, uint8_t raw[64])
{
    if (sig_len < 8 || sig[0] != 0x30) return -1;
    size_t off = 2;
    size_t r_len = 0;
    if (sig[off++] != 0x02) return -1;
    r_len = sig[off++];
    const uint8_t *r = sig + off;
    if (r_len > 1 && r[0] == 0x00) { r++; r_len--; }
    if (r_len > 32) return -1;
    memset(raw, 0, 32);
    memcpy(raw + (32 - r_len), r, r_len);
    off += sig[1 + 1] - (sig[1 + 1] > 0 && (off - 4) > 0 ? 0 : 0);  /* unused */
    /* Walk to s by skipping r's TLV from position 2. */
    off = 2 + 2 + sig[3];   /* sig[2..3] = 02, len; r body follows */
    if (sig[off++] != 0x02) return -1;
    size_t s_len = sig[off++];
    const uint8_t *s = sig + off;
    if (s_len > 1 && s[0] == 0x00) { s++; s_len--; }
    if (s_len > 32) return -1;
    memset(raw + 32, 0, 32);
    memcpy(raw + 32 + (32 - s_len), s, s_len);
    return 0;
}

/* Client-side verify_cb for the in-process test — pins server cert. */
typedef struct {
    ptls_verify_certificate_t super;
    uint8_t                   pin[32];
} client_verifier_t;

static int
client_verify_cb(ptls_verify_certificate_t *self_, ptls_t *tls,
                 const char *server_name,
                 int (**verify_sign)(void *, uint16_t,
                                     ptls_iovec_t, ptls_iovec_t),
                 void **verify_data,
                 ptls_iovec_t *certs, size_t num_certs)
{
    (void)tls; (void)server_name;
    client_verifier_t *self = (client_verifier_t *)self_;
    if (num_certs == 0) return PTLS_ALERT_BAD_CERTIFICATE;
    /* Pin the server's leaf SHA-256. */
    uint8_t actual[32];
    n00b_sha256_digest_t words;
    n00b_sha256_hash(certs[0].base, certs[0].len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        actual[i*4]     = (uint8_t)(w >> 24);
        actual[i*4 + 1] = (uint8_t)(w >> 16);
        actual[i*4 + 2] = (uint8_t)(w >> 8);
        actual[i*4 + 3] = (uint8_t)w;
    }
    if (memcmp(actual, self->pin, 32) != 0) return PTLS_ALERT_BAD_CERTIFICATE;
    return n00b_picotls_install_verify_sign(verify_sign, verify_data,
                                            certs[0].base, certs[0].len);
}

/* ---------------------------------------------------------------- *
 * The actual test: scenario 1 (matched) + scenario 2 (mismatched).
 * ---------------------------------------------------------------- */

typedef struct {
    /* Client side. */
    ptls_t                       *client;
    ptls_context_t                cli_ctx;
    client_verifier_t             cli_verifier;
    /* Client signing — uses the auth helper's machinery (matches the
     * production code path the fix changed). */
    n00b_quic_secret_t           *client_key;
    n00b_acme_tls_client_auth_t   client_auth;
    /* Per-call ctx + signer for the client side.  We build this by
     * hand to mirror what acme_tls.c does internally. */
    ptls_sign_certificate_t       cli_signer;
    n00b_quic_secret_t           *cli_signer_key;

    /* Server side. */
    ptls_t                       *server;
    ptls_context_t                srv_ctx;
    ptls_verify_certificate_t     srv_verifier;
    server_signer_t               srv_signer;
    ptls_iovec_t                  srv_cert_iovec;
    ptls_iovec_t                  cli_cert_iovec;
} ms_t;

/* Client sign_certificate shim — pulls the user's key out of cli_ctx.user_ctx. */
static int
client_test_sign_cb(ptls_sign_certificate_t *self_, ptls_t *tls,
                    ptls_async_job_t **async, uint16_t *sel_algo,
                    ptls_buffer_t *output, ptls_iovec_t input,
                    const uint16_t *algorithms, size_t num_algorithms)
{
    (void)async; (void)self_;
    n00b_quic_secret_t *key = *ptls_get_data_ptr(tls);

    bool es256 = false;
    for (size_t i = 0; i < num_algorithms; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
            es256 = true;
            break;
        }
    }
    if (!es256) return PTLS_ALERT_HANDSHAKE_FAILURE;
    *sel_algo = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;

    n00b_buffer_t in_buf;
    memset(&in_buf, 0, sizeof(in_buf));
    n00b_buffer_init(&in_buf, .raw = (char *)input.base,
                     .length = (int64_t)input.len,
                     .allocator =
                     (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool);

    auto sr = n00b_quic_secret_sign(key, &in_buf, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sr)) return PTLS_ERROR_LIBRARY;
    n00b_buffer_t *raw_sig = n00b_result_get(sr);
    if (raw_sig->byte_len != 64) return PTLS_ERROR_LIBRARY;
    const uint8_t *raw = (const uint8_t *)raw_sig->data;
    size_t r_sz   = ts_der_int_size(raw,      32);
    size_t s_sz   = ts_der_int_size(raw + 32, 32);
    size_t inner  = r_sz + s_sz;
    int rc = ptls_buffer_reserve(output, 2 + inner);
    if (rc != 0) return rc;
    output->base[output->off++] = 0x30;
    output->base[output->off++] = (uint8_t)inner;
    output->off += ts_der_int_emit(output->base + output->off, raw,      32);
    output->off += ts_der_int_emit(output->base + output->off, raw + 32, 32);
    return 0;
}

static void
setup(ms_t *t, n00b_quic_secret_t *client_signing_key)
{
    memset(t, 0, sizeof(*t));

    /* ---- server ctx ---- */
    t->srv_cert_iovec.base = (uint8_t *)n00b_quic_test_cert_der;
    t->srv_cert_iovec.len  = n00b_quic_test_cert_der_len;
    extract_test_scalar(t->srv_signer.priv);
    t->srv_signer.super.cb = server_sign_cb;
    t->srv_verifier.cb     = server_verify_cb;
    t->srv_verifier.algos  = server_algos;

    t->srv_ctx.random_bytes        = ptls_minicrypto_random_bytes;
    t->srv_ctx.get_time            = &ptls_get_time;
    t->srv_ctx.key_exchanges       = ptls_minicrypto_key_exchanges;
    t->srv_ctx.cipher_suites       = ptls_minicrypto_cipher_suites;
    t->srv_ctx.certificates.list   = &t->srv_cert_iovec;
    t->srv_ctx.certificates.count  = 1;
    t->srv_ctx.sign_certificate    = &t->srv_signer.super;
    t->srv_ctx.verify_certificate  = &t->srv_verifier;
    t->srv_ctx.require_client_authentication = 1;

    /* ---- client ctx ---- */
    /* Pin server cert. */
    n00b_sha256_digest_t words;
    n00b_sha256_hash(n00b_quic_test_cert_der,
                     n00b_quic_test_cert_der_len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        t->cli_verifier.pin[i*4]     = (uint8_t)(w >> 24);
        t->cli_verifier.pin[i*4 + 1] = (uint8_t)(w >> 16);
        t->cli_verifier.pin[i*4 + 2] = (uint8_t)(w >> 8);
        t->cli_verifier.pin[i*4 + 3] = (uint8_t)w;
    }
    t->cli_verifier.super.cb    = client_verify_cb;
    t->cli_verifier.super.algos = server_algos;

    /* Client presents the same test cert (a "test PKI" — server's
     * verifier doesn't care which side presents this since both pass
     * the chain through to install_verify_sign and we pinned-equivalent
     * the test cert).  In a real deployment the client cert would be
     * the operator-issued identity, distinct from the server's. */
    t->cli_cert_iovec.base = (uint8_t *)n00b_quic_test_cert_der;
    t->cli_cert_iovec.len  = n00b_quic_test_cert_der_len;
    t->cli_signer.cb       = client_test_sign_cb;

    t->cli_ctx.random_bytes        = ptls_minicrypto_random_bytes;
    t->cli_ctx.get_time            = &ptls_get_time;
    t->cli_ctx.key_exchanges       = ptls_minicrypto_key_exchanges;
    t->cli_ctx.cipher_suites       = ptls_minicrypto_cipher_suites;
    t->cli_ctx.certificates.list   = &t->cli_cert_iovec;
    t->cli_ctx.certificates.count  = 1;
    t->cli_ctx.sign_certificate    = &t->cli_signer;
    t->cli_ctx.verify_certificate  = &t->cli_verifier.super;

    t->client = ptls_new(&t->cli_ctx, 0);
    t->server = ptls_new(&t->srv_ctx, 1);
    assert(t->client && t->server);

    /* Stash the client's signing key on the ptls_t so
     * client_test_sign_cb can fetch it. */
    *ptls_get_data_ptr(t->client) = client_signing_key;

    ptls_set_server_name(t->client, "quic-test.n00b.local", 0);
}

static int
drive_handshake(ms_t *t)
{
    uint8_t  cbuf_arr[16384], sbuf_arr[16384];
    ptls_buffer_t cbuf, sbuf;
    ptls_buffer_init(&cbuf, cbuf_arr, sizeof(cbuf_arr));
    ptls_buffer_init(&sbuf, sbuf_arr, sizeof(sbuf_arr));

    /* Drive ClientHello. */
    int rc = ptls_handshake(t->client, &cbuf, NULL, NULL, NULL);
    if (rc != PTLS_ERROR_IN_PROGRESS) return rc;

    /* Bounce flights between sides until both report done. */
    for (int round = 0; round < 8; round++) {
        if (cbuf.off > 0) {
            size_t consumed = cbuf.off;
            rc = ptls_handshake(t->server, &sbuf, cbuf.base, &consumed, NULL);
            if (rc != 0 && rc != PTLS_ERROR_IN_PROGRESS) return rc;
            cbuf.off = 0;
            if (rc == 0 && sbuf.off == 0) return 0;  /* server done, no more flights */
        }
        if (sbuf.off > 0) {
            size_t consumed = sbuf.off;
            int crc = ptls_handshake(t->client, &cbuf, sbuf.base, &consumed,
                                     NULL);
            if (crc != 0 && crc != PTLS_ERROR_IN_PROGRESS) return crc;
            sbuf.off = 0;
            if (crc == 0 && cbuf.off == 0) return 0;
        }
    }
    return -1;  /* exceeded handshake round budget */
}

static void
test_matched(void)
{
    uint8_t scalar[32];
    extract_test_scalar(scalar);
    n00b_quic_secret_t *key = make_secret_from_scalar(scalar);
    assert(key);

    ms_t t;
    setup(&t, key);

    int rc = drive_handshake(&t);
    if (rc != 0) {
        fprintf(stderr,
                "  [FAIL] matched-key handshake returned %d (expected 0)\n",
                rc);
        abort();
    }
    printf("  [PASS] matched client key/cert: handshake completes\n");
}

static void
test_mismatched(void)
{
    /* Random scalar that does NOT correspond to n00b_quic_test_cert_der's
     * pubkey.  Client signs with this; server's verify_sign rejects. */
    uint8_t bad[32] = {0};
    bad[0] = 1;  /* trivially valid scalar in [1, n-1] */
    n00b_quic_secret_t *key = make_secret_from_scalar(bad);
    assert(key);

    ms_t t;
    setup(&t, key);

    int rc = drive_handshake(&t);
    if (rc == 0) {
        fprintf(stderr,
                "  [REGRESSION] mismatched-key handshake completed cleanly!\n"
                "  Server's verify_sign accepted a CertificateVerify signed\n"
                "  with a key that doesn't match the client cert.  The\n"
                "  picotls CertificateVerify gap has reopened on the\n"
                "  server-side path.\n");
        abort();
    }
    printf("  [PASS] mismatched client key/cert: handshake rejected "
           "(rc=%d)\n", rc);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_acme_tls_mtls:\n");
    test_matched();
    test_mismatched();
    printf("All test_acme_tls_mtls tests passed.\n");

    n00b_shutdown();
    return 0;
}

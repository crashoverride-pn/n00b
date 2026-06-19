/*
 * test_tls_certverify_gap.c — PoC for the CertificateVerify gap in
 * picotls_verify.c / acme_tls.c.
 *
 * Hypothesis: our `verify_cb` adapter does `(void)verify_sign;
 * (void)verify_data;`, so `tls->certificate_verify.cb` stays NULL
 * after we accept the cert chain.  In `handle_certificate_verify`
 * (picotls.c:3453-3458), a NULL cb means picotls returns 0 without
 * checking the peer's CertificateVerify signature.
 *
 * To prove the gap: run an in-memory TLS 1.3 handshake where the
 * server presents a valid cert (pinned by the client) but signs the
 * CertificateVerify message with a DIFFERENT private key.  In a
 * correctly-implemented verifier, the client would reject this
 * handshake (signature can't be verified by the leaf's pubkey).
 * If the handshake completes anyway, the gap is exploitable.
 *
 * This is in-process — no sockets, no DNS, no real server.  Both
 * sides drive ptls_handshake against shared memory buffers, same
 * pattern as picotls's own t/picotls.c::test_handshake.
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
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "crypto/trust.h"
#include "internal/crypto/picotls_certverify.h"

#include "../fixtures/quic_test_pki.h"

/* ---------------------------------------------------------------- */
/* Wrong key (NOT the one matching n00b_quic_test_cert_der).  A    */
/* fixed 32-byte scalar so the test is reproducible.  We sign the  */
/* CertificateVerify with this key, even though the cert claims    */
/* a different pubkey.                                             */
/* ---------------------------------------------------------------- */
static const uint8_t wrong_privkey[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
};

/* ---------------------------------------------------------------- */
/* DER int encoding helpers (copied from picotls_sni.c).           */
/* ---------------------------------------------------------------- */
static size_t
der_int_size(const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    return 1 + 1 + mag + (size_t)pad;
}

static size_t
der_int_emit(uint8_t *out, const uint8_t *be, size_t len)
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

/* ---------------------------------------------------------------- */
/* Bad signer: signs CertificateVerify with wrong_privkey.         */
/* ---------------------------------------------------------------- */
static int
bad_sign_certificate(ptls_sign_certificate_t *self,
                     ptls_t                  *tls,
                     ptls_async_job_t       **async,
                     uint16_t                *selected_algorithm,
                     ptls_buffer_t           *output,
                     ptls_iovec_t             input,
                     const uint16_t          *algorithms,
                     size_t                   num_algorithms)
{
    (void)self;
    (void)tls;
    (void)async;

    bool es256_ok = false;
    for (size_t i = 0; i < num_algorithms; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
            es256_ok = true;
            break;
        }
    }
    if (!es256_ok) return PTLS_ALERT_HANDSHAKE_FAILURE;
    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;

    /* SHA-256 over the handshake-transcript signing input. */
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

    /* Sign with WRONG_PRIVKEY (not the key matching the cert). */
    uint8_t raw_sig[64];
    if (!uECC_sign(wrong_privkey, digest, 32, raw_sig, uECC_secp256r1())) {
        return PTLS_ERROR_LIBRARY;
    }

    /* Emit as DER SEQUENCE(r, s). */
    size_t r_sz  = der_int_size(raw_sig,      32);
    size_t s_sz  = der_int_size(raw_sig + 32, 32);
    size_t inner = r_sz + s_sz;

    int ret = ptls_buffer_reserve(output, 2 + inner);
    if (ret != 0) return ret;
    output->base[output->off++] = 0x30;
    output->base[output->off++] = (uint8_t)inner;
    output->off += der_int_emit(output->base + output->off, raw_sig,      32);
    output->off += der_int_emit(output->base + output->off, raw_sig + 32, 32);
    return 0;
}

/* ---------------------------------------------------------------- */
/* Client-side verify_cb (matches picotls_verify.c shape).         */
/* ---------------------------------------------------------------- */
typedef struct {
    ptls_verify_certificate_t  super;
    n00b_quic_trust_t         *trust;
} verify_ctx_t;

static const uint16_t verify_algos[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    UINT16_MAX,
};

static int
verify_cb(ptls_verify_certificate_t *self_,
          ptls_t                    *tls,
          const char                *server_name,
          int                      (**verify_sign)(void *, uint16_t,
                                                  ptls_iovec_t,
                                                  ptls_iovec_t),
          void                     **verify_data,
          ptls_iovec_t              *certs,
          size_t                     num_certs)
{
    (void)tls;
    (void)server_name;

    verify_ctx_t *self = (verify_ctx_t *)self_;
    if (num_certs == 0) return PTLS_ALERT_BAD_CERTIFICATE;

    const uint8_t *ptrs[8];
    size_t         lens[8];
    if (num_certs > 8) return PTLS_ALERT_INTERNAL_ERROR;
    for (size_t i = 0; i < num_certs; i++) {
        ptrs[i] = certs[i].base;
        lens[i] = certs[i].len;
    }
    auto vr = n00b_quic_trust_verify(self->trust, ptrs, lens, num_certs,
                                     "quic-test.n00b.local");
    if (!n00b_result_is_ok(vr)) return PTLS_ALERT_BAD_CERTIFICATE;

    /* Install the CertificateVerify check using the production
     * installer.  This is the regression-test arm: if a future change
     * regresses the verify_sign wiring, this test starts succeeding
     * the bogus handshake again — which the assertion at the end
     * detects. */
    int rc = n00b_picotls_install_verify_sign(verify_sign, verify_data,
                                              certs[0].base,
                                              certs[0].len);
    return rc;
}

/* ---------------------------------------------------------------- */
/* The PoC.                                                         */
/* ---------------------------------------------------------------- */
static void
run_poc(void)
{
    /* --- Compute SHA-256(cert) so the client can pin it. --- */
    uint8_t cert_fp[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(n00b_quic_test_cert_der,
                         n00b_quic_test_cert_der_len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            cert_fp[i*4]     = (uint8_t)(w >> 24);
            cert_fp[i*4 + 1] = (uint8_t)(w >> 16);
            cert_fp[i*4 + 2] = (uint8_t)(w >> 8);
            cert_fp[i*4 + 3] = (uint8_t)w;
        }
    }
    n00b_quic_trust_t *trust = n00b_quic_trust_pinned(cert_fp);
    assert(trust != nullptr);

    /* --- Build the SERVER context.  It presents the real cert but
     * signs CertificateVerify with WRONG_PRIVKEY. --- */
    ptls_iovec_t cert_iovec = {
        .base = (uint8_t *)n00b_quic_test_cert_der,
        .len  = n00b_quic_test_cert_der_len,
    };
    ptls_sign_certificate_t bad_signer = { .cb = bad_sign_certificate };

    ptls_context_t srv_ctx;
    memset(&srv_ctx, 0, sizeof(srv_ctx));
    srv_ctx.random_bytes              = ptls_minicrypto_random_bytes;
    srv_ctx.get_time                  = &ptls_get_time;
    srv_ctx.key_exchanges             = ptls_minicrypto_key_exchanges;
    srv_ctx.cipher_suites             = ptls_minicrypto_cipher_suites;
    srv_ctx.certificates.list         = &cert_iovec;
    srv_ctx.certificates.count        = 1;
    srv_ctx.sign_certificate          = &bad_signer;

    /* --- Build the CLIENT context.  Mirrors acme_tls.c / picotls_verify.c.
     * --- */
    verify_ctx_t verifier;
    memset(&verifier, 0, sizeof(verifier));
    verifier.super.cb    = verify_cb;
    verifier.super.algos = verify_algos;
    verifier.trust       = trust;

    ptls_context_t cli_ctx;
    memset(&cli_ctx, 0, sizeof(cli_ctx));
    cli_ctx.random_bytes       = ptls_minicrypto_random_bytes;
    cli_ctx.get_time           = &ptls_get_time;
    cli_ctx.key_exchanges      = ptls_minicrypto_key_exchanges;
    cli_ctx.cipher_suites      = ptls_minicrypto_cipher_suites;
    cli_ctx.verify_certificate = &verifier.super;

    /* --- Drive the handshake via in-memory buffers. --- */
    ptls_t *client = ptls_new(&cli_ctx, 0);
    ptls_t *server = ptls_new(&srv_ctx, 1);
    assert(client && server);

    ptls_set_server_name(client, "quic-test.n00b.local", 0);

    uint8_t cbuf_arr[16384], sbuf_arr[16384];
    ptls_buffer_t cbuf, sbuf;
    ptls_buffer_init(&cbuf, cbuf_arr, sizeof(cbuf_arr));
    ptls_buffer_init(&sbuf, sbuf_arr, sizeof(sbuf_arr));

    /* Client → ClientHello */
    int ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    assert(ret == PTLS_ERROR_IN_PROGRESS);
    assert(cbuf.off > 0);

    /* Server consumes ClientHello, emits ServerHello + Cert +
     * CertVerify(BAD) + Finished. */
    size_t consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    /* TLS 1.3 1-RTT server side finishes here (modulo client finished). */
    assert(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);
    assert(consumed == cbuf.off);
    assert(sbuf.off > 0);
    cbuf.off = 0;

    /* Client consumes the server's flight.  THIS is where it would
     * reject the bad CertificateVerify if the verifier were correctly
     * installed.  Returns 0 = handshake done = gap exploited. */
    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);

    if (ret == 0) {
        fprintf(stderr,
                "  [REGRESSION] handshake succeeded with a "
                "CertificateVerify signed by the WRONG key.\n");
        fprintf(stderr,
                "  [REGRESSION] this is RFC 8446 § 4.4.3 "
                "(CertificateVerify) being silently bypassed.\n");
        fprintf(stderr,
                "  Either verify_sign was not installed, or it accepted\n"
                "  a signature it should have rejected.\n");
        fprintf(stderr,
                "  Check `n00b_picotls_install_verify_sign` is wired\n"
                "  from every chain verifier (picotls_verify.c,\n"
                "  acme_tls.c) and the algorithm dispatch in\n"
                "  picotls_certverify.c rejects bad signatures.\n");
    } else {
        printf("  [GAP CLOSED] handshake correctly rejected: "
               "ret=%d (%s)\n",
               ret,
               ret == PTLS_ALERT_DECRYPT_ERROR
                   ? "decrypt_error"
                   : ret == PTLS_ALERT_BAD_CERTIFICATE
                       ? "bad_certificate"
                       : "other");
        printf("  CertificateVerify with the wrong key was rejected\n");
        printf("  as expected — verify_sign is correctly installed.\n");
    }

    /* Fix-verification: a forged CertificateVerify MUST be rejected. */
    assert(ret != 0);

    ptls_free(client);
    ptls_free(server);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_tls_certverify_gap (PoC):\n");
    run_poc();

    n00b_shutdown();
    return 0;
}

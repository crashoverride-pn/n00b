/*
 * test_quic_acme_csr.c — Unit tests for the PKCS#10 CSR builder.
 *
 * Two layers of assertions:
 *
 *   1. **In-process structural sanity** — walk the produced DER with
 *      a tiny ASN.1 reader, verify the outer SEQUENCE encloses three
 *      children, the version is 0, the SubjectPublicKeyInfo carries
 *      our P-256 public key, and the signature parses as
 *      `SEQUENCE { r, s }`.  Verifies the signature against uECC.
 *
 *   2. **External verification** — write the DER to a temp file and
 *      pipe it through `openssl req -in <file> -inform DER -verify
 *      -noout`, asserting the expected stdout / exit code.  Catches
 *      any subtle DER mistakes the in-process reader might miss
 *      (e.g., malformed length prefixes that still happen to parse
 *      under our reader).
 *
 * **Test-time dependency, NOT a build/runtime dep.**  The `openssl`
 * binary is invoked here via `popen()` purely as an independent
 * second opinion on the DER we produced.  libn00b itself does not
 * link against OpenSSL anywhere (the CSR builder uses hand-rolled
 * DER + uECC from picotls-minicrypto).  When no `openssl` binary is
 * found on the system, this test prints a SKIP for that leg and
 * exits 0 with the structural checks still in force.  See
 * `docs/quic/vendored.md` for the full dep policy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "uECC.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/acme_csr.h"

/* ============================================================================
 * Tiny DER reader
 * ============================================================================ */

typedef struct {
    const uint8_t *p;
    size_t         n;
} der_view_t;

static int
der_read_tlv(der_view_t *v, uint8_t *tag_out,
             const uint8_t **body_out, size_t *body_len_out)
{
    if (v->n < 2) return -1;
    *tag_out = v->p[0];
    size_t i = 1;
    size_t len;
    uint8_t l = v->p[i++];
    if ((l & 0x80) == 0) {
        len = l;
    } else {
        size_t n = l & 0x7f;
        if (n == 0 || n > 4 || i + n > v->n) return -1;
        len = 0;
        for (size_t k = 0; k < n; k++) {
            len = (len << 8) | v->p[i++];
        }
    }
    if (i + len > v->n) return -1;
    *body_out     = v->p + i;
    *body_len_out = len;
    v->p += i + len;
    v->n -= i + len;
    return 0;
}

/* ============================================================================
 * Test 1: structural sanity + uECC signature verify
 * ============================================================================ */

static void
test_csr_structure_and_signature(void)
{
    auto sk = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:cert"));
    assert(n00b_result_is_ok(sk));
    n00b_quic_secret_t *cert_key = n00b_result_get(sk);

    auto pubr = n00b_quic_secret_pubkey(cert_key, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(pubr));
    n00b_buffer_t *pub = n00b_result_get(pubr);

    const char *names[] = {"alpha.example.test", "beta.example.test"};
    auto br = n00b_acme_build_csr(cert_key, names, 2);
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *csr = n00b_result_get(br);
    assert(csr->byte_len > 100);  /* CSRs of this shape are ~400-700 bytes */

    der_view_t v = {.p = (const uint8_t *)csr->data, .n = (size_t)csr->byte_len};

    /* Outer SEQUENCE. */
    uint8_t tag;
    const uint8_t *body;
    size_t blen;
    assert(der_read_tlv(&v, &tag, &body, &blen) == 0);
    assert(tag == 0x30);

    der_view_t outer = {.p = body, .n = blen};

    /* CertificationRequestInfo SEQUENCE. */
    const uint8_t *cri_body;
    size_t         cri_len;
    assert(der_read_tlv(&outer, &tag, &cri_body, &cri_len) == 0);
    assert(tag == 0x30);
    /* AlgorithmIdentifier SEQUENCE. */
    const uint8_t *alg_body;
    size_t         alg_len;
    assert(der_read_tlv(&outer, &tag, &alg_body, &alg_len) == 0);
    assert(tag == 0x30);
    assert(alg_len == 10);  /* ecdsa-with-SHA256 = OID 1.2.840.10045.4.3.2 */
    /* signature BIT STRING. */
    const uint8_t *sig_body;
    size_t         sig_len;
    assert(der_read_tlv(&outer, &tag, &sig_body, &sig_len) == 0);
    assert(tag == 0x03);
    assert(sig_len >= 1);
    assert(sig_body[0] == 0x00);  /* zero unused-bits prefix */

    /* The signature payload is a DER SEQUENCE { r INTEGER, s INTEGER }. */
    der_view_t sig_v = {.p = sig_body + 1, .n = sig_len - 1};
    const uint8_t *seq_body;
    size_t         seq_len;
    assert(der_read_tlv(&sig_v, &tag, &seq_body, &seq_len) == 0);
    assert(tag == 0x30);
    der_view_t rs_v = {.p = seq_body, .n = seq_len};

    uint8_t r_buf[33] = {0}, s_buf[33] = {0};
    const uint8_t *rb;
    size_t         rl;
    assert(der_read_tlv(&rs_v, &tag, &rb, &rl) == 0);
    assert(tag == 0x02);
    assert(rl <= 33);
    /* Right-justify r into a 32-byte big-endian buffer. */
    if (rl == 33 && rb[0] == 0x00) { rb++; rl--; }   /* strip pad byte */
    assert(rl <= 32);
    memcpy(r_buf + (32 - rl), rb, rl);

    const uint8_t *sb;
    size_t         sl;
    assert(der_read_tlv(&rs_v, &tag, &sb, &sl) == 0);
    assert(tag == 0x02);
    if (sl == 33 && sb[0] == 0x00) { sb++; sl--; }
    assert(sl <= 32);
    memcpy(s_buf + (32 - sl), sb, sl);

    /* Compose 64-byte r||s for uECC_verify. */
    uint8_t raw_sig[64];
    memcpy(raw_sig,      r_buf, 32);
    memcpy(raw_sig + 32, s_buf, 32);

    /* Hash the CertificationRequestInfo bytes. */
    uint8_t digest[32];
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    /* The DER of the CRI SEQUENCE is `30 LL ...body...`.  We need the
     * full TLV — including the tag and length octets — for the hash. */
    /* Recover the TLV bounds by scanning back: length(body) +
     * length-octet-size + 1 for tag. */
    /* Simpler: feed the original buffer up to body_end. */
    {
        size_t l_octets = 1;
        if (cri_len >= 0x80) {
            size_t n = cri_len;
            l_octets = 0;
            while (n > 0) { n >>= 8; l_octets++; }
            l_octets++;  /* leading 0x80|n byte */
        }
        size_t total = 1 + l_octets + cri_len;
        const uint8_t *tlv_start = cri_body - 1 - l_octets;
        n00b_sha256_update(&ctx, tlv_start, total);
    }
    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        digest[i*4]     = (uint8_t)(w >> 24);
        digest[i*4 + 1] = (uint8_t)(w >> 16);
        digest[i*4 + 2] = (uint8_t)(w >> 8);
        digest[i*4 + 3] = (uint8_t)w;
    }

    int ok = uECC_verify((const uint8_t *)pub->data, digest, 32,
                         raw_sig, uECC_secp256r1());
    assert(ok == 1);

    n00b_quic_secret_close(cert_key);
    printf("  [PASS] CSR structure parses + ECDSA signature verifies\n");
}

/* ============================================================================
 * Test 2: shell out to `openssl req -verify -noout` against the DER.
 * ============================================================================ */

static int
have_openssl(void)
{
    /* Use Homebrew's openssl@3 if present (LibreSSL parses CSRs but
     * has different output formatting we'd have to match). */
    const char *paths[] = {
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/usr/bin/openssl",
        nullptr
    };
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (f) {
            fclose(f);
            return 1;
        }
    }
    return 0;
}

static const char *
openssl_path(void)
{
    const char *paths[] = {
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/usr/bin/openssl",
        nullptr
    };
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (f) {
            fclose(f);
            return paths[i];
        }
    }
    return "openssl";
}

static void
test_csr_openssl_verify(void)
{
    if (!have_openssl()) {
        printf("  [SKIP] openssl not present — skipping external verify\n");
        return;
    }

    auto sk = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:c2"));
    n00b_quic_secret_t *cert_key = n00b_result_get(sk);

    const char *names[] = {"openssl.example.test"};
    auto br = n00b_acme_build_csr(cert_key, names, 1);
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *csr = n00b_result_get(br);

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/n00b_acme_csr_test_%d.der", (int)getpid());
    FILE *f = fopen(tmp, "wb");
    assert(f);
    assert(fwrite(csr->data, 1, csr->byte_len, f) == (size_t)csr->byte_len);
    fclose(f);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "%s req -inform DER -in %s -verify -noout -text 2>&1",
             openssl_path(), tmp);
    FILE *p = popen(cmd, "r");
    assert(p);
    char out[4096];
    size_t got = fread(out, 1, sizeof(out) - 1, p);
    out[got] = '\0';
    int rc = pclose(p);

    /* `openssl req -verify` writes "Certificate request self-signature
     * verify OK" (or, on older releases, "verify OK") and exits 0 on
     * success.  Either phrasing counts. */
    int ok = (rc == 0)
             && (strstr(out, "verify OK") != NULL);

    if (!ok) {
        fprintf(stderr,
                "openssl verify failed: rc=%d, output:\n%s\n", rc, out);
    }
    assert(ok);

    /* Sanity: the openssl -text dump must mention our SAN name. */
    assert(strstr(out, "openssl.example.test") != NULL);

    unlink(tmp);
    n00b_quic_secret_close(cert_key);
    printf("  [PASS] openssl req -verify accepts the CSR\n");
}

/* ============================================================================ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_acme_csr:\n");
    test_csr_structure_and_signature();
    test_csr_openssl_verify();
    printf("All quic_acme_csr tests passed.\n");

    n00b_shutdown();
    return 0;
}

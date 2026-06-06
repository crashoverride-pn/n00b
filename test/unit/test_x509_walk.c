/** @file test/unit/test_x509_walk.c — X.509 + PKCS#8 walker regression.
 *
 *  WP-005 mid-stream cleanup lift regression test for the read-side
 *  walkers exposed in include/util/x509_walk.h.
 *
 *  Fixtures (committed):
 *    - `test/unit/data/pkcs7_fixture_cert.pem` — X.509 cert
 *      (openssl-generated, CN="n00b-attest test fixture").
 *    - `test/unit/data/pkcs7_fixture_key.pem` — companion PKCS#8
 *      RSA-2048 private key.
 *
 *  Assertions:
 *    [1] `n00b_x509_extract_issuer_serial` on the cert DER yields:
 *        - a non-empty issuer-DN TLV starting with the SEQUENCE
 *          tag (0x30);
 *        - a non-empty serial-number INTEGER content slice.
 *    [2] `n00b_x509_extract_rsa_pkcs8_nd` on the key DER yields:
 *        - a non-empty modulus `n` (RSA-2048 → ~257 bytes incl.
 *          leading sign byte);
 *        - a non-empty private exponent `d` (~256 bytes).
 *
 *  Test-file conventions per D-030 (libc I/O for log output and
 *  `<assert.h>` for fail-fast asserts is intentional).
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include <util/x509_walk.h>

#include "picotls.h"
#include "picotls/pembase64.h"

static const char k_cert_pem_path[] = "test/unit/data/pkcs7_fixture_cert.pem";
static const char k_key_pem_path[]  = "test/unit/data/pkcs7_fixture_key.pem";

/* Load a PEM file into a n00b-owned DER iovec via shimmed picotls. */
static ptls_iovec_t
load_pem(const char *path, const char *label)
{
    ptls_iovec_t vec = {0};
    size_t       n   = 0;
    int rc = ptls_load_pem_objects(path, label, &vec, 1, &n);
    if (rc != 0 || n != 1) {
        fprintf(stderr, "ptls_load_pem_objects(%s, %s) failed: rc=%d n=%zu\n",
                path, label, rc, n);
        fprintf(stderr, "  (the test binary must run from the source-tree "
                        "root so the relative path resolves)\n");
        assert(0);
    }
    return vec;
}

static void
test_extract_issuer_serial(void)
{
    fprintf(stderr, "[x509-walk] extract_issuer_serial: load PEM cert\n");
    ptls_iovec_t cert = load_pem(k_cert_pem_path, "CERTIFICATE");
    assert(cert.base != NULL);
    assert(cert.len > 0);

    const uint8_t *issuer_dn    = NULL;
    size_t         issuer_len   = 0;
    const uint8_t *serial_bytes = NULL;
    size_t         serial_len   = 0;

    bool ok = n00b_x509_extract_issuer_serial(
        cert.base, cert.len,
        &issuer_dn, &issuer_len,
        &serial_bytes, &serial_len);
    assert(ok);

    /* Issuer DN TLV: non-empty, starts with SEQUENCE (0x30). */
    assert(issuer_dn != NULL);
    assert(issuer_len > 0);
    assert(issuer_dn[0] == 0x30);
    fprintf(stderr, "  [PASS] issuer DN: %zu bytes, tag 0x%02x\n",
            issuer_len, (unsigned)issuer_dn[0]);

    /* Serial INTEGER content: non-empty. */
    assert(serial_bytes != NULL);
    assert(serial_len > 0);
    fprintf(stderr, "  [PASS] serial: %zu bytes\n", serial_len);

    n00b_free(cert.base);
}

static void
test_extract_rsa_pkcs8_nd(void)
{
    fprintf(stderr, "[x509-walk] extract_rsa_pkcs8_nd: load PEM key\n");
    ptls_iovec_t key = load_pem(k_key_pem_path, "PRIVATE KEY");
    assert(key.base != NULL);
    assert(key.len > 0);

    const uint8_t *n_bytes = NULL;
    size_t         n_len   = 0;
    const uint8_t *d_bytes = NULL;
    size_t         d_len   = 0;

    bool ok = n00b_x509_extract_rsa_pkcs8_nd(
        key.base, key.len,
        &n_bytes, &n_len,
        &d_bytes, &d_len);
    assert(ok);

    /* RSA-2048: modulus n is 256 magnitude bytes; the INTEGER
     * content includes a leading 0x00 sign byte when the high bit
     * of the magnitude is set (which it is for nearly all RSA-2048
     * moduli). So we expect n ≈ 257 bytes; the private exponent d
     * may or may not carry the sign byte depending on its high bit,
     * so we expect d ∈ [256, 257]. */
    assert(n_bytes != NULL);
    assert(n_len >= 256);
    assert(n_len <= 257);
    fprintf(stderr, "  [PASS] modulus n: %zu bytes\n", n_len);

    assert(d_bytes != NULL);
    assert(d_len >= 255);
    assert(d_len <= 257);
    fprintf(stderr, "  [PASS] private exponent d: %zu bytes\n", d_len);

    n00b_free(key.base);
}

static void
test_malformed_inputs(void)
{
    fprintf(stderr, "[x509-walk] malformed inputs return false\n");
    /* All-zero bytes: not a valid DER SEQUENCE. */
    uint8_t junk[16] = {0};
    const uint8_t *issuer_dn    = NULL;
    size_t         issuer_len   = 0;
    const uint8_t *serial_bytes = NULL;
    size_t         serial_len   = 0;
    bool ok = n00b_x509_extract_issuer_serial(
        junk, sizeof(junk),
        &issuer_dn, &issuer_len,
        &serial_bytes, &serial_len);
    assert(!ok);

    const uint8_t *n_bytes = NULL;
    size_t         n_len   = 0;
    const uint8_t *d_bytes = NULL;
    size_t         d_len   = 0;
    ok = n00b_x509_extract_rsa_pkcs8_nd(
        junk, sizeof(junk),
        &n_bytes, &n_len,
        &d_bytes, &d_len);
    assert(!ok);
    fprintf(stderr, "  [PASS] malformed inputs rejected\n");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    test_extract_issuer_serial();
    test_extract_rsa_pkcs8_nd();
    test_malformed_inputs();

    fprintf(stderr, "All x509_walk regression tests passed.\n");
    return 0;
}

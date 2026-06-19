/*
 * test_x509_parse.c — DER -> typed cert end-to-end (WP-042 Phase 1).
 *
 * Loads the committed PEM fixture cert, parses it through the x509_der grammar,
 * and walks the tree into n00b_x509_cert_t. Asserts the extracted fields against
 * the values openssl reports for this cert (v1; serial AC6D74C811A0F556;
 * self-signed CN=n00b-attest test fixture; RSA-2048; sha256WithRSA;
 * 2026-05-21 -> 2027-05-21).
 *
 * Needs workdir: meson.project_source_root() for the relative PEM + grammar path.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"

#include "picotls.h"
#include "picotls/pembase64.h"
#include "internal/crypto/x509_parse.h"
#include "crypto/x509.h"

static const char k_cert_pem_path[] = "test/unit/data/pkcs7_fixture_cert.pem";

static ptls_iovec_t
load_pem(const char *path, const char *label)
{
    ptls_iovec_t vec = {0};
    size_t       n   = 0;
    int          rc  = ptls_load_pem_objects(path, label, &vec, 1, &n);
    if (rc != 0 || n == 0) {
        fprintf(stderr, "ptls_load_pem_objects(%s,%s) rc=%d n=%zu (run from src root)\n",
                path, label, rc, n);
        assert(0);
    }
    return vec;
}

static bool
slice_eq(n00b_der_slice_t s, const uint8_t *exp, size_t len)
{
    return s.len == len && memcmp(s.p, exp, len) == 0;
}

static bool
slice_eq_str(n00b_der_slice_t s, const char *str)
{
    size_t len = strlen(str);
    return s.len == len && memcmp(s.p, str, len) == 0;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    ptls_iovec_t cert = load_pem(k_cert_pem_path, "CERTIFICATE");
    assert(cert.base != NULL && cert.len > 0);
    fprintf(stderr, "[x509-parse] fixture cert: %zu DER bytes\n", cert.len);

    /* Parse to a tree (must be unambiguous). */
    n00b_x509_parse_t pr = n00b_x509_parse_der(cert.base, cert.len);
    if (!pr.ok) {
        fprintf(stderr, "[x509-parse] PARSE FAILED: %.*s\n",
                (int)(pr.error ? pr.error->u8_bytes : 0),
                pr.error ? (char *)pr.error->data : "");
        assert(0);
    }
    assert(pr.tree != NULL);

    /* Walk to a typed cert. */
    n00b_x509_cert_result_t cr = n00b_x509_cert_from_der(cert.base, cert.len);
    if (!cr.ok) {
        fprintf(stderr, "[x509-parse] WALK FAILED: %.*s\n",
                (int)(cr.error ? cr.error->u8_bytes : 0),
                cr.error ? (char *)cr.error->data : "");
        assert(0);
    }
    n00b_x509_cert_t *c = &cr.cert;

    /* version v1 (DEFAULT, no [0] wrapper) */
    assert(c->version == 0);

    /* serial AC6D74C811A0F556, DER INTEGER with a leading 0x00 (high bit set) */
    static const uint8_t serial[] = {0x00, 0xac, 0x6d, 0x74, 0xc8, 0x11, 0xa0, 0xf5, 0x56};
    assert(slice_eq(c->serial, serial, sizeof(serial)));

    /* sha256WithRSAEncryption OID 1.2.840.113549.1.1.11 */
    static const uint8_t sha256rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
    assert(slice_eq(c->sig_alg_oid, sha256rsa, sizeof(sha256rsa)));
    assert(slice_eq(c->sig_alg_oid_outer, sha256rsa, sizeof(sha256rsa)));

    /* validity (UTCTime) */
    assert(c->not_before_tag == 23);
    assert(slice_eq_str(c->not_before, "260521213049Z"));
    assert(c->not_after_tag == 23);
    assert(slice_eq_str(c->not_after, "270521213049Z"));

    /* self-signed: issuer DN == subject DN (full Name TLV) */
    assert(c->issuer.len > 0 && c->subject.len > 0);
    assert(slice_eq(c->subject, c->issuer.p, c->issuer.len));

    /* rsaEncryption OID 1.2.840.113549.1.1.1; RSA-2048 SPKI BIT STRING */
    static const uint8_t rsaenc[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    assert(slice_eq(c->spki_alg_oid, rsaenc, sizeof(rsaenc)));
    assert(c->spki_key.len == 271 && c->spki_key.p[0] == 0x00);

    /* signatureValue BIT STRING: 2048-bit RSA sig (256B + unused-bits byte) */
    assert(c->signature.len == 257 && c->signature.p[0] == 0x00);

    /* tbs = the signed TBSCertificate TLV (SEQUENCE) */
    assert(c->tbs.len > 0 && c->tbs.p[0] == 0x30);

    printf("[x509-parse] typed cert fields match openssl — OK\n");
    return 0;
}

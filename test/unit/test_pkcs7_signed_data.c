/** @file test/unit/test_pkcs7_signed_data.c — PKCS#7 SignedData builder regression.
 *
 *  WP-005 Phase 3 regression test for the PKCS#7 SignedData builder
 *  (include/util/pkcs7.h, src/util/pkcs7.c).
 *
 *  Fixture path (post WP-005 P3-fixups, sub-deliverable 4):
 *    - `test/unit/data/pkcs7_fixture_cert.pem` — X.509 cert,
 *      openssl-generated once (`openssl req -x509 -newkey rsa:2048
 *      -nodes -days 365 -subj '/CN=n00b-attest test fixture'`).
 *    - `test/unit/data/pkcs7_fixture_key.pem` — companion PKCS#8
 *      private key (RSA-2048, unencrypted; the CN explicitly marks
 *      this as test material).
 *
 *  At runtime the test:
 *    [1] Decodes the PEM cert into DER bytes via picotls's
 *        `ptls_load_pem_objects` (label "CERTIFICATE").
 *    [2] Decodes the PEM key into DER PKCS#8 via
 *        `ptls_load_pem_objects` (label "PRIVATE KEY"), then parses
 *        the PKCS#8 envelope manually using picotls's
 *        `ptls_asn1_get_expected_type_and_length` to reach the
 *        inner RSAPrivateKey OCTET STRING, and extracts the (n, d)
 *        big-endian byte slices.
 *    [3] Constructs an `SpcIndirectDataContent` blob from a canned
 *        32-byte Authenticode hash; verifies it parses cleanly via
 *        picotls's `ptls_asn1_validation` (round-trip validity).
 *    [4] Builds a complete PKCS#7 SignedData blob using the loaded
 *        cert + key:
 *          - n00b_pkcs7_signed_data_add_certificate(cert)
 *          - n00b_pkcs7_signed_data_add_signer(... n, d ...)
 *        Asserts the produced DER parses cleanly via
 *        `ptls_asn1_validation` end-to-end.
 *    [5] Asserts API error paths:
 *          - serialize() before set_content() / add_signer() errors.
 *
 *  D-049: the test is hermetic — both PEM files are committed
 *  fixtures, no runtime openssl invocation.
 *
 *  Test-file conventions per D-030.
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
#include <crypto/der_encode.h>
#include <crypto/pkcs7.h>

#include "picotls.h"
#include "picotls/asn1.h"
#include "picotls/pembase64.h"

/* 32-byte fake Authenticode hash for the test fixture. */
static const uint8_t k_authentihash[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
};

/* --- PEM fixture path resolution ----------------------------------- */
/* The test binary runs out of build_debug/ but the data files live in
 * test/unit/data/ relative to the source tree. Build runs from the
 * source dir, so a relative path resolves correctly. */
static const char k_cert_pem_path[] = "test/unit/data/pkcs7_fixture_cert.pem";
static const char k_key_pem_path[]  = "test/unit/data/pkcs7_fixture_key.pem";

/* Load PEM file, return n00b-owned DER bytes via shimmed picotls. */
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

/* Walk a PKCS#8 PrivateKeyInfo to find the inner RSAPrivateKey, then
 * extract (n, d) as big-endian byte slices. Picotls's read-side
 * ASN.1 primitives (asn1.h) provide the type+length walker; we use
 * it to step the structure:
 *
 *   PKCS#8 PrivateKeyInfo ::= SEQUENCE {
 *       version                   INTEGER (0),
 *       privateKeyAlgorithm       AlgorithmIdentifier,
 *       privateKey                OCTET STRING        -- contains RSAPrivateKey
 *   }
 *
 *   RSAPrivateKey ::= SEQUENCE {
 *       version           INTEGER (0),
 *       modulus           INTEGER,   -- n
 *       publicExponent    INTEGER,   -- e
 *       privateExponent   INTEGER,   -- d
 *       prime1            INTEGER,   -- p
 *       prime2            INTEGER,   -- q
 *       exponent1         INTEGER,   -- dP
 *       exponent2         INTEGER,   -- dQ
 *       coefficient       INTEGER    -- qInv
 *   }
 */
static void
extract_rsa_nd(const uint8_t *der, size_t der_len,
               const uint8_t **out_n, size_t *out_n_len,
               const uint8_t **out_d, size_t *out_d_len)
{
    uint32_t length            = 0;
    int      indefinite_length = 0;
    size_t   last_byte         = 0;
    int      decode_error      = 0;
    size_t   idx;

    /* Outer PKCS#8 SEQUENCE. */
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, 0, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);

    /* version INTEGER 0. */
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);
    idx = last_byte;  /* skip the INTEGER content */

    /* privateKeyAlgorithm SEQUENCE — skip. */
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);
    idx = last_byte;  /* skip the SEQUENCE body */

    /* privateKey OCTET STRING (contains the RSAPrivateKey SEQUENCE). */
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x04,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);

    /* The OCTET STRING's content starts at idx; the RSAPrivateKey
     * SEQUENCE begins at byte idx. */
    size_t inner_off = idx;

    /* RSAPrivateKey SEQUENCE. */
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);

    /* version INTEGER 0. */
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);
    inner_off = last_byte;

    /* modulus n — INTEGER. The integer content begins at inner_off
     * and has length `length`. RFC 8017 RSAPrivateKey integers may
     * carry a leading 0x00 sign byte when the high bit of the
     * magnitude is set; the RSA primitives in n00b_rsa_sign_*
     * tolerate the leading zero (they skip leading-zero pad bytes
     * during bn_from_bytes), so we forward the raw INTEGER content
     * verbatim. */
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);
    *out_n     = der + inner_off;
    *out_n_len = length;
    inner_off  = last_byte;

    /* publicExponent e — INTEGER. Skip. */
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);
    inner_off = last_byte;

    /* privateExponent d — INTEGER. */
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, NULL);
    assert(decode_error == 0);
    *out_d     = der + inner_off;
    *out_d_len = length;
}

static void
test_spc_indirect_data(void)
{
    n00b_buffer_t *hash = n00b_buffer_from_bytes((char *)k_authentihash, 32);
    n00b_buffer_t *spc  = n00b_pkcs7_build_spc_indirect_data(hash);
    assert(spc != NULL);
    assert(spc->byte_len > 0);

    /* The output should begin with a SEQUENCE tag. */
    assert((uint8_t)spc->data[0] == 0x30);

    /* Round-trip parse via picotls ASN.1 validation. */
    int rc = ptls_asn1_validation((const uint8_t *)spc->data,
                                  spc->byte_len, NULL);
    assert(rc == 0);
    fprintf(stderr, "[pkcs7] SpcIndirectDataContent round-trip parse: OK\n");
}

static void
test_signed_data_roundtrip(void)
{
    /* Load committed PEM fixtures. */
    ptls_iovec_t cert_der = load_pem(k_cert_pem_path, "CERTIFICATE");
    ptls_iovec_t key_der  = load_pem(k_key_pem_path,  "PRIVATE KEY");
    fprintf(stderr,
            "[pkcs7] loaded cert (%zu bytes DER) + key (%zu bytes DER) "
            "from committed PEM fixtures\n",
            cert_der.len, key_der.len);

    /* Extract raw (n, d) from the PKCS#8 envelope. */
    const uint8_t *n_bytes = NULL;
    size_t         n_len   = 0;
    const uint8_t *d_bytes = NULL;
    size_t         d_len   = 0;
    extract_rsa_nd(key_der.base, key_der.len,
                   &n_bytes, &n_len, &d_bytes, &d_len);
    assert(n_bytes != NULL);
    assert(d_bytes != NULL);
    /* 2048-bit RSA → 256-byte modulus, possibly with a leading 0x00
     * INTEGER sign byte → 257 bytes of INTEGER content. */
    assert(n_len == 256 || n_len == 257);
    fprintf(stderr,
            "[pkcs7] extracted RSA (n=%zu bytes, d=%zu bytes) "
            "from PKCS#8\n",
            n_len, d_len);

    /* Build the SpcIndirectDataContent over our canned hash. */
    n00b_buffer_t *hash = n00b_buffer_from_bytes((char *)k_authentihash, 32);
    n00b_buffer_t *spc  = n00b_pkcs7_build_spc_indirect_data(hash);
    assert(spc != NULL);

    /* Authenticode content-type OID 1.3.6.1.4.1.311.2.1.4. */
    uint32_t spc_oid_arcs[] = { 1, 3, 6, 1, 4, 1, 311, 2, 1, 4 };
    n00b_buffer_t *content_type_oid = n00b_der_encode_oid(
        spc_oid_arcs,
        sizeof(spc_oid_arcs) / sizeof(uint32_t));

    /* Real X.509 cert from the openssl-generated PEM fixture. */
    n00b_buffer_t *cert = n00b_buffer_from_bytes((char *)cert_der.base,
                                                 (int64_t)cert_der.len);

    /* Issuer DN: minimum is an empty Name (SEQUENCE OF RDN, empty). */
    n00b_buffer_t *issuer_dn = n00b_der_encode_sequence(NULL, 0);

    /* Serial: small positive integer. */
    uint8_t serial_bytes[] = { 0x01 };

    /* Build the SignedData. */
    n00b_pkcs7_signed_data_t *sd = n00b_pkcs7_signed_data_new();
    assert(sd != NULL);

    n00b_pkcs7_signed_data_set_content(sd, content_type_oid, spc);
    n00b_pkcs7_signed_data_add_certificate(sd, cert);

    auto sr = n00b_pkcs7_signed_data_add_signer(
        sd,
        issuer_dn,
        serial_bytes, sizeof(serial_bytes),
        spc,
        n_bytes, n_len,
        d_bytes, d_len);
    if (n00b_result_is_err(sr)) {
        fprintf(stderr, "add_signer failed with err=%d\n",
                n00b_result_get_err(sr));
        assert(0);
    }

    auto rr = n00b_pkcs7_signed_data_serialize(sd);
    if (n00b_result_is_err(rr)) {
        fprintf(stderr, "serialize failed with err=%d\n",
                n00b_result_get_err(rr));
        assert(0);
    }

    n00b_buffer_t *der = n00b_result_get(rr);
    assert(der != NULL);
    assert(der->byte_len > 0);

    /* Outer ContentInfo is a SEQUENCE. */
    assert((uint8_t)der->data[0] == 0x30);

    /* Round-trip parse via picotls ASN.1 validation. */
    int rc = ptls_asn1_validation((const uint8_t *)der->data,
                                  der->byte_len, NULL);
    if (rc != 0) {
        fprintf(stderr, "ptls_asn1_validation returned %d for "
                        "%zu-byte SignedData\n", rc, der->byte_len);
        assert(0);
    }

    fprintf(stderr, "[pkcs7] full SignedData round-trip parse "
                    "(%zu bytes): OK\n", der->byte_len);

    /* Picotls is built with n00b's allocation shim, so the decoded DER
     * buffers are n00b-owned in this build. */
    n00b_free(cert_der.base);
    n00b_free(key_der.base);
}

static void
test_serialize_errors(void)
{
    /* No content + no signer → NO_SIGNER (signer check is first). */
    {
        n00b_pkcs7_signed_data_t *sd = n00b_pkcs7_signed_data_new();
        auto rr = n00b_pkcs7_signed_data_serialize(sd);
        assert(n00b_result_is_err(rr));
        assert(n00b_result_get_err(rr) == N00B_PKCS7_ERR_NO_SIGNER);
    }
    /* nullptr handle → INVALID_HANDLE. */
    {
        auto rr = n00b_pkcs7_signed_data_serialize(NULL);
        assert(n00b_result_is_err(rr));
        assert(n00b_result_get_err(rr) == N00B_PKCS7_ERR_INVALID_HANDLE);
    }
    fprintf(stderr, "[pkcs7] error paths: OK\n");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    test_spc_indirect_data();
    test_signed_data_roundtrip();
    test_serialize_errors();

    fprintf(stderr, "All PKCS#7 SignedData regression tests passed.\n");
    return 0;
}

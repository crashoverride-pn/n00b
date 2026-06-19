/** @file src/util/x509_walk.c — X.509 + PKCS#8 read-side walkers.
 *
 *  Implementation of the public surface declared in
 *  include/util/x509_walk.h. Both walkers wrap picotls's
 *  `ptls_asn1_get_expected_type_and_length` primitive to step the
 *  TLV structure; no allocations are performed and no picotls
 *  types leak through the public surface.
 *
 *  Lifted from src/chalk/resign_identity.c (WP-005 P4) so the
 *  walkers are reusable by P5 (Mach-O re-sign) and any future
 *  SignerInfo verify path. The original P4 logic is preserved
 *  byte-for-byte; only the symbol names changed to match the
 *  libn00b prefix convention (`n00b_x509_*`).
 */

#include "n00b.h"
#include "crypto/x509_walk.h"

#include "picotls.h"
#include "picotls/asn1.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ---------------------------------------------------------------------------
// X.509 cert walker — extracts the tbsCertificate.issuer DER blob
// and the tbsCertificate.serialNumber raw INTEGER content bytes.
//
//   Certificate ::= SEQUENCE {
//       tbsCertificate       SEQUENCE {
//           version          [0] EXPLICIT Version DEFAULT v1,
//           serialNumber     CertificateSerialNumber,  -- INTEGER
//           signature        AlgorithmIdentifier,
//           issuer           Name,
//           validity         Validity,
//           subject          Name,
//           ...
//       },
//       ...
//   }
// ---------------------------------------------------------------------------

bool
n00b_x509_extract_issuer_serial(const uint8_t  *der,
                                size_t          der_len,
                                const uint8_t **issuer_dn_start,
                                size_t         *issuer_dn_total_len,
                                const uint8_t **serial_bytes,
                                size_t         *serial_len)
{
    uint32_t length            = 0;
    int      indefinite_length = 0;
    size_t   last_byte         = 0;
    int      decode_error      = 0;
    size_t   idx;

    // Outer Certificate SEQUENCE.
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, 0, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;

    // tbsCertificate SEQUENCE.
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;

    // Optional version [0] EXPLICIT — tag 0xA0 (context-specific
    // constructed, [0]). If present, skip; if absent, the next
    // tag is the serialNumber INTEGER 0x02.
    if (idx < der_len && der[idx] == 0xA0) {
        size_t version_last = 0;
        idx = ptls_asn1_get_expected_type_and_length(
            der, der_len, idx, 0xA0,
            &length, &indefinite_length, &version_last, &decode_error, nullptr);
        if (decode_error != 0) return false;
        idx = version_last;
    }

    // serialNumber INTEGER.
    size_t serial_content_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    *serial_bytes = der + serial_content_off;
    *serial_len   = (size_t)length;
    idx = last_byte;

    // signature AlgorithmIdentifier SEQUENCE — skip.
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    idx = last_byte;

    // issuer Name SEQUENCE — capture the TLV (tag + length +
    // content) for use as the SignerInfo IssuerAndSerialNumber's
    // issuer field.
    size_t issuer_start = idx;
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    *issuer_dn_start     = der + issuer_start;
    *issuer_dn_total_len = last_byte - issuer_start;

    return true;
}

// ---------------------------------------------------------------------------
// PKCS#8 walker — extracts the inner RSAPrivateKey's (n, d) byte
// slices. Mirrors the extract_rsa_nd helper in
// test/unit/test_pkcs7_signed_data.c.
//
//   PKCS#8 PrivateKeyInfo ::= SEQUENCE {
//       version                   INTEGER (0),
//       privateKeyAlgorithm       AlgorithmIdentifier,
//       privateKey                OCTET STRING   -- contains RSAPrivateKey
//   }
//
//   RSAPrivateKey ::= SEQUENCE {
//       version           INTEGER (0),
//       modulus           INTEGER,   -- n
//       publicExponent    INTEGER,   -- e
//       privateExponent   INTEGER,   -- d
//       prime1            INTEGER,   -- p
//       ...
//   }
// ---------------------------------------------------------------------------

bool
n00b_x509_extract_rsa_pkcs8_nd(const uint8_t  *der,
                               size_t          der_len,
                               const uint8_t **out_n,
                               size_t         *out_n_len,
                               const uint8_t **out_d,
                               size_t         *out_d_len)
{
    uint32_t length            = 0;
    int      indefinite_length = 0;
    size_t   last_byte         = 0;
    int      decode_error      = 0;
    size_t   idx;

    // Outer PKCS#8 SEQUENCE.
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, 0, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;

    // version INTEGER 0.
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    idx = last_byte;

    // privateKeyAlgorithm SEQUENCE — skip.
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    idx = last_byte;

    // privateKey OCTET STRING (contains the RSAPrivateKey SEQUENCE).
    idx = ptls_asn1_get_expected_type_and_length(
        der, der_len, idx, 0x04,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    size_t inner_off = idx;

    // RSAPrivateKey SEQUENCE.
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x30,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;

    // version INTEGER 0.
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    inner_off = last_byte;

    // modulus n INTEGER.
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    *out_n     = der + inner_off;
    *out_n_len = length;
    inner_off  = last_byte;

    // publicExponent e INTEGER — skip.
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    inner_off = last_byte;

    // privateExponent d INTEGER.
    inner_off = ptls_asn1_get_expected_type_and_length(
        der, der_len, inner_off, 0x02,
        &length, &indefinite_length, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) return false;
    *out_d     = der + inner_off;
    *out_d_len = length;

    return true;
}

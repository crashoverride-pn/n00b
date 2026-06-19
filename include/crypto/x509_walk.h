#pragma once

/**
 * @file util/x509_walk.h
 * @brief Read-side ASN.1 walkers for X.509 certificates and PKCS#8
 *        RSA private keys.
 *
 * Pure read-side helpers over picotls-decoded DER bytes. Two walkers
 * are exposed:
 *
 *  - @ref n00b_x509_extract_issuer_serial — walks an X.509 v3
 *    `Certificate.tbsCertificate` to slice out the `issuer` `Name`
 *    DER blob (TLV-included) and the raw `serialNumber` INTEGER
 *    content bytes.
 *  - @ref n00b_x509_extract_rsa_pkcs8_nd — walks a PKCS#8
 *    `PrivateKeyInfo` carrying an `RSAPrivateKey` and slices out the
 *    `(n, d)` big-endian byte ranges suitable for direct consumption
 *    by `n00b_rsa_sign_pkcs1_v15_sha256` (`include/util/rsa_sign.h`).
 *
 * Both helpers are non-allocating — every output points into the
 * caller-supplied DER buffer. Lifetime of the slices is bounded by
 * the lifetime of the underlying DER bytes.
 *
 * # Symbol prefix
 *
 * `n00b_x509_*` (lower-case symbols). Top-level libn00b utility
 * namespace, matching the `n00b_der_encode_*` / `n00b_pkcs7_*`
 * precedent.
 *
 * # Scope (v1)
 *
 * - X.509 v1 and v3 certificates (the optional `[0] EXPLICIT
 *   Version` tag is skipped when present).
 * - RSA PKCS#8 keys only. ECDSA / Ed25519 PKCS#8 walkers are
 *   out of scope; a future ergonomics WP adds curves if needed.
 *
 * # No picotls types in the public surface
 *
 * The helpers internally use picotls's `ptls_asn1_get_expected_type_and_length`
 * walker but the public surface trades only in `const uint8_t *` /
 * `size_t` pairs — picotls types do not appear in this header.
 *
 * # Allocator discipline
 *
 * Both helpers are non-allocating; no `.allocator` kwarg is needed.
 * Callers needing allocator-owned copies of the sliced bytes are
 * expected to materialize them at the call site.
 */

#include <n00b.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Walk an X.509 v1/v3 certificate DER blob; slice out the
 *        issuer `Name` (full TLV) and the `serialNumber` INTEGER
 *        content bytes.
 *
 * @param der                   Pointer to the certificate DER bytes
 *                              (the outermost `Certificate` SEQUENCE).
 * @param der_len               Length of @p der in bytes.
 * @param issuer_dn_start       Out: pointer (into @p der) at the
 *                              start of the issuer `Name` TLV
 *                              (`SEQUENCE` tag). The slice spans
 *                              the full TLV including tag + length
 *                              octets, suitable for embedding
 *                              verbatim in a PKCS#7
 *                              `IssuerAndSerialNumber.issuer` field.
 * @param issuer_dn_total_len   Out: byte length of the TLV at
 *                              @p issuer_dn_start.
 * @param serial_bytes          Out: pointer (into @p der) at the
 *                              first content byte of the
 *                              `serialNumber` INTEGER. If the high
 *                              bit of the magnitude is set the
 *                              encoded value retains the leading
 *                              0x00 sign byte; the slice forwards
 *                              the raw INTEGER content verbatim.
 * @param serial_len            Out: length in bytes of
 *                              @p serial_bytes.
 *
 * @return `true` on a successful walk; `false` if the input is
 *         malformed or the walker steps past the buffer end. On
 *         failure the out-parameters are not written.
 *
 * @pre @p der is non-null and @p der_len > 0.
 * @post Output slices are valid for the lifetime of @p der.
 */
extern bool
n00b_x509_extract_issuer_serial(const uint8_t  *der,
                                size_t          der_len,
                                const uint8_t **issuer_dn_start,
                                size_t         *issuer_dn_total_len,
                                const uint8_t **serial_bytes,
                                size_t         *serial_len);

/**
 * @brief Walk a PKCS#8 `PrivateKeyInfo` DER blob carrying an
 *        `RSAPrivateKey`; slice out the modulus `n` and the
 *        private exponent `d` as raw big-endian byte ranges.
 *
 * @param der        Pointer to the PKCS#8 DER bytes (the outermost
 *                   `PrivateKeyInfo` SEQUENCE).
 * @param der_len    Length of @p der in bytes.
 * @param out_n      Out: pointer (into @p der) at the first content
 *                   byte of the `modulus` INTEGER.
 * @param out_n_len  Out: length in bytes of @p out_n.
 * @param out_d      Out: pointer (into @p der) at the first content
 *                   byte of the `privateExponent` INTEGER.
 * @param out_d_len  Out: length in bytes of @p out_d.
 *
 * @details RFC 8017 `RSAPrivateKey` integers may carry a leading
 * 0x00 sign byte when the high bit of the magnitude is set. The
 * helper forwards the raw INTEGER content verbatim; the
 * `n00b_rsa_sign_*` primitives skip leading-zero pad bytes during
 * `bn_from_bytes`, so the slices may be passed through unchanged.
 *
 * @return `true` on a successful walk; `false` if the input is
 *         malformed or the walker steps past the buffer end. On
 *         failure the out-parameters are not written.
 *
 * @pre @p der is non-null and @p der_len > 0.
 * @post Output slices are valid for the lifetime of @p der.
 */
extern bool
n00b_x509_extract_rsa_pkcs8_nd(const uint8_t  *der,
                               size_t          der_len,
                               const uint8_t **out_n,
                               size_t         *out_n_len,
                               const uint8_t **out_d,
                               size_t         *out_d_len);

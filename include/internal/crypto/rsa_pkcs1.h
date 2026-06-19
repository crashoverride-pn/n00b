/**
 * @file rsa_pkcs1.h
 * @internal
 * @brief Hand-rolled RSA PKCS#1-v1.5 + PSS sign/verify primitives.
 *
 * Phase 3 hand-rolls these because picotls-minicrypto vendors only
 * ECDSA via uECC + symmetric primitives via cifra. No RSA primitives
 * ship with the project by default.
 *
 * # Scope
 *
 *   - RSA-PKCS1-v1.5 **verify** (RS256/RS384/RS512). Used by the
 *     QUIC JWT / OIDC path.
 *   - RSA-PSS **verify** + **sign** (rsa_pss_rsae_sha256). Used by
 *     the TLS 1.3 CertificateVerify path and the
 *     `test_rsa_pss_roundtrip` math regression.
 *   - RSA-PKCS1-v1.5 SHA-256 **sign**. Public-surface declared in
 *     `include/util/rsa_sign.h`; the implementation is colocated in
 *     this file's translation unit because it shares the schoolbook
 *     bignum + Knuth-D modular-reduction machinery and the DI_SHA256
 *     prefix with the verify side.
 *
 * Modulus sizes 1024..4096 bits. Public exponents up to 8 bytes
 * (covers 65537 = 0x010001 + anything else operators might use).
 *
 * The implementation is straightforward schoolbook bignum + Knuth-D
 * modular reduction. Small public exponent → ~17 modexp iterations
 * for the canonical e=65537; speed is not critical.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "crypto/jwt.h"

/**
 * @brief Verify an RSA-PKCS1-v1_5 signature.
 *
 * @param jwk     RSA JWK.  Must have `rsa_n` and `rsa_e` populated.
 * @param alg     "RS256", "RS384", or "RS512".  Selects the hash.
 * @param msg     Signing input bytes (the JWS `header.payload`).
 * @param msg_len Length of @p msg.
 * @param sig     Signature bytes.  Length must equal the modulus
 *                size in bytes (`rsa_n_len`).
 * @param sig_len Length of @p sig.
 *
 * @return @c N00B_QUIC_OK on a valid signature; a negative
 *         @c N00B_QUIC_ERR_AUTH_* code otherwise.
 */
extern int
n00b_rsa_verify_pkcs1_v15(n00b_jwk_t    *jwk,
                          const char    *alg,
                          const uint8_t *msg,
                          size_t         msg_len,
                          const uint8_t *sig,
                          size_t         sig_len);

/**
 * @brief Verify an RSA-PSS-SHA256 signature (rsa_pss_rsae_sha256).
 *
 * Salt length is hLen = 32 (the standard rsae setting).  Used by the
 * TLS 1.3 CertificateVerify path for RSA certs — RFC 8446 § 4.2.3
 * forbids PKCS1-v1_5 for handshake signatures in TLS 1.3, so PSS is
 * the only RSA option there.
 *
 * @return @c N00B_QUIC_OK on a valid signature; a negative
 *         @c N00B_QUIC_ERR_AUTH_* code otherwise.
 */
extern int
n00b_rsa_verify_pss_sha256(const uint8_t *rsa_n, size_t rsa_n_len,
                           const uint8_t *rsa_e, size_t rsa_e_len,
                           const uint8_t *msg,   size_t msg_len,
                           const uint8_t *sig,   size_t sig_len);

/**
 * @brief Sign with RSA-PSS-SHA256 (rsa_pss_rsae_sha256).
 *
 * Salt length = hLen = 32 (the standard rsae setting).  Caller
 * supplies the salt bytes — production callers should pass
 * cryptographically random bytes; tests can pass deterministic
 * values for reproducibility.
 *
 * @param rsa_n    Modulus bytes (big-endian, no leading zero).
 * @param rsa_n_len Modulus byte length (signature size = this).
 * @param rsa_d    Private exponent bytes.
 * @param rsa_d_len Length of @p rsa_d.
 * @param salt     Salt bytes (32 bytes for rsa_pss_rsae_sha256).
 * @param salt_len Length of @p salt.
 * @param msg      Message bytes.
 * @param msg_len  Length of @p msg.
 * @param out_sig  Output buffer.  Caller must size it >= rsa_n_len.
 * @param inout_sig_len  In: capacity; out: bytes written.
 *
 * @return @c N00B_QUIC_OK on success, negative on failure.
 */
extern int
n00b_rsa_sign_pss_sha256(const uint8_t *rsa_n,  size_t rsa_n_len,
                         const uint8_t *rsa_d,  size_t rsa_d_len,
                         const uint8_t *salt,   size_t salt_len,
                         const uint8_t *msg,    size_t msg_len,
                         uint8_t       *out_sig, size_t *inout_sig_len);

#pragma once

/**
 * @file util/rsa_sign.h
 * @brief RSA-PKCS1-v1_5 SHA-256 signing primitive.
 *
 * Companion to the verify surface in
 * `internal/net/quic/rsa_pkcs1.h`. The Phase 3 Authenticode work
 * needs to sign SignerInfo digests with the signer's RSA private
 * key under PKCS#1 v1.5 SHA-256 (the RFC 5652 default + the
 * Authenticode v1 spec's required algorithm) — there is no
 * existing libn00b sign primitive for that combination (the
 * existing `n00b_rsa_sign_pss_sha256` is PSS, not PKCS1 v1.5).
 *
 * # Implementation locality
 *
 * The implementation lives in `src/net/quic/rsa_pkcs1.c`, sharing
 * the schoolbook bignum + Knuth-D modular-reduction machinery,
 * the DigestInfo SHA-256 prefix, and the EMSA-PKCS1 padding
 * builder with the verify path. The colocation is intentional —
 * sign and verify are dual operations over the same primitive
 * substrate.
 *
 * # Symbol prefix
 *
 * `n00b_rsa_*` (peer to `n00b_rsa_verify_*` declared in the
 * existing internal QUIC header). Public utility namespace
 * matching the `n00b_base64_*` / `n00b_errno_str` lift precedent
 * (`base64.h`, `errno_str.h`) — general-purpose primitive that
 * the PKCS#7 SignedData builder consumes and that any future
 * RSA-PKCS1 caller (signed artifact bundle, signed update) can
 * reuse.
 *
 * # Scope
 *
 * - SHA-256 only. RSA-PKCS1-v1_5 with SHA-384 / SHA-512 are not
 *   needed by Authenticode v1 or by the immediate PKCS#7 callers;
 *   the verify side (`n00b_rsa_verify_pkcs1_v15`) does support
 *   them via the `alg = "RS256"|"RS384"|"RS512"` selector, but the
 *   sign side is RS256-only until a consumer needs more.
 * - Caller provides `(n, d)` as big-endian byte arrays (the same
 *   shape `n00b_rsa_sign_pss_sha256` takes — minimum coupling).
 * - The CRT optimization (with `p`, `q`, `dP`, `dQ`, `qInv`)
 *   is deferred; the bn_t modexp under the hood runs schoolbook
 *   square-and-multiply with Knuth-D reduction, which is slow
 *   but correct and matches the verify-side primitive's perf
 *   budget for one-signature-per-artifact use.
 *
 * # Allocator discipline
 *
 * The function is allocator-aware via the internal scratch path —
 * the public surface takes raw byte buffers (matching
 * `n00b_rsa_sign_pss_sha256`'s shape), and any internal scratch
 * the bn_t machinery needs flows through the runtime-default
 * conduit_pool allocator. No `_kargs` block on the public surface
 * because the input + output are byte-fixed.
 */

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Sign a message with RSA-PKCS1-v1_5 SHA-256 (RFC 8017 §8.2.1).
 *
 * @param rsa_n          RSA modulus (big-endian, no leading zero).
 * @param rsa_n_len      Length of @p rsa_n in bytes; this is also
 *                       the signature length.
 * @param rsa_d          RSA private exponent (big-endian).
 * @param rsa_d_len      Length of @p rsa_d in bytes.
 * @param msg            Message bytes to sign.
 * @param msg_len        Length of @p msg in bytes.
 * @param out_sig        Output buffer; caller must size it
 *                       `>= rsa_n_len`.
 * @param inout_sig_len  In: capacity of @p out_sig (bytes).
 *                       Out: number of bytes written
 *                       (always `rsa_n_len` on success).
 *
 * @return 0 on success; a negative `N00B_QUIC_ERR_*` code on
 *         failure (invalid arg, modexp overflow, EMSA encoding
 *         length error).
 *
 * @details
 *
 * Algorithm (per RFC 8017 §8.2.1):
 *   1. Compute `mHash = SHA-256(msg)`.
 *   2. Build `T = DigestInfo(SHA-256) || mHash`.
 *   3. Build `EM = 0x00 || 0x01 || PS || 0x00 || T` where `PS` is
 *      `0xFF` padding sized to fill `EM` to `rsa_n_len` bytes
 *      (PS must be >= 8 bytes; this is enforced).
 *   4. Compute `s = EM^d mod n` via schoolbook square-and-multiply.
 *   5. Encode `s` as a big-endian byte string the modulus length wide.
 *
 * @pre @p rsa_n, @p rsa_d, @p msg, @p out_sig, @p inout_sig_len
 *      are non-null. `*inout_sig_len >= rsa_n_len`.
 *
 * @post On success, `*inout_sig_len == rsa_n_len` and the
 *       first `rsa_n_len` bytes of @p out_sig hold the
 *       signature in big-endian order.
 */
extern int
n00b_rsa_sign_pkcs1_v15_sha256(const uint8_t *rsa_n,  size_t rsa_n_len,
                               const uint8_t *rsa_d,  size_t rsa_d_len,
                               const uint8_t *msg,    size_t msg_len,
                               uint8_t       *out_sig, size_t *inout_sig_len);

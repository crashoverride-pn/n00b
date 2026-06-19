/**
 * @file jws.h
 * @internal
 * @brief Minimal JWS encoder + JWK helpers, scoped to ACME (RFC 8555).
 *
 * Only the subset RFC 8555 § 6.2 actually requires:
 *
 *   - **Algorithm**: ES256 only (ECDSA-P-256 + SHA-256).  Ed25519
 *     and RSA-PSS are accepted by some ACME servers but are not the
 *     required-to-implement set.  Adding them is one provider/alg
 *     wire-up away.
 *   - **Serialization**: Flattened JSON serialization
 *     (`{"protected": "...", "payload": "...", "signature": "..."}`).
 *     Compact (dot-separated) is not used by ACME directly.
 *   - **Key identification**: ACME servers want either `jwk` (for the
 *     newAccount call, where the server is *first* meeting the key)
 *     or `kid` (account URL — for every other authenticated call).
 *     We support both via `n00b_jws_build`.
 *   - **JWK shape (EC P-256)**:
 *       `{"kty":"EC","crv":"P-256","x":"<b64url X>","y":"<b64url Y>"}`
 *     Members are emitted in the canonical RFC 7638 order.  This is
 *     also the input shape to the JWK thumbprint helper.
 *
 * **Base64url-no-pad** is used everywhere (RFC 7515 § 2 calls this
 * "BASE64URL(...)" with the unpadded variant).
 *
 * @see ~/dd/quic_2.md § 5.5
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "net/quic/secret.h"

/* ===========================================================================
 * Base64url helpers (no padding, RFC 4648 § 5).
 *
 * Exposed so the ACME state machine can encode challenge tokens and
 * key authorizations directly.
 * =========================================================================== */

/** @brief Encode @p in to base64url-no-pad as a heap-allocated C string. */
extern char *
n00b_b64url_encode(const uint8_t *in, size_t in_len);

/** @brief Decode base64url-no-pad @p in into a freshly allocated buffer.
 *
 *  @return Result: ok on success; err(@c N00B_QUIC_ERR_INVALID_ARG) on
 *          malformed input. */
extern n00b_result_t(n00b_buffer_t *)
n00b_b64url_decode(const char *in, size_t in_len);

/* ===========================================================================
 * JWK helpers (EC P-256 only)
 * =========================================================================== */

/**
 * @brief Build a JWK JSON object for an EC P-256 public key.
 *
 * Members are emitted in canonical RFC 7638 order (`crv`, `kty`, `x`,
 * `y`) so the same JSON bytes also serve as input to the thumbprint
 * helper.
 *
 * @param pubkey 64 bytes, uncompressed X || Y (SEC1 layout without
 *               the 0x04 prefix).  Same shape that
 *               @c n00b_quic_secret_pubkey returns for ES256.
 * @return Heap-allocated NUL-terminated string; lifetime managed by
 *         the conduit pool.
 */
extern char *
n00b_jwk_p256_canonical(const uint8_t pubkey[64]);

/**
 * @brief RFC 7638 JWK thumbprint of an EC P-256 public key.
 *
 * Equals SHA-256 of the canonical JWK JSON (same bytes
 * `n00b_jwk_p256_canonical` produces).
 *
 * @param pubkey 64 bytes, uncompressed X || Y.
 * @param out    Receives the 32-byte thumbprint (big-endian).
 */
extern void
n00b_jwk_p256_thumbprint(const uint8_t pubkey[64], uint8_t out[32]);

/* ===========================================================================
 * JWS builder
 * =========================================================================== */

/**
 * @brief Construct a flattened JSON JWS (ES256) for ACME.
 *
 * Exactly one of @p kid or @p embed_jwk must be set.  ACME RFC 8555
 * § 6.2 requires `jwk` for newAccount and `kid` for every
 * subsequent request.
 *
 * The protected header is built as:
 *   - `{"alg":"ES256","nonce":"<nonce>","url":"<url>","kid":"<kid>"}`
 *   - or `{"alg":"ES256","nonce":"<nonce>","url":"<url>","jwk":<jwk>}`
 * with members in that order.
 *
 * @param signer    A privkey secret handle that supports
 *                  @c N00B_QUIC_SIG_ECDSA_P256.
 * @param nonce     Replay-Nonce value from the previous response (or
 *                  newNonce HEAD).
 * @param url       The full URL the JWS targets (RFC 8555 § 6.4).
 * @param payload   Raw payload bytes; may be empty (POST-as-GET).
 *                  May be NULL iff @p payload_len == 0.
 * @kw   kid        Account URL, or nullptr for the newAccount path.
 * @kw   embed_jwk  When true, the protected header carries the
 *                  signer's JWK instead of `kid`.  Mutually exclusive
 *                  with @p kid.
 *
 * @return Result: ok with the JSON-serialized JWS as a freshly
 *         allocated buffer (the on-the-wire bytes of the
 *         `application/jose+json` body).  err on signing failure or
 *         invalid-argument combinations.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_jws_build(n00b_quic_secret_t *signer,
               const char         *nonce,
               const char         *url,
               const uint8_t      *payload,
               size_t              payload_len)
    _kargs {
        const char *kid       = nullptr;
        bool        embed_jwk = false;
    };

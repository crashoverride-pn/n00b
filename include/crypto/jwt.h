/**
 * @file jwt.h
 * @brief JWT validation: parse compact JWS, verify signature against
 *        a JWKS, validate the claim set.
 *
 * RFC 7515 (JWS), RFC 7519 (JWT), RFC 7517 (JWK), RFC 7638 (JWK
 * thumbprint).
 *
 * Phase 3 § 6 ships:
 *
 *   - Compact JWS parser (`<header>.<payload>.<sig>`).
 *   - Algorithms: ES256 (uECC), RS256 / RS384 / RS512 (hand-rolled
 *     RSA-PKCS1-v1_5).  ES384 / EdDSA are documented as
 *     follow-ups; HS256 is explicitly refused (no shared-secret
 *     story for our use case).
 *   - Claim validation: `iss`, `aud`, `exp`, `nbf` (with leeway).
 *   - Key resolution via a callback ("give me the JWK with kid X").
 *     Phase 3.4 wraps OIDC discovery + JWKS cache around that
 *     callback; here we expose the lower-level surface so that
 *     tests can drive it directly without a live IdP.
 *
 * **No `--insecure` switch.**  `alg=none` is refused;
 * `kid`-without-match is refused; expired tokens are refused.
 *
 * @see ~/dd/quic_3.md § 6
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"

/**
 * @brief A JWK (one public key) parsed from JSON.
 *
 * `alg` and `kid` may be empty when omitted.  The `kty`-specific
 * fields are populated based on `kty`:
 *
 *   - `kty="EC"` + `crv="P-256"`: `ec_x` / `ec_y` are 32-byte
 *     big-endian coordinates.
 *   - `kty="RSA"`: `rsa_n` / `rsa_e` are big-endian bignum bytes
 *     (no leading zero).
 */
typedef struct {
    char    *kty;        /* "EC" | "RSA" */
    char    *crv;        /* "P-256" for EC; null for RSA */
    char    *kid;        /* may be null */
    char    *alg;        /* may be null; informational */
    /* EC */
    uint8_t  ec_x[64];   /* size determined by crv; P-256 = 32 */
    uint8_t  ec_y[64];
    size_t   ec_coord_len;  /* 32 for P-256 */
    /* RSA */
    uint8_t *rsa_n;
    size_t   rsa_n_len;
    uint8_t *rsa_e;
    size_t   rsa_e_len;
} n00b_jwk_t;

/** @brief A list of JWKs (a JWKS). */
typedef struct {
    n00b_jwk_t **keys;
    size_t       count;
} n00b_jwk_set_t;

/**
 * @brief Parse a JWKS JSON document into a `n00b_jwk_set_t *`.
 *
 * @param json   NUL-terminated JSON containing
 *               `{"keys":[ ...JWK... ]}`.
 *
 * @return Result: ok on success; err on parse failure or unsupported
 *         `kty`.
 */
extern n00b_result_t(n00b_jwk_set_t *)
n00b_jwk_set_parse(const char *json);

/**
 * @brief Look up a JWK by `kid`.  Linear scan; JWKS holds 1-10 keys
 *        in practice.
 *
 * @param set The JWKS to search.
 * @param kid The key id to look up, or nullptr to request the
 *            degenerate kid-less fallback (returns the single key
 *            in a one-key set, or the unique kid-less key if exactly
 *            one is present; otherwise none — see implementation
 *            notes in `src/net/quic/jwt.c` for the confused-deputy
 *            rationale).
 *
 * @return The matching JWK wrapped in @c n00b_option_t. Returns
 *         @c n00b_option_none(n00b_jwk_t *) when:
 *           - @p set is nullptr,
 *           - @p kid is non-nullptr but not present in @p set,
 *           - @p kid is nullptr and the kid-less-fallback rules don't
 *             yield exactly one candidate.
 *
 * @post Once unwrapped via @ref n00b_option_get the returned pointer
 *       is borrowed (owned by @p set's backing storage).
 */
extern n00b_option_t(n00b_jwk_t *)
n00b_jwk_set_lookup(n00b_jwk_set_t *set, const char *kid);

/**
 * @brief Decoded JWT claim set.
 *
 * Common claims are surfaced as named fields; the full claim object
 * is available via `claims` for non-RFC claims.  Numeric claims
 * (iat / nbf / exp) are stored as Unix-time milliseconds.
 */
typedef struct {
    char    *iss;
    char    *sub;
    char    *aud;        /* When `aud` is an array, populated only if
                          * the verifier's expected audience is the
                          * single string match; otherwise null. */
    char    *jti;
    int64_t  iat_ms;     /* 0 if absent */
    int64_t  nbf_ms;     /* 0 if absent */
    int64_t  exp_ms;     /* 0 if absent */
    /* RFC 8705 § 3.1: when set, the access token is bound to the
     * client cert whose SHA-256 (over its DER encoding) matches
     * these 32 bytes.  Drives `n00b_mtls_token_verify`. */
    bool     has_cnf_x5t_s256;
    uint8_t  cnf_x5t_s256[32];
    char    *raw_payload_json;  /* full payload JSON for downstream */
} n00b_jwt_claims_t;

/**
 * @brief JWT verifier handle.
 *
 * Encapsulates expected audience/issuer + clock-skew leeway.  The
 * key source is provided via a callback (Phase 3.4 wires this to an
 * OIDC handle).
 */
typedef struct n00b_jwt_verifier n00b_jwt_verifier_t;

/**
 * @brief Key resolution callback.
 *
 * Called once per `verify` invocation.  The callback inspects the
 * compact JWS's `kid` (may be nullptr) and `alg`, and returns a JWK
 * whose `kty`/`crv` are compatible with @p alg.  Return nullptr if
 * no key can be found — verification fails with
 * `N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND`.
 *
 * @note **Callback-contract decision (deliberate).** Unlike library
 *       accessors that return @c n00b_option_t(T *) for "absent vs.
 *       present" disambiguation (per §5.4 of the n00b API
 *       guidelines), this typedef intentionally retains the
 *       `nullptr`-as-absent contract. The signature is implemented
 *       by USER CODE (every JWKS-resolution strategy in the
 *       project provides its own implementation: see
 *       @c resolve_via_set in test/unit/test_quic_jwt.c et al., and
 *       the OIDC wrapper in src/net/quic/oidc.c). Migrating the
 *       typedef to @c n00b_option_t(n00b_jwk_t *) would break every
 *       external implementer with no semantic gain — `kid` lookup
 *       has no ambiguous-value case (the result is either "the
 *       matching JWK" or "no key"). The library code that INVOKES
 *       this callback maps nullptr to
 *       @c N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND at the boundary; that
 *       error-conversion layer is where option semantics would
 *       conceptually apply, but the callback-contract surface
 *       remains a flat nullable pointer by design.
 */
typedef n00b_jwk_t *(*n00b_jwt_resolve_key_fn)(void       *ctx,
                                               const char *kid,
                                               const char *alg);

/**
 * @brief Construct a JWT verifier.
 *
 * @kw expected_audience  Required.  Verification fails if `aud` does
 *                        not match (string equality or membership of
 *                        the array form).
 * @kw expected_issuer    Optional.  When set, `iss` must match.
 * @kw leeway_seconds     Default 60.  Symmetric clock-skew tolerance
 *                        for `nbf` and `exp`.
 * @kw resolve_key        Required.  See `n00b_jwt_resolve_key_fn`.
 * @kw resolve_key_ctx    Opaque ctx passed to @p resolve_key.
 */
extern n00b_result_t(n00b_jwt_verifier_t *)
n00b_jwt_verifier_new() _kargs {
    const char              *expected_audience = nullptr;
    const char              *expected_issuer   = nullptr;
    int32_t                  leeway_seconds    = 60;
    n00b_jwt_resolve_key_fn  resolve_key       = nullptr;
    void                    *resolve_key_ctx   = nullptr;
};

/**
 * @brief Verify a compact JWS and return the decoded claims.
 *
 * Steps performed (RFC 7519 § 7.2):
 *   1. Split @p compact_jws on '.'; expect 3 parts.
 *   2. Decode protected header; reject `alg=none`.
 *   3. Resolve key via verifier's `resolve_key` callback.
 *   4. Verify signature against `header.payload` bytes per `alg`.
 *   5. Decode payload JSON; populate claims.
 *   6. Validate `exp`, `nbf` (with leeway), `iss` (if expected),
 *      `aud` (always required).
 *
 * @return Result: ok with claims on full validation; err with the
 *         appropriate `N00B_QUIC_ERR_AUTH_*` code on any failure.
 */
extern n00b_result_t(n00b_jwt_claims_t *)
n00b_jwt_verify(n00b_jwt_verifier_t *v, const char *compact_jws);

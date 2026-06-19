/**
 * @file dpop.h
 * @brief DPoP (RFC 9449) — proof-of-possession headers for OAuth 2.0
 *        access tokens.
 *
 * A DPoP proof is a compact JWS with a fixed header layout
 * (`typ=dpop+jwt`, the holder's JWK embedded in the header) and a
 * payload containing the request method, URL, a unique `jti`, an
 * `iat` timestamp, and an optional server-issued `nonce`.
 *
 * Phase 3 § 8 covers:
 *
 *   - **Issue side**: build a DPoP proof from a holder secret + the
 *     request shape.
 *   - **Verify side**: validate the proof against expected
 *     `htm`/`htu`/`nonce`, optionally check the JWK thumbprint
 *     (`jkt`) bound to a separate access token, and (via the
 *     replay store) reject reuse of a `jti`.
 *
 * Algorithm support: ES256 only in v1.  RFC 9449 § 4.2 allows
 * ES256/ES384/PS256/etc.; we ship the simplest set that covers
 * Auth0 / Okta / Keycloak's defaults.
 *
 * @see ~/dd/quic_3.md § 8
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/result.h"
#include "core/string.h"
#include "net/quic/secret.h"

/**
 * @brief Build a DPoP proof JWS for an HTTP request.
 *
 * Produces the value of the `DPoP` header as a NUL-terminated
 * compact JWS string.  The signing key must support ES256
 * (the holder secret).  The proof is bound to the request
 * via @p htm + @p htu and to a unique `jti` we generate.
 *
 * @param holder_key  Privkey secret handle (must support
 *                    @c N00B_QUIC_SIG_ECDSA_P256).
 * @param htm         HTTP method ("GET", "POST", …).
 * @param htu         Target URL.  RFC 9449 § 4.2 requires that the
 *                    `htu` be the request URL minus query/fragment;
 *                    callers can pass whatever shape they want, the
 *                    verifier compares strings.
 *
 * @kw nonce          Optional server-issued nonce; when set, the
 *                    proof embeds it (RFC 9449 § 8).
 * @kw access_token   Optional access token to bind via the `ath`
 *                    claim.  When set, the proof embeds
 *                    `ath = base64url(SHA-256(access_token))` per
 *                    RFC 9449 § 4.3.  REQUIRED when this proof
 *                    will be presented alongside an access token.
 * @kw access_token_len  Length of @p access_token.
 *
 * @return Result: ok with a heap-allocated NUL-terminated string
 *         (lifetime: conduit pool).  err on signing failure.
 */
extern n00b_result_t(char *)
n00b_dpop_create(n00b_quic_secret_t *holder_key,
                 const char         *htm,
                 const char         *htu)
    _kargs {
        const char    *nonce            = nullptr;
        const uint8_t *access_token     = nullptr;
        size_t         access_token_len = 0;
    };

/**
 * @brief Replay store for DPoP `jti` values.
 *
 * Bounded LRU keyed on `jti`.  Inserts return "already seen" if the
 * jti is in the cache; otherwise the new jti is inserted (evicting
 * the oldest if at capacity).
 *
 * Phase 3 default capacity is 1024.  Bound is per-process; multi-
 * instance deployments needing cross-replica replay protection
 * should put a Redis-backed sidecar in front (deferred follow-up).
 */
typedef struct n00b_dpop_replay_store n00b_dpop_replay_store_t;

/**
 * @brief Allocate a replay store.
 *
 * @kw capacity  Max entries.  Default 1024.
 */
extern n00b_dpop_replay_store_t *
n00b_dpop_replay_store_new() _kargs {
    int32_t capacity = 1024;
};

/** @brief Close a replay store and release its memory. */
extern void n00b_dpop_replay_store_close(n00b_dpop_replay_store_t *s);

/**
 * @brief Verify a DPoP proof.
 *
 * Steps performed:
 *   1. Parse compact JWS; require 3 parts.
 *   2. Decode header; require `typ=dpop+jwt`, `alg=ES256`,
 *      and a parseable `jwk` (EC P-256 only in v1).
 *   3. Verify signature using the embedded JWK.
 *   4. Decode payload; check `htm`, `htu`, `iat` (within
 *      @p leeway_seconds of now), optional `nonce`.
 *   5. If @p expected_jkt is set, compute the SHA-256 thumbprint
 *      of the embedded JWK (RFC 7638) and compare.
 *   6. If @p replay is set, insert the `jti`; reject if already
 *      seen.
 *
 * @param dpop_header     The DPoP header value (compact JWS).
 * @param htm             Expected HTTP method.
 * @param htu             Expected URL.
 *
 * @kw expected_jkt       SHA-256 thumbprint of the holder's JWK
 *                        (32 bytes).  Optional; when set, the
 *                        proof's embedded JWK must match.
 * @kw expected_nonce     Optional expected server-issued nonce.
 *                        When set, the proof's `nonce` claim must
 *                        match exactly.
 * @kw expected_ath       Optional access-token hash binding.  When
 *                        non-NULL, the proof MUST include `ath` =
 *                        base64url(SHA-256(@p expected_ath)).  This
 *                        is REQUIRED by RFC 9449 § 4.3 when the proof
 *                        is paired with an access token; verifiers
 *                        that omit it allow captured proofs to be
 *                        replayed against a different access token
 *                        at the same URL.
 * @kw expected_ath_len   Length of `expected_ath`.  Required if
 *                        `expected_ath` is non-NULL.
 * @kw leeway_seconds     Symmetric clock-skew tolerance for `iat`.
 *                        Default 60.
 * @kw replay             Optional replay store; when set, the
 *                        `jti` must be fresh.
 *
 * URL comparison: @p htu is compared to the proof's `htu` claim
 * after RFC 9449 § 4.2 normalization on BOTH sides — strip any
 * userinfo (`user:pass@`), query string, and fragment; lowercase
 * scheme + host (including hex digits inside IPv6 literals per
 * RFC 5952); remove a default port if present (`:443` for https,
 * `:80` for http).  IPv6 literal brackets are preserved verbatim
 * (RFC 3986 § 3.2.2).  Callers can pass any reasonable URL shape;
 * the verifier handles canonicalization.
 *
 * @return Result of bool: ok(true) on success; err with the
 *         appropriate `N00B_QUIC_ERR_AUTH_*` code on any failure.
 */
extern n00b_result_t(bool)
n00b_dpop_verify(const char *dpop_header,
                 const char *htm,
                 const char *htu)
    _kargs {
        const uint8_t            *expected_jkt    = nullptr;  /* 32 bytes */
        const char               *expected_nonce  = nullptr;
        const uint8_t            *expected_ath    = nullptr;
        size_t                    expected_ath_len = 0;
        int32_t                   leeway_seconds  = 60;
        n00b_dpop_replay_store_t *replay          = nullptr;
    };

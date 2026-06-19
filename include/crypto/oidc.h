/**
 * @file oidc.h
 * @brief OpenID Connect discovery + JWKS cache.
 *
 * Phase 3 § 7: discover an IdP's signing keys via the well-known
 * configuration endpoint and cache the JWKS with a TTL.  Wraps the
 * lower-level `n00b_jwt_verifier_t` from `quic/jwt.h` so callers
 * can verify tokens without writing a key resolver themselves.
 *
 * Discovery sequence:
 *
 *   1. Issuer URL `https://idp.example` →
 *      GET `https://idp.example/.well-known/openid-configuration`.
 *   2. Parse `jwks_uri` from the JSON response.
 *   3. GET that URL; parse as a JWKS.
 *
 * The JWKS is cached by `kid`.  RFC 7517 § 4.5: when a token's
 * `kid` is absent from the cache, refresh ONCE before failing —
 * this handles the "IdP rotated keys, new kid in the wild"
 * case.  After TTL, the next access refreshes lazily.
 *
 * Trust path: discovery + JWKS GETs use the same OS-trust
 * verification as the ACME shim (Phase 2 § 5.3).  No
 * `--insecure`, no `verify=false`.
 *
 * @see ~/dd/quic_3.md § 7
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/result.h"
#include "core/string.h"
#include "crypto/jwt.h"

typedef struct n00b_oidc n00b_oidc_t;

/**
 * @brief Open an OIDC handle by discovering an issuer.
 *
 * Performs two HTTPS GETs: openid-configuration → jwks_uri.  Both
 * must succeed for `open` to return ok.
 *
 * @param issuer   IdP issuer URL (e.g.,
 *                 `https://accounts.example.com`).  Must be HTTPS.
 *
 * @kw cache_ttl_seconds  How long the JWKS cache stays fresh
 *                        before lazy refresh.  Default 3600 (1 hr).
 * @kw timeout_ms         Per-request HTTP timeout.  Default 30000.
 */
extern n00b_result_t(n00b_oidc_t *)
n00b_oidc_open(const char *issuer)
    _kargs {
        int32_t cache_ttl_seconds = 3600;
        int32_t timeout_ms        = 30000;
    };

/**
 * @brief Test-only constructor: skip the network and seed a JWKS
 *        directly.
 *
 * Used by the synthetic-IdP unit test (Phase 3.10) and any caller
 * that has the JWKS already in hand (mTLS-based key distribution,
 * a sidecar, etc.).
 *
 * @param issuer    Reported issuer (informational; null-OK).
 * @param jwks_json JWKS document as a NUL-terminated JSON string.
 *
 * @kw cache_ttl_seconds  Same as `n00b_oidc_open`.
 */
extern n00b_result_t(n00b_oidc_t *)
n00b_oidc_open_with_jwks(const char *issuer, const char *jwks_json)
    _kargs {
        int32_t cache_ttl_seconds = 3600;
    };

/**
 * @brief Get the JWK matching @p kid.
 *
 * If @p kid is in the cache: return it.  If absent (and the cache
 * isn't stale): trigger a single refresh and try again.  If the
 * cache IS stale (TTL exceeded): refresh first, then look up.
 *
 * @param o    OIDC handle.
 * @param kid  Token's `kid` header (may be nullptr; first-key
 *             fallback applies same as `n00b_jwk_set_lookup`).
 *
 * @return The matching JWK, or nullptr.  Borrowed; callers must
 *         not free.  The pointer remains valid until the next
 *         refresh swap (which is rare; cache TTLs are minutes-to-
 *         hours).
 */
extern n00b_jwk_t *
n00b_oidc_get_key(n00b_oidc_t *o, const char *kid);

/** @brief Close the handle and release cached JWKS bytes. */
extern void
n00b_oidc_close(n00b_oidc_t *o);

/**
 * @brief Convenience: build a JWT verifier wired to this OIDC.
 *
 * The verifier's key resolver delegates to
 * @c n00b_oidc_get_key.  Issuer is filled in from @p o by default;
 * callers can override.
 *
 * @kw expected_issuer   Default: the issuer @p o was opened with.
 * @kw leeway_seconds    Default 60.
 */
extern n00b_result_t(n00b_jwt_verifier_t *)
n00b_oidc_jwt_verifier(n00b_oidc_t *o,
                       const char  *expected_audience)
    _kargs {
        const char *expected_issuer = nullptr;
        int32_t     leeway_seconds  = 60;
    };

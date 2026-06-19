/**
 * @file synthetic_idp.h
 * @brief In-process synthetic IdP fixture for offline auth testing.
 *
 * Phase 3.10: lets unit tests exercise the full Phase 3 stack
 * (OIDC discovery → JWKS → JWT verify → policy eval) without
 * standing up a real IdP container.
 *
 * Shape:
 *   - Generates an ephemeral ES256 keypair on construct.
 *   - Issues a known JWKS document containing that key.
 *   - Mints tokens with caller-specified claims via a single
 *     helper.
 *   - Bridges into n00b_oidc_t via `n00b_oidc_open_with_jwks` —
 *     no HTTP server, no port binding.
 *
 * The fixture lives under test/ and is shared by Phase 3.10's
 * end-to-end test plus any future tests that want a "real-ish"
 * IdP without Docker.  The Keycloak interop fixture for fully
 * realistic testing lives at test/fixtures/keycloak/.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "core/string.h"
#include "crypto/secret.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"

typedef struct n00b_synthetic_idp n00b_synthetic_idp_t;

/**
 * @brief Allocate a synthetic IdP with a fresh ES256 keypair.
 *
 * @param issuer  The issuer URL the IdP "claims" to be.  Used
 *                in `iss` claim of minted tokens and as the
 *                issuer the OIDC handle uses.
 * @param kid     Stable kid for the embedded JWK.
 */
extern n00b_synthetic_idp_t *
n00b_synthetic_idp_new(const char *issuer, const char *kid);

/** @brief The issuer URL passed at construction. */
extern const char *
n00b_synthetic_idp_issuer(n00b_synthetic_idp_t *s);

/** @brief The kid used in the embedded JWK. */
extern const char *
n00b_synthetic_idp_kid(n00b_synthetic_idp_t *s);

/**
 * @brief Open an OIDC handle backed by this IdP (synthetic; no HTTP).
 *
 * Result is owned by the caller; close with `n00b_oidc_close`.
 */
extern n00b_oidc_t *
n00b_synthetic_idp_oidc(n00b_synthetic_idp_t *s);

/**
 * @brief The signing secret (handle to the holder's private key).
 *
 * For convenience: callers wanting to mint a DPoP proof for the
 * same key as the access-token holder can pass this.
 */
extern n00b_quic_secret_t *
n00b_synthetic_idp_signer(n00b_synthetic_idp_t *s);

/**
 * @brief Mint an ES256-signed token.
 *
 * @param s          Synthetic IdP.
 * @param subject    `sub` claim ("alice", etc.).
 * @param audience   `aud` claim.
 * @param exp_offset Seconds from now until expiration (positive
 *                   = in future, negative = already expired).
 *
 * @kw scope         Optional `scope` claim (space-delimited).
 * @kw role          Optional `role` claim.
 * @kw cnf_x5t_s256  Optional cert thumbprint to embed in
 *                   `cnf.x5t#S256` (32-byte raw bytes).
 *
 * @return Compact JWS string; lifetime conduit pool.
 */
extern char *
n00b_synthetic_idp_mint(n00b_synthetic_idp_t *s,
                        const char           *subject,
                        const char           *audience,
                        int64_t               exp_offset_s)
    _kargs {
        const char    *scope        = nullptr;
        const char    *role         = nullptr;
        const uint8_t *cnf_x5t_s256 = nullptr;  /* 32 bytes */
    };

/** @brief Release the IdP + its keypair. */
extern void
n00b_synthetic_idp_close(n00b_synthetic_idp_t *s);

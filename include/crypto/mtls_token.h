/**
 * @file mtls_token.h
 * @brief mTLS-bound access tokens (RFC 8705).
 *
 * RFC 8705 binds an OAuth2 access token to the client certificate
 * used during the mTLS handshake at the IdP.  The token carries a
 * `cnf.x5t#S256` claim — base64url(SHA-256(client_cert_DER)).
 *
 * Verifying:
 *   1. Pull `cnf.x5t#S256` from the JWT claims (already done by
 *      the JWT verifier; surfaced as `claims->has_cnf_x5t_s256` +
 *      `claims->cnf_x5t_s256`).
 *   2. Compute SHA-256 over the DER of the client cert presented
 *      to *this* server.
 *   3. Constant-time compare.
 *
 * This module ships the **pure verification logic**: callers
 * supply the client cert DER bytes.  The integration with
 * picotls's client-auth verify-callback (auto-capture of the
 * peer cert) lands when client-auth is wired through
 * `n00b_quic_endpoint_t` — which is itself a follow-up since
 * Phase 1/2 endpoints don't enable client-auth.  See
 * `~/dd/quic_3.md § 9` and risk #2.
 *
 * @see ~/dd/quic_3.md § 9
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/result.h"
#include "crypto/jwt.h"

/**
 * @brief Verify a JWT's `cnf.x5t#S256` claim against a client cert.
 *
 * Computes SHA-256 over @p peer_cert_der and compares to
 * @p claims->cnf_x5t_s256.  Constant-time.
 *
 * @param claims          JWT claims with `cnf.x5t#S256` populated.
 *                        Must have `has_cnf_x5t_s256 == true`.
 * @param peer_cert_der   DER-encoded client cert bytes (the leaf
 *                        the client presented during mTLS).
 * @param peer_cert_len   Length of @p peer_cert_der.
 *
 * @return Result of bool: ok(true) on match; err with
 *         @c N00B_QUIC_ERR_AUTH_MTLS_MISMATCH on mismatch.
 *         err with @c N00B_QUIC_ERR_AUTH_TOKEN_INVALID if the
 *         claim is absent (caller should pre-check
 *         `has_cnf_x5t_s256`).
 */
extern n00b_result_t(bool)
n00b_mtls_token_verify(const n00b_jwt_claims_t *claims,
                       const uint8_t           *peer_cert_der,
                       size_t                   peer_cert_len);

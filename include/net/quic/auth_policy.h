/**
 * @file auth_policy.h
 * @brief Per-channel auth policy: declarative claims-required-to-
 *        open-this-channel.
 *
 * Phase 3 § 10.  A policy is a small descriptor of what the
 * caller must present (a JWT bearer token, optionally with DPoP
 * and/or mTLS-bound-token confirmation) before bytes flow on a
 * channel.
 *
 * The policy is the **algebra** — what's required.  Evaluation
 * happens in `n00b_quic_auth_policy_eval` against a credentials
 * bundle the caller supplies.  In Phase 4 (RPC), the RPC layer
 * will collect the credentials from the first frame on the
 * channel and run eval at chan_open time.  In Phase 3, the
 * policy + eval ship without the RPC plumbing — applications can
 * use them directly today (e.g., to gate a channel based on the
 * first-message contents they parse themselves).
 *
 * Failure modes:
 *   - Token missing → @c N00B_QUIC_ERR_AUTH_TOKEN_MISSING.
 *   - Token verify fails → @c N00B_QUIC_ERR_AUTH_TOKEN_INVALID.
 *   - DPoP required + missing/invalid → @c N00B_QUIC_ERR_AUTH_DPOP_FAILED.
 *   - mTLS-bound but thumbprint mismatch → @c N00B_QUIC_ERR_AUTH_MTLS_MISMATCH.
 *   - Issuer / audience / claim mismatch → corresponding ISS/AUD codes,
 *     or AUTH_TOKEN_INVALID for generic claim mismatches.
 *
 * @see ~/dd/quic_3.md § 10
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/result.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/jwt.h"
#include "crypto/dpop.h"

typedef struct n00b_quic_auth_policy n00b_quic_auth_policy_t;

/** @brief Allocate an empty policy (no requirements). */
extern n00b_quic_auth_policy_t *n00b_quic_auth_policy_new();

/** @brief Release a policy and all attached requirement strings. */
extern void n00b_quic_auth_policy_close(n00b_quic_auth_policy_t *p);

/* Each setter is monotonic — once a constraint is set it stays.
 * Callers build the policy once at startup and reuse the handle
 * across channels.  Multiple require_claim entries AND together. */

extern void
n00b_quic_auth_policy_require_audience(n00b_quic_auth_policy_t *p,
                                       const char              *audience);

extern void
n00b_quic_auth_policy_require_issuer(n00b_quic_auth_policy_t *p,
                                     const char              *issuer);

/**
 * @brief Require a specific claim (string-equality).
 *
 * @p name and @p value are duplicated.  Multiple calls AND.
 */
extern void
n00b_quic_auth_policy_require_claim(n00b_quic_auth_policy_t *p,
                                    const char              *name,
                                    const char              *value);

/**
 * @brief Require that a claim's value (a space-delimited string)
 *        CONTAINS the given token.
 *
 * Matches OAuth2's `scope` claim shape (RFC 6749 § 3.3) — e.g.,
 * `scope: "rpc:read rpc:write"` would satisfy a require_contains
 * for `rpc:write` but not `rpc:admin`.
 *
 * @p name and @p needle are duplicated.  Multiple calls AND.
 */
extern void
n00b_quic_auth_policy_require_claim_contains(n00b_quic_auth_policy_t *p,
                                             const char              *name,
                                             const char              *needle);

extern void
n00b_quic_auth_policy_require_dpop(n00b_quic_auth_policy_t *p);

extern void
n00b_quic_auth_policy_require_mtls(n00b_quic_auth_policy_t *p);

/**
 * @brief Optional renewal hook — invoked when the channel's
 *        token approaches `exp` (Phase 4 RPC layer triggers it).
 *
 * For Phase 3 the field is stored but never called; Phase 4 wires
 * the trigger.
 *
 * @param fn   Function called with the policy + an opaque ctx.
 *             Returns a fresh bearer token (heap-allocated, caller
 *             frees) or nullptr to keep the existing one.
 * @param ctx  Passed verbatim to @p fn.
 */
typedef char *(*n00b_quic_auth_renewal_fn)(n00b_quic_auth_policy_t *p,
                                           void                    *ctx);

extern void
n00b_quic_auth_policy_set_renewal_hook(n00b_quic_auth_policy_t   *p,
                                       n00b_quic_auth_renewal_fn  fn,
                                       void                      *ctx);

/**
 * @brief What the caller presents to satisfy a policy.
 *
 * Fields not relevant to the policy's requirements may be NULL.
 * For example, a policy without `require_dpop` ignores
 * `dpop_header` / `htm` / `htu`.
 */
typedef struct {
    const char               *bearer_token;     /* compact JWS */
    n00b_jwt_verifier_t      *jwt_verifier;     /* pre-configured */
    /* DPoP — required only if policy.require_dpop */
    const char               *dpop_header;
    const char               *htm;
    const char               *htu;
    n00b_dpop_replay_store_t *dpop_replay;      /* optional */
    /* mTLS — required only if policy.require_mtls */
    const uint8_t            *peer_cert_der;
    size_t                    peer_cert_len;
} n00b_quic_auth_credentials_t;

/**
 * @brief Evaluate a credentials bundle against a policy.
 *
 * @return Result of *claims: ok with the verified claims on
 *         success; err with the appropriate AUTH_* code on
 *         failure.  An empty policy (no requirements) returns
 *         ok with claims=nullptr.
 */
extern n00b_result_t(n00b_jwt_claims_t *)
n00b_quic_auth_policy_eval(n00b_quic_auth_policy_t            *p,
                           const n00b_quic_auth_credentials_t *creds);

/* ===========================================================================
 * Channel integration
 *
 * In Phase 3, set_policy stores the policy reference on a
 * channel for callers that want to evaluate before draining
 * bytes.  Actual transport-level enforcement (refuse bytes until
 * eval succeeds) is the Phase 4 RPC layer's job.
 * =========================================================================== */

/** @brief Attach a policy to a channel.  Borrowed; caller-owned. */
extern void
n00b_quic_chan_set_policy(n00b_quic_chan_t        *chan,
                          n00b_quic_auth_policy_t *policy);

/** @brief Read back the policy attached via set_policy (or nullptr). */
extern n00b_quic_auth_policy_t *
n00b_quic_chan_get_policy(n00b_quic_chan_t *chan);

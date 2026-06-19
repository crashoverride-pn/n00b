/*
 * test_quic_synthetic_idp.c — End-to-end Phase 3 stack against a
 * synthetic IdP fixture.  This is the offline equivalent of the
 * Keycloak interop test; it wires together:
 *
 *   - 3.4 OIDC discovery + JWKS cache (via the IdP fixture).
 *   - 3.3 JWT verifier.
 *   - 3.5 DPoP issue + verify (when the policy requires it).
 *   - 3.6 mTLS-bound thumbprint check.
 *   - 3.7 Per-channel auth policy + eval.
 *   - 3.8 Audit-event emission.
 *
 * Three sub-tests:
 *   1. Token round-trip: issuer mints a token with scope=rpc:write;
 *      policy requires it; eval ok.
 *   2. Token from a different IdP-issuer is rejected (ISS_MISMATCH).
 *   3. Stacked policy with DPoP + mTLS + scope: all three constraints
 *      verified end-to-end via the synthetic IdP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"
#include "crypto/dpop.h"
#include "net/quic/auth_policy.h"
#include "net/quic/audit.h"

#include "../fixtures/synthetic_idp.h"
#include "../fixtures/quic_test_pki.h"

typedef struct {
    int n_allow;
    int n_deny;
    n00b_quic_err_t last_deny_reason;
} audit_count_t;

static void
counter_sub(const n00b_quic_audit_event_t *evt, void *ctx)
{
    audit_count_t *c = ctx;
    if (evt->decision == N00B_QUIC_AUDIT_ALLOW) c->n_allow++;
    else { c->n_deny++; c->last_deny_reason = evt->reason_code; }
}

/* ============================================================================
 * 1. Plain JWT round-trip via synthetic IdP + policy with claim_contains.
 * ============================================================================ */

static void
test_oidc_policy_roundtrip(void)
{
    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k1");
    assert(idp);

    char *jws = n00b_synthetic_idp_mint(idp, "alice", "checkout-api", 3600,
                                        .scope = "rpc:read rpc:write");
    assert(jws);

    n00b_oidc_t *oidc = n00b_synthetic_idp_oidc(idp);
    auto vr = n00b_oidc_jwt_verifier(oidc, "checkout-api");
    assert(n00b_result_is_ok(vr));
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "checkout-api");
    n00b_quic_auth_policy_require_issuer(p, "https://idp.example");
    n00b_quic_auth_policy_require_claim_contains(p, "scope", "rpc:write");

    audit_count_t counter = {0};
    int sub = n00b_quic_audit_subscribe(counter_sub, &counter);

    n00b_quic_auth_credentials_t creds = {.bearer_token = jws,
                                          .jwt_verifier = v};
    auto r = n00b_quic_auth_policy_eval(p, &creds);
    assert(n00b_result_is_ok(r));
    n00b_jwt_claims_t *claims = n00b_result_get(r);
    assert(strcmp(claims->iss, "https://idp.example") == 0);
    assert(strcmp(claims->sub, "alice") == 0);
    assert(counter.n_allow == 1);
    assert(counter.n_deny == 0);
    printf("  [PASS] synthetic IdP → policy_eval allow with audit\n");

    n00b_quic_audit_unsubscribe(sub);
    n00b_quic_auth_policy_close(p);
    n00b_synthetic_idp_close(idp);
}

/* ============================================================================
 * 2. Issuer mismatch when token is from a different (synthetic) IdP.
 * ============================================================================ */

static void
test_issuer_mismatch(void)
{
    n00b_synthetic_idp_t *idp_a =
        n00b_synthetic_idp_new("https://idp-a.example", "ka");
    n00b_synthetic_idp_t *idp_b =
        n00b_synthetic_idp_new("https://idp-b.example", "kb");

    /* Mint with idp_a, but verify against idp_b's OIDC handle.  The
     * verifier looks up the kid via idp_b's JWKS and won't find it
     * (idp_a has its own kid). */
    char *jws = n00b_synthetic_idp_mint(idp_a, "alice", "svc", 3600);

    auto vr = n00b_oidc_jwt_verifier(n00b_synthetic_idp_oidc(idp_b), "svc");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "svc");

    audit_count_t counter = {0};
    int sub = n00b_quic_audit_subscribe(counter_sub, &counter);

    n00b_quic_auth_credentials_t creds = {.bearer_token = jws,
                                          .jwt_verifier = v};
    auto r = n00b_quic_auth_policy_eval(p, &creds);
    assert(n00b_result_is_err(r));
    /* Verifier rejects at key-not-found (kid 'ka' isn't in idp_b's
     * JWKS).  Audit logs a deny. */
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND);
    assert(counter.n_allow == 0);
    assert(counter.n_deny == 1);
    assert(counter.last_deny_reason == N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND);
    printf("  [PASS] cross-IdP token → KEY_NOT_FOUND + audit deny\n");

    n00b_quic_audit_unsubscribe(sub);
    n00b_quic_auth_policy_close(p);
    n00b_synthetic_idp_close(idp_a);
    n00b_synthetic_idp_close(idp_b);
}

/* ============================================================================
 * 3. Stacked policy: scope + DPoP + mTLS-bound (cnf.x5t#S256).
 * ============================================================================ */

static void
test_stacked_oidc_policy(void)
{
    n00b_synthetic_idp_t *idp =
        n00b_synthetic_idp_new("https://idp.example", "k3");

    /* Compute the test cert's SHA-256 thumbprint. */
    uint8_t fp[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(n00b_quic_test_cert_der,
                         n00b_quic_test_cert_der_len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            fp[i*4]     = (uint8_t)(w >> 24);
            fp[i*4 + 1] = (uint8_t)(w >> 16);
            fp[i*4 + 2] = (uint8_t)(w >> 8);
            fp[i*4 + 3] = (uint8_t)w;
        }
    }

    char *jws = n00b_synthetic_idp_mint(idp, "alice", "svc", 3600,
                                        .scope        = "rpc:write",
                                        .cnf_x5t_s256 = fp);

    /* DPoP proof signed by the same holder key. */
    auto dpr = n00b_dpop_create(n00b_synthetic_idp_signer(idp),
                                "POST", "https://api/checkout");
    char *proof = n00b_result_get(dpr);

    n00b_oidc_t *oidc = n00b_synthetic_idp_oidc(idp);
    auto vr = n00b_oidc_jwt_verifier(oidc, "svc");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "svc");
    n00b_quic_auth_policy_require_claim_contains(p, "scope", "rpc:write");
    n00b_quic_auth_policy_require_dpop(p);
    n00b_quic_auth_policy_require_mtls(p);

    n00b_quic_auth_credentials_t creds = {
        .bearer_token  = jws,
        .jwt_verifier  = v,
        .dpop_header   = proof,
        .htm           = "POST",
        .htu           = "https://api/checkout",
        .peer_cert_der = n00b_quic_test_cert_der,
        .peer_cert_len = n00b_quic_test_cert_der_len,
    };
    auto r = n00b_quic_auth_policy_eval(p, &creds);
    assert(n00b_result_is_ok(r));
    n00b_jwt_claims_t *claims = n00b_result_get(r);
    assert(claims->has_cnf_x5t_s256);
    printf("  [PASS] stacked OIDC policy: scope + DPoP + mTLS all green\n");

    n00b_quic_auth_policy_close(p);
    n00b_synthetic_idp_close(idp);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_synthetic_idp:\n");
    test_oidc_policy_roundtrip();
    test_issuer_mismatch();
    test_stacked_oidc_policy();
    printf("All quic_synthetic_idp tests passed.\n");

    n00b_shutdown();
    return 0;
}

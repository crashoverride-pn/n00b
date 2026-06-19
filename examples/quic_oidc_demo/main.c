/*
 * quic_oidc_demo — Demonstration of the Phase 3 auth pipeline.
 *
 * What it shows:
 *   1. Load a manifest with auth.idps[] + auth.policies[].
 *   2. Run preflight (rejects misconfigured manifests).
 *   3. For each declared policy, build an in-memory
 *      `n00b_quic_auth_policy_t` from the manifest entry.
 *   4. Subscribe a JSONL audit sink at /tmp/quic_oidc_demo.jsonl.
 *   5. Present a synthetic token (minted in-process by the
 *      synthetic IdP fixture) and run policy_eval against it.
 *
 * What it doesn't show:
 *   - Actual QUIC server lifecycle.  Phase 4 RPC layer is where
 *     the auth pipeline gets wired into channel-bytes-blocking.
 *     For v1, this demo proves the policy + audit pieces are
 *     working with manifest-driven configuration.
 *
 * Usage:
 *   quic_oidc_demo /tmp/demo-manifest.json
 *
 * The manifest must declare exactly one IdP and one policy, both
 * referenced by the demo flow.  See docs/quic/auth.md for the
 * full schema.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/manifest.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"
#include "crypto/dpop.h"
#include "net/quic/auth_policy.h"
#include "net/quic/audit.h"

#include "../../test/fixtures/synthetic_idp.h"

/* Build an n00b_quic_auth_policy_t from a manifest entry. */
static n00b_quic_auth_policy_t *
realize_policy(const n00b_quic_manifest_policy_t *mp)
{
    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    if (!n00b_quic_mfbuf_empty(mp->audience)) {
        n00b_quic_auth_policy_require_audience(p, mp->audience->data);
    }
    if (!n00b_quic_mfbuf_empty(mp->issuer_override)) {
        n00b_quic_auth_policy_require_issuer(p, mp->issuer_override->data);
    }
    if (mp->require_dpop) n00b_quic_auth_policy_require_dpop(p);
    if (mp->require_mtls) n00b_quic_auth_policy_require_mtls(p);
    size_t claim_n = mp->required_claims
                     ? (size_t)n00b_list_len(*mp->required_claims) : 0;
    for (size_t i = 0; i < claim_n; i++) {
        n00b_quic_manifest_required_claim_t *rc =
            n00b_list_get(*mp->required_claims, i);
        if (rc->op == N00B_QUIC_MANIFEST_CLAIM_CONTAINS) {
            n00b_quic_auth_policy_require_claim_contains(p,
                rc->name->data, rc->value->data);
        } else {
            n00b_quic_auth_policy_require_claim(p,
                rc->name->data, rc->value->data);
        }
    }
    return p;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    if (argc < 2) {
        fprintf(stderr, "usage: quic_oidc_demo <manifest.json>\n");
        return 2;
    }

    /* 1. Load + preflight the manifest. */
    auto mr = n00b_quic_manifest_load_path(argv[1]);
    if (!n00b_result_is_ok(mr)) {
        fprintf(stderr, "Failed to load manifest: err=%d\n",
                n00b_result_get_err(mr));
        return 1;
    }
    n00b_quic_manifest_t *m = n00b_result_get(mr);
    size_t idp_count = m->auth_idps
                       ? (size_t)n00b_list_len(*m->auth_idps) : 0;
    size_t pol_count = m->auth_policies
                       ? (size_t)n00b_list_len(*m->auth_policies) : 0;
    printf("Loaded manifest: %zu IdP(s), %zu policy/-ies\n",
           idp_count, pol_count);

    auto pr = n00b_quic_preflight(m);
    n00b_quic_preflight_report_t *rep = n00b_result_get(pr);
    if (!rep->ok) {
        fprintf(stderr, "Preflight FAILED:\n");
        for (size_t i = 0; i < n00b_list_len(*rep->findings); i++) {
            const char *sev = "INFO";
            if (n00b_list_get(*rep->findings, i)->severity == N00B_QUIC_PREFLIGHT_WARN) sev = "WARN";
            if (n00b_list_get(*rep->findings, i)->severity == N00B_QUIC_PREFLIGHT_ERROR) sev = "ERROR";
            fprintf(stderr, "  [%s] %s: %s\n",
                    sev, n00b_list_get(*rep->findings, i)->check->data,
                    n00b_list_get(*rep->findings, i)->detail
                        ? n00b_list_get(*rep->findings, i)->detail->data : "");
        }
        return 1;
    }
    printf("Preflight: ok (%zu finding(s))\n", n00b_list_len(*rep->findings));

    if (idp_count == 0 || pol_count == 0) {
        fprintf(stderr, "Demo expects at least one idp + one policy.\n");
        return 1;
    }

    /* 2. Audit sink. */
    auto sr = n00b_quic_audit_jsonl_sink_open("/tmp/quic_oidc_demo.jsonl");
    if (!n00b_result_is_ok(sr)) {
        fprintf(stderr, "Cannot open audit sink: err=%d\n",
                n00b_result_get_err(sr));
        return 1;
    }
    printf("Audit sink: /tmp/quic_oidc_demo.jsonl\n");

    /* 3. Stand up a synthetic IdP that "is" the manifest's first IdP.
     *    In a real deployment this would be a remote IdP we discover
     *    via n00b_oidc_open(issuer); for the demo, we use the
     *    in-process synthetic to keep the example self-contained. */
    n00b_quic_manifest_idp_t *idp = n00b_list_get(*m->auth_idps, 0);
    n00b_synthetic_idp_t *sidp =
        n00b_synthetic_idp_new(idp->issuer->data, idp->id->data);
    n00b_oidc_t *oidc = n00b_synthetic_idp_oidc(sidp);

    /* 4. Realize the policy. */
    n00b_quic_manifest_policy_t *mp = n00b_list_get(*m->auth_policies, 0);
    n00b_quic_auth_policy_t *pol = realize_policy(mp);

    /* 5. Build a verifier wired to this OIDC handle. */
    auto vr = n00b_oidc_jwt_verifier(oidc, mp->audience ? mp->audience->data
                                                        : nullptr);
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    /* 6. Mint a token that (we hope) satisfies the policy. */
    char *token = n00b_synthetic_idp_mint(sidp, "alice",
                                          !n00b_quic_mfbuf_empty(mp->audience)
                                              ? mp->audience->data : "demo",
                                          3600,
                                          .scope = "rpc:read rpc:write",
                                          .role  = "admin");

    /* 7. Optional DPoP if the policy requires it. */
    char *dpop = nullptr;
    if (mp->require_dpop) {
        auto dpr = n00b_dpop_create(n00b_synthetic_idp_signer(sidp),
                                    "POST", "https://demo/api");
        dpop = n00b_result_get(dpr);
    }

    n00b_quic_auth_credentials_t creds = {
        .bearer_token = token,
        .jwt_verifier = v,
        .dpop_header  = dpop,
        .htm          = "POST",
        .htu          = "https://demo/api",
    };
    auto er = n00b_quic_auth_policy_eval(pol, &creds);
    if (n00b_result_is_ok(er)) {
        n00b_jwt_claims_t *claims = n00b_result_get(er);
        printf("policy '%s': ALLOW (sub=%s)\n",
               (const char *)mp->id->data,
               claims && claims->sub ? claims->sub : "?");
    } else {
        printf("policy '%s': DENY (reason=%s)\n",
               (const char *)mp->id->data,
               n00b_quic_err_str(n00b_result_get_err(er)));
    }

    /* 8. Deny-path demonstration: mint a token with the WRONG audience
     *    and re-eval.  Useful to confirm the audit log captures both
     *    allow and deny events. */
    char *bad_token = n00b_synthetic_idp_mint(sidp, "alice",
                                              "wrong-audience",
                                              3600,
                                              .scope = "rpc:read rpc:write");
    n00b_quic_auth_credentials_t bad_creds = {
        .bearer_token = bad_token,
        .jwt_verifier = v,
        .dpop_header  = dpop,
        .htm          = "POST",
        .htu          = "https://demo/api",
    };
    auto bad_er = n00b_quic_auth_policy_eval(pol, &bad_creds);
    if (n00b_result_is_err(bad_er)) {
        printf("policy '%s' (wrong-audience token): DENY (reason=%s)\n",
               (const char *)mp->id->data,
               n00b_quic_err_str(n00b_result_get_err(bad_er)));
    }

    printf("Audit events appended to /tmp/quic_oidc_demo.jsonl\n");

    n00b_quic_audit_jsonl_sink_close(n00b_result_get(sr));
    n00b_quic_auth_policy_close(pol);
    n00b_synthetic_idp_close(sidp);
    n00b_quic_manifest_close(m);

    n00b_shutdown();
    return 0;
}

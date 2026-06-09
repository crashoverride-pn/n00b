/*
 * auth_policy.c — Phase 3 § 10: per-channel auth policy.
 *
 * The policy itself is a small immutable-after-construction
 * descriptor.  Evaluation runs the bundle through:
 *   1. JWT verify (issuer/audience implicit via verifier).
 *   2. require_claim checks against the verified claims.
 *   3. require_dpop: DPoP verify with htm/htu/replay.
 *   4. require_mtls: thumbprint compare via mtls_token_verify.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "net/quic/jwt.h"
#include "net/quic/dpop.h"
#include "net/quic/mtls_token.h"
#include "net/quic/auth_policy.h"
#include "net/quic/audit.h"
#include "internal/net/quic/chan_internal.h"

#include <time.h>

/* ===========================================================================
 * Allocator
 * =========================================================================== */

static n00b_allocator_t *
ap_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
ap_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t n = strlen(s);
    char *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                           &(n00b_alloc_opts_t){
                                               .allocator = ap_alloc(),
                                               .no_scan   = true,
                                           });
    memcpy(out, s, n + 1);
    return out;
}

/* ===========================================================================
 * Policy struct
 * =========================================================================== */

#define MAX_REQUIRED_CLAIMS 16

typedef enum {
    CLAIM_OP_EQUALS   = 0,
    CLAIM_OP_CONTAINS = 1,  /* space-delimited token membership */
} claim_op_t;

typedef struct {
    char       *name;
    char       *value;
    claim_op_t  op;
} required_claim_t;

struct n00b_quic_auth_policy {
    char            *audience;
    char            *issuer;
    required_claim_t claims[MAX_REQUIRED_CLAIMS];
    int32_t          n_claims;
    bool             require_dpop;
    bool             require_mtls;
    n00b_quic_auth_renewal_fn renewal_fn;
    void                     *renewal_ctx;
};

n00b_quic_auth_policy_t *
n00b_quic_auth_policy_new()
{
    n00b_quic_auth_policy_t *p = n00b_alloc_with_opts(n00b_quic_auth_policy_t,
        &(n00b_alloc_opts_t){.allocator = ap_alloc()});
    /* Zero-initialized via the conduit pool. */
    return p;
}

void
n00b_quic_auth_policy_close(n00b_quic_auth_policy_t *p)
{
    /* Conduit-pool: no explicit free.  Just zero the fields so a
     * subsequent eval against this struct degrades gracefully. */
    if (!p) return;
    memset(p, 0, sizeof(*p));
}

void
n00b_quic_auth_policy_require_audience(n00b_quic_auth_policy_t *p,
                                       const char              *audience)
{
    if (p) p->audience = ap_strdup(audience);
}

void
n00b_quic_auth_policy_require_issuer(n00b_quic_auth_policy_t *p,
                                     const char              *issuer)
{
    if (p) p->issuer = ap_strdup(issuer);
}

void
n00b_quic_auth_policy_require_claim(n00b_quic_auth_policy_t *p,
                                    const char              *name,
                                    const char              *value)
{
    if (!p || !name || !value) return;
    if (p->n_claims >= MAX_REQUIRED_CLAIMS) return;
    p->claims[p->n_claims].name  = ap_strdup(name);
    p->claims[p->n_claims].value = ap_strdup(value);
    p->claims[p->n_claims].op    = CLAIM_OP_EQUALS;
    p->n_claims++;
}

void
n00b_quic_auth_policy_require_claim_contains(n00b_quic_auth_policy_t *p,
                                             const char              *name,
                                             const char              *needle)
{
    if (!p || !name || !needle) return;
    if (p->n_claims >= MAX_REQUIRED_CLAIMS) return;
    p->claims[p->n_claims].name  = ap_strdup(name);
    p->claims[p->n_claims].value = ap_strdup(needle);
    p->claims[p->n_claims].op    = CLAIM_OP_CONTAINS;
    p->n_claims++;
}

/* Token-in-haystack check (space-delimited list).  Returns true iff
 * `needle` appears as a complete token in `haystack`. */
static bool
contains_token(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !*needle) return false;
    size_t nlen = strlen(needle);
    const char *p = haystack;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ') p++;
        size_t tlen = (size_t)(p - start);
        if (tlen == nlen && memcmp(start, needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

void
n00b_quic_auth_policy_require_dpop(n00b_quic_auth_policy_t *p)
{
    if (p) p->require_dpop = true;
}

void
n00b_quic_auth_policy_require_mtls(n00b_quic_auth_policy_t *p)
{
    if (p) p->require_mtls = true;
}

void
n00b_quic_auth_policy_set_renewal_hook(n00b_quic_auth_policy_t   *p,
                                       n00b_quic_auth_renewal_fn  fn,
                                       void                      *ctx)
{
    if (p) {
        p->renewal_fn  = fn;
        p->renewal_ctx = ctx;
    }
}

/* ===========================================================================
 * Eval helpers
 * =========================================================================== */

/* Walk the raw payload JSON in claims to find a top-level claim by
 * name.  Returns the string value (borrowed; null if absent or
 * non-string). */
static const char *
claims_get_top_string(n00b_jwt_claims_t *claims, const char *name)
{
    if (!claims || !claims->raw_payload_json) return nullptr;
    const char       *err = nullptr;
    n00b_json_node_t *root = n00b_json_parse(claims->raw_payload_json,
                                             strlen(claims->raw_payload_json),
                                             &err);
    if (!root || !n00b_json_is_object(root)) return nullptr;
    n00b_json_node_t *node = n00b_json_object_get_cstr(root, name);
    return n00b_json_as_cstr(node);
}

/* ===========================================================================
 * Eval
 * =========================================================================== */

/* Inner eval: returns the policy outcome.  The public wrapper
 * adds audit-event emission at the single exit point. */
static n00b_result_t(n00b_jwt_claims_t *)
eval_inner(n00b_quic_auth_policy_t            *p,
           const n00b_quic_auth_credentials_t *creds,
           n00b_jwt_claims_t                 **out_claims)
{
    *out_claims = nullptr;
    if (!p) {
        return n00b_result_ok(n00b_jwt_claims_t *, nullptr);
    }
    if (!creds) {
        return n00b_result_err(n00b_jwt_claims_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    bool need_token = (p->audience || p->issuer || p->n_claims > 0
                       || p->require_dpop || p->require_mtls);

    if (need_token && !creds->bearer_token) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_MISSING);
    }

    n00b_jwt_claims_t *claims = nullptr;
    if (creds->bearer_token) {
        if (!creds->jwt_verifier) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   N00B_QUIC_ERR_NULL_ARG);
        }
        auto cr = n00b_jwt_verify(creds->jwt_verifier, creds->bearer_token);
        if (!n00b_result_is_ok(cr)) {
            return cr;
        }
        claims        = n00b_result_get(cr);
        *out_claims   = claims;

        if (p->audience) {
            if (!claims->aud || strcmp(claims->aud, p->audience) != 0) {
                return n00b_result_err(n00b_jwt_claims_t *,
                                       N00B_QUIC_ERR_AUTH_AUD_MISMATCH);
            }
        }
        if (p->issuer) {
            if (!claims->iss || strcmp(claims->iss, p->issuer) != 0) {
                return n00b_result_err(n00b_jwt_claims_t *,
                                       N00B_QUIC_ERR_AUTH_ISS_MISMATCH);
            }
        }

        for (int32_t i = 0; i < p->n_claims; i++) {
            const char *got = claims_get_top_string(claims,
                                                    p->claims[i].name);
            if (!got) {
                return n00b_result_err(n00b_jwt_claims_t *,
                                       N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
            }
            bool matched = (p->claims[i].op == CLAIM_OP_CONTAINS)
                ? contains_token(got, p->claims[i].value)
                : (strcmp(got, p->claims[i].value) == 0);
            if (!matched) {
                return n00b_result_err(n00b_jwt_claims_t *,
                                       N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
            }
        }
    }

    if (p->require_dpop) {
        if (!creds->dpop_header || !creds->htm || !creds->htu) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
        auto dr = n00b_dpop_verify(creds->dpop_header,
                                   creds->htm, creds->htu,
                                   .replay = creds->dpop_replay);
        if (!n00b_result_is_ok(dr)) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   n00b_result_get_err(dr));
        }
    }

    if (p->require_mtls) {
        if (!claims || !creds->peer_cert_der) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   N00B_QUIC_ERR_AUTH_MTLS_MISMATCH);
        }
        auto mr = n00b_mtls_token_verify(claims,
                                         creds->peer_cert_der,
                                         creds->peer_cert_len);
        if (!n00b_result_is_ok(mr)) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   n00b_result_get_err(mr));
        }
    }

    return n00b_result_ok(n00b_jwt_claims_t *, claims);
}

n00b_result_t(n00b_jwt_claims_t *)
n00b_quic_auth_policy_eval(n00b_quic_auth_policy_t            *p,
                           const n00b_quic_auth_credentials_t *creds)
{
    n00b_jwt_claims_t *claims = nullptr;
    auto r = eval_inner(p, creds, &claims);

    /* Empty-policy fast path: no event.  The audit log is for
     * actual auth-policy decisions; an empty policy isn't one. */
    if (!p) return r;

    n00b_quic_audit_event_t evt = {
        .timestamp_ms = n00b_us_timestamp() / 1000,
        .decision     = n00b_result_is_ok(r)
                            ? N00B_QUIC_AUDIT_ALLOW
                            : N00B_QUIC_AUDIT_DENY,
        .reason_code  = n00b_result_is_ok(r)
                            ? N00B_QUIC_OK
                            : (n00b_quic_err_t)n00b_result_get_err(r),
    };
    /* Attach what we know.  Claims may be partial (set on
     * mid-eval failures after JWT verify succeeded). */
    if (claims) {
        evt.iss = claims->iss;
        evt.sub = claims->sub;
        evt.aud = claims->aud;
        evt.jti = claims->jti;
    }
    if (creds) {
        if (creds->htm) evt.htm = creds->htm;
        if (creds->htu) evt.htu = creds->htu;
    }
    n00b_quic_audit_emit(&evt);
    return r;
}

/* ===========================================================================
 * Channel binding
 *
 * Stored as an opaque pointer field on the channel.  We avoid
 * adding a typed field to `n00b_quic_chan_t` so the channel ABI
 * stays stable; instead we use a parallel mapping on the channel
 * struct via a single void* slot we'll add now.
 * =========================================================================== */

void
n00b_quic_chan_set_policy(n00b_quic_chan_t        *chan,
                          n00b_quic_auth_policy_t *policy)
{
    if (chan) chan->auth_policy = policy;
}

n00b_quic_auth_policy_t *
n00b_quic_chan_get_policy(n00b_quic_chan_t *chan)
{
    return chan ? chan->auth_policy : nullptr;
}

/*
 * oidc.c — OpenID Connect discovery + JWKS cache.
 *
 * Phase 3 § 7.  See header for behavior.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
#include "net/quic/oidc.h"
#include "net/http/http_client.h"

/* ===========================================================================
 * Allocator + helpers
 * =========================================================================== */

static n00b_allocator_t *
oidc_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
oidc_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t n = strlen(s);
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = oidc_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, s, n + 1);
    return out;
}

static int64_t
now_ms(void)
{
    return (int64_t)(n00b_us_timestamp() / 1000);
}

/* Strip trailing '/' from issuer so URL joins are predictable. */
static char *
normalize_issuer(const char *issuer)
{
    if (!issuer) return nullptr;
    size_t n = strlen(issuer);
    while (n > 0 && issuer[n - 1] == '/') n--;
    char *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                           &(n00b_alloc_opts_t){
                                               .allocator = oidc_alloc(),
                                               .no_scan   = true,
                                           });
    memcpy(out, issuer, n);
    out[n] = '\0';
    return out;
}

/* ===========================================================================
 * OIDC handle layout
 * =========================================================================== */

struct n00b_oidc {
    char           *issuer;            /* normalized */
    char           *jwks_uri;          /* discovered or null (synthetic mode) */
    n00b_jwk_set_t *cached_jwks;       /* current set; refreshed in place */
    int64_t         fetched_at_ms;
    int32_t         cache_ttl_seconds;
    int32_t         timeout_ms;
    n00b_rwlock_t *mu;
    bool            closed;
};

/* ===========================================================================
 * HTTPS helpers
 * =========================================================================== */

/* Returns the response body as a heap-allocated NUL-terminated string,
 * or nullptr.  status_out receives the HTTP status code (0 on
 * transport failure). */
static char *
https_get_text(const char *url, int32_t timeout_ms, int *status_out)
{
    if (status_out) *status_out = 0;
    auto r = n00b_http_request_sync(
        n00b_string_from_cstr((char *)url),
        .timeout_ms = timeout_ms,
        .prefer_h3  = false);
    if (!n00b_result_is_ok(r)) return nullptr;
    n00b_http_response_t *resp = n00b_result_get(r);
    int status = n00b_http_response_status(resp);
    if (status_out) *status_out = status;
    if (status < 200 || status >= 300) return nullptr;
    n00b_buffer_t *body = n00b_http_response_body(resp);
    if (!body || body->byte_len == 0) return nullptr;

    size_t n = (size_t)body->byte_len;
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = oidc_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, body->data, n);
    out[n] = '\0';
    return out;
}

/* ===========================================================================
 * Discovery
 * =========================================================================== */

/* Read jwks_uri from the openid-configuration JSON body.  Also
 * enforces RFC 8414 § 3.3: the doc's `issuer` claim MUST byte-equal
 * the issuer URL we used to fetch it.  Returns nullptr on issuer
 * mismatch (or missing jwks_uri / parse failure). */
static char *
extract_jwks_uri(const char *config_json, const char *expected_issuer)
{
    const char *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(config_json,
                                             strlen(config_json), &err);
    if (!root || !n00b_json_is_object(root)) return nullptr;

    /* Issuer cross-check.  Mitigates the case where a man-in-the-middle
     * (within the trust boundary) substitutes a discovery document
     * pointing at a different issuer's JWKS — token validation would
     * then succeed against tokens from that other issuer, even though
     * the caller asked us to verify tokens for `expected_issuer`. */
    n00b_json_node_t *iss_node = n00b_json_object_get_cstr(root, "issuer");
    const char       *issuer   = n00b_json_as_cstr(iss_node);
    if (!issuer) {
        return nullptr;
    }
    if (expected_issuer && strcmp(issuer, expected_issuer) != 0) {
        return nullptr;
    }

    n00b_json_node_t *node = n00b_json_object_get_cstr(root, "jwks_uri");
    const char       *uri  = n00b_json_as_cstr(node);
    if (!uri) return nullptr;
    return oidc_strdup(uri);
}

/* Synchronously fetch the openid-configuration + JWKS, populate
 * @p o->jwks_uri + @p o->cached_jwks.  Caller holds the lock. */
static int
discover_and_fetch_jwks(n00b_oidc_t *o)
{
    /* /.well-known/openid-configuration */
    size_t cfg_url_len = strlen(o->issuer)
                       + sizeof("/.well-known/openid-configuration");
    char  *cfg_url     = n00b_alloc_array_with_opts(char,
        (int64_t)cfg_url_len,
        &(n00b_alloc_opts_t){.allocator = oidc_alloc(), .no_scan = true});
    snprintf(cfg_url, cfg_url_len, "%s/.well-known/openid-configuration",
             o->issuer);

    int   status   = 0;
    char *cfg_json = https_get_text(cfg_url, o->timeout_ms, &status);
    if (!cfg_json) return -1;

    char *jwks_uri = extract_jwks_uri(cfg_json, o->issuer);
    if (!jwks_uri) return -1;
    o->jwks_uri = jwks_uri;

    /* JWKS GET */
    char *jwks_json = https_get_text(jwks_uri, o->timeout_ms, &status);
    if (!jwks_json) return -1;

    auto sr = n00b_jwk_set_parse(jwks_json);
    if (!n00b_result_is_ok(sr)) return -1;
    o->cached_jwks   = n00b_result_get(sr);
    o->fetched_at_ms = now_ms();
    return 0;
}

/* Refresh just the JWKS (jwks_uri already known).  Caller holds the
 * lock. */
static int
refresh_jwks(n00b_oidc_t *o)
{
    if (!o->jwks_uri) return -1;
    int   status    = 0;
    char *jwks_json = https_get_text(o->jwks_uri, o->timeout_ms, &status);
    if (!jwks_json) return -1;
    auto sr = n00b_jwk_set_parse(jwks_json);
    if (!n00b_result_is_ok(sr)) return -1;
    o->cached_jwks   = n00b_result_get(sr);
    o->fetched_at_ms = now_ms();
    return 0;
}

/* ===========================================================================
 * Public API
 * =========================================================================== */

n00b_result_t(n00b_oidc_t *)
n00b_oidc_open(const char *issuer) _kargs
{
    int32_t cache_ttl_seconds = 3600;
    int32_t timeout_ms        = 30000;
}
{
    if (!issuer || !*issuer) {
        return n00b_result_err(n00b_oidc_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    /* Issuer must be HTTPS — RFC 8414 § 2 / RFC 7519 § 4.1.1. */
    if (strncmp(issuer, "https://", 8) != 0) {
        return n00b_result_err(n00b_oidc_t *, N00B_QUIC_ERR_INVALID_ARG);
    }

    n00b_oidc_t *o = n00b_alloc_with_opts(n00b_oidc_t,
        &(n00b_alloc_opts_t){.allocator = oidc_alloc()});
    o->issuer            = normalize_issuer(issuer);
    o->cache_ttl_seconds = cache_ttl_seconds;
    o->timeout_ms        = timeout_ms;
    o->mu = n00b_data_lock_new(); 

    if (discover_and_fetch_jwks(o) != 0) {
        return n00b_result_err(n00b_oidc_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    return n00b_result_ok(n00b_oidc_t *, o);
}

n00b_result_t(n00b_oidc_t *)
n00b_oidc_open_with_jwks(const char *issuer, const char *jwks_json) _kargs
{
    int32_t cache_ttl_seconds = 3600;
}
{
    if (!jwks_json) {
        return n00b_result_err(n00b_oidc_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    auto sr = n00b_jwk_set_parse(jwks_json);
    if (!n00b_result_is_ok(sr)) {
        return n00b_result_err(n00b_oidc_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_oidc_t *o = n00b_alloc_with_opts(n00b_oidc_t,
        &(n00b_alloc_opts_t){.allocator = oidc_alloc()});
    o->issuer            = issuer ? normalize_issuer(issuer) : nullptr;
    o->jwks_uri          = nullptr;  /* synthetic: no refresh path */
    o->cached_jwks       = n00b_result_get(sr);
    o->fetched_at_ms     = now_ms();
    o->cache_ttl_seconds = cache_ttl_seconds;
    o->timeout_ms        = 0;
    o->mu = n00b_data_lock_new(); 
    return n00b_result_ok(n00b_oidc_t *, o);
}

n00b_jwk_t *
n00b_oidc_get_key(n00b_oidc_t *o, const char *kid)
{
    if (!o || o->closed) return nullptr;
    n00b_data_write_lock(o->mu);

    /* Stale-cache refresh.  Bypassed for synthetic-mode handles
     * (jwks_uri == nullptr). */
    if (o->jwks_uri) {
        int64_t age_ms = now_ms() - o->fetched_at_ms;
        if (age_ms > (int64_t)o->cache_ttl_seconds * 1000) {
            (void)refresh_jwks(o);  /* best-effort; keep old on failure */
        }
    }

    n00b_option_t(n00b_jwk_t *) k_opt = n00b_jwk_set_lookup(o->cached_jwks, kid);
    if (!n00b_option_is_set(k_opt) && o->jwks_uri) {
        /* Miss-then-refresh: RFC 7517 § 4.5 expects this. */
        if (refresh_jwks(o) == 0) {
            k_opt = n00b_jwk_set_lookup(o->cached_jwks, kid);
        }
    }
    n00b_data_unlock(o->mu);
    /* The caller's contract is the n00b_jwt_resolve_key_fn callback
     * typedef (kept as bare-pointer-return per §5.4 callback-contract
     * carve-out); map option_t back to nullable. */
    return n00b_option_is_set(k_opt) ? n00b_option_get(k_opt) : nullptr;
}

void
n00b_oidc_close(n00b_oidc_t *o)
{
    if (!o || o->closed) return;
    n00b_data_write_lock(o->mu);
    o->cached_jwks = nullptr;
    o->jwks_uri    = nullptr;
    o->closed      = true;
    n00b_data_unlock(o->mu);
}

/* ===========================================================================
 * Verifier convenience
 * =========================================================================== */

static n00b_jwk_t *
oidc_resolve_key(void *ctx, const char *kid, const char *alg)
{
    (void)alg;
    return n00b_oidc_get_key((n00b_oidc_t *)ctx, kid);
}

n00b_result_t(n00b_jwt_verifier_t *)
n00b_oidc_jwt_verifier(n00b_oidc_t *o,
                       const char  *expected_audience) _kargs
{
    const char *expected_issuer = nullptr;
    int32_t     leeway_seconds  = 60;
}
{
    if (!o || !expected_audience) {
        return n00b_result_err(n00b_jwt_verifier_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    const char *iss = expected_issuer ? expected_issuer : o->issuer;
    return n00b_jwt_verifier_new(.expected_audience = expected_audience,
                                 .expected_issuer   = iss,
                                 .leeway_seconds    = leeway_seconds,
                                 .resolve_key       = oidc_resolve_key,
                                 .resolve_key_ctx   = o);
}

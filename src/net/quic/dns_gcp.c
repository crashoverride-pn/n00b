/*
 * dns_gcp.c — GCP Cloud DNS provider via the metadata server.
 *
 * Auth model: GCE / GKE / Cloud Run / etc. expose a metadata
 * server at `http://metadata.google.internal/computeMetadata/v1/`
 * (or 169.254.169.254).  Each VM has an associated service
 * account; the metadata server hands out short-lived OAuth2 access
 * tokens for that account on request.  We never see the long-lived
 * RSA private key — it lives in the GCP control plane.  This is
 * the design-doc intent (`~/dd/quic_2.md` § 5.4) and dodges the
 * "we have no RSA-2048 sign" issue that vanilla service-account
 * JSON auth would otherwise require.
 *
 * Operations:
 *   set_txt(fqdn, value):
 *     POST /dns/v1/projects/{p}/managedZones/{z}/changes
 *       { "additions": [{name, type:"TXT", ttl:60, rrdatas:["...."]}] }
 *
 *   remove_txt(fqdn, value):
 *     POST /dns/v1/projects/{p}/managedZones/{z}/changes
 *       { "deletions": [{...}] }
 *
 * **Limitation**: this provider only works when running on a
 * machine with metadata-server access (any GCP-managed compute).
 * Local-dev operators should use the manual provider, or wait
 * for the service-account-JSON path that lands once we have
 * RSA-2048 support (Phase 3).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "adt/dict_untyped.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "net/quic/dns_provider.h"
#include "net/http/http_client.h"
#include "internal/net/http/http_h1.h"

typedef struct {
    char    *project_id;
    char    *managed_zone;
    /* Cached access token + expiry (Unix-epoch seconds). */
    char    *cached_token;
    int64_t  token_expires_at;
} gcp_state_t;

static n00b_allocator_t *
gcp_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
gcp_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t l = strlen(s);
    char  *o = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                          &(n00b_alloc_opts_t){
                                              .allocator = gcp_alloc(),
                                              .no_scan   = true,
                                          });
    memcpy(o, s, l + 1);
    return o;
}

static int64_t
now_s(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec;
}

/* ===========================================================================
 * Metadata-server token fetch
 *
 * URL: http://metadata.google.internal/computeMetadata/v1/
 *      instance/service-accounts/default/token
 * Header: Metadata-Flavor: Google
 * Response JSON: {"access_token": "...", "expires_in": 3599,
 *                 "token_type": "Bearer"}
 *
 * Note: the URL is HTTP (not HTTPS); the metadata server is on a
 * link-local address that's only reachable from within GCP and
 * isn't routable externally.  Our HTTPS shim only does HTTPS,
 * so we'd normally need an HTTP path.  Workaround: most GCP
 * environments allow metadata via HTTPS too, OR run a sidecar
 * proxy.  For Phase 2 v1 we document the limitation.
 *
 * **Phase 2 v1 simplification**: the operator passes a token
 * directly via env var (`N00B_GCP_ACCESS_TOKEN`); the provider
 * just uses it.  The metadata-server fetch is documented as a
 * Phase 2 follow-up — ships once we add HTTP (non-TLS) to the
 * shim.
 * =========================================================================== */

static int
gcp_get_token(gcp_state_t *st, const char **out_token)
{
    /* Use cached token if not expired. */
    if (st->cached_token && now_s() < st->token_expires_at - 30) {
        *out_token = st->cached_token;
        return N00B_QUIC_OK;
    }

    const char *env = getenv("N00B_GCP_ACCESS_TOKEN");
    if (env && env[0]) {
        st->cached_token     = gcp_strdup(env);
        st->token_expires_at = now_s() + 3600;
        *out_token           = st->cached_token;
        return N00B_QUIC_OK;
    }

    /* TODO: fall through to metadata-server fetch when the HTTP
     * shim ships.  Until then, no token = no GCP DNS calls. */
    return N00B_QUIC_ERR_NOT_IMPLEMENTED;
}

/* Build "Authorization: Bearer ..." + content-type headers. */
static n00b_http_h1_headers_t *
gcp_auth_headers(const char *token)
{
    n00b_http_h1_headers_t *h = n00b_http_h1_headers_new();
    char buf[2048];
    snprintf(buf, sizeof(buf), "Bearer %s", token);
    n00b_http_h1_headers_set(h, "Authorization", buf);
    n00b_http_h1_headers_set(h, "Content-Type", "application/json");
    return h;
}

/* ===========================================================================
 * Cloud DNS changes API
 *
 * Body shape:
 *   { "additions": [...], "deletions": [...] }
 *
 * Each entry:
 *   { "name": "<fqdn.>", "type": "TXT", "ttl": 60, "rrdatas": ["\"<value>\""] }
 *
 * GCP requires the trailing dot on names + escaped double-quotes
 * around the rdata value.
 * =========================================================================== */

static int
gcp_changes(gcp_state_t *st,
            const char  *operation,    /* "additions" or "deletions" */
            const char  *fqdn,
            const char  *value)
{
    const char *token = nullptr;
    int rc = gcp_get_token(st, &token);
    if (rc != N00B_QUIC_OK) return rc;

    /* Body — fqdn gets a trailing dot if missing; rdata is
     * double-quoted. */
    char fqdn_dotted[512];
    snprintf(fqdn_dotted, sizeof(fqdn_dotted),
             "%s%s", fqdn, fqdn[strlen(fqdn) - 1] == '.' ? "" : ".");

    char body_str[2048];
    int  n = snprintf(body_str, sizeof(body_str),
                      "{\"%s\":[{"
                      "\"name\":\"%s\","
                      "\"type\":\"TXT\","
                      "\"ttl\":60,"
                      "\"rrdatas\":[\"\\\"%s\\\"\"]"
                      "}]}",
                      operation, fqdn_dotted, value);
    if (n < 0 || n >= (int)sizeof(body_str)) {
        return N00B_QUIC_ERR_FRAME_TOO_LARGE;
    }

    char url[1024];
    snprintf(url, sizeof(url),
             "https://dns.googleapis.com/dns/v1/projects/%s/managedZones/%s/changes",
             st->project_id, st->managed_zone);

    n00b_buffer_t *body = n00b_buffer_from_bytes(body_str, n);
    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(url),
        .method       = r"POST",
        .body         = body,
        .extra        = gcp_auth_headers(token),
        .content_type = r"application/json",
        .prefer_h3    = false);
    if (!n00b_result_is_ok(r)) {
        return (int)n00b_result_get_err(r);
    }
    n00b_http_response_t *resp = n00b_result_get(r);
    /* Cloud DNS returns 200 + a Change resource on success.  A 4xx
     * with `error.code` indicates a problem (zone not found, name
     * outside the zone, etc.).  We surface non-2xx as PROTOCOL. */
    int status = n00b_http_response_status(resp);
    if (status < 200 || status >= 300) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    return N00B_QUIC_OK;
}

static int
gcp_set_txt(n00b_quic_dns_provider_t *self,
            const char *fqdn, const char *value)
{
    return gcp_changes(self->ctx, "additions", fqdn, value);
}

static int
gcp_remove_txt(n00b_quic_dns_provider_t *self,
               const char *fqdn, const char *value)
{
    /* Cloud DNS DELETE-by-rdata semantics need an exact rdata
     * match.  When called without a value (orchestrator's
     * deprovision), we can't construct the full deletion entry;
     * surface as a no-op. */
    if (!value || value[0] == '\0') {
        return N00B_QUIC_OK;
    }
    return gcp_changes(self->ctx, "deletions", fqdn, value);
}

static void
gcp_close(n00b_quic_dns_provider_t *self)
{
    if (!self || !self->ctx) return;
    gcp_state_t *st = self->ctx;
    if (st->cached_token) {
        memset(st->cached_token, 0, strlen(st->cached_token));
    }
    self->ctx = nullptr;
}

n00b_result_t(n00b_quic_dns_provider_t *)
n00b_quic_dns_provider_gcp(n00b_quic_dns_gcp_config_t config)
{
    return n00b_quic_dns_provider_gcp_raw(config.project_id,
                                         config.managed_zone);
}

n00b_result_t(n00b_quic_dns_provider_t *)
n00b_quic_dns_provider_gcp_raw(const char *project_id,
                               const char *managed_zone)
{
    if (!project_id || !managed_zone ||
        project_id[0] == '\0' || managed_zone[0] == '\0') {
        return n00b_result_err(n00b_quic_dns_provider_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    gcp_state_t *st = n00b_alloc_with_opts(gcp_state_t,
        &(n00b_alloc_opts_t){.allocator = gcp_alloc()});
    st->project_id       = gcp_strdup(project_id);
    st->managed_zone     = gcp_strdup(managed_zone);
    st->cached_token     = nullptr;
    st->token_expires_at = 0;

    n00b_quic_dns_provider_t *p = n00b_alloc_with_opts(
        n00b_quic_dns_provider_t,
        &(n00b_alloc_opts_t){.allocator = gcp_alloc()});
    p->name       = "gcp";
    p->set_txt    = gcp_set_txt;
    p->remove_txt = gcp_remove_txt;
    p->close      = gcp_close;
    p->ctx        = st;
    return n00b_result_ok(n00b_quic_dns_provider_t *, p);
}

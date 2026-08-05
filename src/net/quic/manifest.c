/*
 * manifest.c — Manifest JSON loader.
 *
 * Driven by the n00b JSON parser.  Schema enforcement is
 * "as-strict-as-it-needs-to-be": required fields are checked,
 * unknown fields are tolerated (forward-compat for additive Phase 2
 * follow-ups).
 */

#define N00B_USE_INTERNAL_API
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/file.h"
#include "adt/result.h"
#include "adt/list.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "net/quic/manifest.h"

/* ===========================================================================
 * Allocator + small helpers
 * =========================================================================== */

static n00b_allocator_t *
mf_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

/* Wrap a NUL-terminated C string into a manifest-pool n00b_buffer_t.
 * Excludes the trailing NUL from byte_len; data field is contiguous
 * with a NUL byte at byte_len so consumers can also pass `->data`
 * to libc string APIs unchanged. */
static n00b_buffer_t *
mf_buf_from_cstr(const char *s)
{
    if (!s) return nullptr;
    size_t l = strlen(s);
    n00b_buffer_t *b = n00b_buffer_empty(.allocator = mf_alloc());
    n00b_buffer_resize(b, l + 1);
    memcpy(b->data, s, l + 1);  /* includes the NUL */
    n00b_buffer_resize(b, l);   /* byte_len excludes the NUL terminator */
    return b;
}

static n00b_json_node_t *
json_obj_get(n00b_json_node_t *obj, const char *key)
{
    return n00b_json_object_get_cstr(obj, key);
}

static n00b_buffer_t *
json_obj_get_buf(n00b_json_node_t *obj, const char *key)
{
    n00b_json_node_t *v = json_obj_get(obj, key);
    if (!v || !n00b_json_is_string(v)) return nullptr;
    return mf_buf_from_cstr(n00b_json_as_cstr(v));
}

static int
json_obj_get_int(n00b_json_node_t *obj, const char *key, int64_t *out)
{
    n00b_json_node_t *v = json_obj_get(obj, key);
    if (!v || !n00b_json_is_int(v)) return -1;
    *out = n00b_json_as_i64(v);
    return 0;
}

/* Convert a JSON array of strings into an n00b_list_t of buffers.
 * Returns -1 if the node isn't an array of strings. */
static int
json_string_array(n00b_json_node_t                  *arr,
                  n00b_list_t(n00b_buffer_t *)     **out)
{
    if (!arr || !n00b_json_is_array(arr)) return -1;
    *out = n00b_alloc_with_opts(
        n00b_list_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = mf_alloc()});
    **out = n00b_list_new(n00b_buffer_t *, .allocator = mf_alloc());
    size_t n = n00b_json_array_len(arr);
    for (size_t i = 0; i < n; i++) {
        n00b_json_node_t *e = n00b_json_array_get(arr, i);
        if (!e || !n00b_json_is_string(e)) {
            return -1;
        }
        n00b_list_push(**out, mf_buf_from_cstr(n00b_json_as_cstr(e)));
    }
    return 0;
}

/* ===========================================================================
 * Cert parser
 * =========================================================================== */

static int
parse_cert(n00b_json_node_t           *cert_obj,
           n00b_quic_manifest_cert_t  *out)
{
    if (!cert_obj || !n00b_json_is_object(cert_obj)) return -1;

    n00b_buffer_t *kind = json_obj_get_buf(cert_obj, "kind");
    if (!kind) return -1;
    const char *k = kind->data;

    if (strcmp(k, "static") == 0) {
        out->kind = N00B_QUIC_MANIFEST_CERT_STATIC;
    } else if (strcmp(k, "external") == 0) {
        out->kind = N00B_QUIC_MANIFEST_CERT_EXTERNAL;
    } else if (strcmp(k, "acme") == 0) {
        out->kind = N00B_QUIC_MANIFEST_CERT_ACME;
    } else {
        return -1;
    }

    if (out->kind == N00B_QUIC_MANIFEST_CERT_STATIC ||
        out->kind == N00B_QUIC_MANIFEST_CERT_EXTERNAL) {
        out->chain_pem_path = json_obj_get_buf(cert_obj, "chain_pem_path");
        out->key_secret_uri = json_obj_get_buf(cert_obj, "key_secret_uri");
        if (!out->chain_pem_path || !out->key_secret_uri) {
            return -1;
        }
    }
    if (out->kind == N00B_QUIC_MANIFEST_CERT_EXTERNAL) {
        n00b_json_node_t *argv = json_obj_get(cert_obj, "argv");
        if (json_string_array(argv, &out->argv) != 0
            || n00b_list_len(*out->argv) == 0) {
            return -1;
        }
    }
    if (out->kind == N00B_QUIC_MANIFEST_CERT_ACME) {
        out->directory_url   = json_obj_get_buf(cert_obj, "directory_url");
        out->challenge       = json_obj_get_buf(cert_obj, "challenge");
        out->account_key_uri = json_obj_get_buf(cert_obj, "account_key_uri");
        out->contact_email   = json_obj_get_buf(cert_obj, "contact_email");
        n00b_json_node_t *names = json_obj_get(cert_obj, "subject_names");
        if (json_string_array(names, &out->subject_names) != 0
            || n00b_list_len(*out->subject_names) == 0) {
            return -1;
        }
        if (!out->directory_url || !out->challenge ||
            !out->account_key_uri) {
            return -1;
        }
    }
    return 0;
}

/* ===========================================================================
 * Endpoint + top-level
 * =========================================================================== */

static int
parse_endpoint(n00b_json_node_t              *ep_obj,
               n00b_quic_manifest_endpoint_t *out)
{
    if (!ep_obj || !n00b_json_is_object(ep_obj)) return -1;

    out->id        = json_obj_get_buf(ep_obj, "id");
    out->bind_host = json_obj_get_buf(ep_obj, "bind_host");
    if (!out->id || !out->bind_host) return -1;

    int64_t port = 0;
    if (json_obj_get_int(ep_obj, "bind_port", &port) != 0
        || port < 0 || port > 65535) {
        return -1;
    }
    out->bind_port = (uint16_t)port;

    n00b_json_node_t *alpns = json_obj_get(ep_obj, "alpn");
    if (json_string_array(alpns, &out->alpns) != 0
        || n00b_list_len(*out->alpns) == 0) {
        return -1;
    }

    n00b_json_node_t *cert = json_obj_get(ep_obj, "cert");
    if (parse_cert(cert, &out->cert) != 0) {
        return -1;
    }
    return 0;
}

/* ===========================================================================
 * Phase 3 § 11 — auth section parser
 * =========================================================================== */

static int
parse_idp(n00b_json_node_t *idp_obj, n00b_quic_manifest_idp_t *out)
{
    if (!idp_obj || !n00b_json_is_object(idp_obj)) return -1;
    out->id     = json_obj_get_buf(idp_obj, "id");
    out->issuer = json_obj_get_buf(idp_obj, "issuer");
    if (!out->id || !out->issuer) return -1;
    int64_t ttl = 0;
    if (json_obj_get_int(idp_obj, "jwks_cache_ttl_seconds", &ttl) == 0
        && ttl >= 0 && ttl <= INT32_MAX) {
        out->jwks_cache_ttl_seconds = (int32_t)ttl;
    } else {
        out->jwks_cache_ttl_seconds = 0;  /* library default */
    }
    return 0;
}

static int
parse_required_claims(n00b_json_node_t                                       *arr,
                      n00b_list_t(n00b_quic_manifest_required_claim_t *)     **out)
{
    *out = nullptr;
    if (!arr) return 0;  /* absent is fine */
    if (!n00b_json_is_array(arr)) return -1;
    size_t n = n00b_json_array_len(arr);
    if (n == 0) return 0;

    *out = n00b_alloc_with_opts(
        n00b_list_t(n00b_quic_manifest_required_claim_t *),
        &(n00b_alloc_opts_t){.allocator = mf_alloc()});
    **out = n00b_list_new(n00b_quic_manifest_required_claim_t *,
                          .allocator = mf_alloc());

    for (size_t i = 0; i < n; i++) {
        n00b_json_node_t *e = n00b_json_array_get(arr, i);
        if (!e || !n00b_json_is_object(e)) return -1;
        n00b_quic_manifest_required_claim_t *c = n00b_alloc_with_opts(
            n00b_quic_manifest_required_claim_t,
            &(n00b_alloc_opts_t){.allocator = mf_alloc()});
        c->name = json_obj_get_buf(e, "name");
        if (!c->name) return -1;
        n00b_buffer_t *eq = json_obj_get_buf(e, "equals");
        n00b_buffer_t *cn = json_obj_get_buf(e, "contains");
        if (cn) {
            c->value = cn;
            c->op    = N00B_QUIC_MANIFEST_CLAIM_CONTAINS;
        } else if (eq) {
            c->value = eq;
            c->op    = N00B_QUIC_MANIFEST_CLAIM_EQUALS;
        } else {
            return -1;  /* must specify one */
        }
        n00b_list_push(**out, c);
    }
    return 0;
}

static int
parse_policy(n00b_json_node_t *p_obj, n00b_quic_manifest_policy_t *out)
{
    if (!p_obj || !n00b_json_is_object(p_obj)) return -1;
    out->id              = json_obj_get_buf(p_obj, "id");
    out->idp             = json_obj_get_buf(p_obj, "idp");
    out->audience        = json_obj_get_buf(p_obj, "audience");
    out->issuer_override = json_obj_get_buf(p_obj, "issuer");
    if (!out->id || !out->idp) return -1;

    n00b_json_node_t *dpop = json_obj_get(p_obj, "require_dpop");
    if (dpop && n00b_json_is_bool(dpop)) {
        out->require_dpop = n00b_json_as_bool(dpop);
    }
    n00b_json_node_t *mtls = json_obj_get(p_obj, "require_mtls");
    if (mtls && n00b_json_is_bool(mtls)) {
        out->require_mtls = n00b_json_as_bool(mtls);
    }

    n00b_json_node_t *claims = json_obj_get(p_obj, "require_claim");
    if (parse_required_claims(claims, &out->required_claims) != 0) {
        return -1;
    }
    return 0;
}

static int
parse_auth_section(n00b_json_node_t *root, n00b_quic_manifest_t *m)
{
    n00b_json_node_t *auth = json_obj_get(root, "auth");
    if (!auth) return 0;  /* absent — empty manifest auth */
    if (!n00b_json_is_object(auth)) return -1;

    n00b_json_node_t *idps = json_obj_get(auth, "idps");
    if (idps && n00b_json_is_array(idps)) {
        size_t n = n00b_json_array_len(idps);
        m->auth_idps = n00b_alloc_with_opts(
            n00b_list_t(n00b_quic_manifest_idp_t *),
            &(n00b_alloc_opts_t){.allocator = mf_alloc()});
        *m->auth_idps =
            n00b_list_new(n00b_quic_manifest_idp_t *,
                          .allocator = mf_alloc());
        for (size_t i = 0; i < n; i++) {
            n00b_quic_manifest_idp_t *idp = n00b_alloc_with_opts(
                n00b_quic_manifest_idp_t,
                &(n00b_alloc_opts_t){.allocator = mf_alloc()});
            n00b_json_node_t *node = n00b_json_array_get(idps, i);
            if (parse_idp(node, idp) != 0) return -1;
            n00b_list_push(*m->auth_idps, idp);
        }
    }

    n00b_json_node_t *pols = json_obj_get(auth, "policies");
    if (pols && n00b_json_is_array(pols)) {
        size_t n = n00b_json_array_len(pols);
        m->auth_policies = n00b_alloc_with_opts(
            n00b_list_t(n00b_quic_manifest_policy_t *),
            &(n00b_alloc_opts_t){.allocator = mf_alloc()});
        *m->auth_policies =
            n00b_list_new(n00b_quic_manifest_policy_t *,
                          .allocator = mf_alloc());
        for (size_t i = 0; i < n; i++) {
            n00b_quic_manifest_policy_t *pol = n00b_alloc_with_opts(
                n00b_quic_manifest_policy_t,
                &(n00b_alloc_opts_t){.allocator = mf_alloc()});
            n00b_json_node_t *node = n00b_json_array_get(pols, i);
            if (parse_policy(node, pol) != 0) return -1;
            n00b_list_push(*m->auth_policies, pol);
        }
    }
    return 0;
}

/* ===========================================================================
 * Phase 4 § 4.11 — rpc.services section parser
 * =========================================================================== */

static int
parse_rpc_service(n00b_json_node_t                 *s_obj,
                  n00b_quic_manifest_rpc_service_t *out)
{
    if (!s_obj || !n00b_json_is_object(s_obj)) return -1;
    out->id          = json_obj_get_buf(s_obj, "id");
    out->auth_policy = json_obj_get_buf(s_obj, "auth_policy");
    if (!out->id || !out->auth_policy) return -1;
    return 0;
}

static int
parse_rpc_section(n00b_json_node_t *root, n00b_quic_manifest_t *m)
{
    n00b_json_node_t *rpc = json_obj_get(root, "rpc");
    if (!rpc) return 0;
    if (!n00b_json_is_object(rpc)) return -1;

    n00b_json_node_t *services = json_obj_get(rpc, "services");
    if (!services) return 0;
    if (!n00b_json_is_array(services)) return -1;

    size_t n = n00b_json_array_len(services);
    if (n == 0) return 0;

    m->rpc_services = n00b_alloc_with_opts(
        n00b_list_t(n00b_quic_manifest_rpc_service_t *),
        &(n00b_alloc_opts_t){.allocator = mf_alloc()});
    *m->rpc_services =
        n00b_list_new(n00b_quic_manifest_rpc_service_t *,
                      .allocator = mf_alloc());
    for (size_t i = 0; i < n; i++) {
        n00b_quic_manifest_rpc_service_t *s = n00b_alloc_with_opts(
            n00b_quic_manifest_rpc_service_t,
            &(n00b_alloc_opts_t){.allocator = mf_alloc()});
        n00b_json_node_t *node = n00b_json_array_get(services, i);
        if (parse_rpc_service(node, s) != 0) return -1;
        n00b_list_push(*m->rpc_services, s);
    }
    return 0;
}

/* ===========================================================================
 * Phase 5 § 5.2 — observability section parser
 * =========================================================================== */

static int
parse_observability_section(n00b_json_node_t *root, n00b_quic_manifest_t *m)
{
    n00b_json_node_t *obs = json_obj_get(root, "observability");
    if (!obs) return 0;
    if (!n00b_json_is_object(obs)) return -1;

    n00b_json_node_t *metrics_obj = json_obj_get(obs, "metrics");
    if (!metrics_obj) return 0;
    if (!n00b_json_is_object(metrics_obj)) return -1;

    n00b_quic_manifest_metrics_t *mm = n00b_alloc_with_opts(
        n00b_quic_manifest_metrics_t,
        &(n00b_alloc_opts_t){.allocator = mf_alloc()});
    mm->bind_host = json_obj_get_buf(metrics_obj, "bind_host");
    int64_t port = 9100;
    if (json_obj_get_int(metrics_obj, "bind_port", &port) == 0) {
        if (port < 0 || port > 65535) return -1;
    }
    mm->bind_port = (uint16_t)port;
    m->metrics = mm;
    return 0;
}

n00b_result_t(n00b_quic_manifest_t *)
n00b_quic_manifest_load_json(n00b_buffer_t *body)
{
    if (!body || body->byte_len == 0) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             (size_t)body->byte_len, &err);
    if (!root || !n00b_json_is_object(root)) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }

    int64_t version = 0;
    if (json_obj_get_int(root, "version", &version) != 0 || version != 1) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }

    n00b_buffer_t *service_name = json_obj_get_buf(root, "service_name");
    if (!service_name) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }

    n00b_json_node_t *eps = json_obj_get(root, "endpoints");
    if (!eps || !n00b_json_is_array(eps)) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }
    size_t ep_count = n00b_json_array_len(eps);
    if (ep_count == 0) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }

    n00b_quic_manifest_t *m = n00b_alloc_with_opts(n00b_quic_manifest_t,
        &(n00b_alloc_opts_t){.allocator = mf_alloc()});
    m->version        = (int)version;
    m->service_name   = service_name;
    m->endpoints      = n00b_alloc_with_opts(
        n00b_list_t(n00b_quic_manifest_endpoint_t *),
        &(n00b_alloc_opts_t){.allocator = mf_alloc()});
    *m->endpoints =
        n00b_list_new(n00b_quic_manifest_endpoint_t *,
                      .allocator = mf_alloc());

    for (size_t i = 0; i < ep_count; i++) {
        n00b_quic_manifest_endpoint_t *ep = n00b_alloc_with_opts(
            n00b_quic_manifest_endpoint_t,
            &(n00b_alloc_opts_t){.allocator = mf_alloc()});
        n00b_json_node_t *ep_node = n00b_json_array_get(eps, i);
        if (parse_endpoint(ep_node, ep) != 0) {
            return n00b_result_err(n00b_quic_manifest_t *,
                                   N00B_QUIC_ERR_PROTOCOL);
        }
        n00b_list_push(*m->endpoints, ep);
    }

    /* Phase 3 § 11: optional auth section. */
    if (parse_auth_section(root, m) != 0) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }
    /* Phase 4 § 4.11: optional rpc section. */
    if (parse_rpc_section(root, m) != 0) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }
    /* Phase 5 § 5.2: optional observability section. */
    if (parse_observability_section(root, m) != 0) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }
    return n00b_result_ok(n00b_quic_manifest_t *, m);
}

n00b_result_t(n00b_quic_manifest_t *)
n00b_quic_manifest_load_path(const char *path)
{
    if (!path) {
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    n00b_string_t *p  = n00b_string_from_cstr(path);
    auto           fr = n00b_file_open(p, .mode = N00B_FILE_R);
    if (n00b_result_is_err(fr)) {
        /* Preserve prior contract: bad path / unreadable file →
         * INVALID_ARG so callers distinguish "bad path" from "bad JSON". */
        return n00b_result_err(n00b_quic_manifest_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_file_t *f = n00b_result_get(fr);

    n00b_buffer_t *acc = n00b_buffer_new(0);
    while (!n00b_file_at_eof(f)) {
        auto rr = n00b_file_read(f, 65536);
        if (n00b_result_is_err(rr)) {
            n00b_file_close(f);
            return n00b_result_err(n00b_quic_manifest_t *,
                                   N00B_QUIC_ERR_INVALID_ARG);
        }
        n00b_buffer_t *chunk = n00b_result_get(rr);
        if (!chunk || chunk->byte_len == 0) break;
        n00b_buffer_concat(acc, chunk);
    }
    n00b_file_close(f);

    return n00b_quic_manifest_load_json(acc);
}

void
n00b_quic_manifest_close(n00b_quic_manifest_t *m)
{
    /* All conduit-pool-allocated; nothing to free explicitly. */
    (void)m;
}

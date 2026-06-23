/*
 * acme.c — ACME (RFC 8555) client state machine.
 *
 * Phase 2.3a: directory + newNonce + newAccount.
 *
 * Layout:
 *   §1   Allocator + small JSON helpers
 *   §2   Session struct + nonce management
 *   §3   Directory parse + session_open
 *   §4   newAccount
 *   §5   Public accessors
 *
 * The per-request HTTPS bytes go through the acme_http shim; signing
 * goes through the secret + jws modules.  This file is purely
 * protocol-level glue.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "adt/list.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/acme.h"
#include "net/http/http_client.h"
#include "internal/net/http/http_h1.h"
#include "internal/crypto/jws.h"

/* ===========================================================================
 * §1   Allocator + small JSON helpers
 * =========================================================================== */

static n00b_allocator_t *
acme_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
acme_strdup_c(const char *s)
{
    if (!s) {
        return nullptr;
    }
    size_t len = strlen(s);
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(len + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = acme_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

/* Look up a child node by key.  Returns NULL if absent. */
static n00b_json_node_t *
json_obj_get(n00b_json_node_t *obj, const char *key)
{
    return n00b_json_object_get_cstr(obj, key);
}

/* Returns a heap-allocated copy of obj[key] if it's a string; NULL otherwise. */
static char *
json_obj_get_string(n00b_json_node_t *obj, const char *key)
{
    n00b_json_node_t *v = json_obj_get(obj, key);
    if (!v || !n00b_json_is_string(v)) {
        return nullptr;
    }
    return acme_strdup_c(n00b_json_as_cstr(v));
}

/* ===========================================================================
 * §2   Session struct + nonce management
 *
 * The session owns:
 *   - directory: parsed once at session open
 *   - nonce:     refreshed on every response that carries Replay-Nonce
 *   - account_key: borrowed; caller-owned
 *   - account:   nullable until n00b_acme_new_account succeeds
 *
 * RFC 8555 § 6.5 — every response from ACME carries Replay-Nonce.
 * We update the cached nonce whenever we see one; the next request
 * uses it in its protected header.  If we somehow run out (the cache
 * is cleared after use) we fall back to HEAD <newNonce>.
 * =========================================================================== */

struct n00b_acme_session {
    n00b_acme_directory_t  directory;
    n00b_acme_account_t   *account;       /* nullable */
    n00b_quic_secret_t    *account_key;   /* borrowed */
    char                  *nonce;         /* most recent Replay-Nonce */
    int32_t                timeout_ms;
    bool                   closed;
};

/* Refresh @p s->nonce from a response's Replay-Nonce header. */
static void
session_capture_nonce(n00b_acme_session_t       *s,
                      n00b_http_response_t *resp)
{
    const char *v = n00b_http_response_header_cstr(resp, "Replay-Nonce");
    if (v) {
        s->nonce = acme_strdup_c(v);
    }
}

/* Ensure s->nonce is non-empty.  Issue a HEAD newNonce if needed. */
static int
session_ensure_nonce(n00b_acme_session_t *s)
{
    if (s->nonce && *s->nonce) {
        return N00B_QUIC_OK;
    }
    /* RFC 8555 § 7.2 says HEAD; the directory also accepts GET on
     * newNonce and returns the nonce in the Replay-Nonce header.  We
     * use GET because our HTTPS shim doesn't expose HEAD; the body is
     * empty so the wire cost is minimal.  Servers that reject GET on
     * newNonce produce an error the caller can see. */
    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(s->directory.new_nonce),
        .timeout_ms = s->timeout_ms,
        .prefer_h3  = false);
    if (!n00b_result_is_ok(r)) {
        return (int)n00b_result_get_err(r);
    }
    n00b_http_response_t *resp = n00b_result_get(r);
    int status = n00b_http_response_status(resp);
    if (status < 200 || status >= 300) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    session_capture_nonce(s, resp);
    return s->nonce && *s->nonce ? N00B_QUIC_OK : N00B_QUIC_ERR_PROTOCOL;
}

/* Take and clear the cached nonce. */
static char *
session_take_nonce(n00b_acme_session_t *s)
{
    char *n  = s->nonce;
    s->nonce = nullptr;
    return n;
}

/* ===========================================================================
 * §3   Directory parse + session_open
 *
 * The ACME directory looks like:
 *   {
 *     "newNonce":    "...",
 *     "newAccount":  "...",
 *     "newOrder":    "...",
 *     "revokeCert":  "...",
 *     "keyChange":   "...",
 *     "meta": { "termsOfService": "...", ... }
 *   }
 *
 * We only require newNonce + newAccount + newOrder to be present.
 * =========================================================================== */

static int
parse_directory(n00b_buffer_t         *body,
                n00b_acme_directory_t *out)
{
    if (!body || body->byte_len == 0) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    const char *err = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             (size_t)body->byte_len, &err);
    if (!root || !n00b_json_is_object(root)) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    out->new_nonce   = json_obj_get_string(root, "newNonce");
    out->new_account = json_obj_get_string(root, "newAccount");
    out->new_order   = json_obj_get_string(root, "newOrder");
    out->revoke_cert = json_obj_get_string(root, "revokeCert");
    out->key_change  = json_obj_get_string(root, "keyChange");

    n00b_json_node_t *meta = json_obj_get(root, "meta");
    if (meta) {
        out->terms_of_service = json_obj_get_string(meta, "termsOfService");
    }

    if (!out->new_nonce || !out->new_account || !out->new_order) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    return N00B_QUIC_OK;
}

n00b_result_t(n00b_acme_session_t *)
n00b_acme_session_open(const char         *directory_url,
                       n00b_quic_secret_t *account_key) _kargs
{
    int32_t timeout_ms = 30000;
}
{
    if (!directory_url || !account_key) {
        return n00b_result_err(n00b_acme_session_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    n00b_acme_session_t *s = n00b_alloc_with_opts(n00b_acme_session_t,
        &(n00b_alloc_opts_t){.allocator = acme_alloc()});
    s->timeout_ms = timeout_ms;
    s->account_key = account_key;

    /* GET <directory>. */
    auto dr = n00b_http_request_sync(
        n00b_string_from_cstr((char *)directory_url),
        .timeout_ms = timeout_ms,
        .prefer_h3  = false);
    if (!n00b_result_is_ok(dr)) {
        return n00b_result_err(n00b_acme_session_t *,
                               (int)n00b_result_get_err(dr));
    }
    n00b_http_response_t *resp = n00b_result_get(dr);
    if (n00b_http_response_status(resp) != 200) {
        return n00b_result_err(n00b_acme_session_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    int rc = parse_directory(n00b_http_response_body(resp), &s->directory);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_session_t *, rc);
    }

    /* HEAD-equivalent newNonce GET to seed the cache. */
    rc = session_ensure_nonce(s);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_session_t *, rc);
    }

    return n00b_result_ok(n00b_acme_session_t *, s);
}

void
n00b_acme_session_close(n00b_acme_session_t *s)
{
    if (!s || s->closed) {
        return;
    }
    /* All strings are conduit-pool-allocated; nothing to free
     * explicitly.  Just drop the pointers. */
    s->account_key = nullptr;
    s->account     = nullptr;
    s->nonce       = nullptr;
    s->closed      = true;
}

/* ===========================================================================
 * §4   newAccount
 *
 * Per RFC 8555 § 7.3, newAccount is signed in jwk-form (the ACME
 * server has never seen the key before).  Successful registration
 * returns 201 Created with `Location: <account URL>`.  An existing
 * account key returns 200 OK with the same Location.
 * =========================================================================== */

/* Build the newAccount payload JSON.  Returned string lives in the
 * conduit pool; caller doesn't free. */
static char *
build_new_account_payload(const char  *const *contact,
                          size_t              contact_count,
                          bool                terms_agreed)
{
    /* Worst-case-bound size estimate. */
    size_t cap = 64;
    for (size_t i = 0; i < contact_count; i++) {
        cap += strlen(contact[i]) + 8;
    }
    char *out = n00b_alloc_array_with_opts(char, (int64_t)cap,
                                           &(n00b_alloc_opts_t){
                                               .allocator = acme_alloc(),
                                               .no_scan   = true,
                                           });
    int n = 0;
    n += snprintf(out + n, cap - n, "{");
    if (terms_agreed) {
        n += snprintf(out + n, cap - n, "\"termsOfServiceAgreed\":true");
    }
    if (contact_count > 0) {
        if (n > 1) {
            n += snprintf(out + n, cap - n, ",");
        }
        n += snprintf(out + n, cap - n, "\"contact\":[");
        for (size_t i = 0; i < contact_count; i++) {
            n += snprintf(out + n, cap - n, "%s\"%s\"",
                          i == 0 ? "" : ",", contact[i]);
        }
        n += snprintf(out + n, cap - n, "]");
    }
    n += snprintf(out + n, cap - n, "}");
    return out;
}

n00b_result_t(n00b_acme_account_t *)
n00b_acme_new_account(n00b_acme_session_t *s) _kargs
{
    const char **contact       = nullptr;
    size_t       contact_count = 0;
    bool         terms_agreed  = true;
}
{
    if (!s || s->closed) {
        return n00b_result_err(n00b_acme_account_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    int rc = session_ensure_nonce(s);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_account_t *, rc);
    }

    char *payload = build_new_account_payload(contact, contact_count,
                                              terms_agreed);
    char *nonce   = session_take_nonce(s);

    auto jr = n00b_jws_build(s->account_key, nonce,
                             s->directory.new_account,
                             (const uint8_t *)payload, strlen(payload),
                             .embed_jwk = true);
    if (!n00b_result_is_ok(jr)) {
        return n00b_result_err(n00b_acme_account_t *,
                               (int)n00b_result_get_err(jr));
    }
    n00b_buffer_t *body = n00b_result_get(jr);

    auto rr = n00b_http_request_sync(
        n00b_string_from_cstr(s->directory.new_account),
        .method       = r"POST",
        .body         = body,
        .content_type = r"application/jose+json",
        .timeout_ms   = s->timeout_ms,
        .prefer_h3    = false);
    if (!n00b_result_is_ok(rr)) {
        return n00b_result_err(n00b_acme_account_t *,
                               (int)n00b_result_get_err(rr));
    }
    n00b_http_response_t *resp = n00b_result_get(rr);

    /* Capture the new nonce regardless of status — the server always
     * sends one, even on errors. */
    session_capture_nonce(s, resp);

    int rstatus = n00b_http_response_status(resp);
    if (rstatus != 201 && rstatus != 200) {
        return n00b_result_err(n00b_acme_account_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    n00b_acme_account_t *acct = n00b_alloc_with_opts(n00b_acme_account_t,
        &(n00b_alloc_opts_t){.allocator = acme_alloc()});

    const char *loc = n00b_http_response_header_cstr(resp, "Location");
    if (!loc) {
        return n00b_result_err(n00b_acme_account_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    acct->url = acme_strdup_c(loc);

    /* Pull status out of the response body if it parses; otherwise
     * default to "valid" (a successful 201/200 means the server
     * accepted the registration). */
    n00b_buffer_t *rbody = n00b_http_response_body(resp);
    if (rbody && rbody->byte_len > 0) {
        const char *err = nullptr;
        n00b_json_node_t *root = n00b_json_parse(rbody->data,
                                                 (size_t)rbody->byte_len,
                                                 &err);
        if (root && n00b_json_is_object(root)) {
            acct->status = json_obj_get_string(root, "status");
        }
    }
    if (!acct->status) {
        acct->status = acme_strdup_c("valid");
    }

    s->account = acct;
    return n00b_result_ok(n00b_acme_account_t *, acct);
}

/* ===========================================================================
 * §5   Authenticated POST helper (kid-form)
 *
 * Used by everything after newAccount.  Handles nonce management,
 * JWS construction, the POST round-trip, and the new-nonce capture
 * on the response.  Pass `payload == nullptr` for POST-as-GET (RFC
 * 8555 § 6.3).
 * =========================================================================== */

/*
 * Detect the ACME `badNonce` error on a 4xx response.  RFC 8555
 * § 6.5: "If the server rejects a request because its nonce value
 * was unacceptable... the client SHOULD retry the request after
 * getting a new nonce."  The error type field is
 * `urn:ietf:params:acme:error:badNonce` inside an
 * `application/problem+json` body.
 *
 * The response always includes a fresh Replay-Nonce header, which
 * `session_capture_nonce` has already saved on the session by the
 * time this is called — so retry just needs to re-sign with the
 * cached fresh nonce.
 */
static bool
is_bad_nonce(n00b_http_response_t *resp)
{
    int status = n00b_http_response_status(resp);
    if (!resp || status < 400 || status >= 500) {
        return false;
    }
    n00b_buffer_t *body = n00b_http_response_body(resp);
    if (!body || body->byte_len == 0) {
        return false;
    }
    const char *err = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             (size_t)body->byte_len,
                                             &err);
    if (!root || !n00b_json_is_object(root)) {
        return false;
    }
    n00b_json_node_t *type = json_obj_get(root, "type");
    const char *type_s = n00b_json_as_cstr(type);
    if (!type_s) {
        return false;
    }
    return strcmp(type_s, "urn:ietf:params:acme:error:badNonce") == 0;
}

static int
acme_authenticated_post(n00b_acme_session_t        *s,
                        const char                 *url,
                        const char                 *payload,
                        n00b_http_response_t **resp_out)
{
    if (!s || s->closed) {
        return N00B_QUIC_ERR_NULL_ARG;
    }
    if (!s->account || !s->account->url) {
        /* Authenticated calls require a registered account. */
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    /* One retry on badNonce per RFC 8555 § 6.5.  The server always
     * includes a fresh Replay-Nonce on its error responses; we
     * capture it then re-sign and re-send. */
    for (int attempt = 0; attempt < 2; attempt++) {
        int rc = session_ensure_nonce(s);
        if (rc != N00B_QUIC_OK) {
            return rc;
        }
        char *nonce = session_take_nonce(s);

        const uint8_t *p_bytes = (const uint8_t *)(payload ? payload : "");
        size_t         p_len   = payload ? strlen(payload) : 0;

        auto jr = n00b_jws_build(s->account_key, nonce, url,
                                 p_bytes, p_len,
                                 .kid = s->account->url);
        if (!n00b_result_is_ok(jr)) {
            return (int)n00b_result_get_err(jr);
        }
        n00b_buffer_t *body = n00b_result_get(jr);

        auto rr = n00b_http_request_sync(
            n00b_string_from_cstr((char *)url),
            .method       = r"POST",
            .body         = body,
            .content_type = r"application/jose+json",
            .timeout_ms   = s->timeout_ms,
            .prefer_h3    = false);
        if (!n00b_result_is_ok(rr)) {
            return (int)n00b_result_get_err(rr);
        }
        n00b_http_response_t *resp = n00b_result_get(rr);
        session_capture_nonce(s, resp);

        if (attempt == 0 && is_bad_nonce(resp)) {
            /* Retry once with the fresh nonce. */
            continue;
        }

        *resp_out = resp;
        return N00B_QUIC_OK;
    }
    /* Unreachable — the loop returns on every iteration. */
    return N00B_QUIC_ERR_PROTOCOL;
}

/* ===========================================================================
 * §6   newOrder
 * =========================================================================== */

static char *
build_new_order_payload(const char *const *dns_names, size_t count)
{
    /* Identifiers JSON, sized loosely. */
    size_t cap = 64;
    for (size_t i = 0; i < count; i++) {
        cap += strlen(dns_names[i]) + 32;
    }
    char *out = n00b_alloc_array_with_opts(char, (int64_t)cap,
                                           &(n00b_alloc_opts_t){
                                               .allocator = acme_alloc(),
                                               .no_scan   = true,
                                           });
    int n = 0;
    n += snprintf(out + n, cap - n, "{\"identifiers\":[");
    for (size_t i = 0; i < count; i++) {
        n += snprintf(out + n, cap - n,
                      "%s{\"type\":\"dns\",\"value\":\"%s\"}",
                      i == 0 ? "" : ",", dns_names[i]);
    }
    n += snprintf(out + n, cap - n, "]}");
    return out;
}

/* Parse an ACME Order response body into a typed struct. */
static int
parse_order(n00b_buffer_t      *body,
            const char         *order_url,
            n00b_acme_order_t **out_order)
{
    if (!body || body->byte_len == 0) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             (size_t)body->byte_len, &err);
    if (!root || !n00b_json_is_object(root)) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    n00b_acme_order_t *o = n00b_alloc_with_opts(n00b_acme_order_t,
        &(n00b_alloc_opts_t){.allocator = acme_alloc()});

    o->url         = acme_strdup_c(order_url);
    o->status      = json_obj_get_string(root, "status");
    o->expires     = json_obj_get_string(root, "expires");
    o->finalize    = json_obj_get_string(root, "finalize");
    o->certificate = json_obj_get_string(root, "certificate");

    /* identifiers: array of {type, value} */
    n00b_json_node_t *ids = json_obj_get(root, "identifiers");
    if (ids && n00b_json_is_array(ids)) {
        size_t n = n00b_json_array_len(ids);
        o->identifier_count = n;
        if (n > 0) {
            o->identifiers = n00b_alloc_array_with_opts(
                n00b_acme_identifier_t, (int64_t)n,
                &(n00b_alloc_opts_t){.allocator = acme_alloc()});
            for (size_t i = 0; i < n; i++) {
                n00b_json_node_t *e = n00b_json_array_get(ids, i);
                o->identifiers[i].type  = json_obj_get_string(e, "type");
                o->identifiers[i].value = json_obj_get_string(e, "value");
            }
        }
    }

    /* authorizations: array of strings */
    n00b_json_node_t *auths = json_obj_get(root, "authorizations");
    if (auths && n00b_json_is_array(auths)) {
        size_t n = n00b_json_array_len(auths);
        o->authorization_count = n;
        if (n > 0) {
            o->authorizations = n00b_alloc_array_with_opts(
                char *, (int64_t)n,
                &(n00b_alloc_opts_t){.allocator = acme_alloc()});
            for (size_t i = 0; i < n; i++) {
                n00b_json_node_t *e = n00b_json_array_get(auths, i);
                if (e && n00b_json_is_string(e)) {
                    o->authorizations[i] = acme_strdup_c(n00b_json_as_cstr(e));
                }
            }
        }
    }

    if (!o->status || !o->finalize) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    *out_order = o;
    return N00B_QUIC_OK;
}

n00b_result_t(n00b_acme_order_t *)
n00b_acme_new_order(n00b_acme_session_t *s,
                    const char *const   *dns_names,
                    size_t               count)
{
    if (!s || !dns_names || count == 0) {
        return n00b_result_err(n00b_acme_order_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    char *payload = build_new_order_payload(dns_names, count);

    n00b_http_response_t *resp = nullptr;
    int rc = acme_authenticated_post(s, s->directory.new_order, payload, &resp);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_order_t *, rc);
    }
    int s_status = n00b_http_response_status(resp);
    if (s_status != 201 && s_status != 200) {
        return n00b_result_err(n00b_acme_order_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    const char *loc = n00b_http_response_header_cstr(resp, "Location");
    const char *order_url = loc ? loc : "";

    n00b_acme_order_t *order = nullptr;
    rc = parse_order(n00b_http_response_body(resp), order_url, &order);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_order_t *, rc);
    }
    return n00b_result_ok(n00b_acme_order_t *, order);
}

/* ===========================================================================
 * §7   getAuthz (POST-as-GET)
 * =========================================================================== */

static int
parse_authz(n00b_buffer_t      *body,
            n00b_acme_authz_t **out)
{
    if (!body || body->byte_len == 0) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             (size_t)body->byte_len, &err);
    if (!root || !n00b_json_is_object(root)) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    n00b_acme_authz_t *a = n00b_alloc_with_opts(n00b_acme_authz_t,
        &(n00b_alloc_opts_t){.allocator = acme_alloc()});

    n00b_json_node_t *id = json_obj_get(root, "identifier");
    if (id) {
        a->identifier.type  = json_obj_get_string(id, "type");
        a->identifier.value = json_obj_get_string(id, "value");
    }
    a->status  = json_obj_get_string(root, "status");
    a->expires = json_obj_get_string(root, "expires");

    n00b_json_node_t *wc = json_obj_get(root, "wildcard");
    if (wc && n00b_json_is_bool(wc)) {
        a->wildcard = n00b_json_as_bool(wc);
    }

    n00b_json_node_t *chs = json_obj_get(root, "challenges");
    if (chs && n00b_json_is_array(chs)) {
        size_t n = n00b_json_array_len(chs);
        a->challenge_count = n;
        if (n > 0) {
            a->challenges = n00b_alloc_array_with_opts(
                n00b_acme_challenge_t *, (int64_t)n,
                &(n00b_alloc_opts_t){.allocator = acme_alloc()});
            for (size_t i = 0; i < n; i++) {
                n00b_json_node_t *e = n00b_json_array_get(chs, i);
                n00b_acme_challenge_t *c = n00b_alloc_with_opts(
                    n00b_acme_challenge_t,
                    &(n00b_alloc_opts_t){.allocator = acme_alloc()});
                c->type   = json_obj_get_string(e, "type");
                c->url    = json_obj_get_string(e, "url");
                c->token  = json_obj_get_string(e, "token");
                c->status = json_obj_get_string(e, "status");
                a->challenges[i] = c;
            }
        }
    }

    if (!a->status || !a->identifier.value) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    *out = a;
    return N00B_QUIC_OK;
}

n00b_result_t(n00b_acme_authz_t *)
n00b_acme_get_authz(n00b_acme_session_t *s, const char *authz_url)
{
    if (!s || !authz_url) {
        return n00b_result_err(n00b_acme_authz_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    n00b_http_response_t *resp = nullptr;
    int rc = acme_authenticated_post(s, authz_url, nullptr, &resp);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_authz_t *, rc);
    }
    if (n00b_http_response_status(resp) != 200) {
        return n00b_result_err(n00b_acme_authz_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    n00b_acme_authz_t *authz = nullptr;
    rc = parse_authz(n00b_http_response_body(resp), &authz);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_authz_t *, rc);
    }
    return n00b_result_ok(n00b_acme_authz_t *, authz);
}

/* ===========================================================================
 * §8   HTTP-01 key authorization (RFC 8555 § 8.1)
 *
 *   keyAuthz = token + "." + base64url(SHA-256(canonical-JWK(account-pubkey)))
 * =========================================================================== */

char *
n00b_acme_http01_key_authz(n00b_acme_session_t *s, const char *token)
{
    if (!s || !s->account_key || !token) {
        return nullptr;
    }
    auto pr = n00b_quic_secret_pubkey(s->account_key,
                                      N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(pr)) {
        return nullptr;
    }
    n00b_buffer_t *pub = n00b_result_get(pr);
    if (pub->byte_len != 64) {
        return nullptr;
    }
    uint8_t fp[32];
    n00b_jwk_p256_thumbprint((const uint8_t *)pub->data, fp);

    char *fp_b64 = n00b_b64url_encode(fp, sizeof(fp));

    size_t len   = strlen(token) + 1 + strlen(fp_b64);
    char  *out   = n00b_alloc_array_with_opts(char, (int64_t)(len + 1),
                                              &(n00b_alloc_opts_t){
                                                  .allocator = acme_alloc(),
                                                  .no_scan   = true,
                                              });
    snprintf(out, len + 1, "%s.%s", token, fp_b64);
    return out;
}

/* ===========================================================================
 * §9   Challenge trigger + polling
 *
 * After the caller provisions the HTTP-01 endpoint / DNS TXT record,
 * it POSTs `{}` to the challenge URL.  RFC 8555 § 7.5.1: this is the
 * client telling the server "go ahead and validate."  Server kicks
 * off its outbound validation; status is initially still "pending"
 * (or "processing"), transitions to "valid" or "invalid" later.
 * =========================================================================== */

/* Parse a Challenge object out of a JSON response body. */
static int
parse_challenge_body(n00b_buffer_t          *body,
                     n00b_acme_challenge_t **out)
{
    if (!body || body->byte_len == 0) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             (size_t)body->byte_len, &err);
    if (!root || !n00b_json_is_object(root)) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    n00b_acme_challenge_t *c = n00b_alloc_with_opts(n00b_acme_challenge_t,
        &(n00b_alloc_opts_t){.allocator = acme_alloc()});
    c->type   = json_obj_get_string(root, "type");
    c->url    = json_obj_get_string(root, "url");
    c->token  = json_obj_get_string(root, "token");
    c->status = json_obj_get_string(root, "status");
    if (!c->status || !c->url) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    *out = c;
    return N00B_QUIC_OK;
}

n00b_result_t(n00b_acme_challenge_t *)
n00b_acme_signal_challenge_ready(n00b_acme_session_t   *s,
                                 n00b_acme_challenge_t *challenge)
{
    if (!s || !challenge || !challenge->url) {
        return n00b_result_err(n00b_acme_challenge_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    n00b_http_response_t *resp = nullptr;
    int rc = acme_authenticated_post(s, challenge->url, "{}", &resp);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_challenge_t *, rc);
    }
    if (n00b_http_response_status(resp) != 200) {
        return n00b_result_err(n00b_acme_challenge_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }
    n00b_acme_challenge_t *out = nullptr;
    rc = parse_challenge_body(n00b_http_response_body(resp), &out);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_challenge_t *, rc);
    }
    return n00b_result_ok(n00b_acme_challenge_t *, out);
}

/* Linear backoff: 1 s, 2 s, 4 s, then 5 s thereafter. */
static int
poll_sleep_ms(int attempt)
{
    int ms[] = {1000, 2000, 4000};
    if (attempt < 3) return ms[attempt];
    return 5000;
}

/* Sleep millisecond count without dragging in <time.h> usleep nuance. */
#include <unistd.h>

static void
sleep_ms(int ms)
{
    if (ms <= 0) return;
    usleep((useconds_t)ms * 1000u);
}

n00b_result_t(n00b_acme_authz_t *)
n00b_acme_poll_authz(n00b_acme_session_t *s, const char *authz_url) _kargs
{
    int32_t max_wait_ms = 60000;
}
{
    if (!s || !authz_url) {
        return n00b_result_err(n00b_acme_authz_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    int     attempt  = 0;
    int     waited   = 0;
    n00b_acme_authz_t *latest = nullptr;

    for (;;) {
        auto r = n00b_acme_get_authz(s, authz_url);
        if (!n00b_result_is_ok(r)) {
            return r;
        }
        latest = n00b_result_get(r);
        if (!latest->status) {
            return n00b_result_err(n00b_acme_authz_t *,
                                   N00B_QUIC_ERR_PROTOCOL);
        }
        /* Done states. */
        if (strcmp(latest->status, "pending")    != 0
         && strcmp(latest->status, "processing") != 0) {
            return n00b_result_ok(n00b_acme_authz_t *, latest);
        }
        if (waited >= max_wait_ms) {
            /* Caller can read out latest->status to see we timed out
             * still pending. */
            return n00b_result_ok(n00b_acme_authz_t *, latest);
        }
        int s_ms = poll_sleep_ms(attempt++);
        if (waited + s_ms > max_wait_ms) {
            s_ms = max_wait_ms - waited;
        }
        sleep_ms(s_ms);
        waited += s_ms;
    }
}

n00b_result_t(n00b_acme_order_t *)
n00b_acme_poll_order(n00b_acme_session_t *s, const char *order_url) _kargs
{
    int32_t max_wait_ms = 60000;
}
{
    if (!s || !order_url) {
        return n00b_result_err(n00b_acme_order_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    int attempt = 0;
    int waited  = 0;
    n00b_acme_order_t *latest = nullptr;

    for (;;) {
        n00b_http_response_t *resp = nullptr;
        int rc = acme_authenticated_post(s, order_url, nullptr, &resp);
        if (rc != N00B_QUIC_OK) {
            return n00b_result_err(n00b_acme_order_t *, rc);
        }
        if (n00b_http_response_status(resp) != 200) {
            return n00b_result_err(n00b_acme_order_t *,
                                   N00B_QUIC_ERR_PROTOCOL);
        }
        rc = parse_order(n00b_http_response_body(resp), order_url, &latest);
        if (rc != N00B_QUIC_OK) {
            return n00b_result_err(n00b_acme_order_t *, rc);
        }
        if (strcmp(latest->status, "pending")    != 0
         && strcmp(latest->status, "processing") != 0) {
            return n00b_result_ok(n00b_acme_order_t *, latest);
        }
        if (waited >= max_wait_ms) {
            return n00b_result_ok(n00b_acme_order_t *, latest);
        }
        int s_ms = poll_sleep_ms(attempt++);
        if (waited + s_ms > max_wait_ms) {
            s_ms = max_wait_ms - waited;
        }
        sleep_ms(s_ms);
        waited += s_ms;
    }
}

/* ===========================================================================
 * §10  finalize + get_certificate
 * =========================================================================== */

n00b_result_t(n00b_acme_order_t *)
n00b_acme_finalize(n00b_acme_session_t *s,
                   n00b_acme_order_t   *order,
                   n00b_buffer_t       *csr_der)
{
    if (!s || !order || !order->finalize || !csr_der) {
        return n00b_result_err(n00b_acme_order_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    /* Build {"csr":"<base64url(DER CSR)>"}. */
    char *b64 = n00b_b64url_encode((const uint8_t *)csr_der->data,
                                   (size_t)csr_der->byte_len);
    size_t cap = strlen(b64) + 32;
    char  *payload = n00b_alloc_array_with_opts(char, (int64_t)cap,
                                                &(n00b_alloc_opts_t){
                                                    .allocator = acme_alloc(),
                                                    .no_scan   = true,
                                                });
    snprintf(payload, cap, "{\"csr\":\"%s\"}", b64);

    n00b_http_response_t *resp = nullptr;
    int rc = acme_authenticated_post(s, order->finalize, payload, &resp);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_order_t *, rc);
    }
    int fs = n00b_http_response_status(resp);
    if (fs != 200 && fs != 201) {
        return n00b_result_err(n00b_acme_order_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }
    /* The response body is the updated Order; URL is the same as
     * the finalize call's *order* URL, not the finalize URL itself. */
    n00b_acme_order_t *updated = nullptr;
    rc = parse_order(n00b_http_response_body(resp), order->url, &updated);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_acme_order_t *, rc);
    }
    return n00b_result_ok(n00b_acme_order_t *, updated);
}

n00b_result_t(n00b_buffer_t *)
n00b_acme_get_certificate(n00b_acme_session_t *s,
                          n00b_acme_order_t   *order)
{
    if (!s || !order) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    if (!order->certificate) {
        /* Caller polled too soon. */
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_http_response_t *resp = nullptr;
    int rc = acme_authenticated_post(s, order->certificate, nullptr, &resp);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_buffer_t *, rc);
    }
    if (n00b_http_response_status(resp) != 200) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    /* The body is the PEM cert chain; just return the buffer as-is. */
    return n00b_result_ok(n00b_buffer_t *, n00b_http_response_body(resp));
}

/* ===========================================================================
 * §11  High-level orchestrator
 *
 * Walks RFC 8555 § 7 end-to-end.  Each step is the corresponding
 * verb in this file; the only state we add is the matching of
 * challenges to the provider, the per-authz provision/deprovision
 * pairing, and the post-finalize order-poll loop.
 * =========================================================================== */

#include "internal/crypto/acme_csr.h"

n00b_result_t(n00b_buffer_t *)
n00b_acme_acquire_certificate(const char                     *directory_url,
                              n00b_quic_secret_t             *account_key,
                              n00b_quic_secret_t             *cert_key,
                              const char *const              *dns_names,
                              size_t                          dns_name_count,
                              n00b_acme_challenge_provider_t *provider) _kargs
{
    int32_t timeout_ms       = 30000;
    int32_t poll_max_wait_ms = 60000;
}
{
    if (!directory_url || !account_key || !cert_key || !dns_names
        || dns_name_count == 0 || !provider || !provider->type
        || !provider->provision || !provider->deprovision) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    /* 1. Open session, register account. */
    auto sr = n00b_acme_session_open(directory_url, account_key,
                                     .timeout_ms = timeout_ms);
    if (!n00b_result_is_ok(sr)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(sr));
    }
    n00b_acme_session_t *s = n00b_result_get(sr);

    auto ar = n00b_acme_new_account(s);
    if (!n00b_result_is_ok(ar)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(ar));
    }

    /* 2. Place the order. */
    auto or_ = n00b_acme_new_order(s, dns_names, dns_name_count);
    if (!n00b_result_is_ok(or_)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(or_));
    }
    n00b_acme_order_t *order = n00b_result_get(or_);

    /* 3. For each authorization, fetch it, pick the matching
     *    challenge type, provision, signal ready, poll, deprovision. */
    for (size_t i = 0; i < order->authorization_count; i++) {
        auto azr = n00b_acme_get_authz(s, order->authorizations[i]);
        if (!n00b_result_is_ok(azr)) {
            return n00b_result_err(n00b_buffer_t *,
                                   (int)n00b_result_get_err(azr));
        }
        n00b_acme_authz_t *authz = n00b_result_get(azr);

        /* Already-valid authzs (re-used from a prior order) need no
         * work; ACME servers may return them. */
        if (strcmp(authz->status, "valid") == 0) {
            continue;
        }

        n00b_acme_challenge_t *match = nullptr;
        for (size_t j = 0; j < authz->challenge_count; j++) {
            if (authz->challenges[j] && authz->challenges[j]->type
                && strcmp(authz->challenges[j]->type, provider->type) == 0) {
                match = authz->challenges[j];
                break;
            }
        }
        if (!match) {
            /* The ACME server didn't offer a challenge of the type
             * our configured provider handles (e.g., operator wired
             * a DNS-01 provider but the authz only has HTTP-01).
             * This is a configuration/protocol mismatch, not a
             * missing feature — surface as AUTH_ALG_REFUSED so the
             * caller doesn't confuse it with "the code path isn't
             * written yet." */
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_QUIC_ERR_AUTH_ALG_REFUSED);
        }

        char *key_authz = n00b_acme_http01_key_authz(s, match->token);
        if (!key_authz) {
            return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_PROTOCOL);
        }

        int rc = provider->provision(provider, match,
                                     authz->identifier.value, key_authz);
        if (rc != N00B_QUIC_OK) {
            return n00b_result_err(n00b_buffer_t *, rc);
        }

        auto sgr = n00b_acme_signal_challenge_ready(s, match);
        if (!n00b_result_is_ok(sgr)) {
            (void)provider->deprovision(provider, match,
                                        authz->identifier.value);
            return n00b_result_err(n00b_buffer_t *,
                                   (int)n00b_result_get_err(sgr));
        }

        auto pollr = n00b_acme_poll_authz(s, order->authorizations[i],
                                          .max_wait_ms = poll_max_wait_ms);
        (void)provider->deprovision(provider, match,
                                    authz->identifier.value);
        if (!n00b_result_is_ok(pollr)) {
            return n00b_result_err(n00b_buffer_t *,
                                   (int)n00b_result_get_err(pollr));
        }
        n00b_acme_authz_t *final_authz = n00b_result_get(pollr);
        if (strcmp(final_authz->status, "valid") != 0) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_QUIC_ERR_TRUST_REJECTED);
        }
    }

    /* 4. Build CSR + finalize. */
    auto csrr = n00b_acme_build_csr(cert_key, dns_names, dns_name_count);
    if (!n00b_result_is_ok(csrr)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(csrr));
    }
    n00b_buffer_t *csr_der = n00b_result_get(csrr);

    auto fr = n00b_acme_finalize(s, order, csr_der);
    if (!n00b_result_is_ok(fr)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(fr));
    }
    n00b_acme_order_t *post_finalize = n00b_result_get(fr);

    /* 5. Poll the order until "valid" (the cert URL appears). */
    auto por = n00b_acme_poll_order(s, post_finalize->url,
                                    .max_wait_ms = poll_max_wait_ms);
    if (!n00b_result_is_ok(por)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(por));
    }
    n00b_acme_order_t *valid_order = n00b_result_get(por);
    if (!valid_order->status
        || strcmp(valid_order->status, "valid") != 0
        || !valid_order->certificate) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    /* 6. Pick up the cert. */
    return n00b_acme_get_certificate(s, valid_order);
}

/* ===========================================================================
 * §12  Public accessors
 * =========================================================================== */

const n00b_acme_directory_t *
n00b_acme_session_directory(n00b_acme_session_t *s)
{
    return s ? &s->directory : nullptr;
}

const n00b_acme_account_t *
n00b_acme_session_account(n00b_acme_session_t *s)
{
    return s ? s->account : nullptr;
}

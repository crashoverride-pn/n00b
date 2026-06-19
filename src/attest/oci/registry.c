/* src/attest/oci/registry.c — OCI client lifecycle + request
 * dispatch + URL parser.
 *
 * Implements:
 *   - n00b_attest_oci_client_new       (public; client lifecycle)
 *   - n00b_attest_oci_client_release   (public; client lifecycle)
 *   - n00b_attest_oci_request          (package-private; HTTP
 *                                        dispatch + token-exchange
 *                                        retry per OCI distribution-
 *                                        spec § 5)
 *   - n00b_attest_oci_url_parse        (package-private; image-ref
 *                                        parser per OCI distribution-
 *                                        spec § 4.1)
 *
 * The auth resolver + auth-handle release live in `auth.c`.
 *
 * D-045 `alloc_for_call` idiom: every allocating function threads
 * one `alloc_for_call` local through every allocation site.
 *
 * D-016 algorithm-agnostic: the OCI client ferries opaque bytes;
 * no Ed25519 / ECDSA / algorithm-tag symbols appear here.
 *
 * Decision log:
 *
 * - D-051 OQ-2 (libn00b HTTP surface pre-resolved). The OCI client
 *   wraps `n00b_http_request_sync` from
 *   `include/net/http/http_client.h`. The wrapper threads the OCI
 *   client's stored timeout / trust / redirect kwargs into the
 *   request and force-disables prefer_h3 (registry HTTP/2 / HTTP/1.1
 *   is the realistic deployment shape; H3 to registries is rare and
 *   per the spec footnote in the dispatcher, prefer_h3 = false is a
 *   safe default for OCI).
 *
 * - D-051 OQ-7 (redirect host allowlist is per-call kwarg). The
 *   client stores the allowlist on its handle so subsequent
 *   `_request` calls honor it without re-threading per-call. The
 *   actual host-allowlist enforcement lives inside libn00b's
 *   redirect dispatcher (via the `follow_redirects` kwarg); the OCI
 *   client just toggles it on/off based on `client->allow_redirects`.
 *
 * - D-051 OQ-8 (per-op timeouts). The OCI client stores a client-
 *   level default; Phase 2/3 verb shims override per-call via the
 *   underlying dispatcher.
 *
 * - D-049 build-verification-before-session-exit. The Phase 1 sub-
 *   agent runs `N00B_TEST=1 bash build.sh` synchronously and
 *   inspects `build_debug/meson-logs/testlog.txt` before returning.
 *
 * Phase 1 known simplifications (flagged for orchestrator if they
 * become annoying):
 *
 * - The cached_bearer_token cache is single-slot (one scope at a
 *   time); a different scope on the next call invalidates the
 *   cache. Phase 4 hardening may upgrade to multi-scope LRU.
 *
 * - WWW-Authenticate header parsing handles only the OCI § 5
 *   shape (`Bearer realm=...,service=...,scope=...` with optional
 *   quoting). Non-bearer challenges (Basic, Digest) surface
 *   directly to the caller as a 401.
 */

#include "internal/attest/oci/registry.h"
#include <attest/n00b_attest_oci.h>
#include <attest/n00b_attest_error.h>

#include "core/string.h"
#include "core/buffer.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "adt/dict.h"
#include "net/http/http_client.h"
#include "crypto/trust.h"
#include "internal/net/http/http_h1.h"
#include "internal/attest/json_util.h"

#include <stdatomic.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Helpers — small string utilities.
// ---------------------------------------------------------------------------

static bool
n00b_string_byte_eq(n00b_string_t *a, n00b_string_t *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    if (a->u8_bytes != b->u8_bytes) {
        return false;
    }
    return memcmp(a->data, b->data, a->u8_bytes) == 0;
}

static n00b_string_t *
copy_string(n00b_string_t *src, n00b_allocator_t *alloc_for_call)
{
    if (src == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(src->data,
                                (int64_t)src->u8_bytes,
                                .allocator = alloc_for_call);
}

static bool
starts_with_https(n00b_string_t *url)
{
    if (url == nullptr || url->u8_bytes < 8) {
        return false;
    }
    static const char prefix[] = "https://";
    return memcmp(url->data, prefix, 8) == 0;
}

// ---------------------------------------------------------------------------
// Public surface — client lifecycle.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_attest_oci_client_t *)
n00b_attest_oci_client_new(n00b_string_t *registry_url)
    _kargs {
        n00b_attest_oci_auth_t       *auth                    = nullptr;
        n00b_quic_trust_t            *trust                   = nullptr;
        uint64_t                      timeout_ms              = 0;
        bool                          allow_redirects         = true;
        n00b_list_t(n00b_string_t *) *redirect_host_allowlist = nullptr;
        n00b_allocator_t             *allocator               = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;

    if (registry_url == nullptr || registry_url->u8_bytes == 0
        || !starts_with_https(registry_url)) {
        return n00b_result_err(n00b_attest_oci_client_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    n00b_attest_oci_client_t *c = n00b_alloc_with_opts(
        n00b_attest_oci_client_t,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});

    c->registry_origin         = copy_string(registry_url, alloc_for_call);
    c->auth                    = auth;
    c->trust                   = trust;
    c->timeout_ms              = timeout_ms;
    c->allow_redirects         = allow_redirects;
    c->redirect_host_allowlist = redirect_host_allowlist;
    c->cached_bearer_token     = nullptr;
    c->cached_bearer_scope     = nullptr;
    c->allocator               = alloc_for_call;

    return n00b_result_ok(n00b_attest_oci_client_t *, c);
}

void
n00b_attest_oci_client_release(n00b_attest_oci_client_t *client)
{
    // No crypto_wipe in WP-004 Phase 1 per the header doxygen
    // ("@details" block on n00b_attest_oci_client_release). Under
    // the n00b GC convention the allocator owns the lifetime; the
    // function exists for surface-symmetry with verifier_release
    // / signer_release. The held auth + trust handles are NOT
    // released by this call — the caller owns their lifetime.
    (void)client;
}

// ---------------------------------------------------------------------------
// Helpers — WWW-Authenticate challenge parsing.
//
// Parses an OCI § 5 Bearer challenge of the form:
//   `Bearer realm="https://...",service="...",scope="..."`
// Quotes around values are optional. Returns true if all three
// fields were extracted. The output strings live in `out_alloc`.
// ---------------------------------------------------------------------------

typedef struct {
    n00b_string_t *realm;
    n00b_string_t *service;
    n00b_string_t *scope;
} bearer_challenge_t;

static const char *
skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    return p;
}

static bool
parse_bearer_challenge(const char         *hdr,
                       size_t              hdr_len,
                       bearer_challenge_t *out,
                       n00b_allocator_t   *alloc_for_call)
{
    if (hdr == nullptr || hdr_len < 6) {
        return false;
    }
    // Match `Bearer` (case-sensitive — registries are consistent).
    if (memcmp(hdr, "Bearer", 6) != 0) {
        return false;
    }
    const char *p   = skip_ws(hdr + 6, hdr + hdr_len);
    const char *end = hdr + hdr_len;

    out->realm = out->service = out->scope = nullptr;

    while (p < end) {
        // Each entry: key=value or key="value", comma-separated.
        const char *key_start = p;
        while (p < end && *p != '=' && *p != ',') {
            p++;
        }
        if (p >= end || *p != '=') {
            break;
        }
        size_t      key_len = (size_t)(p - key_start);
        p++;  // past '='
        bool quoted = false;
        if (p < end && *p == '"') {
            quoted = true;
            p++;
        }
        const char *val_start = p;
        if (quoted) {
            while (p < end && *p != '"') {
                p++;
            }
        } else {
            while (p < end && *p != ',') {
                p++;
            }
        }
        size_t      val_len = (size_t)(p - val_start);
        if (quoted && p < end && *p == '"') {
            p++;  // past closing quote
        }
        // skip comma + ws
        while (p < end && (*p == ',' || *p == ' ' || *p == '\t')) {
            p++;
        }

        n00b_string_t **slot = nullptr;
        if (key_len == 5 && memcmp(key_start, "realm", 5) == 0) {
            slot = &out->realm;
        } else if (key_len == 7 && memcmp(key_start, "service", 7) == 0) {
            slot = &out->service;
        } else if (key_len == 5 && memcmp(key_start, "scope", 5) == 0) {
            slot = &out->scope;
        }
        if (slot != nullptr) {
            *slot = n00b_string_from_raw(val_start,
                                         (int64_t)val_len,
                                         .allocator = alloc_for_call);
        }
    }

    // realm is the only strictly-required field per the OCI flow.
    return out->realm != nullptr;
}

// ---------------------------------------------------------------------------
// Helpers — bearer-token-exchange.
//
// Builds the token-realm URL (realm + `?service=...&scope=...`),
// performs an un-authenticated GET, and parses the JSON `{"token":
// "..."}` or `{"access_token": "..."}` response. Returns nullptr on
// failure; the caller maps to _OCI_BEARER_TOKEN_FAILED.
// ---------------------------------------------------------------------------

static n00b_string_t *
url_encode(n00b_string_t *s, n00b_allocator_t *alloc_for_call)
{
    // Minimal URL-encoder — only encodes characters the OCI scope
    // string typically uses (`:`, `/`, alphanumerics, `_`, `-`,
    // `.`). The realm responses don't strictly require this, but
    // belt-and-braces.
    static const char hex[] = "0123456789ABCDEF";
    if (s == nullptr || s->u8_bytes == 0) {
        return n00b_string_empty(.allocator = alloc_for_call);
    }
    size_t out_max = s->u8_bytes * 3;
    char  *buf = n00b_alloc_array_with_opts(
        char,
        out_max + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    size_t o = 0;
    for (size_t i = 0; i < s->u8_bytes; i++) {
        unsigned char c = (unsigned char)s->data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_'
            || c == '.' || c == '~' || c == ':' || c == '/') {
            buf[o++] = (char)c;
        } else {
            buf[o++] = '%';
            buf[o++] = hex[(c >> 4) & 0xf];
            buf[o++] = hex[c & 0xf];
        }
    }
    buf[o] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)o,
                                .allocator = alloc_for_call);
}

static n00b_string_t *
build_token_exchange_url(bearer_challenge_t *ch,
                         n00b_string_t      *override_scope,
                         n00b_allocator_t   *alloc_for_call)
{
    if (ch == nullptr || ch->realm == nullptr) {
        return nullptr;
    }
    n00b_string_t *use_scope = override_scope != nullptr
                                   ? override_scope
                                   : ch->scope;
    n00b_string_t *service_enc = url_encode(ch->service != nullptr
                                                ? ch->service
                                                : n00b_string_empty(),
                                            alloc_for_call);
    n00b_string_t *scope_enc = url_encode(use_scope != nullptr
                                              ? use_scope
                                              : n00b_string_empty(),
                                          alloc_for_call);

    // realm + '?' + 'service=' + service_enc + '&' + 'scope=' +
    // scope_enc
    size_t need = ch->realm->u8_bytes + 1
                  + 8 + service_enc->u8_bytes + 1
                  + 6 + scope_enc->u8_bytes + 1;
    char *buf = n00b_alloc_array_with_opts(
        char,
        need,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    size_t o = 0;
    memcpy(buf + o, ch->realm->data, ch->realm->u8_bytes);
    o += ch->realm->u8_bytes;
    buf[o++] = '?';
    memcpy(buf + o, "service=", 8);
    o += 8;
    memcpy(buf + o, service_enc->data, service_enc->u8_bytes);
    o += service_enc->u8_bytes;
    buf[o++] = '&';
    memcpy(buf + o, "scope=", 6);
    o += 6;
    memcpy(buf + o, scope_enc->data, scope_enc->u8_bytes);
    o += scope_enc->u8_bytes;
    buf[o] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)o,
                                .allocator = alloc_for_call);
}

static n00b_buffer_t *
parse_token_response(n00b_buffer_t    *body,
                     n00b_allocator_t *alloc_for_call)
{
    if (body == nullptr || body->byte_len == 0) {
        return nullptr;
    }
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             body->byte_len,
                                             &err);
    if (root == nullptr || !n00b_json_is_object(root)) {
        return nullptr;
    }
    n00b_json_node_t *tok = n00b_attest_json_obj_lookup(root, r"token");
    if (tok == nullptr || !n00b_json_is_string(tok)) {
        tok = n00b_attest_json_obj_lookup(root, r"access_token");
    }
    const char *tok_s = n00b_json_as_cstr(tok);
    if (tok_s == nullptr) {
        return nullptr;
    }
    return n00b_buffer_from_bytes((char *)tok_s,
                                  (int64_t)strlen(tok_s),
                                  .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// Helpers — URL builder.
//
// `client->registry_origin` ends without a slash; `path` begins
// with `/`. Concatenate verbatim.
// ---------------------------------------------------------------------------

static n00b_string_t *
build_request_url(n00b_string_t    *origin,
                  n00b_string_t    *path,
                  n00b_allocator_t *alloc_for_call)
{
    if (origin == nullptr || path == nullptr) {
        return nullptr;
    }
    // Trim trailing '/' from origin if present, ensure path starts
    // with '/'.
    size_t      olen = origin->u8_bytes;
    while (olen > 0 && origin->data[olen - 1] == '/') {
        olen--;
    }
    const char *path_data = path->data;
    size_t      plen      = path->u8_bytes;
    bool        need_slash = !(plen > 0 && path_data[0] == '/');
    size_t      total = olen + (need_slash ? 1 : 0) + plen;
    char       *buf = n00b_alloc_array_with_opts(
        char,
        total + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, origin->data, olen);
    size_t o = olen;
    if (need_slash) {
        buf[o++] = '/';
    }
    memcpy(buf + o, path_data, plen);
    o += plen;
    buf[o] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)o,
                                .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// Helpers — bearer header injection.
// ---------------------------------------------------------------------------

static void
inject_authorization(n00b_http_h1_headers_t *bag,
                     n00b_attest_oci_client_t *client,
                     n00b_allocator_t *alloc_for_call)
{
    if (bag == nullptr) {
        return;
    }
    // Cached bearer token from a prior token-exchange always wins
    // (post-401 retries land here). Otherwise honor whatever the
    // bound auth handle carries.
    n00b_buffer_t *tok = nullptr;
    n00b_buffer_t *basic = nullptr;
    if (client->cached_bearer_token != nullptr) {
        tok = client->cached_bearer_token;
    } else if (client->auth != nullptr) {
        tok   = client->auth->bearer_token;
        basic = client->auth->basic_auth;
    }
    if (tok != nullptr && tok->byte_len > 0) {
        // "Bearer " + token bytes + NUL.
        size_t need = 7 + tok->byte_len + 1;
        char  *buf = n00b_alloc_array_with_opts(
            char,
            need,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        memcpy(buf, "Bearer ", 7);
        memcpy(buf + 7, tok->data, tok->byte_len);
        buf[7 + tok->byte_len] = '\0';
        n00b_http_h1_headers_set(bag, "Authorization", buf);
        return;
    }
    if (basic != nullptr && basic->byte_len > 0) {
        size_t need = 6 + basic->byte_len + 1;
        char  *buf = n00b_alloc_array_with_opts(
            char,
            need,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        memcpy(buf, "Basic ", 6);
        memcpy(buf + 6, basic->data, basic->byte_len);
        buf[6 + basic->byte_len] = '\0';
        n00b_http_h1_headers_set(bag, "Authorization", buf);
    }
}

// ---------------------------------------------------------------------------
// Public surface — request helper.
// ---------------------------------------------------------------------------

// Merge caller-supplied `(name, value)` headers into the request
// bag. Per the doxygen on `_request`'s @c headers kwarg, caller-
// supplied values WIN on key collision — so the merge runs AFTER
// `inject_authorization` and uses `n00b_http_h1_headers_set` (which
// overwrites). The walk uses the typed dict's `n00b_dict_foreach`
// macro: the registries.json bucket-walk precedent in
// `src/attest/json_util.c` uses the untyped-dict store shape; the
// typed-dict shape ferries keys + values via parallel arrays, and
// the foreach macro encapsulates the correct walk without
// introducing a new helper.
//
// `n00b_string_t->data` is not guaranteed NUL-terminated per the
// public docstring (constructors set the NUL, but the invariant
// isn't preserved at the type level). The libn00b headers-bag
// `_set` primitive takes NUL-terminated C-strings. We materialize
// per-entry NUL-terminated copies under the per-call arena to
// satisfy the primitive's contract; the primitive then makes its
// own copies (it owns the lifetime of bag entries) so the
// materialized copies are released at arena teardown.
static void
merge_extra_headers(n00b_http_h1_headers_t *bag,
                    n00b_dict_t(n00b_string_t *, n00b_string_t *) *extra_headers,
                    n00b_allocator_t       *alloc_for_call)
{
    if (bag == nullptr || extra_headers == nullptr) {
        return;
    }
    n00b_dict_foreach(extra_headers, k, v, {
        if (k == nullptr || v == nullptr) {
            continue;
        }
        if (k->data == nullptr || v->data == nullptr) {
            continue;
        }
        char *kbuf = n00b_alloc_array_with_opts(
            char,
            k->u8_bytes + 1,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        memcpy(kbuf, k->data, k->u8_bytes);
        kbuf[k->u8_bytes] = '\0';
        char *vbuf = n00b_alloc_array_with_opts(
            char,
            v->u8_bytes + 1,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        memcpy(vbuf, v->data, v->u8_bytes);
        vbuf[v->u8_bytes] = '\0';
        n00b_http_h1_headers_set(bag, kbuf, vbuf);
    });
}

static n00b_result_t(n00b_http_response_t *)
dispatch_once(n00b_attest_oci_client_t                   *client,
              n00b_string_t                              *url,
              n00b_string_t                              *method,
              n00b_buffer_t                              *body,
              n00b_string_t                              *content_type,
              n00b_dict_t(n00b_string_t *, n00b_string_t *) *extra_headers,
              uint64_t                                    effective_timeout_ms,
              n00b_allocator_t                           *alloc_for_call)
{
    n00b_http_h1_headers_t *bag = n00b_http_h1_headers_new(
        .allocator = alloc_for_call);
    // Authorization first so caller-supplied headers can override
    // it via the merge below (per the @c headers kwarg's "caller-set
    // values win on key collision" semantic).
    inject_authorization(bag, client, alloc_for_call);
    merge_extra_headers(bag, extra_headers, alloc_for_call);

    int32_t timeout_ms = effective_timeout_ms == 0
                             ? 30000
                             : (int32_t)effective_timeout_ms;

    // WP-004 Phase 4 hardening (D-051 OQ-7 + user direction
    // 2026-05-19): delegate redirect-policy enforcement to libn00b
    // rather than rolling our own. When `allow_redirects` is set
    // on the client handle, pass `follow_redirects = true` plus
    // `max_redirects = 1` (single hop — registries that need more
    // are misconfigured, and a stricter cap reduces the attack
    // surface for redirect chains). libn00b's machinery
    // (documented on `n00b_http_request_sync`) enforces the RFC
    // 9110 § 15.4 method-preservation rules + the cross-scheme
    // HTTPS-only reject (3xx Location targets with non-https://
    // schemes are dropped at libn00b's layer).
    //
    // The host-allowlist enforcement is NOT yet wired: libn00b's
    // `n00b_http_request_sync` does not (yet) carry a per-call
    // `redirect_host_allowlist` kwarg. The kwarg is stored on the
    // client handle for forward-compat with the libn00b lift
    // (tracked as DF-015); once libn00b surfaces the kwarg we'll
    // thread it here without API change.
    auto rr = n00b_http_request_sync(
        url,
        .method           = method,
        .body             = body,
        .content_type     = content_type,
        .extra            = bag,
        .prefer_h3        = false,  // OCI v2 is HTTP/1.1 / HTTP/2
        .timeout_ms       = timeout_ms,
        .trust            = client->trust,
        .follow_redirects = client->allow_redirects,
        .max_redirects    = 1,
        .allocator        = alloc_for_call);
    return rr;
}

// WP-004 Phase 4 hardening: per-page response size cap for
// `_list_referrers`. NFR-5 mandates 1 MiB per page; symmetric with
// Phase 3's `generic_fetch` per-call cap on blob / manifest fetches.
// The cap is enforced n00b-attest-side because libn00b's
// `n00b_http_request_sync` does not (yet) carry a per-call
// `max_body_size` kwarg (tracked as DF-014).
#define N00B_ATTEST_OCI_REFERRERS_DEFAULT_MAX_PAGE_SIZE  (1u << 20)

// WP-004 Phase 4 hardening (D-051 OQ-8): per-op timeout defaults.
// Applied when BOTH the op-level kwarg AND the client-level handle
// field are zero. The precedence chain is therefore:
//   op-level kwarg (non-zero) → client->timeout_ms (non-zero) → these.
// The push value is the largest because push composes four sub-
// requests (HEAD + POST + PUT-blob + PUT-manifest) with the largest
// per-request body sizes; the discover value is the smallest because
// each page is a single small GET; pull sits between because it
// composes two GETs (manifest + blob).
#define N00B_ATTEST_OCI_PUSH_DEFAULT_TIMEOUT_MS      ((uint64_t)60000)
#define N00B_ATTEST_OCI_PULL_DEFAULT_TIMEOUT_MS      ((uint64_t)30000)
#define N00B_ATTEST_OCI_DISCOVER_DEFAULT_TIMEOUT_MS  ((uint64_t)10000)

// WP-004 Phase 4 hardening (NFR-5): JSON-parse depth cap.
//
// libn00b's `n00b_json_parse` (`src/parsers/json.c`) enforces a
// hard-coded maximum nesting depth of 256 frames (see the
// `max_depth = 256` initializer in the parser's body); on excess
// nesting the parser fails with the diagnostic
// "maximum nesting depth exceeded". 256 comfortably exceeds the
// NFR-5 floor of 32, so the OCI client inherits a compliant cap
// without threading a per-call depth kwarg. If libn00b ever lowers
// its default below 32, OCI parses must surface a Phase-4-side
// counter; until then no additional enforcement is needed. The
// inheritance is documented inline at each OCI JSON parse site
// (`append_referrers_page` + the `_pull_envelope` manifest walk).

n00b_result_t(n00b_http_response_t *)
n00b_attest_oci_request(n00b_attest_oci_client_t *client,
                        n00b_string_t            *method,
                        n00b_string_t            *path)
    _kargs {
        n00b_buffer_t                                 *body         = nullptr;
        n00b_string_t                                 *content_type = nullptr;
        n00b_dict_t(n00b_string_t *, n00b_string_t *) *headers     = nullptr;
        n00b_string_t                                 *scope        = nullptr;
        uint64_t                                       timeout_ms   = 0;
        n00b_allocator_t                              *allocator    = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || method == nullptr || path == nullptr) {
        return n00b_result_err(n00b_http_response_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    // WP-004 Phase 4 hardening (D-051 OQ-8): timeout precedence
    // is op-level kwarg (non-zero) → client-level handle field
    // (non-zero) → libn00b's default at the dispatch_once layer
    // (30s). Verb shims that need op-specific defaults
    // (push 60s / pull 30s / discover 10s) pre-resolve their
    // op-specific default before invoking this helper.
    uint64_t effective_timeout = timeout_ms != 0
                                     ? timeout_ms
                                     : client->timeout_ms;

    n00b_string_t *url = build_request_url(client->registry_origin,
                                           path,
                                           alloc_for_call);
    if (url == nullptr) {
        return n00b_result_err(n00b_http_response_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    auto first = dispatch_once(client, url, method, body, content_type,
                                headers, effective_timeout, alloc_for_call);
    if (n00b_result_is_err(first)) {
        // Transport-level error. Surface a representative OCI code.
        // libn00b's HTTPS layer's error codes are negative ints
        // outside our namespace; we route everything through
        // _OCI_HTTP_ERROR for Phase 1. Phase 2/3/4 may grow the
        // mapping (timeout / TLS-handshake distinctions reintroduce
        // their codes) as the higher-level shims need them.
        return n00b_result_err(n00b_http_response_t *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }
    n00b_http_response_t *resp = n00b_result_get(first);

    // Transport-level failure surfaced via the response (status=0
    // + non-zero error code).
    if (n00b_http_response_status(resp) == 0) {
        return n00b_result_err(n00b_http_response_t *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }

    // 401 + bearer challenge -> token-exchange retry.
    if (n00b_http_response_status(resp) == 401) {
        n00b_string_t *www_name = r"WWW-Authenticate";
        n00b_buffer_t *www = n00b_http_response_header(resp, www_name);
        if (www == nullptr || www->byte_len < 6) {
            // No challenge header -> can't recover; surface as 401
            // by returning the response on Ok.
            return n00b_result_ok(n00b_http_response_t *, resp);
        }
        bearer_challenge_t ch = {};
        if (!parse_bearer_challenge(www->data,
                                    www->byte_len,
                                    &ch,
                                    alloc_for_call)) {
            return n00b_result_ok(n00b_http_response_t *, resp);
        }

        n00b_string_t *use_scope = scope != nullptr ? scope : ch.scope;

        // Check the single-slot cache. If the cached scope matches
        // and we haven't already tried it (we did just receive a
        // 401), the cache is stale — clear it before re-exchanging.
        if (client->cached_bearer_scope != nullptr
            && use_scope != nullptr
            && n00b_string_byte_eq(client->cached_bearer_scope, use_scope)) {
            client->cached_bearer_token = nullptr;
            client->cached_bearer_scope = nullptr;
        }

        // Build the token-exchange URL and fetch it.
        n00b_string_t *tok_url = build_token_exchange_url(&ch,
                                                          scope,
                                                          alloc_for_call);
        if (tok_url == nullptr) {
            return n00b_result_err(n00b_http_response_t *,
                                   N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED);
        }

        // The token-exchange dispatch follows the same effective-
        // timeout precedence chain as the primary request (D-051
        // OQ-8 + Phase 4 hardening): the resolved per-op timeout
        // applies to BOTH the original dispatch and the bearer-
        // exchange retry sub-request, keeping the entire op
        // bounded by a single deadline.
        int32_t tok_timeout_ms = effective_timeout == 0
                                     ? 30000
                                     : (int32_t)effective_timeout;
        auto tok_rr = n00b_http_request_sync(
            tok_url,
            .method     = r"GET",
            .prefer_h3  = false,
            .timeout_ms = tok_timeout_ms,
            .trust      = client->trust,
            .allocator  = alloc_for_call);
        if (n00b_result_is_err(tok_rr)) {
            return n00b_result_err(n00b_http_response_t *,
                                   N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED);
        }
        n00b_http_response_t *tok_resp = n00b_result_get(tok_rr);
        if (n00b_http_response_status(tok_resp) != 200) {
            return n00b_result_err(n00b_http_response_t *,
                                   N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED);
        }
        n00b_buffer_t *new_token = parse_token_response(
            n00b_http_response_body(tok_resp), alloc_for_call);
        if (new_token == nullptr) {
            return n00b_result_err(n00b_http_response_t *,
                                   N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED);
        }
        client->cached_bearer_token = new_token;
        client->cached_bearer_scope = use_scope != nullptr
                                          ? copy_string(use_scope,
                                                        alloc_for_call)
                                          : nullptr;

        // Retry the original request with the new bearer.
        auto retry = dispatch_once(client, url, method, body, content_type,
                                    headers, effective_timeout,
                                    alloc_for_call);
        if (n00b_result_is_err(retry)) {
            return n00b_result_err(n00b_http_response_t *,
                                   N00B_ATTEST_ERR_OCI_HTTP_ERROR);
        }
        n00b_http_response_t *retry_resp = n00b_result_get(retry);
        if (n00b_http_response_status(retry_resp) == 401) {
            // Second 401 -> token-exchange flow failed.
            return n00b_result_err(n00b_http_response_t *,
                                   N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED);
        }
        return n00b_result_ok(n00b_http_response_t *, retry_resp);
    }

    return n00b_result_ok(n00b_http_response_t *, resp);
}

// ---------------------------------------------------------------------------
// Public surface — image-ref URL parser.
//
// OCI distribution-spec § 4.1 form: `[<registry>/]<name>{@<digest>|
// :<tag>}`.
//
// Colon-ambiguity rule (§ 4.1):
//   - Colon in the FIRST slash-separated component (before the
//     first `/`) is a port (e.g. `localhost:5000/foo/bar`).
//   - Colon in the LAST slash-separated component (after the last
//     `/`) is a tag separator (`foo/bar:latest`).
// `@sha256:...` always denotes a digest reference regardless of
// position.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_attest_oci_image_ref_t *)
n00b_attest_oci_url_parse(n00b_string_t *image_ref)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;

    if (image_ref == nullptr || image_ref->u8_bytes == 0) {
        return n00b_result_err(n00b_attest_oci_image_ref_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    const char *data = image_ref->data;
    size_t      len  = image_ref->u8_bytes;

    // Look for an `@` first — if present, everything after it is a
    // digest reference (`sha256:...`).
    const char *at = memchr(data, '@', len);
    size_t      body_len;
    const char *digest_start = nullptr;
    size_t      digest_len   = 0;
    if (at != nullptr) {
        body_len     = (size_t)(at - data);
        digest_start = at + 1;
        digest_len   = len - body_len - 1;
        if (digest_len == 0) {
            return n00b_result_err(n00b_attest_oci_image_ref_t *,
                                   N00B_ATTEST_ERR_OCI_BAD_URL);
        }
    } else {
        body_len = len;
    }

    // Now scan the body for a registry prefix. A `/` before any colon
    // signals "first slash-separated component is the registry"; a
    // colon BEFORE the first slash means the registry has a port.
    const char *first_slash = memchr(data, '/', body_len);
    const char *registry_start = nullptr;
    size_t      registry_len   = 0;
    const char *name_start;
    size_t      name_len;

    if (first_slash != nullptr) {
        // Heuristic per OCI / Docker convention: the first component
        // is a registry IFF it contains a '.' or ':' or is exactly
        // "localhost". Otherwise it is a namespace path component
        // (e.g. `library/redis`).
        size_t      first_len = (size_t)(first_slash - data);
        const char *colon_in_first = memchr(data, ':', first_len);
        const char *dot_in_first   = memchr(data, '.', first_len);
        bool        is_localhost = (first_len == 9
                              && memcmp(data, "localhost", 9) == 0);
        if (colon_in_first != nullptr || dot_in_first != nullptr
            || is_localhost) {
            registry_start = data;
            registry_len   = first_len;
            name_start     = first_slash + 1;
            name_len       = body_len - first_len - 1;
        } else {
            name_start = data;
            name_len   = body_len;
        }
    } else {
        // No slash AND no @ AND no colon-in-last-component-or-only
        // -> reject. A bare name with no digest and no tag is
        // not OCI-spec-compliant for our substrate.
        name_start = data;
        name_len   = body_len;
    }

    // If digest form: name may end with `:tag` only if the user
    // wrote `foo/bar:tag@sha256:...` — but this is illegal per
    // OCI spec (tag and digest are mutually exclusive). We do
    // not enforce here; we strip the digest path above and parse
    // the rest as tag-aware.
    n00b_string_t *digest_out = nullptr;
    n00b_string_t *tag_out    = nullptr;

    if (digest_start != nullptr) {
        digest_out = n00b_string_from_raw(digest_start,
                                          (int64_t)digest_len,
                                          .allocator = alloc_for_call);
    } else {
        // Tag form: the colon in the LAST slash-separated component
        // is the tag separator. Search backward from name_end for
        // the last colon AFTER the last slash in body.
        const char *body_end = data + body_len;
        const char *last_slash_in_body = nullptr;
        const char *p;
        for (p = body_end - 1; p >= data; p--) {
            if (*p == '/') {
                last_slash_in_body = p;
                break;
            }
        }
        const char *tag_search_start = last_slash_in_body != nullptr
                                           ? last_slash_in_body + 1
                                           : data;
        const char *colon_in_last = nullptr;
        const char *cp;
        for (cp = body_end - 1; cp >= tag_search_start; cp--) {
            if (*cp == ':') {
                colon_in_last = cp;
                break;
            }
        }
        if (colon_in_last == nullptr) {
            // Neither digest nor tag. Reject per "must be explicitly
            // pinned" framing in the helper's @details.
            return n00b_result_err(n00b_attest_oci_image_ref_t *,
                                   N00B_ATTEST_ERR_OCI_BAD_URL);
        }
        size_t tag_len = (size_t)(body_end - colon_in_last - 1);
        if (tag_len == 0) {
            return n00b_result_err(n00b_attest_oci_image_ref_t *,
                                   N00B_ATTEST_ERR_OCI_BAD_URL);
        }
        tag_out = n00b_string_from_raw(colon_in_last + 1,
                                       (int64_t)tag_len,
                                       .allocator = alloc_for_call);
        // Trim tag from name_*: the colon is INSIDE name_*.
        // name_start..body_end becomes name_start..colon_in_last.
        name_len = (size_t)(colon_in_last - name_start);
    }

    if (name_len == 0) {
        return n00b_result_err(n00b_attest_oci_image_ref_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    n00b_attest_oci_image_ref_t *out = n00b_alloc_with_opts(
        n00b_attest_oci_image_ref_t,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    out->registry = registry_start != nullptr
                        ? n00b_string_from_raw(registry_start,
                                                (int64_t)registry_len,
                                                .allocator = alloc_for_call)
                        : nullptr;
    out->name = n00b_string_from_raw(name_start,
                                     (int64_t)name_len,
                                     .allocator = alloc_for_call);
    out->digest   = digest_out;
    out->tag      = tag_out;
    out->full_ref = copy_string(image_ref, alloc_for_call);

    return n00b_result_ok(n00b_attest_oci_image_ref_t *, out);
}

// ---------------------------------------------------------------------------
// WP-004 Phase 2 — blob upload + manifest upload + manifest pre-fetch.
//
// Compose on top of the Phase 1 substrate (`n00b_attest_oci_request`
// + the OCI v2 token-exchange retry). The bearer-token cache in
// Phase 1 is scope-keyed; the push verb's HEAD + POST + PUT + PUT
// against the same registry share scope `repository:<name>:push,
// pull`, so the token-exchange fires at most once per push (cache
// hits on subsequent requests).
//
// D-053 inheritance: Err legs carry bare codes; no structured Err
// payload shape. DF-011 tracks the libn00b typed-Err-payload
// future lift.
// ---------------------------------------------------------------------------

// Build a path `/v2/<name>/<rest>` against a registry repository
// scope. `rest` is appended verbatim (caller chooses
// `manifests/<ref>` / `blobs/uploads/` / etc.).
static n00b_string_t *
build_v2_path(n00b_string_t    *name,
              const char       *rest,
              size_t            rest_len,
              n00b_allocator_t *alloc_for_call)
{
    if (name == nullptr || rest == nullptr) {
        return nullptr;
    }
    size_t total = 4 + name->u8_bytes + 1 + rest_len;
    char *buf = n00b_alloc_array_with_opts(
        char,
        total + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, "/v2/", 4);
    memcpy(buf + 4, name->data, name->u8_bytes);
    buf[4 + name->u8_bytes] = '/';
    memcpy(buf + 4 + name->u8_bytes + 1, rest, rest_len);
    buf[total] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)total,
                                .allocator = alloc_for_call);
}

// Build a push-scope string for a given repository name. Realistic
// shape: `repository:<name>:push,pull` — the OCI v2 token-exchange
// flow respects either form ("push" or "push,pull"); we use the
// broader form so subsequent same-client pulls re-use the cached
// token.
static n00b_string_t *
build_push_scope(n00b_string_t    *name,
                 n00b_allocator_t *alloc_for_call)
{
    if (name == nullptr) {
        return nullptr;
    }
    static const char prefix[]   = "repository:";
    static const char suffix[]   = ":push,pull";
    size_t            pfx_len    = sizeof(prefix) - 1;
    size_t            sfx_len    = sizeof(suffix) - 1;
    size_t            total      = pfx_len + name->u8_bytes + sfx_len;
    char *buf = n00b_alloc_array_with_opts(
        char,
        total + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, prefix, pfx_len);
    memcpy(buf + pfx_len, name->data, name->u8_bytes);
    memcpy(buf + pfx_len + name->u8_bytes, suffix, sfx_len);
    buf[total] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)total,
                                .allocator = alloc_for_call);
}

// Look up Content-Length from an HTTP response. Returns true on
// success (writes into `*out`); false if the header is missing
// or unparseable. Decimal-only — registries never emit hex /
// other-base Content-Length on the OCI v2 control plane.
static bool
parse_content_length(n00b_http_response_t *resp, uint64_t *out)
{
    if (resp == nullptr || out == nullptr) {
        return false;
    }
    n00b_buffer_t *hdr = n00b_http_response_header(resp, r"Content-Length");
    if (hdr == nullptr || hdr->byte_len == 0) {
        return false;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < (size_t)hdr->byte_len; i++) {
        char c = hdr->data[i];
        if (c == ' ' || c == '\t') {
            // tolerant of stray whitespace; some registries pad
            continue;
        }
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

// Resolve a `Location` header value relative to the client's
// registry origin. Registries return either an absolute URL
// (`https://registry/v2/.../uploads/<id>`) or a relative path
// (`/v2/.../uploads/<id>`); the helper passes absolute URLs
// through verbatim and prepends the registry origin onto relative
// paths.
//
// We extract path-only URLs from absolute ones too so the
// downstream `_request` helper composes them against the same
// origin (avoids forcing the underlying HTTPS dispatcher to
// re-parse the origin). The fragment is dropped (OCI / RFC 3986).
static n00b_string_t *
location_to_path(n00b_attest_oci_client_t *client,
                 n00b_buffer_t            *location,
                 n00b_allocator_t         *alloc_for_call)
{
    if (location == nullptr || location->byte_len == 0) {
        return nullptr;
    }
    const char *data = location->data;
    size_t      len  = (size_t)location->byte_len;

    // Trim CRLF / trailing whitespace some registries leave on
    // the header value.
    while (len > 0 && (data[len - 1] == '\r' || data[len - 1] == '\n'
                       || data[len - 1] == ' ' || data[len - 1] == '\t')) {
        len--;
    }
    if (len == 0) {
        return nullptr;
    }

    // Absolute URL? Strip the origin if it matches our client's
    // origin; otherwise treat as cross-origin and surface as
    // BAD_URL (the OCI spec allows cross-origin upload Locations
    // for federated registries, but Phase 2 doesn't follow them;
    // a Phase 4 hardening item if customers run into this).
    if (len >= 8 && memcmp(data, "https://", 8) == 0) {
        // Find the third `/` (after `https://`). The host:port
        // ends there; the path begins.
        size_t i = 8;
        while (i < len && data[i] != '/') {
            i++;
        }
        // If origin matches verbatim, the registry sent us an
        // absolute URL pointing at ourselves; use the path part.
        // Otherwise reject as cross-origin.
        if (client->registry_origin != nullptr
            && client->registry_origin->u8_bytes == i
            && memcmp(client->registry_origin->data, data, i) == 0) {
            return n00b_string_from_raw(data + i,
                                        (int64_t)(len - i),
                                        .allocator = alloc_for_call);
        }
        // Cross-origin redirect — out of scope.
        return nullptr;
    }

    // Relative path; copy verbatim.
    return n00b_string_from_raw(data,
                                (int64_t)len,
                                .allocator = alloc_for_call);
}

// Append `?digest=<digest>` to a path (or `&digest=` if a `?`
// already appears in the path; some registries embed query
// parameters into the upload location).
static n00b_string_t *
append_digest_query(n00b_string_t    *path,
                    n00b_string_t    *digest,
                    n00b_allocator_t *alloc_for_call)
{
    if (path == nullptr || digest == nullptr) {
        return nullptr;
    }
    bool has_query = false;
    for (size_t i = 0; i < path->u8_bytes; i++) {
        if (path->data[i] == '?') {
            has_query = true;
            break;
        }
    }
    static const char prefix[] = "digest=";
    size_t            need = path->u8_bytes + 1
                  + sizeof(prefix) - 1
                  + digest->u8_bytes;
    char *buf = n00b_alloc_array_with_opts(
        char,
        need + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, path->data, path->u8_bytes);
    size_t o = path->u8_bytes;
    buf[o++] = has_query ? '&' : '?';
    memcpy(buf + o, prefix, sizeof(prefix) - 1);
    o += sizeof(prefix) - 1;
    memcpy(buf + o, digest->data, digest->u8_bytes);
    o += digest->u8_bytes;
    buf[o] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)o,
                                .allocator = alloc_for_call);
}

n00b_result_t(uint64_t *)
n00b_attest_oci_manifest_head(n00b_attest_oci_client_t *client,
                              n00b_string_t            *name,
                              n00b_string_t            *digest)
    _kargs {
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || digest == nullptr || digest->u8_bytes == 0) {
        return n00b_result_err(uint64_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    // Build `/v2/<name>/manifests/<digest>`.
    static const char rest_pfx[] = "manifests/";
    size_t rest_len = sizeof(rest_pfx) - 1 + digest->u8_bytes;
    char  *rest_buf = n00b_alloc_array_with_opts(
        char,
        rest_len,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(rest_buf, rest_pfx, sizeof(rest_pfx) - 1);
    memcpy(rest_buf + sizeof(rest_pfx) - 1,
           digest->data,
           digest->u8_bytes);

    n00b_string_t *path = build_v2_path(name,
                                        rest_buf,
                                        rest_len,
                                        alloc_for_call);
    n00b_string_t *scope = build_push_scope(name, alloc_for_call);

    // HEAD primary.
    auto head_r = n00b_attest_oci_request(client,
                                           r"HEAD",
                                           path,
                                           .scope      = scope,
                                           .timeout_ms = timeout_ms,
                                           .allocator  = alloc_for_call);
    if (n00b_result_is_err(head_r)) {
        return n00b_result_err(uint64_t *,
                               n00b_result_get_err(head_r));
    }
    n00b_http_response_t *resp = n00b_result_get(head_r);
    int status = n00b_http_response_status(resp);

    if (status >= 200 && status < 300) {
        uint64_t size = 0;
        if (!parse_content_length(resp, &size)) {
            // Honest HEAD without a Content-Length is an OCI v2
            // protocol violation; surface as BAD_URL (no body to
            // fall back to). Older non-strict registries that
            // omit Content-Length on HEAD also omit it on GET in
            // practice; we honor the protocol and treat this as
            // malformed.
            return n00b_result_err(uint64_t *,
                                   N00B_ATTEST_ERR_OCI_BAD_URL);
        }
        uint64_t *out = n00b_alloc_with_opts(
            uint64_t,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        *out = size;
        return n00b_result_ok(uint64_t *, out);
    }

    if (status == 405) {
        // D-054 fallback: HEAD not supported; retry as a GET and
        // measure the body length. Some older non-strict
        // registries emit 405 on HEAD; the GET fallback is the
        // documented escape hatch.
        auto get_r = n00b_attest_oci_request(client,
                                              r"GET",
                                              path,
                                              .scope      = scope,
                                              .timeout_ms = timeout_ms,
                                              .allocator  = alloc_for_call);
        if (n00b_result_is_err(get_r)) {
            return n00b_result_err(uint64_t *,
                                   n00b_result_get_err(get_r));
        }
        n00b_http_response_t *gresp = n00b_result_get(get_r);
        int gstatus = n00b_http_response_status(gresp);
        if (gstatus < 200 || gstatus >= 300) {
            return n00b_result_err(uint64_t *,
                                   N00B_ATTEST_ERR_OCI_HTTP_ERROR);
        }
        n00b_buffer_t *body = n00b_http_response_body(gresp);
        uint64_t size = body != nullptr ? (uint64_t)body->byte_len : 0;
        uint64_t *out = n00b_alloc_with_opts(
            uint64_t,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        *out = size;
        return n00b_result_ok(uint64_t *, out);
    }

    // Any other non-success status → HTTP_ERROR. 404 lands here
    // and signals "the subject manifest isn't in the registry,"
    // which is a real pre-flight error condition.
    return n00b_result_err(uint64_t *,
                           N00B_ATTEST_ERR_OCI_HTTP_ERROR);
}

n00b_result_t(void *)
n00b_attest_oci_blob_upload(n00b_attest_oci_client_t *client,
                            n00b_string_t            *name,
                            n00b_buffer_t            *blob,
                            n00b_string_t            *digest)
    _kargs {
        n00b_string_t    *content_type = nullptr;
        uint64_t          timeout_ms   = 0;
        n00b_allocator_t *allocator    = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || blob == nullptr || digest == nullptr
        || digest->u8_bytes == 0) {
        return n00b_result_err(void *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    n00b_string_t *use_ct = content_type != nullptr
                                ? content_type
                                : r"application/octet-stream";

    n00b_string_t *scope = build_push_scope(name, alloc_for_call);

    // Step 1: POST /v2/<name>/blobs/uploads/.
    static const char init_rest[] = "blobs/uploads/";
    n00b_string_t *init_path = build_v2_path(name,
                                             init_rest,
                                             sizeof(init_rest) - 1,
                                             alloc_for_call);
    auto post_r = n00b_attest_oci_request(client,
                                           r"POST",
                                           init_path,
                                           .scope      = scope,
                                           .timeout_ms = timeout_ms,
                                           .allocator  = alloc_for_call);
    if (n00b_result_is_err(post_r)) {
        return n00b_result_err(void *,
                               n00b_result_get_err(post_r));
    }
    n00b_http_response_t *post_resp = n00b_result_get(post_r);
    int post_status = n00b_http_response_status(post_resp);
    // OCI spec: 202 Accepted on success. Some registries return
    // 201 Created if they pre-allocate; tolerate any 2xx.
    if (post_status < 200 || post_status >= 300) {
        return n00b_result_err(void *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }

    n00b_buffer_t *location = n00b_http_response_header(post_resp,
                                                        r"Location");
    if (location == nullptr || location->byte_len == 0) {
        // OCI v2 protocol violation; no upload session to PUT to.
        return n00b_result_err(void *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    n00b_string_t *upload_path = location_to_path(client,
                                                  location,
                                                  alloc_for_call);
    if (upload_path == nullptr) {
        return n00b_result_err(void *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    // Step 2: PUT <location>?digest=<digest> with the blob bytes.
    n00b_string_t *put_path = append_digest_query(upload_path,
                                                  digest,
                                                  alloc_for_call);
    if (put_path == nullptr) {
        return n00b_result_err(void *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    auto put_r = n00b_attest_oci_request(client,
                                          r"PUT",
                                          put_path,
                                          .body         = blob,
                                          .content_type = use_ct,
                                          .scope        = scope,
                                          .timeout_ms   = timeout_ms,
                                          .allocator    = alloc_for_call);
    if (n00b_result_is_err(put_r)) {
        return n00b_result_err(void *,
                               n00b_result_get_err(put_r));
    }
    n00b_http_response_t *put_resp = n00b_result_get(put_r);
    int put_status = n00b_http_response_status(put_resp);
    if (put_status < 200 || put_status >= 300) {
        return n00b_result_err(void *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }

    return n00b_result_ok(void *, nullptr);
}

n00b_result_t(n00b_string_t *)
n00b_attest_oci_manifest_upload(n00b_attest_oci_client_t *client,
                                n00b_string_t            *name,
                                n00b_string_t            *ref,
                                n00b_buffer_t            *manifest_bytes)
    _kargs {
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || ref == nullptr || ref->u8_bytes == 0
        || manifest_bytes == nullptr) {
        return n00b_result_err(n00b_string_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    // Build `/v2/<name>/manifests/<ref>`.
    static const char rest_pfx[] = "manifests/";
    size_t rest_len = sizeof(rest_pfx) - 1 + ref->u8_bytes;
    char  *rest_buf = n00b_alloc_array_with_opts(
        char,
        rest_len,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(rest_buf, rest_pfx, sizeof(rest_pfx) - 1);
    memcpy(rest_buf + sizeof(rest_pfx) - 1,
           ref->data,
           ref->u8_bytes);

    n00b_string_t *path = build_v2_path(name,
                                        rest_buf,
                                        rest_len,
                                        alloc_for_call);
    n00b_string_t *scope = build_push_scope(name, alloc_for_call);

    auto put_r = n00b_attest_oci_request(
        client,
        r"PUT",
        path,
        .body         = manifest_bytes,
        .content_type = r"application/vnd.oci.image.manifest.v1+json",
        .scope        = scope,
        .timeout_ms   = timeout_ms,
        .allocator    = alloc_for_call);
    if (n00b_result_is_err(put_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(put_r));
    }
    n00b_http_response_t *resp = n00b_result_get(put_r);
    int status = n00b_http_response_status(resp);
    if (status < 200 || status >= 300) {
        return n00b_result_err(n00b_string_t *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }

    // Compute the local digest as the fallback / cross-check
    // baseline.
    auto local_r = n00b_attest_oci_digest_of_buffer(
        manifest_bytes,
        .allocator = alloc_for_call);
    if (n00b_result_is_err(local_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(local_r));
    }
    n00b_string_t *local_digest = n00b_result_get(local_r);

    // Read `Docker-Content-Digest` if present.
    n00b_buffer_t *dcd = n00b_http_response_header(resp,
                                                   r"Docker-Content-Digest");
    if (dcd != nullptr && dcd->byte_len > 0) {
        // Trim trailing whitespace some registries leave.
        size_t dlen = (size_t)dcd->byte_len;
        while (dlen > 0 && (dcd->data[dlen - 1] == '\r'
                            || dcd->data[dlen - 1] == '\n'
                            || dcd->data[dlen - 1] == ' '
                            || dcd->data[dlen - 1] == '\t')) {
            dlen--;
        }
        if (dlen != local_digest->u8_bytes
            || memcmp(dcd->data, local_digest->data, dlen) != 0) {
            // Real integrity concern: the registry transformed
            // the manifest in transit (or we / the registry has
            // a bug).
            return n00b_result_err(
                n00b_string_t *,
                N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH);
        }
    }

    return n00b_result_ok(n00b_string_t *, local_digest);
}

// ---------------------------------------------------------------------------
// Public surface — push orchestrator.
//
// Composes the four sub-steps in order: digest envelope, HEAD
// subject, blob-upload envelope, build manifest, digest manifest,
// upload manifest. Each Err leg surfaces with its own bare code
// per D-053; the orchestrator preserves the underlying code so
// audit logs see the precise failure point.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_string_t *)
n00b_attest_oci_push_attestation(n00b_attest_oci_client_t *client,
                                 n00b_string_t            *name,
                                 n00b_string_t            *image_digest,
                                 n00b_buffer_t            *envelope_bytes)
    _kargs {
        n00b_string_t    *predicate_type = nullptr;
        n00b_string_t    *signer_keyid   = nullptr;
        uint64_t          timeout_ms     = 0;
        n00b_allocator_t *allocator      = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || image_digest == nullptr || image_digest->u8_bytes == 0
        || envelope_bytes == nullptr || envelope_bytes->byte_len == 0) {
        return n00b_result_err(n00b_string_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }
    if (predicate_type == nullptr || predicate_type->u8_bytes == 0
        || signer_keyid == nullptr || signer_keyid->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // WP-004 Phase 4 hardening (D-051 OQ-8): resolve the per-op
    // effective timeout. Precedence chain:
    //   op-level kwarg (non-zero) → client->timeout_ms (non-zero) →
    //   push-specific default (60s).
    // Phase 4 resolves the chain at the orchestrator level (here) so
    // sub-steps inherit a single deadline value rather than each
    // re-resolving independently against the client handle.
    uint64_t effective_timeout = timeout_ms != 0
                                     ? timeout_ms
                                     : (client->timeout_ms != 0
                                            ? client->timeout_ms
                                            : N00B_ATTEST_OCI_PUSH_DEFAULT_TIMEOUT_MS);

    // 1. Envelope blob digest.
    auto env_dig_r = n00b_attest_oci_digest_of_buffer(
        envelope_bytes,
        .allocator = alloc_for_call);
    if (n00b_result_is_err(env_dig_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(env_dig_r));
    }
    n00b_string_t *env_digest = n00b_result_get(env_dig_r);

    // 2. HEAD subject manifest to learn its byte-size.
    auto head_r = n00b_attest_oci_manifest_head(
        client,
        name,
        image_digest,
        .timeout_ms = effective_timeout,
        .allocator  = alloc_for_call);
    if (n00b_result_is_err(head_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(head_r));
    }
    uint64_t image_manifest_size = *n00b_result_get(head_r);

    // 3. Upload envelope blob.
    auto blob_r = n00b_attest_oci_blob_upload(
        client,
        name,
        envelope_bytes,
        env_digest,
        .content_type = r"application/vnd.in-toto+json",
        .timeout_ms   = effective_timeout,
        .allocator    = alloc_for_call);
    if (n00b_result_is_err(blob_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(blob_r));
    }

    // 4. Build artifact manifest.
    auto mb_r = n00b_attest_oci_manifest_build(
        image_digest,
        image_manifest_size,
        env_digest,
        (uint64_t)envelope_bytes->byte_len,
        predicate_type,
        signer_keyid,
        .allocator = alloc_for_call);
    if (n00b_result_is_err(mb_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(mb_r));
    }
    n00b_buffer_t *manifest_bytes = n00b_result_get(mb_r);

    // 5. Compute manifest digest (used as the upload reference).
    auto mdig_r = n00b_attest_oci_digest_of_buffer(
        manifest_bytes,
        .allocator = alloc_for_call);
    if (n00b_result_is_err(mdig_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(mdig_r));
    }
    n00b_string_t *manifest_digest = n00b_result_get(mdig_r);

    // 6. Upload manifest.
    auto up_r = n00b_attest_oci_manifest_upload(
        client,
        name,
        manifest_digest,
        manifest_bytes,
        .timeout_ms = effective_timeout,
        .allocator  = alloc_for_call);
    if (n00b_result_is_err(up_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(up_r));
    }
    // `_manifest_upload` returns the registry-confirmed digest
    // (or the locally-computed fallback). Use that as the
    // user-visible result.
    return n00b_result_ok(n00b_string_t *, n00b_result_get(up_r));
}

// ---------------------------------------------------------------------------
// WP-004 Phase 3 — consumer-side substrate: blob fetch + manifest fetch +
// referrers listing + pull-envelope orchestrator.
//
// Composes on top of the Phase 1 substrate (`n00b_attest_oci_request` +
// the OCI v2 token-exchange retry). Pull / discover scope is
// `repository:<name>:pull` so the token-exchange (when needed) fires at
// most once per pull / discover.
// ---------------------------------------------------------------------------

// Per the WP-004 Phase 3 plan: 1 MiB body cap (NFR-5). Typical envelope
// is <= 50 KB (NFR-6), so the cap is comfortable.
#define N00B_ATTEST_OCI_PULL_DEFAULT_MAX_SIZE  (1u << 20)
// Soft pagination cap. Surfaces in the header doxygen on
// `_list_referrers`. Phase 4 hardening replaces this with a
// configurable kwarg.
#define N00B_ATTEST_OCI_REFERRERS_MAX_PAGES    100

// Build a pull-scope string for a given repository name. Shape:
// `repository:<name>:pull`. Used by `_blob_fetch` / `_manifest_fetch` /
// `_list_referrers` so the bearer-token cache on the client handle
// shares the same scope across the multi-request pull sequence.
static n00b_string_t *
build_pull_scope(n00b_string_t    *name,
                 n00b_allocator_t *alloc_for_call)
{
    if (name == nullptr) {
        return nullptr;
    }
    static const char prefix[]   = "repository:";
    static const char suffix[]   = ":pull";
    size_t            pfx_len    = sizeof(prefix) - 1;
    size_t            sfx_len    = sizeof(suffix) - 1;
    size_t            total      = pfx_len + name->u8_bytes + sfx_len;
    char *buf = n00b_alloc_array_with_opts(
        char,
        total + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, prefix, pfx_len);
    memcpy(buf + pfx_len, name->data, name->u8_bytes);
    memcpy(buf + pfx_len + name->u8_bytes, suffix, sfx_len);
    buf[total] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)total,
                                .allocator = alloc_for_call);
}

// Re-compute sha256 of `body` and compare against the requested
// digest string (`sha256:<hex>`). Returns true if they match.
static bool
verify_blob_digest(n00b_buffer_t    *body,
                   n00b_string_t    *expected_digest,
                   n00b_allocator_t *alloc_for_call)
{
    if (body == nullptr || expected_digest == nullptr) {
        return false;
    }
    auto dr = n00b_attest_oci_digest_of_buffer(body,
                                                .allocator = alloc_for_call);
    if (n00b_result_is_err(dr)) {
        return false;
    }
    n00b_string_t *got = n00b_result_get(dr);
    if (got == nullptr) {
        return false;
    }
    return n00b_string_byte_eq(got, expected_digest);
}

// Common body shared by `_blob_fetch` and `_manifest_fetch`. The
// only differences are the path prefix (`blobs/` vs `manifests/`)
// and the integrity-failure error code (manifest disagreement
// surfaces `_OCI_MANIFEST_DIGEST_MISMATCH` from Phase 2; blob
// disagreement surfaces the new `_OCI_BLOB_DIGEST_MISMATCH`).
//
// Phase 3 does NOT thread an Accept header through the request:
// registries handle the OCI v2 GET paths without a caller-supplied
// Accept (real-world zot / ghcr.io / Harbor all return the
// canonical manifest content-type by default on
// `/v2/<n>/manifests/<d>`). Constructing the typed-dict header bag
// (which the `_request` helper expects under its `.headers` kwarg)
// would force an `n00b_dict_init`-style construction site here for
// a single hard-coded entry; we keep that overhead out of the hot
// path for Phase 3. A future hardening WP can promote Accept-header
// threading if a registry surfaces a problem.
static n00b_result_t(n00b_buffer_t *)
generic_fetch(n00b_attest_oci_client_t *client,
              n00b_string_t            *name,
              n00b_string_t            *digest,
              const char               *rest_pfx,
              size_t                    rest_pfx_len,
              n00b_err_t                digest_mismatch_code,
              uint64_t                  max_size,
              uint64_t                  timeout_ms,
              n00b_allocator_t         *alloc_for_call)
{
    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || digest == nullptr || digest->u8_bytes == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    size_t rest_len = rest_pfx_len + digest->u8_bytes;
    char  *rest_buf = n00b_alloc_array_with_opts(
        char,
        rest_len,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(rest_buf, rest_pfx, rest_pfx_len);
    memcpy(rest_buf + rest_pfx_len, digest->data, digest->u8_bytes);

    n00b_string_t *path = build_v2_path(name,
                                        rest_buf,
                                        rest_len,
                                        alloc_for_call);
    n00b_string_t *scope = build_pull_scope(name, alloc_for_call);

    auto get_r = n00b_attest_oci_request(client,
                                          r"GET",
                                          path,
                                          .scope      = scope,
                                          .timeout_ms = timeout_ms,
                                          .allocator  = alloc_for_call);
    if (n00b_result_is_err(get_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(get_r));
    }
    n00b_http_response_t *resp = n00b_result_get(get_r);
    int status = n00b_http_response_status(resp);
    if (status < 200 || status >= 300) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }

    n00b_buffer_t *body = n00b_http_response_body(resp);
    if (body == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_HTTP_ERROR);
    }

    uint64_t cap = max_size == 0
                       ? (uint64_t)N00B_ATTEST_OCI_PULL_DEFAULT_MAX_SIZE
                       : max_size;
    if ((uint64_t)body->byte_len > cap) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BLOB_TOO_LARGE);
    }

    if (!verify_blob_digest(body, digest, alloc_for_call)) {
        return n00b_result_err(n00b_buffer_t *, digest_mismatch_code);
    }

    // Copy the body into the caller's allocator. The HTTPS response
    // body lives in the response's allocator; we materialize a copy
    // so the returned buffer outlives the response handle.
    n00b_buffer_t *out = n00b_buffer_from_bytes(
        body->data,
        body->byte_len,
        .allocator = alloc_for_call);
    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_blob_fetch(n00b_attest_oci_client_t *client,
                           n00b_string_t            *name,
                           n00b_string_t            *digest)
    _kargs {
        uint64_t          max_size   = 0;
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }
    static const char rest_pfx[] = "blobs/";
    return generic_fetch(client,
                         name,
                         digest,
                         rest_pfx,
                         sizeof(rest_pfx) - 1,
                         N00B_ATTEST_ERR_OCI_BLOB_DIGEST_MISMATCH,
                         max_size,
                         timeout_ms,
                         alloc_for_call);
}

n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_manifest_fetch(n00b_attest_oci_client_t *client,
                               n00b_string_t            *name,
                               n00b_string_t            *digest)
    _kargs {
        uint64_t          max_size   = 0;
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }
    static const char rest_pfx[] = "manifests/";
    return generic_fetch(client,
                         name,
                         digest,
                         rest_pfx,
                         sizeof(rest_pfx) - 1,
                         N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH,
                         max_size,
                         timeout_ms,
                         alloc_for_call);
}

// ---------------------------------------------------------------------------
// Referrers listing — pagination via RFC 8288 `Link: </next>; rel="next"`.
// ---------------------------------------------------------------------------

// Parse one `<URL>; rel="next"` entry out of a `Link:` header value.
// Per RFC 8288, multiple `<URL>; rel="..."` entries may appear
// comma-separated. The helper scans the value once and returns the
// FIRST URL whose `rel` matches `"next"`. Returns nullptr if no
// rel="next" entry is found.
static n00b_string_t *
parse_link_next(n00b_buffer_t    *link_hdr,
                n00b_allocator_t *alloc_for_call)
{
    if (link_hdr == nullptr || link_hdr->byte_len < 4) {
        return nullptr;
    }
    const char *p   = link_hdr->data;
    const char *end = p + link_hdr->byte_len;

    while (p < end) {
        // Skip leading whitespace + commas.
        while (p < end && (*p == ' ' || *p == '\t' || *p == ','
                           || *p == '\r' || *p == '\n')) {
            p++;
        }
        if (p >= end || *p != '<') {
            // Malformed entry start; skip to next comma or EOH.
            while (p < end && *p != ',') {
                p++;
            }
            continue;
        }
        p++;  // past '<'
        const char *url_start = p;
        while (p < end && *p != '>') {
            p++;
        }
        if (p >= end) {
            return nullptr;
        }
        size_t      url_len = (size_t)(p - url_start);
        const char *cur_url = url_start;
        p++;  // past '>'

        // Walk params until the next comma or EOH.
        bool is_next = false;
        while (p < end && *p != ',') {
            // Skip whitespace + semicolons.
            while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) {
                p++;
            }
            if (p >= end || *p == ',') {
                break;
            }
            // Param name.
            const char *name_start = p;
            while (p < end && *p != '=' && *p != ';' && *p != ','
                   && *p != ' ' && *p != '\t') {
                p++;
            }
            size_t      name_len = (size_t)(p - name_start);
            if (p < end && *p == '=') {
                p++;
                bool quoted = false;
                if (p < end && *p == '"') {
                    quoted = true;
                    p++;
                }
                const char *val_start = p;
                if (quoted) {
                    while (p < end && *p != '"') {
                        p++;
                    }
                } else {
                    while (p < end && *p != ';' && *p != ',') {
                        p++;
                    }
                }
                size_t val_len = (size_t)(p - val_start);
                if (quoted && p < end && *p == '"') {
                    p++;
                }
                if (name_len == 3
                    && memcmp(name_start, "rel", 3) == 0
                    && val_len == 4
                    && memcmp(val_start, "next", 4) == 0) {
                    is_next = true;
                }
            }
        }

        if (is_next) {
            return n00b_string_from_raw(cur_url,
                                        (int64_t)url_len,
                                        .allocator = alloc_for_call);
        }
    }
    return nullptr;
}

// Resolve a Link-header `next` target into a `/v2/...`-relative
// path against `client->registry_origin`. Same logic as
// `location_to_path` from the push side, but takes an
// `n00b_string_t *` (the parsed URL) rather than a raw buffer.
static n00b_string_t *
link_target_to_path(n00b_attest_oci_client_t *client,
                    n00b_string_t            *target,
                    n00b_allocator_t         *alloc_for_call)
{
    if (target == nullptr || target->u8_bytes == 0) {
        return nullptr;
    }
    const char *data = target->data;
    size_t      len  = target->u8_bytes;

    if (len >= 8 && memcmp(data, "https://", 8) == 0) {
        size_t i = 8;
        while (i < len && data[i] != '/') {
            i++;
        }
        if (client->registry_origin != nullptr
            && client->registry_origin->u8_bytes == i
            && memcmp(client->registry_origin->data, data, i) == 0) {
            return n00b_string_from_raw(data + i,
                                        (int64_t)(len - i),
                                        .allocator = alloc_for_call);
        }
        // Cross-origin pagination is not in scope for Phase 3.
        return nullptr;
    }

    return n00b_string_from_raw(data,
                                (int64_t)len,
                                .allocator = alloc_for_call);
}

// Extract a string-valued annotation by key from a parsed referrer
// manifest's `annotations` object. Returns nullptr if the key is
// missing or the value isn't a string.
static n00b_string_t *
get_annotation_str(n00b_json_node_t *annotations,
                   n00b_string_t    *key,
                   n00b_allocator_t *alloc_for_call)
{
    if (annotations == nullptr || !n00b_json_is_object(annotations)) {
        return nullptr;
    }
    n00b_json_node_t *v = n00b_attest_json_obj_lookup(annotations, key);
    const char *s = n00b_json_as_cstr(v);
    if (s == nullptr) {
        return nullptr;
    }
    return n00b_string_from_cstr(s, .allocator = alloc_for_call);
}

// Append a single page's `manifests[]` entries to the output list.
// Returns Ok(true) on success; Err on malformed-shape failures.
// The parser deliberately tolerates partial entries (missing
// annotations are reported as nullptr; missing `digest` field is a
// hard error and surfaces _OCI_BAD_REFERRER_INDEX).
static n00b_result_t(bool)
append_referrers_page(n00b_list_t(n00b_attest_oci_referrer_t *) *out,
                      n00b_buffer_t                              *body,
                      n00b_allocator_t                           *alloc_for_call)
{
    // WP-004 Phase 4 hardening (NFR-5): libn00b's `n00b_json_parse`
    // enforces a hard-coded `max_depth = 256` (see comment at top of
    // this file); well above NFR-5's floor of 32, so no per-call
    // depth threading is necessary here.
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             body->byte_len,
                                             &err);
    if (root == nullptr || !n00b_json_is_object(root)) {
        return n00b_result_err(bool,
                               N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
    }
    n00b_json_node_t *manifests = n00b_attest_json_obj_lookup(root,
                                                              r"manifests");
    if (manifests == nullptr) {
        // OCI index without `manifests[]` is a valid empty index per
        // some non-strict registries; treat as zero-entries.
        return n00b_result_ok(bool, true);
    }
    if (!n00b_json_is_array(manifests)) {
        return n00b_result_err(bool,
                               N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
    }

    size_t n = n00b_json_array_len(manifests);
    for (size_t i = 0; i < n; i++) {
        n00b_json_node_t *entry = n00b_json_array_get(manifests, i);
        if (!n00b_json_is_object(entry)) {
            return n00b_result_err(bool,
                                   N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
        }
        n00b_json_node_t *digest_node = n00b_attest_json_obj_lookup(
            entry,
            r"digest");
        const char *digest_s = n00b_json_as_cstr(digest_node);
        if (digest_s == nullptr) {
            return n00b_result_err(bool,
                                   N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
        }
        n00b_json_node_t *ann = n00b_attest_json_obj_lookup(entry,
                                                            r"annotations");

        n00b_attest_oci_referrer_t *r = n00b_alloc_with_opts(
            n00b_attest_oci_referrer_t,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        r->manifest_digest = n00b_string_from_cstr(digest_s,
                                                    .allocator = alloc_for_call);
        r->predicate_type = get_annotation_str(
            ann,
            r"com.crashoverride.attestation.predicate-type",
            alloc_for_call);
        r->signer_keyid = get_annotation_str(
            ann,
            r"com.crashoverride.attestation.signer-keyid",
            alloc_for_call);
        r->manifest_bytes = nullptr;
        n00b_list_push(*out, r);
    }
    return n00b_result_ok(bool, true);
}

// Build the initial /v2/<name>/referrers/<digest>[?artifactType=...]
// path used by the first page request. The artifact_type value is
// URL-encoded so media-type characters like `+` (which would be
// interpreted as a space in query strings) survive the round trip.
static n00b_string_t *
build_referrers_path(n00b_string_t    *name,
                     n00b_string_t    *image_digest,
                     n00b_string_t    *artifact_type,
                     n00b_allocator_t *alloc_for_call)
{
    if (name == nullptr || image_digest == nullptr) {
        return nullptr;
    }
    size_t         rest_pfx_len = 10;  // "referrers/"
    n00b_string_t *at_enc       = nullptr;
    size_t         at_q_len     = 0;
    if (artifact_type != nullptr && artifact_type->u8_bytes > 0) {
        at_enc = url_encode(artifact_type, alloc_for_call);
        if (at_enc != nullptr) {
            at_q_len = 14 + at_enc->u8_bytes;  // "?artifactType=" + value
        }
    }
    size_t rest_len = rest_pfx_len + image_digest->u8_bytes + at_q_len;
    char *rest_buf = n00b_alloc_array_with_opts(
        char,
        rest_len,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(rest_buf, "referrers/", rest_pfx_len);
    memcpy(rest_buf + rest_pfx_len,
           image_digest->data,
           image_digest->u8_bytes);
    if (at_q_len > 0) {
        size_t o = rest_pfx_len + image_digest->u8_bytes;
        memcpy(rest_buf + o, "?artifactType=", 14);
        o += 14;
        memcpy(rest_buf + o, at_enc->data, at_enc->u8_bytes);
    }
    return build_v2_path(name, rest_buf, rest_len, alloc_for_call);
}

n00b_result_t(n00b_list_t(n00b_attest_oci_referrer_t *) *)
n00b_attest_oci_list_referrers(n00b_attest_oci_client_t *client,
                               n00b_string_t            *name,
                               n00b_string_t            *image_digest)
    _kargs {
        n00b_string_t    *artifact_type = nullptr;
        uint64_t          timeout_ms    = 0;
        n00b_allocator_t *allocator     = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || image_digest == nullptr || image_digest->u8_bytes == 0) {
        return n00b_result_err(n00b_list_t(n00b_attest_oci_referrer_t *) *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    // WP-004 Phase 4 hardening (D-051 OQ-8): resolve the per-page
    // effective timeout. Precedence chain mirrors push/pull:
    //   op-level kwarg (non-zero) → client->timeout_ms (non-zero) →
    //   discover-specific default (10s).
    // The discover-side default is the smallest of the three per-op
    // defaults because each pagination request is a single small GET.
    uint64_t effective_timeout = timeout_ms != 0
                                     ? timeout_ms
                                     : (client->timeout_ms != 0
                                            ? client->timeout_ms
                                            : N00B_ATTEST_OCI_DISCOVER_DEFAULT_TIMEOUT_MS);

    // Allocate the output list under the per-call allocator. The
    // wrapper is a struct-by-value but we hand back a pointer; the
    // memcpy + lock-pointer behavior of n00b_list is preserved by
    // initializing via n00b_list_new.
    n00b_list_t(n00b_attest_oci_referrer_t *) *out = n00b_alloc_with_opts(
        n00b_list_t(n00b_attest_oci_referrer_t *),
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    *out = n00b_list_new(n00b_attest_oci_referrer_t *,
                         .allocator = alloc_for_call);

    n00b_string_t *scope = build_pull_scope(name, alloc_for_call);
    n00b_string_t *next_path = build_referrers_path(name,
                                                    image_digest,
                                                    artifact_type,
                                                    alloc_for_call);

    for (size_t page_idx = 0;
         page_idx < N00B_ATTEST_OCI_REFERRERS_MAX_PAGES
         && next_path != nullptr;
         page_idx++) {
        auto get_r = n00b_attest_oci_request(client,
                                              r"GET",
                                              next_path,
                                              .scope      = scope,
                                              .timeout_ms = effective_timeout,
                                              .allocator  = alloc_for_call);
        if (n00b_result_is_err(get_r)) {
            return n00b_result_err(
                n00b_list_t(n00b_attest_oci_referrer_t *) *,
                n00b_result_get_err(get_r));
        }
        n00b_http_response_t *resp = n00b_result_get(get_r);
        int status = n00b_http_response_status(resp);

        if (status == 404) {
            // Per OCI spec § 4.5: some registries 404 a subject
            // that has no referrers. Treat as Ok([]) — the caller's
            // semantic is "give me the referrers"; both 200+empty
            // and 404 answer "none."
            return n00b_result_ok(
                n00b_list_t(n00b_attest_oci_referrer_t *) *,
                out);
        }
        if (status < 200 || status >= 300) {
            return n00b_result_err(
                n00b_list_t(n00b_attest_oci_referrer_t *) *,
                N00B_ATTEST_ERR_OCI_HTTP_ERROR);
        }

        n00b_buffer_t *body = n00b_http_response_body(resp);
        if (body == nullptr || body->byte_len == 0) {
            // Empty body on success — treat as empty page (some
            // registries return 200 with empty body when there are
            // no referrers).
            next_path = nullptr;
            continue;
        }

        // WP-004 Phase 4 hardening (NFR-5): enforce the 1 MiB
        // per-page response-body cap. libn00b's
        // `n00b_http_request_sync` does NOT (yet) carry a per-call
        // `max_body_size` kwarg, so the cap is enforced here against
        // the parsed response body. The libn00b gap is tracked as
        // DF-014; once libn00b lifts a body-size kwarg the
        // enforcement can move into the dispatcher and the response
        // body never materializes past the cap. JSON depth-cap
        // inheritance documented at the top of this file
        // (`max_depth = 256` in libn00b's parser).
        if ((uint64_t)body->byte_len
            > N00B_ATTEST_OCI_REFERRERS_DEFAULT_MAX_PAGE_SIZE) {
            return n00b_result_err(
                n00b_list_t(n00b_attest_oci_referrer_t *) *,
                N00B_ATTEST_ERR_OCI_RESPONSE_TOO_LARGE);
        }

        auto pa_r = append_referrers_page(out, body, alloc_for_call);
        if (n00b_result_is_err(pa_r)) {
            return n00b_result_err(
                n00b_list_t(n00b_attest_oci_referrer_t *) *,
                n00b_result_get_err(pa_r));
        }

        // RFC 8288: parse `Link: </path>; rel="next"` for pagination.
        n00b_buffer_t *link_hdr = n00b_http_response_header(resp, r"Link");
        if (link_hdr == nullptr || link_hdr->byte_len == 0) {
            next_path = nullptr;
            continue;
        }
        n00b_string_t *next_link = parse_link_next(link_hdr, alloc_for_call);
        if (next_link == nullptr) {
            next_path = nullptr;
            continue;
        }
        next_path = link_target_to_path(client, next_link, alloc_for_call);
        if (next_path == nullptr) {
            // Cross-origin or unparseable; stop walking.
            break;
        }
    }

    return n00b_result_ok(n00b_list_t(n00b_attest_oci_referrer_t *) *,
                          out);
}

// ---------------------------------------------------------------------------
// Pull-envelope orchestrator.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_pull_envelope(n00b_attest_oci_client_t *client,
                              n00b_string_t            *name,
                              n00b_string_t            *manifest_digest)
    _kargs {
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;
    if (alloc_for_call == nullptr && client != nullptr) {
        alloc_for_call = client->allocator;
    }

    if (client == nullptr || name == nullptr || name->u8_bytes == 0
        || manifest_digest == nullptr || manifest_digest->u8_bytes == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BAD_URL);
    }

    // WP-004 Phase 4 hardening (D-051 OQ-8): resolve the per-sub-
    // request effective timeout. Precedence chain:
    //   op-level kwarg (non-zero) → client->timeout_ms (non-zero) →
    //   pull-specific default (30s).
    // Each of the two sub-fetches (manifest + blob) inherits the
    // same resolved value so the caller's deadline applies per
    // round-trip rather than cumulatively (matches the doxygen on
    // the public surface).
    uint64_t effective_timeout = timeout_ms != 0
                                     ? timeout_ms
                                     : (client->timeout_ms != 0
                                            ? client->timeout_ms
                                            : N00B_ATTEST_OCI_PULL_DEFAULT_TIMEOUT_MS);

    // 1. Fetch the referrer manifest.
    auto mf_r = n00b_attest_oci_manifest_fetch(client,
                                                name,
                                                manifest_digest,
                                                .timeout_ms = effective_timeout,
                                                .allocator = alloc_for_call);
    if (n00b_result_is_err(mf_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(mf_r));
    }
    n00b_buffer_t *manifest_bytes = n00b_result_get(mf_r);

    // 2. Walk layers[0].digest. The libn00b JSON parser enforces a
    //    `max_depth = 256` cap (documented at the top of this file);
    //    well above NFR-5's floor of 32. No per-call depth threading
    //    is necessary at the OCI client layer.
    const char       *jerr = nullptr;
    n00b_json_node_t *root = n00b_json_parse(manifest_bytes->data,
                                             manifest_bytes->byte_len,
                                             &jerr);
    if (root == nullptr || !n00b_json_is_object(root)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
    }
    n00b_json_node_t *layers = n00b_attest_json_obj_lookup(root, r"layers");
    if (layers == nullptr || !n00b_json_is_array(layers)
        || n00b_json_array_len(layers) != 1) {
        // Spec §8.2 in-toto+dsse referrer manifest has a single layer.
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
    }
    n00b_json_node_t *layer = n00b_json_array_get(layers, 0);
    if (!n00b_json_is_object(layer)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
    }
    n00b_json_node_t *layer_digest = n00b_attest_json_obj_lookup(layer,
                                                                 r"digest");
    const char *layer_digest_s = n00b_json_as_cstr(layer_digest);
    if (layer_digest_s == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX);
    }
    n00b_string_t *blob_digest = n00b_string_from_cstr(
        layer_digest_s,
        .allocator = alloc_for_call);

    // 3. Fetch the envelope blob.
    auto bf_r = n00b_attest_oci_blob_fetch(client,
                                            name,
                                            blob_digest,
                                            .timeout_ms = effective_timeout,
                                            .allocator = alloc_for_call);
    if (n00b_result_is_err(bf_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(bf_r));
    }
    return bf_r;
}

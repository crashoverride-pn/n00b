/*
 * http_proxy.c — HTTP_PROXY / HTTPS_PROXY / NO_PROXY resolution for the n00b
 * h1 HTTP client.
 *
 * Deliberately does its own small ASCII-only tokenizing rather than reusing
 * `n00b_http_url_parse()`: that parser rejects userinfo and defaults to
 * HTTPS-only (RFC 9110 §4.2.4 / the Phase 6 plan's §2.2), which is the wrong
 * shape for a `http://user:pass@host:port` proxy value. Hosts/ports here are
 * plain ASCII by construction (env var values), so this mirrors the raw
 * byte-level style `http_url.c` already uses for the same reason.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>

#include "n00b.h"
#include "core/env.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/alloc.h"
#include "adt/array.h"
#include "adt/result.h"
#include "crypto/base64.h"
#include "text/strings/string_ops.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_proxy.h"

static n00b_string_t *
proxy_env(n00b_string_t *name)
{
    n00b_string_t *v = n00b_getenv(name);
    if (!v || v->u8_bytes == 0) {
        return nullptr;
    }
    return v;
}

static bool
ascii_ieq(const char *a, size_t alen, const char *b, size_t blen)
{
    if (alen != blen) {
        return false;
    }
    for (size_t i = 0; i < alen; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + ('a' - 'A'));
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

/* Require a domain boundary ("." + suffix) so NO_PROXY=example.com cannot
 * accidentally exclude notexample.com. */
static bool
ascii_iendswith_dotted(const char *host, size_t host_len,
                       const char *suffix, size_t suffix_len)
{
    if (host_len < suffix_len + 1) {
        return false;
    }
    size_t off = host_len - suffix_len - 1;
    if (host[off] != '.') {
        return false;
    }
    return ascii_ieq(host + off + 1, suffix_len, suffix, suffix_len);
}

static bool
no_proxy_excludes(n00b_string_t *host)
{
    n00b_string_t *raw = proxy_env(r"no_proxy");
    if (!raw) {
        raw = proxy_env(r"NO_PROXY");
    }
    if (!raw) {
        return false;
    }

    n00b_array_t(n00b_string_t *) entries = n00b_unicode_str_split(raw, r",");
    int64_t n = (int64_t)n00b_array_len(entries);

    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *tok = n00b_unicode_str_trim(n00b_array_get(entries, i));
        if (tok->u8_bytes == 0) {
            continue;
        }
        const char *ed   = tok->data;
        size_t      elen = tok->u8_bytes;

        if (elen == 1 && ed[0] == '*') {
            return true; /* NO_PROXY=* — common "disable proxying" idiom */
        }
        if (ed[0] == '.') { /* normalize leading-dot form to bare domain */
            ed++;
            elen--;
        }
        if (elen == 0) {
            continue;
        }
        if (ascii_ieq(host->data, host->u8_bytes, ed, elen)) {
            return true;
        }
        if (ascii_iendswith_dotted(host->data, host->u8_bytes, ed, elen)) {
            return true;
        }
    }
    return false;
}

static bool
scheme_is_https(n00b_string_t *scheme)
{
    return scheme != nullptr && scheme->u8_bytes == 5
        && ascii_ieq(scheme->data, 5, "https", 5);
}

static uint16_t
parse_port(const char *p, size_t len, uint16_t fallback)
{
    if (len == 0 || len > 5) {
        return fallback;
    }
    uint32_t v = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return fallback;
        }
        v = v * 10 + (uint32_t)(p[i] - '0');
        if (v > 65535) {
            return fallback;
        }
    }
    return v == 0 ? fallback : (uint16_t)v;
}

/* Accepts "[scheme://][user:pass@]host[:port][/...]" — the shape every
 * common tool's HTTP_PROXY/HTTPS_PROXY value takes. Any path suffix is
 * ignored (proxy vars shouldn't carry one, but don't misparse one as part
 * of the host if it does). IPv6-literal proxy addresses are not supported. */
static n00b_http_proxy_route_t
parse_proxy_url(n00b_string_t *raw, n00b_allocator_t *a)
{
    n00b_http_proxy_route_t none = {0};

    char  *p   = raw->data;
    size_t len = raw->u8_bytes;

    uint16_t default_port = 80;
    bool     scheme_is_https_proxy = false;
    if (len >= 8 && ascii_ieq(p, 8, "https://", 8)) {
        p += 8;
        len -= 8;
        default_port = 443;
        scheme_is_https_proxy = true;
    }
    else if (len >= 7 && ascii_ieq(p, 7, "http://", 7)) {
        p += 7;
        len -= 7;
    }

    for (size_t i = 0; i < len; i++) {
        if (p[i] == '/') {
            len = i;
            break;
        }
    }
    if (len == 0) {
        return none;
    }

    char  *userinfo     = nullptr;
    size_t userinfo_len = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == '@') {
            userinfo     = p;
            userinfo_len = i;
            p += i + 1;
            len -= i + 1;
            break;
        }
    }
    if (len == 0) {
        return none;
    }

    char    *host     = p;
    size_t   host_len = len;
    uint16_t port     = default_port;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == ':') {
            host_len = i;
            port     = parse_port(p + i + 1, len - i - 1, default_port);
            break;
        }
    }
    if (host_len == 0) {
        return none;
    }

    n00b_http_proxy_route_t route = {0};
    route.active       = true;
    route.host         = n00b_string_from_raw(host, (int64_t)host_len, .allocator = a);
    route.port         = port;
    route.requires_tls = scheme_is_https_proxy;

    if (userinfo != nullptr) {
        n00b_buffer_t *creds = n00b_buffer_from_bytes(userinfo,
                                                      (int64_t)userinfo_len,
                                                      .allocator = a);
        auto enc_r = n00b_base64_encode(creds, .allocator = a);
        if (n00b_result_is_ok(enc_r)) {
            n00b_string_t *b64     = n00b_result_get(enc_r);
            size_t         hdr_cap = 40 + b64->u8_bytes;
            char          *hdr     = n00b_alloc_array_with_opts(
                char, hdr_cap, &(n00b_alloc_opts_t){.allocator = a});
            int hdr_len = snprintf(hdr, hdr_cap,
                                   "Proxy-Authorization: Basic %.*s\r\n",
                                   (int)b64->u8_bytes, b64->data);
            route.proxy_auth_header = n00b_string_from_raw(
                hdr, hdr_len, .allocator = a);
        }
    }

    return route;
}

n00b_http_proxy_route_t
n00b_http_proxy_resolve(n00b_http_url_t *url)
{
    n00b_http_proxy_route_t none = {0};

    if (!url || !url->host || url->host->u8_bytes == 0) {
        return none;
    }
    if (no_proxy_excludes(url->host)) {
        return none;
    }

    n00b_allocator_t *a = nullptr; /* runtime default arena: the route is
                                    * consumed immediately by one connect
                                    * call, not retained long-term. */

    n00b_string_t *raw = nullptr;
    if (scheme_is_https(url->scheme)) {
        raw = proxy_env(r"https_proxy");
        if (!raw) {
            raw = proxy_env(r"HTTPS_PROXY");
        }
    }
    if (!raw) {
        raw = proxy_env(r"http_proxy");
    }
    if (!raw) {
        raw = proxy_env(r"HTTP_PROXY");
    }
    if (!raw) {
        return none;
    }

    return parse_proxy_url(raw, a);
}

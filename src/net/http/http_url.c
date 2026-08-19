/*
 * http_url.c — HTTPS URL parser for the n00b HTTP client.
 *
 * Phase 6, chunk 1 (~/dd/quic_6.md § 7).  Splits an absolute HTTPS
 * URL into the structured form `n00b_http_url_t` so the dispatcher
 * (chunk 5) and transport paths (chunks 2 + 3) don't each re-tokenize
 * the input.
 *
 * Conformance:
 *   - RFC 3986 § 3 for the syntax skeleton (scheme + authority + path
 *     + query); IPv6 literals via § 3.2.2's `[…]` form.
 *   - RFC 9110 § 4.2.4 — userinfo MUST NOT appear in HTTP URIs;
 *     reject explicitly.
 *   - HTTPS only: § 2.2 of the Phase 6 plan rejects `http://` here
 *     so blunders never reach the transport.
 *   - UTS #46 IDNA ToASCII for DNS-label hosts (DF-X): non-ASCII host
 *     labels are converted to their ACE / Punycode form at parse
 *     time, so every downstream consumer (allowlist matcher, cookie
 *     jar, Host header, TLS SNI, getaddrinfo, alt-svc) sees a pure-
 *     ASCII canonical host.  IPv4 dotted-quads survive byte-
 *     identically (UTS-46 is a fixed point on them); IPv6 literals
 *     bypass IDNA entirely (`[::1]` is bracketed-hex, not a DNS
 *     label).
 *
 * Path / query canonicalization (percent-decode, dot-segment
 * removal) remains a transport-layer concern; URLs are tokenized
 * here but not normalized beyond authority.
 */

#define N00B_USE_INTERNAL_API
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "n00b.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "internal/net/http/http_url.h"
#include "text/unicode/idna.h"

/* ----------------------------------------------------------------- */
/* Local helpers                                                     */
/* ----------------------------------------------------------------- */

static inline bool
is_digit_byte(unsigned char b)
{
    return b >= '0' && b <= '9';
}

static inline bool
is_ipv6_byte(unsigned char b)
{
    /* IPv6 literal payload between [ and ]: hex digits, ':', '.'
     * (for IPv4-mapped), and '%' for zone IDs (RFC 6874).  Anything
     * else means a malformed authority. */
    if (is_digit_byte(b)) return true;
    if (b >= 'a' && b <= 'f') return true;
    if (b >= 'A' && b <= 'F') return true;
    return b == ':' || b == '.' || b == '%';
}

static n00b_string_t *
copy_slice(const char *p, size_t len, n00b_allocator_t *allocator)
{
    return n00b_string_from_raw(p, (int64_t)len, .allocator = allocator);
}

static n00b_string_t *
lowercase_ascii_slice(const char *p, size_t len, n00b_allocator_t *allocator)
{
    /* RFC 3986 § 3.2.2: scheme + IP-literal host comparisons are
     * case-insensitive on ASCII.  Used for the scheme slice and for
     * IPv6-literal host payloads (hex digits + `:` + `.` + `%`),
     * where IDNA does not apply.  DNS-label hosts are handled by
     * `canonicalize_host_slice` below, which runs UTS #46 ToASCII.
     *
     * We lowercase into a scratch buffer and then construct the
     * (immutable) n00b_string_t — never mutate a string after init. */
    char  stack[128];
    char *tmp;
    if (len < sizeof(stack)) {
        tmp = stack;
    } else {
        tmp = n00b_alloc_array(char, len, .allocator = allocator);
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        tmp[i] = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : (char)c;
    }
    return n00b_string_from_raw(tmp, (int64_t)len, .allocator = allocator);
}

/* Canonicalize a DNS-label host slice to its UTS #46 ASCII-Compatible
 * Encoding (ACE / Punycode) form.  Pure-ASCII labels are emitted
 * byte-identically (modulo UTS-46 case-folding, which lowercases the
 * ASCII alphabet); non-ASCII labels become `xn--…` Punycode; IPv4
 * dotted-quads are a fixed point of the function (each octet 0-255
 * is a valid pure-ASCII DNS label, leaving the input unchanged).
 *
 * Returns nullptr iff UTS-46 reports any error (invalid UTF-8,
 * disallowed codepoint, BIDI rule violation, label/domain too long,
 * Punycode failure, etc.).  Callers in this file map a nullptr
 * return to `N00B_HTTP_ERR_HOST_INVALID` — a bad-IDN host is a
 * parse-time failure, not a silent fallback to raw bytes.
 *
 * IPv6 literals are bracketed-hex and must NOT be passed here; the
 * parser dispatches to `lowercase_ascii_slice` for that branch. */
static n00b_string_t *
canonicalize_host_slice(const char *p, size_t len, n00b_allocator_t *allocator)
{
    n00b_string_t *raw = n00b_string_from_raw(p, (int64_t)len,
                                              .allocator = allocator);
    if (!raw) return nullptr;
    n00b_unicode_idna_result_t r = n00b_unicode_idna_to_ascii(raw,
                                                              .allocator = allocator);
    if (r.error != N00B_UNICODE_IDNA_OK) return nullptr;
    if (!r.value || r.value->u8_bytes == 0) return nullptr;
    return r.value;
}

static n00b_string_t *
build_origin(n00b_string_t    *host,
             bool              is_ipv6_literal,
             uint16_t          port,
             bool              has_explicit_port,
             bool              is_http_scheme,
             n00b_allocator_t *allocator)
{
    /* "<scheme>://" + maybe-bracketed host + optional :port — kept
     * as one buffer + final string copy; cheaper than
     * n00b_string_concat for a hot path the dispatcher will hit on
     * every request. */
    const char *scheme_prefix     = is_http_scheme ? "http://" : "https://";
    size_t      scheme_prefix_len = is_http_scheme ? 7         : 8;
    uint16_t    default_port      = is_http_scheme ? 80        : 443;

    char   scratch[128];
    char  *out;
    bool   omit_port = !has_explicit_port || port == default_port;
    size_t brackets  = is_ipv6_literal ? 2 : 0;
    size_t port_len  = 0;
    char   port_buf[8];
    if (!omit_port) {
        int n = snprintf(port_buf, sizeof(port_buf), ":%u",
                         (unsigned)port);
        port_len = (n > 0) ? (size_t)n : 0;
    }
    size_t need = scheme_prefix_len
                + brackets
                + host->u8_bytes
                + port_len;

    if (need < sizeof(scratch)) {
        out = scratch;
    } else {
        out = n00b_alloc_array(char, need, .allocator = allocator);
    }
    size_t off = 0;
    memcpy(out + off, scheme_prefix, scheme_prefix_len);
    off += scheme_prefix_len;
    if (is_ipv6_literal) {
        out[off++] = '[';
    }
    memcpy(out + off, host->data, host->u8_bytes);
    off += host->u8_bytes;
    if (is_ipv6_literal) {
        out[off++] = ']';
    }
    if (port_len) {
        memcpy(out + off, port_buf, port_len);
        off += port_len;
    }
    return n00b_string_from_raw(out, (int64_t)off, .allocator = allocator);
}

/* ----------------------------------------------------------------- */
/* Parser                                                             */
/* ----------------------------------------------------------------- */

n00b_result_t(n00b_http_url_t *)
n00b_http_url_parse(n00b_string_t *url)
    _kargs {
        n00b_allocator_t *allocator       = nullptr;
        bool              allow_plain_http = false;
    }
{
    if (!url || !url->data) {
        return n00b_result_err(n00b_http_url_t *,
                               N00B_HTTP_ERR_NULL_ARG);
    }

    const char *p   = url->data;
    const char *end = p + url->u8_bytes;

    /* Scheme: "https://" (case-insensitive), or "http://" when the
     * caller opted in via `allow_plain_http = true`. */
    bool             is_http_scheme  = false;
    static const char HTTPS_SCHEME[] = "https://";
    static const char HTTP_SCHEME[]  = "http://";
    const size_t      hsl            = sizeof(HTTPS_SCHEME) - 1;
    const size_t      hl             = sizeof(HTTP_SCHEME)  - 1;

    if ((size_t)(end - p) >= hsl) {
        bool matches_https = true;
        for (size_t i = 0; i < hsl; i++) {
            char want = HTTPS_SCHEME[i];
            char have = p[i];
            if (have >= 'A' && have <= 'Z') have = (char)(have + ('a' - 'A'));
            if (have != want) { matches_https = false; break; }
        }
        if (matches_https) {
            p += hsl;
            goto scheme_done;
        }
    }
    if (allow_plain_http && (size_t)(end - p) >= hl) {
        bool matches_http = true;
        for (size_t i = 0; i < hl; i++) {
            char want = HTTP_SCHEME[i];
            char have = p[i];
            if (have >= 'A' && have <= 'Z') have = (char)(have + ('a' - 'A'));
            if (have != want) { matches_http = false; break; }
        }
        if (matches_http) {
            is_http_scheme = true;
            p += hl;
            goto scheme_done;
        }
    }
    return n00b_result_err(n00b_http_url_t *,
                           N00B_HTTP_ERR_UNSUPPORTED_SCHEME);

scheme_done:;

    /* Strip fragment up front: HTTP requests never send `#…` and we
     * do not want it appearing in path/query bytes. */
    const char *frag = memchr(p, '#', (size_t)(end - p));
    if (frag) {
        end = frag;
    }

    /* Authority extends to first `/`, `?`, or end (we already
     * trimmed `#`). */
    const char *auth_end = end;
    const char *q;
    for (q = p; q < end; q++) {
        if (*q == '/' || *q == '?') {
            auth_end = q;
            break;
        }
    }

    /* Userinfo check.  RFC 3986 syntactically allows `user@[::1]/`
     * but RFC 9110 § 4.2.4 forbids userinfo for HTTP URIs, so we
     * reject any `@` that appears BEFORE the optional `[` of an IPv6
     * literal.  An `@` *inside* `[...]` is a malformed host instead,
     * caught by the IPv6 validator below. */
    const char *userinfo_search_end = auth_end;
    if (p < auth_end && *p == '[') {
        userinfo_search_end = p;
    }
    if (memchr(p, '@', (size_t)(userinfo_search_end - p))) {
        return n00b_result_err(n00b_http_url_t *,
                               N00B_HTTP_ERR_USERINFO_REJECTED);
    }

    /* Host: bracketed IPv6 literal or bare. */
    bool        is_ipv6 = false;
    const char *host_start;
    const char *host_end;
    if (p < auth_end && *p == '[') {
        is_ipv6  = true;
        p++;                     /* consume `[` */
        host_start = p;
        const char *rb = memchr(p, ']', (size_t)(auth_end - p));
        if (!rb) {
            return n00b_result_err(n00b_http_url_t *,
                                   N00B_HTTP_ERR_HOST_INVALID);
        }
        host_end = rb;
        const char *hq;
        for (hq = host_start; hq < host_end; hq++) {
            if (!is_ipv6_byte((unsigned char)*hq)) {
                return n00b_result_err(n00b_http_url_t *,
                                       N00B_HTTP_ERR_HOST_INVALID);
            }
        }
        p = rb + 1;              /* past `]` */
    } else {
        host_start = p;
        while (p < auth_end && *p != ':') {
            p++;
        }
        host_end = p;
    }
    size_t host_len = (size_t)(host_end - host_start);
    if (host_len == 0) {
        return n00b_result_err(n00b_http_url_t *,
                               N00B_HTTP_ERR_HOST_EMPTY);
    }

    /* Optional :PORT.  Default depends on scheme: 443 for https, 80
     * for http (only reachable when the caller passes
     * `allow_plain_http = true`). */
    uint16_t port              = is_http_scheme ? 80 : 443;
    bool     has_explicit_port = false;
    if (p < auth_end && *p == ':') {
        p++;                     /* consume `:` */
        const char *port_start = p;
        unsigned long pv       = 0;
        while (p < auth_end && is_digit_byte((unsigned char)*p)) {
            pv = pv * 10 + (unsigned long)(*p - '0');
            if (pv > 65535) {
                return n00b_result_err(n00b_http_url_t *,
                                       N00B_HTTP_ERR_PORT_INVALID);
            }
            p++;
        }
        if (p == port_start || p != auth_end || pv == 0) {
            return n00b_result_err(n00b_http_url_t *,
                                   N00B_HTTP_ERR_PORT_INVALID);
        }
        port              = (uint16_t)pv;
        has_explicit_port = true;
    } else if (p != auth_end) {
        /* Garbage in the authority that wasn't a port. */
        return n00b_result_err(n00b_http_url_t *,
                               N00B_HTTP_ERR_INVALID_URL);
    }

    /* Path + query. */
    const char *path_start;
    size_t      path_len;
    const char *query_start = NULL;
    size_t      query_len   = 0;
    const char *q_marker    = memchr(auth_end, '?',
                                      (size_t)(end - auth_end));
    if (auth_end == end) {
        path_start = "/";
        path_len   = 1;
    } else if (*auth_end == '?') {
        path_start  = "/";
        path_len    = 1;
        query_start = auth_end + 1;
        query_len   = (size_t)(end - query_start);
    } else {
        path_start = auth_end;          /* points at the leading `/` */
        if (q_marker) {
            path_len    = (size_t)(q_marker - path_start);
            query_start = q_marker + 1;
            query_len   = (size_t)(end - query_start);
        } else {
            path_len = (size_t)(end - path_start);
        }
    }

    /* Canonicalize the host before constructing the result.  IPv6
     * literals are bracketed-hex and bypass IDNA; DNS-label hosts
     * (including IPv4 dotted-quads, which are a fixed point of
     * UTS-46) go through `canonicalize_host_slice`.  A failed IDNA
     * pass collapses the URL parse with `N00B_HTTP_ERR_HOST_INVALID`
     * — bad-IDN hosts never reach a transport. */
    n00b_string_t *host_str;
    if (is_ipv6) {
        host_str = lowercase_ascii_slice(host_start, host_len, allocator);
    } else {
        host_str = canonicalize_host_slice(host_start, host_len, allocator);
        if (!host_str) {
            return n00b_result_err(n00b_http_url_t *,
                                   N00B_HTTP_ERR_HOST_INVALID);
        }
    }

    /* Build result. */
    n00b_http_url_t *u = n00b_alloc(n00b_http_url_t,
                                    .allocator = allocator);
    u->scheme            = is_http_scheme
                              ? lowercase_ascii_slice("http", 4, allocator)
                              : lowercase_ascii_slice("https", 5, allocator);
    u->host              = host_str;
    u->is_ipv6_literal   = is_ipv6;
    u->port              = port;
    u->has_explicit_port = has_explicit_port;
    u->path              = copy_slice(path_start, path_len, allocator);
    u->query             = query_start
                              ? copy_slice(query_start, query_len, allocator)
                              : n00b_string_empty(.allocator = allocator);
    u->origin            = build_origin(u->host,
                                        is_ipv6,
                                        port,
                                        has_explicit_port,
                                        is_http_scheme,
                                        allocator);
    return n00b_result_ok(n00b_http_url_t *, u);
}

const char *
n00b_http_err_str(n00b_http_err_t err)
{
    switch (err) {
    case N00B_HTTP_OK:                     return "ok";
    case N00B_HTTP_ERR_NULL_ARG:           return "null argument";
    case N00B_HTTP_ERR_INVALID_URL:        return "invalid URL";
    case N00B_HTTP_ERR_UNSUPPORTED_SCHEME: return "unsupported scheme (https only)";
    case N00B_HTTP_ERR_USERINFO_REJECTED:  return "userinfo not allowed in HTTP URI";
    case N00B_HTTP_ERR_HOST_EMPTY:         return "empty host";
    case N00B_HTTP_ERR_HOST_INVALID:       return "invalid host";
    case N00B_HTTP_ERR_PORT_INVALID:       return "invalid port";
    case N00B_HTTP_ERR_BAD_RESPONSE:       return "malformed HTTP response";
    case N00B_HTTP_ERR_RESPONSE_TOO_LARGE: return "response body exceeded max_body_size cap";
    case N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED:
        return "redirect Location host not in caller's allowlist";
    case N00B_HTTP_ERR_PROXY_TLS_UNSUPPORTED:
        return "https:// proxy URL rejected (TLS-to-proxy not supported)";
    case N00B_HTTP_ERR_PROXY_MTLS_UNSUPPORTED:
        return "mTLS request rejected (proxy CONNECT not supported for mTLS)";
    }
    return "unknown error";
}

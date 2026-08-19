/**
 * @file http_proxy.h
 * @brief `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` resolution for the n00b
 *        h1 HTTP client.
 *
 * Every wax remote call goes through `h1_tls_connect()` in
 * `net/http/http_h1.c`, which is HTTPS-only. `n00b_http_proxy_resolve()`
 * decides, for a given target URL, whether an env-configured proxy applies
 * and what to dial instead of the origin.
 *
 * This is deliberately NOT a general RFC 3986 URL parser (that's
 * `http_url.h`, which rejects userinfo and defaults to HTTPS-only — the
 * wrong shape for a `http://user:pass@host:port` proxy value). The parser
 * here accepts the small, well-known shape proxy env vars actually use.
 */
#pragma once

#include "n00b.h"

typedef struct n00b_http_url n00b_http_url_t;

/**
 * @brief Result of resolving proxy env vars against a target URL.
 */
typedef struct {
    /** false => no proxy applies; dial the origin directly (today's
     *  behavior, unchanged). */
    bool            active;
    /** Proxy host to dial instead of the origin. Only meaningful when
     *  `active` is true. */
    n00b_string_t  *host;
    /** Proxy port to dial instead of the origin's port. */
    uint16_t        port;
    /** nullptr, or a complete `Proxy-Authorization: Basic <b64>\r\n` line
     *  (including the trailing CRLF) to splice into the CONNECT request
     *  when the proxy URL carried `user:pass@`. */
    n00b_string_t  *proxy_auth_header;
    /** true when the proxy URL used the `https://` scheme. The proxy
     *  CONNECT tunnel (`src/conduit/xform_tls.c`) only speaks plaintext
     *  HTTP to the proxy; it does not start TLS to the proxy itself.
     *  Callers MUST reject the request (`N00B_HTTP_ERR_PROXY_TLS_UNSUPPORTED`)
     *  rather than dial when `active && requires_tls`, so an `https://`
     *  proxy URL never causes a plaintext CONNECT + credential leak to a
     *  TLS-only proxy endpoint. */
    bool            requires_tls;
} n00b_http_proxy_route_t;

/**
 * @brief Decide whether `url` should be reached through a proxy, per the
 *        standard `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars (both-case
 *        variants checked; lowercase wins on conflict, matching common
 *        tooling convention — this process is a client, not a CGI/web
 *        server trusting inbound headers, so the "httpoxy" spoofing
 *        concern that motivates some tools to distrust `HTTP_PROXY`
 *        entirely does not apply here).
 *
 * For an `https` target: checks `https_proxy`, `HTTPS_PROXY`, then falls
 * back to `http_proxy`, `HTTP_PROXY`. For any other scheme: checks
 * `http_proxy`, `HTTP_PROXY` only.
 *
 * `no_proxy`/`NO_PROXY` (comma-separated hosts; a leading `.` or bare
 * domain matches that host and any subdomain) is always checked first —
 * a match short-circuits to `.active = false` regardless of the proxy
 * vars.
 *
 * @param url  The parsed target URL (only `->scheme` and `->host` are
 *             read). Must be non-null.
 * @return     `.active = false` if no proxy var is set, its value is
 *             unparseable, or the host is excluded by `NO_PROXY` — this
 *             is the common case and leaves connection behavior exactly
 *             as it is today.
 */
extern n00b_http_proxy_route_t
n00b_http_proxy_resolve(n00b_http_url_t *url);

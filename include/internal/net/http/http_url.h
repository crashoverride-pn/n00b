/**
 * @file http_url.h
 * @brief Internal URL parser for the n00b HTTP client (Phase 6, chunk 1).
 *
 * Parses absolute HTTPS URIs into a structured form the client layers
 * (`http_h1`, `http_h3`, `http_pool`, `http_alt_svc`) can route on
 * without re-tokenizing the input.  Scope follows
 * `~/dd/quic_6.md` § 2.1 — RFC 3986 with the relaxed real-world
 * conventions (port-less HTTPS defaults to 443; IPv6 literals in
 * `[…]`) — plus § 2.2: HTTPS-only, no userinfo.
 *
 * This header is **internal**: the URL parser is shared between the
 * h1 and h3 paths but is not part of the public n00b_http surface.
 * Operators interact with URLs through `n00b_http_request(url, ...)`
 * which performs the parse on their behalf.
 */
#pragma once

#include "n00b.h"

/**
 * @brief HTTP-layer error codes (chunk 1 introduces the URL set;
 * later chunks add transport / auth / cookie / compression codes).
 */
typedef enum : int32_t {
    N00B_HTTP_OK                       = 0,
    N00B_HTTP_ERR_NULL_ARG             = -1,
    N00B_HTTP_ERR_INVALID_URL          = -2,
    N00B_HTTP_ERR_UNSUPPORTED_SCHEME   = -3,
    N00B_HTTP_ERR_USERINFO_REJECTED    = -4,
    N00B_HTTP_ERR_HOST_EMPTY           = -5,
    N00B_HTTP_ERR_HOST_INVALID         = -6,
    N00B_HTTP_ERR_PORT_INVALID         = -7,

    /* Response-side codes (chunk 2). */
    N00B_HTTP_ERR_BAD_RESPONSE         = -8,

    /* Per-call policy codes (DF-014 / DF-015 lift). */
    /** Response body exceeded the caller-supplied `max_body_size`
     *  cap.  Raised before the body accumulator allocates past the
     *  cap, so the wire bytes never materialize past the limit. */
    N00B_HTTP_ERR_RESPONSE_TOO_LARGE   = -9,
    /** A 3xx redirect's Location header pointed at a host that is
     *  not present in the caller-supplied
     *  `redirect_host_allowlist`.  Raised before the next hop is
     *  dispatched so no traffic ever leaves for a disallowed host. */
    N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED = -10,
    /** `HTTP_PROXY`/`HTTPS_PROXY` resolved to an `https://` proxy URL.
     *  n00b's proxy CONNECT tunnel speaks plaintext HTTP to the proxy
     *  (RFC 9110 §9.3.6); it does not yet start TLS to the proxy
     *  itself. Raised before dialing the proxy so no CONNECT request
     *  or `Proxy-Authorization` credential is ever sent in cleartext
     *  to what the operator configured as a TLS-only proxy. */
    N00B_HTTP_ERR_PROXY_TLS_UNSUPPORTED     = -11,
    /** A request carries mTLS client-certificate auth AND a proxy
     *  route applies, but the HTTP/1 mTLS transport (`acme_tls`)
     *  cannot yet dial through a CONNECT proxy. Raised before any
     *  socket is opened so an mTLS request never silently bypasses
     *  configured proxy policy by connecting straight to the origin. */
    N00B_HTTP_ERR_PROXY_MTLS_UNSUPPORTED    = -12,
} n00b_http_err_t;

/**
 * @brief Parsed HTTPS URL.
 *
 * All `n00b_string_t *` fields are allocated from the runtime default
 * arena unless an `allocator` kwarg is passed to the parser.  Callers
 * MUST treat the struct as immutable after parse — write-back is not
 * supported.
 *
 * @c host         Host without IPv6 brackets.  For `https://[::1]:8443/`
 *                 this is `"::1"`, not `"[::1]"`.  Always pure ASCII
 *                 post-parse:
 *
 *                 - DNS-label hosts pass through UTS #46 ToASCII at
 *                   parse time (DF-X), so Unicode labels arrive as
 *                   `xn--…` Punycode.  Pure-ASCII labels are
 *                   byte-identical to their raw input modulo
 *                   UTS-46 case-folding (lowercased).
 *                 - IPv4 dotted-quads are a fixed point of UTS-46
 *                   (each octet `0-255` is a valid ASCII DNS label)
 *                   and survive unchanged.
 *                 - IPv6 literals bypass IDNA and are lowercased
 *                   per RFC 3986 § 3.2.2.
 *
 *                 Downstream consumers (allowlist matcher, cookie
 *                 jar, Host header, TLS SNI, `getaddrinfo`,
 *                 alt-svc) therefore see a canonical ACE-form host
 *                 without re-running IDNA themselves.
 * @c is_ipv6_literal  True iff the authority used the `[…]` form.
 * @c port              Effective port — explicit value if present,
 *                      otherwise 443 (the HTTPS default).
 * @c has_explicit_port True iff the URL spelled the port out.
 *                      Needed by the origin-canonicalization rule
 *                      (omit `:443` from the cache key).
 * @c path              Path with leading `/`.  Defaults to `"/"` when
 *                      the URL omits a path entirely.
 * @c query             Query without leading `?`.  Empty string if
 *                      no query was present.
 * @c origin            Canonical `https://host[:port]` for cache /
 *                      pool keys.  Port omitted iff
 *                      `has_explicit_port == false` OR
 *                      `port == 443`.  IPv6 hosts are re-bracketed
 *                      here (so the origin string is a parseable URL
 *                      prefix on its own).
 */
typedef struct n00b_http_url {
    n00b_string_t *scheme;
    n00b_string_t *host;
    bool           is_ipv6_literal;
    uint16_t       port;
    bool           has_explicit_port;
    n00b_string_t *path;
    n00b_string_t *query;
    n00b_string_t *origin;
} n00b_http_url_t;

/**
 * @brief Parse an absolute HTTPS URL.
 *
 * @param url  UTF-8 URL string (must begin with case-insensitive
 *             `https://`).  Fragment (`#…`) is stripped per
 *             RFC 9110 — HTTP requests never carry it.
 *
 * @kw allocator  Allocator for the returned struct + its strings.
 *                Defaults to the runtime default arena.
 *
 * @return  Result carrying a freshly allocated `n00b_http_url_t *`,
 *          or one of:
 *          - `N00B_HTTP_ERR_NULL_ARG`           on `url == nullptr`
 *          - `N00B_HTTP_ERR_UNSUPPORTED_SCHEME` for non-`https://`
 *          - `N00B_HTTP_ERR_USERINFO_REJECTED`  if the authority
 *                                               contains `user[:pass]@`
 *                                               (RFC 9110 § 4.2.4)
 *          - `N00B_HTTP_ERR_HOST_EMPTY`         if the host is empty
 *          - `N00B_HTTP_ERR_HOST_INVALID`       for a malformed IPv6
 *                                               literal OR a DNS-label
 *                                               host that UTS #46 ToASCII
 *                                               rejects (invalid UTF-8,
 *                                               disallowed codepoint,
 *                                               BIDI rule violation,
 *                                               label / domain too long,
 *                                               Punycode failure, etc.)
 *          - `N00B_HTTP_ERR_PORT_INVALID`       for a non-decimal,
 *                                               zero, or out-of-range port
 *          - `N00B_HTTP_ERR_INVALID_URL`        for any other shape error
 */
extern n00b_result_t(n00b_http_url_t *)
n00b_http_url_parse(n00b_string_t *url)
    _kargs {
        n00b_allocator_t *allocator       = nullptr;
        bool              allow_plain_http = false;
    };

/** @brief Stable static string for a parser error code (no allocation). */
extern const char *n00b_http_err_str(n00b_http_err_t err);

/**
 * @file http_client.h
 * @brief Public HTTP client API for n00b (Phase 6).
 *
 * Single entry point for issuing HTTP requests over h3 or h1 with
 * automatic transport selection, fallback, and per-runtime
 * connection pooling.  HTTPS only.
 *
 * @code
 *   auto rr = n00b_http_request_sync(n00b_string_from_cstr(
 *       "https://api.example.com/v1/widgets"));
 *   if (n00b_result_is_ok(rr)) {
 *       n00b_http_response_t *resp = n00b_result_get(rr);
 *       int status = n00b_http_response_status(resp);
 *       n00b_buffer_t *body = n00b_http_response_body(resp);
 *       …
 *   }
 * @endcode
 *
 * The conduit-shaped variant `n00b_http_request` (returns a topic so
 * sync + async share one entry point) lands in the next sub-chunk;
 * this header ships the synchronous form first so callers have a
 * stable surface to write against immediately.
 *
 * @see ~/dd/quic_6.md § 4 + § 5.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "adt/list.h"
#include "conduit/conduit.h"
#include "conduit/topic.h"
#include "conduit/inbox.h"
#include "conduit/subscription.h"
#include "conduit/rw.h"
#include "net/quic/quic_types.h"

/* ----------------------------------------------------------------- */
/* Response                                                          */
/* ----------------------------------------------------------------- */

/**
 * @brief Negotiated transport for an HTTP response.
 *
 * Purely informational — useful for verbose logging / dashboards.
 */
typedef enum : uint8_t {
    N00B_HTTP_TRANSPORT_UNKNOWN = 0,
    N00B_HTTP_TRANSPORT_H1      = 1,  /**< HTTP/1.1 over TCP+TLS */
    N00B_HTTP_TRANSPORT_H3      = 3,  /**< HTTP/3 over QUIC      */
} n00b_http_transport_t;

/** @brief Opaque parsed HTTP response. */
typedef struct n00b_http_response n00b_http_response_t;

/** @brief Numeric status code (100..599). */
extern int n00b_http_response_status(n00b_http_response_t *resp);

/** @brief Response body bytes.  Never nullptr; empty body = empty buffer. */
extern n00b_buffer_t *
n00b_http_response_body(n00b_http_response_t *resp);

/**
 * @brief Case-insensitive header lookup.
 *
 * @param resp  Response.
 * @param name  Header name, any case.
 * @return  Header value as a freshly heap-allocated buffer, or
 *          nullptr if absent.  Last-wins on duplicates.
 */
extern n00b_buffer_t *
n00b_http_response_header(n00b_http_response_t *resp,
                           n00b_string_t        *name);

/**
 * @brief Case-insensitive header lookup returning a NUL-terminated
 *        C string (convenience for ACME-style callers that pass the
 *        value to `strcmp`, `strtoul`, etc).
 *
 * @param resp  Response.
 * @param name  Header name (NUL-terminated, any case).
 * @return  Borrowed pointer into a freshly allocated string with
 *          the header value bytes + a trailing NUL.  nullptr if
 *          the header is absent.
 */
extern const char *
n00b_http_response_header_cstr(n00b_http_response_t *resp,
                                const char           *name);

/**
 * @brief Number of response headers (insertion-order).
 */
extern size_t n00b_http_response_n_headers(n00b_http_response_t *resp);

/**
 * @brief Read the i-th header pair.
 *
 * @param resp     Response.
 * @param idx      Zero-based index in [0, n_headers).
 * @param name_out Borrowed lowercased header name (NUL-terminated).
 * @param value_out Borrowed value (NUL-terminated).
 * @return  true if @p idx is in range, false otherwise.
 */
extern bool
n00b_http_response_header_at(n00b_http_response_t *resp,
                              size_t                idx,
                              n00b_string_t       **name_out,
                              n00b_buffer_t       **value_out);

/** @brief Negotiated transport (H1 or H3). */
extern n00b_http_transport_t
n00b_http_response_transport(n00b_http_response_t *resp);

/**
 * @brief Transport-level error code (0 on success).
 *
 * For successful HTTP responses (any status, including 4xx/5xx) this
 * is 0 and `n00b_http_response_status()` carries the status.  For
 * transport failures (DNS, TCP/TLS handshake, timeout, etc.) the
 * status is 0 and this carries the negative `n00b_quic_err_t` or
 * `n00b_http_err_t` code.  Pattern lets the topic-shaped dispatcher
 * publish either outcome through a single payload type.
 */
extern int32_t
n00b_http_response_error(n00b_http_response_t *resp);

/* Generate the typed-conduit machinery (message / inbox / subscription
 * / topic / read-write helpers) for `n00b_http_response_t *` payloads.
 * After this, callers can use `n00b_conduit_read(n00b_http_response_t *,
 * topic, .timeout_ms = ...)` for sync semantics and
 * `n00b_conduit_subscribe(n00b_http_response_t *, ...)` for async. */
N00B_CONDUIT_FULL_IMPL(n00b_http_response_t *);
N00B_CONDUIT_RW_IMPL(n00b_http_response_t *);

/* ----------------------------------------------------------------- */
/* Request                                                           */
/* ----------------------------------------------------------------- */

/* Forward-declared so we don't pull internal h1 types into the
 * public header.  Built via the chunk-2 internal API; chunk 12
 * exposes a public header bag if callers want to construct one
 * without using the chunk-2 internal header. */
typedef struct n00b_http_h1_headers      n00b_http_h1_headers_t;
typedef struct n00b_quic_trust           n00b_quic_trust_t;
typedef struct n00b_http_cookie_jar      n00b_http_cookie_jar_t;
typedef struct n00b_http_auth            n00b_http_auth_t;
typedef struct n00b_http_connection_pool n00b_http_connection_pool_t;

/**
 * @brief Issue a synchronous HTTPS request.
 *
 * Selects the transport per the kwargs (h3-first by default with
 * sequential h1 fallback), threads the round-trip through the
 * per-runtime connection pool (see
 * `n00b_http_get_connection_pool()`), and returns the parsed
 * response.
 *
 * @param url  Absolute HTTPS URL.  Required.
 *
 * @kw method        Method verb.  Default `"GET"`.
 * @kw body          Optional request body.
 * @kw content_type  Required if @p body is non-NULL.  No default —
 *                   callers pick (e.g. `"application/json"`).
 * @kw extra         Optional caller-supplied headers (chunk 2 bag).
 * @kw prefer_h3     When true, race h3 first; on err / timeout fall
 *                   back to h1.  Default true.
 * @kw h3_handshake_ms  Per-call deadline for the h3 handshake before
 *                      falling back to h1.  Default 1500.
 * @kw timeout_ms    Per-call wall-clock deadline including transport.
 *                   Default 30000.
 * @kw trust         Optional trust handle.  Default nullptr →
 *                   system trust.  The picotls→OS trust bridge is
 *                   wired for both h1 (via `acme_tls.c`) and h3
 *                   (via `picotls_verify.c`); pass an explicit
 *                   `n00b_quic_trust_pinned(...)` for self-signed
 *                   test fixtures.
 * @kw follow_redirects  Default false.  When true, dispatcher
 *                   follows 3xx Location through up to
 *                   @p max_redirects hops, applying RFC 9110
 *                   § 15.4 method-preservation rules (301/302/303
 *                   collapse to GET + drop body; 307/308 preserve
 *                   method + body).  Location resolution implements
 *                   RFC 3986 § 5 (transform-references): absolute
 *                   URI, network-path (`//host/foo`), absolute path,
 *                   relative path, and `..` segment removal — full
 *                   resolver, not the chunk-7 minimal subset.
 *                   Cross-scheme redirects to anything other than
 *                   `https://` are rejected.
 * @kw max_redirects Cap on hops when @p follow_redirects is true.
 *                   Default 5.
 * @kw auto_decompress  Default true.  Advertises
 *                   `Accept-Encoding: gzip, deflate` (+ `br` /
 *                   `zstd` if their libraries dlopen) and
 *                   transparently decompresses responses that
 *                   carry a matching `Content-Encoding`.
 * @kw body_encoding Optional codec for request-body compression.
 *                   `"gzip"` / `"deflate"` / nullptr / `"identity"`.
 *                   When set the dispatcher compresses @p body
 *                   and adds a `Content-Encoding:` header.
 * @kw cookie_jar    Optional jar.  When set, the dispatcher
 *                   attaches matching cookies via `Cookie:` and
 *                   updates the jar from `Set-Cookie:` responses.
 * @kw auth          Optional auth helper (Bearer + DPoP + mTLS
 *                   storage + response verifier).
 * @kw max_body_size Optional per-call response-body byte cap.
 *                   Default 0 = no cap (existing callers see
 *                   identical behavior).  When non-zero, the
 *                   dispatcher threads the cap into both the h1
 *                   and h3 round-trip primitives; on overrun the
 *                   call returns `N00B_HTTP_ERR_RESPONSE_TOO_LARGE`
 *                   (-9).  Enforced before the cookie-jar /
 *                   auto-decompress / redirect-follow seams, so
 *                   the oversized body never materializes past the
 *                   cap to those consumers.
 * @kw redirect_host_allowlist
 *                   Optional list of hosts the dispatcher is
 *                   permitted to follow a 3xx redirect to.  Default
 *                   nullptr = no filter (existing redirect-follow
 *                   semantics unchanged).  Each entry is one of:
 *
 *                     - An exact host (no `*`) — matched against
 *                       the next-hop authority host by ASCII
 *                       case-insensitive byte equality (port, path,
 *                       scheme, and fragment do not participate).
 *                     - A wildcard `*.DOMAIN` with at least one
 *                       label after the leading `*.` (e.g.
 *                       `*.example.com`) — matches any host of the
 *                       form `X.DOMAIN` for non-empty `X`, with the
 *                       same ASCII-CI semantics.  Both
 *                       `foo.example.com` and `a.b.example.com`
 *                       match `*.example.com`.  The apex
 *                       `example.com` does NOT match `*.example.com`;
 *                       to permit the apex too, add a second
 *                       non-wildcard entry `example.com`.
 *                     - Anything else (`foo.*.com`, `**.example.com`,
 *                       `*example.com`, bare `*`) — malformed; the
 *                       entry is silently skipped (no match for
 *                       that entry; the request is not aborted on
 *                       a malformed entry alone).
 *
 *                   **IDN / UTS-46 support.**  Both the next-hop
 *                   host and the canonicalizable portion of each
 *                   entry (the whole entry for exact match; the
 *                   `DOMAIN` after `*.` for a wildcard) are run
 *                   through UTS-46 `to_ascii` before comparison.
 *                   Unicode (`*.例え.com`) and Punycode
 *                   (`*.xn--r8jz45g.com`) forms cross-match in
 *                   either direction.  The `*.` prefix of a
 *                   wildcard is literal ASCII and is NOT fed to
 *                   the IDNA pipeline.  Pure-ASCII entries behave
 *                   byte-identically to the pre-IDN matcher (ASCII
 *                   Punycode is a fixed point of `to_ascii`).
 *                   Entries whose canonicalizable portion fails
 *                   IDNA (disallowed codepoints, BIDI / CONTEXTJ
 *                   violations, oversize labels, malformed UTF-8,
 *                   …) are silently skipped like any other
 *                   malformed entry.
 *
 *                   An empty list (0 entries) means "no hosts
 *                   permitted" — every redirect is rejected.
 *                   Disallowed redirects surface as
 *                   `N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED`
 *                   (-10).  Only consulted when
 *                   `follow_redirects = true`; when redirect-follow
 *                   is off, 3xx responses pass through to the
 *                   caller as-is (no allowlist check).
 * @kw allow_plain_http  When true, `http://` URLs are accepted and
 *                   sent over a one-shot plain TCP HTTP/1.1 round
 *                   trip (no TLS, no H3, no connection pool, no
 *                   redirect handling).  Default false — only
 *                   `https://` is accepted, which is the production
 *                   posture.  Intended for local-development
 *                   loopback callers (CLIs talking to a same-host
 *                   service, adapters talking to a local backing
 *                   store) where TLS is not configured.  Each
 *                   request opens a fresh socket and closes it on
 *                   the response; no idle connection is ever pooled
 *                   under the plain-HTTP path.  Most other kwargs
 *                   (`prefer_h3`, `trust`, `pool`, `auth`,
 *                   `cookie_jar`, `follow_redirects`) are ignored
 *                   when this path is taken — they're TLS / H3 /
 *                   pooling concerns.  `extra`, `body`,
 *                   `content_type`, `method`, `auto_decompress`,
 *                   `body_encoding`, `timeout_ms`, and
 *                   `max_body_size` still apply.
 * @kw allocator     Default per-runtime conduit pool.
 *
 * @return  Result with the populated response, or err carrying
 *          either an `n00b_quic_err_t` (transport failure) or an
 *          `n00b_http_err_t` (URL / wire-format / policy failure)
 *          — both are negative ints so callers can switch on the
 *          value uniformly.
 */
extern n00b_result_t(n00b_http_response_t *)
n00b_http_request_sync(n00b_string_t *url)
    _kargs {
        n00b_string_t          *method            = nullptr;
        n00b_buffer_t          *body              = nullptr;
        n00b_string_t          *content_type      = nullptr;
        n00b_http_h1_headers_t *extra             = nullptr;
        bool                    prefer_h3         = true;
        int32_t                 h3_handshake_ms   = 1500;
        int32_t                 timeout_ms        = 30000;
        n00b_quic_trust_t      *trust             = nullptr;
        bool                    follow_redirects  = false;
        int32_t                 max_redirects     = 5;
        bool                    auto_decompress   = true;
        n00b_string_t          *body_encoding     = nullptr;
        n00b_http_cookie_jar_t *cookie_jar        = nullptr;
        n00b_http_auth_t       *auth              = nullptr;
        n00b_http_connection_pool_t *pool         = nullptr;
        uint64_t                max_body_size     = 0;
        n00b_list_t(n00b_string_t *) *redirect_host_allowlist = nullptr;
        bool                    allow_plain_http  = false;
        n00b_allocator_t       *allocator         = nullptr;
    };

/**
 * @brief Issue a synchronous HTTP/1.1 request over a unix-domain socket.
 *
 * Plain HTTP/1.1 (no TLS) over an AF_UNIX socket, built on the conduit
 * layer (`n00b_conduit_conn_unix` + the fd-managed read/write helpers).
 * Intended for local loopback APIs where a daemon exposes a REST surface
 * on a unix socket (e.g. crayon-gw's local query API). One-shot: connect,
 * send, read the response to EOF (the peer is expected to answer with
 * `Connection: close`), close.
 *
 * @param socket_path  AF_UNIX socket path of the local service. Required.
 * @param path         Request target, e.g. `"/v1/query?term=foo"`. Must
 *                     begin with `/`. Required.
 *
 * @kw method          Method verb. Default `"GET"`.
 * @kw body            Optional request body.
 * @kw content_type    Required if @p body is non-NULL.
 * @kw extra           Optional caller-supplied headers.
 * @kw auto_decompress Decompress the response body. Default true.
 * @kw max_body_size   Cap on response bytes (0 = no cap).
 * @kw allocator       Default per-runtime conduit pool.
 *
 * @return Result with the populated response, or err carrying an
 *         `n00b_http_err_t` / conduit error (both negative ints).
 */
extern n00b_result_t(n00b_http_response_t *)
n00b_http_request_unix_sync(n00b_string_t *socket_path, n00b_string_t *path)
    _kargs {
        n00b_string_t          *method          = nullptr;
        n00b_buffer_t          *body            = nullptr;
        n00b_string_t          *content_type    = nullptr;
        n00b_http_h1_headers_t *extra           = nullptr;
        bool                    auto_decompress = true;
        uint64_t                max_body_size   = 0;
        n00b_allocator_t       *allocator       = nullptr;
    };

/**
 * @brief Streaming unix HTTP request: read the response incrementally off the
 *        conduit fd stream and invoke @p on_line for each '\n'-delimited body
 *        line as it arrives (NDJSON), instead of buffering the whole body.
 *
 * The accumulator is compacted after each line batch, so client memory stays
 * bounded regardless of body size. Returns the HTTP status code on success, or
 * an error if the status line could not be parsed. @p on_line returning false
 * stops reading early (consumer done / cancel).
 */
typedef bool (*n00b_http_line_cb_t)(void *ctx, n00b_string_t *line);

extern n00b_result_t(int)
n00b_http_request_unix_stream(n00b_string_t      *socket_path,
                              n00b_string_t      *path,
                              n00b_http_line_cb_t on_line,
                              void               *ctx)
    _kargs {
        n00b_string_t          *method       = nullptr;
        n00b_buffer_t          *body         = nullptr;
        n00b_string_t          *content_type = nullptr;
        n00b_http_h1_headers_t *extra        = nullptr;
    };

/* ----------------------------------------------------------------- */
/* Topic-shaped request                                              */
/* ----------------------------------------------------------------- */

/**
 * @brief Issue an HTTPS request, returning a one-shot topic.
 *
 * Sync + async share this entry point:
 *
 * - **Sync use** — block until the response lands:
 *   @code
 *     auto tr = n00b_http_request(c, url);
 *     n00b_conduit_topic_t(n00b_http_response_t *) *t = n00b_result_get(tr);
 *     auto rr = n00b_conduit_read(n00b_http_response_t *, t,
 *                                  .timeout_ms = 30000);
 *     n00b_conduit_message_t(n00b_http_response_t *) *m = n00b_result_get(rr);
 *     n00b_http_response_t *resp = m->payload;
 *   @endcode
 *
 * - **Async use** — subscribe and let the conduit IO loop drive:
 *   @code
 *     auto tr = n00b_http_request(c, url);
 *     n00b_conduit_subscribe(n00b_http_response_t *, t, my_inbox, .operations = ALL);
 *     // ... drive the conduit; my_inbox receives the response ...
 *   @endcode
 *
 * The dispatcher spawns a worker thread per request that runs the
 * sync round-trip (chunk-1 URL parse → chunk-3 h3 with chunk-5
 * race+fallback → chunk-2 h1) and publishes the response on the
 * returned topic exactly once.  The topic is closed after the publish
 * (the done-topic fires for any subscribers waiting on that signal).
 *
 * On transport failure the worker still publishes a response — with
 * status = 0 and `n00b_http_response_error()` carrying the negative
 * error code.  Callers pattern-match on
 * `n00b_http_response_error() == 0 && status == X`.
 *
 * Same kwargs as `n00b_http_request_sync`.
 */
extern n00b_result_t(n00b_conduit_topic_t(n00b_http_response_t *) *)
n00b_http_request(n00b_conduit_t *c, n00b_string_t *url)
    _kargs {
        n00b_string_t          *method            = nullptr;
        n00b_buffer_t          *body              = nullptr;
        n00b_string_t          *content_type      = nullptr;
        n00b_http_h1_headers_t *extra             = nullptr;
        bool                    prefer_h3         = true;
        int32_t                 h3_handshake_ms   = 1500;
        int32_t                 timeout_ms        = 30000;
        n00b_quic_trust_t      *trust             = nullptr;
        bool                    follow_redirects  = false;
        int32_t                 max_redirects     = 5;
        bool                    auto_decompress   = true;
        n00b_string_t          *body_encoding     = nullptr;
        n00b_http_cookie_jar_t *cookie_jar        = nullptr;
        n00b_http_auth_t       *auth              = nullptr;
        n00b_http_connection_pool_t *pool         = nullptr;
        uint64_t                max_body_size     = 0;
        n00b_list_t(n00b_string_t *) *redirect_host_allowlist = nullptr;
        n00b_allocator_t       *allocator         = nullptr;
    };

/* ----------------------------------------------------------------- */
/* Loss cache (h3 → h1 sticky downgrade)                             */
/* ----------------------------------------------------------------- */

/**
 * @brief Reset the per-runtime h3 loss cache.
 *
 * The dispatcher remembers origins where h3 failed (handshake,
 * timeout) for `N00B_HTTP_LOSS_CACHE_TTL_MS` so subsequent calls to
 * the same origin skip h3 immediately.  Tests use this to clear
 * state between runs; production code never needs to call it.
 */
extern void n00b_http_loss_cache_reset(void);

/* ----------------------------------------------------------------- */
/* Redirect helpers (test-visible)                                   */
/* ----------------------------------------------------------------- */

/** @brief True iff @p status is a 3xx redirect chunk-7 follows. */
extern bool n00b_http_status_is_redirect(int status);

/** @brief True iff @p status preserves the original method+body. */
extern bool n00b_http_status_preserves_method(int status);

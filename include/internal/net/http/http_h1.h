/**
 * @file http_h1.h
 * @internal
 * @brief HTTP/1.1 transport for the n00b HTTP client (Phase 6,
 * chunk 2).
 *
 * Successor to `internal/net/quic/acme_http.h` — generalized past
 * the ACME-specific assumptions baked into the original shim:
 *
 *   - Any HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
 *   - Caller-supplied content-type (no JOSE default).
 *   - Response-side `Connection:` parsing surfaced as
 *     `keep_alive` so the connection pool can decide whether to
 *     retain the socket (see `pool` kwarg below + `http_pool.h`).
 *   - Operates on a parsed `n00b_http_url_t *` (chunk 1) instead of
 *     re-tokenizing a raw C string.
 *
 * Like `acme_http.c`, the underlying byte-level transport (TCP +
 * picotls) lives in `acme_tls.c` behind the `n00b_acme_tls_*`
 * internal API.  Phase 6 chunk 2 reuses that TLS layer verbatim;
 * the eventual rename to `n00b_http_tls_*` is part of the chunk-11
 * cut-over.
 *
 * @see ~/dd/quic_6.md § 7 (chunks 2 + 4).
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "internal/net/http/http_url.h"

/* ----------------------------------------------------------------- */
/* Header bag                                                        */
/* ----------------------------------------------------------------- */

/**
 * @brief Case-insensitive ASCII header bag.
 *
 * Linked-list internally — HTTP responses carry on the order of a
 * dozen headers, not enough to motivate a hash table.  Insertions
 * lowercase the stored name; lookups are ASCII-case-insensitive on
 * the name; last-wins on duplicates.
 */
typedef struct n00b_http_h1_headers n00b_http_h1_headers_t;

/** @brief Allocate an empty header bag.
 *
 * @kw allocator Allocator to use.  Defaults to the per-runtime
 *               conduit pool so cross-thread IO publishes are safe.
 */
extern n00b_http_h1_headers_t *
n00b_http_h1_headers_new()
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Set a header (overwrite if name already present).
 *
 * Both @p name and @p value are copied; the caller may free their
 * copies after the call.
 */
extern void
n00b_http_h1_headers_set(n00b_http_h1_headers_t *h,
                         const char             *name,
                         const char             *value);

/**
 * @brief Look up a header by ASCII-case-insensitive name.
 *
 * @return Borrowed C-string pointer into the bag's storage, or
 *         nullptr if absent.  Valid while @p h is alive.
 */
extern const char *
n00b_http_h1_headers_get_cstr(n00b_http_h1_headers_t *h, const char *name);

/** @brief Number of header entries currently in @p h. */
extern size_t
n00b_http_h1_headers_len(n00b_http_h1_headers_t *h);

/**
 * @brief Read the i-th (insertion-order) header pair without copying.
 *
 * @param h         Header bag.
 * @param idx       Zero-based index.
 * @param name_out  Output pointer for the lowercased header name
 *                  (NUL-terminated, borrowed).
 * @param value_out Output pointer for the value (NUL-terminated,
 *                  borrowed).
 * @return  true on success, false if @p idx is out of range.
 */
extern bool
n00b_http_h1_headers_at(n00b_http_h1_headers_t *h,
                        size_t                  idx,
                        const char            **name_out,
                        const char            **value_out);

extern void
n00b_http_h1_headers_free(n00b_http_h1_headers_t *h);

/* ----------------------------------------------------------------- */
/* Response                                                          */
/* ----------------------------------------------------------------- */

/**
 * @brief Parsed HTTP/1.1 response.
 *
 * @c status        Numeric status (100..599).
 * @c status_text   Reason phrase from the status line.
 * @c body          Decoded response body.  Never `nullptr`; an empty
 *                  body is an empty `n00b_buffer_t`.  Both
 *                  `Content-Length` and `Transfer-Encoding: chunked`
 *                  bodies are decoded transparently.
 * @c headers       Response headers.
 * @c keep_alive    Whether the server hinted the socket may be reused.
 *                  HTTP/1.1 rule: keep-alive is the default unless
 *                  `Connection: close` is sent (RFC 9112 § 9.6).  We
 *                  also down-grade to false on HTTP/1.0 unless the
 *                  server explicitly opts in via
 *                  `Connection: keep-alive`.
 * @c http_minor    The minor version digit from `HTTP/1.X`.  Lets
 *                  callers distinguish 1.0 vs 1.1 — relevant to the
 *                  keep-alive default + chunked-encoding support.
 */
typedef struct {
    int                     status;
    n00b_string_t          *status_text;
    n00b_buffer_t          *body;
    n00b_http_h1_headers_t *headers;
    bool                    keep_alive;
    uint8_t                 http_minor;
} n00b_http_h1_response_t;

/**
 * @brief Parse a single full HTTP/1.1 response from a contiguous
 * byte buffer.
 *
 * @param raw  Buffer containing exactly one response: status line,
 *             headers, blank line, body.  Trailing bytes past the
 *             advertised body length are tolerated (and ignored).
 *
 * @kw allocator  Allocator for the response + its strings.  Defaults
 *                to the per-runtime conduit pool.
 *
 * @return  Result carrying the parsed response, or one of:
 *          - `N00B_HTTP_ERR_NULL_ARG`      on @p raw nullptr / empty
 *          - `N00B_HTTP_ERR_BAD_RESPONSE`  for any wire-format error
 *                                          (status line, headers,
 *                                          or chunked-body decoding).
 */
extern n00b_result_t(n00b_http_h1_response_t *)
n00b_http_h1_response_parse(n00b_buffer_t *raw)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/* ----------------------------------------------------------------- */
/* Request builder                                                   */
/* ----------------------------------------------------------------- */

/**
 * @brief Build a complete HTTP/1.1 request as a single byte buffer
 *        ready for the wire.
 *
 * The result contains the request line, an automatically populated
 * `Host:` header (with port suppressed when implicit), `User-Agent:`,
 * `Accept: */ /*`, `Connection:` (close or keep-alive per the
 * `keep_alive` kwarg), `Content-Type:` + `Content-Length:` when a
 * body is present, every header from @p extra (verbatim — case
 * preserved), the blank line, and the body bytes.
 *
 * No header validation: the caller is internal.  Callers that
 * accept untrusted input must validate first.
 *
 * @param url  Parsed URL from `n00b_http_url_parse`.  Required.
 *
 * @kw method        Method verb. Default `"GET"`.
 * @kw body          Optional request body. When present, an
 *                   accurate `Content-Length` header is added.
 * @kw content_type  Required if @p body is non-NULL.  No default —
 *                   ACME callers explicitly pass
 *                   `application/jose+json`; general callers pick.
 * @kw extra         Optional caller-supplied headers.  Override the
 *                   built-ins case-insensitively.
 * @kw user_agent    Default `"n00b-http/0.1"`.
 * @kw keep_alive    Default false → emits `Connection: close`.
 *                   When true emits `Connection: keep-alive` so a
 *                   pool can retain the socket.
 * @kw allocator     Default per-runtime conduit pool.
 *
 * @return  Heap-allocated buffer.  Caller owns; consumed by the
 *          round-trip driver below.
 */
extern n00b_buffer_t *
n00b_http_h1_request_build(n00b_http_url_t *url)
    _kargs {
        const char             *method       = "GET";
        n00b_buffer_t          *body         = nullptr;
        const char             *content_type = nullptr;
        n00b_http_h1_headers_t *extra        = nullptr;
        const char             *user_agent   = "n00b-http/0.1";
        bool                    keep_alive   = false;
        n00b_allocator_t       *allocator    = nullptr;
    };

/* ----------------------------------------------------------------- */
/* Round trip                                                         */
/* ----------------------------------------------------------------- */

/**
 * @brief One synchronous HTTP/1.1 request → response round trip.
 *
 * Wraps the `acme_tls.c` connect/send/recv primitives (TCP + TLS
 * 1.3 + cert verification through the `acme_trust_*.c` paths) with
 * the generalized request builder + response parser.  When the
 * caller passes a non-null `pool` kwarg, the round-trip first tries
 * `acquire(origin, H1)` and falls through to a fresh
 * `n00b_acme_tls_connect()` only on miss; clean responses from
 * keep-alive-advertising peers are returned to the pool, while
 * stale / half-shut connections close on close.
 *
 * @param url  Parsed URL.  Required.
 *
 * @kw method        Default `"GET"`.
 * @kw body          Optional request body.
 * @kw content_type  Required if @p body is non-NULL.
 * @kw extra         Optional caller headers.
 * @kw timeout_ms    Hard deadline.  Default 30000.
 * @kw max_body_size Optional per-call response-body byte cap.
 *                   Default 0 = no cap (existing callers see
 *                   identical behavior).  When non-zero, the
 *                   receive loop aborts as soon as the accumulated
 *                   response bytes (status line + headers + body)
 *                   would push past the cap and surfaces
 *                   `N00B_HTTP_ERR_RESPONSE_TOO_LARGE` (-9).  Also
 *                   short-circuits before reading any body bytes
 *                   when an advertised `Content-Length` exceeds
 *                   the cap.
 * @kw allocator     Default per-runtime conduit pool.
 *
 * @return  Result with the parsed response on success, or one of the
 *          `n00b_quic_err_t` codes from the underlying TLS shim
 *          (negative ints — e.g. `N00B_QUIC_ERR_HANDSHAKE`,
 *          `N00B_QUIC_ERR_TIMEOUT`).  Wire-format errors come back as
 *          `N00B_HTTP_ERR_BAD_RESPONSE` from the parser; over-cap
 *          bodies as `N00B_HTTP_ERR_RESPONSE_TOO_LARGE`.
 *          HTTP 4xx / 5xx are **ok**, not errors — the caller
 *          interprets status codes.
 */
/* Forward decl — pool struct lives in include/internal/net/http/http_pool.h. */
typedef struct n00b_http_connection_pool n00b_http_connection_pool_t;
/* Forward decl — public auth helper from net/http/http_auth.h. */
typedef struct n00b_http_auth            n00b_http_auth_t;
/* Forward decl — public trust handle from net/quic/trust.h. */
typedef struct n00b_quic_trust           n00b_quic_trust_t;

extern n00b_result_t(n00b_http_h1_response_t *)
n00b_http_h1_round_trip(n00b_http_url_t *url)
    _kargs {
        const char                  *method       = "GET";
        n00b_buffer_t               *body         = nullptr;
        const char                  *content_type = nullptr;
        n00b_http_h1_headers_t      *extra        = nullptr;
        int32_t                      timeout_ms   = 30000;
        n00b_http_connection_pool_t *pool         = nullptr;
        /** Optional auth helper; when @p auth->mtls_key + chain are
         *  set the round-trip presents a client cert at handshake
         *  time.  Pool entries are keyed by the auth pointer so two
         *  requests with different mTLS identities never share a
         *  connection. */
        n00b_http_auth_t            *auth         = nullptr;
        /** Optional trust handle.  Default @c nullptr — the
         *  round-trip falls through to the OS system trust store
         *  (byte-identical to the pre-trust-threading default).  Pass
         *  an explicit handle (e.g. @c n00b_quic_trust_pinned for
         *  self-signed test fixtures, or @c n00b_quic_trust_with_extra
         *  for corporate PKI on top of the system store) to override
         *  the verify_certificate verdict.  The trust handle is
         *  borrowed; it must outlive the connection.  This is the h1
         *  twin of the trust kwarg on @c n00b_http_h3_round_trip; the
         *  public @c n00b_http_request_sync dispatcher forwards the
         *  same handle into both transports so they agree on the
         *  verdict for any given trust handle. */
        n00b_quic_trust_t           *trust        = nullptr;
        /** Per-call response-body byte cap.  Default 0 = no cap.
         *  When non-zero, the receive loop aborts as soon as the
         *  accumulated wire bytes (status line + headers + body)
         *  would exceed the cap and surfaces
         *  `N00B_HTTP_ERR_RESPONSE_TOO_LARGE`.  An advertised
         *  `Content-Length` greater than the cap short-circuits
         *  before any body bytes are read. */
        uint64_t                     max_body_size = 0;
        n00b_allocator_t            *allocator    = nullptr;
    };

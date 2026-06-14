/**
 * @file h3.h
 * @brief HTTP/3 client (RFC 9114) — public API.
 *
 * Phase 4 § 4.3.  This module ships the **client** half of HTTP/3
 * over the n00b QUIC transport: it builds on `n00b_quic_endpoint_t`
 * + `n00b_quic_conn_t` + `n00b_quic_chan_t` for transport, on
 * `n00b_qpack_*` for header compression, and on the H3 frame
 * encoder/decoder in this module for the wire format.
 *
 * The server half lands in sub-phase 4.4.  The two share the frame
 * encoder/decoder and the SETTINGS exchange but have separate
 * lifecycle managers.
 *
 * ### What this module ships in sub-phase 4.3
 *
 * - **Frame encoder/decoder** (`h3_frame.c`) — DATA, HEADERS,
 *   SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, with proper handling
 *   of reserved frame types (RFC 9114 § 7.2.8) and grease (must
 *   ignore).  Handles truncated input cleanly via
 *   `N00B_QUIC_ERR_NEED_MORE_DATA`.
 * - **SETTINGS negotiation** (`h3_settings.c`) — the encoder for
 *   outbound settings, the parser for inbound.
 * - **Client lifecycle** (`h3_client.c`) — creates the H3 control +
 *   QPACK encoder + QPACK decoder unidirectional streams; opens a
 *   bidi request stream; sends HEADERS+DATA; reads the response
 *   HEADERS+DATA back.
 *
 * Server-push acceptance, trailers (TE: trailers + trailer HEADERS),
 * and the request-iterator API are deferred to v1.1.  v1 supports
 * the unary `GET / POST` shape that the Caddy CI smoke tests
 * exercise and that the RPC layer (sub-phase 4.6+) needs.
 *
 * ### Allocator + threading
 *
 * Per `MEMORY.md`: every long-lived H3 object lives in
 * `runtime->conduit_pool`.  The client + per-request state share a
 * pthread mutex; the IO loop and the application thread can both
 * call into the client safely.
 *
 * @see h3_types.h, qpack.h
 * @see ~/dd/quic_4.md § 5 sub-phase 4.3
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "conduit/conduit.h"
#include "conduit/inbox.h"
#include "conduit/message.h"
#include "conduit/subscription.h"
#include "conduit/topic.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/h3_types.h"
#include "net/quic/qpack.h"

/* ===========================================================================
 * Public types
 * =========================================================================== */

/**
 * @brief A single decoded H3 frame.
 *
 * Returned by the frame parser.  The @c body pointer is borrowed
 * into the source buffer; copy out before mutating the source.
 *
 * For a HEADERS frame the body is the raw QPACK-encoded field
 * section — the caller (or the request-stream demultiplexer) feeds
 * those bytes to the QPACK decoder.
 */
typedef struct {
    uint64_t       type;            /**< RFC 9114 frame type varint. */
    const uint8_t *body;            /**< Borrowed pointer into source. */
    size_t         body_len;        /**< Bytes of body. */
    size_t         consumed;        /**< Total bytes the frame occupies. */
} n00b_h3_frame_t;

/**
 * @brief A single header field (name + value).
 *
 * Mirrors `n00b_qpack_field_t` for parity with the QPACK API; both
 * names are lower-case ASCII per RFC 9114 § 4.2.
 */
typedef struct {
    const uint8_t *name;
    size_t         name_len;
    const uint8_t *value;
    size_t         value_len;
} n00b_h3_header_t;

/**
 * @brief Negotiated SETTINGS values (per-connection).
 *
 * Populated as soon as the peer's SETTINGS frame is parsed; carries
 * the values our peer advertised.  RFC 9204's QPACK settings are
 * mirrored here so the client can size its encoder/decoder
 * appropriately.
 */
typedef struct {
    uint64_t qpack_max_table_capacity;   /**< RFC 9204 § 5 */
    uint64_t qpack_blocked_streams;      /**< RFC 9204 § 5 */
    uint64_t max_field_section_size;     /**< RFC 9114 § 7.2.4.1 */
    bool     enable_connect_protocol;
    bool     received;                   /**< true once parsed from peer. */
} n00b_h3_settings_t;

/** @brief Opaque H3 client handle. */
typedef struct n00b_h3_client n00b_h3_client_t;

/** @brief Opaque H3 request handle (one outbound request). */
typedef struct n00b_h3_request n00b_h3_request_t;

/**
 * @brief Decoded H3 response.
 *
 * Populated by `n00b_h3_request_await`.  All bytes are conduit-pool
 * allocated and remain valid until the owning client is closed.
 */
typedef struct {
    /** HTTP status code from the `:status` pseudo-header. */
    uint16_t        status;
    /** Decoded response headers (does NOT include `:status`). */
    n00b_h3_header_t *headers;
    size_t            n_headers;
    /** Response body (concatenated DATA frame contents). */
    n00b_buffer_t    *body;
} n00b_h3_response_t;

typedef struct {
    const n00b_h3_header_t *items;
    size_t                  count;
} n00b_h3_header_list_t;

#define n00b_h3_headers(...)                                                  \
    ((n00b_h3_header_list_t){                                                 \
        .items = (n00b_h3_header_t []){__VA_ARGS__},                          \
        .count = sizeof((n00b_h3_header_t []){__VA_ARGS__}) /                 \
                 sizeof(n00b_h3_header_t)})

typedef struct {
    const char            *method;
    const char            *scheme;
    const char            *authority;
    const char            *path;
    n00b_h3_header_list_t  headers;
    const uint8_t         *body;
    size_t                 body_len;
    bool                   keep_open;
} n00b_h3_request_spec_t;

typedef struct {
    const uint8_t *body;
    size_t         body_len;
    bool           fin;
} n00b_h3_data_t;

typedef struct {
    uint16_t               status;
    n00b_h3_header_list_t  headers;
    bool                   fin;
} n00b_h3_response_headers_t;

typedef struct {
    uint16_t               status;
    n00b_h3_header_list_t  headers;
    const uint8_t         *body;
    size_t                 body_len;
    bool                   keep_open;
} n00b_h3_response_spec_t;

/* ===========================================================================
 * Frame encoder / decoder
 *
 * The frame layer is shared between client and server.  These entry
 * points operate on raw bytes; they do not own any per-connection
 * state.  Tests use them directly to build round-trip vectors.
 * =========================================================================== */

/**
 * @brief Append an H3 frame header (`varint(type) || varint(length)`)
 *        to @p out.
 *
 * The caller appends the @p length-byte body afterwards.
 *
 * @param out    Destination buffer.
 * @param type   RFC 9114 frame type.
 * @param length Length of the body (bytes).
 *
 * @return ok(bytes-written) — always ≥ 2.
 *         err(@c N00B_QUIC_ERR_FRAME_TOO_LARGE) if @p length exceeds
 *         the QUIC varint maximum (2^62 - 1).
 */
extern n00b_result_t(size_t)
    n00b_h3_frame_emit_header(n00b_buffer_t *out,
                              uint64_t       type,
                              uint64_t       length);

/**
 * @brief Encode + append a complete frame in one shot.
 *
 * @param out      Destination buffer.
 * @param type     Frame type.
 * @param body     Body bytes (may be nullptr only if @p body_len == 0).
 * @param body_len Length of @p body.
 *
 * @kw max_size Hard cap on the body length (bytes).  Default
 *              @c N00B_H3_DEFAULT_MAX_FRAME_BODY.
 *
 * @return ok(true) on success;
 *         err(@c N00B_QUIC_ERR_FRAME_TOO_LARGE) on cap overflow.
 */
extern n00b_result_t(bool)
    n00b_h3_frame_emit(n00b_buffer_t *out,
                       uint64_t       type,
                       const uint8_t *body,
                       size_t         body_len)
    _kargs {
        size_t max_size = N00B_H3_DEFAULT_MAX_FRAME_BODY;
    };

/**
 * @brief Try to parse one frame from @p in starting at @p offset.
 *
 * @param in     Source buffer.
 * @param offset Byte offset to start parsing at.
 * @param out    Populated on success.
 *
 * @kw max_size  Maximum allowed body length; default
 *               @c N00B_H3_DEFAULT_MAX_FRAME_BODY.
 *
 * @return ok(true) if a complete frame was parsed; @p out is filled
 *         in.
 *         err(@c N00B_QUIC_ERR_NEED_MORE_DATA) if the input does not
 *         yet contain a complete frame.
 *         err(@c N00B_QUIC_ERR_FRAME_TOO_LARGE) if the advertised
 *         length exceeds the cap.
 *         err(@c N00B_QUIC_ERR_BAD_VARINT) on malformed varint.
 *         err(@c N00B_QUIC_ERR_PROTOCOL) on a reserved frame type
 *         (RFC 9114 § 7.2.8).
 *         err(@c N00B_QUIC_ERR_NULL_ARG) on null pointers.
 */
extern n00b_result_t(bool)
    n00b_h3_frame_parse(n00b_buffer_t   *in,
                        size_t           offset,
                        n00b_h3_frame_t *out)
    _kargs {
        size_t max_size = N00B_H3_DEFAULT_MAX_FRAME_BODY;
    };

/**
 * @brief Parse from raw bytes (no buffer wrapping).
 *
 * Same semantics as `n00b_h3_frame_parse`; useful when the bytes
 * arrived from a non-`n00b_buffer_t` source.
 */
extern n00b_result_t(bool)
    n00b_h3_frame_parse_bytes(const uint8_t   *data,
                              size_t           data_len,
                              n00b_h3_frame_t *out)
    _kargs {
        size_t max_size = N00B_H3_DEFAULT_MAX_FRAME_BODY;
    };

/* ===========================================================================
 * SETTINGS
 * =========================================================================== */

/**
 * @brief Encode a SETTINGS frame body (the QPACK-aware payload).
 *
 * Call `n00b_h3_frame_emit(... type = SETTINGS, body = result)` to
 * wrap.
 *
 * @param out                       Destination buffer (appended).
 * @param qpack_max_table_capacity  Local QPACK encoder dyn-table cap.
 * @param qpack_blocked_streams     Local blocked-streams allowance.
 * @param max_field_section_size    Local cap on inbound field sections;
 *                                  0 = no advertised cap.
 *
 * @return ok(true) on success.
 */
extern n00b_result_t(bool)
    n00b_h3_settings_emit_body(n00b_buffer_t *out,
                               uint64_t       qpack_max_table_capacity,
                               uint64_t       qpack_blocked_streams,
                               uint64_t       max_field_section_size);

/**
 * @brief Parse a SETTINGS frame body.
 *
 * @param body       Body bytes (the contents of the SETTINGS frame's
 *                   payload, NOT the frame envelope).
 * @param body_len   Length of @p body.
 * @param out        Settings struct, populated on success.
 *
 * @return ok(true) on success;
 *         err(@c N00B_QUIC_ERR_PROTOCOL) on duplicate identifiers
 *         (RFC 9114 § 7.2.4) or trailing-byte issues;
 *         err(@c N00B_QUIC_ERR_BAD_VARINT) on a malformed varint.
 */
extern n00b_result_t(bool)
    n00b_h3_settings_parse(const uint8_t      *body,
                           size_t              body_len,
                           n00b_h3_settings_t *out);

/* ===========================================================================
 * Client API
 *
 * Lifecycle: `n00b_h3_client_new` over an already-connected
 * `n00b_quic_conn_t` (the QUIC handshake must have completed with ALPN
 * = "h3").  After construction the client opens its three uni streams
 * (control + QPACK encoder + QPACK decoder) and emits its SETTINGS
 * frame; subsequent calls to `n00b_h3_client_drive` advance the IO
 * state machine.
 * =========================================================================== */

/**
 * @brief Allocate a new H3 client over an already-connected QUIC
 *        connection.
 *
 * The QUIC connection must:
 * - have completed its handshake (state == @c CONNECTED), and
 * - have negotiated ALPN "h3" — the caller is responsible for
 *   constructing the endpoint with `.alpn = "h3"`.
 *
 * After construction the client is "ready to drive": call
 * `n00b_h3_client_drive` to push the initial SETTINGS frame onto the
 * wire and process inbound frames.  Issue requests via
 * `n00b_h3_client_request`.
 *
 * @param conn  Connected QUIC connection.
 *
 * @kw max_frame_body          Hard cap on inbound frame body bytes;
 *                             default @c N00B_H3_DEFAULT_MAX_FRAME_BODY.
 * @kw qpack_max_table_capacity Local QPACK encoder dyn-table cap;
 *                              default 4096.
 * @kw qpack_blocked_streams    Local blocked-streams allowance; default 0.
 *
 * @return Result: ok with a new client, or err on invalid args /
 *         channel-allocation failure.
 *
 * @pre @p conn is non-NULL and in the CONNECTED state.
 * @post On success the client owns three uni streams + a SETTINGS
 *       frame queued for transmission; the caller drives IO via
 *       @c n00b_h3_client_drive.
 */
extern n00b_result_t(n00b_h3_client_t *)
    n00b_h3_client_new(n00b_quic_conn_t *conn)
    _kargs {
        size_t   max_frame_body          = N00B_H3_DEFAULT_MAX_FRAME_BODY;
        uint64_t qpack_max_table_capacity = 4096;
        uint64_t qpack_blocked_streams    = 0;
    };

/**
 * @brief Release the H3 client.
 *
 * Closes the client's owned streams and releases QPACK state.  Does
 * NOT close the underlying QUIC connection — the caller decides when
 * to do that (a single conn may host one client during its lifetime).
 *
 * @param client Client (may be NULL).
 */
extern void n00b_h3_client_close(n00b_h3_client_t *client);

/**
 * @brief Drive one iteration of the client's IO state machine.
 *
 * Reads any pending bytes from the underlying QUIC streams and
 * dispatches them through the frame + QPACK decoders.  This call
 * does NOT pump UDP — the caller is expected to call
 * `n00b_quic_endpoint_run_once` separately (typically in the same
 * loop iteration).
 *
 * @param client Client.
 *
 * @return ok(true) on success;
 *         err on any propagated parse error.
 */
extern n00b_result_t(bool)
    n00b_h3_client_drive(n00b_h3_client_t *client);

/**
 * @brief Snapshot the peer's negotiated SETTINGS.
 *
 * Returns a zero-filled struct with `.received == false` until the
 * peer's SETTINGS frame has arrived.  Useful to gate operations that
 * depend on QPACK capacity advertised by the server.
 */
extern n00b_h3_settings_t
n00b_h3_client_peer_settings(n00b_h3_client_t *client);

/* ---------------------------------------------------------------------------
 * Requests
 * --------------------------------------------------------------------------- */

/**
 * @brief Issue a request.
 *
 * Builds the HEADERS frame, optionally appends a DATA frame, and
 * (unless `request.keep_open` is true) FINs the request stream.  Does
 * NOT block on the response — call `n00b_h3_request_await` to drain.
 *
 * @param client   H3 client.
 * @param request  Request descriptor. Required: `method`, `authority`.
 *                 Defaults: `scheme = "https"`, `path = "/"`,
 *                 `keep_open = false`.
 *
 * @return Result: ok with a new request handle.
 */
extern n00b_result_t(n00b_h3_request_t *)
    n00b_h3_client_request(n00b_h3_client_t *client,
                           n00b_h3_request_spec_t request);

/**
 * @brief Low-level request API.
 *
 * Most callers should prefer `n00b_h3_client_request`; this raw form is
 * useful when a caller already has separate pseudo-header fields and wants
 * the old explicit argument shape.
 */
extern n00b_result_t(n00b_h3_request_t *)
    n00b_h3_client_request_raw(n00b_h3_client_t *client,
                               const char       *method,
                               const char       *scheme,
                               const char       *authority,
                               const char       *path)
    _kargs {
        const n00b_h3_header_t *extra_headers = nullptr;
        size_t                  n_extra       = 0;
        const uint8_t          *body          = nullptr;
        size_t                  body_len      = 0;
        bool                    fin           = true;
    };

/**
 * @brief Wait (with deadline) for the response to a request.
 *
 * Drives the client's IO loop until the response HEADERS + body have
 * been received OR the deadline elapses.  The caller is also expected
 * to call `n00b_quic_endpoint_run_once` from the same thread; this
 * call interleaves drive() with sleep so UDP packets continue
 * flowing.
 *
 * @param req         Request handle.
 *
 * @kw deadline_ms    Maximum wall-clock time to wait, milliseconds.
 *                    Default 10000.  -1 = wait indefinitely.
 * @kw drive          When false, the await loop does NOT pump the
 *                    endpoint via `n00b_quic_endpoint_run_once`.
 *                    Default: true (await drives the endpoint
 *                    itself, which is fine for single-call test
 *                    patterns).
 * @kw max_body_size  Per-call response-body byte cap.  Default
 *                    0 = no cap.  When non-zero, the receive loop
 *                    enforces the cap on each DATA-frame append AND
 *                    on a `content-length` response header (when the
 *                    server sent one).  Overrun resets the stream
 *                    with `N00B_H3_ERR_EXCESSIVE_LOAD` and the await
 *                    returns `N00B_QUIC_ERR_LOCAL_RESET`; callers
 *                    inspect `n00b_h3_request_body_cap_exceeded` to
 *                    distinguish cap-driven resets from peer resets.
 *
 * @return Result: ok with the populated response;
 *         err(@c N00B_QUIC_ERR_TIMEOUT) on deadline expiry;
 *         err(@c N00B_QUIC_ERR_PEER_RESET) if the peer reset the
 *         stream;
 *         err(@c N00B_QUIC_ERR_LOCAL_RESET) if the local cap fired
 *         (see `n00b_h3_request_body_cap_exceeded`);
 *         err(@c N00B_QUIC_ERR_PROTOCOL) on a malformed response.
 */
extern n00b_result_t(n00b_h3_response_t *)
    n00b_h3_request_await(n00b_h3_request_t *req)
    _kargs {
        int32_t  deadline_ms   = 10000;
        bool     drive         = true;
        uint64_t max_body_size = 0;
    };

/**
 * @brief Did the local `max_body_size` cap fire on this request?
 *
 * True when the receive loop reset the stream because the server's
 * response body (or its declared `content-length`) exceeded the
 * caller-supplied cap.  Always false when no cap was set.
 *
 * Pairs with `n00b_h3_request_await`'s `LOCAL_RESET` return to
 * disambiguate cap-driven resets from other local resets (none today;
 * exists for forward-compat).
 */
extern bool
n00b_h3_request_body_cap_exceeded(n00b_h3_request_t *req);

/**
 * @brief Cancel a request.
 *
 * Sends RESET_STREAM for the request body direction and STOP_SENDING for the
 * response body direction with @c REQUEST_CANCELLED.
 */
extern void n00b_h3_request_cancel(n00b_h3_request_t *req);

/**
 * @brief Stream id of a request (diagnostic).
 *
 * @return The request's bidi stream id, or @c UINT64_MAX if @p req
 *         is null or not yet opened.
 */
extern uint64_t n00b_h3_request_stream_id(n00b_h3_request_t *req);

/* ---------------------------------------------------------------------------
 * Streaming request/response primitives (sub-phase 4.7)
 *
 * For streaming RPC patterns we need to (a) send additional DATA frames
 * after the request was opened with `.fin = false`, and (b) consume
 * received DATA bytes incrementally rather than waiting for FIN.  The
 * helpers below cover both directions.
 * --------------------------------------------------------------------------- */

/**
 * @brief Append another DATA frame to a request stream.
 *
 * Use after `n00b_h3_client_request(... .keep_open = true)` to push more
 * body bytes; set `data.fin` to true to FIN the stream after this DATA frame.
 *
 * @param req       Request handle.
 * @param data      DATA-frame descriptor.
 *
 * @return ok(true) on success; err on closed/reset stream or transport
 *         failure.
 */
extern n00b_result_t(bool)
n00b_h3_request_send_data(n00b_h3_request_t *req,
                          n00b_h3_data_t      data);

extern n00b_result_t(bool)
n00b_h3_request_send_data_raw(n00b_h3_request_t *req,
                              const uint8_t     *body,
                              size_t             body_len,
                              bool               fin);

/**
 * @brief Has the response HEADERS frame been parsed?
 *
 * False until the server's first HEADERS frame arrives + decodes; true
 * thereafter for the lifetime of the request.
 */
extern bool n00b_h3_request_headers_received(n00b_h3_request_t *req);

/** @brief HTTP `:status` parsed from the response HEADERS (0 until received). */
extern uint16_t n00b_h3_request_status(n00b_h3_request_t *req);

/**
 * @brief Borrowed pointer to the response headers (excluding `:status`).
 *
 * @param req    Request handle.
 * @param n_out  Optional out-arg; populated with the header count.
 *
 * @pre `n00b_h3_request_headers_received(req)` has returned `true`.
 *      That readiness function is the authoritative presence signal;
 *      callers MUST check it before invoking this accessor.
 *
 * @return Borrowed pointer to a header array. Returns `nullptr` as a
 *         defensive-not-asserted fallback when the precondition is
 *         violated (HEADERS frame has not arrived); the canonical
 *         pattern is to check `_headers_received` first, not to
 *         disambiguate on the nullptr return (per §5.4 — not a
 *         sentinel-nullable contract; a precondition-violation
 *         hedge).
 */
extern const n00b_h3_header_t *
n00b_h3_request_response_headers(n00b_h3_request_t *req, size_t *n_out);

/**
 * @brief Consume up to @p max bytes of currently-buffered response body.
 *
 * Drains DATA-frame bytes that have been parsed but not yet read by the
 * caller.  Bytes are removed from the request's internal buffer; a
 * subsequent call only returns NEW bytes.  Does not block.
 *
 * @param req Request handle.
 * @param out Destination buffer.
 * @param max Maximum bytes to copy.
 *
 * @return Bytes copied (0 ≤ N ≤ @p max); 0 if no data is buffered.
 */
extern size_t n00b_h3_request_consume_body(n00b_h3_request_t *req,
                                           uint8_t           *out,
                                           size_t             max);

/** @brief True iff the peer has FIN'd the response stream. */
extern bool n00b_h3_request_recv_fin(n00b_h3_request_t *req);

/** @brief True iff the request stream is in the RESET state. */
extern bool n00b_h3_request_is_reset(n00b_h3_request_t *req);

/* ===========================================================================
 * Server API (sub-phase 4.4)
 *
 * Mirrors the client lifecycle on the server side.  An H3 server wraps
 * a listen-mode QUIC endpoint: it subscribes to the endpoint's accept
 * topic, builds a per-conn `n00b_h3_server_conn_t` for each accepted
 * cnx (opening the three uni streams + emitting SETTINGS), discovers
 * the peer's three uni streams as their kind-varint arrives, and
 * surfaces inbound bidi streams as `n00b_h3_inbound_request_t`s on a
 * "request" topic the application subscribes to.
 *
 * The application reads the four pseudo-headers + extra headers + body
 * via the inbound-request accessors, and emits a response via
 * `n00b_h3_inbound_request_respond`.
 *
 * Server push (uni stream kind 0x01) is NOT supported in v1.
 * =========================================================================== */

/** @brief Opaque H3 server handle. */
typedef struct n00b_h3_server n00b_h3_server_t;

/** @brief Opaque per-conn state under a server. */
typedef struct n00b_h3_server_conn n00b_h3_server_conn_t;

/** @brief Opaque inbound-request handle (one client-initiated bidi). */
typedef struct n00b_h3_inbound_request n00b_h3_inbound_request_t;

/* Inbound-request topic plumbing — modelled on the QUIC accept event
 * surface in `endpoint.h`. */

typedef struct {
    n00b_h3_inbound_request_t *req;
} n00b_h3_request_event_t;

N00B_CONDUIT_FULL_IMPL(n00b_h3_request_event_t);

typedef n00b_conduit_message_t(n00b_h3_request_event_t)
    n00b_h3_request_msg_t;
typedef n00b_conduit_inbox_t(n00b_h3_request_event_t)
    n00b_h3_request_inbox_t;

#define n00b_h3_request_inbox_new(c)                                           \
    ({                                                                          \
        n00b_h3_request_inbox_t *_inbox =                                       \
            n00b_alloc(n00b_h3_request_inbox_t);                                \
        n00b_conduit_inbox_init(n00b_h3_request_event_t,                        \
                                _inbox, c, N00B_CONDUIT_BP_UNBOUNDED, 0);       \
        _inbox;                                                                 \
    })

#define n00b_h3_request_subscribe(topic, inbox, ...)                            \
    n00b_conduit_subscribe(n00b_h3_request_event_t,                             \
        (n00b_conduit_topic_t(n00b_h3_request_event_t) *)(topic), inbox, __VA_ARGS__)

#define n00b_h3_request_inbox_pop(inbox)                                        \
    n00b_conduit_inbox_pop_msg(n00b_h3_request_event_t, inbox)

#define n00b_h3_request_inbox_has_messages(inbox)                               \
    n00b_conduit_inbox_has_msg(n00b_h3_request_event_t, inbox)

/**
 * @brief Build an H3 server over a listen-mode QUIC endpoint.
 *
 * The endpoint must have been created with `.listen = true` and ALPN
 * = "h3".  The server subscribes to the endpoint's accept topic; each
 * inbound `n00b_quic_conn_t` is wrapped in a per-conn struct by the
 * next `n00b_h3_server_drive(server)` call.
 *
 * @param endpoint  Listen-mode endpoint (ALPN "h3").
 * @param conduit   Conduit hosting the request topic.
 *
 * @kw max_frame_body          Hard cap on inbound frame body bytes;
 *                             default @c N00B_H3_DEFAULT_MAX_FRAME_BODY.
 * @kw qpack_max_table_capacity  Server's QPACK encoder dyn-table cap;
 *                                default 4096.
 * @kw qpack_blocked_streams     Server's blocked-streams allowance;
 *                                default 0.
 *
 * @return Result: ok with a new server, or err on invalid args.
 *
 * @pre @p endpoint is non-NULL, in listen mode, with ALPN "h3".
 */
extern n00b_result_t(n00b_h3_server_t *)
    n00b_h3_server_new(n00b_quic_endpoint_t *endpoint,
                       n00b_conduit_t       *conduit)
    _kargs {
        size_t   max_frame_body          = N00B_H3_DEFAULT_MAX_FRAME_BODY;
        uint64_t qpack_max_table_capacity = 4096;
        uint64_t qpack_blocked_streams    = 0;
        /**
         * @kw early_publish When true, inbound requests are published on the
         *                   request topic as soon as their HEADERS frame is
         *                   parsed (instead of waiting for the peer's FIN).
         *                   Required for client-streaming + bidi RPC where
         *                   the application must consume DATA frames before
         *                   the peer FINs.  Default false (unary semantics).
         */
        bool     early_publish           = false;
    };

/**
 * @brief Topic on which the server publishes
 *        @c n00b_h3_request_event_t for each fully-received inbound
 *        request.
 *
 * Each event fires once per client-initiated bidi stream, AFTER the
 * request HEADERS have been QPACK-decoded AND the client has FIN'd
 * its half (so the body is complete).  The application handles the
 * request and calls `n00b_h3_inbound_request_respond`.
 */
extern n00b_conduit_topic_base_t *
n00b_h3_server_request_topic(n00b_h3_server_t *server);

/**
 * @brief Drive one iteration of the server's IO state machine.
 *
 * Processes new accept events, drains per-conn uni streams, parses
 * inbound request frames, and publishes ready requests on the
 * server's request topic.  Call in a loop alongside
 * `n00b_quic_endpoint_run_once` (which pumps UDP).
 *
 * @return ok(true) on success; err on a propagated parse error.
 */
extern n00b_result_t(bool)
    n00b_h3_server_drive(n00b_h3_server_t *server);

/**
 * @brief Initiate an orderly server close (RFC 9114 § 5.2 GOAWAY).
 *
 * Emits a GOAWAY frame on each per-conn control stream advertising
 * `(highest-issued-client-stream-id) + 4` as the limit.  Subsequent
 * client-initiated bidi streams beyond that limit will not be
 * processed.  Drains in-flight requests; after this call returns
 * `n00b_h3_server_drive` becomes a no-op for new conns.
 *
 * @param server Server (may be NULL).
 */
extern void n00b_h3_server_close(n00b_h3_server_t *server);

/* ---------------------------------------------------------------------------
 * Inbound request — accessors
 * --------------------------------------------------------------------------- */

/** @brief Method pseudo-header (e.g. "GET", "POST"). */
extern const char *
n00b_h3_inbound_request_method(n00b_h3_inbound_request_t *req);

/** @brief Scheme pseudo-header (typically "https"). */
extern const char *
n00b_h3_inbound_request_scheme(n00b_h3_inbound_request_t *req);

/** @brief Authority pseudo-header (host[:port]). */
extern const char *
n00b_h3_inbound_request_authority(n00b_h3_inbound_request_t *req);

/** @brief Path-and-query pseudo-header. */
extern const char *
n00b_h3_inbound_request_path(n00b_h3_inbound_request_t *req);

/**
 * @brief Inbound request headers (other than the four pseudo-headers).
 *
 * @param req       Inbound request.
 * @param n_out     Populated with the header count (may be NULL).
 *
 * @return Borrowed pointer to a header array (lifetime = the request).
 */
extern const n00b_h3_header_t *
n00b_h3_inbound_request_headers(n00b_h3_inbound_request_t *req,
                                size_t                    *n_out);

/**
 * @brief Inbound request body buffer (may be empty).
 */
extern n00b_buffer_t *
n00b_h3_inbound_request_body(n00b_h3_inbound_request_t *req);

/**
 * @brief Stream id of an inbound request (diagnostic).
 */
extern uint64_t
n00b_h3_inbound_request_stream_id(n00b_h3_inbound_request_t *req);

/**
 * @brief Peer address of the underlying QUIC connection.
 *
 * Convenience for server-side handlers + audit sinks: the inbound
 * request carries the channel, the channel carries the connection,
 * the connection carries the peer addr.
 *
 * @param req  Inbound request.
 * @param out  Destination `sockaddr_storage` (caller-allocated).
 *
 * @return true on success; false if any pointer is null or the
 *         underlying connection has not yet learned a peer addr.
 */
extern bool
n00b_h3_inbound_request_peer_addr(n00b_h3_inbound_request_t *req,
                                  struct sockaddr_storage   *out);

/**
 * @brief Send a response on the request stream.
 *
 * Emits HEADERS (`:status` + extras) followed by an optional DATA
 * frame for the body.  When @c fin is true (the default), FINs the
 * stream after the body.
 *
 * @param req       Inbound request.
 * @param response  Response descriptor. `keep_open = false` FINs the
 *                  response stream after the body.
 *
 * @return ok(true) on success;
 *         err(@c N00B_QUIC_ERR_PROTOCOL) on a malformed-status
 *         (>999 or 0); err on a closed stream / failed send.
 */
extern n00b_result_t(bool)
    n00b_h3_inbound_request_respond(n00b_h3_inbound_request_t *req,
                                    n00b_h3_response_spec_t    response);

extern n00b_result_t(bool)
    n00b_h3_inbound_request_respond_raw(n00b_h3_inbound_request_t *req,
                                        uint16_t                   status,
                                        const n00b_h3_header_t    *headers,
                                        size_t                     n_headers,
                                        const uint8_t             *body,
                                        size_t                     body_len)
    _kargs {
        bool fin = true;
    };

/**
 * @brief Reset an inbound request stream (RESET_STREAM with @p app_err).
 *
 * Useful when the server decides not to handle the request — e.g.,
 * malformed pseudo-headers, server push attempt.
 */
extern void
n00b_h3_inbound_request_reset(n00b_h3_inbound_request_t *req,
                              uint64_t                   app_err);

/* ---------------------------------------------------------------------------
 * Inbound request streaming (sub-phase 4.7)
 *
 * Mirrors the client-side streaming helpers.  `n00b_h3_inbound_request_respond`
 * sends HEADERS+DATA+FIN in one shot — the right shape for unary calls.
 * For server-streaming or bidi the application instead emits HEADERS up
 * front, drives a sequence of DATA frames, and FINs at the end.
 * --------------------------------------------------------------------------- */

/**
 * @brief Send the response HEADERS frame.
 *
 * @param req      Inbound request.
 * @param headers  Response HEADERS descriptor. `headers.fin = false`
 *                 leaves room for DATA frames.
 *
 * @return ok(true) on success.
 */
extern n00b_result_t(bool)
    n00b_h3_inbound_request_send_headers(n00b_h3_inbound_request_t *req,
                                         n00b_h3_response_headers_t headers);

extern n00b_result_t(bool)
    n00b_h3_inbound_request_send_headers_raw(n00b_h3_inbound_request_t *req,
                                             uint16_t                   status,
                                             const n00b_h3_header_t    *headers,
                                             size_t                     n_headers)
    _kargs {
        bool fin = false;
    };

/**
 * @brief Send a DATA frame on the response stream.
 *
 * @param req   Inbound request (HEADERS must already have been sent).
 * @param data  DATA-frame descriptor.
 */
extern n00b_result_t(bool)
n00b_h3_inbound_request_send_data(n00b_h3_inbound_request_t *req,
                                  n00b_h3_data_t             data);

extern n00b_result_t(bool)
n00b_h3_inbound_request_send_data_raw(n00b_h3_inbound_request_t *req,
                                      const uint8_t             *body,
                                      size_t                     body_len,
                                      bool                       fin);

/**
 * @brief Consume up to @p max bytes of the inbound DATA stream.
 *
 * Drains bytes that have been parsed from DATA frames but not yet read.
 * Pairs with `early_publish = true` on `n00b_h3_server_new` so the
 * handler can read DATA chunks as they arrive (client-streaming /
 * bidi).
 *
 * @return Bytes copied; 0 if none buffered.
 */
extern size_t n00b_h3_inbound_request_consume_body(
    n00b_h3_inbound_request_t *req,
    uint8_t                   *out,
    size_t                     max);

/** @brief True iff the peer has FIN'd the request stream. */
extern bool
n00b_h3_inbound_request_peer_fin(n00b_h3_inbound_request_t *req);

/** @brief True iff the inbound request stream is in the RESET state. */
extern bool
n00b_h3_inbound_request_is_reset(n00b_h3_inbound_request_t *req);

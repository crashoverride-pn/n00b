/**
 * @file quic_types.h
 * @brief Common types, opaque handles, and error codes for the QUIC module.
 *
 * This is the leaf header of the QUIC dependency graph: it has no
 * QUIC-internal dependencies and can be included from any other QUIC
 * header.  It declares opaque public handle types, the
 * @c n00b_quic_err_t error code enumeration, frame-type tag namespace
 * constants, and small public POD types shared across the module.
 *
 * ### Opaque handles
 *
 * - `n00b_quic_endpoint_t` — A UDP socket plus picoquic context; can both
 *   initiate outbound connections and accept inbound (when configured to
 *   listen).  Allocated from the conduit pool; never moves.
 * - `n00b_quic_conn_t` — One QUIC connection with an established TLS 1.3
 *   handshake.  Owns its set of channels.
 * - `n00b_quic_chan_t` — One stream / channel within a connection.
 *   Lifecycle states are observable; half-close is exposed.
 * - `n00b_quic_trust_t` — A trust store: source of trusted root CAs.
 * - `n00b_quic_secret_t` — Handle to a secret stored in a blessed source
 *   (Keychain, libsecret, PKCS#11, ...).  The underlying material is never
 *   surfaced through the public API.
 *
 * ### Allocator discipline
 *
 * All long-lived QUIC state (endpoints, connections, channels, timers,
 * inboxes) **must** be allocated from the runtime's `conduit_pool`,
 * not the default GC arena.  Default-arena objects can be moved by the
 * GC while the IO backend holds raw pointers from a separate thread; that
 * is the bug `MEMORY.md → conduit_allocator_audit.md` documents.  See
 * `docs/quic/allocator.md` for the full rule.
 *
 * @see quic.h, framer.h, stats.h
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

/* ===========================================================================
 * Opaque public handles
 * =========================================================================== */

typedef struct n00b_quic_endpoint n00b_quic_endpoint_t;
typedef struct n00b_quic_conn     n00b_quic_conn_t;
typedef struct n00b_quic_chan     n00b_quic_chan_t;
typedef struct n00b_quic_trust    n00b_quic_trust_t;
typedef struct n00b_quic_secret   n00b_quic_secret_t;

/* ===========================================================================
 * Channel kind enumeration
 *
 * A channel is the application-visible unit on top of a QUIC stream.  Three
 * kinds are exposed:
 *
 * - @c FRAMED — Length-prefixed, type-tagged frames (see framer.h).  Suitable
 *   for request/reply or message-stream protocols.  Used by RPC and H3 frame
 *   chunks.
 * - @c BYTES — Raw byte stream.  No framing.  The caller imposes whatever
 *   structure they need.  Useful for tunneling or proxying.
 * - @c DGRAM — RFC 9221 unreliable datagram channel.  No retransmits, no
 *   ordering.  Useful for latency-sensitive payloads where loss is preferable
 *   to head-of-line blocking.
 *
 * The kinds are deliberately disjoint at the channel level: a single channel
 * is one kind for its entire lifetime.  This avoids the HTTP/2
 * CONTINUATION-frame class of bug.
 * =========================================================================== */
typedef enum : uint8_t {
    N00B_QUIC_CHAN_FRAMED = 0,
    N00B_QUIC_CHAN_BYTES  = 1,
    N00B_QUIC_CHAN_DGRAM  = 2,
} n00b_quic_chan_kind_t;

/* ===========================================================================
 * Channel state enumeration
 *
 * Observable state of a single channel.  Half-close is exposed deliberately:
 * every interesting protocol uses it.  The full lifecycle:
 *
 *     OPEN
 *      ├─ send FIN     → SEND_HALF_CLOSED  → recv FIN → CLOSED
 *      ├─ recv FIN     → RECV_HALF_CLOSED  → send FIN → CLOSED
 *      ├─ local reset  → LOCAL_RESET                  → CLOSED
 *      └─ peer reset   → PEER_RESET                   → CLOSED
 * =========================================================================== */
typedef enum : uint8_t {
    N00B_QUIC_CHAN_STATE_OPEN              = 0,
    N00B_QUIC_CHAN_STATE_SEND_HALF_CLOSED  = 1,
    N00B_QUIC_CHAN_STATE_RECV_HALF_CLOSED  = 2,
    N00B_QUIC_CHAN_STATE_LOCAL_RESET       = 3,
    N00B_QUIC_CHAN_STATE_PEER_RESET        = 4,
    N00B_QUIC_CHAN_STATE_CLOSED            = 5,
} n00b_quic_chan_state_t;

/* ===========================================================================
 * Congestion control algorithm enumeration
 *
 * Surfaced through @c n00b_quic_conn_stats_t so operators can see which CC
 * algorithm is in effect.  Picoquic ships NewReno, Cubic, and BBR.
 * =========================================================================== */
typedef enum : uint8_t {
    N00B_QUIC_CC_NEWRENO = 0,
    N00B_QUIC_CC_CUBIC   = 1,
    N00B_QUIC_CC_BBR     = 2,
} n00b_quic_cc_algo_t;

/* ===========================================================================
 * Error codes
 *
 * Module-specific error codes are negative to leave the positive int space
 * for errno values when a syscall is the underlying source.  Use
 * @c n00b_quic_err_str() to get a human-readable string for any code in this
 * range.  POSIX errno values returned through the same channel are *not*
 * recognized by @c n00b_quic_err_str — use @c strerror() for those.
 * =========================================================================== */
typedef enum : int32_t {
    N00B_QUIC_OK                  = 0,
    N00B_QUIC_ERR_BIND_FAILED     = -1,
    N00B_QUIC_ERR_HANDSHAKE       = -2,
    N00B_QUIC_ERR_TRUST_REJECTED  = -3,
    N00B_QUIC_ERR_PEER_CLOSED     = -4,
    N00B_QUIC_ERR_LOCAL_RESET     = -5,
    N00B_QUIC_ERR_PEER_RESET      = -6,
    N00B_QUIC_ERR_FLOW_BLOCKED    = -7,
    N00B_QUIC_ERR_FRAME_TOO_LARGE = -8,
    N00B_QUIC_ERR_PROTOCOL        = -9,
    N00B_QUIC_ERR_TIMEOUT         = -10,
    N00B_QUIC_ERR_NOT_IMPLEMENTED = -11,
    N00B_QUIC_ERR_INVALID_ARG     = -12,
    N00B_QUIC_ERR_NEED_MORE_DATA  = -13,
    N00B_QUIC_ERR_BAD_VARINT      = -14,
    N00B_QUIC_ERR_BAD_TYPE        = -15,
    N00B_QUIC_ERR_NULL_ARG        = -16,

    /* Phase 3 (auth) — JWT / OIDC / DPoP / mTLS-bound tokens. */
    N00B_QUIC_ERR_AUTH_TOKEN_MISSING   = -17,
    N00B_QUIC_ERR_AUTH_TOKEN_INVALID   = -18,
    N00B_QUIC_ERR_AUTH_TOKEN_EXPIRED   = -19,
    N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND   = -20,
    N00B_QUIC_ERR_AUTH_ALG_REFUSED     = -21,
    N00B_QUIC_ERR_AUTH_ISS_MISMATCH    = -22,
    N00B_QUIC_ERR_AUTH_AUD_MISMATCH    = -23,
    N00B_QUIC_ERR_AUTH_DPOP_FAILED     = -24,
    N00B_QUIC_ERR_AUTH_MTLS_MISMATCH   = -25,
    N00B_QUIC_ERR_AUTH_REPLAY_DETECTED = -26,

    /* HTTP CONNECT proxy tunneling (h1 TLS transport). */
    /** The proxy responded to `CONNECT host:port` with a non-2xx status,
     *  or the response never arrived before the connect deadline. */
    N00B_QUIC_ERR_PROXY_REJECTED        = -27,
} n00b_quic_err_t;

/**
 * @brief Look up a stable human-readable string for a QUIC error code.
 *
 * Returns a pointer to a statically-allocated string; the caller must not
 * free the result.  Codes outside the @c n00b_quic_err_t range produce the
 * sentinel string `"unknown"`.
 *
 * @param err Error code as defined in @c n00b_quic_err_t.
 * @return    Static, non-NULL, NUL-terminated description.
 *
 * @post Return value remains valid for the lifetime of the program.
 */
extern const char *n00b_quic_err_str(n00b_quic_err_t err);

/* ===========================================================================
 * Frame type-tag namespace
 *
 * The wire framer's 1-byte type tag is partitioned into ranges so H3 and RPC
 * cannot collide on type assignments while sharing the framer.  Phase 1
 * defines the ranges only; concrete frame-type constants are defined within
 * each consumer's namespace (H3 / RPC ship in later phases).
 *
 * Range allocations:
 *
 * | Range          | Owner    | Notes                                   |
 * | -------------- | -------- | --------------------------------------- |
 * | `0x00`–`0x3f`  | Transport| Reserved for cross-cutting frames (drain, keepalive). |
 * | `0x40`–`0x7f`  | H3       | nghttp3 + glue.                         |
 * | `0x80`–`0xbf`  | RPC      | Per-codec session.                      |
 * | `0xc0`–`0xff`  | Unassigned | Future extensions.                    |
 * =========================================================================== */
#define N00B_QUIC_FRAME_T_TRANSPORT_LO  ((uint8_t)0x00u)
#define N00B_QUIC_FRAME_T_TRANSPORT_HI  ((uint8_t)0x3fu)
#define N00B_QUIC_FRAME_T_H3_LO         ((uint8_t)0x40u)
#define N00B_QUIC_FRAME_T_H3_HI         ((uint8_t)0x7fu)
#define N00B_QUIC_FRAME_T_RPC_LO        ((uint8_t)0x80u)
#define N00B_QUIC_FRAME_T_RPC_HI        ((uint8_t)0xbfu)
#define N00B_QUIC_FRAME_T_UNASSIGNED_LO ((uint8_t)0xc0u)
#define N00B_QUIC_FRAME_T_UNASSIGNED_HI ((uint8_t)0xffu)

/* ===========================================================================
 * Wire format constants
 * =========================================================================== */

/**
 * @brief Default upper bound on a single encoded frame, in bytes.
 *
 * Includes the varint length header, the type byte, and the payload.  The
 * framer rejects emit / parse operations that would exceed this size.
 * Configurable downward at the call site via the `.max_size` kwarg on
 * @c n00b_quic_frame_emit / @c n00b_quic_frame_parse; configurable upward
 * only with the @c N00B_QUIC_ALLOW_LARGE_FRAMES compile flag.
 *
 * @details Default 16 MiB matches the source design.  Production deployments
 * are expected to tune downward based on their payload profile.
 */
#define N00B_QUIC_DEFAULT_MAX_FRAME_SIZE ((size_t)(16u * 1024u * 1024u))

/**
 * @brief Maximum value representable by an RFC 9000 §16 8-byte varint.
 *
 * Encoded as `0xc0 || (62 low bits of value)`.  Used as the absolute hard
 * cap during varint parsing.
 */
#define N00B_QUIC_VARINT_MAX  ((uint64_t)((UINT64_C(1) << 62) - 1))

/* ===========================================================================
 * Stream budget defaults
 *
 * Initial values sent in QUIC transport parameters.  100/100 matches industry
 * consensus (nghttp3, msquic, quiche, picoquic-demo, aioquic).  See
 * `docs/quic/stream_budgets.md` for the measurement methodology that will
 * either confirm these values or surface a knee that motivates lowering them.
 * =========================================================================== */
#define N00B_QUIC_DEFAULT_MAX_STREAMS_BIDI  ((uint64_t)100)
#define N00B_QUIC_DEFAULT_MAX_STREAMS_UNI   ((uint64_t)100)

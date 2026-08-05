/**
 * @file conn.h
 * @brief A QUIC connection — one peer, one TLS session, many channels.
 *
 * `n00b_quic_conn_t` wraps one `picoquic_cnx_t` plus the n00b-side
 * lifecycle and lock state.  Connections are owned by an endpoint;
 * an endpoint may host many connections concurrently (typical client
 * usage is one connection per peer; a server endpoint accepts many).
 *
 * ### What this revision ships
 *
 * Phase 1 (this pass): outbound `n00b_quic_connect`, ordered
 * `n00b_quic_close`, observable state machine, snapshot stats.
 * Inbound accept and the per-connection cert/auth surfaces ship
 * once the secret-to-picotls bridge lands.
 *
 * Channels (`n00b_quic_chan_t`) ride on top of connections; their
 * API ships in the follow-up that wires picoquic stream callbacks
 * to topics.  Without channels, a connection is a handshake-only
 * object — useful for testing the transport, not yet for moving
 * application bytes.
 *
 * @see endpoint.h, chan.h, quic_types.h
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "net/quic/stats.h"

#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

/**
 * @brief Coarse-grained connection state.
 *
 * Picoquic exposes ~17 fine-grained states; we project them onto
 * this 5-bucket enum for application use.  When something needs a
 * picoquic-fine-grained state value (debugging, qlog), reach into
 * the internal struct.
 */
typedef enum : uint8_t {
    N00B_QUIC_CONN_STATE_CONNECTING  = 0, /**< Pre-handshake-complete. */
    N00B_QUIC_CONN_STATE_CONNECTED   = 1, /**< Application-data ready. */
    N00B_QUIC_CONN_STATE_CLOSING     = 2, /**< Local or remote close started. */
    N00B_QUIC_CONN_STATE_CLOSED      = 3, /**< Drained; no more data. */
    N00B_QUIC_CONN_STATE_FAILED      = 4, /**< Handshake or transport error. */
} n00b_quic_conn_state_t;

/**
 * @brief Initiate an outbound QUIC connection.
 *
 * Allocates a new `n00b_quic_conn_t`, creates the picoquic
 * connection context against @p remote_addr, and queues the Initial
 * Client Hello.  The actual handshake bytes do not flow until the
 * caller calls @c n00b_quic_endpoint_run_once on the owning
 * endpoint.  Returns immediately — does **not** block on handshake
 * completion.  Callers wait for the connection to leave
 * @c CONNECTING by polling @c n00b_quic_conn_state.
 *
 * @param ep          Endpoint to connect from.
 * @param remote_addr Destination address (borrowed; copied internally).
 * @param sni         Server Name Indication for cert verification.
 *                    Required.
 *
 * @kw timeout_ms   Soft handshake timeout in milliseconds; default
 *                  10000.  *Currently advisory only — picoquic's
 *                  internal idle timeout is what actually fires.
 *                  Wired through in a follow-up.*
 * @kw alpn_pref    Specific ALPN to request.  Default nullptr → use
 *                  the endpoint's default ALPN.
 * @kw zero_rtt     Default false.  *Reserved; opt-in 0-RTT lands
 *                  with the channel API per `quic_1.md § 12 open
 *                  decisions`.*
 *
 * @return Result: ok with the new connection on success.  An error
 *         here means the local handshake setup failed (no memory,
 *         bad address); a remote handshake failure surfaces as
 *         @c N00B_QUIC_CONN_STATE_FAILED later.
 *
 * @pre @p ep is non-NULL and not closed.
 * @pre @p remote_addr is non-NULL.
 * @pre @p sni is non-NULL.
 * @post On success the connection is registered with the endpoint
 *       and will be driven by @c n00b_quic_endpoint_run_once.
 */
extern n00b_result_t(n00b_quic_conn_t *)
    n00b_quic_connect(n00b_quic_endpoint_t  *ep,
                      const struct sockaddr *remote_addr,
                      n00b_string_t         *sni)
    _kargs {
        int32_t        timeout_ms = 10000;
        n00b_string_t *alpn_pref  = nullptr;
        bool           zero_rtt   = false;
    };

/**
 * @brief Initiate an ordered close.
 *
 * Sends a CONNECTION_CLOSE frame with the application-layer error
 * code @p app_err and transitions the connection to
 * @c CLOSING.  After the close acknowledgement (or the closing
 * timeout) the connection moves to @c CLOSED.  This call returns
 * immediately; the actual frames flow on the next
 * @c n00b_quic_endpoint_run_once.
 *
 * Calling close on an already-closed connection is a no-op.
 *
 * @param conn   Connection to close.
 * @param app_err Application-layer 62-bit error code (0 = normal).
 *
 * @kw reason  Optional human-readable string included in the close
 *             frame.  Default nullptr.  Truncated to 1024 bytes.
 */
extern void n00b_quic_close(n00b_quic_conn_t *conn,
                            uint64_t          app_err)
    _kargs {
        n00b_string_t *reason = nullptr;
    };

/**
 * @brief Observable connection state.
 *
 * @param conn Connection handle.
 * @return Coarse-grained state; @c CLOSED for NULL or freed
 *         connections.
 */
extern n00b_quic_conn_state_t
n00b_quic_conn_state(n00b_quic_conn_t *conn);

/**
 * @brief Snapshot per-connection stats.
 *
 * Returns a self-consistent snapshot of RTT, congestion window,
 * data sent / received, and other operator-visible counters.
 * Sourced from picoquic accessors.
 *
 * @param conn Connection handle (may be NULL).
 * @return Stats; zeroed on a NULL or closed connection.
 */
extern n00b_quic_conn_stats_t
n00b_quic_conn_stats(n00b_quic_conn_t *conn);

/**
 * @brief Source of a connection close.  Identifies which event fired
 *        the close so the application can distinguish "we closed it"
 *        from "peer closed gracefully" from "peer stateless-reset us".
 */
typedef enum : uint8_t {
    N00B_QUIC_CLOSE_SOURCE_NONE             = 0, /**< Still open. */
    N00B_QUIC_CLOSE_SOURCE_LOCAL            = 1, /**< n00b_quic_close called. */
    N00B_QUIC_CLOSE_SOURCE_PEER_TRANSPORT   = 2, /**< picoquic_callback_close. */
    N00B_QUIC_CLOSE_SOURCE_PEER_APPLICATION = 3, /**< picoquic_callback_application_close. */
    N00B_QUIC_CLOSE_SOURCE_STATELESS_RESET  = 4, /**< picoquic_callback_stateless_reset. */
    N00B_QUIC_CLOSE_SOURCE_IDLE_TIMEOUT     = 5, /**< Idle timeout (no peer action). */
} n00b_quic_close_source_t;

/**
 * @brief Snapshot of close-reason metadata.
 *
 * Populated after the connection enters a closed state.  Until then
 * @c source is `NONE` and the codes are zero.
 *
 * Public struct (Principle 12 — public fields are stable).
 */
typedef struct {
    n00b_quic_close_source_t source;
    uint64_t                 local_reason;       /**< Local transport reason. */
    uint64_t                 remote_reason;      /**< Peer's transport reason. */
    uint64_t                 local_app_reason;   /**< Local app-close reason. */
    uint64_t                 remote_app_reason;  /**< Peer's app-close reason. */
    n00b_string_t           *local_reason_phrase;/**< Reason string we sent. */
} n00b_quic_close_info_t;

/**
 * @brief Read the close-reason metadata for a connection.
 *
 * Safe to call at any time; until the conn closes, @c source is
 * `NONE` and the codes are zero.  Use this alongside
 * @c n00b_quic_conn_state to distinguish "closing" from
 * "closed-because-X".
 *
 * @param conn Connection handle (may be NULL).
 * @return Close info; all fields zero on a NULL handle.
 */
extern n00b_quic_close_info_t
n00b_quic_conn_close_info(n00b_quic_conn_t *conn);

/**
 * @brief Owning endpoint of a connection.
 *
 * @param conn Connection handle.
 * @return Owning endpoint, or NULL if @p conn is NULL.
 */
extern n00b_quic_endpoint_t *
n00b_quic_conn_endpoint(n00b_quic_conn_t *conn);

/**
 * @brief Maximum QUIC connection-ID length, in bytes.
 *
 * Per RFC 9000 § 5.1.1, CIDs are 0..20 bytes.  picoquic clamps
 * to this same range.
 */
#define N00B_QUIC_MAX_CID_LEN 20

/**
 * @brief Connection-ID value passed by-out from
 *        `n00b_quic_conn_remote_cid`.
 *
 * Public struct (Principle 12 — public fields are intentional
 * and stable).  `len` ≤ `N00B_QUIC_MAX_CID_LEN`; the meaningful
 * bytes are `bytes[0..len)`.
 */
typedef struct {
    uint8_t bytes[N00B_QUIC_MAX_CID_LEN];
    size_t  len;
} n00b_quic_cid_t;

/**
 * @brief Copy the connection's *remote* CID into @p out.
 *
 * For a client-initiated connection this is the server-issued
 * CID — the bytes the client puts in the destination-CID field of
 * its outgoing 1-RTT packets.  When the server endpoint was
 * constructed with `.lb_cid_config = ...` the CID is the
 * AES-encrypted `<server_id>||<nonce>` (Phase 5 § 5.8,
 * `draft-ietf-quic-load-balancers`).  Decoders should pass
 * `out->bytes` (length `out->len`, expected to be
 * `N00B_QUIC_LB_CID_LEN`) through `n00b_quic_lb_cid_decode`
 * with the shared LB key.
 *
 * @param conn  Connection handle.
 * @param out   Receives the CID.  Caller-owned; never aliased.
 *
 * @return @c true if the CID was copied (handshake far enough
 *         along that picoquic has chosen one); @c false if
 *         @p conn or @p out is NULL or the connection has no
 *         remote CID yet.  On @c false, `out->len` is zero.
 */
extern bool
n00b_quic_conn_remote_cid(n00b_quic_conn_t *conn,
                          n00b_quic_cid_t  *out);

/**
 * @brief First channel on this connection (head of the channel list).
 *
 * Use together with @c n00b_quic_chan_next_in_conn to iterate.
 * Useful for server-side handlers that walk all open streams to look
 * for new data to process.
 *
 * @param conn Connection handle.
 * @return First channel, or NULL if @p conn has no open channels.
 */
extern n00b_quic_chan_t *
n00b_quic_conn_first_chan(n00b_quic_conn_t *conn);

/**
 * @brief Peer address as a `sockaddr_storage`, copied into @p out.
 *
 * On the server side this is the client's UDP source address; on the
 * client side it's the address we connected to.  For dual-stack
 * sockets the family on @p out reflects the wire family of the most
 * recent peer datagram (AF_INET / AF_INET6).
 *
 * @param conn Connection handle.
 * @param out  Destination buffer (caller-allocated).  Populated only
 *             on success.
 * @return true on success; false if @p conn or @p out is NULL or the
 *         connection is closed before a peer addr was learned.
 */
extern bool
n00b_quic_conn_peer_addr(n00b_quic_conn_t        *conn,
                         struct sockaddr_storage *out);

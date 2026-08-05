/**
 * @file socket_udp.h
 * @brief UDP datagram socket abstraction for the conduit system.
 *
 * `n00b_conduit_udp_t` wraps a UDP socket, registers it with an IO
 * backend, and publishes received datagrams on a typed topic.  Unlike
 * the TCP listener, there is no "accept" — every received datagram
 * carries its peer address inline so callers can multiplex packets
 * from many peers off a single socket (which is exactly what the QUIC
 * transport needs).
 *
 * ### Lifecycle
 *
 * ```c
 *     auto r = n00b_conduit_udp_bind(c, io);
 *     n00b_conduit_udp_t *u = n00b_result_get(r);
 *     n00b_conduit_topic_base_t *t = n00b_conduit_udp_recv_topic(u);
 *     // ... subscribe an inbox to t ...
 *     // poll the IO backend in your main loop ...
 *     n00b_conduit_udp_send(u, peer, peer_len, bytes, len);
 *     n00b_conduit_udp_close(u);
 * ```
 *
 * ### Allocator discipline
 *
 * The @c n00b_conduit_udp_t handle and every published
 * @c n00b_conduit_udp_datagram_t share the conduit's allocator (set
 * at @c n00b_conduit_new time).  Per
 * `MEMORY.md → conduit_allocator_audit.md`, this is the only safe
 * allocation policy for IO-thread-published memory.
 *
 * ### Send semantics
 *
 * @c n00b_conduit_udp_send is non-blocking by default.  On `EAGAIN`
 * it returns @c N00B_CONDUIT_ERR_IO with `errno == EAGAIN` so the
 * caller can either drop the packet (the QUIC pacer will reschedule)
 * or wait for an on-writable event.  We deliberately do **not** keep
 * an internal send queue: this is a primitive, not a transport.
 *
 * @see conduit/socket.h, conduit/conduit_types.h
 */
#pragma once

#include "conduit/conduit_types.h"
#include "conduit/inbox.h"
#include "conduit/topic.h"
#include "conduit/publisher.h"
#include "conduit/message.h"

#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

/* ===========================================================================
 * Datagram payload type (published on the recv topic)
 * =========================================================================== */

/**
 * @brief Payload published for each received datagram.
 *
 * @c bytes is heap-allocated under the conduit's allocator; ownership
 * transfers from publisher to inbox subscriber on consumption.  After
 * the message is popped, @c bytes remains valid only until the
 * subscriber explicitly releases the message or the GC reclaims it.
 */
typedef struct {
    struct sockaddr_storage peer;     /**< Source address of the datagram. */
    socklen_t               peer_len; /**< Valid bytes in @c peer. */
    uint8_t                *bytes;    /**< Datagram payload (owned). */
    size_t                  len;      /**< Length of @c bytes. */
    uint64_t                rx_ns;    /**< Monotonic nanoseconds at recvfrom. */
} n00b_conduit_udp_datagram_t;

N00B_CONDUIT_FULL_IMPL(n00b_conduit_udp_datagram_t);

typedef n00b_conduit_message_t(n00b_conduit_udp_datagram_t)
    n00b_conduit_udp_datagram_msg_t;
typedef n00b_conduit_inbox_t(n00b_conduit_udp_datagram_t)
    n00b_conduit_udp_datagram_inbox_t;

/* Convenience inbox factory (matches the n00b_conduit_sock_accept_inbox_new style). */
#define n00b_conduit_udp_inbox_new(c)                                          \
    ({                                                                         \
        n00b_conduit_t *_c = (c);                                               \
        n00b_conduit_udp_datagram_inbox_t *_inbox =                            \
            n00b_alloc_with_opts(n00b_conduit_udp_datagram_inbox_t,             \
                &(n00b_alloc_opts_t){.allocator = _c->allocator});             \
        n00b_conduit_inbox_init(n00b_conduit_udp_datagram_t,                   \
                                _inbox, _c, N00B_CONDUIT_BP_UNBOUNDED, 0);     \
        _inbox;                                                                \
    })

#define n00b_conduit_udp_subscribe(topic, inbox, ...)                          \
    n00b_conduit_subscribe(n00b_conduit_udp_datagram_t,                        \
                           (n00b_conduit_topic_t(n00b_conduit_udp_datagram_t) *)(topic), \
                           inbox, __VA_ARGS__)

#define n00b_conduit_udp_inbox_pop(inbox)                                      \
    n00b_conduit_inbox_pop_msg(n00b_conduit_udp_datagram_t, inbox)

#define n00b_conduit_udp_inbox_has_messages(inbox)                             \
    n00b_conduit_inbox_has_msg(n00b_conduit_udp_datagram_t, inbox)

/* ===========================================================================
 * UDP handle structure (public so callers can read fd / port; not opaque)
 * =========================================================================== */

/**
 * @brief UDP socket — owns a datagram FD, publishes received packets.
 */
struct n00b_conduit_udp {
    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;
    base_socket_t              fd;
    n00b_conduit_topic_base_t *recv_topic;   /**< topic for n00b_conduit_udp_datagram_t. */
    uint64_t                   udp_id;       /**< Unique-per-conduit identifier. */
    uint64_t                   rx_packets;   /**< Stats: datagrams received. */
    uint64_t                   rx_bytes;     /**< Stats: bytes received (payload only). */
    uint64_t                   tx_packets;   /**< Stats: datagrams sent. */
    uint64_t                   tx_bytes;     /**< Stats: bytes sent (payload only). */
    uint64_t                   rx_drops;     /**< Stats: datagrams dropped before publish. */
    _Atomic(bool)              active;
};

/* ===========================================================================
 * Public API
 * =========================================================================== */

/**
 * @brief Create a UDP socket bound to @p host:@p port and register it.
 *
 * If @p host is nullptr or empty, binds to `INADDR_ANY` (IPv4 wildcard).
 * If @p port is 0, the OS assigns an ephemeral port; query the assigned
 * port via @c n00b_conduit_udp_local_port.
 *
 * @param c    Conduit instance (must outlive the returned socket).
 * @param io   IO backend.
 * @param host Bind address as a string ("0.0.0.0", "127.0.0.1", "::") or
 *             nullptr / "" for any IPv4.
 * @param port Local port (0 = ephemeral).
 *
 * @return Result: ok with the new handle, or err(errno).
 *
 * @pre  @p c and @p io are non-NULL.
 * @post On success the socket FD is non-blocking, registered with the IO
 *       backend for read events, and listed in the conduit's listener dict.
 */
extern n00b_result_t(n00b_conduit_udp_t *)
n00b_conduit_udp_bind(n00b_conduit_t            *c,
                      n00b_conduit_io_backend_t *io,
                      const char                *host,
                      uint16_t                   port);

/**
 * @brief Get the recv topic for subscribing.
 *
 * Each delivered message has type @c n00b_conduit_udp_datagram_t.
 *
 * @param u UDP handle.
 * @return  Topic pointer; nullptr if @p u is nullptr.
 */
extern n00b_conduit_topic_base_t *
n00b_conduit_udp_recv_topic(n00b_conduit_udp_t *u);

/**
 * @brief Send a datagram to @p peer.
 *
 * Issues one `sendto` syscall.  Does **not** queue internally on EAGAIN —
 * callers wanting backpressure handling subscribe to writability events
 * on the underlying FD via the IO backend's primitives.
 *
 * @param u        UDP handle.
 * @param peer     Destination address.
 * @param peer_len Length of @p peer.
 * @param bytes    Payload to send (may be nullptr only if @p len is 0).
 * @param len      Number of bytes to send.
 *
 * @return Result of size_t: ok(N) where N is the bytes written
 *         (always equals @p len for UDP on success).  err(errno) on a
 *         syscall failure; specifically err(EAGAIN) when the kernel
 *         buffer is full.
 *
 * @pre @p u is non-NULL and active.
 */
extern n00b_result_t(size_t)
n00b_conduit_udp_send(n00b_conduit_udp_t    *u,
                      const struct sockaddr *peer,
                      socklen_t              peer_len,
                      const uint8_t         *bytes,
                      size_t                 len);

/**
 * @brief Read out the locally-bound address (post-bind).
 *
 * Useful when @p port was 0 and the OS assigned an ephemeral port.
 *
 * @param u        UDP handle.
 * @param out      Buffer to receive the local sockaddr.
 * @param out_len  In/out parameter — caller passes capacity in bytes; on
 *                 return holds the actual length written.
 *
 * @return Ok(true) on success; err(errno) on getsockname failure.
 */
extern n00b_result_t(bool)
n00b_conduit_udp_local_addr(n00b_conduit_udp_t *u,
                            struct sockaddr    *out,
                            socklen_t          *out_len);

/**
 * @brief Close the UDP socket and release its conduit registration.
 *
 * Idempotent.  Subsequent calls are no-ops.
 *
 * @param u UDP handle (may be NULL).
 *
 * @post @p u->fd is closed; the recv topic is closed; the IO backend no
 *       longer routes events for this FD.
 */
extern void n00b_conduit_udp_close(n00b_conduit_udp_t *u);

/**
 * @internal Dispatch a readiness event for this UDP socket.
 *
 * Called by the conduit IO loop; not a public-facing entry point.
 */
extern void
n00b_conduit_udp_dispatch(n00b_conduit_udp_t *u, uint32_t io_ops);

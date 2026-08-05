/*
 * socket_udp.c — UDP datagram socket abstraction for the conduit system.
 *
 * Mirrors the listener half of socket.c (the bind/dispatch/close trio) but
 * for SOCK_DGRAM.  Each received datagram is published as a typed
 * n00b_conduit_udp_datagram_t message on the socket's recv topic.
 */

#include "conduit/conduit.h"
#include "conduit/socket_udp.h"
#include "conduit/io.h"
#include "core/runtime.h"
#include "core/time.h"

#include <errno.h>
#include <string.h>

#ifdef _WIN32
#include "internal/win32_sockets.h"
#define N00B_CLOSE_SOCKET(fd) closesocket((SOCKET)(fd))
#define N00B_SOCK_ERRNO       WSAGetLastError()
#define N00B_EWOULDBLOCK      WSAEWOULDBLOCK
#define N00B_EAGAIN           WSAEWOULDBLOCK
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define N00B_CLOSE_SOCKET(fd) close(fd)
#define N00B_SOCK_ERRNO       errno
#define N00B_EWOULDBLOCK      EWOULDBLOCK
#define N00B_EAGAIN           EAGAIN
#endif

/* ===========================================================================
 * Helpers
 * =========================================================================== */

static n00b_result_t(int)
udp_make_nonblocking(base_socket_t fd)
{
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket((SOCKET)fd, FIONBIO, &mode) != 0)
        return n00b_result_err(int, N00B_SOCK_ERRNO);
    return n00b_result_ok(int, 0);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return n00b_result_err(int, errno);
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return n00b_result_err(int, errno);
    return n00b_result_ok(int, 0);
#endif
}

/* ===========================================================================
 * Bind
 * =========================================================================== */

n00b_result_t(n00b_conduit_udp_t *)
n00b_conduit_udp_bind(n00b_conduit_t            *c,
                      n00b_conduit_io_backend_t *io,
                      const char                *host,
                      uint16_t                   port)
{
    if (!c || !io) {
        return n00b_result_err(n00b_conduit_udp_t *, EINVAL);
    }

    base_socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == BASE_INVALID_SOCKET) {
        return n00b_result_err(n00b_conduit_udp_t *, N00B_SOCK_ERRNO);
    }

    int opt = 1;
#ifdef _WIN32
    int reuse_opt = SO_EXCLUSIVEADDRUSE;
#else
    int reuse_opt = SO_REUSEADDR;
#endif
    if (setsockopt(fd, SOL_SOCKET, reuse_opt,
                   (const char *)&opt, sizeof(opt)) != 0) {
        int err = N00B_SOCK_ERRNO;
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_udp_t *, err);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (host && host[0] != '\0') {
        if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
            N00B_CLOSE_SOCKET(fd);
            return n00b_result_err(n00b_conduit_udp_t *, EINVAL);
        }
    }
    else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = N00B_SOCK_ERRNO;
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_udp_t *, err);
    }

    {
        auto nb_r = udp_make_nonblocking(fd);
        if (n00b_result_is_err(nb_r)) {
            N00B_CLOSE_SOCKET(fd);
            return n00b_result_err(n00b_conduit_udp_t *,
                                   n00b_result_get_err(nb_r));
        }
    }

    n00b_conduit_udp_t *u = n00b_alloc_with_opts(n00b_conduit_udp_t,
                              &(n00b_alloc_opts_t){.allocator = c->allocator});

    u->conduit = c;
    u->io      = io;
    u->fd      = fd;
    u->udp_id  = n00b_atomic_add(&c->next_listener_id, 1);
    n00b_atomic_store(&u->active, true);

    /* Typed initializer so subscriptions is pool-allocated — see the matching
     * comment in n00b_conduit_conn_from_fd (socket.c). */
    n00b_conduit_topic_t(n00b_conduit_udp_datagram_t) *recv_topic =
        n00b_conduit_topic_init(n00b_conduit_udp_datagram_t,
                                c, N00B_CONDUIT_URI_UDP_RECV(u->udp_id));
    if (!recv_topic) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_udp_t *, ENOMEM);
    }
    u->recv_topic = (n00b_conduit_topic_base_t *)recv_topic;

    /* Register with the IO backend; tag as udp via the variant. */
    n00b_conduit_io_target_t *target = n00b_alloc_with_opts(n00b_conduit_io_target_t,
                                          &(n00b_alloc_opts_t){.allocator = c->allocator});
    _n00b_variant_set_ptr(target, n00b_conduit_udp_t *, u);
    n00b_conduit_io_watch(io, fd, N00B_CONDUIT_IO_READ, target);

    return n00b_result_ok(n00b_conduit_udp_t *, u);
}

n00b_conduit_topic_base_t *
n00b_conduit_udp_recv_topic(n00b_conduit_udp_t *u)
{
    return u ? u->recv_topic : nullptr;
}

/* ===========================================================================
 * Dispatch (recvfrom loop on read-ready)
 * =========================================================================== */

void
n00b_conduit_udp_dispatch(n00b_conduit_udp_t *u, uint32_t io_ops)
{
    if (!u || !n00b_atomic_load(&u->active)) {
        return;
    }
    if (!(io_ops & N00B_CONDUIT_IO_READ)) {
        return;
    }

    n00b_conduit_topic_base_t *topic = u->recv_topic;

    /* Scratch buffer for recvfrom; sized for max IPv6 UDP payload (RFC 8200
     * hints at 65527 max).  Stays on the stack — no allocation per-iteration
     * beyond the per-datagram buffer copy.  */
    uint8_t buf[65536];

    while (1) {
        struct sockaddr_storage peer;
        socklen_t               peer_len = sizeof(peer);

        ssize_t n = recvfrom(u->fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            int err = N00B_SOCK_ERRNO;
            if (err == N00B_EAGAIN || err == N00B_EWOULDBLOCK) {
                break;
            }
#ifndef _WIN32
            if (err == EINTR) {
                continue;
            }
#endif
            /* Unrecoverable read error.  We do not publish — drop and break;
             * a future on_error callback could surface this. */
            u->rx_drops++;
            break;
        }

        n00b_result_t(n00b_conduit_publisher_t *) pub_res =
            n00b_conduit_publish_try_claim(topic);
        if (n00b_result_is_err(pub_res)) {
            /* Topic is closed / no publisher available — drop. */
            u->rx_drops++;
            continue;
        }
        n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

        n00b_conduit_udp_datagram_msg_t *msg = n00b_alloc_with_opts(
            n00b_conduit_udp_datagram_msg_t,
            &(n00b_alloc_opts_t){.allocator = u->conduit->allocator});

        msg->header.type       = N00B_CONDUIT_MSG_USER;
        msg->header.topic      = topic;
        msg->header.generation = n00b_conduit_topic_generation(topic);
        msg->header.epoch      = n00b_conduit_topic_epoch(topic);
        msg->header.timestamp  = 0;
        msg->header.next       = nullptr;

        msg->payload.peer     = peer;
        msg->payload.peer_len = peer_len;
        msg->payload.len      = (size_t)n;
        msg->payload.rx_ns    = (uint64_t)n00b_ns_timestamp();

        if (n > 0) {
            uint8_t *bytes = n00b_alloc_array_with_opts(uint8_t, (size_t)n,
                                &(n00b_alloc_opts_t){
                                    .allocator = u->conduit->allocator,
                                    .no_scan   = true,
                                });
            memcpy(bytes, buf, (size_t)n);
            msg->payload.bytes = bytes;
        }
        else {
            msg->payload.bytes = nullptr;
        }

        u->rx_packets++;
        u->rx_bytes += (uint64_t)n;

        n00b_conduit_topic_deliver_msg(
            n00b_conduit_udp_datagram_t,
            (n00b_conduit_topic_t(n00b_conduit_udp_datagram_t) *)topic,
            msg,
            N00B_CONDUIT_OP_ALL);

        n00b_conduit_publish_yield(pub);
    }
}

/* ===========================================================================
 * Send
 * =========================================================================== */

n00b_result_t(size_t)
n00b_conduit_udp_send(n00b_conduit_udp_t    *u,
                      const struct sockaddr *peer,
                      socklen_t              peer_len,
                      const uint8_t         *bytes,
                      size_t                 len)
{
    if (!u || !n00b_atomic_load(&u->active)) {
        return n00b_result_err(size_t, EBADF);
    }
    if (!peer || peer_len == 0) {
        return n00b_result_err(size_t, EINVAL);
    }
    if (!bytes && len > 0) {
        return n00b_result_err(size_t, EINVAL);
    }

    ssize_t n = sendto(u->fd, bytes, len, 0, peer, peer_len);
    if (n < 0) {
        return n00b_result_err(size_t, N00B_SOCK_ERRNO);
    }

    u->tx_packets++;
    u->tx_bytes += (uint64_t)n;

    return n00b_result_ok(size_t, (size_t)n);
}

/* ===========================================================================
 * Local addr (after bind)
 * =========================================================================== */

n00b_result_t(bool)
n00b_conduit_udp_local_addr(n00b_conduit_udp_t *u,
                            struct sockaddr    *out,
                            socklen_t          *out_len)
{
    if (!u || !out || !out_len) {
        return n00b_result_err(bool, EINVAL);
    }
    if (getsockname(u->fd, out, out_len) < 0) {
        return n00b_result_err(bool, N00B_SOCK_ERRNO);
    }
    return n00b_result_ok(bool, true);
}

/* ===========================================================================
 * Close
 * =========================================================================== */

void
n00b_conduit_udp_close(n00b_conduit_udp_t *u)
{
    if (!u) {
        return;
    }
    if (!n00b_atomic_read_then_set(&u->active, false)) {
        return; /* already closed */
    }

    n00b_conduit_io_unwatch(u->io, u->fd);
    N00B_CLOSE_SOCKET(u->fd);
    n00b_conduit_topic_close(u->recv_topic);
    u->fd         = BASE_INVALID_SOCKET;
    u->recv_topic = nullptr;
}

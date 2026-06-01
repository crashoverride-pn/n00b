/*
 * socket.c - Socket abstraction for conduit
 *
 * Implements listeners (accept loop) and connections (managed FD wrapper).
 */

#include "conduit/conduit.h"
#include "conduit/socket.h"
#include "conduit/io.h"
#include <errno.h>
#include <string.h>

#ifdef _WIN32
#include "internal/win32_sockets.h"
#define N00B_CLOSE_SOCKET(fd) closesocket((SOCKET)(fd))
#define N00B_SOCK_ERRNO       WSAGetLastError()
#define N00B_EWOULDBLOCK      WSAEWOULDBLOCK
#define N00B_EINPROGRESS      WSAEWOULDBLOCK
#define N00B_ECONNREFUSED     WSAECONNREFUSED
#define N00B_ECONNRESET       WSAECONNRESET
#define N00B_ETIMEDOUT        WSAETIMEDOUT
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#define N00B_CLOSE_SOCKET(fd) close(fd)
#define N00B_SOCK_ERRNO       errno
#define N00B_EWOULDBLOCK      EWOULDBLOCK
#define N00B_EINPROGRESS      EINPROGRESS
#define N00B_ECONNREFUSED     ECONNREFUSED
#define N00B_ECONNRESET       ECONNRESET
#define N00B_ETIMEDOUT        ETIMEDOUT
#endif

// ============================================================================
// Listener dict helpers
// ============================================================================

static void
listener_insert(n00b_conduit_t *c, n00b_conduit_listener_t *listener)
{
    n00b_dict_untyped_put(&c->listeners, (void *)(intptr_t)listener->fd, listener);
}

static void
listener_remove(n00b_conduit_t *c, n00b_conduit_listener_t *listener)
{
    n00b_dict_untyped_remove(&c->listeners, (void *)(intptr_t)listener->fd);
}

n00b_option_t(n00b_conduit_listener_t *)
n00b_conduit_listener_get(n00b_conduit_t *c, int fd)
{
    if (!c || fd < 0) {
        return n00b_option_none(n00b_conduit_listener_t *);
    }

    bool found = false;
    void *val = n00b_dict_untyped_get(&c->listeners, (void *)(intptr_t)fd, &found);
    if (found) {
        return n00b_option_set(n00b_conduit_listener_t *, (n00b_conduit_listener_t *)val);
    }
    return n00b_option_none(n00b_conduit_listener_t *);
}

// ============================================================================
// Listener implementation
// ============================================================================

/*
 * Shared post-bind/post-listen wireup. Caller owns `fd` on entry; the
 * helper takes ownership on success (and on internal failure paths
 * the helper closes `fd` before returning the error). Used by both
 * the AF_INET and the AF_UNIX listener entry points so the
 * make_nonblocking / accept_topic / io_watch / listener_insert
 * sequence lives in exactly one place. `allocator == nullptr` selects
 * `c->allocator`.
 */
static n00b_result_t(n00b_conduit_listener_t *)
finalize_listener(n00b_conduit_t            *c,
                  n00b_conduit_io_backend_t *io,
                  int                        fd,
                  n00b_allocator_t          *allocator);

/*
 * Shared post-socket wireup for outbound connects. On entry `fd` is
 * already a non-blocking socket (the caller has chosen the address
 * family). The helper allocates the conn struct, attaches an
 * fd_owner, wires up the status topic and the connect-completion
 * hook, and returns the conn ready for the caller to call
 * `connect(2)` on. The caller then handles the connect return value
 * (immediate success vs EINPROGRESS) via `connect_finalize`.
 * `allocator == nullptr` selects `c->allocator`.
 */
static n00b_result_t(n00b_conduit_conn_t *)
prepare_outbound_conn(n00b_conduit_t            *c,
                      n00b_conduit_io_backend_t *io,
                      int                        fd,
                      n00b_allocator_t          *allocator);

/*
 * Post-connect() finishing for outbound conns. `connect_ret` is the
 * return code from connect(2) on the conn's fd; `connect_errno` is
 * the captured errno on a non-zero return.
 *
 *  - ret == 0: synchronously fire CONNECTED on the status topic.
 *  - ret < 0, errno == EINPROGRESS: leave pending; on_first_writable
 *    will fire when the kernel completes the handshake.
 *  - otherwise: close the fd, return errno.
 */
static n00b_result_t(n00b_conduit_conn_t *)
connect_finalize(n00b_conduit_conn_t *conn,
                 int                  connect_ret,
                 int                  connect_errno);

static n00b_result_t(int)
make_nonblocking(int fd)
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

n00b_result_t(n00b_conduit_listener_t *)
n00b_conduit_listen_tcp(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                        n00b_string_t *host, uint16_t port, int backlog)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    if (!c || !io) {
        return n00b_result_err(n00b_conduit_listener_t *, EINVAL);
    }

    int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return n00b_result_err(n00b_conduit_listener_t *, N00B_SOCK_ERRNO);
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (host && host->u8_bytes) {
        if (inet_pton(AF_INET, host->data, &addr.sin_addr) != 1) {
            N00B_CLOSE_SOCKET(fd);
            return n00b_result_err(n00b_conduit_listener_t *, EINVAL);
        }
    }
    else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_listener_t *, N00B_SOCK_ERRNO);
    }

    if (backlog <= 0) {
        backlog = 128;
    }
    if (listen(fd, backlog) < 0) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_listener_t *, N00B_SOCK_ERRNO);
    }

    return finalize_listener(c, io, fd, allocator);
}

static n00b_result_t(n00b_conduit_listener_t *)
finalize_listener(n00b_conduit_t            *c,
                  n00b_conduit_io_backend_t *io,
                  int                        fd,
                  n00b_allocator_t          *allocator)
{
    {
        auto nb_r = make_nonblocking(fd);
        if (n00b_result_is_err(nb_r)) {
            N00B_CLOSE_SOCKET(fd);
            return n00b_result_err(n00b_conduit_listener_t *,
                                    n00b_result_get_err(nb_r));
        }
    }

    n00b_allocator_t *alloc = allocator ? allocator : c->allocator;

    n00b_conduit_listener_t *listener =
        n00b_alloc_with_opts(n00b_conduit_listener_t,
                              &(n00b_alloc_opts_t){.allocator = alloc});

    listener->conduit     = c;
    listener->io          = io;
    listener->fd          = fd;
    listener->listener_id = n00b_atomic_add(&c->next_listener_id, 1);
    n00b_atomic_store(&listener->active, true);

    n00b_result_t(n00b_conduit_topic_base_t *) res =
        n00b_conduit_topic_get(c,
                                N00B_CONDUIT_URI_SOCK_ACCEPT(listener->listener_id),
                                sizeof(n00b_conduit_topic_t(n00b_conduit_sock_accept_payload_t)));
    if (n00b_result_is_err(res)) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_listener_t *, ENOMEM);
    }
    listener->accept_topic = n00b_result_get(res);

    // Register with I/O backend for read events (accept readiness).
    // Wrap in a variant so the IO dispatch loop can discriminate.
    n00b_conduit_io_target_t *target =
        n00b_alloc_with_opts(n00b_conduit_io_target_t,
                              &(n00b_alloc_opts_t){.allocator = alloc});
    _n00b_variant_set_ptr(target, n00b_conduit_listener_t *, listener);
    listener->io_target = target;
    n00b_conduit_io_watch(io, fd, N00B_CONDUIT_IO_READ, target);

    listener_insert(c, listener);

    return n00b_result_ok(n00b_conduit_listener_t *, listener);
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_listener_accept_topic(n00b_conduit_listener_t *listener)
{
    return n00b_option_from_nullable(n00b_conduit_topic_base_t *,
                                     listener ? listener->accept_topic : nullptr);
}

void
n00b_conduit_listener_close(n00b_conduit_listener_t *listener)
{
    if (!listener) {
        return;
    }

    n00b_atomic_store(&listener->active, false);

    listener_remove(listener->conduit, listener);
    n00b_conduit_io_unwatch(listener->io, listener->fd);
    N00B_CLOSE_SOCKET(listener->fd);
    n00b_conduit_topic_close(listener->accept_topic);
    // The io watch target was allocated in n00b_conduit_listener_create and
    // is no longer referenced once the fd is unwatched; free it so a
    // create/close listener cycle does not leak.
    n00b_free(listener->io_target);
    listener->io_target = nullptr;
}

void
n00b_conduit_listener_dispatch(n00b_conduit_listener_t *listener, uint32_t io_ops)
{
    if (!listener || !n00b_atomic_load(&listener->active)) {
        return;
    }

    if (!(io_ops & N00B_CONDUIT_IO_READ)) {
        return;
    }

    n00b_conduit_topic_base_t *topic = listener->accept_topic;

    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = (int)accept(listener->fd,
                                     (struct sockaddr *)&client_addr,
                                     &addr_len);
        if (client_fd < 0) {
            int err = N00B_SOCK_ERRNO;
            if (err == N00B_EWOULDBLOCK
#ifndef _WIN32
                || err == EAGAIN
#endif
            ) {
                break;
            }
#ifndef _WIN32
            if (err == EINTR) {
                continue;
            }
#endif
            break;
        }

        (void)make_nonblocking(client_fd);

        n00b_result_t(n00b_conduit_publisher_t *) pub_res =
            n00b_conduit_publish_try_claim(topic);
        if (n00b_result_is_err(pub_res)) {
            N00B_CLOSE_SOCKET(client_fd);
            continue;
        }
        n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

        n00b_conduit_sock_accept_msg_t *msg = n00b_alloc_with_opts(
            n00b_conduit_sock_accept_msg_t,
            &(n00b_alloc_opts_t){.allocator = listener->conduit->allocator});

        msg->header.type       = N00B_CONDUIT_MSG_USER;
        msg->header.topic      = topic;
        msg->header.generation = n00b_conduit_topic_generation(topic);
        msg->header.epoch      = n00b_conduit_topic_epoch(topic);
        msg->header.timestamp  = 0;
        msg->header.next       = nullptr;

        msg->payload.client_fd = client_fd;
        msg->payload.addr      = client_addr;
        msg->payload.addr_len  = addr_len;

        n00b_conduit_topic_deliver_msg(
            n00b_conduit_sock_accept_payload_t,
            (n00b_conduit_topic_t(n00b_conduit_sock_accept_payload_t) *)topic,
            msg,
            N00B_CONDUIT_OP_ALL);

        n00b_conduit_publish_yield(pub);
    }
}

// ============================================================================
// Connection implementation
// ============================================================================

static void
publish_conn_status(n00b_conduit_conn_t *conn,
                    n00b_conduit_conn_event_t event, int error_code)
{
    n00b_conduit_topic_base_t *topic = conn->status_topic;

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(topic);
    if (n00b_result_is_err(pub_res)) {
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_sock_status_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_sock_status_msg_t,
        &(n00b_alloc_opts_t){.allocator = conn->conduit->allocator});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = topic;
    msg->header.generation = n00b_conduit_topic_generation(topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.fd         = conn->fd;
    msg->payload.event      = event;
    msg->payload.error_code = error_code;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_sock_status_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_sock_status_payload_t) *)topic,
        msg,
        N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_yield(pub);
}

n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_from_fd(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                          int fd)
{
    if (!c || !io || fd < 0) {
        return n00b_result_err(n00b_conduit_conn_t *, EINVAL);
    }

    n00b_conduit_conn_t *conn = n00b_alloc_with_opts(
        n00b_conduit_conn_t,
        &(n00b_alloc_opts_t){.allocator = c->allocator});

    conn->conduit         = c;
    conn->fd              = fd;
    conn->connect_pending = false;
    n00b_atomic_store(&conn->conn_state, N00B_CONDUIT_CONN_ST_CONNECTED);

    auto manage_r = n00b_conduit_fd_manage(c, io, fd, true);
    if (n00b_result_is_err(manage_r)) {
        return n00b_result_err(n00b_conduit_conn_t *, n00b_result_get_err(manage_r));
    }
    conn->owner = n00b_result_get(manage_r);

    n00b_result_t(n00b_conduit_topic_base_t *) res =
        n00b_conduit_topic_get(c, N00B_CONDUIT_URI_SOCK_STATUS(fd),
                                sizeof(n00b_conduit_topic_t(n00b_conduit_sock_status_payload_t)));
    if (n00b_result_is_err(res)) {
        return n00b_result_err(n00b_conduit_conn_t *, ENOMEM);
    }
    conn->status_topic = n00b_result_get(res);

    publish_conn_status(conn, N00B_CONDUIT_CONN_CONNECTED, 0);

    return n00b_result_ok(n00b_conduit_conn_t *, conn);
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_conn_status_topic(n00b_conduit_conn_t *conn)
{
    return n00b_option_from_nullable(n00b_conduit_topic_base_t *,
                                     conn ? conn->status_topic : nullptr);
}

n00b_option_t(n00b_conduit_fd_owner_t *)
n00b_conduit_conn_fd_owner(n00b_conduit_conn_t *conn)
{
    return n00b_option_from_nullable(n00b_conduit_fd_owner_t *,
                                     conn ? conn->owner : nullptr);
}

void
n00b_conduit_conn_close(n00b_conduit_conn_t *conn)
{
    if (!conn) {
        return;
    }

    int prev = n00b_atomic_read_then_set(&conn->conn_state,
                                          N00B_CONDUIT_CONN_ST_CLOSED);
    if (prev == N00B_CONDUIT_CONN_ST_CLOSED) {
        return;
    }

    publish_conn_status(conn, N00B_CONDUIT_CONN_CLOSED, 0);
    n00b_conduit_topic_close(conn->status_topic);
}

// ============================================================================
// Outbound connect
// ============================================================================

static void
connect_completion_hook(n00b_conduit_fd_owner_t *owner, void *ctx)
{
    n00b_conduit_conn_t *conn = ctx;

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(owner->fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);

    conn->connect_pending = false;

    if (so_error == 0) {
        n00b_atomic_store(&conn->conn_state, N00B_CONDUIT_CONN_ST_CONNECTED);
        publish_conn_status(conn, N00B_CONDUIT_CONN_CONNECTED, 0);
    }
    else {
        n00b_atomic_store(&conn->conn_state, N00B_CONDUIT_CONN_ST_ERROR);

        n00b_conduit_conn_event_t event;
        switch (so_error) {
        case N00B_ECONNREFUSED:
            event = N00B_CONDUIT_CONN_REFUSED;
            break;
        case N00B_ECONNRESET:
            event = N00B_CONDUIT_CONN_RESET;
            break;
        case N00B_ETIMEDOUT:
            event = N00B_CONDUIT_CONN_TIMEOUT;
            break;
        default:
            event = N00B_CONDUIT_CONN_ERROR;
            break;
        }

        publish_conn_status(conn, event, so_error);
    }
}

static n00b_result_t(n00b_conduit_conn_t *)
prepare_outbound_conn(n00b_conduit_t            *c,
                      n00b_conduit_io_backend_t *io,
                      int                        fd,
                      n00b_allocator_t          *allocator)
{
    n00b_allocator_t *alloc = allocator ? allocator : c->allocator;

    n00b_conduit_conn_t *conn = n00b_alloc_with_opts(
        n00b_conduit_conn_t,
        &(n00b_alloc_opts_t){.allocator = alloc});

    conn->conduit         = c;
    conn->fd              = fd;
    conn->connect_pending = true;
    n00b_atomic_store(&conn->conn_state, N00B_CONDUIT_CONN_ST_CONNECTING);

    auto manage_r = n00b_conduit_fd_manage(c, io, fd, true);
    if (n00b_result_is_err(manage_r)) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_conn_t *,
                                n00b_result_get_err(manage_r));
    }
    conn->owner = n00b_result_get(manage_r);

    n00b_result_t(n00b_conduit_topic_base_t *) res =
        n00b_conduit_topic_get(c,
                                N00B_CONDUIT_URI_SOCK_STATUS(fd),
                                sizeof(n00b_conduit_topic_t(n00b_conduit_sock_status_payload_t)));
    if (n00b_result_is_err(res)) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_conn_t *, ENOMEM);
    }
    conn->status_topic = n00b_result_get(res);

    conn->owner->on_first_writable     = connect_completion_hook;
    conn->owner->on_first_writable_ctx = conn;

    return n00b_result_ok(n00b_conduit_conn_t *, conn);
}

static n00b_result_t(n00b_conduit_conn_t *)
connect_finalize(n00b_conduit_conn_t *conn,
                 int                  connect_ret,
                 int                  connect_errno)
{
    if (connect_ret < 0) {
        if (connect_errno != N00B_EINPROGRESS) {
            // Tear down through the full conn-close path so the
            // fd_owner registered by prepare_outbound_conn is
            // unwatched and the status topic closed — closing only
            // the raw fd would leave a dangling owner in the IO
            // backend.
            n00b_conduit_conn_close(conn);
            return n00b_result_err(n00b_conduit_conn_t *, connect_errno);
        }
        return n00b_result_ok(n00b_conduit_conn_t *, conn);
    }

    // Immediate connection (e.g. localhost AF_INET or unix-domain).
    conn->connect_pending              = false;
    conn->owner->on_first_writable     = nullptr;
    conn->owner->on_first_writable_ctx = nullptr;
    n00b_atomic_store(&conn->conn_state, N00B_CONDUIT_CONN_ST_CONNECTED);
    publish_conn_status(conn, N00B_CONDUIT_CONN_CONNECTED, 0);
    return n00b_result_ok(n00b_conduit_conn_t *, conn);
}

n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_tcp(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                      n00b_string_t *host, uint16_t port)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    if (!c || !io || !host || !host->u8_bytes) {
        return n00b_result_err(n00b_conduit_conn_t *, EINVAL);
    }

    int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return n00b_result_err(n00b_conduit_conn_t *, N00B_SOCK_ERRNO);
    }

    {
        auto nb_r = make_nonblocking(fd);
        if (n00b_result_is_err(nb_r)) {
            N00B_CLOSE_SOCKET(fd);
            return n00b_result_err(n00b_conduit_conn_t *,
                                    n00b_result_get_err(nb_r));
        }
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, host->data, &addr.sin_addr) != 1) {
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_conn_t *, EINVAL);
    }

    auto conn_r = prepare_outbound_conn(c, io, fd, allocator);
    if (n00b_result_is_err(conn_r)) {
        return conn_r;
    }
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved_errno = N00B_SOCK_ERRNO;
    return connect_finalize(conn, ret, saved_errno);
}

// ============================================================================
// AF_UNIX listener + outbound connect
// ============================================================================

#ifdef _WIN32

n00b_result_t(n00b_conduit_listener_t *)
n00b_conduit_listen_unix([[maybe_unused]] n00b_conduit_t            *c,
                         [[maybe_unused]] n00b_conduit_io_backend_t *io,
                         [[maybe_unused]] n00b_string_t             *socket_path,
                         [[maybe_unused]] int                        backlog)
    _kargs {
        bool              unlink_stale = false;
        int               mode         = 0;
        n00b_allocator_t *allocator    = nullptr;
    }
{
    return n00b_result_err(n00b_conduit_listener_t *,
                            N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_unix([[maybe_unused]] n00b_conduit_t            *c,
                       [[maybe_unused]] n00b_conduit_io_backend_t *io,
                       [[maybe_unused]] n00b_string_t             *socket_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    return n00b_result_err(n00b_conduit_conn_t *,
                            N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

#else

/*
 * Fill `addr` for an AF_UNIX socket targeting `socket_path`. Returns
 * Ok(addr_len) on success, Err(errno) if the path doesn't fit in
 * sun_path. The size of sun_path varies by platform (104 on darwin,
 * 108 on Linux); we use sizeof(addr->sun_path) which captures
 * whichever is correct at compile time.
 */
static n00b_result_t(socklen_t)
build_unix_sockaddr(struct sockaddr_un *addr, n00b_string_t *socket_path)
{
    *addr = (struct sockaddr_un){};
    addr->sun_family = AF_UNIX;

    size_t path_len = socket_path->u8_bytes;
    // Leave room for the trailing NUL byte inside sun_path.
    if (path_len >= sizeof(addr->sun_path)) {
        return n00b_result_err(socklen_t, ENAMETOOLONG);
    }
    memcpy(addr->sun_path, socket_path->data, path_len);
    addr->sun_path[path_len] = '\0';

    /*
     * SUN_LEN portability: not all platforms ship the macro.
     * We use offsetof + path_len + 1 (for the NUL) which is the
     * standard portable form. The kernel only cares about the
     * sun_family field plus the path bytes up to the terminator.
     */
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path)
                                + path_len + 1);
    return n00b_result_ok(socklen_t, len);
}

n00b_result_t(n00b_conduit_listener_t *)
n00b_conduit_listen_unix(n00b_conduit_t            *c,
                         n00b_conduit_io_backend_t *io,
                         n00b_string_t             *socket_path,
                         int                        backlog)
    _kargs {
        bool              unlink_stale = false;
        int               mode         = 0;
        n00b_allocator_t *allocator    = nullptr;
    }
{
    if (!c || !io || !socket_path) {
        return n00b_result_err(n00b_conduit_listener_t *, EINVAL);
    }

    struct sockaddr_un addr = {};
    socklen_t addr_len = 0;
    {
        auto a_r = build_unix_sockaddr(&addr, socket_path);
        if (n00b_result_is_err(a_r)) {
            return n00b_result_err(n00b_conduit_listener_t *,
                                    n00b_result_get_err(a_r));
        }
        addr_len = n00b_result_get(a_r);
    }

    if (unlink_stale) {
        // ENOENT is fine — there was no stale file to remove.
        if (unlink(socket_path->data) != 0 && errno != ENOENT) {
            return n00b_result_err(n00b_conduit_listener_t *, errno);
        }
    }

    int fd = (int)socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return n00b_result_err(n00b_conduit_listener_t *, errno);
    }

    if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
        int saved_errno = errno;
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_listener_t *, saved_errno);
    }

    if (mode != 0) {
        if (chmod(socket_path->data, (mode_t)mode) != 0) {
            int saved_errno = errno;
            N00B_CLOSE_SOCKET(fd);
            // Leave the socket file in place; the caller may want to
            // inspect it. chmod failure should not silently succeed.
            return n00b_result_err(n00b_conduit_listener_t *, saved_errno);
        }
    }

    if (backlog <= 0) {
        backlog = 128;
    }
    if (listen(fd, backlog) < 0) {
        int saved_errno = errno;
        N00B_CLOSE_SOCKET(fd);
        return n00b_result_err(n00b_conduit_listener_t *, saved_errno);
    }

    return finalize_listener(c, io, fd, allocator);
}

n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_unix(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                       n00b_string_t *socket_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    if (!c || !io || !socket_path) {
        return n00b_result_err(n00b_conduit_conn_t *, EINVAL);
    }

    struct sockaddr_un addr = {};
    socklen_t addr_len = 0;
    {
        auto a_r = build_unix_sockaddr(&addr, socket_path);
        if (n00b_result_is_err(a_r)) {
            return n00b_result_err(n00b_conduit_conn_t *,
                                    n00b_result_get_err(a_r));
        }
        addr_len = n00b_result_get(a_r);
    }

    int fd = (int)socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return n00b_result_err(n00b_conduit_conn_t *, errno);
    }

    {
        auto nb_r = make_nonblocking(fd);
        if (n00b_result_is_err(nb_r)) {
            N00B_CLOSE_SOCKET(fd);
            return n00b_result_err(n00b_conduit_conn_t *,
                                    n00b_result_get_err(nb_r));
        }
    }

    auto conn_r = prepare_outbound_conn(c, io, fd, allocator);
    if (n00b_result_is_err(conn_r)) {
        return conn_r;
    }
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    int ret = connect(fd, (struct sockaddr *)&addr, addr_len);
    int saved_errno = errno;
    return connect_finalize(conn, ret, saved_errno);
}

#endif

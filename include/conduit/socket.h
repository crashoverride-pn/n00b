/**
 * @file socket.h
 * @brief TCP socket abstraction for the conduit system.
 *
 * Two distinct concepts:
 * - **Listener**: Owns a listening socket FD directly, accepts connections,
 *   publishes new connections as events. Does not use fd_manage.
 * - **Connection**: Wraps a @ref n00b_conduit_fd_owner_t for byte-stream I/O
 *   via the managed FD infrastructure. Adds a lifecycle/status topic.
 *
 * Usage:
 * @code
 *     n00b_conduit_listener_t *l =
 *         n00b_conduit_listen_tcp(c, io, nullptr, 8080, 128);
 *     // subscribe to n00b_conduit_listener_accept_topic(l) ...
 * @endcode
 */
#pragma once

#include "conduit/fd_managed.h"
#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

// Forward declarations
typedef struct n00b_conduit_conn     n00b_conduit_conn_t;

// ============================================================================
// Connection Lifecycle Events
// ============================================================================

/**
 * @brief Connection lifecycle event types.
 */
typedef enum {
    N00B_CONDUIT_CONN_CONNECTED = 1, /**< Connection established */
    N00B_CONDUIT_CONN_REFUSED   = 2, /**< Connection refused */
    N00B_CONDUIT_CONN_RESET     = 3, /**< Connection reset by peer */
    N00B_CONDUIT_CONN_TIMEOUT   = 4, /**< Connection timed out */
    N00B_CONDUIT_CONN_ERROR     = 5, /**< Connection error */
    N00B_CONDUIT_CONN_CLOSED    = 6, /**< Connection closed */
} n00b_conduit_conn_event_t;

// ============================================================================
// Payload Types
// ============================================================================

/**
 * @brief Payload published when a listener accepts a new connection.
 *
 * The subscriber **owns** @c client_fd: it must either wrap it with
 * @c n00b_conduit_conn_from_fd or close it explicitly.  Failing to do
 * either will leak the file descriptor.
 */
typedef struct {
    base_socket_t           client_fd;    /**< Raw socket — owned by subscriber */
    struct sockaddr_storage addr;         /**< Client socket address */
    socklen_t               addr_len;     /**< Length of address structure */
} n00b_conduit_sock_accept_payload_t;

/**
 * @brief Connection lifecycle event payload.
 */
typedef struct {
    base_socket_t             fd;          /**< Native socket */
    n00b_conduit_conn_event_t event;       /**< Lifecycle event */
    int                       error_code;  /**< errno if error occurred */
} n00b_conduit_sock_status_payload_t;

// ============================================================================
// Socket type instantiations
// ============================================================================

N00B_CONDUIT_FULL_IMPL(n00b_conduit_sock_accept_payload_t);
N00B_CONDUIT_FULL_IMPL(n00b_conduit_sock_status_payload_t);

// ============================================================================
// Convenience type aliases
// ============================================================================

typedef n00b_conduit_message_t(n00b_conduit_sock_accept_payload_t)
    n00b_conduit_sock_accept_msg_t;
typedef n00b_conduit_message_t(n00b_conduit_sock_status_payload_t)
    n00b_conduit_sock_status_msg_t;

typedef n00b_conduit_inbox_t(n00b_conduit_sock_accept_payload_t)
    n00b_conduit_sock_accept_inbox_t;
typedef n00b_conduit_inbox_t(n00b_conduit_sock_status_payload_t)
    n00b_conduit_sock_status_inbox_t;

// ============================================================================
// Convenience inbox macros
// ============================================================================

/** @brief Create a new inbox for socket accept events. */
#define n00b_conduit_sock_accept_inbox_new(c)                                  \
    ({                                                                         \
        n00b_conduit_t *_n00b_sock_c = (c);                                    \
        n00b_conduit_sock_accept_inbox_t *_inbox =                             \
            n00b_alloc_with_opts(n00b_conduit_sock_accept_inbox_t,             \
                                 &(n00b_alloc_opts_t){                         \
                                     .allocator = _n00b_sock_c->allocator,     \
                                 });                                           \
        n00b_conduit_inbox_init(n00b_conduit_sock_accept_payload_t,            \
                                _inbox, _n00b_sock_c,                          \
                                N00B_CONDUIT_BP_UNBOUNDED, 0);                 \
        _inbox;                                                                \
    })

/** @brief Create a new inbox for socket status events. */
#define n00b_conduit_sock_status_inbox_new(c)                                  \
    ({                                                                         \
        n00b_conduit_t *_n00b_sock_c = (c);                                    \
        n00b_conduit_sock_status_inbox_t *_inbox =                             \
            n00b_alloc_with_opts(n00b_conduit_sock_status_inbox_t,             \
                                 &(n00b_alloc_opts_t){                         \
                                     .allocator = _n00b_sock_c->allocator,     \
                                 });                                           \
        n00b_conduit_inbox_init(n00b_conduit_sock_status_payload_t,            \
                                _inbox, _n00b_sock_c,                          \
                                N00B_CONDUIT_BP_UNBOUNDED, 0);                 \
        _inbox;                                                                \
    })

// ============================================================================
// Convenience subscribe macros
// ============================================================================

/** @brief Subscribe to socket accept events. */
#define n00b_conduit_sock_accept_subscribe(topic, inbox, ...)                  \
    n00b_conduit_subscribe(n00b_conduit_sock_accept_payload_t,                 \
                           (n00b_conduit_topic_t(n00b_conduit_sock_accept_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/** @brief Subscribe to socket status events. */
#define n00b_conduit_sock_status_subscribe(topic, inbox, ...)                  \
    n00b_conduit_subscribe(n00b_conduit_sock_status_payload_t,                 \
                           (n00b_conduit_topic_t(n00b_conduit_sock_status_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

// ============================================================================
// Convenience pop macros
// ============================================================================

#define n00b_conduit_sock_accept_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_conduit_sock_accept_payload_t, inbox)
#define n00b_conduit_sock_status_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_conduit_sock_status_payload_t, inbox)

// ============================================================================
// Convenience has_messages macros
// ============================================================================

#define n00b_conduit_sock_accept_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_conduit_sock_accept_payload_t, inbox)
#define n00b_conduit_sock_status_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_conduit_sock_status_payload_t, inbox)

// ============================================================================
// Connection State
// ============================================================================

/**
 * @brief Connection state machine values.
 */
typedef enum {
    N00B_CONDUIT_CONN_ST_CONNECTING = 0,
    N00B_CONDUIT_CONN_ST_CONNECTED  = 1,
    N00B_CONDUIT_CONN_ST_CLOSED     = 2,
    N00B_CONDUIT_CONN_ST_ERROR      = 3,
} n00b_conduit_conn_state_t;

// ============================================================================
// Listener Structure
// ============================================================================

/**
 * @brief TCP listener -- owns a listening socket, publishes accept events.
 */
struct n00b_conduit_listener {
    n00b_conduit_t              *conduit;
    n00b_conduit_io_backend_t   *io;
    base_socket_t                fd;
    n00b_conduit_topic_base_t   *accept_topic;
    void                        *io_target;  // io-backend watch target; freed on close
    uint64_t                     listener_id;
    _Atomic(bool)                active;
    _Atomic(bool)                registry_registered;
    _Atomic(bool)                native_released;
    _Atomic(uint64_t)            close_generation;
};

// ============================================================================
// Connection Structure
// ============================================================================

/**
 * @brief TCP connection -- wraps a managed FD with lifecycle tracking.
 */
struct n00b_conduit_conn {
    n00b_conduit_t              *conduit;
    n00b_conduit_fd_owner_t     *owner;
    n00b_conduit_topic_base_t   *status_topic;
    base_socket_t                fd;
    _Atomic(int)                 conn_state;
    bool                         connect_pending;
    _Atomic(uint64_t)            close_generation;
    _Atomic(uint32_t)            terminal_status_count;
};

// ============================================================================
// Listener API
// ============================================================================

/**
 * @brief Create a TCP listener on addr:port.
 * @param c       Conduit instance.
 * @param io      I/O backend.
 * @param host    Host to bind (nullptr for INADDR_ANY).
 * @param port    Port number.
 * @param backlog Listen backlog size.
 * @kw allocator  Allocator for the new listener and its internal
 *                topics. nullptr means use @c c->allocator.
 * @return Ok(listener) on success, or Err(errno) on failure.
 */
extern n00b_result_t(n00b_conduit_listener_t *)
n00b_conduit_listen_tcp(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                        n00b_string_t *host, uint16_t port, int backlog)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Get the accept topic for subscribing.
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_listener_accept_topic(n00b_conduit_listener_t *listener);

/**
 * @brief Return the local TCP port the listener is bound to.
 *
 * For a TCP listener created with port 0 (ephemeral), this returns the
 * kernel-assigned port. Returns 0 for a non-TCP listener (e.g. AF_UNIX)
 * or if the bound address cannot be read.
 */
extern uint16_t
n00b_conduit_listener_local_port(n00b_conduit_listener_t *listener);

/**
 * @brief Release a raw accepted descriptor that was never handed to the
 *        fd-managed layer.
 *
 * The accept event transfers ownership of `client_fd` to the subscriber.
 * If the subscriber decides not to manage it (e.g. it is shutting down, or
 * `n00b_conduit_fd_manage` failed), this returns the descriptor to the
 * kernel. Keeps the raw close inside the conduit/socket layer so callers
 * stay free of POSIX fd primitives.
 */
extern void
n00b_conduit_release_fd(base_socket_t fd);

/**
 * @brief Stop listening (close socket, close topic).
 */
extern void
n00b_conduit_listener_close(n00b_conduit_listener_t *listener);

/**
 * @brief Create an AF_UNIX listener at @p socket_path.
 *
 * Mirrors @ref n00b_conduit_listen_tcp for Unix-domain sockets.
 * The listener publishes accept events on its accept topic exactly
 * the same way; @c struct sockaddr_storage in
 * @ref n00b_conduit_sock_accept_payload_t is large enough to hold
 * the resulting @c sockaddr_un, so existing accept-event consumers
 * work without changes.
 *
 * Path-length handling: if @p socket_path exceeds the platform's
 * @c sun_path capacity minus one, this returns @c ENAMETOOLONG.
 * No silent truncation.
 *
 * @param c           Conduit instance.
 * @param io          I/O backend.
 * @param socket_path Absolute or relative path for the socket file.
 * @param backlog     Listen backlog size; 0 means use 128.
 *
 * @kw unlink_stale   If true, attempt @c unlink(socket_path) before
 *                    @c bind to remove a leftover socket file. ENOENT
 *                    from unlink is treated as success. Off by
 *                    default — the caller should know what it is
 *                    about to overwrite.
 * @kw mode           If non-zero, @c chmod(socket_path, mode) after
 *                    successful bind. Zero leaves the kernel default
 *                    in place.
 * @kw allocator      Allocator for the new listener and its internal
 *                    topics. nullptr means use @c c->allocator.
 *
 * @return Ok(listener) on success, or Err(errno) on failure.
 *
 * @note On Windows this uses Winsock AF_UNIX support.
 */
extern n00b_result_t(n00b_conduit_listener_t *)
n00b_conduit_listen_unix(n00b_conduit_t            *c,
                         n00b_conduit_io_backend_t *io,
                         n00b_string_t             *socket_path,
                         int                        backlog)
    _kargs {
        bool              unlink_stale = false;
        int               mode         = 0;
        n00b_allocator_t *allocator    = nullptr;
    };

/**
 * @internal Dispatch readiness event to listener.
 */
extern void
n00b_conduit_listener_dispatch(n00b_conduit_listener_t *listener, uint32_t io_ops);

/**
 * @brief Lookup listener by FD.
 * @return Some(listener) if found, None otherwise.
 */
extern n00b_option_t(n00b_conduit_listener_t *)
n00b_conduit_listener_get(n00b_conduit_t *c, base_socket_t fd);

// ============================================================================
// Connection API
// ============================================================================

/**
 * @brief Wrap an already-connected FD (e.g. from accept).
 * @return Ok(conn) on success, or Err(errno) on failure.
 */
extern n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_from_fd(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                          base_socket_t fd);

/**
 * @brief Initiate outbound TCP connection (non-blocking connect).
 * @kw allocator  Allocator for the new conn and its internal
 *                topics. nullptr means use @c c->allocator.
 * @return Ok(conn) on success, or Err(errno) on failure.
 */
extern n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_tcp(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                      n00b_string_t *host, uint16_t port)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Get connection status topic.
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_conn_status_topic(n00b_conduit_conn_t *conn);

/**
 * @brief Get the underlying FD owner (for Layer 1/2 I/O).
 */
extern n00b_option_t(n00b_conduit_fd_owner_t *)
n00b_conduit_conn_fd_owner(n00b_conduit_conn_t *conn);

/**
 * @brief Close connection.
 */
extern void
n00b_conduit_conn_close(n00b_conduit_conn_t *conn);

/**
 * @brief Initiate an outbound AF_UNIX connection to @p socket_path.
 *
 * Unix-domain sockets are local endpoints, so connection setup is
 * completed before the fd is registered with conduit I/O. On success,
 * the returned connection is already wired into the status-topic /
 * fd_owner machinery and already in @c N00B_CONDUIT_CONN_ST_CONNECTED.
 * Missing or stale endpoints return Err(errno) directly; no pending
 * fd_owner is published for a connection that has not completed.
 *
 * @param c           Conduit instance.
 * @param io          I/O backend.
 * @param socket_path Path of the listener.
 *
 * @kw allocator      Allocator for the new conn and its internal
 *                    topics. nullptr means use @c c->allocator.
 *
 * @return Ok(connected conn) on success, or Err(errno) on failure.
 *         ENOENT or ECONNREFUSED indicate no listener at the path.
 *
 * @note On Windows this uses Winsock AF_UNIX support.
 */
extern n00b_result_t(n00b_conduit_conn_t *)
n00b_conduit_conn_unix(n00b_conduit_t            *c,
                       n00b_conduit_io_backend_t *io,
                       n00b_string_t             *socket_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

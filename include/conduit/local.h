/**
 * @file local.h
 * @brief Portable local IPC conduit API.
 *
 * Local IPC resources expose normal conduit topics. Users subscribe/read/write
 * through the generic conduit APIs; backend-native handles stay private to the
 * implementation.
 */
#pragma once

#include "adt/option.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "util/worker_pool.h"

typedef struct n00b_conduit_local_listener n00b_conduit_local_listener_t;
typedef struct n00b_conduit_local_conn     n00b_conduit_local_conn_t;

typedef enum {
    N00B_CONDUIT_LOCAL_AUTO = 0,
    N00B_CONDUIT_LOCAL_XPC,
    N00B_CONDUIT_LOCAL_UNIX,
    N00B_CONDUIT_LOCAL_WINDOWS_NAMED,
} n00b_conduit_local_backend_t;

typedef enum {
    N00B_CONDUIT_LOCAL_CONNECTED = 1,
    N00B_CONDUIT_LOCAL_REFUSED,
    N00B_CONDUIT_LOCAL_RESET,
    N00B_CONDUIT_LOCAL_TIMEOUT,
    N00B_CONDUIT_LOCAL_ERROR,
    N00B_CONDUIT_LOCAL_CLOSED,
} n00b_conduit_local_event_t;

typedef struct {
    n00b_conduit_local_backend_t backend;
    n00b_option_t(uint64_t)      pid;
    n00b_option_t(uint64_t)      uid;
    n00b_option_t(uint64_t)      gid;
    n00b_option_t(n00b_string_t *) code_signing_id;
} n00b_conduit_local_peer_t;

typedef struct {
    n00b_conduit_local_conn_t  *conn;
    n00b_conduit_local_peer_t   peer;
} n00b_conduit_local_accept_payload_t;

typedef struct {
    n00b_conduit_local_backend_t backend;
    n00b_conduit_local_event_t   event;
    int                          error_code;
    n00b_string_t               *error_detail;
} n00b_conduit_local_status_payload_t;

N00B_CONDUIT_FULL_IMPL(n00b_conduit_local_accept_payload_t);
N00B_CONDUIT_FULL_IMPL(n00b_conduit_local_status_payload_t);

typedef n00b_conduit_message_t(n00b_conduit_local_accept_payload_t)
    n00b_conduit_local_accept_msg_t;
typedef n00b_conduit_message_t(n00b_conduit_local_status_payload_t)
    n00b_conduit_local_status_msg_t;

typedef n00b_conduit_inbox_t(n00b_conduit_local_accept_payload_t)
    n00b_conduit_local_accept_inbox_t;
typedef n00b_conduit_inbox_t(n00b_conduit_local_status_payload_t)
    n00b_conduit_local_status_inbox_t;

/**
 * @brief Allocate and initialize an inbox for local accept payloads.
 *
 * @param c Conduit that owns subscriptions using this inbox.
 * @return A non-null inbox for @ref n00b_conduit_local_accept_payload_t
 *         messages.
 * @pre c != nullptr.
 * @post Returned inbox is initialized for unbounded accept-message delivery.
 */
#define n00b_conduit_local_accept_inbox_new(c)                                \
    ({                                                                        \
        n00b_conduit_t *_bl_c = (c);                                          \
        n00b_conduit_local_accept_inbox_t *_bl_inbox =                        \
            n00b_alloc_with_opts(n00b_conduit_local_accept_inbox_t,           \
                                 &(n00b_alloc_opts_t){                        \
                                     .allocator = _bl_c->allocator,           \
                                 });                                          \
        n00b_conduit_inbox_init(n00b_conduit_local_accept_payload_t,          \
                                _bl_inbox, _bl_c,                             \
                                N00B_CONDUIT_BP_UNBOUNDED, 0);                \
        _bl_inbox;                                                            \
    })

/**
 * @brief Allocate and initialize an inbox for local status payloads.
 *
 * @param c Conduit that owns subscriptions using this inbox.
 * @return A non-null inbox for @ref n00b_conduit_local_status_payload_t
 *         messages.
 * @pre c != nullptr.
 * @post Returned inbox is initialized for unbounded status-message delivery.
 */
#define n00b_conduit_local_status_inbox_new(c)                                \
    ({                                                                        \
        n00b_conduit_t *_bl_c = (c);                                          \
        n00b_conduit_local_status_inbox_t *_bl_inbox =                        \
            n00b_alloc_with_opts(n00b_conduit_local_status_inbox_t,           \
                                 &(n00b_alloc_opts_t){                        \
                                     .allocator = _bl_c->allocator,           \
                                 });                                          \
        n00b_conduit_inbox_init(n00b_conduit_local_status_payload_t,          \
                                _bl_inbox, _bl_c,                             \
                                N00B_CONDUIT_BP_UNBOUNDED, 0);                \
        _bl_inbox;                                                            \
    })

/**
 * @brief Subscribe an inbox to a local accept topic.
 *
 * @param topic Local accept topic returned by a local listener accessor.
 * @param inbox Inbox created by @ref n00b_conduit_local_accept_inbox_new.
 * @return The underlying subscription result from @ref n00b_conduit_subscribe.
 * @pre topic != nullptr.
 * @pre inbox != nullptr.
 * @post On success, @p inbox receives accept payload messages from @p topic.
 */
#define n00b_conduit_local_accept_subscribe(topic, inbox, ...)                \
    n00b_conduit_subscribe(n00b_conduit_local_accept_payload_t,               \
                           (n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/**
 * @brief Subscribe an inbox to a local status topic.
 *
 * @param topic Local status topic returned by a local connection accessor.
 * @param inbox Inbox created by @ref n00b_conduit_local_status_inbox_new.
 * @return The underlying subscription result from @ref n00b_conduit_subscribe.
 * @pre topic != nullptr.
 * @pre inbox != nullptr.
 * @post On success, @p inbox receives status payload messages from @p topic.
 */
#define n00b_conduit_local_status_subscribe(topic, inbox, ...)                \
    n00b_conduit_subscribe(n00b_conduit_local_status_payload_t,               \
                           (n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/**
 * @brief Pop the next local accept message from an inbox.
 *
 * @param inbox Local accept inbox.
 * @return Next accept message, or nullptr when no message is available.
 * @pre inbox != nullptr.
 * @post If non-null, returned message carries
 *       @ref n00b_conduit_local_accept_payload_t.
 */
#define n00b_conduit_local_accept_inbox_pop(inbox)                            \
    n00b_conduit_inbox_pop_msg(n00b_conduit_local_accept_payload_t, inbox)

/**
 * @brief Pop the next local status message from an inbox.
 *
 * @param inbox Local status inbox.
 * @return Next status message, or nullptr when no message is available.
 * @pre inbox != nullptr.
 * @post If non-null, returned message carries
 *       @ref n00b_conduit_local_status_payload_t.
 */
#define n00b_conduit_local_status_inbox_pop(inbox)                            \
    n00b_conduit_inbox_pop_msg(n00b_conduit_local_status_payload_t, inbox)

/**
 * @brief Test whether a local accept inbox has queued messages.
 *
 * @param inbox Local accept inbox.
 * @return true when at least one accept message is available.
 * @pre inbox != nullptr.
 * @post Does not remove messages from @p inbox.
 */
#define n00b_conduit_local_accept_inbox_has_messages(inbox)                   \
    n00b_conduit_inbox_has_msg(n00b_conduit_local_accept_payload_t, inbox)

/**
 * @brief Test whether a local status inbox has queued messages.
 *
 * @param inbox Local status inbox.
 * @return true when at least one status message is available.
 * @pre inbox != nullptr.
 * @post Does not remove messages from @p inbox.
 */
#define n00b_conduit_local_status_inbox_has_messages(inbox)                   \
    n00b_conduit_inbox_has_msg(n00b_conduit_local_status_payload_t, inbox)

/**
 * @brief Start a portable local IPC listener.
 *
 * @param c Conduit that owns the listener and its topics.
 * @param name Backend-local service name/path.
 * @kw backend Backend selector. Defaults to @ref N00B_CONDUIT_LOCAL_AUTO.
 * @kw io Optional IO backend for FD-backed implementations. Defaults to
 *     nullptr.
 * @kw backlog Backend listen backlog. Defaults to 0.
 * @kw unlink_stale Remove stale AF_UNIX socket path before listening.
 *     Defaults to false.
 * @kw mode Backend file mode for path-like local transports. Defaults to 0.
 * @kw allocator Optional allocator for local listener bookkeeping. Defaults to
 *     nullptr.
 * @return Ok(listener) on success, or Err(code) on failure.
 *
 * @pre c != nullptr.
 * @pre name != nullptr.
 * @pre @p name is non-empty after backend-specific normalization.
 * @pre backend is a valid @ref n00b_conduit_local_backend_t value.
 * @pre If backend is explicit, it is supported on the current platform.
 * @pre If @p io is supplied, it is registered with or usable by @p c.
 * @pre backlog >= 0.
 * @pre mode >= 0.
 * @post On Ok, returned listener is non-null and owned by @p c.
 * @post On Ok, listener backend is resolved, fixed, and not AUTO.
 * @post On Ok, the accept topic exists and carries
 *       @ref n00b_conduit_local_accept_payload_t.
 * @post On Ok, the status topic exists and carries
 *       @ref n00b_conduit_local_status_payload_t.
 * @post On Err, no listener is published and no native listener leaks.
 */
extern n00b_result_t(n00b_conduit_local_listener_t *)
n00b_conduit_local_listen(n00b_conduit_t *c, n00b_string_t *name)
    _kargs {
        n00b_conduit_local_backend_t backend      = N00B_CONDUIT_LOCAL_AUTO;
        n00b_conduit_io_backend_t   *io           = nullptr;
        int                          backlog      = 0;
        bool                         unlink_stale = false;
        int                          mode         = 0;
        n00b_allocator_t            *allocator    = nullptr;
        n00b_worker_pool_t          *bridge_pool  = nullptr;
    };

/**
 * @brief Construct a worker pool suitable for use as the @c bridge_pool of
 *        @ref n00b_conduit_local_listen.
 *
 * Accepted connections whose listener carries this pool run their bridge loop
 * as a pool job instead of spawning a dedicated thread per connection, reusing
 * @p size threads across all connections and eliminating per-connection thread
 * spawn/reap churn. @p cap bounds queued-but-not-yet-running connections;
 * @ref n00b_conduit_local_listen / accept backpressures when the ring is full.
 *
 * Shutdown ordering: a bridge job runs on a pool worker for the lifetime of its
 * connection and reads the conduit each iteration, so the owner must drain and
 * join the pool (@ref n00b_worker_pool_quiesce then @ref n00b_worker_pool_shutdown)
 * only once every accepted connection has closed or the conduit has been shut
 * down (which makes each bridge loop observe shutdown and return); destroying the
 * conduit while a bridge job is still in-flight is a use-after-free.
 *
 * @param size Worker thread count (>= 1).
 * @param cap  Pending-connection ring capacity (>= 1).
 * @kw allocator Optional allocator for the pool's internal allocations.
 * @return Ok with a live pool, or Err on invalid arguments / spawn failure.
 */
extern n00b_result_t(n00b_worker_pool_t *)
n00b_conduit_local_bridge_pool_new(int32_t size, int32_t cap)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Connect to a portable local IPC endpoint.
 *
 * @param c Conduit that owns the connection and its topics.
 * @param name Backend-local service name/path.
 * @kw backend Backend selector. Defaults to @ref N00B_CONDUIT_LOCAL_AUTO.
 * @kw io Optional IO backend for FD-backed implementations. Defaults to
 *     nullptr.
 * @kw allocator Optional allocator for local connection bookkeeping. Defaults
 *     to nullptr.
 * @return Ok(connection) on success, or Err(code) on failure.
 *
 * @pre c != nullptr.
 * @pre name != nullptr.
 * @pre @p name is non-empty after backend-specific normalization.
 * @pre backend is a valid @ref n00b_conduit_local_backend_t value.
 * @pre If backend is explicit, it is supported on the current platform.
 * @pre If @p io is supplied, it is registered with or usable by @p c.
 * @post On Ok, returned connection is non-null and owned by @p c.
 * @post On Ok, connection backend is resolved, fixed, and not AUTO.
 * @post On Ok, read/write/status topics exist.
 * @post On Ok, read/write topics carry @c n00b_buffer_t * payloads.
 * @post On Ok, the status topic carries
 *       @ref n00b_conduit_local_status_payload_t.
 * @post On Err, no connection is published and no native connection leaks.
 */
extern n00b_result_t(n00b_conduit_local_conn_t *)
n00b_conduit_local_connect(n00b_conduit_t *c, n00b_string_t *name)
    _kargs {
        n00b_conduit_local_backend_t backend   = N00B_CONDUIT_LOCAL_AUTO;
        n00b_conduit_io_backend_t   *io        = nullptr;
        n00b_allocator_t            *allocator = nullptr;
    };

/**
 * @brief Return the listener accept topic.
 *
 * @param listener Local listener, or nullptr.
 * @return Some(topic) while @p listener is open or closing; None for null or
 *         fully closed listeners.
 * @pre listener may be nullptr.
 * @post If Some, returned topic is owned by the same conduit as @p listener.
 * @post If Some, returned topic carries
 *       @ref n00b_conduit_local_accept_payload_t.
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_listener_accept_topic(n00b_conduit_local_listener_t *listener);

/**
 * @brief Typed form of @ref n00b_conduit_local_listener_accept_topic.
 *
 * @param listener Local listener, or nullptr.
 * @return Typed accept topic while @p listener is open or closing; nullptr
 *         for null or fully closed listeners.
 * @pre listener may be nullptr.
 * @post If non-null, returned topic carries
 *       @ref n00b_conduit_local_accept_payload_t.
 */
static inline n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *
n00b_conduit_local_listener_accept_topic_typed(
    n00b_conduit_local_listener_t *listener)
{
    auto opt = n00b_conduit_local_listener_accept_topic(listener);
    return n00b_option_is_set(opt)
        ? (n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *)n00b_option_get(opt)
        : nullptr;
}

/**
 * @brief Return the local connection read topic.
 *
 * @param conn Local connection, or nullptr.
 * @return Some(topic) while @p conn is open or closing; None for null or
 *         fully closed connections.
 * @pre conn may be nullptr.
 * @post If Some, returned topic is owned by the same conduit as @p conn.
 * @post If Some, returned topic carries @c n00b_buffer_t * payloads.
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_conn_read_topic(n00b_conduit_local_conn_t *conn);

/**
 * @brief Typed form of @ref n00b_conduit_local_conn_read_topic.
 *
 * @param conn Local connection, or nullptr.
 * @return Typed read topic while @p conn is open or closing; nullptr for null
 *         or fully closed connections.
 * @pre conn may be nullptr.
 * @post If non-null, returned topic carries @c n00b_buffer_t * payloads.
 */
static inline n00b_conduit_topic_t(n00b_buffer_t *) *
n00b_conduit_local_conn_read_topic_typed(n00b_conduit_local_conn_t *conn)
{
    auto opt = n00b_conduit_local_conn_read_topic(conn);
    return n00b_option_is_set(opt)
        ? (n00b_conduit_topic_t(n00b_buffer_t *) *)n00b_option_get(opt)
        : nullptr;
}

/**
 * @brief Return the local connection write topic.
 *
 * @param conn Local connection, or nullptr.
 * @return Some(topic) while @p conn is open or closing; None for null or
 *         fully closed connections.
 * @pre conn may be nullptr.
 * @post If Some, returned topic is owned by the same conduit as @p conn.
 * @post If Some, returned topic carries @c n00b_buffer_t * payloads.
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_conn_write_topic(n00b_conduit_local_conn_t *conn);

/**
 * @brief Typed form of @ref n00b_conduit_local_conn_write_topic.
 *
 * @param conn Local connection, or nullptr.
 * @return Typed write topic while @p conn is open or closing; nullptr for null
 *         or fully closed connections.
 * @pre conn may be nullptr.
 * @post If non-null, returned topic carries @c n00b_buffer_t * payloads.
 */
static inline n00b_conduit_topic_t(n00b_buffer_t *) *
n00b_conduit_local_conn_write_topic_typed(n00b_conduit_local_conn_t *conn)
{
    auto opt = n00b_conduit_local_conn_write_topic(conn);
    return n00b_option_is_set(opt)
        ? (n00b_conduit_topic_t(n00b_buffer_t *) *)n00b_option_get(opt)
        : nullptr;
}

/**
 * @brief Return the local connection status topic.
 *
 * @param conn Local connection, or nullptr.
 * @return Some(topic) while @p conn is open or closing; None for null or
 *         fully closed connections.
 * @pre conn may be nullptr.
 * @post If Some, returned topic is owned by the same conduit as @p conn.
 * @post If Some, returned topic carries
 *       @ref n00b_conduit_local_status_payload_t.
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_conn_status_topic(n00b_conduit_local_conn_t *conn);

/**
 * @brief Typed form of @ref n00b_conduit_local_conn_status_topic.
 *
 * @param conn Local connection, or nullptr.
 * @return Typed status topic while @p conn is open or closing; nullptr for
 *         null or fully closed connections.
 * @pre conn may be nullptr.
 * @post If non-null, returned topic carries
 *       @ref n00b_conduit_local_status_payload_t.
 */
static inline n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *
n00b_conduit_local_conn_status_topic_typed(n00b_conduit_local_conn_t *conn)
{
    auto opt = n00b_conduit_local_conn_status_topic(conn);
    return n00b_option_is_set(opt)
        ? (n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *)n00b_option_get(opt)
        : nullptr;
}

/**
 * @brief Close a local listener.
 *
 * @param listener Local listener to close, or nullptr.
 * @return Nothing.
 * @pre listener may be nullptr.
 * @post Close is idempotent.
 * @post If @p listener was open, native resources are released exactly once.
 * @post Accept/status topics are closed exactly once.
 * @post Backend registry entries for the listener are removed exactly once.
 * @post Later close calls are no-ops.
 */
extern void
n00b_conduit_local_listener_close(n00b_conduit_local_listener_t *listener);

/**
 * @brief Close a local connection.
 *
 * @param conn Local connection to close, or nullptr.
 * @return Nothing.
 * @pre conn may be nullptr.
 * @post Close is idempotent.
 * @post If @p conn was open, backend-native resources are released exactly
 *       once.
 * @post Read/write/status topics are closed exactly once.
 * @post Backend registry entries for the connection are removed exactly once.
 * @post At most one terminal status event is published.
 * @post Later close calls are no-ops.
 */
extern void
n00b_conduit_local_conn_close(n00b_conduit_local_conn_t *conn);

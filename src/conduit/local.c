/*
 * local.c - Portable local IPC conduit API core.
 */

#include "conduit/local.h"
#include "conduit/fd_managed.h"
#include "conduit/service.h"
#include "conduit/socket.h"
#include "core/atomic.h"
#include "core/condition.h"
#include "core/thread.h"
#include "local_internal.h"

static void local_listener_accept_on_first_subscribe(
    n00b_conduit_topic_base_t *topic, void *ctx);
static void local_listener_accept_on_last_unsubscribe(
    n00b_conduit_topic_base_t *topic, void *ctx);
static void *local_listener_accept_loop(void *raw);
static void local_conn_read_on_first_subscribe(
    n00b_conduit_topic_base_t *topic, void *ctx);
static void local_conn_read_on_last_unsubscribe(
    n00b_conduit_topic_base_t *topic, void *ctx);
static void *local_conn_bridge_loop(void *raw);

static n00b_result_t(bool)
local_conn_attach_xpc(n00b_conduit_local_conn_t *conn, void *native_conn);

extern n00b_result_t(bool)
_n00b_conduit_fd_close_unmanaged(int fd);

static bool
backend_valid(n00b_conduit_local_backend_t backend)
{
    return backend >= N00B_CONDUIT_LOCAL_AUTO
        && backend <= N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
}

static n00b_allocator_t *
local_allocator(n00b_conduit_t *c, n00b_allocator_t *allocator)
{
    if (allocator != nullptr) {
        return allocator;
    }

    return c != nullptr ? c->allocator : nullptr;
}

static n00b_conduit_local_backend_t
resolve_backend(n00b_conduit_local_backend_t backend)
{
    if (backend != N00B_CONDUIT_LOCAL_AUTO) {
        return backend;
    }

#if defined(_WIN32)
    return N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
#elif defined(__APPLE__)
    return N00B_CONDUIT_LOCAL_XPC;
#else
    return N00B_CONDUIT_LOCAL_UNIX;
#endif
}

static uint64_t
next_local_id(n00b_conduit_t *c)
{
    return n00b_atomic_add(&c->next_local_id, 1);
}

static void
close_topic_if_set(n00b_conduit_topic_base_t *topic)
{
    if (topic != nullptr) {
        n00b_conduit_topic_close(topic);
    }
}

static n00b_conduit_inbox_t(n00b_buffer_t *) *
local_buffer_inbox_new(n00b_conduit_t *c, n00b_allocator_t *allocator)
{
    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox = n00b_alloc_with_opts(
        n00b_conduit_inbox_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    return inbox;
}

static n00b_conduit_sock_accept_inbox_t *
local_sock_accept_inbox_new(n00b_conduit_t *c, n00b_allocator_t *allocator)
{
    n00b_conduit_sock_accept_inbox_t *inbox = n00b_alloc_with_opts(
        n00b_conduit_sock_accept_inbox_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_conduit_inbox_init(n00b_conduit_sock_accept_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    return inbox;
}

static n00b_conduit_sock_status_inbox_t *
local_sock_status_inbox_new(n00b_conduit_t *c, n00b_allocator_t *allocator)
{
    n00b_conduit_sock_status_inbox_t *inbox = n00b_alloc_with_opts(
        n00b_conduit_sock_status_inbox_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_conduit_inbox_init(n00b_conduit_sock_status_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    return inbox;
}

static n00b_result_t(n00b_conduit_io_backend_t *)
resolve_fd_io(n00b_conduit_t *c, n00b_conduit_io_backend_t *io)
    requires {
        c != nullptr;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
    }
{
    if (io != nullptr) {
        return n00b_result_ok(n00b_conduit_io_backend_t *, io);
    }

    if (c->service != nullptr) {
        auto st_opt = n00b_conduit_service_default_io(c->service);
        if (n00b_option_is_set(st_opt)) {
            auto io_opt = n00b_conduit_svc_thread_io(n00b_option_get(st_opt));
            if (n00b_option_is_set(io_opt)) {
                return n00b_result_ok(n00b_conduit_io_backend_t *,
                                      n00b_option_get(io_opt));
            }
        }
    }

    return n00b_conduit_io_new_default(c);
}

static void
pause_socket_listener(n00b_conduit_listener_t *listener)
{
    if (listener != nullptr) {
        n00b_conduit_io_modify(listener->io, listener->fd, 0,
                               listener->io_target);
    }
}

static void
resume_socket_listener(n00b_conduit_listener_t *listener)
{
    if (listener != nullptr) {
        n00b_conduit_io_modify(listener->io, listener->fd,
                               N00B_CONDUIT_IO_READ, listener->io_target);
    }
}

[[maybe_unused]] static n00b_result_t(n00b_conduit_local_listener_t *)
local_listener_alloc(n00b_conduit_t               *c,
                     n00b_conduit_local_backend_t backend,
                     n00b_allocator_t             *allocator)
    requires {
        c != nullptr;
        backend != N00B_CONDUIT_LOCAL_AUTO;
        backend >= N00B_CONDUIT_LOCAL_XPC;
        backend <= N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
    }
{
    n00b_allocator_t *alloc = local_allocator(c, allocator);
    n00b_conduit_local_listener_t *listener = n00b_alloc_with_opts(
        n00b_conduit_local_listener_t,
        &(n00b_alloc_opts_t){.allocator = alloc});
    if (listener == nullptr) {
        return n00b_result_err(n00b_conduit_local_listener_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }

    listener->conduit   = c;
    listener->allocator = alloc;
    listener->local_id  = next_local_id(c);
    listener->backend   = backend;
    listener->backend_accept_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    n00b_condition_init(&listener->accept_cv);
    n00b_mutex_init(&listener->publish_lock);
    n00b_atomic_store(&listener->closed, false);
    n00b_atomic_store(&listener->accept_started, false);
    n00b_atomic_store(&listener->accept_running, false);
    n00b_atomic_store(&listener->accept_stop, false);
    n00b_atomic_store(&listener->native_released, false);
    n00b_atomic_store(&listener->close_generation, 0);

    n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *accept_topic =
        n00b_conduit_topic_init(n00b_conduit_local_accept_payload_t, c,
                                N00B_CONDUIT_URI_LOCAL_ACCEPT(listener->local_id));
    if (accept_topic == nullptr) {
        n00b_free(listener);
        return n00b_result_err(n00b_conduit_local_listener_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    listener->accept_topic = (n00b_conduit_topic_base_t *)accept_topic;
    listener->accept_topic->on_first_subscribe =
        local_listener_accept_on_first_subscribe;
    listener->accept_topic->on_first_subscribe_ctx = listener;
    listener->accept_topic->on_last_unsubscribe =
        local_listener_accept_on_last_unsubscribe;
    listener->accept_topic->on_last_unsubscribe_ctx = listener;

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *status_topic =
        n00b_conduit_topic_init(n00b_conduit_local_status_payload_t, c,
                                N00B_CONDUIT_URI_LOCAL_STATUS(listener->local_id));
    if (status_topic == nullptr) {
        close_topic_if_set(listener->accept_topic);
        n00b_free(listener);
        return n00b_result_err(n00b_conduit_local_listener_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    listener->status_topic = (n00b_conduit_topic_base_t *)status_topic;

    return n00b_result_ok(n00b_conduit_local_listener_t *, listener);
}

[[maybe_unused]] static n00b_result_t(n00b_conduit_local_conn_t *)
local_conn_alloc(n00b_conduit_t               *c,
                 n00b_conduit_local_backend_t backend,
                 n00b_allocator_t             *allocator)
    requires {
        c != nullptr;
        backend != N00B_CONDUIT_LOCAL_AUTO;
        backend >= N00B_CONDUIT_LOCAL_XPC;
        backend <= N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
    }
{
    n00b_allocator_t *alloc = local_allocator(c, allocator);
    n00b_conduit_local_conn_t *conn = n00b_alloc_with_opts(
        n00b_conduit_local_conn_t,
        &(n00b_alloc_opts_t){.allocator = alloc});
    if (conn == nullptr) {
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }

    conn->conduit   = c;
    conn->allocator = alloc;
    conn->local_id  = next_local_id(c);
    conn->backend   = backend;
    conn->read_sub  = N00B_CONDUIT_INVALID_SUB_HANDLE;
    conn->write_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    conn->status_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    n00b_atomic_store(&conn->closed, false);
    n00b_atomic_store(&conn->bridge_started, false);
    n00b_atomic_store(&conn->bridge_running, false);
    n00b_atomic_store(&conn->bridge_stop, false);
    n00b_atomic_store(&conn->native_released, false);
    n00b_atomic_store(&conn->close_generation, 0);
    n00b_atomic_store(&conn->terminal_status_count, 0);

    n00b_conduit_topic_t(n00b_buffer_t *) *read_topic =
        n00b_conduit_topic_init(n00b_buffer_t *, c,
                                N00B_CONDUIT_URI_LOCAL_READ(conn->local_id));
    if (read_topic == nullptr) {
        n00b_free(conn);
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    conn->read_topic = (n00b_conduit_topic_base_t *)read_topic;
    conn->read_topic->on_first_subscribe = local_conn_read_on_first_subscribe;
    conn->read_topic->on_first_subscribe_ctx = conn;
    conn->read_topic->on_last_unsubscribe = local_conn_read_on_last_unsubscribe;
    conn->read_topic->on_last_unsubscribe_ctx = conn;

    n00b_conduit_topic_t(n00b_buffer_t *) *write_topic =
        n00b_conduit_topic_init(n00b_buffer_t *, c,
                                N00B_CONDUIT_URI_LOCAL_WRITE(conn->local_id));
    if (write_topic == nullptr) {
        close_topic_if_set(conn->read_topic);
        n00b_free(conn);
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    conn->write_topic = (n00b_conduit_topic_base_t *)write_topic;

    n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *status_topic =
        n00b_conduit_topic_init(n00b_conduit_local_status_payload_t, c,
                                N00B_CONDUIT_URI_LOCAL_STATUS(conn->local_id));
    if (status_topic == nullptr) {
        close_topic_if_set(conn->read_topic);
        close_topic_if_set(conn->write_topic);
        n00b_free(conn);
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    conn->status_topic = (n00b_conduit_topic_base_t *)status_topic;

    return n00b_result_ok(n00b_conduit_local_conn_t *, conn);
}

static n00b_conduit_fd_owner_t *
local_conn_fd_owner(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr || conn->backend != N00B_CONDUIT_LOCAL_UNIX ||
        conn->backend_conn == nullptr) {
        return nullptr;
    }

    auto owner_opt =
        n00b_conduit_conn_fd_owner((n00b_conduit_conn_t *)conn->backend_conn);
    return n00b_option_is_set(owner_opt) ? n00b_option_get(owner_opt) : nullptr;
}

static void
signal_topic_done(n00b_conduit_topic_base_t *topic)
{
    if (topic == nullptr) {
        return;
    }

    n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *done =
        (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)
            n00b_atomic_load(&topic->done_topic);
    if (done == nullptr) {
        return;
    }

    n00b_conduit_message_t(n00b_conduit_topic_base_t *) *msg =
        n00b_alloc_with_opts(
            n00b_conduit_message_t(n00b_conduit_topic_base_t *),
            &(n00b_alloc_opts_t){.allocator = topic->conduit->allocator});
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)done;
    msg->header.generation = n00b_conduit_topic_generation(
        (n00b_conduit_topic_base_t *)done);
    msg->header.epoch      = n00b_conduit_topic_epoch(
        (n00b_conduit_topic_base_t *)done);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload           = topic;

    n00b_conduit_topic_deliver_msg(n00b_conduit_topic_base_t *,
                                   done, msg, N00B_CONDUIT_OP_ALL);
}

static n00b_result_t(n00b_conduit_local_listener_t *)
local_xpc_listen(n00b_conduit_t     *c,
                 n00b_string_t      *name,
                 n00b_allocator_t   *allocator)
    requires {
        c != nullptr;
        name != nullptr;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->backend == N00B_CONDUIT_LOCAL_XPC;
    }
{
#if defined(__APPLE__)
    if (_n00b_conduit_local_xpc_native_backend_present() == 0) {
        return n00b_result_err(n00b_conduit_local_listener_t *,
                               N00B_CONDUIT_ERR_NOT_SUPPORTED);
    }

    auto listener_r = local_listener_alloc(c, N00B_CONDUIT_LOCAL_XPC,
                                           allocator);
    if (n00b_result_is_err(listener_r)) {
        return listener_r;
    }

    n00b_conduit_local_listener_t *listener = n00b_result_get(listener_r);
    void *native_listener = nullptr;
    int native_status = _n00b_conduit_local_xpc_native_listen(
        listener, name->data, name->u8_bytes, &native_listener);
    if (native_status != N00B_LOCAL_XPC_NATIVE_OK) {
        close_topic_if_set(listener->accept_topic);
        close_topic_if_set(listener->status_topic);
        n00b_free(listener);
        int err = native_status == N00B_LOCAL_XPC_NATIVE_ALLOC
            ? N00B_CONDUIT_ERR_ALLOC
            : N00B_CONDUIT_ERR_INVALID_STATE;
        return n00b_result_err(n00b_conduit_local_listener_t *, err);
    }

    listener->backend_listener = native_listener;
    return n00b_result_ok(n00b_conduit_local_listener_t *, listener);
#endif

    return n00b_result_err(n00b_conduit_local_listener_t *,
                           N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

static n00b_result_t(n00b_conduit_local_conn_t *)
local_xpc_connect(n00b_conduit_t     *c,
                  n00b_string_t      *name,
                  n00b_allocator_t   *allocator)
    requires {
        c != nullptr;
        name != nullptr;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->backend == N00B_CONDUIT_LOCAL_XPC;
    }
{
#if defined(__APPLE__)
    if (_n00b_conduit_local_xpc_native_backend_present() == 0) {
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_NOT_SUPPORTED);
    }

    auto conn_r = local_conn_alloc(c, N00B_CONDUIT_LOCAL_XPC, allocator);
    if (n00b_result_is_err(conn_r)) {
        return conn_r;
    }

    n00b_conduit_local_conn_t *conn = n00b_result_get(conn_r);
    void *native_conn = nullptr;
    int native_status = _n00b_conduit_local_xpc_native_connect(
        conn, name->data, name->u8_bytes, &native_conn);
    if (native_status != N00B_LOCAL_XPC_NATIVE_OK) {
        close_topic_if_set(conn->read_topic);
        close_topic_if_set(conn->write_topic);
        close_topic_if_set(conn->status_topic);
        n00b_free(conn);
        int err = N00B_CONDUIT_ERR_CONNECT;
        if (native_status == N00B_LOCAL_XPC_NATIVE_ALLOC) {
            err = N00B_CONDUIT_ERR_ALLOC;
        }
        else if (native_status == N00B_LOCAL_XPC_NATIVE_NOT_FOUND) {
            err = N00B_CONDUIT_ERR_NOT_FOUND;
        }
        else if (native_status == N00B_LOCAL_XPC_NATIVE_INVALID) {
            err = N00B_CONDUIT_ERR_INVALID_STATE;
        }
        return n00b_result_err(n00b_conduit_local_conn_t *, err);
    }

    auto attach_r = local_conn_attach_xpc(conn, native_conn);
    if (n00b_result_is_err(attach_r)) {
        _n00b_conduit_local_xpc_native_cancel_conn(native_conn);
        close_topic_if_set(conn->read_topic);
        close_topic_if_set(conn->write_topic);
        close_topic_if_set(conn->status_topic);
        n00b_free(conn);
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               n00b_result_get_err(attach_r));
    }

    return n00b_result_ok(n00b_conduit_local_conn_t *, conn);
#endif

    return n00b_result_err(n00b_conduit_local_conn_t *,
                           N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

static n00b_conduit_local_event_t
map_socket_event(n00b_conduit_conn_event_t event)
{
    switch (event) {
    case N00B_CONDUIT_CONN_CONNECTED:
        return N00B_CONDUIT_LOCAL_CONNECTED;
    case N00B_CONDUIT_CONN_REFUSED:
        return N00B_CONDUIT_LOCAL_REFUSED;
    case N00B_CONDUIT_CONN_RESET:
        return N00B_CONDUIT_LOCAL_RESET;
    case N00B_CONDUIT_CONN_TIMEOUT:
        return N00B_CONDUIT_LOCAL_TIMEOUT;
    case N00B_CONDUIT_CONN_CLOSED:
        return N00B_CONDUIT_LOCAL_CLOSED;
    case N00B_CONDUIT_CONN_ERROR:
    default:
        return N00B_CONDUIT_LOCAL_ERROR;
    }
}

static void
publish_local_status(n00b_conduit_local_conn_t   *conn,
                     n00b_conduit_local_event_t  event,
                     int                         error_code)
{
    if (conn == nullptr || conn->status_topic == nullptr) {
        return;
    }

    if (event == N00B_CONDUIT_LOCAL_CLOSED) {
        uint64_t expected = 0;
        if (n00b_atomic_cas(&conn->terminal_status_count, &expected, 1) == false) {
            return;
        }
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(conn->status_topic);
    if (n00b_result_is_err(pub_res)) {
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_local_status_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_local_status_msg_t,
        &(n00b_alloc_opts_t){.allocator = conn->allocator});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = conn->status_topic;
    msg->header.generation = n00b_conduit_topic_generation(conn->status_topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(conn->status_topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.backend      = conn->backend;
    msg->payload.event        = event;
    msg->payload.error_code   = error_code;
    msg->payload.error_detail = nullptr;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_local_status_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_local_status_payload_t) *)
            conn->status_topic,
        msg,
        N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_yield(pub);
}

static void
publish_local_read(n00b_conduit_local_conn_t *conn, n00b_buffer_t *buf)
{
    if (conn == nullptr || conn->read_topic == nullptr || buf == nullptr) {
        return;
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(conn->read_topic);
    if (n00b_result_is_err(pub_res)) {
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_message_t(n00b_buffer_t *) *msg = n00b_alloc_with_opts(
        n00b_conduit_message_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = conn->allocator});
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = conn->read_topic;
    msg->header.generation = n00b_conduit_topic_generation(conn->read_topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(conn->read_topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload           = buf;

    n00b_conduit_topic_deliver_msg(
        n00b_buffer_t *,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)conn->read_topic,
        msg,
        N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_yield(pub);
}

static bool
local_conn_process_read(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr || conn->read_inbox == nullptr) {
        return false;
    }

    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, conn->read_inbox);
    if (msg == nullptr) {
        return false;
    }

    publish_local_read(conn, msg->payload);
    n00b_free(msg);
    return true;
}

static bool
local_conn_process_write(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr || conn->write_inbox == nullptr) {
        return false;
    }

    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, conn->write_inbox);
    if (msg == nullptr) {
        return false;
    }

    n00b_conduit_fd_owner_t *owner = local_conn_fd_owner(conn);
    n00b_buffer_t *buf = msg->payload;
    if (owner != nullptr && buf != nullptr && buf->data != nullptr &&
        buf->byte_len > 0) {
        auto wr = n00b_fd_owner_write_attempt(owner, buf->data, buf->byte_len);
        if (n00b_result_is_err(wr)) {
            publish_local_status(conn, N00B_CONDUIT_LOCAL_ERROR,
                                 n00b_result_get_err(wr));
        }
        else {
            n00b_fd_owner_write_attempt_t attempt = n00b_result_get(wr);
            if (attempt.error) {
                publish_local_status(conn, N00B_CONDUIT_LOCAL_ERROR,
                                     attempt.error_code);
            }
        }
    }
    else {
        publish_local_status(conn, N00B_CONDUIT_LOCAL_ERROR,
                             N00B_CONDUIT_ERR_NULL_ARG);
    }

    signal_topic_done(conn->write_topic);
    n00b_free(msg);
    return true;
}

static bool
local_conn_process_status(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr || conn->status_inbox == nullptr) {
        return false;
    }

    n00b_conduit_sock_status_msg_t *msg =
        n00b_conduit_sock_status_inbox_pop(conn->status_inbox);
    if (msg == nullptr) {
        return false;
    }

    publish_local_status(conn, map_socket_event(msg->payload.event),
                         msg->payload.error_code);
    n00b_free(msg);
    return true;
}

static void
local_conn_drain_sys(n00b_conduit_local_conn_t *conn)
{
    if (conn->read_inbox != nullptr) {
        n00b_conduit_sys_msg_t *sys;
        while ((sys = n00b_conduit_inbox_pop_sys(conn->read_inbox)) != nullptr) {
            if (sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
                close_topic_if_set(conn->read_topic);
            }
            n00b_free(sys);
        }
    }

    if (conn->status_inbox != nullptr) {
        n00b_conduit_sys_msg_t *sys;
        while ((sys = n00b_conduit_inbox_pop_sys(conn->status_inbox)) != nullptr) {
            if (sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
                publish_local_status(conn, N00B_CONDUIT_LOCAL_CLOSED, 0);
            }
            n00b_free(sys);
        }
    }
}

static void *
local_conn_bridge_loop(void *raw)
{
    n00b_conduit_local_conn_t *conn = raw;
    n00b_atomic_store(&conn->bridge_running, true);

    while (!n00b_conduit_is_shutdown(conn->conduit)) {
        if (local_conn_process_write(conn)) {
            continue;
        }
        if (local_conn_process_read(conn)) {
            continue;
        }
        if (local_conn_process_status(conn)) {
            continue;
        }
        local_conn_drain_sys(conn);

        if (n00b_atomic_load(&conn->bridge_stop)) {
            break;
        }

        n00b_condition_lock(&conn->write_inbox->cv);
        if (n00b_atomic_load(&conn->bridge_stop) == false &&
            n00b_conduit_is_shutdown(conn->conduit) == false &&
            n00b_conduit_inbox_has_msg(n00b_buffer_t *, conn->write_inbox) == false) {
            n00b_condition_wait(&conn->write_inbox->cv,
                                .timeout_ms = 25,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&conn->write_inbox->cv);
        }
    }

    while (local_conn_process_write(conn) ||
           local_conn_process_read(conn) ||
           local_conn_process_status(conn)) {
    }
    n00b_atomic_store(&conn->bridge_running, false);
    return nullptr;
}

static bool
local_conn_start_read(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr || conn->read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return true;
    }

    n00b_conduit_fd_owner_t *owner = local_conn_fd_owner(conn);
    if (owner == nullptr) {
        return false;
    }

    if (conn->read_inbox == nullptr) {
        conn->read_inbox = local_buffer_inbox_new(conn->conduit,
                                                  conn->allocator);
    }

    conn->read_sub = n00b_conduit_subscribe(
        n00b_buffer_t *,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)owner->read_topic,
        conn->read_inbox,
        .operations = N00B_CONDUIT_FD_OP_READ_DATA);

    return conn->read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE;
}

static void
local_conn_stop_read(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr) {
        return;
    }

    if (conn->read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(conn->read_sub);
        conn->read_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
}

static void
local_conn_read_on_first_subscribe(n00b_conduit_topic_base_t *topic, void *ctx)
{
    (void)topic;
    (void)local_conn_start_read((n00b_conduit_local_conn_t *)ctx);
}

static void
local_conn_read_on_last_unsubscribe(n00b_conduit_topic_base_t *topic, void *ctx)
{
    (void)topic;
    local_conn_stop_read((n00b_conduit_local_conn_t *)ctx);
}

static void
local_conn_stop_bridge(n00b_conduit_local_conn_t *conn)
{
    if (conn == nullptr) {
        return;
    }

    n00b_atomic_store(&conn->bridge_stop, true);
    if (conn->write_inbox != nullptr) {
        n00b_condition_notify(&conn->write_inbox->cv, .auto_unlock = true);
    }
    if (conn->read_inbox != nullptr) {
        n00b_condition_notify(&conn->read_inbox->cv, .auto_unlock = true);
    }
    if (conn->status_inbox != nullptr) {
        n00b_condition_notify(&conn->status_inbox->cv, .auto_unlock = true);
    }

    local_conn_stop_read(conn);
    if (conn->write_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(conn->write_sub);
        conn->write_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    if (conn->status_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(conn->status_sub);
        conn->status_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    if (conn->bridge_thread != nullptr) {
        n00b_thread_join(conn->bridge_thread);
        conn->bridge_thread = nullptr;
    }
}

static n00b_result_t(bool)
local_conn_attach_socket(n00b_conduit_local_conn_t *conn,
                         n00b_conduit_conn_t       *socket_conn)
    requires {
        conn != nullptr;
        socket_conn != nullptr;
    }
    ensures {
        n00b_result_is_err(result) || conn->backend_conn == socket_conn;
    }
{
    conn->backend_conn = socket_conn;
    conn->write_inbox = local_buffer_inbox_new(conn->conduit,
                                               conn->allocator);
    if (conn->write_inbox == nullptr) {
        return n00b_result_err(bool, N00B_CONDUIT_ERR_ALLOC);
    }
    conn->write_sub = n00b_conduit_subscribe(
        n00b_buffer_t *,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)conn->write_topic,
        conn->write_inbox,
        .operations = N00B_CONDUIT_OP_ALL);
    if (conn->write_sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_err(bool, N00B_CONDUIT_ERR_ALLOC);
    }

    conn->status_inbox = local_sock_status_inbox_new(conn->conduit,
                                                     conn->allocator);
    auto status_opt = n00b_conduit_conn_status_topic(socket_conn);
    if (n00b_option_is_set(status_opt)) {
        conn->status_sub = n00b_conduit_sock_status_subscribe(
            (n00b_conduit_topic_t(n00b_conduit_sock_status_payload_t) *)
                n00b_option_get(status_opt),
            conn->status_inbox,
            .operations = N00B_CONDUIT_OP_ALL);
        if (conn->status_sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
            return n00b_result_err(bool, N00B_CONDUIT_ERR_ALLOC);
        }
    }

    bool expected = false;
    if (n00b_atomic_cas(&conn->bridge_started, &expected, true)) {
        auto spawn_r = n00b_thread_spawn(local_conn_bridge_loop, conn);
        if (n00b_result_is_err(spawn_r)) {
            return n00b_result_err(bool, n00b_result_get_err(spawn_r));
        }
        conn->bridge_thread = n00b_result_get(spawn_r);
    }

    publish_local_status(conn, N00B_CONDUIT_LOCAL_CONNECTED, 0);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
local_conn_attach_xpc(n00b_conduit_local_conn_t *conn, void *native_conn)
    requires {
        conn != nullptr;
        native_conn != nullptr;
    }
    ensures {
        n00b_result_is_err(result) || conn->backend_conn == native_conn;
    }
{
    conn->backend_conn = native_conn;
    publish_local_status(conn, N00B_CONDUIT_LOCAL_CONNECTED, 0);
    return n00b_result_ok(bool, true);
}

static n00b_conduit_local_peer_t
local_xpc_peer_facts(void *native_conn)
{
    n00b_conduit_local_peer_t peer = {
        .backend         = N00B_CONDUIT_LOCAL_XPC,
        .pid             = n00b_option_none(uint64_t),
        .uid             = n00b_option_none(uint64_t),
        .gid             = n00b_option_none(uint64_t),
        .code_signing_id = n00b_option_none(n00b_string_t *),
    };

#if defined(__APPLE__)
    uint64_t pid = 0;
    uint64_t uid = 0;
    uint64_t gid = 0;
    bool has_pid = false;
    bool has_uid = false;
    bool has_gid = false;
    _n00b_conduit_local_xpc_native_peer_facts(native_conn,
                                              &pid, &has_pid,
                                              &uid, &has_uid,
                                              &gid, &has_gid);
    if (has_pid) {
        peer.pid = n00b_option_set(uint64_t, pid);
    }
    if (has_uid) {
        peer.uid = n00b_option_set(uint64_t, uid);
    }
    if (has_gid) {
        peer.gid = n00b_option_set(uint64_t, gid);
    }
#endif

    return peer;
}

static bool
local_accept_has_downstream(n00b_conduit_local_listener_t *listener)
{
    return listener != nullptr && listener->accept_topic != nullptr
        && n00b_atomic_load(&listener->accept_topic->sub_list_head) != nullptr;
}

static void
publish_local_accept(n00b_conduit_local_listener_t *listener,
                     n00b_conduit_local_conn_t     *conn,
                     n00b_conduit_local_peer_t      peer)
{
    if (listener == nullptr || conn == nullptr) {
        n00b_conduit_local_conn_close(conn);
        return;
    }

    n00b_mutex_lock(&listener->publish_lock);
    if (n00b_atomic_load(&listener->closed) == true ||
        local_accept_has_downstream(listener) == false) {
        n00b_mutex_unlock(&listener->publish_lock);
        n00b_conduit_local_conn_close(conn);
        return;
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(listener->accept_topic);
    if (n00b_result_is_err(pub_res)) {
        n00b_mutex_unlock(&listener->publish_lock);
        n00b_conduit_local_conn_close(conn);
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_local_accept_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_local_accept_msg_t,
        &(n00b_alloc_opts_t){.allocator = listener->allocator});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = listener->accept_topic;
    msg->header.generation = n00b_conduit_topic_generation(listener->accept_topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(listener->accept_topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.conn    = conn;
    msg->payload.peer    = peer;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_local_accept_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_local_accept_payload_t) *)
            listener->accept_topic,
        msg,
        N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_yield(pub);
    n00b_mutex_unlock(&listener->publish_lock);
}

static bool
local_listener_process_unix_accept(n00b_conduit_local_listener_t *listener)
{
    if (listener == nullptr || listener->backend_accept_inbox == nullptr) {
        return false;
    }

    n00b_conduit_sock_accept_msg_t *sock_msg =
        n00b_conduit_sock_accept_inbox_pop(listener->backend_accept_inbox);
    if (sock_msg == nullptr) {
        return false;
    }

    int client_fd = sock_msg->payload.client_fd;
    n00b_conduit_listener_t *socket_listener =
        (n00b_conduit_listener_t *)listener->backend_listener;

    if (local_accept_has_downstream(listener) == false) {
        (void)_n00b_conduit_fd_close_unmanaged(client_fd);
        n00b_free(sock_msg);
        return true;
    }

    auto socket_conn_r = n00b_conduit_conn_from_fd(listener->conduit,
                                                  socket_listener->io,
                                                  client_fd);
    if (n00b_result_is_err(socket_conn_r)) {
        (void)_n00b_conduit_fd_close_unmanaged(client_fd);
        n00b_free(sock_msg);
        return true;
    }

    auto local_conn_r = local_conn_alloc(listener->conduit,
                                         N00B_CONDUIT_LOCAL_UNIX,
                                         listener->allocator);
    if (n00b_result_is_err(local_conn_r)) {
        n00b_conduit_conn_close(n00b_result_get(socket_conn_r));
        n00b_free(sock_msg);
        return true;
    }

    n00b_conduit_local_conn_t *local_conn = n00b_result_get(local_conn_r);
    auto attach_r = local_conn_attach_socket(local_conn,
                                             n00b_result_get(socket_conn_r));
    if (n00b_result_is_err(attach_r)) {
        n00b_conduit_local_conn_close(local_conn);
        n00b_free(sock_msg);
        return true;
    }
    n00b_conduit_local_peer_t peer = {
        .backend         = N00B_CONDUIT_LOCAL_UNIX,
        .pid             = n00b_option_none(uint64_t),
        .uid             = n00b_option_none(uint64_t),
        .gid             = n00b_option_none(uint64_t),
        .code_signing_id = n00b_option_none(n00b_string_t *),
    };
    publish_local_accept(listener, local_conn, peer);
    n00b_free(sock_msg);
    return true;
}

static bool
local_listener_process_xpc_accept(n00b_conduit_local_listener_t *listener)
{
#if defined(__APPLE__)
    if (listener == nullptr || listener->backend_listener == nullptr) {
        return false;
    }

    void *native_conn = _n00b_conduit_local_xpc_native_listener_pop_accept(
        listener->backend_listener);
    if (native_conn == nullptr) {
        return false;
    }

    if (n00b_atomic_load(&listener->closed) == true) {
        _n00b_conduit_local_xpc_native_cancel_conn(native_conn);
        return true;
    }

    if (local_accept_has_downstream(listener) == false) {
        _n00b_conduit_local_xpc_native_cancel_conn(native_conn);
        return true;
    }

    auto local_conn_r = local_conn_alloc(listener->conduit,
                                         N00B_CONDUIT_LOCAL_XPC,
                                         listener->allocator);
    if (n00b_result_is_err(local_conn_r)) {
        _n00b_conduit_local_xpc_native_cancel_conn(native_conn);
        return true;
    }

    n00b_conduit_local_conn_t *local_conn = n00b_result_get(local_conn_r);
    auto attach_r = local_conn_attach_xpc(local_conn, native_conn);
    if (n00b_result_is_err(attach_r)) {
        _n00b_conduit_local_xpc_native_cancel_conn(native_conn);
        close_topic_if_set(local_conn->read_topic);
        close_topic_if_set(local_conn->write_topic);
        close_topic_if_set(local_conn->status_topic);
        n00b_free(local_conn);
        return true;
    }

    publish_local_accept(listener, local_conn, local_xpc_peer_facts(native_conn));
    return true;
#else
    (void)listener;
    return false;
#endif
}

static bool
local_listener_process_accept(n00b_conduit_local_listener_t *listener)
{
    if (listener == nullptr) {
        return false;
    }

    if (listener->backend == N00B_CONDUIT_LOCAL_UNIX) {
        return local_listener_process_unix_accept(listener);
    }
    if (listener->backend == N00B_CONDUIT_LOCAL_XPC) {
        return local_listener_process_xpc_accept(listener);
    }

    return false;
}

static void *
local_listener_accept_loop(void *raw)
{
    n00b_conduit_local_listener_t *listener = raw;
    n00b_atomic_store(&listener->accept_running, true);

    while (n00b_conduit_is_shutdown(listener->conduit) == false) {
        if (local_listener_process_accept(listener)) {
            continue;
        }

        if (listener->backend_accept_inbox != nullptr) {
            n00b_conduit_sys_msg_t *sys =
                n00b_conduit_inbox_pop_sys(listener->backend_accept_inbox);
            if (sys != nullptr) {
                n00b_conduit_msg_type_t mt = sys->header.type;
                n00b_free(sys);
                if (mt == N00B_CONDUIT_MSG_TOPIC_CLOSED ||
                    mt == N00B_CONDUIT_MSG_PUBLISHER_LOST) {
                    while (local_listener_process_accept(listener)) {
                    }
                    break;
                }
                continue;
            }
        }

        if (n00b_atomic_load(&listener->accept_stop)) {
            break;
        }

        n00b_condition_t *wait_cv = listener->backend_accept_inbox != nullptr
            ? &listener->backend_accept_inbox->cv
            : &listener->accept_cv;
        n00b_condition_lock(wait_cv);
        if (n00b_atomic_load(&listener->accept_stop) == false &&
            n00b_conduit_is_shutdown(listener->conduit) == false &&
            (listener->backend_accept_inbox == nullptr ||
             (n00b_conduit_sock_accept_inbox_has_messages(
                 listener->backend_accept_inbox) == false &&
              n00b_conduit_inbox_has_sys(listener->backend_accept_inbox) == false))) {
            n00b_condition_wait(wait_cv,
                                .timeout_ms = 25,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(wait_cv);
        }
    }

    while (local_listener_process_accept(listener)) {
    }
    n00b_atomic_store(&listener->accept_running, false);
    return nullptr;
}

static bool
local_listener_start_accept(n00b_conduit_local_listener_t *listener)
{
    if (listener == nullptr || listener->backend_listener == nullptr ||
        n00b_atomic_load(&listener->closed) == true) {
        return false;
    }

    n00b_atomic_store(&listener->accept_stop, false);

    bool expected = false;
    if (n00b_atomic_cas(&listener->accept_started, &expected, true)) {
        if (listener->backend == N00B_CONDUIT_LOCAL_UNIX) {
            listener->backend_accept_inbox =
                local_sock_accept_inbox_new(listener->conduit,
                                            listener->allocator);

            n00b_conduit_listener_t *socket_listener =
                (n00b_conduit_listener_t *)listener->backend_listener;
            auto topic_opt = n00b_conduit_listener_accept_topic(socket_listener);
            if (n00b_option_is_set(topic_opt) == false) {
                n00b_atomic_store(&listener->accept_started, false);
                return false;
            }

            listener->backend_accept_sub = n00b_conduit_sock_accept_subscribe(
                (n00b_conduit_topic_t(n00b_conduit_sock_accept_payload_t) *)
                    n00b_option_get(topic_opt),
                listener->backend_accept_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
            if (listener->backend_accept_sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
                n00b_atomic_store(&listener->accept_started, false);
                return false;
            }
        }
        else if (listener->backend != N00B_CONDUIT_LOCAL_XPC) {
            n00b_atomic_store(&listener->accept_started, false);
            return false;
        }

        auto spawn_r = n00b_thread_spawn(local_listener_accept_loop, listener);
        if (n00b_result_is_err(spawn_r)) {
            if (listener->backend_accept_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
                n00b_conduit_sub_cancel(listener->backend_accept_sub);
                listener->backend_accept_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
            }
            n00b_atomic_store(&listener->accept_started, false);
            return false;
        }
        listener->accept_thread = n00b_result_get(spawn_r);
    }

    if (listener->backend == N00B_CONDUIT_LOCAL_UNIX) {
        resume_socket_listener((n00b_conduit_listener_t *)listener->backend_listener);
    }
    return true;
}

static void
local_listener_pause_accept(n00b_conduit_local_listener_t *listener)
{
    if (listener == nullptr || listener->backend != N00B_CONDUIT_LOCAL_UNIX) {
        return;
    }

    pause_socket_listener((n00b_conduit_listener_t *)listener->backend_listener);
}

static void
local_listener_stop_accept(n00b_conduit_local_listener_t *listener)
{
    if (listener == nullptr) {
        return;
    }

    n00b_atomic_store(&listener->accept_stop, true);
    local_listener_pause_accept(listener);
    n00b_condition_notify(&listener->accept_cv, .auto_unlock = true);
    if (listener->backend_accept_inbox != nullptr) {
        n00b_condition_notify(&listener->backend_accept_inbox->cv,
                              .auto_unlock = true);
    }
    if (listener->backend_accept_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(listener->backend_accept_sub);
        listener->backend_accept_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    if (listener->accept_thread != nullptr) {
        n00b_thread_join(listener->accept_thread);
        listener->accept_thread = nullptr;
    }
}

static void
local_listener_accept_on_first_subscribe(n00b_conduit_topic_base_t *topic,
                                         void *ctx)
{
    (void)topic;
    (void)local_listener_start_accept((n00b_conduit_local_listener_t *)ctx);
}

static void
local_listener_accept_on_last_unsubscribe(n00b_conduit_topic_base_t *topic,
                                          void *ctx)
{
    (void)topic;
    local_listener_pause_accept((n00b_conduit_local_listener_t *)ctx);
}

n00b_result_t(n00b_conduit_local_listener_t *)
n00b_conduit_local_listen(n00b_conduit_t *c, n00b_string_t *name)
    _kargs {
        n00b_conduit_local_backend_t backend      = N00B_CONDUIT_LOCAL_AUTO;
        n00b_conduit_io_backend_t   *io           = nullptr;
        int                          backlog      = 0;
        bool                         unlink_stale = false;
        int                          mode         = 0;
        n00b_allocator_t            *allocator    = nullptr;
    }
    requires {
        c != nullptr;
        name != nullptr;
        backend >= N00B_CONDUIT_LOCAL_AUTO;
        backend <= N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
        backlog >= 0;
        mode >= 0;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
        n00b_result_is_err(result) || n00b_result_value(result)->conduit == c;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->backend != N00B_CONDUIT_LOCAL_AUTO;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->accept_topic != nullptr;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->status_topic != nullptr;
    }
{
    if (c == nullptr || name == nullptr) {
        return n00b_result_err(n00b_conduit_local_listener_t *,
                               N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (backend_valid(backend) == false || backlog < 0 || mode < 0) {
        return n00b_result_err(n00b_conduit_local_listener_t *,
                               N00B_CONDUIT_ERR_INVALID_STATE);
    }

    backend = resolve_backend(backend);

    if (backend == N00B_CONDUIT_LOCAL_UNIX) {
        auto io_r = resolve_fd_io(c, io);
        if (n00b_result_is_err(io_r)) {
            return n00b_result_err(n00b_conduit_local_listener_t *,
                                   n00b_result_get_err(io_r));
        }
        n00b_conduit_io_backend_t *resolved_io = n00b_result_get(io_r);

        auto socket_listener_r = n00b_conduit_listen_unix(
            c, resolved_io, name, backlog,
            .unlink_stale = unlink_stale,
            .mode         = mode,
            .allocator    = allocator);
        if (n00b_result_is_err(socket_listener_r)) {
            return n00b_result_err(n00b_conduit_local_listener_t *,
                                   n00b_result_get_err(socket_listener_r));
        }

        auto local_listener_r = local_listener_alloc(c, backend, allocator);
        if (n00b_result_is_err(local_listener_r)) {
            n00b_conduit_listener_close(n00b_result_get(socket_listener_r));
            return n00b_result_err(n00b_conduit_local_listener_t *,
                                   n00b_result_get_err(local_listener_r));
        }

        n00b_conduit_local_listener_t *listener =
            n00b_result_get(local_listener_r);
        listener->backend_listener = n00b_result_get(socket_listener_r);
        pause_socket_listener(
            (n00b_conduit_listener_t *)listener->backend_listener);
        return n00b_result_ok(n00b_conduit_local_listener_t *, listener);
    }
    if (backend == N00B_CONDUIT_LOCAL_XPC) {
        return local_xpc_listen(c, name, allocator);
    }

    return n00b_result_err(n00b_conduit_local_listener_t *,
                           N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

n00b_result_t(n00b_conduit_local_conn_t *)
n00b_conduit_local_connect(n00b_conduit_t *c, n00b_string_t *name)
    _kargs {
        n00b_conduit_local_backend_t backend   = N00B_CONDUIT_LOCAL_AUTO;
        n00b_conduit_io_backend_t   *io        = nullptr;
        n00b_allocator_t            *allocator = nullptr;
    }
    requires {
        c != nullptr;
        name != nullptr;
        backend >= N00B_CONDUIT_LOCAL_AUTO;
        backend <= N00B_CONDUIT_LOCAL_WINDOWS_NAMED;
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) != nullptr;
        n00b_result_is_err(result) || n00b_result_value(result)->conduit == c;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->backend != N00B_CONDUIT_LOCAL_AUTO;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->read_topic != nullptr;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->write_topic != nullptr;
        n00b_result_is_err(result) ||
            n00b_result_value(result)->status_topic != nullptr;
    }
{
    if (c == nullptr || name == nullptr) {
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (backend_valid(backend) == false) {
        return n00b_result_err(n00b_conduit_local_conn_t *,
                               N00B_CONDUIT_ERR_INVALID_STATE);
    }

    backend = resolve_backend(backend);

    if (backend == N00B_CONDUIT_LOCAL_UNIX) {
        auto io_r = resolve_fd_io(c, io);
        if (n00b_result_is_err(io_r)) {
            return n00b_result_err(n00b_conduit_local_conn_t *,
                                   n00b_result_get_err(io_r));
        }

        auto socket_conn_r = n00b_conduit_conn_unix(c, n00b_result_get(io_r),
                                                    name,
                                                    .allocator = allocator);
        if (n00b_result_is_err(socket_conn_r)) {
            return n00b_result_err(n00b_conduit_local_conn_t *,
                                   n00b_result_get_err(socket_conn_r));
        }

        auto local_conn_r = local_conn_alloc(c, backend, allocator);
        if (n00b_result_is_err(local_conn_r)) {
            n00b_conduit_conn_close(n00b_result_get(socket_conn_r));
            return n00b_result_err(n00b_conduit_local_conn_t *,
                                   n00b_result_get_err(local_conn_r));
        }

        n00b_conduit_local_conn_t *conn = n00b_result_get(local_conn_r);
        auto attach_r = local_conn_attach_socket(conn,
                                                 n00b_result_get(socket_conn_r));
        if (n00b_result_is_err(attach_r)) {
            n00b_conduit_local_conn_close(conn);
            return n00b_result_err(n00b_conduit_local_conn_t *,
                                   n00b_result_get_err(attach_r));
        }

        return n00b_result_ok(n00b_conduit_local_conn_t *, conn);
    }
    if (backend == N00B_CONDUIT_LOCAL_XPC) {
        return local_xpc_connect(c, name, allocator);
    }

    return n00b_result_err(n00b_conduit_local_conn_t *,
                           N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_listener_accept_topic(n00b_conduit_local_listener_t *listener)
    ensures {
        listener == nullptr || listener->closed == false ||
            n00b_option_is_set(result) == false;
        n00b_option_is_set(result) == false || result.value != nullptr;
        n00b_option_is_set(result) == false ||
            result.value == listener->accept_topic;
    }
{
    if (listener == nullptr || n00b_atomic_load(&listener->closed) == true) {
        return n00b_option_none(n00b_conduit_topic_base_t *);
    }

    return n00b_option_from_nullable(n00b_conduit_topic_base_t *,
                                     listener->accept_topic);
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_conn_read_topic(n00b_conduit_local_conn_t *conn)
    ensures {
        conn == nullptr || conn->closed == false ||
            n00b_option_is_set(result) == false;
        n00b_option_is_set(result) == false || result.value != nullptr;
        n00b_option_is_set(result) == false ||
            result.value == conn->read_topic;
    }
{
    if (conn == nullptr || n00b_atomic_load(&conn->closed) == true) {
        return n00b_option_none(n00b_conduit_topic_base_t *);
    }

    return n00b_option_from_nullable(n00b_conduit_topic_base_t *,
                                     conn->read_topic);
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_conn_write_topic(n00b_conduit_local_conn_t *conn)
    ensures {
        conn == nullptr || conn->closed == false ||
            n00b_option_is_set(result) == false;
        n00b_option_is_set(result) == false || result.value != nullptr;
        n00b_option_is_set(result) == false ||
            result.value == conn->write_topic;
    }
{
    if (conn == nullptr || n00b_atomic_load(&conn->closed) == true) {
        return n00b_option_none(n00b_conduit_topic_base_t *);
    }

    return n00b_option_from_nullable(n00b_conduit_topic_base_t *,
                                     conn->write_topic);
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_conduit_local_conn_status_topic(n00b_conduit_local_conn_t *conn)
    ensures {
        conn == nullptr || conn->closed == false ||
            n00b_option_is_set(result) == false;
        n00b_option_is_set(result) == false || result.value != nullptr;
        n00b_option_is_set(result) == false ||
            result.value == conn->status_topic;
    }
{
    if (conn == nullptr || n00b_atomic_load(&conn->closed) == true) {
        return n00b_option_none(n00b_conduit_topic_base_t *);
    }

    return n00b_option_from_nullable(n00b_conduit_topic_base_t *,
                                     conn->status_topic);
}

void
n00b_conduit_local_listener_close(n00b_conduit_local_listener_t *listener)
    ensures {
        listener == nullptr || listener->closed == true;
        listener == nullptr || listener->close_generation <= 1;
        listener == nullptr || old(listener->closed) == true ||
            listener->native_released == true;
        listener == nullptr || old(listener->closed) == true ||
            listener->close_generation == old(listener->close_generation) + 1;
        listener == nullptr || old(listener->closed) == false ||
            listener->close_generation == old(listener->close_generation);
    }
{
    if (listener == nullptr) {
        return;
    }

    n00b_mutex_lock(&listener->publish_lock);
    bool previous = n00b_atomic_read_then_set(&listener->closed, true);
    if (previous == true) {
        n00b_mutex_unlock(&listener->publish_lock);
        return;
    }
    n00b_atomic_add(&listener->close_generation, 1);
    n00b_mutex_unlock(&listener->publish_lock);

    void *xpc_listener_to_release = nullptr;
    if (listener->backend == N00B_CONDUIT_LOCAL_XPC &&
        listener->backend_listener != nullptr) {
#if defined(__APPLE__)
        _n00b_conduit_local_xpc_native_cancel_listener(
            listener->backend_listener);
#endif
        xpc_listener_to_release = listener->backend_listener;
    }
    local_listener_stop_accept(listener);
    if (xpc_listener_to_release != nullptr) {
#if defined(__APPLE__)
        _n00b_conduit_local_xpc_native_release_listener(xpc_listener_to_release);
#endif
        listener->backend_listener = nullptr;
    }
    if (listener->backend == N00B_CONDUIT_LOCAL_UNIX &&
        listener->backend_listener != nullptr) {
        n00b_conduit_listener_close(
            (n00b_conduit_listener_t *)listener->backend_listener);
        listener->backend_listener = nullptr;
    }
    n00b_atomic_store(&listener->native_released, true);
    close_topic_if_set(listener->accept_topic);
    close_topic_if_set(listener->status_topic);
}

void
n00b_conduit_local_conn_close(n00b_conduit_local_conn_t *conn)
    ensures {
        conn == nullptr || conn->closed == true;
        conn == nullptr || conn->close_generation <= 1;
        conn == nullptr || conn->terminal_status_count <= 1;
        conn == nullptr || old(conn->closed) == true ||
            conn->native_released == true;
        conn == nullptr || old(conn->closed) == true ||
            conn->close_generation == old(conn->close_generation) + 1;
        conn == nullptr || old(conn->closed) == false ||
            conn->close_generation == old(conn->close_generation);
        conn == nullptr ||
            conn->terminal_status_count >= old(conn->terminal_status_count);
    }
{
    if (conn == nullptr) {
        return;
    }

    bool previous = n00b_atomic_read_then_set(&conn->closed, true);
    if (previous == true) {
        return;
    }
    n00b_atomic_add(&conn->close_generation, 1);

    local_conn_stop_bridge(conn);
    if (conn->backend == N00B_CONDUIT_LOCAL_UNIX &&
        conn->backend_conn != nullptr) {
        n00b_conduit_conn_close((n00b_conduit_conn_t *)conn->backend_conn);
        conn->backend_conn = nullptr;
    }
#if defined(__APPLE__)
    if (conn->backend == N00B_CONDUIT_LOCAL_XPC &&
        conn->backend_conn != nullptr) {
        _n00b_conduit_local_xpc_native_cancel_conn(conn->backend_conn);
        conn->backend_conn = nullptr;
    }
#endif
    n00b_atomic_store(&conn->native_released, true);
    publish_local_status(conn, N00B_CONDUIT_LOCAL_CLOSED, 0);
    close_topic_if_set(conn->read_topic);
    close_topic_if_set(conn->write_topic);
    close_topic_if_set(conn->status_topic);
}

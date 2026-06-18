/*
 * fd_managed.c - Managed FD I/O implementation
 *
 * Implements the two-layer FD I/O model:
 *   Layer 1: Non-blocking reads/writes, publish as-done buffers as events
 *   Layer 2: Stream readers that accumulate as-done buffers into N-byte
 *            responses
 */

#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/io.h"
#include "conduit/rw.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#ifndef PIPE_BUF
#define PIPE_BUF 512
#endif

#define READ_BUF_SIZE 4096

#ifdef _WIN32
static bool
fd_is_winsock_socket(int fd)
{
    int type = 0;
    int len  = sizeof(type);
    return getsockopt((SOCKET)fd, SOL_SOCKET, SO_TYPE,
                      (char *)&type, &len) == 0;
}

static void
fd_owner_make_nonblocking(n00b_conduit_fd_owner_t *owner)
{
    if (!owner->win_socket) {
        return;
    }

    u_long mode = 1;
    ioctlsocket((SOCKET)owner->fd, FIONBIO, &mode);
}

static int
fd_chunk_len(size_t len)
{
    return len > INT_MAX ? INT_MAX : (int)len;
}
#endif

static ssize_t
fd_owner_read_raw(n00b_conduit_fd_owner_t *owner, void *buf, size_t len)
{
#ifdef _WIN32
    if (owner->win_socket) {
        return (ssize_t)recv((SOCKET)owner->fd, (char *)buf, fd_chunk_len(len), 0);
    }
    return (ssize_t)_read(owner->fd, buf, (unsigned int)fd_chunk_len(len));
#else
    return read(owner->fd, buf, len);
#endif
}

static ssize_t
fd_owner_write_raw(n00b_conduit_fd_owner_t *owner, const void *buf, size_t len)
{
#ifdef _WIN32
    if (owner->win_socket) {
        return (ssize_t)send((SOCKET)owner->fd, (const char *)buf,
                             fd_chunk_len(len), 0);
    }
    return (ssize_t)_write(owner->fd, buf, (unsigned int)fd_chunk_len(len));
#else
    return write(owner->fd, buf, len);
#endif
}

static int
fd_owner_last_error(n00b_conduit_fd_owner_t *owner)
{
#ifdef _WIN32
    return owner->win_socket ? WSAGetLastError() : errno;
#else
    (void)owner;
    return errno;
#endif
}

static bool
fd_owner_error_is_would_block(n00b_conduit_fd_owner_t *owner, int err)
{
#ifdef _WIN32
    if (owner->win_socket) {
        return err == WSAEWOULDBLOCK;
    }
#else
    if (err == EINTR) {
        return true;
    }
#endif
    return err == EAGAIN || err == EWOULDBLOCK;
}

static bool
fd_owner_error_is_pipe_closed(n00b_conduit_fd_owner_t *owner, int err)
{
#ifdef _WIN32
    if (owner->win_socket) {
        return err == WSAECONNRESET;
    }
#else
    (void)owner;
#endif
    return err == EPIPE;
}

static n00b_allocator_t *
fd_owner_allocator(n00b_conduit_fd_owner_t *owner)
{
    (void)owner;
    // FD owner payloads move between the IO thread and consumers. Keep them
    // in the system pool with the FD owner itself, not in a moving arena.
    return (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
}

static int
fd_owner_close_raw(n00b_conduit_fd_owner_t *owner)
{
#ifdef _WIN32
    if (owner->win_socket) {
        if (closesocket((SOCKET)owner->fd) != 0) {
            return WSAGetLastError();
        }
        return 0;
    }
    if (_close(owner->fd) != 0) {
        return errno;
    }
    return 0;
#else
    if (close(owner->fd) != 0) {
        return errno;
    }
    return 0;
#endif
}

// ============================================================================
// on_first_subscribe callback for FD read topics
// ============================================================================

static void fd_owner_update_io_mask(n00b_conduit_fd_owner_t *owner);
static void fd_owner_do_reads(n00b_conduit_fd_owner_t *owner);
static void wq_drain_with_error(n00b_conduit_fd_owner_t *owner, int error_code);
static void publish_status(n00b_conduit_fd_owner_t *owner,
                           n00b_conduit_fd_status_op_t status,
                           int error_code);

static void
fd_read_on_first_subscribe(n00b_conduit_topic_base_t *topic, void *ctx)
{
    (void)topic;
    n00b_conduit_fd_owner_t *owner = (n00b_conduit_fd_owner_t *)ctx;
    n00b_atomic_store(&owner->read_active, true);
    fd_owner_update_io_mask(owner);
    fd_owner_do_reads(owner);
}

static void
fd_read_on_last_unsubscribe(n00b_conduit_topic_base_t *topic, void *ctx)
{
    (void)topic;
    n00b_conduit_fd_owner_t *owner = (n00b_conduit_fd_owner_t *)ctx;
    n00b_atomic_store(&owner->read_active, false);
    fd_owner_update_io_mask(owner);
}

/**
 * Recompute and apply the IO watch mask from read_active/write_active.
 */
static void
fd_owner_update_io_mask(n00b_conduit_fd_owner_t *owner)
{
    n00b_conduit_io_op_t ops = 0;
    if (n00b_atomic_load(&owner->read_active))  ops |= N00B_CONDUIT_IO_READ;
    if (n00b_atomic_load(&owner->write_active)) ops |= N00B_CONDUIT_IO_WRITE;

    n00b_conduit_io_modify(owner->io, owner->fd, ops, owner->io_target);
}

// ============================================================================
// FD Owner creation + lookup
// ============================================================================

n00b_result_t(n00b_conduit_fd_owner_t *)
n00b_conduit_fd_manage(n00b_conduit_t *c, n00b_conduit_io_backend_t *io,
                       int fd, bool close_on_done)
{
    if (!c || !io || fd < 0) {
        return n00b_result_err(n00b_conduit_fd_owner_t *, EINVAL);
    }

    void *fd_key = (void *)(intptr_t)fd;

    // Check if already managed
    bool found = false;
    void *existing = n00b_dict_untyped_get(&c->fd_owners, fd_key, &found);
    if (found) {
        return n00b_result_ok(n00b_conduit_fd_owner_t *, (n00b_conduit_fd_owner_t *)existing);
    }

    // Allocate from the system pool — fd owners are accessed by IO
    // threads and must not be relocated by the GC.
    n00b_allocator_t *sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    n00b_conduit_fd_owner_t *owner = n00b_alloc_with_opts(n00b_conduit_fd_owner_t,
                                        &(n00b_alloc_opts_t){.allocator = sp});

    owner->conduit       = c;
    owner->io            = io;
    owner->fd            = fd;
    owner->close_on_done = close_on_done;
#ifdef _WIN32
    owner->win_socket    = fd_is_winsock_socket(fd);
#endif
    n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_ACTIVE);
    n00b_atomic_store(&owner->read_pos, 0);
    n00b_atomic_store(&owner->write_pos, 0);
    n00b_atomic_store(&owner->next_request_id, 1);
    n00b_atomic_store(&owner->read_active, false);
    n00b_atomic_store(&owner->write_active, false);
    n00b_atomic_store(&owner->write_draining, false);
    n00b_atomic_store(&owner->registry_registered, false);
    n00b_atomic_store(&owner->native_released, false);
    n00b_atomic_store(&owner->close_generation, 0);
    n00b_atomic_store(&owner->terminal_status_count, 0);

    // Create the 4 topics.
    n00b_conduit_topic_t(n00b_buffer_t *) *read_topic =
        n00b_conduit_topic_init(n00b_buffer_t *, c,
                                N00B_CONDUIT_URI_FD_READ(fd));
    if (!read_topic) {
        return n00b_result_err(n00b_conduit_fd_owner_t *, ENOMEM);
    }
    owner->read_topic = (n00b_conduit_topic_base_t *)read_topic;

    // Edge-triggered read activation: reads start when the first subscriber
    // registers and stop when the last subscriber is removed.
    owner->read_topic->on_first_subscribe      = fd_read_on_first_subscribe;
    owner->read_topic->on_first_subscribe_ctx  = owner;
    owner->read_topic->on_last_unsubscribe     = fd_read_on_last_unsubscribe;
    owner->read_topic->on_last_unsubscribe_ctx = owner;

    n00b_conduit_topic_t(n00b_conduit_fd_write_payload_t) *write_topic =
        n00b_conduit_topic_init(n00b_conduit_fd_write_payload_t, c,
                                N00B_CONDUIT_URI_FD_WRITE(fd));
    if (!write_topic) {
        return n00b_result_err(n00b_conduit_fd_owner_t *, ENOMEM);
    }
    owner->write_topic = (n00b_conduit_topic_base_t *)write_topic;

    n00b_conduit_topic_t(n00b_conduit_fd_status_payload_t) *status_topic =
        n00b_conduit_topic_init(n00b_conduit_fd_status_payload_t, c,
                                N00B_CONDUIT_URI_FD_STATUS(fd));
    if (!status_topic) {
        return n00b_result_err(n00b_conduit_fd_owner_t *, ENOMEM);
    }
    owner->status_topic = (n00b_conduit_topic_base_t *)status_topic;

    n00b_conduit_topic_t(n00b_conduit_fd_write_req_payload_t) *wreq_topic =
        n00b_conduit_topic_init(n00b_conduit_fd_write_req_payload_t, c,
                                N00B_CONDUIT_URI_FD_WREQ(fd));
    if (!wreq_topic) {
        return n00b_result_err(n00b_conduit_fd_owner_t *, ENOMEM);
    }
    owner->wreq_topic = (n00b_conduit_topic_base_t *)wreq_topic;

    // Write queue starts empty; write monitoring is demand-driven.
    owner->wq_head = nullptr;
    owner->wq_tail = nullptr;

    // Make FD non-blocking
#ifndef _WIN32
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
#else
    fd_owner_make_nonblocking(owner);
#endif

    n00b_runtime_t *_rt = n00b_get_runtime();
    n00b_allocator_t *cp = (n00b_allocator_t *)&_rt->conduit_pool;
    n00b_conduit_io_target_t *target = n00b_alloc_with_opts(n00b_conduit_io_target_t,
                                                           &(n00b_alloc_opts_t){.allocator = cp});
    _n00b_variant_set_ptr(target, n00b_conduit_fd_owner_t *, owner);
    owner->io_target = target;
    // Register with the IO backend but with no events initially.
    // Read and write monitoring are activated on demand by the
    // on_first_subscribe callbacks on the read and wreq topics.
    n00b_conduit_io_watch(io, fd, 0, target);

    // Insert into fd_owners dict
    n00b_dict_untyped_put(&c->fd_owners, fd_key, owner);
    n00b_atomic_store(&owner->registry_registered, true);

    return n00b_result_ok(n00b_conduit_fd_owner_t *, owner);
}

n00b_option_t(n00b_conduit_fd_owner_t *)
n00b_conduit_fd_get_owner(n00b_conduit_t *c, int fd)
{
    if (!c || fd < 0) {
        return n00b_option_none(n00b_conduit_fd_owner_t *);
    }

    bool found = false;
    void *val = n00b_dict_untyped_get(&c->fd_owners, (void *)(intptr_t)fd, &found);
    if (found) {
        return n00b_option_set(n00b_conduit_fd_owner_t *, (n00b_conduit_fd_owner_t *)val);
    }
    return n00b_option_none(n00b_conduit_fd_owner_t *);
}

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_fd_read_topic(n00b_conduit_fd_owner_t *owner)
{
    if (!owner) return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    return n00b_result_ok(n00b_conduit_topic_base_t *, owner->read_topic);
}

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_fd_write_topic(n00b_conduit_fd_owner_t *owner)
{
    if (!owner) return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    return n00b_result_ok(n00b_conduit_topic_base_t *, owner->write_topic);
}

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_fd_status_topic(n00b_conduit_fd_owner_t *owner)
{
    if (!owner) return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    return n00b_result_ok(n00b_conduit_topic_base_t *, owner->status_topic);
}

void
n00b_conduit_fd_activate_reads(n00b_conduit_fd_owner_t *owner)
{
    if (!owner) {
        return;
    }

    bool expected = false;
    if (n00b_atomic_cas(&owner->read_active, &expected, true)) {
        fd_owner_update_io_mask(owner);
    }
}

void
n00b_conduit_fd_deactivate_reads(n00b_conduit_fd_owner_t *owner)
{
    if (!owner) {
        return;
    }

    bool expected = true;
    if (n00b_atomic_cas(&owner->read_active, &expected, false)) {
        fd_owner_update_io_mask(owner);
    }
}

// ============================================================================
// FD Owner teardown
// ============================================================================

static bool
fd_owner_begin_close(n00b_conduit_fd_owner_t *owner)
{
    uint64_t expected = 0;
    return n00b_atomic_cas(&owner->close_generation, &expected, 1);
}

static void
fd_owner_remove_registry(n00b_conduit_fd_owner_t *owner)
{
    bool expected = true;
    if (n00b_atomic_cas(&owner->registry_registered, &expected, false)
        && owner->conduit != nullptr) {
        n00b_dict_untyped_remove(&owner->conduit->fd_owners,
                                 (void *)(intptr_t)owner->fd);
    }
}

static void
fd_owner_publish_closed_once(n00b_conduit_fd_owner_t *owner)
{
    uint32_t previous = n00b_atomic_read_then_set(
        &owner->terminal_status_count,
        1);
    if (previous == 0) {
        publish_status(owner, N00B_CONDUIT_FD_ST_CLOSED, 0);
    }
}

static int
fd_owner_release_native_once(n00b_conduit_fd_owner_t *owner)
{
    if (!owner->close_on_done) {
        return 0;
    }

    bool previous = n00b_atomic_read_then_set(&owner->native_released, true);
    if (previous) {
        return 0;
    }

    return fd_owner_close_raw(owner);
}

static int
fd_owner_finish_closed(n00b_conduit_fd_owner_t *owner, bool close_topics)
{
    n00b_atomic_store(&owner->read_active, false);
    n00b_atomic_store(&owner->write_active, false);
    n00b_conduit_io_unwatch(owner->io, owner->fd);
    fd_owner_remove_registry(owner);
    fd_owner_publish_closed_once(owner);

    if (close_topics) {
        n00b_conduit_topic_close(owner->read_topic);
        n00b_conduit_topic_close(owner->write_topic);
        n00b_conduit_topic_close(owner->status_topic);
        n00b_conduit_topic_close(owner->wreq_topic);
    }

    n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_CLOSED);
    return fd_owner_release_native_once(owner);
}

void
n00b_conduit_fd_owner_close(n00b_conduit_fd_owner_t *owner)
{
    (void)n00b_conduit_fd_owner_close_result(owner);
}

n00b_result_t(bool)
n00b_conduit_fd_owner_close_result(n00b_conduit_fd_owner_t *owner)
    ensures {
        owner == nullptr || owner->close_generation <= 1;
        owner == nullptr || owner->terminal_status_count <= 1;
        owner == nullptr || n00b_result_is_err(result) ||
            n00b_result_value(result) == false ||
            owner->state == N00B_CONDUIT_FD_CLOSED;
        owner == nullptr || n00b_result_is_err(result) ||
            n00b_result_value(result) == false ||
            owner->registry_registered == false;
        owner == nullptr || n00b_result_is_err(result) ||
            n00b_result_value(result) == false ||
            owner->close_on_done == false ||
            owner->native_released == true;
    }
{
    if (!owner) {
        return n00b_result_ok(bool, false);
    }

    if (!fd_owner_begin_close(owner)) {
        return n00b_result_ok(bool, false);
    }

    // Drain the write queue — send error completions for pending entries.
    wq_drain_with_error(owner, ECANCELED);

    int close_err = fd_owner_finish_closed(owner, true);
    if (close_err) {
        return n00b_result_err(bool, close_err);
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
_n00b_conduit_fd_close_unmanaged(int fd)
    ensures {
        fd < 0 || n00b_result_is_err(result) ||
            n00b_result_value(result) == true;
        fd >= 0 || n00b_result_is_err(result) ||
            n00b_result_value(result) == false;
    }
{
    if (fd < 0) {
        return n00b_result_ok(bool, false);
    }

    n00b_conduit_fd_owner_t owner = {
        .fd            = fd,
        .close_on_done = true,
    };
#ifdef _WIN32
    owner.win_socket = fd_is_winsock_socket(fd);
#endif
    n00b_atomic_store(&owner.native_released, false);
    int close_err = fd_owner_release_native_once(&owner);
    if (close_err != 0) {
        return n00b_result_err(bool, close_err);
    }

    return n00b_result_ok(bool, true);
}

// ============================================================================
// Read path (Layer 1)
// ============================================================================

static void
publish_status(n00b_conduit_fd_owner_t *owner,
               n00b_conduit_fd_status_op_t status, int error_code)
{
    n00b_conduit_topic_base_t *topic = owner->status_topic;

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(topic);
    if (n00b_result_is_err(pub_res)) {
        n00b_atomic_add(&topic->epoch, 1);
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_allocator_t *alloc = fd_owner_allocator(owner);
    n00b_conduit_fd_status_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_fd_status_msg_t,
        &(n00b_alloc_opts_t){.allocator = alloc});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = topic;
    msg->header.generation = n00b_conduit_topic_generation(topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.fd         = owner->fd;
    msg->payload.status     = status;
    msg->payload.error_code = error_code;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_fd_status_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_fd_status_payload_t) *)topic,
        msg,
        N00B_CONDUIT_FD_OP_STATUS);

    n00b_conduit_publish_yield(pub);
}

static void
transition_state(n00b_conduit_fd_owner_t *owner, bool read_closed, bool write_closed)
{
    int current = n00b_atomic_load(&owner->state);

    if (read_closed && write_closed) {
        n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_CLOSED);
    }
    else if (read_closed) {
        if (current == N00B_CONDUIT_FD_WRITE_CLOSED) {
            n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_CLOSED);
        }
        else if (current == N00B_CONDUIT_FD_ACTIVE) {
            n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_READ_CLOSED);
        }
    }
    else if (write_closed) {
        if (current == N00B_CONDUIT_FD_READ_CLOSED) {
            n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_CLOSED);
        }
        else if (current == N00B_CONDUIT_FD_ACTIVE) {
            n00b_atomic_store(&owner->state, N00B_CONDUIT_FD_WRITE_CLOSED);
        }
    }

    // If fully closed, finish teardown exactly once. This removes the owner
    // from the registry before the OS can reuse the fd number.
    if (n00b_atomic_load(&owner->state) == N00B_CONDUIT_FD_CLOSED) {
        if (fd_owner_begin_close(owner)) {
            (void)fd_owner_finish_closed(owner, true);
        }
    }
}

static void
fd_owner_do_reads(n00b_conduit_fd_owner_t *owner)
{
    if (!n00b_atomic_load(&owner->read_active)) {
        return;
    }

    int state = n00b_atomic_load(&owner->state);
    if (state == N00B_CONDUIT_FD_READ_CLOSED || state == N00B_CONDUIT_FD_CLOSED) {
        return;
    }

    n00b_conduit_topic_base_t *topic = owner->read_topic;

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(topic);
    if (n00b_result_is_err(pub_res)) {
        // Bump epoch so subscribers know a read event was dropped.
        n00b_atomic_add(&topic->epoch, 1);
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    uint8_t buf[READ_BUF_SIZE];

    while (1) {
        ssize_t n = fd_owner_read_raw(owner, buf, sizeof(buf));

        if (n > 0) {
            n00b_atomic_add(&owner->read_pos, (uint64_t)n);

            n00b_allocator_t *alloc = fd_owner_allocator(owner);
            n00b_buffer_t *payload = n00b_buffer_from_bytes((char *)buf,
                                                            (int64_t)n,
                                                            .allocator = alloc);

            n00b_conduit_message_t(n00b_buffer_t *) *msg =
                n00b_alloc_with_opts(
                    n00b_conduit_message_t(n00b_buffer_t *),
                    &(n00b_alloc_opts_t){.allocator = alloc});

            msg->header.type       = N00B_CONDUIT_MSG_USER;
            msg->header.topic      = topic;
            msg->header.generation = n00b_conduit_topic_generation(topic);
            msg->header.epoch      = n00b_conduit_topic_epoch(topic);
            msg->header.timestamp  = 0;
            msg->header.next       = nullptr;

            msg->payload = payload;

            n00b_conduit_topic_deliver_msg(
                n00b_buffer_t *,
                (n00b_conduit_topic_t(n00b_buffer_t *) *)topic,
                msg,
                N00B_CONDUIT_FD_OP_READ_DATA);
            continue;
        }

        if (n == 0) {
            // EOF. Publish the status event (for status-topic
            // subscribers), then close the read_topic so its
            // subscribers see TOPIC_CLOSED *after* every prior chunk
            // they were delivered. The close is what gives
            // single-topic ordering between data and end-of-stream
            // — without it, a subscriber that sees the status EOF
            // event has no guarantee that the last chunks have
            // already landed in its read inbox.
            publish_status(owner, N00B_CONDUIT_FD_ST_READ_EOF, 0);
            n00b_conduit_topic_close(owner->read_topic);
            transition_state(owner, true, false);
            break;
        }

        // n < 0 -- error
        int read_err = fd_owner_last_error(owner);
        if (fd_owner_error_is_would_block(owner, read_err)) {
            break; // Normal: no more data available right now
        }

        // Real error. Close the read_topic so subscribers stop
        // waiting on it (same ordering reasoning as the EOF path).
        publish_status(owner, N00B_CONDUIT_FD_ST_READ_ERR, read_err);
        n00b_conduit_topic_close(owner->read_topic);
        transition_state(owner, true, false);
        break;
    }

    n00b_conduit_publish_yield(pub);
}

// ============================================================================
// Write path (Layer 1)
// ============================================================================

static void fd_owner_do_writes(n00b_conduit_fd_owner_t *owner);

/**
 * Append a write entry to the tail of the owner's write queue.
 * If the queue was empty, activate write monitoring and attempt
 * an immediate write (kqueue EV_CLEAR may miss the initial
 * writable edge on an already-writable fd).
 */
static void
wq_enqueue(n00b_conduit_fd_owner_t *owner, n00b_conduit_write_entry_t *entry)
{
    entry->next = nullptr;

    if (owner->wq_tail) {
        owner->wq_tail->next = entry;
    }
    else {
        owner->wq_head = entry;
    }
    owner->wq_tail = entry;

    // Activate write monitoring if this is the first entry.
    bool expected = false;
    if (n00b_atomic_cas(&owner->write_active, &expected, true)) {
        fd_owner_update_io_mask(owner);
        // Attempt an immediate write — kqueue with EV_CLEAR may not
        // deliver a writable event if the fd was already writable
        // before we registered EVFILT_WRITE.
        fd_owner_do_writes(owner);
    }
}

/**
 * Dequeue the head entry from the write queue.
 * If the queue becomes empty, deactivate write monitoring.
 */
static void
wq_dequeue_head(n00b_conduit_fd_owner_t *owner)
{
    n00b_conduit_write_entry_t *head = owner->wq_head;
    if (!head) {
        return;
    }

    owner->wq_head = head->next;
    if (!owner->wq_head) {
        owner->wq_tail = nullptr;
        // Queue is empty — deactivate write monitoring.
        bool expected = true;
        if (n00b_atomic_cas(&owner->write_active, &expected, false)) {
            fd_owner_update_io_mask(owner);
        }
    }
}

n00b_result_t(uint64_t)
n00b_conduit_fd_write_submit(n00b_conduit_fd_owner_t *owner,
                             const void *data, size_t len,
                             void *reply_inbox,
                             bool (*reply_push)(void *, void *))
{
    if (!owner || !data || len == 0) {
        return n00b_result_err(uint64_t, EINVAL);
    }

    int state = n00b_atomic_load(&owner->state);
    if (state == N00B_CONDUIT_FD_WRITE_CLOSED || state == N00B_CONDUIT_FD_CLOSED) {
        return n00b_result_err(uint64_t, EPIPE);
    }

    uint64_t request_id = n00b_atomic_add(&owner->next_request_id, 1);

    // Copy the data into a GC-managed buffer so the caller can free
    // or reuse their original immediately.
    n00b_allocator_t *sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uint8_t *copy = n00b_alloc_array_with_opts(uint8_t, len,
                        &(n00b_alloc_opts_t){.allocator = sp});
    memcpy(copy, data, len);

    n00b_conduit_write_entry_t *entry = n00b_alloc_with_opts(n00b_conduit_write_entry_t,
                                            &(n00b_alloc_opts_t){.allocator = sp});
    entry->data        = copy;
    entry->total_len   = len;
    entry->bytes_sent  = 0;
    entry->request_id  = request_id;
    entry->reply_inbox = reply_inbox;
    entry->reply_push  = reply_push;

    wq_enqueue(owner, entry);

    return n00b_result_ok(uint64_t, request_id);
}

static size_t
pending_write_bytes(n00b_conduit_fd_owner_t *owner, uint64_t request_id)
{
    n00b_conduit_write_entry_t *entry = owner->wq_head;

    while (entry != nullptr) {
        if (entry->request_id == request_id) {
            return entry->bytes_sent;
        }
        entry = entry->next;
    }

    return 0;
}

static int
write_done_error_code(n00b_conduit_fd_owner_t *owner, int error_code)
{
    if (fd_owner_error_is_pipe_closed(owner, error_code)) {
        return N00B_CONDUIT_ERR_EPIPE;
    }

    return N00B_CONDUIT_ERR_IO;
}

static void
send_write_done(n00b_conduit_fd_owner_t *owner,
                void *reply_inbox, bool (*reply_push)(void *, void *),
                uint64_t request_id, size_t bytes_written,
                bool error, int error_code)
{
    if (!reply_inbox || !reply_push) {
        return;
    }

    n00b_allocator_t *alloc = fd_owner_allocator(owner);
    n00b_conduit_fd_write_done_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_fd_write_done_msg_t,
        &(n00b_alloc_opts_t){.allocator = alloc});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = nullptr;
    msg->header.generation = 0;
    msg->header.epoch      = 0;
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.fd            = owner->fd;
    msg->payload.request_id    = request_id;
    msg->payload.bytes_written = bytes_written;
    msg->payload.error         = error;
    msg->payload.error_code    = error_code;

    reply_push(reply_inbox, msg);
}

static void
publish_write_done_event(n00b_conduit_fd_owner_t *owner,
                         n00b_conduit_publisher_t *pub,
                         const uint8_t *data, size_t len,
                         uint64_t stream_pos, uint64_t request_id)
{
    (void)pub;

    // Allocate immutable copy
    n00b_allocator_t *alloc = fd_owner_allocator(owner);
    void *copy = n00b_alloc_array_with_opts(uint8_t, len,
        &(n00b_alloc_opts_t){.allocator = alloc});
    memcpy(copy, data, len);

    n00b_conduit_fd_write_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_fd_write_msg_t,
        &(n00b_alloc_opts_t){.allocator = alloc});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = owner->write_topic;
    msg->header.generation = n00b_conduit_topic_generation(owner->write_topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(owner->write_topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.fd         = owner->fd;
    msg->payload.data       = copy;
    msg->payload.len        = len;
    msg->payload.stream_pos = stream_pos;
    msg->payload.request_id = request_id;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_fd_write_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_fd_write_payload_t) *)owner->write_topic,
        msg,
        N00B_CONDUIT_FD_OP_WRITE_DATA);
}

/**
 * Drain the write queue, sending error completions for all entries.
 * Used on fatal write error and on owner close.
 */
static void
wq_drain_with_error(n00b_conduit_fd_owner_t *owner, int error_code)
{
    while (owner->wq_head) {
        n00b_conduit_write_entry_t *entry = owner->wq_head;
        send_write_done(owner, entry->reply_inbox, entry->reply_push,
                        entry->request_id, entry->bytes_sent,
                        true, error_code);
        wq_dequeue_head(owner);
    }
}

static void
fd_owner_do_writes(n00b_conduit_fd_owner_t *owner)
{
    bool expected_draining = false;
    if (!n00b_atomic_cas(&owner->write_draining,
                         &expected_draining,
                         true)) {
        return;
    }

    int state = n00b_atomic_load(&owner->state);
    if (state == N00B_CONDUIT_FD_WRITE_CLOSED || state == N00B_CONDUIT_FD_CLOSED) {
        goto done;
    }

    // Fire one-shot on_first_writable hook (used by outbound connect).
    if (owner->on_first_writable) {
        void (*cb)(n00b_conduit_fd_owner_t *, void *) = owner->on_first_writable;
        void *ctx                                      = owner->on_first_writable_ctx;
        owner->on_first_writable                       = nullptr;
        owner->on_first_writable_ctx                   = nullptr;
        cb(owner, ctx);
    }

    // Process entries from the write queue head.
    while (owner->wq_head) {
        n00b_conduit_write_entry_t *entry = owner->wq_head;
        size_t remaining = entry->total_len - entry->bytes_sent;

        // Claim publisher on write topic for as-done events.
        n00b_result_t(n00b_conduit_publisher_t *) pub_res =
            n00b_conduit_publish_try_claim(owner->write_topic);
        n00b_conduit_publisher_t *write_pub = nullptr;
        if (n00b_result_is_ok(pub_res)) {
            write_pub = n00b_result_get(pub_res);
        }
        else {
            n00b_atomic_add(&owner->write_topic->epoch, 1);
        }

        bool     blocked = false;
        bool     error   = false;
        int      err_code = 0;

        while (remaining > 0) {
            size_t  chunk = remaining < PIPE_BUF ? remaining : PIPE_BUF;
            ssize_t n     = fd_owner_write_raw(owner,
                                               entry->data + entry->bytes_sent,
                                               chunk);

            if (n > 0) {
                uint64_t pos = n00b_atomic_add(&owner->write_pos, (uint64_t)n);

                if (write_pub) {
                    publish_write_done_event(owner, write_pub,
                                             entry->data + entry->bytes_sent,
                                             (size_t)n, pos,
                                             entry->request_id);
                }

                entry->bytes_sent += (size_t)n;
                remaining         -= (size_t)n;
                continue;
            }

            if (n < 0) {
                int write_err = fd_owner_last_error(owner);
                if (fd_owner_error_is_would_block(owner, write_err)) {
                    // Can't write more right now — leave entry at head,
                    // next WRITE readiness will continue.
                    blocked = true;
                    break;
                }

                if (fd_owner_error_is_pipe_closed(owner, write_err)) {
                    publish_status(owner, N00B_CONDUIT_FD_ST_WRITE_EPIPE,
                                   write_err);
                    transition_state(owner, false, true);
                    error   = true;
                    err_code = write_err;
                    break;
                }

                publish_status(owner, N00B_CONDUIT_FD_ST_WRITE_ERR, write_err);
                transition_state(owner, false, true);
                error    = true;
                err_code = write_err;
                break;
            }
        }

        if (write_pub) {
            n00b_conduit_publish_yield(write_pub);
        }

        if (error) {
            // Fatal write error — send error for this entry and drain
            // the rest of the queue with errors.
            send_write_done(owner, entry->reply_inbox, entry->reply_push,
                            entry->request_id, entry->bytes_sent,
                            true, err_code);
            wq_dequeue_head(owner);
            wq_drain_with_error(owner, err_code);
            goto done;
        }

        if (blocked) {
            // Short write / EAGAIN — leave entry at head, return.
            // Next WRITE readiness event will pick up where we left off.
            goto done;
        }

        // Entry fully written — send success completion and advance.
        send_write_done(owner, entry->reply_inbox, entry->reply_push,
                        entry->request_id, entry->bytes_sent,
                        false, 0);
        wq_dequeue_head(owner);
    }

done:
    n00b_atomic_store(&owner->write_draining, false);
}

// ============================================================================
// FD Owner dispatch (called from io.c when readiness event arrives)
// ============================================================================

void
n00b_conduit_fd_owner_dispatch(n00b_conduit_fd_owner_t *owner, uint32_t io_ops)
{
    if (!owner) {
        return;
    }

    if (io_ops & N00B_CONDUIT_IO_READ) {
        fd_owner_do_reads(owner);
    }

    if (io_ops & N00B_CONDUIT_IO_WRITE) {
        fd_owner_do_writes(owner);
    }

    if (io_ops & (N00B_CONDUIT_IO_HUP | N00B_CONDUIT_IO_ERROR)) {
        // If a connect completion hook is pending, fire it now
        if (owner->on_first_writable) {
            void (*cb)(n00b_conduit_fd_owner_t *, void *) = owner->on_first_writable;
            void *ctx                                      = owner->on_first_writable_ctx;
            owner->on_first_writable                       = nullptr;
            owner->on_first_writable_ctx                   = nullptr;
            cb(owner, ctx);
        }

        int fstate = n00b_atomic_load(&owner->state);
        if (fstate == N00B_CONDUIT_FD_ACTIVE) {
            if (io_ops & N00B_CONDUIT_IO_HUP) {
                fd_owner_do_reads(owner);
            }
        }
    }
}

// ============================================================================
// Stream reader (Layer 2)
// ============================================================================

static inline size_t
accum_len(n00b_conduit_stream_reader_t *reader)
{
    return reader->accum ? reader->accum->byte_len : 0;
}

static inline char *
accum_data(n00b_conduit_stream_reader_t *reader)
{
    return reader->accum ? reader->accum->data : nullptr;
}

static void
accum_consume(n00b_conduit_stream_reader_t *reader, size_t nbytes)
{
    if (reader == nullptr || nbytes == 0) {
        return;
    }
    if (reader->accum == nullptr) {
        return;
    }
    if (nbytes > reader->accum->byte_len) {
        nbytes = reader->accum->byte_len;
    }
    if (nbytes > 0 && nbytes < reader->accum->byte_len) {
        memmove(reader->accum->data, reader->accum->data + nbytes,
                reader->accum->byte_len - nbytes);
    }
    reader->accum->byte_len -= nbytes;
    reader->accum_pos       += nbytes;
}

static void
try_fulfill_request(n00b_conduit_stream_reader_t *reader)
{
    while (reader->pending_head) {
        n00b_conduit_stream_request_t *req = reader->pending_head;
        size_t alen = accum_len(reader);

        if (req->use_delimiter) {
            size_t scan_limit = req->max_bytes;
            if (scan_limit == 0 || scan_limit > alen) {
                scan_limit = alen;
            }

            const uint8_t *found = memchr(accum_data(reader), req->delimiter, scan_limit);
            size_t          nbytes;

            if (found) {
                nbytes = (size_t)(found - (const uint8_t *)accum_data(reader)) + 1;
            }
            else if (req->max_bytes > 0 && alen >= req->max_bytes) {
                nbytes = req->max_bytes;
            }
            else if (reader->eof || reader->error) {
                nbytes = alen;
            }
            else {
                break;
            }

            if (nbytes == 0 && !reader->eof && !reader->error) {
                break;
            }

            void *result_data = nullptr;
            if (nbytes > 0) {
                n00b_allocator_t *alloc = fd_owner_allocator(reader->owner);
                result_data = n00b_alloc_array_with_opts(uint8_t, nbytes,
                    &(n00b_alloc_opts_t){.allocator = alloc});
                memcpy(result_data, accum_data(reader), nbytes);
            }

            n00b_allocator_t *alloc = fd_owner_allocator(reader->owner);
            n00b_conduit_fd_stream_msg_t *msg = n00b_alloc_with_opts(
                n00b_conduit_fd_stream_msg_t,
                &(n00b_alloc_opts_t){.allocator = alloc});

            msg->header.type       = N00B_CONDUIT_MSG_USER;
            msg->header.topic      = nullptr;
            msg->header.generation = 0;
            msg->header.epoch      = 0;
            msg->header.timestamp  = 0;
            msg->header.next       = nullptr;

            msg->payload.fd         = reader->owner->fd;
            msg->payload.data       = result_data;
            msg->payload.len        = nbytes;
            msg->payload.stream_pos = reader->accum_pos;
            msg->payload.eof        = reader->eof && nbytes >= alen;
            msg->payload.error      = reader->error;
            msg->payload.error_code = reader->error_code;

            if (req->reply_push) {
                req->reply_push(req->reply_inbox, msg);
            }

            accum_consume(reader, nbytes);
        }
        else {
            // read N bytes
            size_t nbytes = req->requested;

            if (alen >= nbytes) {
                // Have enough
            }
            else if (reader->eof || reader->error) {
                nbytes = alen;
            }
            else {
                break;
            }

            if (nbytes == 0 && !reader->eof && !reader->error) {
                break;
            }

            void *result_data = nullptr;
            if (nbytes > 0) {
                n00b_allocator_t *alloc = fd_owner_allocator(reader->owner);
                result_data = n00b_alloc_array_with_opts(uint8_t, nbytes,
                    &(n00b_alloc_opts_t){.allocator = alloc});
                memcpy(result_data, accum_data(reader), nbytes);
            }

            n00b_allocator_t *alloc = fd_owner_allocator(reader->owner);
            n00b_conduit_fd_stream_msg_t *msg = n00b_alloc_with_opts(
                n00b_conduit_fd_stream_msg_t,
                &(n00b_alloc_opts_t){.allocator = alloc});

            msg->header.type       = N00B_CONDUIT_MSG_USER;
            msg->header.topic      = nullptr;
            msg->header.generation = 0;
            msg->header.epoch      = 0;
            msg->header.timestamp  = 0;
            msg->header.next       = nullptr;

            msg->payload.fd         = reader->owner->fd;
            msg->payload.data       = result_data;
            msg->payload.len        = nbytes;
            msg->payload.stream_pos = reader->accum_pos;
            msg->payload.eof        = reader->eof && nbytes >= alen;
            msg->payload.error      = reader->error;
            msg->payload.error_code = reader->error_code;

            if (req->reply_push) {
                req->reply_push(req->reply_inbox, msg);
            }

            accum_consume(reader, nbytes);
        }

        reader->pending_head = req->next;
        if (!reader->pending_head) {
            reader->pending_tail = nullptr;
        }
    }
}

void
n00b_conduit_stream_reader_process(n00b_conduit_stream_reader_t *reader)
{
    if (!reader) {
        return;
    }

    // Drain as-done read buffers from internal inbox
    n00b_conduit_message_t(n00b_buffer_t *) *msg;
    while ((msg = n00b_conduit_inbox_pop_msg(n00b_buffer_t *, reader->internal_inbox)) != nullptr) {
        n00b_buffer_t *buf = msg->payload;
        if (buf && buf->byte_len > 0) {
            if (!reader->accum) {
                reader->accum = n00b_buffer_empty(
                    .allocator = fd_owner_allocator(reader->owner));
            }
            n00b_buffer_concat(reader->accum, buf);
        }
    }

    // Check for status events (EOF/error) via system queue
    n00b_conduit_sys_msg_t *sys;
    while ((sys = n00b_conduit_inbox_pop_sys(reader->internal_inbox)) != nullptr) {
        if (sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
            reader->eof = true;
        }
    }

    try_fulfill_request(reader);
}

n00b_result_t(n00b_conduit_stream_reader_t *)
n00b_conduit_stream_reader_new(n00b_conduit_t *c, n00b_conduit_fd_owner_t *owner)
{
    if (!c || !owner) {
        return n00b_result_err(n00b_conduit_stream_reader_t *, EINVAL);
    }

    n00b_conduit_stream_reader_t *reader = n00b_alloc_with_opts(
        n00b_conduit_stream_reader_t,
        &(n00b_alloc_opts_t){.allocator = c->allocator});

    reader->conduit = c;
    reader->owner   = owner;

    reader->internal_inbox = ({
         n00b_conduit_inbox_t(n00b_buffer_t *) *_inbox =
             n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                 &(n00b_alloc_opts_t){.allocator = c->allocator});
        n00b_conduit_inbox_init(n00b_buffer_t *,
                                _inbox, c, N00B_CONDUIT_BP_UNBOUNDED, 0);
        _inbox;
    });

    // Subscribe to the owner's read topic (now publishes n00b_buffer_t *).
    // The on_first_subscribe callback on the read topic will automatically
    // activate reads when this (or any) first subscriber registers.
    reader->sub_handle = n00b_conduit_subscribe(
        n00b_buffer_t *,
        (n00b_conduit_topic_t(n00b_buffer_t *) *)owner->read_topic,
        reader->internal_inbox,
        .operations = N00B_CONDUIT_FD_OP_READ_DATA);

    reader->accum        = nullptr;
    reader->accum_pos    = 0;
    reader->pending_head = nullptr;
    reader->pending_tail = nullptr;
    reader->eof          = false;
    reader->error        = false;
    reader->error_code   = 0;

    return n00b_result_ok(n00b_conduit_stream_reader_t *, reader);
}

void
n00b_conduit_stream_reader_destroy(n00b_conduit_stream_reader_t *reader)
{
    if (!reader) {
        return;
    }

    n00b_conduit_sub_cancel(reader->sub_handle);
    reader->pending_head = nullptr;
    reader->pending_tail = nullptr;
}

void
n00b_conduit_stream_read(n00b_conduit_stream_reader_t *reader, size_t nbytes,
                         void *reply_inbox, bool (*reply_push)(void *, void *))
{
    if (!reader || nbytes == 0 || !reply_inbox || !reply_push) {
        return;
    }

    n00b_conduit_stream_request_t *req = n00b_alloc_with_opts(
        n00b_conduit_stream_request_t,
        &(n00b_alloc_opts_t){.allocator = reader->conduit->allocator});

    req->requested     = nbytes;
    req->delimiter     = 0;
    req->max_bytes     = 0;
    req->use_delimiter = false;
    req->reply_inbox   = reply_inbox;
    req->reply_push    = reply_push;
    req->next          = nullptr;

    if (reader->pending_tail) {
        reader->pending_tail->next = req;
    }
    else {
        reader->pending_head = req;
    }
    reader->pending_tail = req;

    n00b_conduit_stream_reader_process(reader);
}

void
n00b_conduit_stream_read_until(n00b_conduit_stream_reader_t *reader,
                               uint8_t delimiter, size_t max_bytes,
                               void *reply_inbox,
                               bool (*reply_push)(void *, void *))
{
    if (!reader || !reply_inbox || !reply_push) {
        return;
    }

    n00b_conduit_stream_request_t *req = n00b_alloc_with_opts(
        n00b_conduit_stream_request_t,
        &(n00b_alloc_opts_t){.allocator = reader->conduit->allocator});

    req->requested     = 0;
    req->delimiter     = delimiter;
    req->max_bytes     = max_bytes;
    req->use_delimiter = true;
    req->reply_inbox   = reply_inbox;
    req->reply_push    = reply_push;
    req->next          = nullptr;

    if (reader->pending_tail) {
        reader->pending_tail->next = req;
    }
    else {
        reader->pending_head = req;
    }
    reader->pending_tail = req;

    n00b_conduit_stream_reader_process(reader);
}

// ============================================================================
// Stream writer convenience
// ============================================================================

// Non-kwarg core of n00b_fd_owner_read_all.
static n00b_result_t(n00b_buffer_t *)
fd_owner_read_all_core(n00b_conduit_fd_owner_t *owner,
                       n00b_allocator_t *allocator)
{
    if (!owner) {
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    int state = n00b_atomic_load(&owner->state);
    if (state == N00B_CONDUIT_FD_READ_CLOSED || state == N00B_CONDUIT_FD_CLOSED) {
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_FD_CLOSED);
    }

    n00b_conduit_t *c = owner->conduit;
    if (!c) {
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    // Allocate the typed read inbox from the conduit pool, matching
    // file.c's stream-open machinery so the inbox's GC scan
    // semantics line up with the rest of the conduit infrastructure.
    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_allocator_t *inbox_alloc = rt
        ? (n00b_allocator_t *)&rt->conduit_pool
        : c->allocator;

    // Allocate + initialize the typed inbox in a statement-expression,
    // mirroring `n00b_conduit_stream_reader_new`'s pattern.
    auto inbox = ({
        n00b_conduit_inbox_t(n00b_buffer_t *) *_inbox = n00b_alloc_with_opts(
            n00b_conduit_inbox_t(n00b_buffer_t *),
            &(n00b_alloc_opts_t){.allocator = inbox_alloc});
        n00b_conduit_inbox_init(n00b_buffer_t *, _inbox, c,
                                N00B_CONDUIT_BP_UNBOUNDED, 0);
        _inbox;
    });
    if (!inbox) {
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    // Subscribe to the status topic FIRST so READ_ERR events cannot
    // race ahead of our data subscription. Both subscriptions are
    // cancelled before return.
    n00b_conduit_fd_status_inbox_t *status_inbox =
        n00b_conduit_fd_status_inbox_new(c);
    n00b_conduit_sub_handle_t status_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    auto status_topic = n00b_conduit_fd_status_topic_typed(owner);
    if (status_topic && status_inbox) {
        status_sub = n00b_conduit_fd_status_subscribe(
            status_topic, status_inbox, .flags = 0);
    }

    // Subscribe persistently to the read topic. The on_first_subscribe
    // callback flips read_active=true and the IO thread starts pumping
    // bytes; no chunks can be published before we are subscribed.
    auto read_topic = n00b_conduit_fd_read_topic_typed(owner);
    if (!read_topic) {
        if (status_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
            n00b_conduit_sub_cancel(status_sub);
        }
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    auto sub_r = n00b_conduit_read_async(n00b_buffer_t *,
                                         read_topic, inbox);
    if (n00b_result_is_err(sub_r)) {
        if (status_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
            n00b_conduit_sub_cancel(status_sub);
        }
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_ALLOC);
    }
    n00b_conduit_sub_handle_t read_sub = n00b_result_get(sub_r).handle;

    // Accumulator owned by the caller's allocator.
    n00b_buffer_t *acc = n00b_buffer_new(0, .allocator = allocator);

    bool eof       = false;
    int  io_err    = 0;

    while (!eof && !io_err) {
        // Drain any pending status events first. Read errors are
        // authoritative; READ_EOF on the status side is a hint, not
        // load-bearing — TOPIC_CLOSED on the read inbox sys queue is
        // the ordered EOF signal.
        if (status_inbox) {
            n00b_conduit_fd_status_msg_t *m;
            while ((m = n00b_conduit_fd_status_inbox_pop(status_inbox))
                   != nullptr) {
                uint32_t s = m->payload.status;
                if (s & N00B_CONDUIT_FD_ST_READ_ERR) {
                    io_err = m->payload.error_code ? m->payload.error_code
                                                   : N00B_CONDUIT_ERR_IO;
                    break;
                }
            }
        }
        if (io_err) break;

        auto msg = n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
        if (msg) {
            n00b_buffer_t *chunk = msg->payload;
            if (!chunk || chunk->byte_len == 0) {
                // Zero-byte chunk is an EOF marker.
                eof = true;
                break;
            }
            n00b_buffer_concat(acc, chunk);
            continue;
        }

        // No data: drain sys queue. TOPIC_CLOSED is the authoritative
        // EOF signal because it is in-order with respect to data
        // chunks (the IO thread publishes the last chunk THEN closes
        // the topic).
        if (n00b_conduit_inbox_has_sys(inbox)) {
            n00b_conduit_sys_msg_t *sys = n00b_conduit_inbox_pop_sys(inbox);
            if (sys && sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
                eof = true;
                break;
            }
            // Other sys messages (SUB_ACCEPTED etc.) are not relevant
            // here; continue polling.
            continue;
        }

        // Inbox empty + no sys close: wait for IO thread to notify.
        // `.auto_unlock = true` releases the CV mutex on wakeup so
        // the IO thread can re-acquire it for the next notify.
        n00b_condition_wait(&inbox->cv,
                            .timeout_ms = 50,
                            .auto_unlock = true);
    }

    // Cancel subscriptions before returning so the IO thread stops
    // publishing into our inbox.
    if (read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(read_sub);
    }
    if (status_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(status_sub);
    }

    if (io_err) {
        return n00b_result_err(n00b_buffer_t *, N00B_CONDUIT_ERR_IO);
    }

    return n00b_result_ok(n00b_buffer_t *, acc);
}

n00b_result_t(n00b_buffer_t *)
n00b_fd_owner_read_all(n00b_conduit_fd_owner_t *owner) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return fd_owner_read_all_core(owner, allocator);
}

n00b_result_t(int)
n00b_fd_owner_write(n00b_conduit_fd_owner_t *owner,
                    const void *data, size_t len)
{
    auto attempt_r = n00b_fd_owner_write_attempt(owner, data, len);
    if (n00b_result_is_err(attempt_r)) {
        return n00b_result_err(int, n00b_result_get_err(attempt_r));
    }

    n00b_fd_owner_write_attempt_t attempt = n00b_result_get(attempt_r);
    if (attempt.error) {
        return n00b_result_err(int, attempt.error_code);
    }

    return n00b_result_ok(int, (int)attempt.bytes_written);
}

n00b_result_t(n00b_fd_owner_write_attempt_t)
n00b_fd_owner_write_attempt(n00b_conduit_fd_owner_t *owner,
                            const void *data, size_t len)
{
    if (!owner || !data || len == 0) {
        return n00b_result_err(n00b_fd_owner_write_attempt_t,
                               N00B_CONDUIT_ERR_NULL_ARG);
    }

    int state = n00b_atomic_load(&owner->state);
    if (state == N00B_CONDUIT_FD_WRITE_CLOSED || state == N00B_CONDUIT_FD_CLOSED) {
        return n00b_result_err(n00b_fd_owner_write_attempt_t,
                               N00B_CONDUIT_ERR_FD_CLOSED);
    }

    // Per-thread reusable completion inbox: a blocking write needs a private
    // reply channel, but allocating a fresh one per call churned a condition
    // variable each time, and because that CV lives in the (non-GC) conduit
    // pool, _n00b_condition_init registered a GC root for it that was never
    // unregistered -- so a streaming N-row writer leaked N roots and went
    // O(N^2) in _n00b_gc_register_root's linear root scan. One inbox per
    // (pooled) thread, reused for the thread's life, bounds that to a single
    // root per thread. Completions are matched by (fd, request_id) below, so
    // reusing one inbox across owners/conduits -- and across concurrent
    // writers, each on its own thread -- is safe.
    n00b_thread_t *self = n00b_thread_self();
    n00b_conduit_fd_write_done_inbox_t *done_inbox =
        (n00b_conduit_fd_write_done_inbox_t *)self->write_done_inbox;
    if (done_inbox == nullptr) {
        done_inbox = n00b_conduit_fd_write_done_inbox_new(owner->conduit);
        self->write_done_inbox = done_inbox;
    }

    auto submit_r = n00b_conduit_fd_write_submit(
        owner, data, len, done_inbox,
        (bool (*)(void *, void *))_N00B_INBOX_FN(push, n00b_conduit_fd_write_done_payload_t));

    if (n00b_result_is_err(submit_r)) {
        return n00b_result_err(n00b_fd_owner_write_attempt_t,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    uint64_t request_id = n00b_result_get(submit_r);

    // Drive the write queue directly until our entry completes. Because the
    // inbox is reused, it may also carry a late completion from an earlier
    // write on this thread that timed out (its entry finished afterward);
    // those carry a different (fd, request_id) -- discard and free them.
    n00b_conduit_fd_write_done_msg_t *done = nullptr;

    for (int attempts = 0; attempts < 500 && !done; attempts++) {
        fd_owner_do_writes(owner);
        n00b_conduit_fd_write_done_msg_t *m;
        while ((m = n00b_conduit_fd_write_done_inbox_pop(done_inbox)) != nullptr) {
            if (m->payload.fd == owner->fd
                && m->payload.request_id == request_id) {
                done = m;
                break;
            }
            n00b_free(m); // stale completion from an abandoned earlier write
        }
        if (!done) {
            // Brief wait for FD writability.
            n00b_condition_wait(&done_inbox->cv,
                                .timeout_ms = 10,
                                .auto_unlock = true);
        }
    }

    if (!done) {
        return n00b_result_ok(
            n00b_fd_owner_write_attempt_t,
            ((n00b_fd_owner_write_attempt_t){
                .bytes_written = pending_write_bytes(owner, request_id),
                .error         = true,
                .error_code    = N00B_CONDUIT_ERR_IO,
            }));
    }

    n00b_fd_owner_write_attempt_t attempt = {
        .bytes_written = done->payload.bytes_written,
        .error         = done->payload.error,
        .error_code    = done->payload.error
                             ? write_done_error_code(owner,
                                                     done->payload.error_code)
                             : N00B_CONDUIT_ERR_NONE,
    };

    // The inbox is reused for the thread's life; return this completion's slot
    // to its allocator now (the per-write inbox path used to leak it with the
    // whole inbox). Payload is POD -- no nested pointers to release.
    n00b_free(done);

    return n00b_result_ok(n00b_fd_owner_write_attempt_t, attempt);
}

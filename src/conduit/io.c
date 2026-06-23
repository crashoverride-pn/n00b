/*
 * io.c — Generic I/O backend implementation.
 *
 * Common code shared by all backends: lifecycle, watch/unwatch,
 * event delivery loop.
 */

#include "conduit/io.h"
#include "conduit/fd_managed.h"
#include "conduit/socket.h"
#include "core/runtime.h"
#include "core/time.h"

#ifdef _WIN32
extern bool n00b_wsa_ensure_init(void);
#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif
#endif

// ============================================================================
// Lifecycle
// ============================================================================

n00b_result_t(n00b_conduit_io_backend_t *)
n00b_conduit_io_new_default(n00b_conduit_t *c)
{
    const n00b_conduit_io_ops_t *ops = n00b_conduit_io_default_ops()!;
    n00b_result_t(n00b_conduit_io_backend_t *) res = n00b_conduit_io_new(c, ops);

#ifdef __linux__
    if (n00b_result_is_err(res)) {
        res = n00b_conduit_io_new(c, n00b_conduit_io_poll_ops()!);
    }
#endif

    return res;
}

n00b_result_t(n00b_conduit_io_backend_t *)
n00b_conduit_io_new(n00b_conduit_t *c, const n00b_conduit_io_ops_t *ops)
{
    if (!c || !ops || !ops->init) {
        return n00b_result_err(n00b_conduit_io_backend_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

#ifdef _WIN32
    if (!n00b_wsa_ensure_init()) {
        return n00b_result_err(n00b_conduit_io_backend_t *, N00B_CONDUIT_ERR_ALLOC);
    }
#endif

    n00b_conduit_io_backend_t *io = n00b_alloc_with_opts(n00b_conduit_io_backend_t,
                                        &(n00b_alloc_opts_t){.allocator = c->allocator});
    if (!io) {
        return n00b_result_err(n00b_conduit_io_backend_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    io->conduit = c;
    io->ops     = ops;
    n00b_atomic_store(&io->shutdown, false);

    io->ctx = ops->init(c);
    if (!io->ctx) {
        return n00b_result_err(n00b_conduit_io_backend_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    n00b_result_t(bool) reg = n00b_conduit_register_backend(c, io);
    if (n00b_result_is_err(reg)) {
        ops->cleanup(io->ctx);
        return n00b_result_err(n00b_conduit_io_backend_t *, n00b_result_get_err(reg));
    }

    return n00b_result_ok(n00b_conduit_io_backend_t *, io);
}

void
n00b_conduit_io_destroy(n00b_conduit_io_backend_t *io)
{
    if (!io) return;

    n00b_atomic_store(&io->shutdown, true);

    if (io->conduit) {
        n00b_conduit_unregister_backend(io->conduit, io);
    }

    if (io->ops && io->ops->cleanup && io->ctx) {
        io->ops->cleanup(io->ctx);
    }
    io->ctx = nullptr;
}

// ============================================================================
// FD monitoring
// ============================================================================

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_io_watch(n00b_conduit_io_backend_t *io, int fd,
                      n00b_conduit_io_op_t ops,
                      n00b_conduit_io_target_t *target)
{
    if (!io || fd < 0) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (n00b_atomic_load(&io->shutdown)) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_SHUTDOWN);
    }

    n00b_result_t(n00b_conduit_topic_base_t *) topic_res =
        n00b_conduit_topic_for_fd(io->conduit, fd);
    if (n00b_result_is_err(topic_res)) {
        return topic_res;
    }

    n00b_conduit_topic_base_t *topic = n00b_result_get(topic_res);

    if (!io->ops->add(io->ctx, fd, ops, target)) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    return n00b_result_ok(n00b_conduit_topic_base_t *, topic);
}

bool
n00b_conduit_io_modify(n00b_conduit_io_backend_t *io, int fd,
                       n00b_conduit_io_op_t ops,
                       n00b_conduit_io_target_t *target)
{
    if (!io || fd < 0 || !io->ops->modify) return false;
    return io->ops->modify(io->ctx, fd, ops, target);
}

bool
n00b_conduit_io_unwatch(n00b_conduit_io_backend_t *io, int fd)
{
    if (!io || fd < 0 || !io->ops->remove) return false;
    return io->ops->remove(io->ctx, fd);
}

// ============================================================================
// Event delivery
// ============================================================================

static n00b_conduit_msg_type_t
io_op_to_msg_type(n00b_conduit_io_op_t op)
{
    if (op & N00B_CONDUIT_IO_ERROR) return N00B_CONDUIT_MSG_ERROR;
    if (op & N00B_CONDUIT_IO_HUP)  return N00B_CONDUIT_MSG_HUP;
    if (op & N00B_CONDUIT_IO_READ) return N00B_CONDUIT_MSG_READABLE;
    if (op & N00B_CONDUIT_IO_WRITE) return N00B_CONDUIT_MSG_WRITABLE;
    return N00B_CONDUIT_MSG_USER;
}

static void
deliver_io_event(n00b_conduit_io_backend_t *io, n00b_conduit_io_event_t *event)
{
    n00b_conduit_io_target_t *target = event->target;

    // Dispatch to the appropriate handler based on the variant tag.
    if (target && _n00b_variant_is_type_ptr(target, n00b_conduit_fd_owner_t *)) {
        n00b_conduit_fd_owner_t *owner =
            _n00b_variant_get_ptr(target, n00b_conduit_fd_owner_t *);
        n00b_conduit_fd_owner_dispatch(owner, event->ops);
        return;
    }

    if (target && _n00b_variant_is_type_ptr(target, n00b_conduit_listener_t *)) {
        n00b_conduit_listener_t *listener =
            _n00b_variant_get_ptr(target, n00b_conduit_listener_t *);
        n00b_conduit_listener_dispatch(listener, event->ops);
        return;
    }

    if (target && _n00b_variant_is_type_ptr(target, n00b_conduit_udp_t *)) {
        n00b_conduit_udp_t *udp =
            _n00b_variant_get_ptr(target, n00b_conduit_udp_t *);
        extern void n00b_conduit_udp_dispatch(n00b_conduit_udp_t *,
                                              uint32_t io_ops);
        n00b_conduit_udp_dispatch(udp, event->ops);
        return;
    }
}

n00b_result_t(int)
n00b_conduit_io_poll(n00b_conduit_io_backend_t *io, int timeout_ms)
{
    if (!io || !io->ops->wait) return n00b_result_err(int, EINVAL);
    if (n00b_atomic_load(&io->shutdown)) return n00b_result_err(int, ESHUTDOWN);

    n00b_conduit_io_event_t events[64];
    int n = io->ops->wait(io->ctx, events, 64, timeout_ms);
    if (n < 0) {
        int err = (n < -1) ? -n : errno;
        return n00b_result_err(int, err);
    }

    if (n00b_atomic_load(&io->shutdown)) return n00b_result_err(int, ESHUTDOWN);

    for (int i = 0; i < n; i++) {
        deliver_io_event(io, &events[i]);
    }
    return n00b_result_ok(int, n);
}

void
n00b_conduit_io_run(n00b_conduit_io_backend_t *io)
{
    if (!io) return;

    while (!n00b_atomic_load(&io->shutdown) &&
           !n00b_conduit_is_shutdown(io->conduit)) {
        auto poll_r = n00b_conduit_io_poll(io, 1000);
        if (n00b_result_is_err(poll_r)) break;
    }
}

void
n00b_conduit_io_shutdown(n00b_conduit_io_backend_t *io)
{
    if (io) {
        n00b_atomic_store(&io->shutdown, true);
        if (io->ops && io->ops->wake && io->ctx) {
            io->ops->wake(io->ctx);
        }
    }
}

// Process / vnode fire implementations are in proc_lifecycle.c / file_change.c.

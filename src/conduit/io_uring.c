/*
 * io_uring.c - Linux io_uring I/O backend for conduit
 */

#include "conduit/io.h"
#include "conduit/timer.h"
#include "conduit/signal.h"
#include "conduit/user_event.h"
#include "conduit/proc_lifecycle_internal.h"
#include "core/stw.h"

#ifdef __linux__

#include <liburing.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

// ============================================================================
// Entry type and CQE dispatch structures
// ============================================================================

typedef enum {
    URING_ENTRY_FD_POLL,
    URING_ENTRY_TIMER,
    URING_ENTRY_SIGNAL,
    URING_ENTRY_PROC,
    URING_ENTRY_VNODE,
    URING_ENTRY_USER_EVENT,
    URING_ENTRY_WAKE,
} uring_entry_type_t;

typedef struct uring_entry {
    uring_entry_type_t   type;
    int                  backing_fd; // timerfd/signalfd/pidfd/eventfd/-1
    int                  user_fd;    // original FD for FD_POLL, inotify wd for VNODE
    n00b_conduit_io_op_t poll_mask;  // POLLIN/POLLOUT for FD_POLL
    n00b_conduit_io_target_t *target;   // dispatch target for FD_POLL
    union {
        n00b_conduit_timer_t        *timer;
        n00b_conduit_signal_watch_t *signal_watch;
        n00b_conduit_proc_watch_t   *proc_watch;
        n00b_conduit_vnode_watch_t  *vnode_watch;
        n00b_conduit_user_event_t   *user_event;
    };
    struct uring_entry *next;
} uring_entry_t;

// ============================================================================
// Backend context
// ============================================================================

typedef struct {
    struct io_uring  ring;
    n00b_conduit_t  *conduit;
    uring_entry_t   *entries;       // linked list of all registrations
    int              inotify_fd;    // shared inotify instance, -1 if not init
    uring_entry_t   *inotify_entry; // poll entry for inotify_fd
    bool             inotify_registered;
    int              wake_fd;
    uring_entry_t   *wake_entry;
} uring_ctx_t;

// ============================================================================
// Helpers
// ============================================================================

static bool
uring_submit_poll(uring_ctx_t *ctx, uring_entry_t *entry, int fd,
                  short poll_events)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe)
        return false;
    io_uring_prep_poll_multishot(sqe, fd, poll_events);
    io_uring_sqe_set_data(sqe, entry);
    io_uring_submit(&ctx->ring);
    return true;
}

static void
uring_cancel_entry(uring_ctx_t *ctx, uring_entry_t *entry)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe) {
        io_uring_prep_cancel(sqe, entry, 0);
        io_uring_sqe_set_data(sqe, nullptr);
        io_uring_submit(&ctx->ring);
    }
}

static void
uring_unlink_entry(uring_ctx_t *ctx, uring_entry_t *entry)
{
    uring_entry_t **pp = &ctx->entries;
    while (*pp) {
        if (*pp == entry) {
            *pp         = entry->next;
            entry->next = nullptr;
            return;
        }
        pp = &(*pp)->next;
    }
}

static void
uring_signal_restore_mask(n00b_conduit_signal_watch_t *watch)
{
    if (!watch || watch->mask_was_blocked) {
        return;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, watch->signum);
    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
}

// ============================================================================
// Inotify <-> conduit vnode mask conversion
// ============================================================================

static uint32_t
inotify_mask_to_vnode_ops(uint32_t mask)
{
    uint32_t ops = 0;
    if (mask & IN_DELETE_SELF)
        ops |= N00B_CONDUIT_VNODE_DELETE;
    if (mask & IN_MODIFY)
        ops |= N00B_CONDUIT_VNODE_WRITE | N00B_CONDUIT_VNODE_EXTEND;
    if (mask & IN_ATTRIB)
        ops |= N00B_CONDUIT_VNODE_ATTRIB | N00B_CONDUIT_VNODE_LINK;
    if (mask & IN_MOVE_SELF)
        ops |= N00B_CONDUIT_VNODE_RENAME;
    return ops;
}

static uint32_t
vnode_ops_to_inotify_mask(uint32_t ops)
{
    uint32_t mask = 0;
    if (ops & N00B_CONDUIT_VNODE_DELETE)
        mask |= IN_DELETE_SELF;
    if (ops & (N00B_CONDUIT_VNODE_WRITE | N00B_CONDUIT_VNODE_EXTEND))
        mask |= IN_MODIFY;
    if (ops & (N00B_CONDUIT_VNODE_ATTRIB | N00B_CONDUIT_VNODE_LINK))
        mask |= IN_ATTRIB;
    if (ops & N00B_CONDUIT_VNODE_RENAME)
        mask |= IN_MOVE_SELF;
    if (ops & N00B_CONDUIT_VNODE_REVOKE)
        mask |= IN_DELETE_SELF;
    return mask;
}

// ============================================================================
// init / cleanup
// ============================================================================

static void *
uring_init(n00b_conduit_t *c)
{
    n00b_allocator_t *sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;

    uring_ctx_t *ctx = n00b_alloc_with_opts(uring_ctx_t,
                           &(n00b_alloc_opts_t){.allocator = sp});
    if (!ctx)
        return nullptr;

    if (io_uring_queue_init(256, &ctx->ring, 0) < 0) {
        return nullptr;
    }

    ctx->conduit            = c;
    ctx->entries            = nullptr;
    ctx->inotify_fd         = -1;
    ctx->inotify_entry      = nullptr;
    ctx->inotify_registered = false;
    ctx->wake_fd            = -1;
    ctx->wake_entry         = nullptr;

    int wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd >= 0) {
        uring_entry_t *entry = n00b_alloc_with_opts(
            uring_entry_t,
            &(n00b_alloc_opts_t){.allocator = sp});
        if (entry) {
            entry->type       = URING_ENTRY_WAKE;
            entry->backing_fd = wake_fd;
            entry->user_fd    = -1;
            entry->next       = ctx->entries;
            ctx->entries      = entry;
            if (uring_submit_poll(ctx, entry, wake_fd, POLLIN)) {
                ctx->wake_fd    = wake_fd;
                ctx->wake_entry = entry;
            }
            else {
                ctx->entries = entry->next;
                close(wake_fd);
            }
        }
        else {
            close(wake_fd);
        }
    }
    return ctx;
}

static void
uring_cleanup(void *vctx)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx)
        return;

    // Close all backing FDs
    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_SIGNAL && e->signal_watch) {
            uring_signal_restore_mask(e->signal_watch);
        }
        if (e->backing_fd >= 0) {
            close(e->backing_fd);
            e->backing_fd = -1;
        }
    }

    if (ctx->inotify_fd >= 0) {
        close(ctx->inotify_fd);
        ctx->inotify_fd = -1;
    }

    io_uring_queue_exit(&ctx->ring);
}

// ============================================================================
// FD poll: add / modify / remove
// ============================================================================

static bool
uring_add(void *vctx, int fd, n00b_conduit_io_op_t ops,
          n00b_conduit_io_target_t *target)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx)
        return false;

    n00b_allocator_t *_sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uring_entry_t *entry = n00b_alloc_with_opts(uring_entry_t,
                               &(n00b_alloc_opts_t){.allocator = _sp});
    if (!entry)
        return false;

    entry->type       = URING_ENTRY_FD_POLL;
    entry->backing_fd = -1;
    entry->user_fd    = fd;
    entry->poll_mask  = ops;
    entry->target     = target;
    entry->next       = ctx->entries;
    ctx->entries      = entry;

    short poll_events = 0;
    if (ops & N00B_CONDUIT_IO_READ)
        poll_events |= POLLIN;
    if (ops & N00B_CONDUIT_IO_WRITE)
        poll_events |= POLLOUT;

    return uring_submit_poll(ctx, entry, fd, poll_events);
}

static bool
uring_modify(void *vctx, int fd, n00b_conduit_io_op_t ops,
             n00b_conduit_io_target_t *target)
{
    (void)target; // io_uring preserves target via the entry linked list
    uring_ctx_t *ctx = vctx;
    if (!ctx)
        return false;

    // Find existing entry
    uring_entry_t *entry = nullptr;
    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_FD_POLL && e->user_fd == fd) {
            entry = e;
            break;
        }
    }
    if (!entry)
        return false;

    // Cancel existing poll and re-add with new mask
    uring_cancel_entry(ctx, entry);
    entry->poll_mask = ops;

    short poll_events = 0;
    if (ops & N00B_CONDUIT_IO_READ)
        poll_events |= POLLIN;
    if (ops & N00B_CONDUIT_IO_WRITE)
        poll_events |= POLLOUT;

    return uring_submit_poll(ctx, entry, fd, poll_events);
}

static bool
uring_remove(void *vctx, int fd)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx)
        return false;

    uring_entry_t *entry = nullptr;
    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_FD_POLL && e->user_fd == fd) {
            entry = e;
            break;
        }
    }
    if (!entry)
        return false;

    uring_cancel_entry(ctx, entry);
    uring_unlink_entry(ctx, entry);
    return true;
}

// ============================================================================
// wait - CQE dispatch by entry type
// ============================================================================

static int
uring_wait(void *vctx, n00b_conduit_io_event_t *events, int max_events,
           int timeout_ms)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !events || max_events <= 0)
        return -1;

    struct __kernel_timespec  ts;
    struct __kernel_timespec *ts_ptr = nullptr;
    if (timeout_ms >= 0) {
        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        ts_ptr     = &ts;
    }

    struct io_uring_cqe *cqe;
    int                  ret;
    n00b_run_blocking(ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe,
                                                       ts_ptr));
    if (ret == -ETIME || ret == -EINTR)
        return 0;
    if (ret < 0)
        return -1;

    int      event_count = 0;
    unsigned head;
    unsigned count = 0;

    io_uring_for_each_cqe(&ctx->ring, head, cqe)
    {
        count++;
        uring_entry_t *entry = io_uring_cqe_get_data(cqe);
        if (!entry)
            continue; // cancelled SQE

        switch (entry->type) {
        case URING_ENTRY_FD_POLL: {
            if (cqe->res < 0)
                break;
            n00b_conduit_io_op_t ops = 0;
            if (cqe->res & POLLIN)
                ops |= N00B_CONDUIT_IO_READ;
            if (cqe->res & POLLOUT)
                ops |= N00B_CONDUIT_IO_WRITE;
            if (cqe->res & POLLERR)
                ops |= N00B_CONDUIT_IO_ERROR;
            if (cqe->res & POLLHUP)
                ops |= N00B_CONDUIT_IO_HUP;

            if (event_count < max_events && ops) {
                events[event_count].fd        = entry->user_fd;
                events[event_count].ops       = ops;
                events[event_count].topic     = nullptr;
                events[event_count].target    = entry->target;
                event_count++;
            }

            // Re-arm if not multishot continuation
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                short poll_events = 0;
                if (entry->poll_mask & N00B_CONDUIT_IO_READ)
                    poll_events |= POLLIN;
                if (entry->poll_mask & N00B_CONDUIT_IO_WRITE)
                    poll_events |= POLLOUT;
                uring_submit_poll(ctx, entry, entry->user_fd, poll_events);
            }
            break;
        }

        case URING_ENTRY_TIMER: {
            if (entry->backing_fd >= 0 && cqe->res >= 0) {
                uint64_t expirations;
                (void)read(entry->backing_fd, &expirations,
                           sizeof(expirations));
                if (entry->timer && !entry->timer->cancelled) {
                    n00b_conduit_timer_fire(entry->timer);
                }
            }
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uring_submit_poll(ctx, entry, entry->backing_fd, POLLIN);
            }
            break;
        }

        case URING_ENTRY_SIGNAL: {
            if (entry->backing_fd >= 0 && cqe->res >= 0) {
                struct signalfd_siginfo info;
                (void)read(entry->backing_fd, &info, sizeof(info));
                if (entry->signal_watch) {
                    n00b_conduit_signal_fire(entry->signal_watch);
                }
            }
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uring_submit_poll(ctx, entry, entry->backing_fd, POLLIN);
            }
            break;
        }

        case URING_ENTRY_PROC: {
            if (entry->backing_fd >= 0 && entry->proc_watch) {
                // pidfd became readable => process exited.
                // Try waitid for exit status (best-effort -- may fail if
                // already reaped via waitpid).
                siginfo_t info;
                memset(&info, 0, sizeof(info));
                int exit_status = 0;

                if (syscall(SYS_waitid,
                            P_PIDFD,
                            entry->backing_fd,
                            &info,
                            WEXITED | WNOHANG,
                            nullptr)
                        == 0
                    && info.si_pid > 0) {
                    exit_status = n00b_conduit_proc_wait_status_from_siginfo(&info);
                }

                n00b_conduit_proc_fire(entry->proc_watch,
                                       N00B_CONDUIT_PROC_EXIT, exit_status);
            }
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uring_submit_poll(ctx, entry, entry->backing_fd, POLLIN);
            }
            break;
        }

        case URING_ENTRY_VNODE: {
            // inotify fd became readable -- drain all events
            if (ctx->inotify_fd >= 0 && cqe->res >= 0) {
                char buf[4096]
                    __attribute__((aligned(__alignof__(struct inotify_event))));
                ssize_t len;
                while ((len = read(ctx->inotify_fd, buf, sizeof(buf))) > 0) {
                    char *ptr;
                    for (ptr = buf; ptr < buf + len;) {
                        struct inotify_event *ev =
                            (struct inotify_event *)ptr;
                        // Find watch by wd
                        uring_entry_t *ve;
                        for (ve = ctx->entries; ve; ve = ve->next) {
                            if (ve->type == URING_ENTRY_VNODE
                                && ve->user_fd == ev->wd) {
                                uint32_t vops =
                                    inotify_mask_to_vnode_ops(ev->mask);
                                if (vops && ve->vnode_watch) {
                                    n00b_conduit_vnode_fire(ve->vnode_watch,
                                                           vops);
                                }
                                break;
                            }
                        }
                        ptr += sizeof(struct inotify_event) + ev->len;
                    }
                }
            }
            // Re-arm multishot for inotify fd
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uring_submit_poll(ctx, entry, ctx->inotify_fd, POLLIN);
            }
            break;
        }

        case URING_ENTRY_USER_EVENT: {
            if (entry->backing_fd >= 0 && cqe->res >= 0) {
                uint64_t val;
                (void)read(entry->backing_fd, &val, sizeof(val));
                if (entry->user_event) {
                    n00b_conduit_user_event_fire(entry->user_event);
                }
            }
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uring_submit_poll(ctx, entry, entry->backing_fd, POLLIN);
            }
            break;
        }

        case URING_ENTRY_WAKE: {
            if (entry->backing_fd >= 0 && cqe->res >= 0) {
                uint64_t val;
                while (read(entry->backing_fd, &val, sizeof(val)) > 0) {}
            }
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uring_submit_poll(ctx, entry, entry->backing_fd, POLLIN);
            }
            break;
        }
        }
    }

    io_uring_cq_advance(&ctx->ring, count);
    return event_count;
}

static void
uring_wake(void *vctx)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || ctx->wake_fd < 0) {
        return;
    }

    uint64_t val = 1;
    (void)write(ctx->wake_fd, &val, sizeof(val));
}

// ============================================================================
// name
// ============================================================================

static n00b_string_t *
uring_name(void)
{
    return r"io_uring";
}

// ============================================================================
// Timer support
// ============================================================================

static bool
uring_timer_add(void *vctx, n00b_conduit_timer_t *timer)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !timer)
        return false;

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0)
        return false;

    struct itimerspec its = {0};
    its.it_value.tv_sec   = timer->interval_ms / 1000;
    its.it_value.tv_nsec  = (long)(timer->interval_ms % 1000) * 1000000L;
    if (timer->repeating) {
        its.it_interval = its.it_value;
    }

    if (timerfd_settime(tfd, 0, &its, nullptr) < 0) {
        close(tfd);
        return false;
    }

    n00b_allocator_t *_sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uring_entry_t *entry = n00b_alloc_with_opts(uring_entry_t,
                               &(n00b_alloc_opts_t){.allocator = _sp});
    if (!entry) {
        close(tfd);
        return false;
    }

    entry->type       = URING_ENTRY_TIMER;
    entry->backing_fd = tfd;
    entry->user_fd    = -1;
    entry->timer      = timer;
    entry->next       = ctx->entries;
    ctx->entries      = entry;

    return uring_submit_poll(ctx, entry, tfd, POLLIN);
}

static void
uring_timer_remove(void *vctx, n00b_conduit_timer_t *timer)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !timer)
        return;

    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_TIMER && e->timer == timer) {
            uring_cancel_entry(ctx, e);
            if (e->backing_fd >= 0) {
                close(e->backing_fd);
                e->backing_fd = -1;
            }
            uring_unlink_entry(ctx, e);
            timer->cancelled = true;
            return;
        }
    }
}

// ============================================================================
// Signal support
// ============================================================================

static bool
uring_signal_add(void *vctx, n00b_conduit_signal_watch_t *watch)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !watch)
        return false;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, watch->signum);
    sigset_t old_mask;
    if (sigprocmask(SIG_BLOCK, &mask, &old_mask) != 0) {
        return false;
    }
    watch->mask_was_blocked = sigismember(&old_mask, watch->signum) == 1;

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) {
        uring_signal_restore_mask(watch);
        return false;
    }

    n00b_allocator_t *_sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uring_entry_t *entry = n00b_alloc_with_opts(uring_entry_t,
                               &(n00b_alloc_opts_t){.allocator = _sp});
    if (!entry) {
        close(sfd);
        uring_signal_restore_mask(watch);
        return false;
    }

    entry->type         = URING_ENTRY_SIGNAL;
    entry->backing_fd   = sfd;
    entry->user_fd      = watch->signum;
    entry->signal_watch = watch;
    entry->next         = ctx->entries;
    ctx->entries        = entry;

    watch->next = nullptr;

    if (!uring_submit_poll(ctx, entry, sfd, POLLIN)) {
        uring_unlink_entry(ctx, entry);
        close(sfd);
        n00b_free(entry);
        uring_signal_restore_mask(watch);
        return false;
    }

    return true;
}

static void
uring_signal_remove(void *vctx, n00b_conduit_signal_watch_t *watch)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !watch)
        return;

    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_SIGNAL && e->signal_watch == watch) {
            uring_cancel_entry(ctx, e);
            if (e->backing_fd >= 0) {
                close(e->backing_fd);
                e->backing_fd = -1;
            }
            uring_unlink_entry(ctx, e);

            uring_signal_restore_mask(watch);
            return;
        }
    }
}

// ============================================================================
// Process monitoring (pidfd_open via syscall, EXIT only)
// ============================================================================

static bool
uring_proc_add(void *vctx, n00b_conduit_proc_watch_t *watch)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !watch)
        return false;

    int pidfd = (int)syscall(SYS_pidfd_open, watch->pid, 0);
    if (pidfd < 0)
        return false;

    n00b_allocator_t *_sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uring_entry_t *entry = n00b_alloc_with_opts(uring_entry_t,
                               &(n00b_alloc_opts_t){.allocator = _sp});
    if (!entry) {
        close(pidfd);
        return false;
    }

    entry->type       = URING_ENTRY_PROC;
    entry->backing_fd = pidfd;
    entry->user_fd    = -1;
    entry->proc_watch = watch;
    entry->next       = ctx->entries;
    ctx->entries      = entry;

    watch->next = nullptr;

    return uring_submit_poll(ctx, entry, pidfd, POLLIN);
}

static void
uring_proc_remove(void *vctx, n00b_conduit_proc_watch_t *watch)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !watch)
        return;

    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_PROC && e->proc_watch == watch) {
            uring_cancel_entry(ctx, e);
            if (e->backing_fd >= 0) {
                close(e->backing_fd);
                e->backing_fd = -1;
            }
            uring_unlink_entry(ctx, e);
            return;
        }
    }
}

// ============================================================================
// Vnode monitoring (inotify, resolve FD -> path via /proc/self/fd/<n>)
// ============================================================================

static bool
uring_vnode_add(void *vctx, n00b_conduit_vnode_watch_t *watch)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !watch)
        return false;

    // Lazy inotify init
    if (ctx->inotify_fd < 0) {
        ctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (ctx->inotify_fd < 0)
            return false;
    }

    // Resolve FD to path via /proc/self/fd/<n>
    char    proc_path[64];
    char    real_path[4096];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", watch->fd);
    ssize_t len = readlink(proc_path, real_path, sizeof(real_path) - 1);
    if (len < 0)
        return false;
    real_path[len] = '\0';

    uint32_t mask = vnode_ops_to_inotify_mask(watch->ops);
    int      wd   = inotify_add_watch(ctx->inotify_fd, real_path, mask);
    if (wd < 0)
        return false;

    n00b_allocator_t *_sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uring_entry_t *entry = n00b_alloc_with_opts(uring_entry_t,
                               &(n00b_alloc_opts_t){.allocator = _sp});
    if (!entry) {
        inotify_rm_watch(ctx->inotify_fd, wd);
        return false;
    }

    entry->type        = URING_ENTRY_VNODE;
    entry->backing_fd  = -1; // uses shared inotify_fd
    entry->user_fd     = wd; // inotify watch descriptor
    entry->vnode_watch = watch;
    entry->next        = ctx->entries;
    ctx->entries       = entry;

    watch->next = nullptr;

    // Register inotify fd for polling if not already done
    if (!ctx->inotify_registered) {
        n00b_allocator_t *_isp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
        ctx->inotify_entry = n00b_alloc_with_opts(uring_entry_t,
                                 &(n00b_alloc_opts_t){.allocator = _isp});
        if (!ctx->inotify_entry)
            return false;
        ctx->inotify_entry->type        = URING_ENTRY_VNODE;
        ctx->inotify_entry->backing_fd  = -1;
        ctx->inotify_entry->user_fd     = -1; // sentinel: inotify dispatcher
        ctx->inotify_entry->vnode_watch = nullptr;
        ctx->inotify_entry->next        = ctx->entries;
        ctx->entries                     = ctx->inotify_entry;

        uring_submit_poll(ctx, ctx->inotify_entry, ctx->inotify_fd, POLLIN);
        ctx->inotify_registered = true;
    }

    return true;
}

static void
uring_vnode_remove(void *vctx, n00b_conduit_vnode_watch_t *watch)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !watch)
        return;

    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_VNODE && e->vnode_watch == watch) {
            if (ctx->inotify_fd >= 0 && e->user_fd >= 0) {
                inotify_rm_watch(ctx->inotify_fd, e->user_fd);
            }
            uring_unlink_entry(ctx, e);
            return;
        }
    }
}

// ============================================================================
// User events (eventfd)
// ============================================================================

static bool
uring_user_event_add(void *vctx, n00b_conduit_user_event_t *event)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !event)
        return false;

    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (efd < 0)
        return false;

    n00b_allocator_t *_sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    uring_entry_t *entry = n00b_alloc_with_opts(uring_entry_t,
                               &(n00b_alloc_opts_t){.allocator = _sp});
    if (!entry) {
        close(efd);
        return false;
    }

    entry->type       = URING_ENTRY_USER_EVENT;
    entry->backing_fd = efd;
    entry->user_fd    = -1;
    entry->user_event = event;
    entry->next       = ctx->entries;
    ctx->entries      = entry;

    event->next = nullptr;

    return uring_submit_poll(ctx, entry, efd, POLLIN);
}

static void
uring_user_event_remove(void *vctx, n00b_conduit_user_event_t *event)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !event)
        return;

    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_USER_EVENT && e->user_event == event) {
            uring_cancel_entry(ctx, e);
            if (e->backing_fd >= 0) {
                close(e->backing_fd);
                e->backing_fd = -1;
            }
            uring_unlink_entry(ctx, e);
            return;
        }
    }
}

static void
uring_user_event_trigger(void *vctx, n00b_conduit_user_event_t *event)
{
    uring_ctx_t *ctx = vctx;
    if (!ctx || !event)
        return;

    uring_entry_t *e;
    for (e = ctx->entries; e; e = e->next) {
        if (e->type == URING_ENTRY_USER_EVENT && e->user_event
            && e->user_event->event_id == event->event_id) {
            uint64_t val = 1;
            (void)write(e->backing_fd, &val, sizeof(val));
            return;
        }
    }
}

// ============================================================================
// Vtable and accessor
// ============================================================================

static const n00b_conduit_io_ops_t uring_ops = {
    .init               = uring_init,
    .cleanup            = uring_cleanup,
    .add                = uring_add,
    .modify             = uring_modify,
    .remove             = uring_remove,
    .wait               = uring_wait,
    .wake               = uring_wake,
    .name               = uring_name,
    .timer_add          = uring_timer_add,
    .timer_remove       = uring_timer_remove,
    .signal_add         = uring_signal_add,
    .signal_remove      = uring_signal_remove,
    .proc_add           = uring_proc_add,
    .proc_remove        = uring_proc_remove,
    .vnode_add          = uring_vnode_add,
    .vnode_remove       = uring_vnode_remove,
    .user_event_add     = uring_user_event_add,
    .user_event_remove  = uring_user_event_remove,
    .user_event_trigger = uring_user_event_trigger,
};

n00b_result_t(const n00b_conduit_io_ops_t *)
n00b_conduit_io_uring_ops(void)
{
    return n00b_result_ok(const n00b_conduit_io_ops_t *, &uring_ops);
}

#else // !__linux__

n00b_result_t(const n00b_conduit_io_ops_t *)
n00b_conduit_io_uring_ops(void)
{
    return n00b_result_err(const n00b_conduit_io_ops_t *, N00B_CONDUIT_ERR_NOT_SUPPORTED);
}

#endif // __linux__

/**
 * @file io.h
 * @brief Generic I/O backend interface for the conduit system.
 *
 * Defines a backend-agnostic interface for I/O multiplexing.
 * Implementations: kqueue (macOS/BSD), poll (POSIX), epoll (Linux),
 * io_uring (Linux optional), WSAPoll (Windows).
 */
#pragma once

#include "conduit/conduit.h"
#include <sys/types.h>

// ============================================================================
// Forward declarations
// ============================================================================

typedef struct n00b_conduit_io_backend  n00b_conduit_io_backend_t;
typedef struct n00b_conduit_timer       n00b_conduit_timer_t;
typedef struct n00b_conduit_signal_watch n00b_conduit_signal_watch_t;
typedef struct n00b_conduit_proc_watch  n00b_conduit_proc_watch_t;
typedef struct n00b_conduit_vnode_watch n00b_conduit_vnode_watch_t;
typedef struct n00b_conduit_user_event  n00b_conduit_user_event_t;

// ============================================================================
// I/O operations
// ============================================================================

typedef enum {
    N00B_CONDUIT_IO_READ  = (1 << 0),
    N00B_CONDUIT_IO_WRITE = (1 << 1),
    N00B_CONDUIT_IO_ERROR = (1 << 2),
    N00B_CONDUIT_IO_HUP   = (1 << 3),
    N00B_CONDUIT_IO_ALL   = 0x0F,
} n00b_conduit_io_op_t;

// Process event flags (used by kqueue EVFILT_PROC and pidfd backends)
typedef enum {
    N00B_CONDUIT_PROC_EXIT   = (1 << 0),
    N00B_CONDUIT_PROC_FORK   = (1 << 1),
    N00B_CONDUIT_PROC_EXEC   = (1 << 2),
    N00B_CONDUIT_PROC_SIGNAL = (1 << 3),
    N00B_CONDUIT_PROC_ALL    = 0x0F,
} n00b_conduit_proc_op_t;

// Vnode event flags (used by kqueue EVFILT_VNODE and inotify backends)
typedef enum {
    N00B_CONDUIT_VNODE_DELETE  = (1 << 0),
    N00B_CONDUIT_VNODE_WRITE   = (1 << 1),
    N00B_CONDUIT_VNODE_EXTEND  = (1 << 2),
    N00B_CONDUIT_VNODE_ATTRIB  = (1 << 3),
    N00B_CONDUIT_VNODE_LINK    = (1 << 4),
    N00B_CONDUIT_VNODE_RENAME  = (1 << 5),
    N00B_CONDUIT_VNODE_REVOKE  = (1 << 6),
    N00B_CONDUIT_VNODE_FUNLOCK = (1 << 7),
    N00B_CONDUIT_VNODE_ALL     = 0xFF,
} n00b_conduit_vnode_op_t;

typedef struct {
    int                        fd;
    n00b_conduit_io_op_t       ops;
    n00b_conduit_topic_base_t *topic;
    n00b_conduit_io_target_t  *target;
} n00b_conduit_io_event_t;

// ============================================================================
// Backend operations vtable
// ============================================================================

typedef struct n00b_conduit_io_ops {
    void       *(*init)(n00b_conduit_t *c);
    void        (*cleanup)(void *ctx);
    bool        (*add)(void *ctx, int fd, n00b_conduit_io_op_t ops,
                       n00b_conduit_io_target_t *target);
    bool        (*modify)(void *ctx, int fd, n00b_conduit_io_op_t ops,
                         n00b_conduit_io_target_t *target);
    bool        (*remove)(void *ctx, int fd);
    int         (*wait)(void *ctx, n00b_conduit_io_event_t *events,
                        int max_events, int timeout_ms);
    /** @brief Wake a thread currently blocked in @ref wait, if supported. */
    void        (*wake)(void *ctx);
    n00b_string_t *(*name)(void);

    // Optional extended operations.
    bool (*timer_add)(void *ctx, n00b_conduit_timer_t *timer);
    void (*timer_remove)(void *ctx, n00b_conduit_timer_t *timer);
    bool (*signal_add)(void *ctx, n00b_conduit_signal_watch_t *watch);
    void (*signal_remove)(void *ctx, n00b_conduit_signal_watch_t *watch);
    bool (*proc_add)(void *ctx, n00b_conduit_proc_watch_t *watch);
    void (*proc_remove)(void *ctx, n00b_conduit_proc_watch_t *watch);
    bool (*vnode_add)(void *ctx, n00b_conduit_vnode_watch_t *watch);
    void (*vnode_remove)(void *ctx, n00b_conduit_vnode_watch_t *watch);
    bool (*user_event_add)(void *ctx, n00b_conduit_user_event_t *event);
    void (*user_event_remove)(void *ctx, n00b_conduit_user_event_t *event);
    void (*user_event_trigger)(void *ctx, n00b_conduit_user_event_t *event);
} n00b_conduit_io_ops_t;

// ============================================================================
// Process watch (kqueue EVFILT_PROC, Linux pidfd)
// ============================================================================

struct n00b_conduit_proc_watch {
    pid_t                          pid;
    uint32_t                       ops;    /**< N00B_CONDUIT_PROC_* bitmask */
    n00b_conduit_topic_base_t     *topic;
    struct n00b_conduit_proc_watch *next;
};

extern void
n00b_conduit_proc_fire(n00b_conduit_proc_watch_t *watch,
                        uint32_t ops, int exit_status);

// ============================================================================
// Vnode watch (kqueue EVFILT_VNODE, Linux inotify)
// ============================================================================

struct n00b_conduit_vnode_watch {
    int                             fd;
    uint32_t                        ops;   /**< N00B_CONDUIT_VNODE_* bitmask */
    n00b_conduit_topic_base_t      *topic;
    struct n00b_conduit_vnode_watch *next;
};

extern void
n00b_conduit_vnode_fire(n00b_conduit_vnode_watch_t *watch, uint32_t ops);

// ============================================================================
// Backend instance
// ============================================================================

struct n00b_conduit_io_backend {
    n00b_conduit_t              *conduit;
    const n00b_conduit_io_ops_t *ops;
    void                        *ctx;
    _Atomic(bool)                shutdown;
};

// ============================================================================
// Backend registration
// ============================================================================

extern n00b_result_t(const n00b_conduit_io_ops_t *) n00b_conduit_io_kqueue_ops(void);
extern n00b_result_t(const n00b_conduit_io_ops_t *) n00b_conduit_io_poll_ops(void);
extern n00b_result_t(const n00b_conduit_io_ops_t *) n00b_conduit_io_epoll_ops(void);
extern n00b_result_t(const n00b_conduit_io_ops_t *) n00b_conduit_io_uring_ops(void);
extern n00b_result_t(const n00b_conduit_io_ops_t *) n00b_conduit_io_wsa_ops(void);

static inline n00b_result_t(const n00b_conduit_io_ops_t *)
n00b_conduit_io_default_ops(void)
{
#if defined(_WIN32)
    return n00b_conduit_io_wsa_ops();
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return n00b_conduit_io_kqueue_ops();
#elif defined(__linux__)
    return n00b_conduit_io_epoll_ops();
#else
    return n00b_conduit_io_poll_ops();
#endif
}

// ============================================================================
// Lifecycle API
// ============================================================================

extern n00b_result_t(n00b_conduit_io_backend_t *)
n00b_conduit_io_new(n00b_conduit_t *c, const n00b_conduit_io_ops_t *ops);

extern n00b_result_t(n00b_conduit_io_backend_t *)
n00b_conduit_io_new_default(n00b_conduit_t *c);

extern void n00b_conduit_io_destroy(n00b_conduit_io_backend_t *io);

static inline n00b_string_t *
n00b_conduit_io_name(n00b_conduit_io_backend_t *io)
{
    return io && io->ops && io->ops->name
         ? io->ops->name()
         : n00b_string_from_raw("unknown", 7);
}

// ============================================================================
// FD monitoring API
// ============================================================================

extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_io_watch(n00b_conduit_io_backend_t *io, int fd,
                      n00b_conduit_io_op_t ops,
                      n00b_conduit_io_target_t *target);

extern bool n00b_conduit_io_modify(n00b_conduit_io_backend_t *io, int fd,
                                   n00b_conduit_io_op_t ops,
                                   n00b_conduit_io_target_t *target);

extern bool n00b_conduit_io_unwatch(n00b_conduit_io_backend_t *io, int fd);

// ============================================================================
// Event processing API
// ============================================================================

extern n00b_result_t(int) n00b_conduit_io_poll(n00b_conduit_io_backend_t *io, int timeout_ms);
extern void n00b_conduit_io_run(n00b_conduit_io_backend_t *io);
extern void n00b_conduit_io_shutdown(n00b_conduit_io_backend_t *io);

// ============================================================================
// IO event inbox instantiation
// ============================================================================

N00B_CONDUIT_INBOX_IMPL_NO_MSG(n00b_conduit_io_payload_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_conduit_io_payload_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_conduit_io_payload_t);

typedef n00b_conduit_inbox_t(n00b_conduit_io_payload_t) n00b_conduit_io_inbox_t;

#define n00b_conduit_io_subscribe(topic, inbox, ...) \
    n00b_conduit_subscribe(n00b_conduit_io_payload_t, \
                           (n00b_conduit_topic_t(n00b_conduit_io_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

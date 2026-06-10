/**
 * @file service.h
 * @brief Service thread pool for the conduit system.
 *
 * Manages background threads that own IO backends and run poll loops.
 * Each service thread creates its own `n00b_conduit_io_backend_t` —
 * there is no centralized dispatch. The service is a thin lifecycle
 * coordinator; the existing publisher ownership protocol handles all
 * cross-thread coordination.
 *
 * Usage:
 * @code
 *     n00b_result_t(n00b_conduit_service_t *) sr =
 *         n00b_conduit_service_new(c);
 *     n00b_conduit_service_t *svc = n00b_result_get(sr);
 *     n00b_conduit_service_start(svc);
 *     // ... FDs managed via svc thread backends ...
 *     n00b_conduit_service_stop(svc);
 *     n00b_conduit_service_destroy(svc);
 * @endcode
 */
#pragma once

#include "conduit/conduit.h"
#include "conduit/io.h"
#include "core/thread.h"
#include "core/condition.h"

// ============================================================================
// Constants
// ============================================================================

/** @brief Maximum service threads per conduit. */
#define N00B_CONDUIT_MAX_SERVICE_THREADS 16

// ============================================================================
// Service thread roles
// ============================================================================

typedef enum {
    N00B_CONDUIT_SVC_IO,       /**< Runs an IO backend poll loop */
    N00B_CONDUIT_SVC_SIGNAL,   /**< Dedicated signal handler thread */
    N00B_CONDUIT_SVC_WORKER,   /**< Drains the service's job queue */
} n00b_conduit_svc_role_t;

/**
 * @brief Function signature for `n00b_conduit_service_submit` work
 *        items.
 *
 * @param arg  The opaque pointer the caller handed to submit().
 *             The work function owns @p arg's lifetime — the
 *             service does not free it.
 */
typedef void (*n00b_conduit_work_fn)(void *arg);

// ============================================================================
// Service thread
// ============================================================================

typedef struct n00b_conduit_svc_thread {
    n00b_conduit_t              *conduit;
    n00b_conduit_svc_role_t      role;
    n00b_conduit_io_backend_t   *io;        /**< This thread's own backend */
    n00b_thread_t               *thread;    /**< n00b thread handle */
    _Atomic(bool)                stop;      /**< Shutdown flag */
    const char                  *name;      /**< e.g. "io:kqueue", "signal" */
} n00b_conduit_svc_thread_t;

// ============================================================================
// Service pool
// ============================================================================

/* Forward decl for the worker job queue. */
typedef struct n00b_conduit_job n00b_conduit_job_t;

struct n00b_conduit_service {
    n00b_conduit_t              *conduit;
    n00b_conduit_svc_thread_t   *threads[N00B_CONDUIT_MAX_SERVICE_THREADS];
    _Atomic(int)                 num_threads;
    _Atomic(bool)                started;
    _Atomic(bool)                shutdown;

    /* Work-item queue (chunk-5 async dispatcher).  Lazy-init: the
     * first `n00b_conduit_service_submit` call adds a worker thread
     * if none exist yet.  Workers wait on `job_cv`; submit pushes a
     * job + signals.  Drained on stop. */
    n00b_conduit_job_t          *job_head;
    n00b_conduit_job_t          *job_tail;
    n00b_condition_t             job_cv;
    _Atomic(int)                 worker_threads;
};

// ============================================================================
// Result types
// ============================================================================

// ============================================================================
// Service API
// ============================================================================

/**
 * @brief Create a service pool for the conduit.
 *
 * Stored on `conduit->service`. Only one service per conduit.
 */
extern n00b_result_t(n00b_conduit_service_t *)
n00b_conduit_service_new(n00b_conduit_t *c);

/**
 * @brief Start default service threads.
 *
 * Spawns 1 IO thread (platform default backend) and, on Unix,
 * 1 dedicated signal thread.
 */
extern n00b_result_t(bool)
n00b_conduit_service_start(n00b_conduit_service_t *svc);

/**
 * @brief Add an IO thread with a specific backend type.
 *
 * Creates a new `n00b_conduit_io_backend_t` on the thread and starts
 * the poll loop.
 *
 * @param svc Service pool.
 * @param ops IO operations vtable (e.g. `n00b_conduit_io_poll_ops()`).
 * @return Ok(svc_thread) on success.
 */
extern n00b_result_t(n00b_conduit_svc_thread_t *)
n00b_conduit_service_add_io(n00b_conduit_service_t   *svc,
                             const n00b_conduit_io_ops_t *ops);

/**
 * @brief Signal all service threads to stop and join them.
 *
 * Worker threads stop accepting new submissions once shutdown begins, but
 * drain work that was already queued before they exit.
 */
extern void
n00b_conduit_service_stop(n00b_conduit_service_t *svc);

/**
 * @brief Destroy the service pool and release resources.
 *
 * Calls `n00b_conduit_service_stop` if not already stopped.
 */
extern void
n00b_conduit_service_destroy(n00b_conduit_service_t *svc);

/**
 * @brief Get a service thread's IO backend.
 * @return Some(io) if the thread has a backend, None otherwise.
 */
static inline n00b_option_t(n00b_conduit_io_backend_t *)
n00b_conduit_svc_thread_io(n00b_conduit_svc_thread_t *st)
{
    if (!st) return n00b_option_none(n00b_conduit_io_backend_t *);
    return n00b_option_from_nullable(n00b_conduit_io_backend_t *, st->io);
}

/**
 * @brief Submit a work item for execution on a worker thread.
 *
 * The first call lazy-spawns a single worker thread; subsequent
 * calls reuse it.  Use `n00b_conduit_service_add_worker` to bring
 * up additional workers when concurrency demands it.
 *
 * Work items run in FIFO order.  Each work item is fire-and-forget:
 * @p fn is responsible for any synchronization back to the caller
 * (typically by writing into a result struct + signaling a
 * condition variable, or by publishing on a conduit topic).
 *
 * @param svc Service pool.  Must be `start`-ed.
 * @param fn  Work function.  Required.
 * @param arg Opaque argument.  Borrowed; @p fn owns lifetime.
 *
 * @return Ok(true) on success.  Err on null args, on @p svc not
 *         started, or when worker spawn fails.
 */
extern n00b_result_t(bool)
n00b_conduit_service_submit(n00b_conduit_service_t *svc,
                            n00b_conduit_work_fn    fn,
                            void                   *arg);

/**
 * @brief Add an additional worker thread to the service.
 *
 * Workers share the job queue; multiple workers run jobs in
 * parallel.  Returns Ok(svc_thread) on success.
 */
extern n00b_result_t(n00b_conduit_svc_thread_t *)
n00b_conduit_service_add_worker(n00b_conduit_service_t *svc);

/**
 * @brief Get the default IO service thread.
 *
 * Returns the first IO-role thread, which is created by
 * `n00b_conduit_service_start`.
 *
 * @return Some(svc_thread) or None if no IO threads exist.
 */
static inline n00b_option_t(n00b_conduit_svc_thread_t *)
n00b_conduit_service_default_io(n00b_conduit_service_t *svc)
{
    if (!svc) return n00b_option_none(n00b_conduit_svc_thread_t *);

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *st = svc->threads[i];
        if (st && st->role == N00B_CONDUIT_SVC_IO) {
            return n00b_option_set(n00b_conduit_svc_thread_t *, st);
        }
    }
    return n00b_option_none(n00b_conduit_svc_thread_t *);
}

/**
 * @brief Get the dedicated signal service thread.
 *
 * Returns None on platforms or service configurations that do not create a
 * signal-role thread.
 */
static inline n00b_option_t(n00b_conduit_svc_thread_t *)
n00b_conduit_service_signal_io(n00b_conduit_service_t *svc)
{
    if (!svc) return n00b_option_none(n00b_conduit_svc_thread_t *);

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *st = svc->threads[i];
        if (st && st->role == N00B_CONDUIT_SVC_SIGNAL) {
            return n00b_option_set(n00b_conduit_svc_thread_t *, st);
        }
    }
    return n00b_option_none(n00b_conduit_svc_thread_t *);
}

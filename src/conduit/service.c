/*
 * service.c — Service thread pool implementation.
 *
 * Each service thread owns its own IO backend and runs a poll loop.
 * The service is a thin lifecycle coordinator; no centralized dispatch.
 */

#define __N00B_THREAD_INTERNAL

#include "conduit/service.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/condition.h"
#include <string.h>

/* Internal job-queue types — declared opaque in the header so
 * service.h doesn't pull in private layout. */
struct n00b_conduit_job {
    n00b_conduit_work_fn  fn;
    void                 *arg;
    struct n00b_conduit_job *next;
};

// ============================================================================
// Thread entry points
// ============================================================================

static void *
io_thread_loop(void *raw)
{
    n00b_conduit_svc_thread_t *st = raw;

    // The dedicated signal thread does double-duty as the reaper's PROMPT
    // backstop (WP-3a Phase 2, D-034): each poll iteration it sweeps the
    // reap-pending queue so unheld detached workers are reclaimed without
    // waiting for the next spawn.  The IO role keeps to its own duties.  The
    // sweep is bounded (one queue walk) and reclaims only OS-confirmed-dead
    // workers, so it cannot starve the poll loop.
    bool is_signal = (st->role == N00B_CONDUIT_SVC_SIGNAL);

    while (!n00b_atomic_load(&st->stop) &&
           !n00b_conduit_is_shutdown(st->conduit)) {
        (void)n00b_conduit_io_poll(st->io, 500);
        if (is_signal) {
            n00b_thread_reap_pending();
        }
    }

    return nullptr;
}

/* Pop the head of @p svc's job queue.  Caller must hold the
 * job_cv lock.  Returns nullptr when the queue is empty. */
static n00b_conduit_job_t *
worker_pop(n00b_conduit_service_t *svc)
{
    n00b_conduit_job_t *j = svc->job_head;
    if (!j) return nullptr;
    svc->job_head = j->next;
    if (!svc->job_head) svc->job_tail = nullptr;
    j->next = nullptr;
    return j;
}

static void *
worker_thread_loop(void *raw)
{
    n00b_conduit_svc_thread_t *st  = raw;
    n00b_conduit_service_t    *svc = st->conduit->service;

    while (true) {
        n00b_conduit_job_t *job = nullptr;

        n00b_condition_lock(&svc->job_cv);
        while (!svc->job_head
               && !n00b_atomic_load(&st->stop)
               && !n00b_conduit_is_shutdown(st->conduit)) {
            /* 500ms safety net so a stop request that races with the
             * predicate check still wakes the worker reasonably soon. */
            n00b_condition_wait(&svc->job_cv,
                                .timeout_ms = 500);
        }
        if (n00b_atomic_load(&st->stop)
            || n00b_conduit_is_shutdown(st->conduit)) {
            n00b_condition_unlock(&svc->job_cv);
            break;
        }
        job = worker_pop(svc);
        n00b_condition_unlock(&svc->job_cv);

        if (job && job->fn) {
            job->fn(job->arg);
        }
    }
    return nullptr;
}

// ============================================================================
// Internal helpers
// ============================================================================

static n00b_result_t(n00b_conduit_svc_thread_t *)
add_thread(n00b_conduit_service_t      *svc,
           n00b_conduit_svc_role_t      role,
           const n00b_conduit_io_ops_t *ops,
           const char                  *name)
{
    int n = n00b_atomic_load(&svc->num_threads);
    if (n >= N00B_CONDUIT_MAX_SERVICE_THREADS) {
        return n00b_result_err(n00b_conduit_svc_thread_t *, N00B_CONDUIT_ERR_REGISTRY_FULL);
    }

    // Create the thread's own IO backend.
    n00b_result_t(n00b_conduit_io_backend_t *) io_res = n00b_conduit_io_new(svc->conduit, ops);
    if (n00b_result_is_err(io_res)) {
        return n00b_result_err(n00b_conduit_svc_thread_t *, n00b_result_get_err(io_res));
    }
    n00b_conduit_io_backend_t *io = n00b_result_get(io_res);

    n00b_conduit_svc_thread_t *st = n00b_alloc_with_opts(n00b_conduit_svc_thread_t,
                                        &(n00b_alloc_opts_t){.allocator = svc->conduit->allocator});
    if (!st) {
        n00b_conduit_io_destroy(io);
        return n00b_result_err(n00b_conduit_svc_thread_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    st->conduit = svc->conduit;
    st->role    = role;
    st->io      = io;
    st->name    = name;
    n00b_atomic_store(&st->stop, false);

    // CAS loop to claim a slot.
    while (1) {
        n = n00b_atomic_load(&svc->num_threads);
        if (n >= N00B_CONDUIT_MAX_SERVICE_THREADS) {
            n00b_conduit_io_destroy(io);
            return n00b_result_err(n00b_conduit_svc_thread_t *, N00B_CONDUIT_ERR_REGISTRY_FULL);
        }
        int expected = n;
        if (n00b_atomic_cas(&svc->num_threads, &expected, n + 1)) {
            svc->threads[n] = st;
            break;
        }
    }

    // Spawn the thread.
    auto spawn_r = n00b_thread_spawn(io_thread_loop, st);
    if (n00b_result_is_err(spawn_r)) {
        svc->threads[n] = nullptr;
        n00b_atomic_add(&svc->num_threads, -1);
        n00b_conduit_io_destroy(io);
        return n00b_result_err(n00b_conduit_svc_thread_t *, N00B_CONDUIT_ERR_ALLOC);
    }
    st->thread = n00b_result_get(spawn_r);

    return n00b_result_ok(n00b_conduit_svc_thread_t *, st);
}

// ============================================================================
// Service lifecycle
// ============================================================================

n00b_result_t(n00b_conduit_service_t *)
n00b_conduit_service_new(n00b_conduit_t *c)
{
    if (!c) {
        return n00b_result_err(n00b_conduit_service_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (c->service) {
        return n00b_result_ok(n00b_conduit_service_t *, c->service);
    }

    n00b_conduit_service_t *svc = n00b_alloc_with_opts(n00b_conduit_service_t,
                                      &(n00b_alloc_opts_t){.allocator = c->allocator});
    if (!svc) {
        return n00b_result_err(n00b_conduit_service_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    svc->conduit = c;
    n00b_atomic_store(&svc->num_threads, 0);
    n00b_atomic_store(&svc->started, false);
    n00b_atomic_store(&svc->shutdown, false);
    n00b_atomic_store(&svc->worker_threads, 0);
    svc->job_head = nullptr;
    svc->job_tail = nullptr;
    n00b_condition_init(&svc->job_cv);

    for (int i = 0; i < N00B_CONDUIT_MAX_SERVICE_THREADS; i++) {
        svc->threads[i] = nullptr;
    }

    c->service = svc;
    return n00b_result_ok(n00b_conduit_service_t *, svc);
}

n00b_result_t(bool)
n00b_conduit_service_start(n00b_conduit_service_t *svc)
{
    if (!svc) {
        return n00b_result_err(bool, N00B_CONDUIT_ERR_NULL_ARG);
    }

    bool expected = false;
    if (!n00b_atomic_cas(&svc->started, &expected, true)) {
        // Already started.
        return n00b_result_ok(bool, true);
    }

    // Add default IO thread.
    auto ops_r = n00b_conduit_io_default_ops();
    if (n00b_result_is_err(ops_r)) {
        n00b_atomic_store(&svc->started, false);
        return n00b_result_err(bool, n00b_result_get_err(ops_r));
    }
    const n00b_conduit_io_ops_t *ops = n00b_result_get(ops_r);
    n00b_string_t *io_name = ops->name ? ops->name() : r"io";

    // Build a descriptive name: "io:<backend_name>"
    size_t name_len = 3 + io_name->u8_bytes + 1;
    char *name_buf = n00b_alloc_array_with_opts(char, name_len,
                         &(n00b_alloc_opts_t){.allocator = svc->conduit->allocator});
    memcpy(name_buf, "io:", 3);
    memcpy(name_buf + 3, io_name->data, io_name->u8_bytes);
    name_buf[3 + io_name->u8_bytes] = '\0';

    n00b_result_t(n00b_conduit_svc_thread_t *) io_res =
        add_thread(svc, N00B_CONDUIT_SVC_IO, ops, name_buf);
    if (n00b_result_is_err(io_res)) {
        n00b_atomic_store(&svc->started, false);
        return n00b_result_err(bool, n00b_result_get_err(io_res));
    }

#ifndef _WIN32
    // Add dedicated signal thread (uses same backend type — the IO
    // loop only has signal watches registered, no FDs).
    n00b_result_t(n00b_conduit_svc_thread_t *) sig_res =
        add_thread(svc, N00B_CONDUIT_SVC_SIGNAL, ops, "signal");
    if (n00b_result_is_err(sig_res)) {
        // Non-fatal: IO thread is still running.
        // Signal handling falls back to the main IO thread.
    }
#endif

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_conduit_svc_thread_t *)
n00b_conduit_service_add_io(n00b_conduit_service_t   *svc,
                             const n00b_conduit_io_ops_t *ops)
{
    if (!svc || !ops) {
        return n00b_result_err(n00b_conduit_svc_thread_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_string_t *io_name = ops->name ? ops->name() : n00b_string_from_raw("io", 2);
    size_t name_len = 3 + io_name->u8_bytes + 1;
    char *name_buf = n00b_alloc_array_with_opts(char, name_len,
                         &(n00b_alloc_opts_t){.allocator = svc->conduit->allocator});
    memcpy(name_buf, "io:", 3);
    memcpy(name_buf + 3, io_name->data, io_name->u8_bytes);
    name_buf[3 + io_name->u8_bytes] = '\0';

    return add_thread(svc, N00B_CONDUIT_SVC_IO, ops, name_buf);
}

n00b_result_t(n00b_conduit_svc_thread_t *)
n00b_conduit_service_add_worker(n00b_conduit_service_t *svc)
{
    if (!svc) {
        return n00b_result_err(n00b_conduit_svc_thread_t *,
                               N00B_CONDUIT_ERR_NULL_ARG);
    }

    int n = n00b_atomic_load(&svc->num_threads);
    if (n >= N00B_CONDUIT_MAX_SERVICE_THREADS) {
        return n00b_result_err(n00b_conduit_svc_thread_t *,
                               N00B_CONDUIT_ERR_REGISTRY_FULL);
    }

    /* Workers don't own an IO backend.  Allocate the thread record
     * directly without going through `add_thread`. */
    n00b_conduit_svc_thread_t *st = n00b_alloc_with_opts(
        n00b_conduit_svc_thread_t,
        &(n00b_alloc_opts_t){.allocator = svc->conduit->allocator});
    st->conduit = svc->conduit;
    st->role    = N00B_CONDUIT_SVC_WORKER;
    st->io      = nullptr;
    st->name    = "worker";
    n00b_atomic_store(&st->stop, false);

    while (1) {
        n = n00b_atomic_load(&svc->num_threads);
        if (n >= N00B_CONDUIT_MAX_SERVICE_THREADS) {
            return n00b_result_err(n00b_conduit_svc_thread_t *,
                                   N00B_CONDUIT_ERR_REGISTRY_FULL);
        }
        int expected = n;
        if (n00b_atomic_cas(&svc->num_threads, &expected, n + 1)) {
            svc->threads[n] = st;
            break;
        }
    }

    auto sr = n00b_thread_spawn(worker_thread_loop, st);
    if (n00b_result_is_err(sr)) {
        svc->threads[n] = nullptr;
        n00b_atomic_add(&svc->num_threads, -1);
        return n00b_result_err(n00b_conduit_svc_thread_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }
    st->thread = n00b_result_get(sr);
    n00b_atomic_add(&svc->worker_threads, 1);

    return n00b_result_ok(n00b_conduit_svc_thread_t *, st);
}

n00b_result_t(bool)
n00b_conduit_service_submit(n00b_conduit_service_t *svc,
                            n00b_conduit_work_fn    fn,
                            void                   *arg)
{
    if (!svc || !fn) {
        return n00b_result_err(bool, N00B_CONDUIT_ERR_NULL_ARG);
    }

    /* Lazy-spawn the first worker on demand. */
    if (n00b_atomic_load(&svc->worker_threads) == 0) {
        auto wr = n00b_conduit_service_add_worker(svc);
        if (n00b_result_is_err(wr)) {
            return n00b_result_err(bool, n00b_result_get_err(wr));
        }
    }

    n00b_conduit_job_t *job = n00b_alloc_with_opts(
        n00b_conduit_job_t,
        &(n00b_alloc_opts_t){.allocator = svc->conduit->allocator});
    job->fn   = fn;
    job->arg  = arg;
    job->next = nullptr;

    n00b_condition_lock(&svc->job_cv);
    if (svc->job_tail) {
        svc->job_tail->next = job;
    } else {
        svc->job_head = job;
    }
    svc->job_tail = job;
    /* Wake exactly one waiter — preserves ordering and avoids the
     * thundering-herd that notify_all causes when multiple workers
     * race for one item. */
    n00b_condition_notify(&svc->job_cv, .auto_unlock = true);

    return n00b_result_ok(bool, true);
}

void
n00b_conduit_service_stop(n00b_conduit_service_t *svc)
{
    if (!svc) return;

    bool expected = false;
    if (!n00b_atomic_cas(&svc->shutdown, &expected, true)) {
        return; // Already shutting down.
    }

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *st = svc->threads[i];
        if (st) {
            n00b_atomic_store(&st->stop, true);
            if (st->io) {
                n00b_conduit_io_shutdown(st->io);
            }
        }
    }

    /* Wake any sleeping workers so they observe the stop flag. */
    n00b_condition_lock(&svc->job_cv);
    n00b_condition_notify(&svc->job_cv,
                          .all = true, .auto_unlock = true);

    // Join all threads.
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *st = svc->threads[i];
        if (st && st->thread) {
            n00b_thread_join(st->thread);
            st->thread = nullptr;
        }
    }
}

void
n00b_conduit_service_destroy(n00b_conduit_service_t *svc)
{
    if (!svc) return;

    if (!n00b_atomic_load(&svc->shutdown)) {
        n00b_conduit_service_stop(svc);
    }

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *st = svc->threads[i];
        if (st && st->io) {
            n00b_conduit_io_destroy(st->io);
            st->io = nullptr;
        }
        svc->threads[i] = nullptr;
    }

    n00b_atomic_store(&svc->num_threads, 0);
    n00b_atomic_store(&svc->started, false);
    n00b_atomic_store(&svc->shutdown, false);

    if (svc->conduit) {
        svc->conduit->service = nullptr;
    }
}

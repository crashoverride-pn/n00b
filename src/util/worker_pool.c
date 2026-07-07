/* src/util/worker_pool.c — bounded worker pool implementation.
 *
 * Single condition variable, two predicates:
 *   - workers wake when (len > 0) or shutdown
 *   - producers wake when (len < cap) or shutdown
 *
 * One CV with `notify_all` on every state change keeps the
 * synchronization simple; the pool is intended for moderate worker
 * counts (1-256 in the SKP ingestion case) where the cost of
 * spurious wakeups is irrelevant.
 *
 * Threads are spawned via `n00b_thread_spawn` so the runtime
 * registers each one for stop-the-world participation. The pool
 * struct itself lives in the n00b GC heap; workers hold a
 * `n00b_worker_pool_t *` for the duration of the thread.
 */

#include "n00b.h"
#include "util/worker_pool.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/condition.h"
#include "core/thread.h"

struct n00b_worker_pool_t {
    int32_t           size;
    n00b_thread_t   **threads;
    n00b_condition_t  work_cv;
    bool              shutdown;
    /* Bounded ring of job pointers. */
    void            **queue;
    int32_t           cap;
    int32_t           head;
    int32_t           tail;
    int32_t           len;
    int32_t           in_flight;
    n00b_worker_fn_t  fn;
    void             *user_data;
    bool              worker_scratch_arena;
    // Registry of the per-worker scratch arenas (worker_scratch_arena pools),
    // so a caller can reset them all at a batch boundary via
    // n00b_worker_pool_reset_scratch. Each worker appends its arena at startup
    // via an atomic bump into worker_arenas[0..worker_arena_count).
    n00b_arena_t    **worker_arenas;
    _Atomic int32_t   worker_arena_count;
};

static void *
worker_thread_fn(void *arg)
{
    n00b_worker_pool_t *pool = arg;

    // Optional per-worker bump-arena scratch (opt-in via .worker_scratch_arena).
    // Created once at worker startup and installed as this thread's
    // current_allocator for the worker's lifetime; job callbacks reset it
    // (n00b_arena_reset) per job rather than creating/destroying an allocator
    // per item. Inline headers (not OOB) keep allocations self-describing for
    // find_alloc_info without the per-alloc metadata dict + STW read-lock; not
    // GC'd (reset reclaims wholesale); hidden (opaque scratch, never scanned).
    n00b_arena_t     *scratch      = nullptr;
    n00b_allocator_t *scratch_prev = nullptr;
    if (pool->worker_scratch_arena) {
        scratch      = n00b_new_arena(.use_gc         = false,
                                      .hidden         = true,
                                      .inline_headers = true,
                                      .name           = "n00b_worker_scratch");
        scratch_prev = n00b_set_current_allocator((n00b_allocator_t *)scratch);
        // Publish this worker's arena so the batch owner can reset it at a
        // batch boundary (n00b_worker_pool_reset_scratch). worker_arenas is
        // sized `size`; each worker claims a distinct slot.
        int32_t slot = atomic_fetch_add(&pool->worker_arena_count, 1);
        pool->worker_arenas[slot] = scratch;
    }

    while (true) {
        n00b_condition_lock(&pool->work_cv);
        while (pool->len == 0 && !pool->shutdown) {
            n00b_condition_wait(&pool->work_cv);
        }
        if (pool->shutdown && pool->len == 0) {
            n00b_condition_unlock(&pool->work_cv);
            break;
        }
        void *job = pool->queue[pool->head];
        pool->queue[pool->head] = nullptr;
        pool->head = (pool->head + 1) % pool->cap;
        pool->len -= 1;
        pool->in_flight += 1;
        /* Wake any producer waiting for space. */
        n00b_condition_notify(&pool->work_cv, .all = true);
        n00b_condition_unlock(&pool->work_cv);

        if (pool->fn) {
            pool->fn(job, pool->user_data);
        }

        n00b_condition_lock(&pool->work_cv);
        pool->in_flight -= 1;
        n00b_condition_notify(&pool->work_cv, .all = true);
        n00b_condition_unlock(&pool->work_cv);
    }

    // Tear down the per-worker scratch arena (restore the prior current
    // allocator first so nothing on the exit path touches the freed arena).
    if (scratch != nullptr) {
        n00b_set_current_allocator(scratch_prev);
        n00b_allocator_destroy((n00b_allocator_t *)scratch);
    }
    return nullptr;
}

n00b_worker_pool_t *
n00b_worker_pool_new(int32_t          size,
                     int32_t          cap,
                     n00b_worker_fn_t fn,
                     void            *user_data) _kargs {
    n00b_allocator_t *allocator = nullptr;
    bool              worker_scratch_arena = false;
}
{
    if (size <= 0 || cap <= 0 || !fn) {
        return nullptr;
    }
    n00b_worker_pool_t *pool = n00b_alloc(n00b_worker_pool_t,
                                          N00B_ALLOC_OPTS(allocator));
    pool->size                 = size;
    pool->cap                  = cap;
    pool->head                 = 0;
    pool->tail                 = 0;
    pool->len                  = 0;
    pool->in_flight            = 0;
    pool->shutdown             = false;
    pool->fn                   = fn;
    pool->user_data            = user_data;
    pool->worker_scratch_arena = worker_scratch_arena;
    pool->queue     = n00b_alloc_array(void *, cap, N00B_ALLOC_OPTS(allocator));
    pool->threads   = n00b_alloc_array(n00b_thread_t *, size,
                                       N00B_ALLOC_OPTS(allocator));
    pool->worker_arenas = worker_scratch_arena
                              ? n00b_alloc_array(n00b_arena_t *, size,
                                                 N00B_ALLOC_OPTS(allocator))
                              : nullptr;
    atomic_store(&pool->worker_arena_count, 0);
    n00b_condition_init(&pool->work_cv);

    for (int32_t i = 0; i < size; i++) {
        auto sp = n00b_thread_spawn(worker_thread_fn, pool);
        if (n00b_result_is_err(sp)) {
            /* Tear down the partially-built pool: signal what we
             * have, join those threads, return failure. */
            n00b_condition_lock(&pool->work_cv);
            pool->shutdown = true;
            n00b_condition_notify(&pool->work_cv, .all = true);
            n00b_condition_unlock(&pool->work_cv);
            for (int32_t j = 0; j < i; j++) {
                n00b_thread_join(pool->threads[j]);
            }
            return nullptr;
        }
        pool->threads[i] = n00b_result_get(sp);
    }
    return pool;
}

void
n00b_worker_pool_submit(n00b_worker_pool_t *pool, void *job)
{
    if (!pool) {
        return;
    }
    n00b_condition_lock(&pool->work_cv);
    while (pool->len == pool->cap && !pool->shutdown) {
        n00b_condition_wait(&pool->work_cv);
    }
    if (pool->shutdown) {
        n00b_condition_unlock(&pool->work_cv);
        return;
    }
    pool->queue[pool->tail] = job;
    pool->tail = (pool->tail + 1) % pool->cap;
    pool->len += 1;
    n00b_condition_notify(&pool->work_cv, .all = true);
    n00b_condition_unlock(&pool->work_cv);
}

void
n00b_worker_pool_shutdown(n00b_worker_pool_t *pool)
{
    if (!pool) {
        return;
    }
    n00b_condition_lock(&pool->work_cv);
    pool->shutdown = true;
    n00b_condition_notify(&pool->work_cv, .all = true);
    n00b_condition_unlock(&pool->work_cv);
    for (int32_t i = 0; i < pool->size; i++) {
        n00b_thread_join(pool->threads[i]);
    }
}

void
n00b_worker_pool_reset_scratch(n00b_worker_pool_t *pool)
{
    if (pool == nullptr || pool->worker_arenas == nullptr) {
        return;
    }
    // Reset every worker's scratch arena (bump pointer rewound + zeroed) to
    // reclaim a batch's worth of transient allocations. Safe only when the
    // workers are idle w.r.t. these arenas -- callers invoke this at a batch
    // boundary where a latch/shutdown has already joined all in-flight jobs.
    int32_t n = atomic_load(&pool->worker_arena_count);
    for (int32_t i = 0; i < n; i++) {
        if (pool->worker_arenas[i] != nullptr) {
            n00b_arena_reset(pool->worker_arenas[i]);
        }
    }
}

int32_t
n00b_worker_pool_pending(n00b_worker_pool_t *pool)
{
    if (!pool) {
        return 0;
    }
    n00b_condition_lock(&pool->work_cv);
    int32_t v = pool->len;
    n00b_condition_unlock(&pool->work_cv);
    return v;
}

int32_t
n00b_worker_pool_in_flight(n00b_worker_pool_t *pool)
{
    if (!pool) {
        return 0;
    }
    n00b_condition_lock(&pool->work_cv);
    int32_t v = pool->in_flight;
    n00b_condition_unlock(&pool->work_cv);
    return v;
}

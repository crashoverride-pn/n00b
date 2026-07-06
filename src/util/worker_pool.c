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
};

static void *
worker_thread_fn(void *arg)
{
    n00b_worker_pool_t *pool = arg;
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
    return nullptr;
}

n00b_worker_pool_t *
n00b_worker_pool_new(int32_t          size,
                     int32_t          cap,
                     n00b_worker_fn_t fn,
                     void            *user_data) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (size <= 0 || cap <= 0 || !fn) {
        return nullptr;
    }
    n00b_worker_pool_t *pool = n00b_alloc(n00b_worker_pool_t,
                                          N00B_ALLOC_OPTS(allocator));
    pool->size      = size;
    pool->cap       = cap;
    pool->head      = 0;
    pool->tail      = 0;
    pool->len       = 0;
    pool->in_flight = 0;
    pool->shutdown  = false;
    pool->fn        = fn;
    pool->user_data = user_data;
    pool->queue     = n00b_alloc_array(void *, cap, N00B_ALLOC_OPTS(allocator));
    pool->threads   = n00b_alloc_array(n00b_thread_t *, size,
                                       N00B_ALLOC_OPTS(allocator));
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

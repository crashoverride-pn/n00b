/**
 * @file util/worker_pool.h
 * @brief Bounded worker pool — generic producer/consumer primitive.
 *
 * A thread pool with a fixed worker count and a bounded ring of
 * pending jobs. Producers call `n00b_worker_pool_submit` from any
 * thread; workers pop jobs and invoke the caller's
 * `n00b_worker_fn_t`. Backpressure is built in: `_submit` blocks
 * when the ring is full, and workers block when the ring is empty.
 *
 * Lifecycle:
 *   - `n00b_worker_pool_new(size, cap, fn, user)` spawns `size`
 *     worker threads and arms the ring with capacity `cap`.
 *   - Per-job state should be heap-allocated (`n00b_alloc(T)`) by
 *     the producer so the GC tracks it; the pool stores `void *`
 *     entries and never copies job bytes itself.
 *   - `n00b_worker_pool_shutdown(pool)` signals every worker to
 *     exit after already-submitted work drains, then joins all
 *     threads.
 *
 * Per D-002 (substrate placement): this lives in n00b/util rather
 * than in any single consumer, because the producer-consumer pattern
 * with bounded backpressure has broad value across the n00b
 * ecosystem (SKP's ingestion worker is the first consumer; future
 * services slot in identically).
 */
#pragma once

#include "n00b.h"
#include "adt/result.h"
#include "core/alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct n00b_worker_pool_t n00b_worker_pool_t;

/**
 * @brief Worker callback shape.
 *
 * @param job        Pointer the producer handed to `_submit`. The
 *                   pool itself does nothing with it; ownership is
 *                   purely between the producer and the callback.
 * @param user_data  Static state pointer passed at pool creation.
 */
typedef void (*n00b_worker_fn_t)(void *job, void *user_data);

/**
 * @brief Allocate + start a worker pool.
 *
 * @param size       Worker thread count (>= 1).
 * @param cap        Pending-job ring capacity (>= 1).
 * @param fn         Per-job callback invoked on a pool thread.
 * @param user_data  Opaque state forwarded to every `fn` invocation.
 * @return           A live pool or `nullptr` on argument / spawn
 *                   failure. Callers shut down via
 *                   `n00b_worker_pool_shutdown` before drop.
 */
extern n00b_worker_pool_t *
n00b_worker_pool_new(int32_t          size,
                     int32_t          cap,
                     n00b_worker_fn_t fn,
                     void            *user_data) _kargs {
    n00b_allocator_t *allocator = nullptr;
    // When true, each worker thread creates its own bump-arena scratch at
    // startup and installs it as that thread's current_allocator for the
    // worker's lifetime (torn down at worker exit). Job callbacks that want a
    // transient per-item scratch reset it (n00b_arena_reset) at the top of each
    // job instead of creating/destroying an allocator per item -- avoiding
    // per-item mmap-registry churn. Only enable for pools whose jobs treat the
    // default allocator as per-job scratch (they must not retain allocations
    // made from it across jobs).
    bool worker_scratch_arena = false;
};

/**
 * @brief Submit one job to the pool, blocking when the ring is full.
 *
 * @p job is opaque to the pool — it is passed verbatim to the
 * worker callback. Producers typically `n00b_alloc(T)` a job
 * struct and pass the resulting pointer.
 */
extern void
n00b_worker_pool_submit(n00b_worker_pool_t *pool, void *job);

/**
 * @brief Reset every worker's per-worker scratch arena (bump pointer rewound +
 *        zeroed), for pools created with `.worker_scratch_arena = true`.
 *
 * Reclaims a batch's worth of transient per-worker allocations without
 * destroying the arenas (no per-item pool churn). MUST be called only at a
 * point where all in-flight jobs are joined (e.g. after a latch wait /
 * shutdown), since it mutates arenas the workers otherwise allocate from.
 * No-op for pools without per-worker scratch arenas.
 */
extern void
n00b_worker_pool_reset_scratch(n00b_worker_pool_t *pool);

/**
 * @brief Signal every worker to exit, then join. After this returns
 *        the pool is no longer usable.
 */
extern void n00b_worker_pool_shutdown(n00b_worker_pool_t *pool);

/** @brief Current pending-job count (for diagnostics / tests). */
extern int32_t n00b_worker_pool_pending(n00b_worker_pool_t *pool);

/** @brief Current in-flight (callback-running) job count. */
extern int32_t n00b_worker_pool_in_flight(n00b_worker_pool_t *pool);

#ifdef __cplusplus
}
#endif

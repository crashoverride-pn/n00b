/*
 * test_rwlock_contention.c — Minimal repro for the rwlock deadlock
 * surfaced while wiring locking into the HTTP connection pool.
 *
 * Hypothesis: mixed reader/writer traffic on n00b_rwlock_t deadlocks
 * deterministically within tens of iterations on 4 threads.
 *
 * This test deliberately uses the rwlock directly with NO pool / NO
 * GC-allocated origins / NO containers — just a stack-allocated lock
 * and a shared counter — so any deadlock we see is purely a rwlock
 * problem.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/data_lock.h"
#include "core/rwlock.h"
#include "core/thread.h"
#include "core/stw.h"

static n00b_rwlock_t *g_lock;
static _Atomic int    g_writes;
static _Atomic int    g_reads;

#define THREADS 4
#define ITERS   200

static void *
mixed_worker(void *arg)
{
    intptr_t id = (intptr_t)arg;
    for (int i = 0; i < ITERS; i++) {
        /* Half write, half read. */
        if ((i + (int)id) & 1) {
            n00b_data_write_lock(g_lock);
            atomic_fetch_add_explicit(&g_writes, 1, memory_order_relaxed);
            n00b_data_unlock(g_lock);
        } else {
            n00b_data_read_lock(g_lock);
            atomic_fetch_add_explicit(&g_reads, 1, memory_order_relaxed);
            n00b_data_unlock(g_lock);
        }
    }
    return nullptr;
}

static void
test_mixed_contention(void)
{
    g_lock = n00b_data_lock_new();
    atomic_store_explicit(&g_writes, 0, memory_order_relaxed);
    atomic_store_explicit(&g_reads,  0, memory_order_relaxed);

    n00b_thread_t *threads[THREADS];
    for (int i = 0; i < THREADS; i++) {
        auto tr = n00b_thread_spawn(mixed_worker, (void *)(intptr_t)i);
        threads[i] = n00b_result_get(tr);
    }
    for (int i = 0; i < THREADS; i++) {
        (void)n00b_thread_join(threads[i]);
    }
    int total_writes = atomic_load_explicit(&g_writes, memory_order_relaxed);
    int total_reads  = atomic_load_explicit(&g_reads,  memory_order_relaxed);
    assert(total_writes + total_reads == THREADS * ITERS);
    printf("  [PASS] mixed read/write contention: %d threads x %d iters "
           "(writes=%d, reads=%d)\n",
           THREADS, ITERS, total_writes, total_reads);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_rwlock_contention:\n");
    test_mixed_contention();
    printf("All tests passed.\n");

    n00b_shutdown();
    return 0;
}

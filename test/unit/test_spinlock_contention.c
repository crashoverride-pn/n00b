/* test/unit/test_spinlock_contention.c - n00b#271: a spinlock under more
 * waiters than cores must not starve its holder.
 *
 * The mmap registry lock is a pure spin (a barrier participant must never
 * park). With twelve query threads spinning on it, a sensor producer's single
 * enqueue blocked for up to 82 s: more spinners than free cores starved the
 * holder of CPU. The lock now spins N00B_SPIN_LIMIT times, then backs off with
 * a raw nanosleep (still not parking), so the holder gets scheduled.
 *
 * This drives 3x the core count of threads through one spinlock, each holding
 * it for a short critical section, and asserts the whole thing finishes in a
 * bounded time and every increment landed. Under the old pure spin this took
 * seconds to minutes on a loaded machine; with backoff it takes milliseconds.
 */
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/spinlock.h"
#include "core/thread.h"
#include "core/time.h"

#define ITERS 2000

static n00b_spin_lock_t g_lock;
static _Atomic uint64_t g_count;
static uint64_t         g_plain; // protected by g_lock; the real check

static void *
worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        n00b_spinlock_lock(&g_lock);
        // A short critical section that touches memory, like the registry's
        // tree insert: enough that a descheduled holder is observable.
        g_plain++;
        volatile uint64_t sink = 0;
        for (int k = 0; k < 64; k++) {
            sink += (uint64_t)k * g_plain;
        }
        (void)sink;
        n00b_spinlock_unlock(&g_lock);
        atomic_fetch_add(&g_count, 1);
    }
    return nullptr;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) {
        cores = 1;
    }
    int nthreads = (int)(cores * 3);
    if (nthreads < 8) {
        nthreads = 8;
    }
    if (nthreads > 64) {
        nthreads = 64;
    }

    n00b_spinlock_init(&g_lock);
    n00b_thread_t **threads = n00b_alloc_array(n00b_thread_t *, nthreads);

    int64_t start = n00b_ns_timestamp();
    for (int i = 0; i < nthreads; i++) {
        auto r = n00b_thread_spawn(worker, nullptr);
        assert(n00b_result_is_ok(r));
        threads[i] = n00b_result_get(r);
    }
    for (int i = 0; i < nthreads; i++) {
        n00b_thread_join(threads[i]);
    }
    int64_t elapsed_ms = (n00b_ns_timestamp() - start) / 1000000;

    uint64_t want = (uint64_t)nthreads * ITERS;
    assert(atomic_load(&g_count) == want);
    assert(g_plain == want); // mutual exclusion held
    // Generous for a shared CI runner; the pure spin blew past this by an
    // order of magnitude whenever spinners outnumbered free cores.
    assert(elapsed_ms < 20000);
    printf("  [PASS] spinlock_contention (%d threads x %d, %lld ms)\n",
           nthreads,
           ITERS,
           (long long)elapsed_ms);
    n00b_shutdown();
    return 0;
}

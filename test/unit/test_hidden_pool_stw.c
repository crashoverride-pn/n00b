/*
 * test_hidden_pool_stw.c
 *
 * Repro for the SIGBUS / abort the wax raw_gateway has been hitting
 * under sustained burst load: n00b_visit_possible_pointer faults while
 * the GC mark scans an mmap-tree entry whose backing page has been
 * munmap'd by a concurrent pool_free.
 *
 * Hypothesis under test: foreign (non-n00b-spawned) pthreads that
 * call n00b_thread_init on entry but otherwise skip n00b_thread_checkin
 * can run pool_alloc / pool_free concurrently with a GC mark phase.
 * The pool registers / unregisters pages in the global mmap tree
 * (subject to the pool's own locking), but the GC mark walks the tree
 * without re-acquiring the per-mutator safepoint, and the freed
 * mmap_info_t / unmapped page lands underneath the scanner.
 *
 * Repro shape:
 *   - 4 n00b-spawned alloc/free threads on a hidden+metadata pool
 *   - 4 raw pthreads doing the same (mimicking XPC / libdispatch
 *     workers that hit our public surface from outside n00b's
 *     thread system). Each calls n00b_thread_init() on entry; no
 *     periodic n00b_thread_checkin().
 *   - main thread loops n00b_collect(default_arena) at ~1ms cadence
 *
 * Run with --duration N to soak longer; default 5s.
 *
 * Exit 0 = no crash inside the test window. SIGBUS / abort = the bug
 * we were chasing reproduces standalone, no root, no ES, no wax.
 */

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Unlocks the n00b_thread_init / n00b_thread_destroy kwarg-style
 * decls in core/thread.h, same pattern as test_mutex.c / test_rwlock.c. */
#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/alloc.h"
// Raw futex timed wait (__ulock_wait2 / FUTEX_WAIT) — a pthread-free sleep for
// the n00b-managed (raw Mach) collect_worker; see collect_worker for why.
#include "core/futex.h"
#include "core/gc.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"

#define N00B_THREADS    4
#define FOREIGN_THREADS 4
#define DEFAULT_DURATION_SECONDS 5
#define COLLECT_PERIOD_US        1000

static _Atomic bool     g_stop = false;
static _Atomic uint64_t g_n00b_thread_ops;
static _Atomic uint64_t g_foreign_thread_ops;
static _Atomic uint64_t g_collect_count;

static n00b_pool_t g_pool;

static n00b_allocator_t *
pool_alloc(void)
{
    return (n00b_allocator_t *)&g_pool;
}

/* Burn a few allocations of varying size against the pool. The mix of
 * small (freelist class) and big (mmap'd page) allocs is what stresses
 * the pool's register / unregister hot path; pure small allocs would
 * never trip the GC-vs-pool race because they don't unregister anything. */
static void
churn_one_round(void)
{
    n00b_alloc_opts_t opts = {.allocator = pool_alloc(), .no_scan = true};

    /* Small allocation: freelist class, no mmap-tree churn. */
    uint8_t *small = n00b_alloc_array_with_opts(uint8_t, 64, &opts);
    /* Mid allocation: still in freelist range. */
    uint8_t *mid   = n00b_alloc_array_with_opts(uint8_t, 256, &opts);
    /* Big allocation: gets its own mmap'd page; n00b_mmap_register_pool_page
     * + matching n00b_mmap_unregister on free is what races. */
    uint8_t *big   = n00b_alloc_array_with_opts(uint8_t, 8192, &opts);

    /* Touch the memory so it's resident — pure mmap without write would
     * not stress phys_footprint, but more importantly the GC scan
     * conservatively dereferences inside pages it reaches, and a clean
     * page that's later unmapped vs a dirty one behave the same to
     * the kernel's protection bits. */
    if (small) small[0] = 1;
    if (mid)   mid[0]   = 2;
    if (big)   big[0]   = 3;

    n00b_free(big);
    n00b_free(mid);
    n00b_free(small);
}

/* n00b-spawned worker: gets full STW participation via every
 * _n00b_alloc_raw / n00b_free checkin. Baseline — should NEVER
 * cause a crash even under heavy GC pressure. */
static void *
n00b_worker(void *arg)
{
    (void)arg;
    while (!atomic_load(&g_stop)) {
        churn_one_round();
        atomic_fetch_add(&g_n00b_thread_ops, 1);
    }
    return nullptr;
}

/* Foreign pthread: simulates an XPC / libdispatch worker. Calls
 * n00b_thread_init() on first entry to attach to the runtime (so
 * STW iteration finds it in rt->threads), but otherwise does the
 * same churn pattern as the n00b worker. */
static void *
foreign_worker(void *arg)
{
    (void)arg;
    /* The raw pthread is initially unknown to n00b: __n00b_thread_self
     * is uninitialised until we call n00b_thread_init.  The runtime does NOT
     * discover a foreign thread's stack bounds (no libc/pthread inside n00b);
     * the embedding app supplies them.  THIS test harness IS the embedding app,
     * so it queries its own pthread stack and passes [low, high) explicitly.
     * The query API is platform-specific: macOS/BSD expose the stack TOP +
     * size via pthread_get_stackaddr_np/pthread_get_stacksize_np; glibc exposes
     * the stack BASE (lowest addr) + size via pthread_getattr_np +
     * pthread_attr_getstack (needs _GNU_SOURCE, set by the build). */
    char  *lo;
    char  *hi;
#if defined(__APPLE__)
    hi         = (char *)pthread_get_stackaddr_np(pthread_self());
    size_t sz  = pthread_get_stacksize_np(pthread_self());
    lo         = hi - sz;
#else
    pthread_attr_t attr;
    pthread_getattr_np(pthread_self(), &attr);
    void  *base;
    size_t sz;
    pthread_attr_getstack(&attr, &base, &sz);
    pthread_attr_destroy(&attr);
    lo = (char *)base;
    hi = lo + sz;
#endif
    n00b_thread_init(.foreign_stack_low = lo, .foreign_stack_high = hi);

    while (!atomic_load(&g_stop)) {
        churn_one_round();
        atomic_fetch_add(&g_foreign_thread_ops, 1);
    }

    /* Foreign threads MUST explicitly deregister so n00b drops their slot and
     * stops tracking/scanning their stack. */
    n00b_thread_destroy();
    return nullptr;
}

/* GC-pressure thread: trigger n00b_collect on the default arena at
 * a fast cadence so the STW window is open frequently relative to
 * the mutator churn rate. */
static void *
collect_worker(void *arg)
{
    n00b_arena_t *arena = (n00b_arena_t *)arg;
    /* collect_worker is an n00b-managed RAW Mach thread (n00b_thread_spawn,
     * thread.c:125), NOT a pthread, so it has no pthread TSD.  It must not call
     * libc cancellation-point wrappers (nanosleep / usleep / ...): those route
     * through pthread_testcancel, which dereferences the pthread TSD a raw Mach
     * thread does not have -> intermittent SIGSEGV (the soak crash).  Sleep via
     * n00b's raw futex timed wait instead (__ulock_wait2 on macOS / FUTEX_WAIT
     * on Linux — a bare syscall, no pthread).  The futex value never changes, so
     * the wait always runs the full timeout and returns ETIMEDOUT. */
    n00b_futex_t idle = 0;
    while (!atomic_load(&g_stop)) {
        n00b_collect(arena);
        atomic_fetch_add(&g_collect_count, 1);
        n00b_futex_wait(&idle, 0, (uint64_t)COLLECT_PERIOD_US * 1000);
    }
    return nullptr;
}

int
main(int argc, char **argv)
{
    int duration = DEFAULT_DURATION_SECONDS;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--duration") == 0) {
            duration = atoi(argv[i + 1]);
        }
    }

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    /* Hidden + external_metadata, matching the rt->user_pool shape
     * the wax raw_gateway uses. This is the configuration whose
     * pool_alloc / pool_free traverse n00b_mmap_register_pool_page +
     * n00b_mmap_unregister and contend with GC mark. */
    n00b_pool_init(&g_pool,
                   .hidden            = true,
                   .external_metadata = true,
                   .name              = "test_hidden_pool_stw");

    /* Spawn n00b-managed workers via n00b_thread_spawn. */
    pthread_t n00b_native[N00B_THREADS];
    for (int i = 0; i < N00B_THREADS; i++) {
        auto r = n00b_thread_spawn(n00b_worker, nullptr);
        assert(n00b_result_is_ok(r));
        (void)n00b_result_get(r);
        /* n00b_thread_spawn returns the n00b_thread_t*, not a pthread_t;
         * we don't need the handle for join — main loop drives stop. */
        n00b_native[i] = 0;
        (void)n00b_native;
    }

    /* Spawn foreign pthreads — raw pthread_create, not n00b_thread_spawn. */
    pthread_t foreign[FOREIGN_THREADS];
    for (int i = 0; i < FOREIGN_THREADS; i++) {
        int rc = pthread_create(&foreign[i], nullptr, foreign_worker, nullptr);
        assert(rc == 0);
    }

    /* Spawn the collect-driver thread (n00b-spawned so its own
     * allocations are well-behaved; only its job is to call
     * n00b_collect at high frequency). */
    auto cr = n00b_thread_spawn(collect_worker, runtime.default_arena);
    assert(n00b_result_is_ok(cr));

    /* Soak. */
    fprintf(stderr,
            "test_hidden_pool_stw: %d n00b threads + %d foreign threads, "
            "collect every ~%dus, %d second soak\n",
            N00B_THREADS, FOREIGN_THREADS, COLLECT_PERIOD_US, duration);
    // Soak for the FULL duration without any libc sleep wrapper.  The
    // preemptive STW suspends every thread (including main) via an RT signal,
    // and libc sleep()/nanosleep() return early on EINTR regardless of
    // SA_RESTART — which would otherwise end the soak after the first collect
    // (~ms).  Worse, nanosleep is a libc cancellation point this runtime
    // deliberately avoids; sleep on n00b's raw futex instead, exactly as
    // collect_worker does (__ulock_wait2 on macOS / FUTEX_WAIT on Linux, a bare
    // syscall, no pthread, portable).  The futex value never changes, so each
    // wait runs the slice and returns ETIMEDOUT — or returns early on the STW
    // EINTR — and we re-check the monotonic deadline either way.
    {
        n00b_futex_t idle     = 0;
        int64_t      deadline = n00b_ns_timestamp()
                         + (int64_t)duration * N00B_NS_PER_SEC;
        int64_t remaining;
        while ((remaining = deadline - n00b_ns_timestamp()) > 0) {
            // Cap each wait below 1s: n00b_futex_wait packs the whole timeout
            // into timespec.tv_nsec (tv_sec stays 0), and Linux's futex(2)
            // rejects tv_nsec >= 1e9 with EINVAL.  Re-checking the deadline
            // after each slice also bounds the post-EINTR re-wait.
            uint64_t slice = remaining > (N00B_NS_PER_SEC / 2)
                                 ? (uint64_t)(N00B_NS_PER_SEC / 2)
                                 : (uint64_t)remaining;
            n00b_futex_wait(&idle, 0, slice);
        }
    }
    atomic_store(&g_stop, true);

    /* Join foreign pthreads. n00b workers exit when g_stop flips
     * and the runtime tears down on shutdown. */
    for (int i = 0; i < FOREIGN_THREADS; i++) {
        (void)pthread_join(foreign[i], nullptr);
    }

    fprintf(stderr,
            "test_hidden_pool_stw: PASS — survived %ds\n"
            "  n00b_thread_ops    = %llu\n"
            "  foreign_thread_ops = %llu\n"
            "  collect_count      = %llu\n",
            duration,
            (unsigned long long)atomic_load(&g_n00b_thread_ops),
            (unsigned long long)atomic_load(&g_foreign_thread_ops),
            (unsigned long long)atomic_load(&g_collect_count));

    n00b_shutdown();
    return 0;
}

#define N00B_USE_INTERNAL_API

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"

// ============================================================================
// Microbenchmark: cost of n00b_thread_self() on a WORKER thread, which takes
// the worker/foreign branch (the live-slot bounds scan introduced for
// foreign-thread safety) — NOT the O(1) main-thread range check.  Run with a
// realistic number of idle-but-live worker threads populating the live-slot
// bitmap, so the scan walks a representative live set.  This is the hottest
// path in the runtime (every gc-framed prologue calls it via gc_stack_push),
// so per-call cost directly bounds framed-call throughput.
// ============================================================================

#define N_PARKED 24             // idle live workers (populate live_slot_bits)
#define N_ITERS  50000000ULL    // thread_self() calls to time

static _Atomic uint32_t go_release = 0;
static _Atomic uint32_t parked_ready = 0;
static double           g_bench_ns_total = 0.0; // filled by bench worker, printed by main

static void *
parked_fn(void *raw)
{
    (void)raw;
    atomic_fetch_add(&parked_ready, 1);
    // No GC/STW is triggered by the bench (n00b_thread_self allocates
    // nothing), so a plain spin keeps these workers live without needing a
    // checkin.  Touch thread_self each iteration so the worker stays a
    // normal participant.
    while (atomic_load(&go_release) == 0) {
        (void)n00b_thread_self();
    }
    return raw;
}

static void *
bench_fn(void *raw)
{
    (void)raw;
    // Touch a volatile sink so the compiler can't elide the calls.
    volatile uintptr_t sink = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < N_ITERS; i++) {
        n00b_thread_t *s = n00b_thread_self();
        sink ^= (uintptr_t)s;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    (void)sink;
    // Do NOT printf floats on an n00b worker — dtoa -> libsystem_malloc ->
    // pthread_self traps off-libc.  Hand the result to main to print.
    g_bench_ns_total = (double)(t1.tv_sec - t0.tv_sec) * 1e9
                     + (double)(t1.tv_nsec - t0.tv_nsec);
    return raw;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("thread_self bench: %d parked live workers\n", N_PARKED);

    n00b_thread_t *parked[N_PARKED];
    for (int i = 0; i < N_PARKED; i++) {
        auto r = n00b_thread_spawn(parked_fn, nullptr);
        assert(n00b_result_is_ok(r));
        parked[i] = n00b_result_get(r);
    }
    while (atomic_load(&parked_ready) != N_PARKED) {
    }

    auto br = n00b_thread_spawn(bench_fn, nullptr);
    assert(n00b_result_is_ok(br));
    n00b_thread_t *bench = n00b_result_get(br);
    n00b_thread_join(bench);

    atomic_store(&go_release, 1);
    for (int i = 0; i < N_PARKED; i++) {
        n00b_thread_join(parked[i]);
    }

    double ns = g_bench_ns_total;
    printf("  worker thread_self(): %.2f ns/call  (%llu calls, %.1fM calls/s)\n",
           ns / (double)N_ITERS, (unsigned long long)N_ITERS,
           (double)N_ITERS / (ns / 1e9) / 1e6);
    printf("done.\n");
    n00b_shutdown();
    return 0;
}

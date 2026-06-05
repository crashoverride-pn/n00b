#define N00B_USE_INTERNAL_API

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"

// Pure-preemptive STW (WP-001): there is no cooperative self-park, no
// n00b_thread_checkin, and no self_lock STW/BLOCKING/SUSPEND bits.  A
// stop-the-world initiator acquires the single critical_execution gate and then
// preemptively suspends every other thread (gc_preempt_suspended set, registers
// captured); restart clears the flag and resumes them.  These tests exercise
// that model directly.

static _Atomic uint32_t worker_blocking_stage;
static _Atomic uint32_t worker_blocking_after_bits;

enum {
    WORKER_BLOCKING_INIT = 0,
    WORKER_BLOCKING_READY,
    WORKER_BLOCKING_RELEASE,
};

static _Atomic uint32_t spinner_stage;
static _Atomic uint64_t spinner_counter;

enum {
    SPINNER_INIT = 0,
    SPINNER_SPINNING,
    SPINNER_STOP,
};

static uint32_t
self_lock_bits(void)
{
    return n00b_atomic_load(&n00b_thread_self()->self_lock);
}

static void
test_stw_owner_not_left_suspended(void)
{
    // The initiator stays RUNNING across its own stop/restart — it is never
    // suspended (it is the one doing the suspending).
    assert(!n00b_world_is_stopped());

    n00b_stop_the_world();
    assert(n00b_world_is_stopped());
    n00b_restart_the_world();

    assert(!n00b_world_is_stopped());

    printf("  [PASS] STW owner is not left suspended\n");
}

static void
test_stw_nesting(void)
{
    // Nested stop/restart: only the outermost pair actually stops/restarts the
    // world.  The gate's recursion + the initiator-owned nesting counter handle
    // the inner pair.
    n00b_stop_the_world();
    assert(n00b_world_is_stopped());
    n00b_stop_the_world();
    assert(n00b_world_is_stopped());
    n00b_restart_the_world();
    // Still stopped: the inner restart only unwound one nesting level.
    assert(n00b_world_is_stopped());
    n00b_restart_the_world();
    assert(!n00b_world_is_stopped());

    printf("  [PASS] nested stop/restart only stops once\n");
}

static void *
worker_running_during_stw(void *arg)
{
    (void)arg;

    atomic_store(&worker_blocking_stage, WORKER_BLOCKING_READY);

    // Tight RUNNING spin, no checkin — the initiator must preempt us.
    while (atomic_load(&worker_blocking_stage) == WORKER_BLOCKING_READY) {
    }

    atomic_store(&worker_blocking_after_bits, self_lock_bits());

    return nullptr;
}

static void
test_stw_preempts_running_worker(void)
{
    atomic_store(&worker_blocking_stage, WORKER_BLOCKING_INIT);
    atomic_store(&worker_blocking_after_bits, UINT32_MAX);

    auto result = n00b_thread_spawn(worker_running_during_stw, nullptr);
    assert(n00b_result_is_ok(result));

    n00b_thread_t *thread = n00b_result_get(result);

    while (atomic_load(&worker_blocking_stage) != WORKER_BLOCKING_READY) {
    }

    n00b_stop_the_world();

    // The worker is RUNNING and never checks in, so the initiator suspends it
    // preemptively and captures its register file.
    assert(n00b_atomic_load(&thread->gc_preempt_suspended));

    atomic_store(&worker_blocking_stage, WORKER_BLOCKING_RELEASE);
    n00b_restart_the_world();

    n00b_thread_join(thread);

    // Cleanly resumed: the preempt flag is cleared and self_lock carries no
    // residual state (it is unused under pure-preemptive STW).
    uint32_t bits = atomic_load(&worker_blocking_after_bits);
    assert(bits == 0);
    assert(!n00b_atomic_load(&thread->gc_preempt_suspended));

    printf("  [PASS] STW preemptively stops a running worker\n");
}

// A worker spinning in PURE COMPUTE — no checkin, no allocation, no blocking
// call.  It reaches no safepoint of any kind; only preemptive suspension can
// stop it.
static void *
worker_pure_compute_spinner(void *arg)
{
    (void)arg;

    atomic_store(&spinner_stage, SPINNER_SPINNING);

    while (atomic_load(&spinner_stage) != SPINNER_STOP) {
        atomic_fetch_add(&spinner_counter, 1); // pure compute, no safepoint
    }

    return nullptr;
}

static void
test_preemptive_stw_stops_compute_spinner(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    atomic_store(&spinner_stage, SPINNER_INIT);
    atomic_store(&spinner_counter, 0);

    auto result = n00b_thread_spawn(worker_pure_compute_spinner, nullptr);
    assert(n00b_result_is_ok(result));
    n00b_thread_t *thread = n00b_result_get(result);

    // Wait until the worker is genuinely spinning.
    while (atomic_load(&spinner_stage) != SPINNER_SPINNING) {
    }

    // The worker never reaches a safepoint.  Preemptive suspension Mach-suspends
    // it and returns; if this hangs, the meson timeout fails the test.
    n00b_stop_the_world();
    assert(n00b_world_is_stopped());

    // It must have been stopped PREEMPTIVELY, with its register file captured.
    assert(n00b_atomic_load(&thread->gc_preempt_suspended));

    n00b_restart_the_world();

    // Restart clears the flag before thread_resume; the worker then resumes from
    // its interrupted PC and keeps spinning.
    assert(!n00b_atomic_load(&thread->gc_preempt_suspended));

    atomic_store(&spinner_stage, SPINNER_STOP);
    n00b_thread_join(thread);

    printf("  [PASS] preemptive STW stops a pure-compute spinner (no checkins)\n");
#else
    printf("  [SKIP] preemptive STW spinner "
           "(preemptive backend is macOS/arm64 only so far — D-040)\n");
#endif
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_stw:\n");
    test_stw_owner_not_left_suspended();
    test_stw_nesting();
    test_stw_preempts_running_worker();
    test_preemptive_stw_stops_compute_spinner();
    printf("All STW tests passed.\n");

    n00b_shutdown();
    return 0;
}

#include <stdio.h>
#include <assert.h>
#include <time.h> // nanosleep/struct timespec for the waiter-pacing sleeps

// stack_condition_thread reads n00b_thread_self()->stack_map (internal field),
// so the internal thread surface stays exposed; the waiter workers below run on
// n00b_thread_spawn workers (NOT pthread_create + n00b_thread_init).
#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/condition.h"
#include "core/atomic.h"
#include "core/gc.h"
#include "core/mmaps.h"
#include "core/stw.h"

// ============================================================================
// 1. Basic wait/notify
// ============================================================================

static n00b_condition_t basic_cv;
static _Atomic int      basic_ready;
static _Atomic int      basic_result;

static void *
basic_waiter(void *arg)
{
    (void)arg;

    void *result = n00b_condition_wait(&basic_cv);
    atomic_store(&basic_result, (int)(uintptr_t)result);

    n00b_condition_unlock(&basic_cv);
    return nullptr;
}

static void
test_basic_wait_notify(void)
{
    memset(&basic_cv, 0, sizeof(basic_cv));
    n00b_condition_init(&basic_cv);
    atomic_store(&basic_ready, 0);
    atomic_store(&basic_result, -1);

    n00b_result_t(n00b_thread_t *) wr = n00b_thread_spawn(basic_waiter, nullptr);
    assert(n00b_result_is_ok(wr));
    n00b_thread_t *waiter = n00b_result_get(wr);

    // Give the waiter time to enter wait().
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000000}; // 50ms
    nanosleep(&ts, nullptr);

    n00b_condition_notify(&basic_cv, .value = (void *)42);
    n00b_condition_unlock(&basic_cv);

    n00b_thread_join(waiter);

    assert(atomic_load(&basic_result) == 42);

    printf("  [PASS] basic wait/notify\n");
}

// ============================================================================
// 2. Predicate-based selective wake
// ============================================================================

static n00b_condition_t pred_cv;
static _Atomic int      pred_woke_1;
static _Atomic int      pred_woke_2;

static void *
pred_waiter_1(void *arg)
{
    (void)arg;

    void *result = n00b_condition_wait(&pred_cv, .predicate = 1);
    (void)result;
    atomic_store(&pred_woke_1, 1);

    n00b_condition_unlock(&pred_cv);
    return nullptr;
}

static void *
pred_waiter_2(void *arg)
{
    (void)arg;

    void *result = n00b_condition_wait(&pred_cv, .predicate = 2);
    (void)result;
    atomic_store(&pred_woke_2, 1);

    n00b_condition_unlock(&pred_cv);
    return nullptr;
}

static void
test_predicate_wake(void)
{
    memset(&pred_cv, 0, sizeof(pred_cv));
    n00b_condition_init(&pred_cv);
    atomic_store(&pred_woke_1, 0);
    atomic_store(&pred_woke_2, 0);

    n00b_result_t(n00b_thread_t *) wr1 = n00b_thread_spawn(pred_waiter_1, nullptr);
    n00b_result_t(n00b_thread_t *) wr2 = n00b_thread_spawn(pred_waiter_2, nullptr);
    assert(n00b_result_is_ok(wr1));
    assert(n00b_result_is_ok(wr2));
    n00b_thread_t *w1 = n00b_result_get(wr1);
    n00b_thread_t *w2 = n00b_result_get(wr2);

    struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000000};
    nanosleep(&ts, nullptr);

    // Notify only predicate=1.
    n00b_condition_notify(&pred_cv, .predicate = 1, .all = true);
    n00b_condition_unlock(&pred_cv);

    nanosleep(&ts, nullptr);

    // Waiter 1 should have woken, waiter 2 should still be asleep.
    assert(atomic_load(&pred_woke_1) == 1);

    // Now wake waiter 2.
    n00b_condition_notify(&pred_cv, .predicate = 2, .all = true);
    n00b_condition_unlock(&pred_cv);

    n00b_thread_join(w1);
    n00b_thread_join(w2);

    assert(atomic_load(&pred_woke_2) == 1);

    printf("  [PASS] predicate-based selective wake\n");
}

// ============================================================================
// 3. Static callback root deduplication
// ============================================================================

static n00b_condition_t dedupe_cv;

static bool
dedupe_predicate(uint64_t actual_pred,
                 uint64_t thread_pred,
                 void    *output,
                 void    *cv_param,
                 void    *thread_param)
{
    (void)actual_pred;
    (void)thread_pred;
    (void)output;
    (void)cv_param;
    (void)thread_param;
    return true;
}

static void
test_static_callback_root_dedup(void)
{
    n00b_runtime_t *rt     = n00b_get_runtime();
    size_t          before = n00b_list_len(rt->gc_roots);

    dedupe_cv = (n00b_condition_t){};
    n00b_condition_init(&dedupe_cv);

    size_t after_init = n00b_list_len(rt->gc_roots);

    n00b_condition_set_callback(&dedupe_cv, dedupe_predicate, nullptr);

    size_t after_callback = n00b_list_len(rt->gc_roots);

    assert(after_init >= before);
    assert(after_callback == after_init);

    printf("  [PASS] static callback root deduplication\n");
}

// ============================================================================
// 4. Stack-backed CVs are already covered by stack scanning
// ============================================================================

static _Atomic uintptr_t stack_thread_probe;
static _Atomic uintptr_t stack_thread_limit;

static bool
gc_root_addr_in_range(uintptr_t lo, uintptr_t hi)
{
    n00b_runtime_t *rt  = n00b_get_runtime();
    size_t          len = n00b_list_len(rt->gc_roots);

    for (size_t i = 0; i < len; i++) {
        n00b_gc_root_t root = n00b_list_get(rt->gc_roots, i);
        uintptr_t      addr = (uintptr_t)root.addr;

        if (addr >= lo && addr < hi) {
            return true;
        }
    }

    return false;
}

static void
make_stack_condition(void)
{
    n00b_condition_t cv = {};
    uintptr_t        lo = (uintptr_t)&cv;
    uintptr_t        hi = lo + sizeof(cv);

    n00b_condition_init(&cv);
    assert(!gc_root_addr_in_range(lo, hi));

    n00b_condition_set_callback(&cv, dedupe_predicate, nullptr);
    assert(!gc_root_addr_in_range(lo, hi));
}

static void *
stack_condition_thread(void *arg)
{
    (void)arg;

    n00b_mmap_info_t *stack_map = n00b_thread_self()->stack_map;
    assert(stack_map != nullptr);
    atomic_store(&stack_thread_probe, (uintptr_t)stack_map->start);
    atomic_store(&stack_thread_limit, (uintptr_t)stack_map->end);

    make_stack_condition();

    return nullptr;
}

static void
test_stack_condition_roots(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    make_stack_condition();

    atomic_store(&stack_thread_probe, 0);
    atomic_store(&stack_thread_limit, 0);

    n00b_result_t(n00b_thread_t *) tr = n00b_thread_spawn(stack_condition_thread,
                                                          nullptr);
    assert(n00b_result_is_ok(tr));
    n00b_thread_join(n00b_result_get(tr));

    uintptr_t stack_addr  = atomic_load(&stack_thread_probe);
    uintptr_t stack_limit = atomic_load(&stack_thread_limit);
    assert(stack_addr != 0);
    assert(stack_limit > stack_addr);
    assert(!gc_root_addr_in_range(stack_addr, stack_limit));

    // (Pre-WP-3a this asserted the worker's stack was UNMAPPED after join, on
    // the old model where the joiner freed the callstack.  Under D-034 the
    // callstack is returned to the pool and reclaimed by the reaper at
    // OS-confirmed death — NOT unmapped at join — and its mmap registration is
    // retained across pool reuse, so the region's map state at this point is
    // intentionally non-deterministic and no longer a valid assertion.  The
    // lifetime property this test actually guards is that a stack-backed CV
    // leaves NO dangling GC root, which the gc_root_addr_in_range check above
    // asserts; the forced collection below then runs a GC over the region.)

    n00b_stop_the_world();
    n00b_collect(rt->default_arena);
    n00b_restart_the_world();

    // After a full collection, the dead worker's stack range must STILL carry
    // no live GC root (the real invariant this test guards — a stack-backed CV
    // must not leave a dangling root behind once the owning thread is gone).
    assert(!gc_root_addr_in_range(stack_addr, stack_limit));

    printf("  [PASS] stack-backed CV root lifetime\n");
}

// ============================================================================
// 5. Timeout
// ============================================================================

static void
test_timeout(void)
{
    n00b_condition_t cv = {};
    n00b_condition_init(&cv);

    // Wait with a short timeout — nobody will notify.
    void *result = n00b_condition_wait(&cv, .timeout_ms = 10);
    n00b_condition_unlock(&cv);

    // Timeout returns ~0ULL.
    assert(result == (void *)~0ULL);

    printf("  [PASS] timeout\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_condition:\n");
    fflush(stdout);
    test_basic_wait_notify();
    fflush(stdout);
    test_predicate_wake();
    fflush(stdout);
    test_static_callback_root_dedup();
    fflush(stdout);
    test_stack_condition_roots();
    fflush(stdout);
    test_timeout();
    fflush(stdout);

    printf("All condition variable tests passed.\n");
    n00b_shutdown();
    return 0;
}

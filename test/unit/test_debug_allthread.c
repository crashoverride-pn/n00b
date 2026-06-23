#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "debug/debug.h"

// All-thread watchpoints: a watch set on one thread must trap writes made on
// OTHER threads too. Two paths are exercised:
//   1. enroll  - worker spawned AFTER the watch is set (launcher-hook path)
//   2. enumerate - worker already running WHEN the watch is set (task_threads)

static volatile uint64_t g_target;
static _Atomic int       g_hits;
static _Atomic int       g_go;
static _Atomic int       g_done;

static n00b_debug_action_t
on_hit(n00b_debug_hit_t *hit, void *ud)
{
    (void)hit;
    (void)ud;
    atomic_fetch_add(&g_hits, 1);
    return N00B_DEBUG_CONTINUE; // keep armed, step over the write
}

// Writes g_target arg times.
static void *
writer_fn(void *arg)
{
    int n = (int)(intptr_t)arg;
    for (int i = 0; i < n; i++) {
        g_target = (uint64_t)(i + 1);
    }
    return nullptr;
}

// Spins until released, then writes once.
static void *
spinner_fn(void *arg)
{
    (void)arg;
    while (atomic_load(&g_go) == 0) {
        // busy-wait for the main thread to arm the watch
    }
    g_target = 0xabc;
    atomic_store(&g_done, 1);
    return nullptr;
}

static bool
test_allthread_enroll(void)
{
    g_target = 0;
    atomic_store(&g_hits, 0);

    n00b_result_t(n00b_debug_watchpoint_t *) r =
        n00b_debug_watch((void *)&g_target, .on_hit = on_hit);
    if (n00b_result_is_err(r)) {
        if (n00b_result_get_err(r) == N00B_DEBUG_ERR_UNSUPPORTED) {
            printf("  [SKIP] all-thread tests (unsupported on this target)\n");
            return false;
        }
        printf("  [FAIL] enroll: install error %d\n", n00b_result_get_err(r));
        assert(false);
    }
    n00b_debug_watchpoint_t *wp = n00b_result_get(r);

    // Worker spawned AFTER the watch -> must enroll via the launcher hook.
    n00b_result_t(n00b_thread_t *) tr =
        n00b_thread_spawn(writer_fn, (void *)(intptr_t)5);
    assert(n00b_result_is_ok(tr));
    n00b_thread_join(n00b_result_get(tr));

    assert(atomic_load(&g_hits) == 5); // every cross-thread write trapped
    assert(g_target == 5);
    assert(n00b_debug_watch_clear(wp) == N00B_DEBUG_OK);
    printf("  [PASS] allthread_enroll\n");
    return true;
}

static void
test_allthread_enumerate(void)
{
    g_target = 0;
    atomic_store(&g_hits, 0);
    atomic_store(&g_go, 0);
    atomic_store(&g_done, 0);

    // Worker is already running BEFORE the watch is set.
    n00b_result_t(n00b_thread_t *) tr = n00b_thread_spawn(spinner_fn, nullptr);
    assert(n00b_result_is_ok(tr));

    n00b_result_t(n00b_debug_watchpoint_t *) r =
        n00b_debug_watch((void *)&g_target, .on_hit = on_hit);
    assert(n00b_result_is_ok(r));
    n00b_debug_watchpoint_t *wp = n00b_result_get(r);

    atomic_store(&g_go, 1);        // release the spinner; its write should trap
    n00b_thread_join(n00b_result_get(tr));

    assert(atomic_load(&g_done) == 1);
    assert(atomic_load(&g_hits) >= 1); // pre-existing thread was enrolled
    assert(g_target == 0xabc);
    assert(n00b_debug_watch_clear(wp) == N00B_DEBUG_OK);
    printf("  [PASS] allthread_enumerate\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running all-thread watchpoint tests...\n");
    if (test_allthread_enroll()) {
        test_allthread_enumerate();
        printf("All all-thread watchpoint tests passed.\n");
    }
    n00b_shutdown();
    return 0;
}

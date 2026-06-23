#include <stdio.h>
#include <assert.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/runtime.h"
#include "debug/debug.h"

// These tests program a hardware watchpoint on the *calling* thread and then
// store to the watched word on that same thread. macOS delivers the watchpoint
// as a Mach exception to the server thread, which suspends this thread, runs
// the callback, applies the action, and resumes us — so by the time a store
// statement returns, the callback has already run (no sleeps needed).

static volatile uint64_t g_target;
static volatile uint64_t g_target2;
static _Atomic int       g_hits;
static volatile uint64_t g_seen_old;
static volatile uint64_t g_seen_new;
static volatile void    *g_seen_addr;

static n00b_debug_action_t
on_write_disable(n00b_debug_hit_t *hit, void *ud)
{
    (void)ud;
    g_seen_addr = n00b_debug_hit_addr(hit);
    g_seen_old  = (uint64_t)n00b_debug_hit_old_value(hit);
    g_seen_new  = (uint64_t)n00b_debug_hit_new_value(hit);
    atomic_fetch_add(&g_hits, 1);
    return N00B_DEBUG_DISABLE; // one-shot: clear, let the write proceed
}

static n00b_debug_action_t
on_write_continue(n00b_debug_hit_t *hit, void *ud)
{
    (void)hit;
    (void)ud;
    atomic_fetch_add(&g_hits, 1);
    return N00B_DEBUG_CONTINUE; // keep watching; step over the write
}

// Returns false if the platform can't do watchpoints (skip the suite).
static bool
test_watch_disable(void)
{
    g_target = 0x1111;
    atomic_store(&g_hits, 0);

    n00b_result_t(n00b_debug_watchpoint_t *) r =
        n00b_debug_watch((void *)&g_target,
                         .size   = N00B_DEBUG_WATCH_SIZE_8,
                         .kind   = N00B_DEBUG_WATCH_WRITE,
                         .on_hit = on_write_disable);

    if (n00b_result_is_err(r)) {
        n00b_debug_err_t e = n00b_result_get_err(r);
        if (e == N00B_DEBUG_ERR_UNSUPPORTED) {
            printf("  [SKIP] watch tests (unsupported on this target)\n");
            return false;
        }
        printf("  [FAIL] watch_disable: install error %d\n", e);
        assert(false);
    }

    g_target = 0x2222; // should trap -> callback -> DISABLE -> write completes

    assert(atomic_load(&g_hits) == 1);
    assert(g_target == 0x2222);          // DISABLE lets the store through
    assert(g_seen_new == 0x2222);        // decoded store value
    assert(g_seen_old == 0x1111);        // pre-write value
    assert(g_seen_addr == (void *)&g_target);

    // One-shot: a second write must NOT trap (slot was cleared).
    g_target = 0x3333;
    assert(atomic_load(&g_hits) == 1);
    assert(g_target == 0x3333);
    printf("  [PASS] watch_disable\n");
    return true;
}

static void
test_watch_continue(void)
{
    g_target = 0;
    atomic_store(&g_hits, 0);

    n00b_result_t(n00b_debug_watchpoint_t *) r =
        n00b_debug_watch((void *)&g_target, .on_hit = on_write_continue);
    assert(n00b_result_is_ok(r));
    n00b_debug_watchpoint_t *wp = n00b_result_get(r);

    g_target = 1; // fire, single-step over, stay armed
    g_target = 2; // fire again
    g_target = 3; // fire again

    assert(atomic_load(&g_hits) == 3); // armed across all three writes
    assert(g_target == 3);             // every write actually landed

    assert(n00b_debug_watch_is_enabled(wp));
    assert(n00b_debug_watch_clear(wp) == N00B_DEBUG_OK);

    // After clear, writes are untrapped.
    g_target = 4;
    assert(atomic_load(&g_hits) == 3);
    assert(g_target == 4);
    printf("  [PASS] watch_continue\n");
}

static bool
count_cb(n00b_debug_watchpoint_t *wp, void *ud)
{
    (void)n00b_debug_watch_addr(wp); // accessors are usable mid-iteration
    (*(int *)ud)++;
    return true;
}

static bool
stop_after_one_cb(n00b_debug_watchpoint_t *wp, void *ud)
{
    (void)wp;
    (*(int *)ud)++;
    return false; // early stop
}

static void
test_watch_foreach(void)
{
    // Two armed (untriggered) watchpoints; enumeration must visit both.
    n00b_result_t(n00b_debug_watchpoint_t *) r1 =
        n00b_debug_watch((void *)&g_target);
    n00b_result_t(n00b_debug_watchpoint_t *) r2 =
        n00b_debug_watch((void *)&g_target2);
    assert(n00b_result_is_ok(r1) && n00b_result_is_ok(r2));

    int n = 0;
    n00b_debug_watch_foreach(count_cb, &n);
    assert(n == 2);

    int m = 0;
    n00b_debug_watch_foreach(stop_after_one_cb, &m);
    assert(m == 1); // stopped early

    assert(n00b_debug_watch_clear(n00b_result_get(r1)) == N00B_DEBUG_OK);
    assert(n00b_debug_watch_clear(n00b_result_get(r2)) == N00B_DEBUG_OK);

    int z = 0;
    n00b_debug_watch_foreach(count_cb, &z);
    assert(z == 0); // none left
    printf("  [PASS] watch_foreach\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running debug watchpoint tests...\n");

    if (test_watch_disable()) {
        test_watch_continue();
        test_watch_foreach();
        printf("All debug watchpoint tests passed.\n");
    }

    n00b_shutdown();
    return 0;
}

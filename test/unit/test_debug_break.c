#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/runtime.h"
#include "debug/debug.h"

// Hardware execute breakpoints, set on (and fired from) the calling thread.

static _Atomic int    g_bhits;
static volatile void *g_bpc;

[[gnu::noinline]] static int
target_fn(int x)
{
    // Keep the body non-trivial so it is not folded away.
    volatile int y = x;
    return y + 1;
}

static n00b_debug_action_t
on_break_continue(n00b_debug_hit_t *hit, void *ud)
{
    (void)ud;
    g_bpc = n00b_debug_hit_pc(hit);
    atomic_fetch_add(&g_bhits, 1);
    return N00B_DEBUG_CONTINUE; // run the function, keep the breakpoint armed
}

static n00b_debug_action_t
on_break_disable(n00b_debug_hit_t *hit, void *ud)
{
    (void)hit;
    (void)ud;
    atomic_fetch_add(&g_bhits, 1);
    return N00B_DEBUG_DISABLE; // one-shot
}

static bool
test_break_continue(void)
{
    void *fn = (void *)(uintptr_t)&target_fn;
    atomic_store(&g_bhits, 0);

    n00b_result_t(n00b_debug_breakpoint_t *) r =
        n00b_debug_break(fn, .on_hit = on_break_continue);

    if (n00b_result_is_err(r)) {
        n00b_debug_err_t e = n00b_result_get_err(r);
        if (e == N00B_DEBUG_ERR_UNSUPPORTED) {
            printf("  [SKIP] breakpoint tests (unsupported on this target)\n");
            return false;
        }
        printf("  [FAIL] break_continue: install error %d\n", e);
        assert(false);
    }
    n00b_debug_breakpoint_t *bp = n00b_result_get(r);

    int a = target_fn(10); // fire, step over entry, run -> 11
    int b = target_fn(20); // fire again -> 21

    assert(atomic_load(&g_bhits) == 2);
    assert(a == 11 && b == 21);
    assert(g_bpc == fn); // PC at the hit is the breakpoint address

    assert(n00b_debug_break_is_enabled(bp));
    assert(n00b_debug_break_clear(bp) == N00B_DEBUG_OK);

    int c = target_fn(30); // untrapped now
    assert(atomic_load(&g_bhits) == 2);
    assert(c == 31);
    printf("  [PASS] break_continue\n");
    return true;
}

static void
test_break_disable(void)
{
    void *fn = (void *)(uintptr_t)&target_fn;
    atomic_store(&g_bhits, 0);

    n00b_result_t(n00b_debug_breakpoint_t *) r =
        n00b_debug_break(fn, .on_hit = on_break_disable);
    assert(n00b_result_is_ok(r));

    int a = target_fn(1); // fire once, DISABLE, run -> 2
    int b = target_fn(2); // untrapped -> 3

    assert(atomic_load(&g_bhits) == 1);
    assert(a == 2 && b == 3);
    printf("  [PASS] break_disable\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running debug breakpoint tests...\n");

    if (test_break_continue()) {
        test_break_disable();
        printf("All debug breakpoint tests passed.\n");
    }

    n00b_shutdown();
    return 0;
}

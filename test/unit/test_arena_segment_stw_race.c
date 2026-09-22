/* test/unit/test_arena_segment_stw_race.c - n00b-lang/n00b#431.
 *
 * n00b_add_arena_segment is critical execution: it mmaps a region, links a
 * fresh descriptor onto the arena's segment chain, and then REPUBLISHES the
 * arena's three published fields --
 *
 *     arena->next_alloc  = ...;                              // new segment
 *     arena->segment_end = ...;                              // new segment
 *     n00b_atomic_store(&arena->current_segment, segment);
 *
 * -- and until #431 it was the one piece of critical execution that did not
 * hold rt->critical_execution.  Stop-the-world is purely preemptive, so a
 * collect could begin anywhere in there, run to completion, and the thread
 * would then resume and finish those stores with values computed BEFORE the
 * collect: the collector's to-space drops off the chain and the pre-collect
 * from-space head -- descriptors n00b_reclaim_pinned_pages has already handed
 * back to system_pool -- takes its place.  Every crash signature on #431 walks
 * that chain.
 *
 * The window is a few instructions wide, so racing into it by chance is not a
 * test: 25 runs of a 6-thread churn against the UNGATED build on a 10-core box
 * never hit it.  So this test stands in the window on purpose, via
 * n00b_arena_segment_publish_hook, and races one collect into it.
 *
 *   * With the gate: n00b_collect blocks on the STW write lock until the add
 *     completes, the chain is never republished under it, and the audit is
 *     clean.
 *   * Without it: the collect runs to completion inside the window, the
 *     resuming thread clobbers the swap, and the next collect's segment-chain
 *     audit finds a freed descriptor on the live chain and aborts.
 *
 * A multi-threaded churn would be a natural second half (the gate is taken
 * BEFORE the per-arena spin lock, and getting that order wrong deadlocks), but
 * that workload currently trips the OTHER, unfixed #431 mechanism roughly 7
 * runs in 10 -- see test_gc_large_alloc_churn, which is checked in quarantined
 * for exactly that.  Keeping it here would make this test red for an unrelated
 * reason.  The single racing collect below still proves the gate blocks: with
 * the gate missing it completes inside the window, and with it present it does
 * not.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "conduit/print.h"
#include "util/assert.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)


// ---------------------------------------------------------------------------
// Part 1: deterministic race into the publish window.
// ---------------------------------------------------------------------------

// A private GC arena, deliberately created with a small initial segment, so
// every few allocations force a real n00b_add_arena_segment.  The default
// arena is no good for this: its segment grows, its garbage is collected, and
// after warm-up it simply stops adding segments.
// A GC arena only adds a segment when an allocation does not fit even AFTER a
// collect (n00b_arena_alloc's `already_collected` path) -- growth normally
// happens by the to-space coming back bigger.  So the allocations here are
// much larger than the arena, which makes every one of them a real
// n00b_add_arena_segment on a NON-hidden arena.
#define RACE_ARENA_SIZE (64 * 1024)
#define RACE_ALLOC      (4 * 1024 * 1024)

static n00b_arena_t   *g_race_arena  = nullptr;

static _Atomic int64_t g_in_window   = 0; // adder has reached the window
static _Atomic int64_t g_arm         = 0; // hook is armed (one shot)
static _Atomic int64_t g_window_hits = 0;
static _Atomic int64_t g_hook_calls  = 0;

static void
publish_window_hook(n00b_arena_t *arena)
{
    if (arena != g_race_arena) {
        return;
    }

    n00b_atomic_add(&g_hook_calls, 1);

    if (!n00b_atomic_load(&g_arm)) {
        return;
    }
    // One shot.
    int64_t expected = 1;
    if (!n00b_cas(&g_arm, &expected, 0)) {
        return;
    }

    n00b_atomic_add(&g_window_hits, 1);
    n00b_atomic_store(&g_in_window, 1);

    // Hold the window open long enough for the other thread's collect to run
    // to completion.  Deliberately a sleep and NOT a handshake: with the gate
    // in place that collect cannot start until we return, so waiting for it
    // would deadlock the correct build.
    usleep(400 * 1000);
}

// Allocate and immediately verify.  Nothing is kept across a collect on
// purpose: a file-scope array of GC pointers is not a root in n00b, so holding
// them there would be the test's own use-after-collect rather than the
// collector's.  The assertion for this test is the segment-chain audit, not
// object survival.
static void
race_alloc(char tag)
{
    char *p = n00b_alloc_array_with_opts(
        char,
        RACE_ALLOC,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)g_race_arena});

    p[0]              = tag;
    p[RACE_ALLOC - 1] = tag;
    CHECK(p[0] == p[RACE_ALLOC - 1]);
}

static void *
window_adder_main(void *arg)
{
    (void)arg;

    for (int i = 0; i < 16 && n00b_atomic_load(&g_window_hits) == 0; i++) {
        race_alloc('w');
    }
    // Keep allocating after the racing collect, so the clobbered publish (if
    // the gate is missing) actually gets used.
    for (int i = 0; i < 8; i++) {
        race_alloc('x');
    }

    return nullptr;
}

static void
test_publish_window_race(void)
{
    g_race_arena = n00b_new_arena(.size   = RACE_ARENA_SIZE,
                                  .use_gc = true,
                                  .name   = "n00b431-race");
    CHECK(g_race_arena != nullptr);

    n00b_arena_segment_publish_hook = publish_window_hook;
    n00b_atomic_store(&g_arm, 1);

    auto r = n00b_thread_spawn(window_adder_main, nullptr);
    CHECK(n00b_result_is_ok(r));
    n00b_thread_t *adder = n00b_result_get(r);

    // Wait until the adder is parked in the publish window, then collect into
    // it.  Bounded so a build where the hook never fires fails loudly rather
    // than hanging.
    for (int i = 0; i < 4000 && !n00b_atomic_load(&g_in_window); i++) {
        usleep(1000);
    }

    n00b_eprintf("publish-window race: hook_calls=[|#|] in_window=[|#|]\n",
                 (int64_t)n00b_atomic_load(&g_hook_calls),
                 (int64_t)n00b_atomic_load(&g_in_window));
    CHECK(n00b_atomic_load(&g_in_window) == 1);

    // THE RACE.  With the gate this blocks until the adder publishes; without
    // it, it runs to completion inside the window.
    n00b_collect(g_race_arena);

    n00b_thread_join(adder);
    n00b_arena_segment_publish_hook = nullptr;

    // The audit runs at collect entry: if the window clobbered the chain, this
    // is where it is found.
    n00b_collect(g_race_arena);

    CHECK(n00b_atomic_load(&g_window_hits) == 1);
}

int
main(int argc, char *argv[])
{
    // The segment-chain audit IS the assertion for part 1, and it is read once
    // and cached on first use, so it has to be set before any collect runs.
    setenv("N00B_GC_AUDIT_SEGMENT_CHAIN", "1", 1);

    n00b_init_simple(argc, argv);

    test_publish_window_race();

    n00b_eprintf("arena segment/STW race: shrink_retries=[|#|]\n",
                 (int64_t)n00b_atomic_load(&n00b_arena_segment_shrink_retries));

    n00b_eprintf("test_arena_segment_stw_race OK\n");
    return 0;
}

// n00b#395 / n00b#275 -- does one large, since-collected allocation make every
// later collect worse over an UNCHANGED live set?
//
// The scan bound (_find_sentinal in alloc.c) is n00b_max_inline_alloc_len, an
// all-time high-water mark that is monotonic by design. The hysteresis model
// says a single big allocation permanently widens every conservative
// interior-pointer backward scan, and each page of that scan can cost a
// write/read/poll triple via n00b_check_memory_perms.
//
// This measures it directly rather than inferring it from a wedged gateway:
// identical live set, identical collect count, before and after. Syscall
// probes are counted as well as wall-clock, because a change that trades
// kernel entries for cache misses must not be able to look like a win --
// that is how PR #384 came to look sufficient.
//
// A NULL RESULT KILLS THE MODEL and is worth more than the fix.

#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/gc.h"
#include "core/memory_info.h"
#include "core/time.h"
#include "core/runtime.h"

#define LIVE_OBJECTS   2000
#define LIVE_OBJ_BYTES 512
#define BIG_BYTES      (500ull * 1024ull * 1024ull)
#define COLLECTS       5

typedef struct {
    uint64_t wall_ns;
    uint64_t syscall_probes;
    uint64_t fastpath_hits;
    uint64_t scan_bound;
} phase_t;

// Held across both phases so the live set is provably identical.
[[n00b::nomap]] static void *g_live[LIVE_OBJECTS];

static void
build_live_set(void)
{
    for (int i = 0; i < LIVE_OBJECTS; i++) {
        g_live[i] = n00b_alloc_array(uint8_t, LIVE_OBJ_BYTES);
        // Touch it so the pages are committed and the object is genuinely live.
        ((uint8_t *)g_live[i])[0]                  = (uint8_t)i;
        ((uint8_t *)g_live[i])[LIVE_OBJ_BYTES - 1] = (uint8_t)i;
    }
}

static phase_t
measure(const char *label, n00b_arena_t *arena)
{
    n00b_atomic_store(&n00b_memperm_syscall_probes, 0);
    n00b_atomic_store(&n00b_memperm_fastpath_hits, 0);

    uint64_t t0 = base_monotonic_ns();
    for (int i = 0; i < COLLECTS; i++) {
        n00b_collect(arena);
    }
    uint64_t t1 = base_monotonic_ns();

    phase_t p = {
        .wall_ns        = t1 - t0,
        .syscall_probes = n00b_atomic_load(&n00b_memperm_syscall_probes),
        .fastpath_hits  = n00b_atomic_load(&n00b_memperm_fastpath_hits),
        .scan_bound     = n00b_atomic_load(&n00b_max_inline_alloc_len),
    };

    printf("  %-8s wall %10llu ns | syscall probes %10llu | fastpath %10llu | scan bound %12llu\n",
           label,
           (unsigned long long)p.wall_ns,
           (unsigned long long)p.syscall_probes,
           (unsigned long long)p.fastpath_hits,
           (unsigned long long)p.scan_bound);
    return p;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    // The default arena is where build_live_set() and the big allocation land,
    // so it is the one whose collect we must time (n00b_collect dereferences
    // arena->current_segment; nullptr faults at NULL+0x60).
    n00b_arena_t *arena = n00b_get_runtime()->default_arena;
    assert(arena != nullptr);

    build_live_set();

    printf("n00b#395 scan-bound hysteresis: %d live objects x %d B, %d collects per phase\n",
           LIVE_OBJECTS,
           LIVE_OBJ_BYTES,
           COLLECTS);

    // Warm: first collect does one-time work (static scan tree, etc.) that
    // would otherwise be charged to BEFORE and flatter the AFTER.
    n00b_collect(arena);

    phase_t before = measure("BEFORE", arena);

    // One large allocation, immediately unreachable. It is collected below --
    // only the high-water mark survives it. That is the whole point: the live
    // set in AFTER is identical to BEFORE.
    {
        void *big = n00b_alloc_array(uint8_t, BIG_BYTES);
        assert(big != nullptr);
        ((uint8_t *)big)[0]             = 1;
        ((uint8_t *)big)[BIG_BYTES - 1] = 1;
    }
    n00b_collect(arena); // reclaim it; the bound does not come back down

    phase_t after = measure("AFTER", arena);

    printf("\n  live set unchanged; only n00b_max_inline_alloc_len moved: %llu -> %llu\n",
           (unsigned long long)before.scan_bound,
           (unsigned long long)after.scan_bound);

    if (before.wall_ns > 0) {
        printf("  wall           %.2fx\n",
               (double)after.wall_ns / (double)before.wall_ns);
    }
    if (before.syscall_probes > 0) {
        printf("  syscall probes %.2fx\n",
               (double)after.syscall_probes / (double)before.syscall_probes);
    }
    else {
        printf("  syscall probes BEFORE was 0 -- after = %llu\n",
               (unsigned long long)after.syscall_probes);
    }

    // The bound must have moved, or the experiment did not run.
    assert(after.scan_bound > before.scan_bound);

    // Keep the live set reachable to the very end so neither phase can win by
    // collecting it.
    for (int i = 0; i < LIVE_OBJECTS; i++) {
        assert(g_live[i] != nullptr);
    }

    printf("\n  [DONE] numbers above are the result; this test reports, it does not grade.\n");
    return 0;
}

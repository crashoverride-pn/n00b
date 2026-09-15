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
//
// The one thing this bench MUST get right is that the big allocation is dead
// when AFTER runs.  It checks that (arena size after the reclaim collect) and
// refuses to report if it is not; see allocate_and_drop_big().

#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
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
    uint64_t indeterminate;
    uint64_t scan_bound;
    // n00b#395 follow-up: what the guard scan actually walked. Once the
    // per-mapping bound is in, the global scan bound above still rises and
    // stays risen, so these two are the numbers that say whether the SCAN
    // got longer -- as opposed to the collect getting slower for a reason
    // that is not the scan at all (a to-space sized to the peak, say).
    uint64_t scan_calls;
    uint64_t scan_words;
    uint64_t arena_bytes;
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
    n00b_atomic_store(&n00b_memperm_indeterminate, 0);
    n00b_atomic_store(&n00b_sentinel_scan_calls, 0);
    n00b_atomic_store(&n00b_sentinel_scan_words, 0);

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
        .indeterminate  = n00b_atomic_load(&n00b_memperm_indeterminate),
        .scan_calls     = n00b_atomic_load(&n00b_sentinel_scan_calls),
        .scan_words     = n00b_atomic_load(&n00b_sentinel_scan_words),
        .arena_bytes    = n00b_arena_size(arena),
    };

    printf("  %-8s wall %10llu ns | syscall probes %8llu | indeterminate %6llu | fastpath %8llu | scan bound %12llu\n",
           label,
           (unsigned long long)p.wall_ns,
           (unsigned long long)p.syscall_probes,
           (unsigned long long)p.indeterminate,
           (unsigned long long)p.fastpath_hits,
           (unsigned long long)p.scan_bound);
    printf("  %-8s guard scans %8llu | words walked %12llu | words/scan %8llu | arena %12llu B\n",
           "",
           (unsigned long long)p.scan_calls,
           (unsigned long long)p.scan_words,
           (unsigned long long)(p.scan_calls ? p.scan_words / p.scan_calls : 0),
           (unsigned long long)p.arena_bytes);
    return p;
}

// The big allocation is made in its own frame and the frame is then torn
// down, because a stack slot in main() would keep it alive: this test runs at
// -O0, main()'s locals get a fixed slot for the whole function, and the
// collector's own stack is scanned conservatively from the collect frame down
// through main()'s.  n00b#398's first version did `{ void *big = ...; }` in
// main() and the object survived every collect that followed -- copied in
// moving mode (primary used 524,304,896 B after the "reclaim"), retained in
// pin-all mode -- which is what n00b#406 measured.
static __attribute__((noinline)) void
allocate_and_drop_big(void)
{
    volatile uint8_t *big = n00b_alloc_array(uint8_t, BIG_BYTES);
    assert(big != nullptr);
    big[0]             = 1;
    big[BIG_BYTES - 1] = 1;
    // Returning drops the only reference: the slot is in THIS frame, and the
    // pointer never left a caller-saved register.
}

// Overwrite the stack region the dead frame (and any callee spill slots below
// main()) occupied, and clear the callee-saved registers, so nothing that
// looked like the big pointer can be found by the conservative scan.  The
// buffer is volatile so the store loop is not optimised away; 256 KB is far
// more than allocate_and_drop_big() plus n00b_alloc's own frames used.
static __attribute__((noinline)) void
scrub_dead_frames(void)
{
    volatile uint8_t junk[256 * 1024];
    for (size_t i = 0; i < sizeof(junk); i++) {
        junk[i] = 0;
    }
#if defined(__aarch64__)
    __asm__ volatile("" ::: "x19", "x20", "x21", "x22", "x23", "x24", "x25",
                     "x26", "x27", "x28", "memory");
#elif defined(__x86_64__)
    __asm__ volatile("" ::: "rbx", "r12", "r13", "r14", "r15", "memory");
#endif
    (void)junk[sizeof(junk) - 1];
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

    // One large allocation, then make it GENUINELY unreachable before the
    // reclaim collect.  See kill_big_allocation() for why that takes work,
    // and n00b#406 for what happens when it is skipped.
    allocate_and_drop_big();
    scrub_dead_frames();

    n00b_collect(arena); // reclaim it; only the high-water mark survives

    // The AFTER phase measures NOTHING unless the object actually died.  A
    // live 500 MB object is copied (moving GC) or retained (pin-all) on every
    // later collect, and that shows up as exactly the "arena stays at peak,
    // collect 50x slower" shape a hysteresis would -- which is how n00b#406
    // got filed against a bench whose big object was still reachable through
    // a dead stack slot.  Check the arena rather than the object: if the
    // object lived, its 500 MB is still mapped in here.
    uint64_t arena_after_reclaim = n00b_arena_size(arena);
    printf("  arena after the reclaim collect: %llu B\n",
           (unsigned long long)arena_after_reclaim);
    if (arena_after_reclaim >= BIG_BYTES) {
        printf("  [FAIL] the big allocation survived the reclaim collect: a"
               " stale root still reaches it, so AFTER would measure a live"
               " %llu MB object, not hysteresis\n",
               (unsigned long long)(BIG_BYTES >> 20));
        return 1;
    }

    phase_t after = measure("AFTER", arena);

    printf("\n  live set unchanged; only n00b_max_inline_alloc_len moved: %llu -> %llu\n",
           (unsigned long long)before.scan_bound,
           (unsigned long long)after.scan_bound);

    if (before.wall_ns > 0) {
        printf("  wall           %.2fx\n",
               (double)after.wall_ns / (double)before.wall_ns);
    }
    if (before.scan_words > 0) {
        printf("  words walked   %.2fx\n",
               (double)after.scan_words / (double)before.scan_words);
    }
    else {
        printf("  words walked   BEFORE was 0 -- after = %llu\n",
               (unsigned long long)after.scan_words);
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

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/gc_map.h"
#include "core/stw.h"
#include "core/atomic.h"

#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}

typedef struct {
    uint64_t value;
    void    *next;
} target_t;

// `saved` is itself a heap allocation with scan_kind=NONE so the
// conservative stack scan can't see pointer-shaped values stored in it
// and rewrite them.  Comparing backing[i] to a stack-local uint64_t
// array does NOT work — the stack scanner forwards any heap-pointer-
// shaped slot, including the "saved" snapshot, which masks the test.
static __attribute__((noinline)) uint64_t *
none_save_buffer(n00b_arena_t *arena, uint64_t n, uint64_t *src)
{
    uint64_t *buf = n00b_alloc_array_with_opts(uint64_t,
                                               n,
                                               &(n00b_alloc_opts_t){
                                                   .allocator = (n00b_allocator_t *)arena,
                                                   .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                               });
    memcpy(buf, src, n * sizeof(uint64_t));
    return buf;
}

// ============================================================================
// 1. scan_kind=NONE: pointer-shaped word in the backing store is NOT rewritten.
// ============================================================================

static __attribute__((noinline)) void
test_selective_none_inner(n00b_arena_t *arena)
{
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0001ULL;

    uint64_t *backing = n00b_alloc_array_with_opts(uint64_t,
                                                   4,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = (n00b_allocator_t *)arena,
                                                       .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                                   });
    backing[0] = (uint64_t)(uintptr_t)target; // pointer-shaped slot
    backing[1] = 42;
    backing[2] = 0xFEEDFACE00000000ULL; // far above any mmap range
    backing[3] = 0;

    uint64_t *saved = none_save_buffer(arena, 4, backing);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // Every slot retains its pre-collection bytes — including the
    // pointer-shaped slot[0], which the conservative scanner would
    // otherwise have rewritten.
    for (int i = 0; i < 4; ++i) {
        assert(backing[i] == saved[i]);
    }
    // Sanity: the live target was forwarded and reachable via the
    // rewritten stack pointer.  Its content survives.
    assert(target->value == 0xCAFE0001ULL);
    // The pre-GC value in backing[0] was the old target address; after
    // GC the stack `target` has been rewritten to the new address.
    // With scan_kind=NONE the slot still holds the OLD address, so it
    // must differ from the live pointer.
    assert(backing[0] != (uint64_t)(uintptr_t)target);
}

static void
test_selective_none(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    test_selective_none_inner(arena);
    printf("  [PASS] selective_none\n");
}

// ============================================================================
// 2. scan_kind=ALL: pointer slot IS rewritten to forwarded address.
// ============================================================================

static __attribute__((noinline)) void
test_selective_all_inner(n00b_arena_t *arena)
{
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0002ULL;

    uint64_t *backing = n00b_alloc_array_with_opts(uint64_t,
                                                   4,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = (n00b_allocator_t *)arena,
                                                       .scan_kind = N00B_GC_SCAN_KIND_ALL,
                                                   });
    backing[0] = (uint64_t)(uintptr_t)target;

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // After GC: target was forwarded to a new address.  Stack-scanned
    // 'target' was rewritten to the new address.  backing[0] should
    // also be rewritten to the same new address (scan_kind=ALL).
    assert(backing[0] == (uint64_t)(uintptr_t)target);
    assert(target->value == 0xCAFE0002ULL);
}

static void
test_selective_all(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    test_selective_all_inner(arena);
    printf("  [PASS] selective_all\n");
}

// ============================================================================
// 3. scan_kind=EVERY_OTHER: only even slots (0, 2, 4, …) get rewritten.
// ============================================================================

#define EO_HALF 8

static __attribute__((noinline)) void
test_selective_every_other_inner(n00b_arena_t *arena)
{
    target_t *targets[EO_HALF];
    for (int i = 0; i < EO_HALF; ++i) {
        targets[i]        = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
        targets[i]->value = 0x1000ULL + (uint64_t)i;
    }
    // A "decoy" pointer that lives in the heap.  Stored in odd slots so
    // that if EVERY_OTHER mistakenly visited them, the slot would get
    // rewritten — which we can detect.
    target_t *decoy = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    decoy->value    = 0xDEC0DE00ULL;

    uint64_t *backing = n00b_alloc_array_with_opts(uint64_t,
                                                   2 * EO_HALF,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = (n00b_allocator_t *)arena,
                                                       .scan_kind = N00B_GC_SCAN_KIND_EVERY_OTHER,
                                                   });

    for (int i = 0; i < EO_HALF; ++i) {
        backing[2 * i]     = (uint64_t)(uintptr_t)targets[i];
        backing[2 * i + 1] = (uint64_t)(uintptr_t)decoy; // odd slot — must stay OLD
    }

    uint64_t *saved = none_save_buffer(arena, 2 * EO_HALF, backing);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // Even slots: rewritten to forwarded targets (NEW address).
    // Odd slots: retain the OLD decoy address — i.e. they MUST NOT
    // equal the live `decoy` pointer, which has been rewritten to NEW.
    for (int i = 0; i < EO_HALF; ++i) {
        assert(backing[2 * i] == (uint64_t)(uintptr_t)targets[i]);
        assert(backing[2 * i + 1] == saved[2 * i + 1]);
        assert(backing[2 * i + 1] != (uint64_t)(uintptr_t)decoy);
        assert(targets[i]->value == 0x1000ULL + (uint64_t)i);
    }
    assert(decoy->value == 0xDEC0DE00ULL);
}

static void
test_selective_every_other_pointer(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);
    test_selective_every_other_inner(arena);
    printf("  [PASS] selective_every_other_pointer\n");
}

// ============================================================================
// 4. scan_kind=CALLBACK: callback marks word 5; only word 5 is rewritten.
// ============================================================================

static void
mark_word_5_cb(n00b_gc_map_t *m, void *user)
{
    (void)user;
    n00b_gc_map_mark(m, 5);
}

static __attribute__((noinline)) void
test_selective_callback_inner(n00b_arena_t *arena)
{
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0004ULL;
    target_t *decoy  = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    decoy->value     = 0xDEC0DE04ULL;

    uint64_t *backing = n00b_alloc_array_with_opts(uint64_t,
                                                   16,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = (n00b_allocator_t *)arena,
                                                       .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
                                                       .scan_cb   = mark_word_5_cb,
                                                   });

    for (int i = 0; i < 16; ++i) {
        backing[i] = (uint64_t)(uintptr_t)decoy; // every non-marked slot points at decoy
    }
    backing[5] = (uint64_t)(uintptr_t)target;

    uint64_t *saved = none_save_buffer(arena, 16, backing);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // Only word 5 visited by the GC; only word 5 rewritten.
    assert(backing[5] == (uint64_t)(uintptr_t)target);
    for (int i = 0; i < 16; ++i) {
        if (i != 5) {
            assert(backing[i] == saved[i]);
            assert(backing[i] != (uint64_t)(uintptr_t)decoy);
        }
    }
    assert(target->value == 0xCAFE0004ULL);
    assert(decoy->value == 0xDEC0DE04ULL);
}

static void
test_selective_callback(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);
    test_selective_callback_inner(arena);
    printf("  [PASS] selective_callback\n");
}

// ============================================================================
// 5. inline_only_callback_fallback: CALLBACK + inline-only allocator falls
//    back to DEFAULT because CALLBACK metadata cannot survive forwarding
//    without the OOB metadata path.
// ============================================================================

static void
dummy_cb(n00b_gc_map_t *m, void *user)
{
    (void)m;
    (void)user;
}

static void
test_inline_only_callback_fallback(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size   = 4096,
                                          .use_gc = true,
                                          .no_map = true);
    assert(arena != nullptr);
    assert(((n00b_allocator_t *)arena)->metadata_pool == nullptr);

    uint64_t *value = n00b_alloc_with_opts(
        uint64_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = dummy_cb,
        });
    assert(value != nullptr);
    *value = 0x1A11BACCE55ULL;

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    assert(*value == 0x1A11BACCE55ULL);
    printf("  [PASS] inline_only_callback_fallback\n");
}

// ============================================================================
// 6. bitmap_clearing: two consecutive GCs produce identical results.  Proves
//    the VLA bitmap is properly zero-initialised on each dispatch call.
// ============================================================================

static void
mark_5_and_10_cb(n00b_gc_map_t *m, void *user)
{
    (void)user;
    n00b_gc_map_mark(m, 5);
    n00b_gc_map_mark(m, 10);
}

static __attribute__((noinline)) void
test_bitmap_clearing_inner(n00b_arena_t *arena)
{
    target_t *t5    = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target_t *t10   = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target_t *decoy = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    t5->value       = 0xAAAA0005ULL;
    t10->value      = 0xAAAA000AULL;
    decoy->value    = 0xAAAADEC0ULL;

    uint64_t *backing = n00b_alloc_array_with_opts(uint64_t,
                                                   16,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = (n00b_allocator_t *)arena,
                                                       .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
                                                       .scan_cb   = mark_5_and_10_cb,
                                                   });
    for (int i = 0; i < 16; ++i) {
        backing[i] = (uint64_t)(uintptr_t)decoy;
    }
    backing[5]  = (uint64_t)(uintptr_t)t5;
    backing[10] = (uint64_t)(uintptr_t)t10;

    uint64_t *saved = none_save_buffer(arena, 16, backing);

    for (int pass = 0; pass < 2; ++pass) {
        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();

        assert(backing[5]  == (uint64_t)(uintptr_t)t5);
        assert(backing[10] == (uint64_t)(uintptr_t)t10);
        assert(t5->value  == 0xAAAA0005ULL);
        assert(t10->value == 0xAAAA000AULL);

        for (int i = 0; i < 16; ++i) {
            if (i != 5 && i != 10) {
                assert(backing[i] == saved[i]);
                assert(backing[i] != (uint64_t)(uintptr_t)decoy);
            }
        }
    }
}

static void
test_bitmap_clearing(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);
    test_bitmap_clearing_inner(arena);
    printf("  [PASS] bitmap_clearing\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running gc_selective_scan tests...\n");

    test_selective_none();
    test_selective_all();
    test_selective_every_other_pointer();
    test_selective_callback();
    test_inline_only_callback_fallback();
    test_bitmap_clearing();

    printf("All gc_selective_scan tests passed.\n");
    n00b_shutdown();
    return 0;
}

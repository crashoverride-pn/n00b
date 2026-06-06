#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/gc.h"

// ============================================================================
// Helpers
// ============================================================================

// Walk the runtime gc_roots list and return the index of the entry whose
// addr matches `target`, or -1 if not present.
static int64_t
find_root_index(void *target)
{
    n00b_runtime_t *rt  = n00b_get_runtime();
    size_t          len = n00b_list_len(rt->gc_roots);

    for (size_t i = 0; i < len; i++) {
        n00b_gc_root_t entry = n00b_list_get(rt->gc_roots, i);
        if (entry.addr == target) {
            return (int64_t)i;
        }
    }
    return -1;
}

static size_t
count_roots_with_addr(void *target)
{
    n00b_runtime_t *rt  = n00b_get_runtime();
    size_t          len = n00b_list_len(rt->gc_roots);
    size_t          n   = 0;

    for (size_t i = 0; i < len; i++) {
        n00b_gc_root_t entry = n00b_list_get(rt->gc_roots, i);
        if (entry.addr == target) {
            n++;
        }
    }
    return n;
}

// ============================================================================
// 1. Basic batch registration
// ============================================================================

static void
test_batch_basic(void)
{
    // Stack-allocated slots used as the "managed" pointers.  We never
    // dereference these via the GC — the test only inspects the
    // registration list contents.
    void *slot_a = nullptr;
    void *slot_b = nullptr;
    void *slot_c = nullptr;

    // Stack-allocated table — NOT a TU-scope static, which would
    // auto-register via ncc's --ncc-auto-gc-roots transform and pollute
    // the test fixture.
    n00b_gc_root_t table[3] = {
        {.addr = &slot_a, .num_words = 1},
        {.addr = &slot_b, .num_words = 1},
        {.addr = &slot_c, .num_words = 1},
    };

    n00b_gc_register_roots(table, 3);

    assert(find_root_index(&slot_a) >= 0);
    assert(find_root_index(&slot_b) >= 0);
    assert(find_root_index(&slot_c) >= 0);

    _n00b_gc_unregister_root(&slot_a);
    _n00b_gc_unregister_root(&slot_b);
    _n00b_gc_unregister_root(&slot_c);

    printf("  [PASS] batch basic\n");
}

// ============================================================================
// 2. count == 0 is a clean no-op
// ============================================================================

static void
test_batch_zero_count(void)
{
    n00b_runtime_t *rt     = n00b_get_runtime();
    size_t          before = n00b_list_len(rt->gc_roots);

    void          *slot = nullptr;
    n00b_gc_root_t one  = {.addr = &slot, .num_words = 1};

    // Pass a real table pointer but count = 0 — must touch nothing.
    n00b_gc_register_roots(&one, 0);

    size_t after = n00b_list_len(rt->gc_roots);
    assert(after == before);
    assert(find_root_index(&slot) < 0);

    // nullptr table is also tolerated regardless of count.
    n00b_gc_register_roots(nullptr, 0);
    assert(n00b_list_len(rt->gc_roots) == before);

    printf("  [PASS] batch zero count\n");
}

// ============================================================================
// 3. Address dedup: same addr twice does not add a duplicate
// ============================================================================

static void
test_batch_dedup_same_size(void)
{
    void *slot = nullptr;

    n00b_gc_root_t table[2] = {
        {.addr = &slot, .num_words = 4},
        {.addr = &slot, .num_words = 4},
    };

    n00b_gc_register_roots(table, 2);

    // Exactly one entry should exist for this address.
    assert(count_roots_with_addr(&slot) == 1);

    int64_t idx = find_root_index(&slot);
    assert(idx >= 0);
    n00b_runtime_t *rt    = n00b_get_runtime();
    n00b_gc_root_t  entry = n00b_list_get(rt->gc_roots, (size_t)idx);
    assert(entry.num_words == 4);

    // Re-batch the same address again — still no duplicate, still num_words=4.
    n00b_gc_register_roots(table, 1);
    assert(count_roots_with_addr(&slot) == 1);

    _n00b_gc_unregister_root(&slot);

    printf("  [PASS] batch dedup (same size)\n");
}

// ============================================================================
// 4. Address dedup with size upgrade: re-registering with a larger
//    num_words must update the existing entry's num_words in place.
// ============================================================================

static void
test_batch_dedup_size_upgrade(void)
{
    void *slot = nullptr;

    // First batch: register at num_words = 2.
    n00b_gc_root_t small[1] = {
        {.addr = &slot, .num_words = 2},
    };
    n00b_gc_register_roots(small, 1);

    assert(count_roots_with_addr(&slot) == 1);
    int64_t idx = find_root_index(&slot);
    assert(idx >= 0);
    n00b_runtime_t *rt    = n00b_get_runtime();
    n00b_gc_root_t  entry = n00b_list_get(rt->gc_roots, (size_t)idx);
    assert(entry.num_words == 2);

    // Second batch: larger num_words for the same addr must upgrade.
    n00b_gc_root_t larger[1] = {
        {.addr = &slot, .num_words = 8},
    };
    n00b_gc_register_roots(larger, 1);

    assert(count_roots_with_addr(&slot) == 1);
    idx = find_root_index(&slot);
    assert(idx >= 0);
    entry = n00b_list_get(rt->gc_roots, (size_t)idx);
    assert(entry.num_words == 8);

    // Third batch: smaller num_words must NOT shrink the existing entry
    // (matches _n00b_gc_register_root behavior).
    n00b_gc_root_t smaller_again[1] = {
        {.addr = &slot, .num_words = 1},
    };
    n00b_gc_register_roots(smaller_again, 1);

    assert(count_roots_with_addr(&slot) == 1);
    idx   = find_root_index(&slot);
    entry = n00b_list_get(rt->gc_roots, (size_t)idx);
    assert(entry.num_words == 8);

    _n00b_gc_unregister_root(&slot);

    printf("  [PASS] batch dedup (size upgrade)\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running n00b_gc_register_roots API tests...\n");

    test_batch_basic();
    test_batch_zero_count();
    test_batch_dedup_same_size();
    test_batch_dedup_size_upgrade();

    printf("All n00b_gc_register_roots API tests passed.\n");
    n00b_shutdown();
    return 0;
}

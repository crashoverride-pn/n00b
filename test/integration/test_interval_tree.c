#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/interval_tree.h"

// Convenience alias — n00b_result_get returns void * now.
#define inode_t n00b_interval_node_t(void *)

// ============================================================================
// 1. Create empty tree
// ============================================================================

static void
test_create_empty(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    assert(tree != nullptr);
    assert(tree->root == nullptr);

    printf("  [PASS] create_empty\n");
}

// ============================================================================
// 2. Single insert — insert [10, 20] and find it
// ============================================================================

static void
test_single_insert(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    auto r = n00b_interval_insert(tree, 10, 20, (void *)0xA);
    assert(n00b_result_is_ok(r));
    inode_t *node = n00b_result_get(r);
    assert(node != nullptr);
    assert(node->low == 10);
    assert(node->high == 20);
    assert(node->data == (void *)0xA);

    auto sr = n00b_interval_search_any(tree, 10, 20);
    assert(n00b_result_is_ok(sr));
    inode_t *found = n00b_result_get(sr);
    assert(found != nullptr);
    assert(found->low == 10);

    printf("  [PASS] single_insert\n");
}

// ============================================================================
// 3. Multi insert — 5 non-overlapping intervals, search_any finds each
// ============================================================================

static void
test_multi_insert(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    uint64_t intervals[][2] = {
        {10, 20},
        {30, 40},
        {50, 60},
        {70, 80},
        {90, 100},
    };

    for (int i = 0; i < 5; i++) {
        auto r = n00b_interval_insert(tree, intervals[i][0], intervals[i][1],
                                       (void *)(uintptr_t)i);
        assert(n00b_result_is_ok(r));
    }

    for (int i = 0; i < 5; i++) {
        auto sr = n00b_interval_search_any(tree,
                                            intervals[i][0],
                                            intervals[i][1]);
        assert(n00b_result_is_ok(sr));
        inode_t *found = n00b_result_get(sr);
        assert(found != nullptr);
        assert(found->low == intervals[i][0]);
        assert(found->high == intervals[i][1]);
    }

    printf("  [PASS] multi_insert\n");
}

// ============================================================================
// 4. Overlap search — overlapping ranges; search returns correct count
// ============================================================================

static void
test_overlap_search(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    // Insert overlapping intervals: [10,30], [20,40], [25,35]
    n00b_interval_insert(tree, 10, 30, nullptr);
    n00b_interval_insert(tree, 20, 40, nullptr);
    n00b_interval_insert(tree, 25, 35, nullptr);

    n00b_stack_t(void *) results = n00b_stack_new(void *);
    auto r = n00b_interval_search(tree, 22, 28, &results);
    assert(n00b_result_is_ok(r));

    // All three should overlap with [22, 28]
    assert(n00b_stack_len(results) == 3);

    n00b_stack_free(results);
    printf("  [PASS] overlap_search\n");
}

// ============================================================================
// 5. Ordered search — results sorted by low bound
// ============================================================================

static void
test_ordered_search(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    // Insert in non-sorted order
    n00b_interval_insert(tree, 30, 50, nullptr);
    n00b_interval_insert(tree, 10, 40, nullptr);
    n00b_interval_insert(tree, 20, 45, nullptr);

    n00b_stack_t(void *) results = n00b_stack_new(void *);
    auto r = n00b_interval_search_ordered(tree, 15, 35, &results);
    assert(n00b_result_is_ok(r));

    size_t count = n00b_stack_len(results);
    assert(count == 3);

    // Verify ordering by low bound
    uint64_t prev_low = 0;
    n00b_stack_foreach(results, p) {
        inode_t *node = (inode_t *)*p;
        assert(node->low >= prev_low);
        prev_low = node->low;
    }

    n00b_stack_free(results);
    printf("  [PASS] ordered_search\n");
}

// ============================================================================
// 6. Delete — remove a node; verify search_any no longer finds it
// ============================================================================

static void
test_delete(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    auto r1 = n00b_interval_insert(tree, 10, 20, (void *)1);
    auto r2 = n00b_interval_insert(tree, 30, 40, (void *)2);
    auto r3 = n00b_interval_insert(tree, 50, 60, (void *)3);

    assert(n00b_result_is_ok(r1));
    assert(n00b_result_is_ok(r2));
    assert(n00b_result_is_ok(r3));

    inode_t *mid = n00b_result_get(r2);

    // Delete [30, 40]
    auto dr = n00b_interval_delete(tree, mid);
    assert(n00b_result_is_ok(dr));

    // Should not find [30, 40] anymore
    auto sr = n00b_interval_search_any(tree, 30, 40);
    assert(n00b_result_is_ok(sr));
    inode_t *found = n00b_result_get(sr);
    assert(found == nullptr);

    // [10, 20] and [50, 60] should still be there
    auto sr1 = n00b_interval_search_any(tree, 10, 20);
    assert(n00b_result_is_ok(sr1));
    assert(n00b_result_get(sr1) != nullptr);

    auto sr3 = n00b_interval_search_any(tree, 50, 60);
    assert(n00b_result_is_ok(sr3));
    assert(n00b_result_get(sr3) != nullptr);

    printf("  [PASS] delete\n");
}

// ============================================================================
// 7. Min / max — match expected values
// ============================================================================

static void
test_min_max(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    n00b_interval_insert(tree, 50, 60, nullptr);
    n00b_interval_insert(tree, 10, 20, nullptr);
    n00b_interval_insert(tree, 80, 100, nullptr);

    auto min_r = n00b_interval_min(tree);
    assert(n00b_result_is_ok(min_r));
    assert(n00b_result_get(min_r) == 10);

    auto max_r = n00b_interval_max(tree);
    assert(n00b_result_is_ok(max_r));
    assert(n00b_result_get(max_r) == 100);

    printf("  [PASS] min_max\n");
}

// ============================================================================
// 8. Next low — finds the correct successor
// ============================================================================

static void
test_next_low(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    n00b_interval_insert(tree, 10, 20, nullptr);
    n00b_interval_insert(tree, 30, 40, nullptr);
    n00b_interval_insert(tree, 50, 60, nullptr);

    // next_low(25) should find [30, 40]
    auto r = n00b_interval_next_low(tree, 25);
    assert(n00b_result_is_ok(r));
    inode_t *node = n00b_result_get(r);
    assert(node != nullptr);
    assert(node->low == 30);

    // next_low(10) should find [10, 20] (exact match)
    auto r2 = n00b_interval_next_low(tree, 10);
    assert(n00b_result_is_ok(r2));
    inode_t *node2 = n00b_result_get(r2);
    assert(node2 != nullptr);
    assert(node2->low == 10);

    printf("  [PASS] next_low\n");
}

// ============================================================================
// 9. Not found — search a gap between intervals returns nullptr
// ============================================================================

static void
test_not_found(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    n00b_interval_insert(tree, 10, 20, nullptr);
    n00b_interval_insert(tree, 50, 60, nullptr);

    // Search gap [25, 35] — no overlap
    auto sr = n00b_interval_search_any(tree, 25, 35);
    assert(n00b_result_is_ok(sr));
    inode_t *found = n00b_result_get(sr);
    assert(found == nullptr);

    printf("  [PASS] not_found\n");
}

// ============================================================================
// 10. Stress — insert 500, delete half, verify remaining
// ============================================================================

static void
test_stress(void)
{
    n00b_allocator_t *alloc = n00b_default_allocator();

    n00b_interval_tree_t(void *) *tree = n00b_alloc_with_opts(
        n00b_interval_tree_t(void *), &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_interval_tree_init(tree, .allocator = alloc);

    inode_t *nodes[500];

    for (int i = 0; i < 500; i++) {
        uint64_t low  = (uint64_t)i * 100;
        uint64_t high = low + 50;
        auto     r    = n00b_interval_insert(tree, low, high, (void *)(uintptr_t)i);
        assert(n00b_result_is_ok(r));
        nodes[i] = n00b_result_get(r);
    }

    // Delete even-indexed nodes
    for (int i = 0; i < 500; i += 2) {
        auto dr = n00b_interval_delete(tree, nodes[i]);
        assert(n00b_result_is_ok(dr));
    }

    // Verify odd-indexed remain findable
    for (int i = 1; i < 500; i += 2) {
        uint64_t low  = (uint64_t)i * 100;
        uint64_t high = low + 50;
        auto     sr   = n00b_interval_search_any(tree, low, high);
        assert(n00b_result_is_ok(sr));
        inode_t *found = n00b_result_get(sr);
        assert(found != nullptr);
        assert(found->low == low);
    }

    // Verify even-indexed are gone
    for (int i = 0; i < 500; i += 2) {
        uint64_t low  = (uint64_t)i * 100;
        uint64_t high = low + 50;
        auto     sr   = n00b_interval_search_any(tree, low, high);
        assert(n00b_result_is_ok(sr));
        inode_t *found = n00b_result_get(sr);
        assert(found == nullptr);
    }

    printf("  [PASS] stress\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running interval tree tests...\n");

    test_create_empty();
    test_single_insert();
    test_multi_insert();
    test_overlap_search();
    test_ordered_search();
    test_delete();
    test_min_max();
    test_next_low();
    test_not_found();
    test_stress();

    printf("All interval tree tests passed.\n");
    return 0;
}

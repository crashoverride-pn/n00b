#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/array.h"

static bool
alloc_is_no_scan(void *ptr)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(ptr);

    if (info.kind == n00b_alloc_inline) {
        return info.hdr.in_line->scan_kind == N00B_GC_SCAN_KIND_NONE &&
               info.hdr.in_line->no_scan;
    }
    if (info.kind == n00b_alloc_oob) {
        return info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_NONE &&
               info.hdr.oob->no_scan;
    }

    return false;
}

// ============================================================================
// 1. n00b_array_set updates len correctly (off-by-one regression test)
// ============================================================================

static void
test_array_set_len(void)
{
    n00b_array_t(int) arr = n00b_array_new(int, 16);

    // Setting index 0 on an empty array should make len = 1, not 0.
    n00b_array_set(arr, 0, 42);
    assert(n00b_array_len(arr) == 1);

    // Setting index 3 should make len = 4.
    n00b_array_set(arr, 3, 99);
    assert(n00b_array_len(arr) == 4);

    // Setting index 1 (already within len) should not change len.
    n00b_array_set(arr, 1, 7);
    assert(n00b_array_len(arr) == 4);

    // Verify values.
    assert(n00b_array_get(arr, 0) == 42);
    assert(n00b_array_get(arr, 1) == 7);
    assert(n00b_array_get(arr, 3) == 99);

    n00b_array_free(arr);
    printf("  [PASS] array_set_len\n");
}

// ============================================================================
// 2. n00b_init is idempotent (double-init guard)
// ============================================================================

static void
test_init_idempotent(n00b_runtime_t *rt, int argc, char **argv)
{
    // Second call should be a no-op (returns immediately).
    n00b_init(rt, argc, argv);

    // Runtime should still be functional.
    n00b_array_t(int) arr = n00b_array_new(int, 4);
    n00b_array_set(arr, 0, 1);
    assert(n00b_array_get(arr, 0) == 1);
    n00b_array_free(arr);

    printf("  [PASS] init_idempotent\n");
}

// ============================================================================
// 3. n00b_array_clone preserves backing scan metadata
// ============================================================================

static void
test_array_clone_preserves_no_scan(void)
{
    n00b_array_t(uint64_t) arr =
        n00b_array_new(uint64_t, 4, .scan_kind = N00B_GC_SCAN_KIND_NONE);

    n00b_array_set(arr, 0, 10);
    n00b_array_set(arr, 1, 20);

    n00b_array_t(uint64_t) copy = n00b_array_clone(arr);

    assert(copy.scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(alloc_is_no_scan(copy.data));
    assert(n00b_array_len(copy) == 2);
    assert(n00b_array_get(copy, 0) == 10);
    assert(n00b_array_get(copy, 1) == 20);

    n00b_array_free(arr);
    n00b_array_free(copy);
    printf("  [PASS] array_clone_preserves_no_scan\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running array tests...\n");

    test_array_set_len();
    test_init_idempotent(&runtime, argc, argv);
    test_array_clone_preserves_no_scan();

    printf("All array tests passed.\n");
    n00b_shutdown();
    return 0;
}

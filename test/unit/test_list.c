#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/list.h"

// ============================================================================
// Helpers
// ============================================================================

static bool
alloc_is_no_scan(void *ptr)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(ptr, .scan_for_header = true);

    if (info.kind == n00b_alloc_inline) {
        return info.hdr.in_line->no_scan
            || info.hdr.in_line->scan_kind == N00B_GC_SCAN_KIND_NONE;
    }
    if (info.kind == n00b_alloc_oob) {
        return info.hdr.oob->no_scan
            || info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_NONE;
    }

    return false;
}

static int
int_cmp(const void *a, const void *b)
{
    int ia = *(const int *)a;
    int ib = *(const int *)b;

    return (ia > ib) - (ia < ib);
}

// ============================================================================
// 1. Construction
// ============================================================================

static void
test_construction(void)
{
    n00b_list_t(int) a = n00b_list_new(int);
    assert(n00b_list_len(a) == 0);
    assert(n00b_list_cap(a) == N00B_DEFAULT_LIST_SZ);
    n00b_list_free(a);

    n00b_list_t(int) b = n00b_list_new_cap(int, 100);
    assert(n00b_list_len(b) == 0);
    // cap must be a power of 2 >= 100
    size_t cap = n00b_list_cap(b);
    assert(cap >= 100);
    assert((cap & (cap - 1)) == 0); // power of 2
    n00b_list_free(b);

    printf("  [PASS] construction\n");
}

// ============================================================================
// 2. Push / Pop (back)
// ============================================================================

static void
test_push_pop_back(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);

    n00b_list_push(lst, 10);
    n00b_list_push(lst, 20);
    n00b_list_push(lst, 30);
    assert(n00b_list_len(lst) == 3);

    assert(n00b_option_get(n00b_list_pop(int, lst)) == 30);
    assert(n00b_option_get(n00b_list_pop(int, lst)) == 20);
    assert(n00b_option_get(n00b_list_pop(int, lst)) == 10);
    assert(n00b_list_len(lst) == 0);

    n00b_list_free(lst);
    printf("  [PASS] push/pop back\n");
}

// ============================================================================
// 3. Get / Set
// ============================================================================

static void
test_get_set(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);

    n00b_list_push(lst, 100);
    n00b_list_push(lst, 200);
    n00b_list_push(lst, 300);

    assert(n00b_list_get(lst, 0) == 100);
    assert(n00b_list_get(lst, 1) == 200);
    assert(n00b_list_get(lst, 2) == 300);

    n00b_list_set(lst, 1, 999);
    assert(n00b_list_get(lst, 1) == 999);

    n00b_list_free(lst);
    printf("  [PASS] get/set\n");
}

// ============================================================================
// 4. Push / Pop (front)
// ============================================================================

static void
test_push_pop_front(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);

    n00b_list_push_front(lst, 1);
    n00b_list_push_front(lst, 2);
    n00b_list_push_front(lst, 3);

    // Order should be: 3, 2, 1
    assert(n00b_list_get(lst, 0) == 3);
    assert(n00b_list_get(lst, 1) == 2);
    assert(n00b_list_get(lst, 2) == 1);

    assert(n00b_option_get(n00b_list_pop_front(int, lst)) == 3);
    assert(n00b_option_get(n00b_list_pop_front(int, lst)) == 2);
    assert(n00b_option_get(n00b_list_pop_front(int, lst)) == 1);
    assert(n00b_list_len(lst) == 0);

    n00b_list_free(lst);
    printf("  [PASS] push/pop front\n");
}

// ============================================================================
// 5. Insert / Delete (single)
// ============================================================================

static void
test_insert_delete_single(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);

    n00b_list_push(lst, 10);
    n00b_list_push(lst, 30);

    // Insert 20 at index 1 → [10, 20, 30]
    n00b_list_insert(lst, 1, 20);
    assert(n00b_list_len(lst) == 3);
    assert(n00b_list_get(lst, 0) == 10);
    assert(n00b_list_get(lst, 1) == 20);
    assert(n00b_list_get(lst, 2) == 30);

    // Delete at index 1 → [10, 30], returns 20
    int removed = n00b_list_delete(lst, 1);
    assert(removed == 20);
    assert(n00b_list_len(lst) == 2);
    assert(n00b_list_get(lst, 0) == 10);
    assert(n00b_list_get(lst, 1) == 30);

    n00b_list_free(lst);
    printf("  [PASS] insert/delete single\n");
}

// ============================================================================
// 6. Insert list
// ============================================================================

static void
test_insert_list(void)
{
    n00b_list_t(int) dst = n00b_list_new(int);
    n00b_list_push(dst, 1);
    n00b_list_push(dst, 5);

    n00b_list_t(int) src = n00b_list_new(int);
    n00b_list_push(src, 2);
    n00b_list_push(src, 3);
    n00b_list_push(src, 4);

    // Insert src at index 1 → [1, 2, 3, 4, 5]
    n00b_list_insert_list(dst, 1, src);
    assert(n00b_list_len(dst) == 5);
    for (int i = 0; i < 5; i++) {
        assert(n00b_list_get(dst, i) == i + 1);
    }

    n00b_list_free(dst);
    n00b_list_free(src);
    printf("  [PASS] insert list\n");
}

// ============================================================================
// 7. Delete range
// ============================================================================

static void
test_delete_range(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    for (int i = 0; i < 10; i++) {
        n00b_list_push(lst, i);
    }

    // Remove indices 3..6 (count=4) → [0,1,2, 7,8,9]
    n00b_list_delete_range(lst, 3, 4);
    assert(n00b_list_len(lst) == 6);
    assert(n00b_list_get(lst, 0) == 0);
    assert(n00b_list_get(lst, 1) == 1);
    assert(n00b_list_get(lst, 2) == 2);
    assert(n00b_list_get(lst, 3) == 7);
    assert(n00b_list_get(lst, 4) == 8);
    assert(n00b_list_get(lst, 5) == 9);

    n00b_list_free(lst);
    printf("  [PASS] delete range\n");
}

// ============================================================================
// 8. Concat
// ============================================================================

static void
test_concat(void)
{
    n00b_list_t(int) a = n00b_list_new(int);
    n00b_list_push(a, 1);
    n00b_list_push(a, 2);

    n00b_list_t(int) b = n00b_list_new(int);
    n00b_list_push(b, 3);
    n00b_list_push(b, 4);

    n00b_list_t(int) c = n00b_list_concat(a, b);
    assert(n00b_list_len(c) == 4);
    assert(n00b_list_get(c, 0) == 1);
    assert(n00b_list_get(c, 1) == 2);
    assert(n00b_list_get(c, 2) == 3);
    assert(n00b_list_get(c, 3) == 4);

    // Originals are unchanged
    assert(n00b_list_len(a) == 2);
    assert(n00b_list_len(b) == 2);

    n00b_list_free(a);
    n00b_list_free(b);
    n00b_list_free(c);
    printf("  [PASS] concat\n");
}

// ============================================================================
// 9. Find
// ============================================================================

static void
test_find(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    n00b_list_push(lst, 10);
    n00b_list_push(lst, 20);
    n00b_list_push(lst, 30);

    assert(n00b_option_get(n00b_list_find(lst, 20)) == 1);
    assert(n00b_option_get(n00b_list_find(lst, 30)) == 2);
    assert(!n00b_option_is_set(n00b_list_find(lst, 99)));

    n00b_list_free(lst);
    printf("  [PASS] find\n");
}

// ============================================================================
// 10. Sort
// ============================================================================

static void
test_sort(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    n00b_list_push(lst, 50);
    n00b_list_push(lst, 10);
    n00b_list_push(lst, 40);
    n00b_list_push(lst, 20);
    n00b_list_push(lst, 30);

    n00b_list_sort(lst, int_cmp);
    for (int i = 0; i < 5; i++) {
        assert(n00b_list_get(lst, i) == (i + 1) * 10);
    }

    n00b_list_free(lst);
    printf("  [PASS] sort\n");
}

// ============================================================================
// 11. Remove all by value
// ============================================================================

static void
test_remove_all(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    n00b_list_push(lst, 1);
    n00b_list_push(lst, 2);
    n00b_list_push(lst, 3);
    n00b_list_push(lst, 2);
    n00b_list_push(lst, 4);
    n00b_list_push(lst, 2);

    size_t removed = n00b_list_remove_all(lst, 2);
    assert(removed == 3);
    assert(n00b_list_len(lst) == 3);
    assert(n00b_list_get(lst, 0) == 1);
    assert(n00b_list_get(lst, 1) == 3);
    assert(n00b_list_get(lst, 2) == 4);

    // Remove value that doesn't exist
    removed = n00b_list_remove_all(lst, 99);
    assert(removed == 0);
    assert(n00b_list_len(lst) == 3);

    n00b_list_free(lst);
    printf("  [PASS] remove all\n");
}

// ============================================================================
// 12. Dynamic growth
// ============================================================================

static void
test_dynamic_growth(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);

    for (int i = 0; i < 1000; i++) {
        n00b_list_push(lst, i);
    }

    assert(n00b_list_len(lst) == 1000);
    size_t cap = n00b_list_cap(lst);
    assert(cap >= 1000);
    assert((cap & (cap - 1)) == 0); // power of 2

    // Verify all values
    for (int i = 0; i < 1000; i++) {
        assert(n00b_list_get(lst, i) == i);
    }

    n00b_list_free(lst);
    printf("  [PASS] dynamic growth\n");
}

// ============================================================================
// 13. Clone
// ============================================================================

static void
test_clone(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    n00b_list_push(lst, 10);
    n00b_list_push(lst, 20);
    n00b_list_push(lst, 30);

    n00b_list_t(int) cpy = n00b_list_clone(lst);
    assert(n00b_list_len(cpy) == 3);
    assert(n00b_list_get(cpy, 0) == 10);
    assert(n00b_list_get(cpy, 1) == 20);
    assert(n00b_list_get(cpy, 2) == 30);

    // Mutating clone doesn't affect original
    n00b_list_set(cpy, 0, 999);
    assert(n00b_list_get(lst, 0) == 10);
    assert(n00b_list_get(cpy, 0) == 999);

    n00b_list_free(lst);
    n00b_list_free(cpy);
    printf("  [PASS] clone\n");
}

// ============================================================================
// 14. Foreach
// ============================================================================

static void
test_foreach(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    n00b_list_push(lst, 1);
    n00b_list_push(lst, 2);
    n00b_list_push(lst, 3);

    int sum   = 0;
    int count = 0;

    n00b_list_foreach(lst, p) {
        sum += *p;
        count++;
    }

    assert(count == 3);
    assert(sum == 6);

    n00b_list_free(lst);
    printf("  [PASS] foreach\n");
}

// ============================================================================
// 15. String list (char *)
// ============================================================================

static void
test_string_list(void)
{
    n00b_list_t(char *) lst = n00b_list_new(char *);

    char *hello = "hello";
    char *world = "world";

    n00b_list_push(lst, hello);
    n00b_list_push(lst, world);

    assert(n00b_list_len(lst) == 2);
    assert(n00b_list_get(lst, 0) == hello);
    assert(n00b_list_get(lst, 1) == world);
    assert(strcmp(n00b_list_get(lst, 0), "hello") == 0);
    assert(strcmp(n00b_list_get(lst, 1), "world") == 0);

    assert(n00b_option_get(n00b_list_find(lst, hello)) == 0);
    assert(n00b_option_get(n00b_list_find(lst, world)) == 1);

    n00b_list_free(lst);
    printf("  [PASS] string list\n");
}

// ============================================================================
// 16. List-to-array preserves scan metadata
// ============================================================================

static void
test_list_to_array_preserves_no_scan(void)
{
    n00b_list_t(uint64_t) lst =
        n00b_list_new(uint64_t, .scan_kind = N00B_GC_SCAN_KIND_NONE);

    n00b_list_push(lst, 10);
    n00b_list_push(lst, 20);

    n00b_array_t(uint64_t) arr = n00b_list_to_array(uint64_t, lst);

    assert(arr.scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(alloc_is_no_scan(arr.data));
    assert(n00b_array_len(arr) == 2);
    assert(n00b_array_get(arr, 0) == 10);
    assert(n00b_array_get(arr, 1) == 20);

    n00b_array_free(arr);
    printf("  [PASS] list_to_array_preserves_no_scan\n");
}

// ============================================================================
// Main
// ============================================================================
// Pop empty returns none
// ============================================================================

static void
test_pop_empty(void)
{
    n00b_list_t(int) lst = n00b_list_new(int);
    assert(!n00b_option_is_set(n00b_list_pop(int, lst)));
    assert(!n00b_option_is_set(n00b_list_pop_front(int, lst)));
    n00b_list_free(lst);
    printf("  [PASS] pop empty\n");
}

// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running list tests...\n");

    test_construction();
    test_push_pop_back();
    test_pop_empty();
    test_get_set();
    test_push_pop_front();
    test_insert_delete_single();
    test_insert_list();
    test_delete_range();
    test_concat();
    test_find();
    test_sort();
    test_remove_all();
    test_dynamic_growth();
    test_clone();
    test_foreach();
    test_string_list();
    test_list_to_array_preserves_no_scan();

    printf("All list tests passed.\n");
    n00b_shutdown();
    return 0;
}

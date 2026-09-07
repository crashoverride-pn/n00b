#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "adt/heap.h"

static int
int_min_cmp(const void *a, const void *b)
{
    int ai = *(const int *)a, bi = *(const int *)b;
    return (ai > bi) - (ai < bi);
}

static int
int_max_cmp(const void *a, const void *b)
{
    int ai = *(const int *)a, bi = *(const int *)b;
    return (ai < bi) - (ai > bi);
}

// Insert an unsorted batch, drain via pop, ensure ascending order out of a
// min-heap and the inverse out of a max-heap.
static void
test_heap_drain_sorted(void)
{
    int input[] = {5, 1, 9, 3, 7, 2, 8, 4, 6, 0};
    int n       = sizeof(input) / sizeof(input[0]);

    n00b_heap_t(int) min = n00b_heap_new(int, int_min_cmp);
    for (int i = 0; i < n; i++) n00b_heap_push(min, input[i]);
    assert(n00b_heap_len(min) == (size_t)n);
    int prev = -1;
    for (int i = 0; i < n; i++) {
        int v;
        assert(n00b_heap_pop(min, &v));
        assert(v >= prev);
        prev = v;
    }
    assert(n00b_heap_len(min) == 0);
    int discard;
    assert(!n00b_heap_pop(min, &discard));

    n00b_heap_t(int) max = n00b_heap_new(int, int_max_cmp);
    for (int i = 0; i < n; i++) n00b_heap_push(max, input[i]);
    int prev_max = 1000;
    for (int i = 0; i < n; i++) {
        int v;
        assert(n00b_heap_pop(max, &v));
        assert(v <= prev_max);
        prev_max = v;
    }
}

// peek returns the root without removing it; on empty it yields the
// zero-initialised element.
static void
test_heap_peek(void)
{
    n00b_heap_t(int) h = n00b_heap_new(int, int_min_cmp);
    assert(n00b_heap_peek(h) == 0);
    n00b_heap_push(h, 42);
    n00b_heap_push(h, 7);
    n00b_heap_push(h, 99);
    assert(n00b_heap_peek(h) == 7);
    assert(n00b_heap_len(h) == 3);
    int v;
    n00b_heap_pop(h, &v);
    assert(v == 7);
    assert(n00b_heap_peek(h) == 42);
}

// pushpop: when the new value is smaller than the root in a min-heap, it
// must come back out unchanged (the root is preserved); otherwise the old
// root is dropped.
static void
test_heap_pushpop(void)
{
    n00b_heap_t(int) h = n00b_heap_new(int, int_min_cmp);
    int dropped;

    // Empty: pushpop just inserts, returns false (nothing dropped).
    assert(!n00b_heap_pushpop(h, 5, &dropped));
    assert(n00b_heap_len(h) == 1);
    assert(n00b_heap_peek(h) == 5);

    // New < root: new comes back as "dropped", root unchanged.
    assert(n00b_heap_pushpop(h, 3, &dropped));
    assert(dropped == 3);
    assert(n00b_heap_peek(h) == 5);
    assert(n00b_heap_len(h) == 1);

    // New >= root: root is dropped, new takes its place after sifting.
    n00b_heap_push(h, 10);
    n00b_heap_push(h, 8);
    // Heap now contains {5, 10, 8}; root = 5.
    assert(n00b_heap_pushpop(h, 12, &dropped));
    assert(dropped == 5);
    assert(n00b_heap_peek(h) == 8);
}

// Bounded top-K: stream of values, keep a min-heap of size K.  After the
// stream, the heap holds the K largest values.
static void
test_heap_bounded_topk(void)
{
    int stream[] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9};
    int n        = sizeof(stream) / sizeof(stream[0]);
    int K        = 4;

    n00b_heap_t(int) h = n00b_heap_new(int, int_min_cmp);
    for (int i = 0; i < n; i++) {
        if ((int)n00b_heap_len(h) < K) {
            n00b_heap_push(h, stream[i]);
        } else {
            int dropped;
            n00b_heap_pushpop(h, stream[i], &dropped);
        }
    }
    assert(n00b_heap_len(h) == (size_t)K);

    // Drain ascending — should be {7,8,9,9} (top 4 of the stream).
    int got[4];
    for (int i = 0; i < K; i++) {
        assert(n00b_heap_pop(h, &got[i]));
    }
    int expected[] = {8, 9, 9, 9};
    for (int i = 0; i < K; i++) assert(got[i] == expected[i]);
}

// Heap with a non-trivial element type (struct).  Verifies that swap/sift
// move full structs, not just leading bytes.
typedef struct {
    int   key;
    char  tag[8];
} kv_t;

static int
kv_cmp(const void *a, const void *b)
{
    int ai = ((const kv_t *)a)->key;
    int bi = ((const kv_t *)b)->key;
    return (ai > bi) - (ai < bi);
}

static void
test_heap_struct_elements(void)
{
    n00b_heap_t(kv_t) h = n00b_heap_new(kv_t, kv_cmp);
    n00b_heap_push(h, ((kv_t){.key = 5, .tag = "five"}));
    n00b_heap_push(h, ((kv_t){.key = 1, .tag = "one"}));
    n00b_heap_push(h, ((kv_t){.key = 3, .tag = "three"}));

    kv_t out;
    assert(n00b_heap_pop(h, &out));
    assert(out.key == 1 && strcmp(out.tag, "one") == 0);
    assert(n00b_heap_pop(h, &out));
    assert(out.key == 3 && strcmp(out.tag, "three") == 0);
    assert(n00b_heap_pop(h, &out));
    assert(out.key == 5 && strcmp(out.tag, "five") == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_heap_drain_sorted();
    test_heap_peek();
    test_heap_pushpop();
    test_heap_bounded_topk();
    test_heap_struct_elements();

    printf("All heap tests passed.\n");
    n00b_shutdown();
    return 0;
}

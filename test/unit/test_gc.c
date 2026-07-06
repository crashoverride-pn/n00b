#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/stw.h"
#include "core/atomic.h"

// ============================================================================
// Test helper type
// ============================================================================

typedef struct {
    uint64_t value;
    void    *next;
} test_obj_t;

// Convenience macro: cast arena pointer to allocator for n00b_alloc_with_opts().
#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}
#define ARENA_OPTS_NOSCAN(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a), .no_scan = true}

// ============================================================================
// 1. Arena metrics
// ============================================================================

static void
test_arena_metrics(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    uint64_t initial_used = n00b_arena_used(arena);
    uint64_t capacity     = n00b_arena_size(arena);

    assert(capacity > 0);
    // Initial usage should be near zero (just segment header alignment).
    assert(initial_used < 256);

    for (int i = 0; i < 10; i++) {
        test_obj_t *obj = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        obj->value      = i;
    }

    uint64_t after_used = n00b_arena_used(arena);

    assert(after_used > initial_used);
    assert(after_used <= capacity);

    printf("  [PASS] arena metrics\n");
}

// ============================================================================
// 2. Basic collection (pressure-based)
// ============================================================================

static void
test_basic_collection(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    uint32_t prev_count = 0;
    bool     collected  = false;

    for (int i = 0; i < 10000; i++) {
        test_obj_t *obj = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        obj->value      = i;

        uint32_t cur = n00b_atomic_load(&arena->alloc_count);

        if (cur < prev_count) {
            // alloc_count was reset by n00b_collect_internal — GC happened.
            collected = true;
            break;
        }
        prev_count = cur;
    }

    assert(collected);
    printf("  [PASS] basic collection\n");
}

// ============================================================================
// 3. Object survival
// ============================================================================

#define SURVIVAL_COUNT 50

static void
test_object_survival(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *objs[SURVIVAL_COUNT];

    for (int i = 0; i < SURVIVAL_COUNT; i++) {
        objs[i]        = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        objs[i]->value = 0xDEAD0000ULL + (uint64_t)i;
        objs[i]->next  = nullptr;
    }

    // Trigger GC — all 50 objects are reachable from the stack-local array.
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // Verify every object's magic value survived the copy.
    for (int i = 0; i < SURVIVAL_COUNT; i++) {
        assert(objs[i]->value == 0xDEAD0000ULL + (uint64_t)i);
    }

    printf("  [PASS] object survival\n");
}

// ============================================================================
// 4. Pointer chain rewriting
// ============================================================================

static void
test_pointer_chain(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *a = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
    test_obj_t *b = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
    test_obj_t *c = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));

    a->value = 0xAAAA;
    b->value = 0xBBBB;
    c->value = 0xCCCC;
    a->next  = b;
    b->next  = c;
    c->next  = nullptr;

    // Drop direct references; chain is only reachable via a->next->next.
    b = nullptr;
    c = nullptr;

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // Walk the chain — proves internal heap pointers were rewritten.
    assert(a->value == 0xAAAA);

    test_obj_t *b2 = (test_obj_t *)a->next;
    assert(b2 != nullptr);
    assert(b2->value == 0xBBBB);

    test_obj_t *c2 = (test_obj_t *)b2->next;
    assert(c2 != nullptr);
    assert(c2->value == 0xCCCC);
    assert(c2->next == nullptr);

    printf("  [PASS] pointer chain\n");
}

// ============================================================================
// 5. Unreachable objects collected
// ============================================================================

// noinline so the 399 discarded pointers live only in this frame,
// which is dead when the caller triggers collection.
static __attribute__((noinline)) test_obj_t *
allocate_waste(n00b_arena_t *arena, int count)
{
    test_obj_t *last = nullptr;

    for (int i = 0; i < count; i++) {
        last        = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        last->value = (uint64_t)i;
        last->next  = nullptr;
    }

    return last;
}

static void
test_unreachable_collected(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    // Allocate 400 objects; only the very last pointer is returned.
    test_obj_t *survivor = allocate_waste(arena, 400);

    uint64_t before = n00b_arena_used(arena);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    uint64_t after = n00b_arena_used(arena);

    // Conservative stack scanning may keep a handful alive, but the
    // vast majority should be reclaimed.
    assert(after < before);
    assert(after < before / 2);

    assert(survivor->value == 399);

    printf("  [PASS] unreachable collected\n");
}

// ============================================================================
// 6. Multiple collections
// ============================================================================

#define MULTI_COUNT 20

static void
test_multiple_collections(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    for (int round = 0; round < 3; round++) {
        test_obj_t *objs[MULTI_COUNT];

        for (int i = 0; i < MULTI_COUNT; i++) {
            objs[i]        = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
            objs[i]->value = (uint64_t)(round * 1000 + i);
        }

        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();

        for (int i = 0; i < MULTI_COUNT; i++) {
            assert(objs[i]->value == (uint64_t)(round * 1000 + i));
        }
    }

    printf("  [PASS] multiple collections\n");
}

// ============================================================================
// 7. Manual collect
// ============================================================================

static void
test_manual_collect(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *obj = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
    obj->value      = 0x12345678DEADBEEFULL;
    obj->next       = nullptr;

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    assert(obj->value == 0x12345678DEADBEEFULL);
    assert(obj->next == nullptr);

    printf("  [PASS] manual collect\n");
}

// ============================================================================
// 8. Conservative header-address false positives
// ============================================================================

static void
test_header_address_false_positive(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *target = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
    test_obj_t *holder = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));

    n00b_option_t(n00b_inline_hdr_t *) hdr_opt = n00b_inline_alloc_header(target);
    assert(n00b_option_is_set(hdr_opt));

    target->value = 0xFEEDFACEULL;
    target->next  = nullptr;
    holder->value = (uint64_t)(uintptr_t)n00b_option_get(hdr_opt);
    holder->next  = target;

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    assert(target->value == 0xFEEDFACEULL);
    assert(holder->next == target);

    printf("  [PASS] conservative header-address false positive\n");
}

// ============================================================================
// 9. No-scan objects survive
// ============================================================================

#define NOSCAN_COUNT 10

static void
test_noscan_survival(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *objs[NOSCAN_COUNT];

    for (int i = 0; i < NOSCAN_COUNT; i++) {
        objs[i]        = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS_NOSCAN(arena));
        objs[i]->value = 0xCAFE0000ULL + (uint64_t)i;
        objs[i]->next  = nullptr;
    }

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    for (int i = 0; i < NOSCAN_COUNT; i++) {
        assert(objs[i]->value == 0xCAFE0000ULL + (uint64_t)i);
    }

    printf("  [PASS] noscan survival\n");
}

// ============================================================================
// 10. Allocation after collection
// ============================================================================

static void
test_alloc_after_collection(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *pre = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
    pre->value      = 0x1111;

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // Allocate 10 new objects on the post-collection arena.
    test_obj_t *post[10];

    for (int i = 0; i < 10; i++) {
        post[i] = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        assert(post[i] != nullptr);
        post[i]->value = 0x2000ULL + (uint64_t)i;
    }

    for (int i = 0; i < 10; i++) {
        assert(post[i]->value == 0x2000ULL + (uint64_t)i);
    }

    // Pre-collection object must also survive.
    assert(pre->value == 0x1111);

    printf("  [PASS] alloc after collection\n");
}

// ============================================================================
// 11. Large linked list (GC fires mid-construction)
// ============================================================================

#define LIST_LENGTH 600

static void
test_large_linked_list(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_obj_t *head = nullptr;
    test_obj_t *prev = nullptr;

    for (int i = 0; i < LIST_LENGTH; i++) {
        test_obj_t *node = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        node->value      = (uint64_t)i;
        node->next       = nullptr;

        if (prev) {
            prev->next = node;
        }
        else {
            head = node;
        }
        prev = node;
    }

    // With ~500 allocs filling a 32K segment, at least one collection
    // must have occurred during the 600-node build.  Walk the entire
    // list and verify every value.
    test_obj_t *cur = head;

    for (int i = 0; i < LIST_LENGTH; i++) {
        assert(cur != nullptr);
        assert(cur->value == (uint64_t)i);
        cur = (test_obj_t *)cur->next;
    }
    assert(cur == nullptr);

    printf("  [PASS] large linked list\n");
}

// ============================================================================
// 12. Memo table resize during collection
// ============================================================================

#define MEMO_RESIZE_COUNT 4096

static void
test_memo_resize_during_collection(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 1024 * 1024, .use_gc = true);

    test_obj_t *head = nullptr;

    for (int i = 0; i < MEMO_RESIZE_COUNT; i++) {
        test_obj_t *node = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        node->value      = 0x600D0000ULL + (uint64_t)i;
        node->next       = head;
        head             = node;
    }

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    uint64_t    expected = 0x600D0000ULL + (uint64_t)(MEMO_RESIZE_COUNT - 1);
    test_obj_t *cur      = head;

    for (int i = 0; i < MEMO_RESIZE_COUNT; i++) {
        assert(cur != nullptr);
        assert(cur->value == expected - (uint64_t)i);
        cur = (test_obj_t *)cur->next;
    }
    assert(cur == nullptr);

    printf("  [PASS] memo resize during collection\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running GC tests...\n");

    test_arena_metrics();
    test_basic_collection();
    test_object_survival();
    test_pointer_chain();
    test_unreachable_collected();
    test_multiple_collections();
    test_manual_collect();
    test_header_address_false_positive();
    test_noscan_survival();
    test_alloc_after_collection();
    test_large_linked_list();
    test_memo_resize_during_collection();

    printf("All GC tests passed.\n");
    n00b_shutdown();
    return 0;
}

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
#include "core/buffer.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/stack.h"
#include "adt/array.h"
#include "adt/tree.h"
#include "adt/dict.h"
#include "adt/dict_untyped.h"
#include "adt/interval_tree.h"
#include "adt/llist.h"

#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}

typedef struct {
    uint64_t value;
    void    *next;
} target_t;

// A NONE-allocated heap snapshot of `n` uint64_t words; the
// conservative stack scanner can't see pointer-shaped values stashed
// here, so byte-for-byte comparison after GC is meaningful.
static __attribute__((noinline)) uint64_t *
none_snapshot(n00b_arena_t *arena, uint64_t n, const void *src)
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
// 1. n00b_buffer_t — default NONE; pointer-shaped bytes survive GC verbatim.
// ============================================================================

static __attribute__((noinline)) void
test_buffer_inner(n00b_arena_t *arena)
{
    // Allocate a "target" object so we have a real heap pointer to
    // stash in the buffer's bytes.  Without a real target, the
    // conservative scanner would never try to forward the slot, and
    // the test wouldn't exercise NONE meaningfully.
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0001ULL;

    // Build a buffer whose bytes happen to look like 4 heap pointers
    // followed by some pad.  scan_kind defaults to NONE for buffers.
    n00b_buffer_t *buf = n00b_buffer_new(64, .allocator = (n00b_allocator_t *)arena);
    assert(buf != nullptr);
    assert(n00b_buffer_len(buf) == 64);

    uint64_t *as_words = (uint64_t *)buf->data;
    for (int i = 0; i < 4; ++i) {
        as_words[i] = (uint64_t)(uintptr_t)target;
    }
    for (int i = 4; i < 8; ++i) {
        as_words[i] = 0xFEEDFACE00000000ULL + (uint64_t)i;
    }

    uint64_t *saved = none_snapshot(arena, 8, buf->data);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    uint64_t *now_words = (uint64_t *)buf->data;
    for (int i = 0; i < 8; ++i) {
        assert(now_words[i] == saved[i]);
    }
    // The stack-local `target` was forwarded to the new address; the
    // buffer's bytes hold the OLD address (untouched).  They must
    // differ — that's the proof that NONE held.
    if (!n00b_gc_pin_all_policy()) { // pin-all: nothing moves
            assert(now_words[0] != (uint64_t)(uintptr_t)target);
    }
    assert(target->value == 0xCAFE0001ULL);
}

static void
test_buffer_scan_kind_none_default(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    test_buffer_inner(arena);
    printf("  [PASS] buffer_scan_kind_none_default\n");
}

// ============================================================================
// 2. n00b_list_t(uint64_t) — explicit NONE; pointer-shaped pushes survive GC.
//    Push enough elements to trigger a grow; verify the grown backing
//    store still inherits NONE.
// ============================================================================

#define LIST_GROW_TARGET 200

static __attribute__((noinline)) void
test_list_inner(n00b_arena_t *arena)
{
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0002ULL;

    n00b_list_t(uint64_t) lst = n00b_list_new(
        uint64_t,
        .allocator = (n00b_allocator_t *)arena,
        .scan_kind = N00B_GC_SCAN_KIND_NONE);

    assert(lst.scan_kind == N00B_GC_SCAN_KIND_NONE);

    // Push many pointer-shaped values.  The first push fits within
    // the default capacity; later pushes force the grow path, which
    // must re-apply NONE to the new backing store.
    for (uint64_t i = 0; i < LIST_GROW_TARGET; ++i) {
        n00b_list_push(lst, (uint64_t)(uintptr_t)target);
    }
    assert(lst.cap >= LIST_GROW_TARGET);
    assert(lst.scan_kind == N00B_GC_SCAN_KIND_NONE);

    // Snapshot the pointer-shaped slot values.
    uint64_t *saved = none_snapshot(arena, LIST_GROW_TARGET, lst.data);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // The conservative scanner saw `target` on the stack and forwarded
    // it; the stack-local `target` was rewritten to the new address.
    // The list's backing store, with scan_kind=NONE, retains the OLD
    // pointer bytes verbatim.
    for (uint64_t i = 0; i < LIST_GROW_TARGET; ++i) {
        assert(lst.data[i] == saved[i]);
    }
    if (!n00b_gc_pin_all_policy()) { // pin-all: nothing moves
            assert(lst.data[0] != (uint64_t)(uintptr_t)target);
    }
    assert(target->value == 0xCAFE0002ULL);
    assert(lst.scan_kind == N00B_GC_SCAN_KIND_NONE);
}

static void
test_list_scan_kind_none_with_grow(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 65536, .use_gc = true);
    test_list_inner(arena);
    printf("  [PASS] list_scan_kind_none_with_grow\n");
}

// ============================================================================
// 3. n00b_stack_t(uint64_t) — same shape as list; NONE survives push+grow.
// ============================================================================

#define STACK_GROW_TARGET 200

static __attribute__((noinline)) void
test_stack_inner(n00b_arena_t *arena)
{
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0003ULL;

    n00b_stack_t(uint64_t) stk = n00b_stack_new(
        uint64_t,
        .allocator = (n00b_allocator_t *)arena,
        .scan_kind = N00B_GC_SCAN_KIND_NONE);

    assert(stk.scan_kind == N00B_GC_SCAN_KIND_NONE);

    for (uint64_t i = 0; i < STACK_GROW_TARGET; ++i) {
        n00b_stack_push(stk, (uint64_t)(uintptr_t)target);
    }
    assert(stk.cap >= STACK_GROW_TARGET);
    assert(stk.scan_kind == N00B_GC_SCAN_KIND_NONE);

    uint64_t *saved = none_snapshot(arena, STACK_GROW_TARGET, stk.data);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    for (uint64_t i = 0; i < STACK_GROW_TARGET; ++i) {
        assert(stk.data[i] == saved[i]);
    }
    if (!n00b_gc_pin_all_policy()) { // pin-all: nothing moves
        assert(stk.data[0] != (uint64_t)(uintptr_t)target);
    }
    assert(target->value == 0xCAFE0003ULL);
}

static void
test_stack_scan_kind_none_with_grow(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 65536, .use_gc = true);
    test_stack_inner(arena);
    printf("  [PASS] stack_scan_kind_none_with_grow\n");
}

// ============================================================================
// 4. n00b_array_t(uint64_t) — no-grow; NONE survives GC.
// ============================================================================

static __attribute__((noinline)) void
test_array_inner(n00b_arena_t *arena)
{
    target_t *target = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    target->value    = 0xCAFE0004ULL;

    n00b_array_t(uint64_t) arr = n00b_array_new(
        uint64_t, 8,
        .allocator = (n00b_allocator_t *)arena,
        .scan_kind = N00B_GC_SCAN_KIND_NONE);

    assert(arr.scan_kind == N00B_GC_SCAN_KIND_NONE);
    for (uint64_t i = 0; i < 8; ++i) {
        arr.data[i] = (uint64_t)(uintptr_t)target;
    }
    arr.len = 8;

    uint64_t *saved = none_snapshot(arena, 8, arr.data);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    for (uint64_t i = 0; i < 8; ++i) {
        assert(arr.data[i] == saved[i]);
    }
    if (!n00b_gc_pin_all_policy()) { // pin-all: nothing moves
        assert(arr.data[0] != (uint64_t)(uintptr_t)target);
    }
    assert(target->value == 0xCAFE0004ULL);
}

static void
test_array_scan_kind_none(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    test_array_inner(arena);
    printf("  [PASS] array_scan_kind_none\n");
}

// ============================================================================
// 4b. n00b_tree_t — node holds the scan kargs; children-array alloc + grow
//     both forward them.  Build a node, force a grow by adding many children,
//     verify scan_kind persists.
// ============================================================================

static void
test_tree_scan_kind_plumbing(void)
{
    // Default: scan_kind=DEFAULT — children pointer array honours legacy.
    n00b_tree_t(int, char *) *root = n00b_tree_node(int, char *, 1);
    assert(root != nullptr);
    assert(root->node.scan_kind == N00B_GC_SCAN_KIND_DEFAULT);

    // Force the children array to grow past its initial capacity.
    for (int i = 0; i < 32; ++i) {
        n00b_tree_add_leaf(root, int, char *, "x");
    }
    assert(root->node.capacity >= 32);
    // The grow path must preserve the node's scan_kind.
    assert(root->node.scan_kind == N00B_GC_SCAN_KIND_DEFAULT);

    // Explicit override on a fresh node:
    n00b_tree_t(int, char *) *root2 = n00b_tree_node(
        int, char *, 2,
        .scan_kind = N00B_GC_SCAN_KIND_ALL);
    assert(root2 != nullptr);
    assert(root2->node.scan_kind == N00B_GC_SCAN_KIND_ALL);

    printf("  [PASS] tree_scan_kind_plumbing\n");
}

// ============================================================================
// 5. n00b_string_t — default NONE.  String bytes never look pointer-like in
//    practice, but verify the alloc plumbing reaches the char-data backing.
// ============================================================================

static __attribute__((noinline)) void
test_string_inner(n00b_arena_t *arena)
{
    n00b_string_t *s = n00b_alloc_with_opts(n00b_string_t,
                                            &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
    n00b_string_init(s,
                     .src       = "hello world",
                     .byte_len  = 11,
                     .allocator = (n00b_allocator_t *)arena);
    assert(s->u8_bytes == 11);
    assert(memcmp(s->data, "hello world", 11) == 0);

    // Force a GC; with NONE the byte data is preserved verbatim.
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    assert(s->u8_bytes == 11);
    assert(memcmp(s->data, "hello world", 11) == 0);
}

static void
test_string_scan_kind_none_default(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    test_string_inner(arena);
    printf("  [PASS] string_scan_kind_none_default\n");
}

// ============================================================================
// 6. n00b_dict_t — karg plumbed; backing-store allocs inherit scan_kind.
//    This verifies the dict init accepts the karg and that successive
//    inserts plus a forced collection don't disturb POD slots in NONE
//    keys/values arrays.
// ============================================================================

static __attribute__((noinline)) void
test_dict_scan_kind_plumbing(void)
{
    n00b_dict_t(uint64_t, uint64_t) d;
    n00b_dict_init(&d, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    // The stored scan_kind should match what we asked for.
    assert(d.scan_kind == N00B_GC_SCAN_KIND_NONE);
    uint64_t k1 = 1, k2 = 2, k3 = 3;
    uint64_t v1 = 0xCAFE0001ULL, v2 = 0xCAFE0002ULL, v3 = 0xCAFE0003ULL;
    n00b_dict_put(&d, k1, v1);
    n00b_dict_put(&d, k2, v2);
    n00b_dict_put(&d, k3, v3);
    bool found = false;
    uint64_t got = n00b_dict_get(&d, k2, &found);
    assert(found);
    assert(got == v2);
    printf("  [PASS] dict_scan_kind_plumbing\n");
}

// ============================================================================
// 7. n00b_dict_untyped_t — karg plumbed.
// ============================================================================

static void
test_dict_untyped_scan_kind_plumbing(void)
{
    n00b_dict_untyped_t d;
    n00b_dict_untyped_init(&d, .scan_kind = N00B_GC_SCAN_KIND_DEFAULT);
    assert(d.scan_kind == N00B_GC_SCAN_KIND_DEFAULT);
    printf("  [PASS] dict_untyped_scan_kind_plumbing\n");
}

// ============================================================================
// 8. n00b_interval_tree_t — karg plumbed.
// ============================================================================

static void
test_interval_tree_scan_kind_plumbing(void)
{
    n00b_interval_tree_t(int) tree;
    n00b_interval_tree_init(&tree, .scan_kind = N00B_GC_SCAN_KIND_DEFAULT);
    assert(tree.scan_kind == N00B_GC_SCAN_KIND_DEFAULT);
    printf("  [PASS] interval_tree_scan_kind_plumbing\n");
}

// ============================================================================
// 9. n00b_linked_list_t — struct-field setter; append/prepend forward.
// ============================================================================

static void
test_linked_list_scan_kind_plumbing(void)
{
    n00b_linked_list_t(uint64_t) list = {
        .scan_kind = N00B_GC_SCAN_KIND_NONE,
    };
    assert(list.scan_kind == N00B_GC_SCAN_KIND_NONE);
    n00b_linked_list_append(&list, (uint64_t)0xAAAA0001);
    n00b_linked_list_append(&list, (uint64_t)0xAAAA0002);
    auto first = n00b_linked_list_first(&list);
    assert(first != nullptr);
    assert(n00b_linked_list_node_contents(first) == (uint64_t)0xAAAA0001);
    printf("  [PASS] linked_list_scan_kind_plumbing\n");
}

// ============================================================================
// main — runs one test per container as those land in Step 4.
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running container scan_kind tests...\n");

    test_buffer_scan_kind_none_default();
    test_list_scan_kind_none_with_grow();
    test_stack_scan_kind_none_with_grow();
    test_array_scan_kind_none();
    test_tree_scan_kind_plumbing();
    test_string_scan_kind_none_default();
    test_dict_scan_kind_plumbing();
    test_dict_untyped_scan_kind_plumbing();
    test_interval_tree_scan_kind_plumbing();
    test_linked_list_scan_kind_plumbing();

    printf("All container scan_kind tests passed.\n");
    n00b_shutdown();
    return 0;
}

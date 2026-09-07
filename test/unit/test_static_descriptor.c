#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/gc_map.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/stw.h"

#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}

#define STATIC_ROOT_TINFO UINT64_C(0x5374617469630001)
#define STATIC_LEAF_TINFO UINT64_C(0x5374617469630002)
#define STATIC_ROOT_ID    UINT64_C(0x1001)
#define STATIC_LEAF_ID    UINT64_C(0x1002)

typedef struct {
    uint64_t value;
    void    *next;
} target_t;

typedef struct {
    target_t *child;
    uint64_t  tag;
} static_leaf_t;

typedef struct {
    static_leaf_t *leaf;
    uint64_t       tag;
} static_root_t;

static static_root_t descriptor_root;
static static_leaf_t descriptor_leaf;

static __attribute__((noinline)) uint64_t *
save_old_pointer(n00b_arena_t *arena, void *ptr)
{
    uint64_t *saved = n00b_alloc_array_with_opts(
        uint64_t,
        1,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });

    saved[0] = (uint64_t)(uintptr_t)ptr;
    return saved;
}

static __attribute__((noinline)) void
test_nested_static_descriptors_inner(n00b_arena_t *arena)
{
    descriptor_root = (static_root_t){.leaf = &descriptor_leaf, .tag = 0xABC001};
    descriptor_leaf = (static_leaf_t){.tag = 0xABC002};

    n00b_alloc_range_t *root_range = n00b_static_object_register(
        &descriptor_root,
        sizeof(descriptor_root),
        STATIC_ROOT_TINFO,
        .scan_kind = N00B_GC_SCAN_KIND_ALL,
        .object_id = STATIC_ROOT_ID);
    n00b_alloc_range_t *leaf_range = n00b_static_object_register(
        &descriptor_leaf,
        sizeof(descriptor_leaf),
        STATIC_LEAF_TINFO,
        .scan_kind = N00B_GC_SCAN_KIND_ALL,
        .object_id = STATIC_LEAF_ID);

    assert(root_range->kind == n00b_mmap_static);
    assert(root_range->tinfo == STATIC_ROOT_TINFO);
    assert(root_range->object_id == STATIC_ROOT_ID);
    assert(root_range->len == sizeof(descriptor_root));
    assert(leaf_range->kind == n00b_mmap_static);
    assert(leaf_range->tinfo == STATIC_LEAF_TINFO);
    assert(leaf_range->object_id == STATIC_LEAF_ID);

    auto root_lookup = n00b_mmap_range_by_address(&descriptor_root.leaf);
    auto leaf_lookup = n00b_mmap_range_by_address(&descriptor_leaf.child);
    assert(n00b_option_is_set(root_lookup));
    assert(n00b_option_get(root_lookup) == root_range);
    assert(n00b_option_is_set(leaf_lookup));
    assert(n00b_option_get(leaf_lookup) == leaf_range);

    descriptor_leaf.child        = n00b_alloc_with_opts(target_t, ARENA_OPTS(arena));
    descriptor_leaf.child->value = 0xCAFE500DULL;

    uint64_t      *saved = save_old_pointer(arena, descriptor_leaf.child);
    static_root_t *root  = &descriptor_root;

    n00b_gc_register_root(root);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_unregister_root(root);

    assert(root == &descriptor_root);
    assert(descriptor_root.leaf == &descriptor_leaf);
    assert((uint64_t)(uintptr_t)descriptor_leaf.child != saved[0]);
    assert(descriptor_leaf.child->value == 0xCAFE500DULL);
}

static void
test_nested_static_descriptors(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);
    test_nested_static_descriptors_inner(arena);
    printf("  [PASS] nested_static_descriptors\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running static descriptor tests...\n");

    test_nested_static_descriptors();

    printf("All static descriptor tests passed.\n");
    n00b_shutdown();
    return 0;
}

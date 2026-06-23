#include <stdint.h>
#include <string.h>

#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/gc_baked.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "n00b_crt.h"
#include "util/assert.h"
#include "util/comptime_image.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

typedef struct writable_gc_heap_node_t {
    uint64_t tag;
} writable_gc_heap_node_t;

typedef struct writable_gc_image_root_t {
    writable_gc_heap_node_t *heap;
    uint64_t                 tag;
} writable_gc_image_root_t;

static void
set_ptr_words(void *obj, uint32_t ptr_words)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(obj);

    if (info.kind == n00b_alloc_oob) {
        info.hdr.oob->ptr_words = ptr_words;
        if (info.hdr.oob->hcur != nullptr) {
            info.hdr.oob->hcur->ptr_words = ptr_words;
        }
        return;
    }

    CHECK(info.kind == n00b_alloc_inline);
    info.hdr.in_line->ptr_words = ptr_words;
}

static void *
map_image(n00b_buffer_t *image)
{
    size_t map_len = n00b_page_align(image->byte_len);
    auto map_r = n00b_mmap(map_len,
                           .kind = n00b_mmap_api_mmap,
                           .name = "ct-writable-gc");
    CHECK(n00b_result_is_ok(map_r));
    void *mapping = n00b_result_get(map_r);
    memcpy(mapping, image->data, image->byte_len);
    return mapping;
}

static writable_gc_image_root_t *
apply_writable_root(void)
{
    writable_gc_image_root_t *root = n00b_alloc(writable_gc_image_root_t);
    set_ptr_words(root, 1);
    root->heap = nullptr;
    root->tag  = UINT64_C(0x57424743524f4f54);

    [[n00b::nomap]] n00b_result_t(n00b_buffer_t *) export_r =
        n00b_ct_image_export_writable(root);
    CHECK(n00b_result_is_ok(export_r));
    n00b_buffer_t *image = n00b_result_get(export_r);
    void *mapping = map_image(image);

    [[n00b::nomap]] n00b_result_t(void *) apply_r =
        n00b_crt_apply_writable_image_region(mapping, image->byte_len, nullptr);
    CHECK(n00b_result_is_ok(apply_r));
    return n00b_result_get(apply_r);
}

static void
test_post_relocation_write_is_tracked_by_gc(void)
{
    writable_gc_image_root_t *root = apply_writable_root();
    uintptr_t root_addr_xor = (uintptr_t)root ^ UINT64_C(0xfeedfacecafebeef);
    CHECK(n00b_gc_addr_in_baked_region(root));

    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);
    writable_gc_heap_node_t *heap = n00b_alloc_with_opts(
        writable_gc_heap_node_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    heap->tag = UINT64_C(0x5742474348454150);
    uintptr_t heap_addr_xor = (uintptr_t)heap ^ UINT64_C(0x9e3779b97f4a7c15);

    root->heap = heap;
    heap = nullptr;

    n00b_collect(arena);

    CHECK(((uintptr_t)root ^ UINT64_C(0xfeedfacecafebeef)) == root_addr_xor);
    CHECK(root->heap != nullptr);
    CHECK(((uintptr_t)root->heap ^ UINT64_C(0x9e3779b97f4a7c15)) != heap_addr_xor);
    CHECK(root->heap->tag == UINT64_C(0x5742474348454150));
    CHECK(n00b_gc_addr_in_baked_region(root));
    CHECK(!n00b_gc_addr_in_baked_region(root->heap));

    writable_gc_heap_node_t *heap2 = n00b_alloc_with_opts(
        writable_gc_heap_node_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    heap2->tag = UINT64_C(0x5742474348454132);
    uintptr_t heap2_addr_xor = (uintptr_t)heap2 ^ UINT64_C(0xd1b54a32d192ed03);

    root->heap = heap2;
    heap2 = nullptr;

    n00b_collect(arena);

    CHECK(((uintptr_t)root ^ UINT64_C(0xfeedfacecafebeef)) == root_addr_xor);
    CHECK(root->heap != nullptr);
    CHECK(((uintptr_t)root->heap ^ UINT64_C(0xd1b54a32d192ed03)) != heap2_addr_xor);
    CHECK(root->heap->tag == UINT64_C(0x5742474348454132));
    CHECK(n00b_gc_addr_in_baked_region(root));
    CHECK(!n00b_gc_addr_in_baked_region(root->heap));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_post_relocation_write_is_tracked_by_gc();

    n00b_shutdown();
    return 0;
}

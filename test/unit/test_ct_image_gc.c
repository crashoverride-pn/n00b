#include <stdint.h>
#include <stdio.h>
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

typedef struct ct_gc_node_t {
    struct ct_gc_node_t *next;
    uint64_t             tag;
} ct_gc_node_t;

typedef struct {
    ct_gc_node_t *image_node;
    uint64_t      tag;
} ct_gc_holder_t;

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

static n00b_buffer_t *
export_one(void *root)
{
    [[n00b::nomap]] n00b_result_t(n00b_buffer_t *) r =
        n00b_ct_image_export(root);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static size_t
page_round_up(size_t n)
{
    return n00b_page_align(n);
}

static void *
map_image(n00b_buffer_t *image, size_t *protect_len_out)
{
    size_t protect_len = page_round_up(image->byte_len);
    auto map_r = n00b_mmap(protect_len,
                           .kind = n00b_mmap_api_mmap,
                           .name = "ct-image-gc");
    CHECK(n00b_result_is_ok(map_r));
    void *mapping = n00b_result_get(map_r);
    memcpy(mapping, image->data, image->byte_len);
    *protect_len_out = protect_len;
    return mapping;
}

[[gnu::noinline]] static uint64_t *
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

static void
unmap_image(void *mapping)
{
    auto unmap_r = n00b_munmap(mapping);
    CHECK(n00b_result_is_ok(unmap_r));
}

static void
test_baked_image_is_pinned_and_scanned(void)
{
    ct_gc_node_t *first  = n00b_alloc(ct_gc_node_t);
    ct_gc_node_t *second = n00b_alloc(ct_gc_node_t);
    set_ptr_words(first, 1);
    set_ptr_words(second, 1);
    first->next  = second;
    first->tag   = UINT64_C(0xba5ed001);
    second->next = first;
    second->tag  = UINT64_C(0xba5ed002);

    n00b_buffer_t *image = export_one(first);
    size_t protect_len = 0;
    void *mapping = map_image(image, &protect_len);

    [[n00b::nomap]] n00b_result_t(void *) apply_r =
        n00b_crt_apply_comptime_image_region(mapping, image->byte_len,
                                             protect_len);
    CHECK(n00b_result_is_ok(apply_r));

    ct_gc_node_t *copy_first = n00b_result_get(apply_r);
    CHECK(copy_first != first);
    CHECK(copy_first->tag == first->tag);
    CHECK(copy_first->next != second);
    CHECK(copy_first->next->tag == second->tag);
    CHECK(copy_first->next->next == copy_first);

    CHECK(n00b_gc_addr_in_baked_region(copy_first));
    CHECK(n00b_gc_addr_in_baked_region(copy_first->next));

    auto first_range = n00b_mmap_range_by_address(copy_first);
    auto second_range = n00b_mmap_range_by_address(copy_first->next);
    CHECK(n00b_option_is_set(first_range));
    CHECK(n00b_option_is_set(second_range));
    CHECK((n00b_option_get(first_range)->flags & N00B_STATIC_OBJECT_F_BAKED) != 0);
    CHECK((n00b_option_get(second_range)->flags & N00B_STATIC_OBJECT_F_BAKED) != 0);

    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);
    ct_gc_holder_t *holder = n00b_alloc_with_opts(
        ct_gc_holder_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    holder->image_node = copy_first->next;
    holder->tag        = UINT64_C(0x600dc0de);

    ct_gc_holder_t *holder_root = holder;
    uint64_t *old_holder = save_old_pointer(arena, holder_root);
    holder = nullptr;
    n00b_gc_register_root(holder_root);
    n00b_collect(arena);
    n00b_gc_unregister_root(holder_root);

    CHECK((uint64_t)(uintptr_t)holder_root != old_holder[0]);
    CHECK(holder_root->tag == UINT64_C(0x600dc0de));
    CHECK(holder_root->image_node == copy_first->next);
    CHECK(copy_first->next->next == copy_first);
    CHECK(copy_first->tag == UINT64_C(0xba5ed001));
    CHECK(copy_first->next->tag == UINT64_C(0xba5ed002));
    CHECK(!n00b_gc_addr_in_baked_region(holder_root));

    unmap_image(mapping);
    (void)protect_len;
}

static void
test_baked_image_rejects_heap_pointer_slots(void)
{
    ct_gc_node_t *first = n00b_alloc(ct_gc_node_t);
    set_ptr_words(first, 1);
    first->next = nullptr;
    first->tag  = UINT64_C(0xba5ed010);

    n00b_buffer_t *image = export_one(first);
    size_t protect_len = 0;
    void *mapping = map_image(image, &protect_len);
    (void)protect_len;

    [[n00b::nomap]] n00b_result_t(void *) relocate_r =
        n00b_ct_image_relocate_inplace(mapping, image->byte_len);
    CHECK(n00b_result_is_ok(relocate_r));

    ct_gc_node_t *copy_first = n00b_result_get(relocate_r);
    ct_gc_node_t *external   = n00b_alloc(ct_gc_node_t);
    set_ptr_words(external, 1);
    external->next = nullptr;
    external->tag  = UINT64_C(0xba5ed011);
    copy_first->next = external;

    n00b_ct_image_header_t *hdr = mapping;
    n00b_gc_baked_region_t region = {
        .base           = mapping,
        .len            = image->byte_len,
        .marshal_stream = (char *)mapping + hdr->marshal_off,
        .marshal_len    = hdr->marshal_len,
        .root           = copy_first,
    };
    auto register_r = n00b_gc_register_baked_region(&region);
    CHECK(n00b_result_is_err(register_r));
    CHECK(n00b_result_get_err(register_r)
          == N00B_GC_BAKED_ERR_EXTERNAL_POINTER);

    unmap_image(mapping);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running comptime image GC tests...\n");
    test_baked_image_is_pinned_and_scanned();
    test_baked_image_rejects_heap_pointer_slots();
    printf("All comptime image GC tests passed.\n");

    n00b_shutdown();
    return 0;
}

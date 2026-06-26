#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/codegen_abi.h" // GC/marshal codegen-ABI structs used by value
#include "core/codegen_abi_inject.h" // GC/marshal descriptor structs / scan-cb externs used by value
#include "adt/array.h"
#include "core/alloc.h"
#include "core/alloc_mdata.h"
#include "core/gc_map.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/static_objects.h"
#include "core/type_info.h"
#include "text/strings/text_style.h"

typedef n00b_array_t(int) generated_int_array_t;
typedef n00b_string_t *n00b_string_ptr_t;
typedef void *generated_ptr_t;

typedef struct {
    n00b_string_ptr_t label;
    uint64_t          tag;
    n00b_string_ptr_t alt;
} generated_labeled_item_t;

static n00b_alloc_range_t *
range_for_address(const void *addr)
{
    auto found = n00b_mmap_range_by_address((void *)addr);
    assert(n00b_option_is_set(found));
    return n00b_option_get(found);
}

static void
assert_static_alloc_info(const void *addr, n00b_alloc_range_t *range)
{
    n00b_alloc_info_t info = n00b_find_alloc_info((void *)addr);
    assert(info.kind == n00b_alloc_static_range);
    assert(n00b_alloc_info_is_static_range(info));
    assert(!n00b_alloc_info_is_heap(info));
    assert(info.hdr.range == range);
}

static void
assert_generated_identity(n00b_alloc_range_t *range,
                          n00b_static_identity_kind_t kind,
                          const char *key_prefix)
{
    assert(range->identity != nullptr);
    assert(range->identity->version == N00B_STATIC_IDENTITY_VERSION);
    assert(range->identity->kind == kind);
    assert(range->identity->namespace_id != nullptr);
    assert(strcmp(range->identity->namespace_id, "n00b.tests") == 0);
    assert(range->identity->object_key != nullptr);
    assert(strncmp(range->identity->object_key,
                   key_prefix,
                   strlen(key_prefix)) == 0);
    assert(strstr(range->identity->object_key,
                  "test_ncc_static_objects.c:") != nullptr);

    n00b_static_identity_query_t query = {
        .checks      = N00B_STATIC_IDENTITY_CHECK_LEN
                     | N00B_STATIC_IDENTITY_CHECK_SCAN_KIND
                     | N00B_STATIC_IDENTITY_CHECK_FLAGS,
        .len         = range->len,
        .scan_kind   = range->scan_kind,
        .flags_mask  = range->flags,
        .flags_value = range->flags,
    };
    n00b_alloc_range_t *resolved = nullptr;
    assert(n00b_static_identity_lookup(range->identity, &query, &resolved)
           == N00B_STATIC_IDENTITY_OK);
    assert(resolved == range);
}

static void
test_generated_rstring_descriptors(void)
{
    n00b_string_t *plain  = r"descriptor";
    n00b_string_t *styled = r"[|b|]hi[|/b|]";

    n00b_static_objects_register_all();

    n00b_alloc_range_t *plain_range = range_for_address(plain);
    assert_static_alloc_info(plain, plain_range);
    assert(n00b_obj_typehash(plain) == plain_range->tinfo);
    assert(plain_range->tinfo != 0);
    assert(plain_range->kind == n00b_mmap_static);
    assert(plain_range->len == sizeof(*plain));
    assert(plain_range->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(plain_range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(plain_range,
                              N00B_STATIC_IDENTITY_NCC_RSTR,
                              "ncc-rstr:");
    assert(plain->u8_bytes == 10);
    assert(memcmp(plain->data, "descriptor", 10) == 0);

    n00b_alloc_range_t *styled_range = range_for_address(styled);
    assert_static_alloc_info(styled, styled_range);
    assert(n00b_obj_typehash(styled) == styled_range->tinfo);
    assert(styled_range->tinfo != 0);
    assert(styled_range->kind == n00b_mmap_static);
    assert(styled_range->len == sizeof(*styled));
    assert(styled_range->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(styled_range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(styled_range,
                              N00B_STATIC_IDENTITY_NCC_RSTR,
                              "ncc-rstr:");
    assert(styled->u8_bytes == 2);
    assert(styled->styling != nullptr);

    printf("  [PASS] generated_rstring_descriptors\n");
}

static void
test_generated_scalar_array_descriptor(void)
{
    const n00b_array_t(int) values = [10, 20, 30];

    n00b_static_objects_register_all();

    n00b_alloc_range_t *range = range_for_address(values.data);
    assert_static_alloc_info(values.data, range);
    assert(range->kind == n00b_mmap_static);
    assert(range->len == sizeof(int) * 3);
    assert(range->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(range,
                              N00B_STATIC_IDENTITY_NCC_ARRAY_DATA,
                              "ncc-array-data:");
    assert(values.len == 3);
    assert(values.data[0] == 10);
    assert(values.data[2] == 30);

    printf("  [PASS] generated_scalar_array_descriptor\n");
}

static void
test_generated_pointer_array_descriptor(void)
{
    const n00b_array_t(n00b_string_ptr_t) words =
        [r"alpha", r"[|b|]hi[|/b|]"];
    const n00b_array_t(generated_ptr_t) ptrs =
        [nullptr, nullptr];

    n00b_static_objects_register_all();

    n00b_alloc_range_t *range = range_for_address(words.data);
    assert_static_alloc_info(words.data, range);
    assert(range->kind == n00b_mmap_static);
    assert(range->len == sizeof(n00b_string_t *) * 2);
    assert(range->scan_kind == N00B_GC_SCAN_KIND_ALL);
    assert(range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(range,
                              N00B_STATIC_IDENTITY_NCC_ARRAY_DATA,
                              "ncc-array-data:");
    assert(words.len == 2);
    assert(words.data[0]->u8_bytes == 5);
    assert(words.data[1]->u8_bytes == 2);
    assert(words.data[1]->styling != nullptr);

    assert(range_for_address(words.data[0])->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(range_for_address(words.data[1])->scan_kind == N00B_GC_SCAN_KIND_NONE);

    n00b_alloc_range_t *ptr_range = range_for_address(ptrs.data);
    assert_static_alloc_info(ptrs.data, ptr_range);
    assert(ptr_range->kind == n00b_mmap_static);
    assert(ptr_range->len == sizeof(generated_ptr_t) * 2);
    assert(ptr_range->scan_kind == N00B_GC_SCAN_KIND_ALL);
    assert(ptr_range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(ptr_range,
                              N00B_STATIC_IDENTITY_NCC_ARRAY_DATA,
                              "ncc-array-data:");
    assert(ptrs.len == 2);
    assert(ptrs.data[0] == nullptr);
    assert(ptrs.data[1] == nullptr);

    printf("  [PASS] generated_pointer_array_descriptor\n");
}

static void
test_generated_nested_array_descriptor(void)
{
    const n00b_array_t(generated_int_array_t) rows = [[1, 2], [3]];

    n00b_static_objects_register_all();

    n00b_alloc_range_t *range = range_for_address(rows.data);
    assert_static_alloc_info(rows.data, range);
    assert(range->kind == n00b_mmap_static);
    assert(range->len == sizeof(generated_int_array_t) * 2);
    assert(range->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(range->scan_cb == n00b_gc_scan_cb_struct_field);
    assert(range->scan_user != nullptr);
    assert(range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(range,
                              N00B_STATIC_IDENTITY_NCC_ARRAY_DATA,
                              "ncc-array-data:");
    assert(rows.len == 2);
    assert(rows.data[0].len == 2);
    assert(rows.data[0].data[1] == 2);
    assert(rows.data[1].len == 1);
    assert(rows.data[1].data[0] == 3);

    assert(range_for_address(rows.data[0].data)->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(range_for_address(rows.data[1].data)->scan_kind == N00B_GC_SCAN_KIND_NONE);

    printf("  [PASS] generated_nested_array_descriptor\n");
}

static void
test_generated_aggregate_array_descriptor(void)
{
    const n00b_array_t(generated_labeled_item_t) items =
        [{ .label = r"aggregate", .tag = 44, .alt = nullptr }];

    n00b_static_objects_register_all();

    n00b_alloc_range_t *range = range_for_address(items.data);
    assert_static_alloc_info(items.data, range);
    assert(range->kind == n00b_mmap_static);
    assert(range->len == sizeof(generated_labeled_item_t));
    assert(range->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(range->scan_cb == n00b_gc_scan_cb_struct_layout);
    assert(range->scan_user != nullptr);
    assert(range->flags & N00B_STATIC_OBJECT_F_MUTABLE);
    assert_generated_identity(range,
                              N00B_STATIC_IDENTITY_NCC_ARRAY_DATA,
                              "ncc-array-data:");

    n00b_gc_struct_layout_t *layout = range->scan_user;
    assert(layout->count == 1);
    assert(layout->stride == sizeof(generated_labeled_item_t) / sizeof(void *));
    assert(layout->offset_count == 2);
    assert(layout->offsets[0] == offsetof(generated_labeled_item_t, label) / sizeof(void *));
    assert(layout->offsets[1] == offsetof(generated_labeled_item_t, alt) / sizeof(void *));

    assert(items.len == 1);
    assert(items.data[0].tag == 44);
    assert(items.data[0].alt == nullptr);
    assert(items.data[0].label->u8_bytes == 9);
    assert(memcmp(items.data[0].label->data, "aggregate", 9) == 0);
    assert(range_for_address(items.data[0].label)->scan_kind == N00B_GC_SCAN_KIND_NONE);

    printf("  [PASS] generated_aggregate_array_descriptor\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running ncc static object descriptor tests...\n");
    test_generated_rstring_descriptors();
    test_generated_scalar_array_descriptor();
    test_generated_pointer_array_descriptor();
    test_generated_nested_array_descriptor();
    test_generated_aggregate_array_descriptor();

    return 0;
}

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "adt/dict.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "util/assert.h"
#include "util/marshal.h"
#include "util/path.h"

#include <rocs/n00b_rocs.h>
#include <rocs/map.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    uint64_t marshal_magic;
    uint32_t version;
    uint32_t base_address;
    uint32_t root_offset;
    uint32_t payload_front_len;
} test_marshal_stream_header_t;

typedef struct {
    uint64_t records;
    uint64_t columns;
    uint64_t retain_raw;
    uint32_t state;
    uint32_t reserved;
    uint64_t record_count;
    uint64_t byte_estimate;
    uint64_t open_ts;
    uint64_t seal_ts;
    uint64_t shard_id;
} test_shard_wire_t;

typedef struct {
    uint64_t tag;
    uint64_t value;
} test_leaf_t;

typedef struct {
    n00b_buffer_t  *image;
    n00b_uint128_t  target_hv;
    n00b_uint128_t  deleted_hv;
    uint64_t        shard_id;
} map_fixture_t;

static void *
arena_obj(n00b_arena_t *arena, size_t len, n00b_gc_scan_kind_t scan_kind)
{
    return n00b_alloc_size_with_opts(1,
                                     len,
                                     &(n00b_alloc_opts_t){
                                         .allocator = (n00b_allocator_t *)arena,
                                         .scan_kind = scan_kind,
                                     });
}

static map_fixture_t
make_fixture(void)
{
    enum {
        BASE = 0x5a17c0deu,
    };

    n00b_arena_t *arena = n00b_new_arena(.size = 16384, .use_gc = true);

    test_leaf_t *record0 = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *record1 = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *key0    = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *key1    = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *key2    = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *value0  = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *value1  = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);
    test_leaf_t *value2  = arena_obj(arena, sizeof(test_leaf_t),
                                     N00B_GC_SCAN_KIND_NONE);

    record0->tag = UINT64_C(0x1000);
    record1->tag = UINT64_C(0x1001);
    key0->tag    = UINT64_C(0x2000);
    key1->tag    = UINT64_C(0x2001);
    key2->tag    = UINT64_C(0x2002);
    value0->tag  = UINT64_C(0x3000);
    value1->tag  = UINT64_C(0x3001);
    value2->tag  = UINT64_C(0x3002);

    n00b_list_t(void *) *records = arena_obj(arena,
                                             sizeof(n00b_list_t(void *)),
                                             N00B_GC_SCAN_KIND_ALL);
    void **record_data = n00b_alloc_array_with_opts(
        void *,
        2,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    record_data[0] = record0;
    record_data[1] = record1;
    *records = (n00b_list_t(void *)){
        .data = record_data,
        .len  = 2,
        .cap  = 2,
    };

    /*
     * CONTRACT: Build a typed-dict layout fixture directly, not through
     * hot dict APIs. The mapped reader must resolve this layout by vaddr and
     * must not write bucket flags even when sync-only bits are present. Buckets
     * are POD; key/value arrays carry the pointer scan shape.
     */
    _n00b_dict_internal_t *columns = arena_obj(arena,
                                               sizeof(_n00b_dict_internal_t),
                                               N00B_GC_SCAN_KIND_ALL);
    __n00b_internal_type_erased_store_t *store = arena_obj(
        arena,
        sizeof(__n00b_internal_type_erased_store_t),
        N00B_GC_SCAN_KIND_ALL);
    n00b_dict_bucket_t *buckets = n00b_alloc_array_with_opts(
        n00b_dict_bucket_t,
        16,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    void **keys = n00b_alloc_array_with_opts(
        void *,
        16,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    void **values = n00b_alloc_array_with_opts(
        void *,
        16,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });

    n00b_uint128_t colliding_hv = (n00b_uint128_t)0x15u;
    n00b_uint128_t target_hv    = (n00b_uint128_t)0x25u;
    n00b_uint128_t deleted_hv   = (n00b_uint128_t)0x28u;

    buckets[5].hv = colliding_hv;
    keys[5]       = key0;
    values[5]     = value0;

    buckets[6].hv = target_hv;
    atomic_store(&buckets[6].flags,
                 N00B_HT_FLAG_MUTEX | N00B_HT_FLAG_COPYING | N00B_HT_FLAG_MOVING);
    keys[6]   = key1;
    values[6] = value1;

    buckets[8].hv = deleted_hv;
    atomic_store(&buckets[8].flags,
                 N00B_HT_FLAG_DELETED | N00B_HT_FLAG_MUTEX);
    keys[8]   = key2;
    values[8] = value2;

    store->last_slot = 15;
    store->threshold = 11;
    atomic_store(&store->used_count, 3);
    store->buckets = buckets;
    store->keys    = keys;
    store->values  = values;
    atomic_store(&columns->store, (void **)store);
    atomic_store(&columns->length, 2);

    test_shard_wire_t *root = arena_obj(arena,
                                        sizeof(test_shard_wire_t),
                                        N00B_GC_SCAN_KIND_ALL);
    *root = (test_shard_wire_t){
        .records       = (uint64_t)(uintptr_t)records,
        .columns       = (uint64_t)(uintptr_t)columns,
        .record_count  = 2,
        .byte_estimate = 128,
        .open_ts       = 11,
        .seal_ts       = 22,
        .shard_id      = UINT64_C(0xabcddcba12344321),
    };

    n00b_buffer_t *image = n00b_marshal(root, .base_address = BASE);
    CHECK(image != nullptr);

    return (map_fixture_t){
        .image      = image,
        .target_hv  = target_hv,
        .deleted_hv = deleted_hv,
        .shard_id   = root->shard_id,
    };
}

static n00b_buffer_t *
copy_buffer(n00b_buffer_t *src)
{
    _n00b_buffer_rlock(src);
    n00b_buffer_t *result = n00b_buffer_from_bytes(src->data,
                                                   (int64_t)src->byte_len);
    _n00b_buffer_unlock(src);
    return result;
}

static test_shard_wire_t *
buffer_root(n00b_buffer_t *buf)
{
    test_marshal_stream_header_t *hdr = (void *)buf->data;
    return (void *)(buf->data + sizeof(*hdr) + hdr->root_offset);
}

static void
expect_open_buffer_err(n00b_buffer_t *buf, n00b_store_map_err_t err)
{
    auto r = n00b_store_map_open_buffer(buf);
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_get_err(r) == err);
}

static n00b_string_t *
write_image_file(n00b_buffer_t *image)
{
    n00b_string_t *path = n00b_new_temp_path(r"rocs_map_", r".bin");
    auto           open = n00b_file_open(path, .mode = N00B_FILE_W);
    CHECK(n00b_result_is_ok(open));
    n00b_file_t *file = n00b_result_get(open);
    auto         wr   = n00b_file_write_all(file, image);
    CHECK(n00b_result_is_ok(wr));
    CHECK(n00b_result_get(wr) == n00b_buffer_len(image));
    auto close = n00b_file_close_result(file);
    CHECK(n00b_result_is_ok(close));
    return path;
}

static n00b_buffer_t *
read_file_copy(n00b_string_t *path)
{
    auto open = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    CHECK(n00b_result_is_ok(open));
    n00b_file_t *file = n00b_result_get(open);
    auto         br   = n00b_file_as_buffer(file);
    CHECK(n00b_result_is_ok(br));
    n00b_buffer_t *mapped = n00b_result_get(br);
    n00b_buffer_t *copy   = n00b_buffer_from_bytes(mapped->data,
                                                   (int64_t)mapped->byte_len);
    n00b_buffer_free(mapped);
    n00b_file_close(file);
    return copy;
}

static bool
buffers_equal(n00b_buffer_t *a, n00b_buffer_t *b)
{
    if (n00b_buffer_len(a) != n00b_buffer_len(b)) {
        return false;
    }
    return memcmp(a->data, b->data, a->byte_len) == 0;
}

static void
test_bad_images(void)
{
    map_fixture_t fixture = make_fixture();

    n00b_buffer_t *bad_magic = copy_buffer(fixture.image);
    ((test_marshal_stream_header_t *)bad_magic->data)->marshal_magic
        ^= UINT64_C(0x55);
    expect_open_buffer_err(bad_magic, N00B_STORE_MAP_ERR_BAD_MAGIC);

    n00b_buffer_t *bad_version = copy_buffer(fixture.image);
    ((test_marshal_stream_header_t *)bad_version->data)->version = 3;
    expect_open_buffer_err(bad_version, N00B_STORE_MAP_ERR_BAD_VERSION);

    n00b_buffer_t *truncated = n00b_buffer_from_bytes(
        fixture.image->data,
        (int64_t)n00b_buffer_len(fixture.image) - 1);
    expect_open_buffer_err(truncated, N00B_STORE_MAP_ERR_BAD_LAYOUT);

    n00b_string_t *path = write_image_file(bad_magic);
    auto           r    = n00b_store_map_open_local_file(path);
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_get_err(r) == N00B_STORE_MAP_ERR_BAD_MAGIC);
    (void)n00b_file_unlink(path, .ignore_missing = true);
}

static void
test_open_buffer_and_views(void)
{
    map_fixture_t fixture = make_fixture();
    auto          open    = n00b_store_map_open_buffer(fixture.image);
    CHECK(n00b_result_is_ok(open));
    n00b_store_map_t *map = n00b_result_get(open);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    n00b_store_map_shard_t *root = n00b_result_get(root_r);
    auto shard_id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_ok(shard_id_r));
    CHECK(n00b_result_get(shard_id_r) == fixture.shard_id);
    auto record_len_r = n00b_store_map_shard_records_len(root);
    CHECK(n00b_result_is_ok(record_len_r));
    CHECK(n00b_result_get(record_len_r) == 2);

    auto records_r = n00b_store_map_shard_records(root);
    CHECK(n00b_result_is_ok(records_r));
    n00b_store_map_list_t *records = n00b_result_get(records_r);
    auto list_len_r = n00b_store_map_list_len(records);
    CHECK(n00b_result_is_ok(list_len_r));
    CHECK(n00b_result_get(list_len_r) == 2);

    auto slot_r = n00b_store_map_list_slot(records, 0);
    CHECK(n00b_result_is_ok(slot_r));
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    CHECK(n00b_option_is_set(slot_opt));
    auto ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    CHECK(n00b_result_is_ok(ref_r));
    CHECK(n00b_option_is_set(n00b_result_get(ref_r)));

    auto missing_slot = n00b_store_map_list_slot(records, 99);
    CHECK(n00b_result_is_ok(missing_slot));
    CHECK(!n00b_option_is_set(n00b_result_get(missing_slot)));

    auto columns_r = n00b_store_map_shard_columns(root);
    CHECK(n00b_result_is_ok(columns_r));
    n00b_store_map_dict_t *columns = n00b_result_get(columns_r);
    auto found_r = n00b_store_map_dict_find_hv(columns, fixture.target_hv);
    CHECK(n00b_result_is_ok(found_r));
    n00b_option_t(n00b_store_map_dict_entry_t *) found = n00b_result_get(found_r);
    CHECK(n00b_option_is_set(found));
    n00b_store_map_dict_entry_t *entry = n00b_option_get(found);
    CHECK(entry->bucket_index == 6);
    CHECK(entry->hv == fixture.target_hv);

    auto key_ref = n00b_store_map_slot_ref(entry->key);
    CHECK(n00b_result_is_ok(key_ref));
    CHECK(n00b_option_is_set(n00b_result_get(key_ref)));
    auto value_ref = n00b_store_map_slot_ref(entry->value);
    CHECK(n00b_result_is_ok(value_ref));
    CHECK(n00b_option_is_set(n00b_result_get(value_ref)));

    auto deleted_r = n00b_store_map_dict_find_hv(columns, fixture.deleted_hv);
    CHECK(n00b_result_is_ok(deleted_r));
    CHECK(!n00b_option_is_set(n00b_result_get(deleted_r)));

    auto missing_r = n00b_store_map_dict_find_hv(columns, (n00b_uint128_t)0x3fu);
    CHECK(n00b_result_is_ok(missing_r));
    CHECK(!n00b_option_is_set(n00b_result_get(missing_r)));

    auto close_r = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close_r));

    auto closed_id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_err(closed_id_r));
    CHECK(n00b_result_get_err(closed_id_r) == N00B_STORE_MAP_ERR_ARG);
    auto closed_records_len_r = n00b_store_map_shard_records_len(root);
    CHECK(n00b_result_is_err(closed_records_len_r));
    CHECK(n00b_result_get_err(closed_records_len_r) == N00B_STORE_MAP_ERR_ARG);
    auto closed_list_len_r = n00b_store_map_list_len(records);
    CHECK(n00b_result_is_err(closed_list_len_r));
    CHECK(n00b_result_get_err(closed_list_len_r) == N00B_STORE_MAP_ERR_ARG);
    auto null_id_r = n00b_store_map_shard_id(nullptr);
    CHECK(n00b_result_is_err(null_id_r));
    CHECK(n00b_result_get_err(null_id_r) == N00B_STORE_MAP_ERR_ARG);
    auto null_list_len_r = n00b_store_map_list_len(nullptr);
    CHECK(n00b_result_is_err(null_list_len_r));
    CHECK(n00b_result_get_err(null_list_len_r) == N00B_STORE_MAP_ERR_ARG);
}

static void
test_nested_range_errors(void)
{
    map_fixture_t fixture = make_fixture();
    n00b_buffer_t *bad    = copy_buffer(fixture.image);
    test_marshal_stream_header_t *hdr = (void *)bad->data;
    test_shard_wire_t            *root = buffer_root(bad);
    root->records = ((uint64_t)hdr->base_address << 32)
                  | (uint64_t)(hdr->payload_front_len + 8u);

    auto open = n00b_store_map_open_buffer(bad);
    CHECK(n00b_result_is_ok(open));
    n00b_store_map_t *map = n00b_result_get(open);
    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    auto records_r = n00b_store_map_shard_records(n00b_result_get(root_r));
    CHECK(n00b_result_is_err(records_r));
    CHECK(n00b_result_get_err(records_r) == N00B_STORE_MAP_ERR_RANGE);
    (void)n00b_store_map_close(map);
}

static void
test_local_file_and_no_write_lookup(void)
{
    map_fixture_t fixture = make_fixture();
    n00b_buffer_t *before = copy_buffer(fixture.image);
    n00b_string_t *path   = write_image_file(fixture.image);

    auto open = n00b_store_map_open_local_file(path);
    CHECK(n00b_result_is_ok(open));
    n00b_store_map_t *map = n00b_result_get(open);
    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    auto dict_r = n00b_store_map_shard_columns(n00b_result_get(root_r));
    CHECK(n00b_result_is_ok(dict_r));
    auto found_r = n00b_store_map_dict_find_hv(n00b_result_get(dict_r),
                                               fixture.target_hv);
    CHECK(n00b_result_is_ok(found_r));
    CHECK(n00b_option_is_set(n00b_result_get(found_r)));
    auto close_r = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close_r));

    n00b_buffer_t *after = read_file_copy(path);
    CHECK(buffers_equal(before, after));
    (void)n00b_file_unlink(path, .ignore_missing = true);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_bad_images();
    test_open_buffer_and_views();
    test_nested_range_errors();
    test_local_file_and_no_write_lookup();
    n00b_shutdown();
    return 0;
}

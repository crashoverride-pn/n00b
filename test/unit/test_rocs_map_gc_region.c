#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/gc.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "util/assert.h"
#include "util/marshal.h"
#include "util/path.h"

#include <rocs/n00b_rocs.h>
#include <rocs/map.h>
#include "internal/rocs/map.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    uint64_t records;
    uint64_t columns;
    uint64_t retain_raw;
    uint64_t raw_bytes;
    uint32_t state;
    uint32_t reserved;
    uint64_t record_count;
    uint64_t byte_estimate;
    uint64_t open_ts;
    uint64_t seal_ts;
    uint64_t shard_id;
} test_shard_wire_t;

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

static n00b_buffer_t *
make_fixture(uint64_t shard_id)
{
    enum {
        BASE = 0x6c17c0deu,
    };

    n00b_arena_t     *arena = n00b_new_arena(.size = 16384, .use_gc = true);
    test_shard_wire_t *root = arena_obj(arena,
                                        sizeof(test_shard_wire_t),
                                        N00B_GC_SCAN_KIND_NONE);
    *root = (test_shard_wire_t){
        .shard_id = shard_id,
    };

    n00b_buffer_t *image = n00b_marshal(root, .base_address = BASE);
    CHECK(image != nullptr);
    CHECK(n00b_buffer_len(image) > sizeof(test_shard_wire_t));
    return image;
}

static n00b_string_t *
write_image_file(n00b_buffer_t *image)
{
    n00b_string_t *path = n00b_new_temp_path(r"rocs_map_gc_region_", r".bin");
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

static uint8_t *
registered_probe(n00b_store_map_t *map)
{
    auto base_r = n00b_store_map_resident_base_for_test(map);
    CHECK(n00b_result_is_ok(base_r));
    auto len_r = n00b_store_map_resident_len_for_test(map);
    CHECK(n00b_result_is_ok(len_r));

    uint8_t *base = (uint8_t *)(uintptr_t)n00b_result_get(base_r);
    uint64_t len  = n00b_result_get(len_r);
    CHECK(base != nullptr);
    CHECK(len > 0);

    uint8_t *probe = base + len / 2;
    auto     mmap  = n00b_mmap_by_address(probe);
    CHECK(n00b_option_is_set(mmap));
    CHECK(n00b_option_get(mmap)->kind == n00b_mmap_api_mmap);

    auto range = n00b_mmap_range_by_address(probe);
    CHECK(!n00b_option_is_set(range));
    return probe;
}

static void
expect_unregistered(uint8_t *probe)
{
    auto mmap = n00b_mmap_by_address(probe);
    CHECK(!n00b_option_is_set(mmap));

    auto range = n00b_mmap_range_by_address(probe);
    CHECK(!n00b_option_is_set(range));
}

static void
collect_with_live_views(n00b_store_map_t *map, uint64_t shard_id)
{
    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    n00b_store_map_shard_t *root = n00b_result_get(root_r);
    auto shard_id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_ok(shard_id_r));
    CHECK(n00b_result_get(shard_id_r) == shard_id);

    n00b_gc_register_root(map);
    n00b_gc_register_root(root);
    n00b_collect(n00b_get_runtime()->default_arena);
    n00b_gc_unregister_root(root);
    n00b_gc_unregister_root(map);

    shard_id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_ok(shard_id_r));
    CHECK(n00b_result_get(shard_id_r) == shard_id);
}

static void
test_buffer_backing_region(void)
{
    uint64_t      shard_id = UINT64_C(0x427566666572);
    n00b_buffer_t *image   = make_fixture(shard_id);

    auto open = n00b_store_map_open_buffer(image);
    CHECK(n00b_result_is_ok(open));
    n00b_store_map_t *map   = n00b_result_get(open);
    uint8_t          *probe = registered_probe(map);

    collect_with_live_views(map, shard_id);

    auto close = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close));
    expect_unregistered(probe);
}

static void
test_local_file_region(void)
{
    uint64_t       shard_id = UINT64_C(0x46494c45524f4353);
    n00b_buffer_t *image    = make_fixture(shard_id);
    n00b_string_t *path     = write_image_file(image);

    auto open = n00b_store_map_open_local_file(path);
    CHECK(n00b_result_is_ok(open));
    n00b_store_map_t *map   = n00b_result_get(open);
    uint8_t          *probe = registered_probe(map);

    collect_with_live_views(map, shard_id);

    auto close = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close));
    expect_unregistered(probe);
    (void)n00b_file_unlink(path, .ignore_missing = true);
}

static void
test_failed_open_does_not_expose_source(void)
{
    n00b_buffer_t *bad = make_fixture(UINT64_C(0xbad));
    bad->data[0] ^= 0x55;

    auto open = n00b_store_map_open_buffer(bad);
    CHECK(n00b_result_is_err(open));

    /*
     * CONTRACT: rocs registers only the owned resident copy after validation.
     * The caller's source buffer is never a resident rocs region, including
     * failed-open paths.
     */
    auto range = n00b_mmap_range_by_address(bad->data);
    CHECK(!n00b_option_is_set(range));

    auto mmap = n00b_mmap_by_address(bad->data);
    if (n00b_option_is_set(mmap)) {
        CHECK(n00b_option_get(mmap)->kind != n00b_mmap_api_mmap);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_buffer_backing_region();
    test_local_file_region();
    test_failed_open_does_not_expose_source();
    n00b_shutdown();
    return 0;
}

/* test/unit/test_rocs_residency.c - WP-005 Phase 4 residency contracts. */

#include <stdint.h>

#include "n00b.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/hooks.h"
#include "vfs/vfs.h"

#include "internal/rocs/map.h"
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    uint64_t shard_opens;
} hook_counter_t;

static n00b_store_schema_t *
new_schema(void)
{
    auto r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_vfs_t *
new_memory_vfs(n00b_vfs_mount_t **mount_out)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    if (mount_out != nullptr) {
        *mount_out = n00b_result_get(mount_r);
    }
    return vfs;
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs) _kargs
{
    n00b_store_residency_policy_t *policy = nullptr;
}
{
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       new_schema(),
                                       .residency_policy = policy);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_store_catalog_entry_t *
seal_one(n00b_store_t *store, uint64_t seal_ts)
{
    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static n00b_store_catalog_entry_t *
find_entry(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static uint64_t
entry_len(n00b_store_catalog_entry_t *entry)
{
    auto len_r = n00b_store_catalog_entry_get_byte_len(entry);
    CHECK(n00b_result_is_ok(len_r));
    return n00b_result_get(len_r);
}

static void
count_shard_open_hook(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    hook_counter_t *counter = cookie;
    if (ctx->path != nullptr
        && n00b_unicode_str_starts_with(ctx->path, r"/rocs/shards/")) {
        counter->shard_opens++;
    }
}

static n00b_store_map_t *
resident_map(n00b_store_resident_shard_t *resident)
{
    auto map_r = n00b_store_resident_shard_map(resident);
    CHECK(n00b_result_is_ok(map_r));
    return n00b_result_get(map_r);
}

static void
check_shard_id(n00b_store_map_t *map, uint64_t expected)
{
    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    auto id_r = n00b_store_map_shard_id(n00b_result_get(root_r));
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_get(id_r) == expected);
}

static void
test_metadata_only_reopen_still_cold(void)
{
    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(&mount);
    n00b_store_t     *store = open_store(vfs);

    for (uint64_t i = 0; i < 4; i++) {
        seal_one(store, i + 1);
    }
    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    hook_counter_t counter = {};
    auto hook_r = n00b_vfs_hook_add(mount,
                                    N00B_VFS_HOOK_PRE_OPEN,
                                    count_shard_open_hook,
                                    &counter,
                                    0);
    CHECK(n00b_result_is_ok(hook_r));

    n00b_store_t *reopened = open_store(vfs);
    CHECK(counter.shard_opens == 0);

    auto count_r = n00b_store_catalog_get_entry_count(reopened);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 4);
    auto resident_r = n00b_store_get_resident_shard_count(reopened);
    CHECK(n00b_result_is_ok(resident_r));
    CHECK(n00b_result_get(resident_r) == 0);

    close_r = n00b_store_close(reopened);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_lazy_load_reuse_and_trim(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *first  = seal_one(store, 10);
    n00b_store_catalog_entry_t *second = seal_one(store, 20);
    uint64_t first_len  = entry_len(first);
    uint64_t second_len = entry_len(second);

    auto is_resident = n00b_store_catalog_entry_is_resident(first);
    CHECK(n00b_result_is_ok(is_resident));
    CHECK(!n00b_result_get(is_resident));

    auto first_r = n00b_store_resident_shard_acquire(store, first);
    CHECK(n00b_result_is_ok(first_r));
    n00b_store_resident_shard_t *first_handle = n00b_result_get(first_r);
    check_shard_id(resident_map(first_handle), 1);

    auto count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);
    auto bytes_r = n00b_store_get_resident_bytes(store);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) == first_len);

    auto release_r = n00b_store_resident_shard_release(first_handle);
    CHECK(n00b_result_is_ok(release_r));

    first_r = n00b_store_resident_shard_acquire(store, first);
    CHECK(n00b_result_is_ok(first_r));
    first_handle = n00b_result_get(first_r);
    count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);
    release_r = n00b_store_resident_shard_release(first_handle);
    CHECK(n00b_result_is_ok(release_r));

    auto second_r = n00b_store_resident_shard_acquire(store, second);
    CHECK(n00b_result_is_ok(second_r));
    n00b_store_resident_shard_t *second_handle = n00b_result_get(second_r);
    release_r = n00b_store_resident_shard_release(second_handle);
    CHECK(n00b_result_is_ok(release_r));

    count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);
    bytes_r = n00b_store_get_resident_bytes(store);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) == first_len + second_len);

    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == first_len + second_len);
    count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
    bytes_r = n00b_store_get_resident_bytes(store);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) == 0);

    auto stat_r = n00b_store_catalog_entry_verify_object(store, first);
    CHECK(n00b_result_is_ok(stat_r));
    stat_r = n00b_store_catalog_entry_verify_object(store, second);
    CHECK(n00b_result_is_ok(stat_r));

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_pin_blocks_trim_and_close(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *entry = seal_one(store, 30);

    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == 0);
    auto count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_err(close_r));
    CHECK(n00b_result_get_err(close_r) == N00B_STORE_ERR_PINNED);

    auto release_r = n00b_store_resident_shard_release(resident);
    CHECK(n00b_result_is_ok(release_r));
    trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == entry_len(entry));
    close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_unload_unregisters_region(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *entry = seal_one(store, 40);

    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);
    n00b_store_map_t *map = resident_map(resident);

    auto base_r = n00b_store_map_resident_base_for_test(map);
    CHECK(n00b_result_is_ok(base_r));
    auto len_r = n00b_store_map_resident_len_for_test(map);
    CHECK(n00b_result_is_ok(len_r));
    uint8_t *probe = (uint8_t *)(uintptr_t)n00b_result_get(base_r)
                   + n00b_result_get(len_r) / 2;
    CHECK(n00b_option_is_set(n00b_mmap_by_address(probe)));

    auto release_r = n00b_store_resident_shard_release(resident);
    CHECK(n00b_result_is_ok(release_r));
    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(!n00b_option_is_set(n00b_mmap_by_address(probe)));

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_explicit_mmap_modes_do_not_fake_vfs_paths(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *entry = seal_one(store, 50);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));
    n00b_string_t *path = n00b_result_get(path_r);

    n00b_store_residency_policy_t policy =
        n00b_store_residency_policy_get_default();
    policy.preferred_backing = N00B_STORE_IMAGE_LOCAL_MMAP;
    auto map_r = n00b_store_map_open_vfs(vfs, path, .policy = &policy);
    CHECK(n00b_result_is_err(map_r));
    CHECK(n00b_result_get_err(map_r) == N00B_STORE_MAP_ERR_BACKING);

    policy.preferred_backing = N00B_STORE_IMAGE_CACHE_MMAP;
    map_r = n00b_store_map_open_vfs(vfs, path, .policy = &policy);
    CHECK(n00b_result_is_err(map_r));
    CHECK(n00b_result_get_err(map_r) == N00B_STORE_MAP_ERR_CACHE);

    policy.preferred_backing = N00B_STORE_IMAGE_PINNED_BUFFER;
    map_r = n00b_store_map_open_vfs(vfs, path, .policy = &policy);
    CHECK(n00b_result_is_ok(map_r));
    auto close_r = n00b_store_map_close(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(close_r));

    close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_metadata_only_reopen_still_cold();
    test_lazy_load_reuse_and_trim();
    test_pin_blocks_trim_and_close();
    test_unload_unregisters_region();
    test_explicit_mmap_modes_do_not_fake_vfs_paths();
    n00b_shutdown();
    return 0;
}

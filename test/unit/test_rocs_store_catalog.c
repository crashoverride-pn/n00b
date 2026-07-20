/* test/unit/test_rocs_store_catalog.c - WP-005 Phase 2 catalog contracts. */

#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/path.h"
#include "vfs/backend_local.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static n00b_string_t *tmp_dir;

typedef struct {
    uint64_t shard_opens;
} hook_counter_t;

typedef struct {
    bool deny_catalog_open;
} catalog_deny_t;

static void
make_tmpdir(void)
{
    auto tmp_r = n00b_new_temp_dir(r"n00b_rocs_store_catalog_", nullptr);
    CHECK(n00b_result_is_ok(tmp_r));
    tmp_dir = n00b_result_get(tmp_r);
}

static void
rm_tmpdir(void)
{
    if (tmp_dir == nullptr) {
        return;
    }

    auto rm_r = n00b_path_remove_tree(tmp_dir, .ignore_missing = true);
    CHECK(n00b_result_is_ok(rm_r));
    tmp_dir = nullptr;
}

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

static n00b_vfs_t *
new_local_vfs(void)
{
    make_tmpdir();

    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_local_new(tmp_dir);
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    return vfs;
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs)
{
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", new_schema());
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

static n00b_json_node_t *
record_with_id(uint64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put(record, "id", n00b_json_int_new((int64_t)id));
    return record;
}

static n00b_store_catalog_entry_t *
seal_record(n00b_store_t *store, uint64_t id, uint64_t seal_ts)
{
    auto ingest_r = n00b_store_ingest(store, record_with_id(id));
    CHECK(n00b_result_is_ok(ingest_r));
    return seal_one(store, seal_ts);
}

static void
write_vfs_string(n00b_vfs_t *vfs, n00b_string_t *path, n00b_string_t *data)
{
    auto open_r = n00b_vfs_open(vfs, path, N00B_VFS_O_W);
    CHECK(n00b_result_is_ok(open_r));

    n00b_buffer_t *buf = n00b_buffer_from_bytes(data->data,
                                                (int64_t)data->u8_bytes);
    auto write_r = n00b_vfs_write(vfs, n00b_result_get(open_r), buf);
    CHECK(n00b_result_is_ok(write_r));
    CHECK(n00b_result_get(write_r) == data->u8_bytes);

    auto close_r = n00b_vfs_close(vfs, n00b_result_get(open_r));
    CHECK(n00b_result_is_ok(close_r));
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

static void
deny_catalog_open_hook(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    catalog_deny_t *control = cookie;
    if (control->deny_catalog_open && ctx->path != nullptr
        && n00b_unicode_str_eq(ctx->path, r"/rocs/catalog.rocs")
        && (ctx->flags & N00B_VFS_OPEN_WRITE)) {
        ctx->denied  = true;
        ctx->deny_err = N00B_VFS_ERR_IO;
    }
}

static n00b_store_catalog_entry_t *
find_entry(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static n00b_store_catalog_entry_t *
find_any_entry(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_any_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static void
test_position_token_roundtrip(void)
{
    n00b_store_pos_t pos = {
        .shard_id   = 42,
        .ordinal    = 7,
        .generation = 3,
    };

    auto token_r = n00b_store_pos_encode(pos);
    CHECK(n00b_result_is_ok(token_r));
    CHECK(n00b_result_get(token_r)->u8_bytes == 48);

    auto decoded_r = n00b_store_pos_decode(n00b_result_get(token_r));
    CHECK(n00b_result_is_ok(decoded_r));
    CHECK(n00b_store_pos_compare(pos, n00b_result_get(decoded_r)) == 0);

    n00b_store_pos_t later = {
        .shard_id   = 43,
        .ordinal    = 0,
        .generation = 3,
    };
    CHECK(n00b_store_pos_compare(pos, later) < 0);

    auto bad_r = n00b_store_pos_decode(r"not-a-token");
    CHECK(n00b_result_is_err(bad_r));
    CHECK(n00b_result_get_err(bad_r) == N00B_STORE_ERR_ARG);
}

static void
test_memory_catalog_reopen(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *entry = seal_one(store, 123);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(path_r),
                              r"/rocs/shards/1.n00b"));

    auto bytes_r = n00b_store_catalog_entry_get_byte_len(entry);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) > 0);

    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 0);

    auto etag_r = n00b_store_catalog_entry_get_etag(entry);
    CHECK(n00b_result_is_ok(etag_r));
    CHECK(!n00b_option_is_set(n00b_result_get(etag_r)));

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    n00b_store_t *reopened = open_store(vfs);
    auto count_r = n00b_store_catalog_get_entry_count(reopened);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *found = find_entry(reopened, 1);
    auto verify_r = n00b_store_catalog_entry_verify_object(reopened, found);
    CHECK(n00b_result_is_ok(verify_r));

    n00b_store_catalog_entry_t *second = seal_one(reopened, 456);
    path_r = n00b_store_catalog_entry_get_object_path(second);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(path_r),
                              r"/rocs/shards/2.n00b"));
}

static void
test_metadata_only_reopen(void)
{
    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(&mount);
    n00b_store_t     *store = open_store(vfs);

    for (uint64_t i = 0; i < 8; i++) {
        seal_one(store, i + 1);
    }

    hook_counter_t counter = {};
    auto hook_r = n00b_vfs_hook_add(mount,
                                    N00B_VFS_HOOK_PRE_OPEN,
                                    count_shard_open_hook,
                                    &counter,
                                    0);
    CHECK(n00b_result_is_ok(hook_r));

    n00b_store_t *reopened = open_store(vfs);
    CHECK(reopened != nullptr);
    CHECK(counter.shard_opens == 0);

    auto count_r = n00b_store_catalog_get_entry_count(reopened);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 8);
}

static void
test_missing_shard_object_error(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *entry = seal_one(store, 99);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));

    auto del_r = n00b_vfs_delete(vfs, n00b_result_get(path_r));
    CHECK(n00b_result_is_ok(del_r));

    auto verify_r = n00b_store_catalog_entry_verify_object(store, entry);
    CHECK(n00b_result_is_err(verify_r));
    CHECK(n00b_result_get_err(verify_r) == N00B_STORE_ERR_VFS);

    n00b_store_t *reopened = open_store(vfs);
    n00b_store_catalog_entry_t *found = find_entry(reopened, 1);
    verify_r = n00b_store_catalog_entry_verify_object(reopened, found);
    CHECK(n00b_result_is_err(verify_r));
    CHECK(n00b_result_get_err(verify_r) == N00B_STORE_ERR_VFS);
}

static void
test_drop_missing_shard_object_prunes_catalog(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *entry = seal_one(store, 101);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));
    n00b_string_t *path = n00b_result_get(path_r);

    auto del_r = n00b_vfs_delete(vfs, path);
    CHECK(n00b_result_is_ok(del_r));

    auto drop_r = n00b_store_drop_sealed_shard(store,
                                               1,
                                               .drop_reason = r"repair");
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));

    auto find_r = n00b_store_catalog_find_shard(store, 1);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(!n00b_option_is_set(n00b_result_get(find_r)));

    auto stat_r = n00b_vfs_stat(vfs, path);
    CHECK(n00b_result_is_err(stat_r));
    CHECK(n00b_result_get_err(stat_r) == N00B_VFS_ERR_NOT_FOUND);

    n00b_store_t *reopened = open_store(vfs);
    auto count_r = n00b_store_catalog_get_entry_count(reopened);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
}

static void
test_existing_shard_object_blocks_seal(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    write_vfs_string(vfs, r"/rocs/shards/1.n00b", r"occupied");

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 22);
    CHECK(n00b_result_is_err(seal_r));
    CHECK(n00b_result_get_err(seal_r) == N00B_STORE_ERR_VFS);

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
}

static void
test_catalog_failure_rolls_back_visibility(void)
{
    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(&mount);
    n00b_store_t     *store = open_store(vfs);
    catalog_deny_t    control = {
        .deny_catalog_open = true,
    };

    auto hook_r = n00b_vfs_hook_add(mount,
                                    N00B_VFS_HOOK_PRE_OPEN,
                                    deny_catalog_open_hook,
                                    &control,
                                    0);
    CHECK(n00b_result_is_ok(hook_r));

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 33);
    CHECK(n00b_result_is_err(seal_r));
    CHECK(n00b_result_get_err(seal_r) == N00B_STORE_ERR_VFS);

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);

    auto orphan_r = n00b_vfs_stat(vfs, r"/rocs/shards/1.n00b");
    CHECK(n00b_result_is_err(orphan_r));
    CHECK(n00b_result_get_err(orphan_r) == N00B_VFS_ERR_NOT_FOUND);

    control.deny_catalog_open = false;
    n00b_store_catalog_entry_t *entry = seal_one(store, 34);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(path_r),
                              r"/rocs/shards/2.n00b"));
}

static void
test_corrupt_shard_length_error(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *entry = seal_one(store, 44);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));

    write_vfs_string(vfs, n00b_result_get(path_r), r"bad");

    auto verify_r = n00b_store_catalog_entry_verify_object(store, entry);
    CHECK(n00b_result_is_err(verify_r));
    CHECK(n00b_result_get_err(verify_r) == N00B_STORE_ERR_CORRUPT);
}

static void
test_corrupt_shard_does_not_poison_catalog_ops(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *bad  = seal_record(store, 1, 100);
    n00b_store_catalog_entry_t *good = seal_record(store, 2, 200);

    auto bad_path_r = n00b_store_catalog_entry_get_object_path(bad);
    CHECK(n00b_result_is_ok(bad_path_r));
    write_vfs_string(vfs, n00b_result_get(bad_path_r), r"bad");

    auto bad_verify_r = n00b_store_catalog_entry_verify_object(store, bad);
    CHECK(n00b_result_is_err(bad_verify_r));
    CHECK(n00b_result_get_err(bad_verify_r) == N00B_STORE_ERR_CORRUPT);
    CHECK(n00b_result_is_ok(
        n00b_store_catalog_entry_verify_object(store, good)));

    auto count_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    auto backlog_r = n00b_store_catalog_backlog(store, nullptr);
    CHECK(n00b_result_is_ok(backlog_r));
    n00b_store_backlog_t backlog = n00b_result_get(backlog_r);
    CHECK(backlog.shards_remaining == 2);
    CHECK(backlog.records_remaining == 2);

    auto oldest_r = n00b_store_oldest_available_pos(store);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    CHECK(n00b_option_get(n00b_result_get(oldest_r)).shard_id == 1);

    auto expires_r = n00b_store_oldest_available_expires_at_ns(store);
    CHECK(n00b_result_is_ok(expires_r));
    // Retention is opt-in now; open_store requests no window, so the oldest
    // shard has no age-expiry. (The set-expiry path is covered in the retention
    // suite, which opens with an explicit window.)
    CHECK(!n00b_option_is_set(n00b_result_get(expires_r)));

    auto good_find_r = n00b_store_catalog_find_shard(store, 2);
    CHECK(n00b_result_is_ok(good_find_r));
    CHECK(n00b_option_is_set(n00b_result_get(good_find_r)));

    auto drop_r = n00b_store_drop_sealed_shard(store,
                                               1,
                                               .drop_reason = r"repair");
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));

    auto bad_find_r = n00b_store_catalog_find_shard(store, 1);
    CHECK(n00b_result_is_ok(bad_find_r));
    CHECK(!n00b_option_is_set(n00b_result_get(bad_find_r)));

    good_find_r = n00b_store_catalog_find_shard(store, 2);
    CHECK(n00b_result_is_ok(good_find_r));
    CHECK(n00b_option_is_set(n00b_result_get(good_find_r)));
    CHECK(n00b_result_is_ok(n00b_store_catalog_entry_verify_object(
        store,
        n00b_option_get(n00b_result_get(good_find_r)))));
}

static void
test_quarantine_hides_and_persists(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);

    (void)seal_record(store, 1, 100);
    (void)seal_record(store, 2, 200);

    auto quarantine_r = n00b_store_quarantine_shard(store,
                                                    1,
                                                    .reason = r"test");
    CHECK(n00b_result_is_ok(quarantine_r));
    CHECK(n00b_result_get(quarantine_r));

    auto visible_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(visible_r));
    CHECK(n00b_result_get(visible_r) == 1);

    auto all_r = n00b_store_catalog_all_entry_count(store);
    CHECK(n00b_result_is_ok(all_r));
    CHECK(n00b_result_get(all_r) == 2);

    auto visible_find_r = n00b_store_catalog_find_shard(store, 1);
    CHECK(n00b_result_is_ok(visible_find_r));
    CHECK(!n00b_option_is_set(n00b_result_get(visible_find_r)));

    n00b_store_catalog_entry_t *quarantined = find_any_entry(store, 1);
    auto state_r = n00b_store_catalog_entry_get_state(quarantined);
    CHECK(n00b_result_is_ok(state_r));
    CHECK(n00b_result_get(state_r)
          == N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED);

    auto backlog_r = n00b_store_catalog_backlog(store, nullptr);
    CHECK(n00b_result_is_ok(backlog_r));
    n00b_store_backlog_t backlog = n00b_result_get(backlog_r);
    CHECK(backlog.shards_remaining == 1);
    CHECK(backlog.records_remaining == 1);

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.sealed_shards == 1);
    CHECK(stats.quarantined_shards == 1);
    CHECK(stats.quarantined_records == 1);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    n00b_store_t *reopened = open_store(vfs);
    all_r = n00b_store_catalog_all_entry_count(reopened);
    CHECK(n00b_result_is_ok(all_r));
    CHECK(n00b_result_get(all_r) == 2);
    quarantined = find_any_entry(reopened, 1);
    state_r = n00b_store_catalog_entry_get_state(quarantined);
    CHECK(n00b_result_is_ok(state_r));
    CHECK(n00b_result_get(state_r)
          == N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED);

    auto drop_r = n00b_store_drop_sealed_shard(reopened,
                                               1,
                                               .drop_reason = r"test_cleanup");
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));

    auto gone_r = n00b_store_catalog_find_any_shard(reopened, 1);
    CHECK(n00b_result_is_ok(gone_r));
    CHECK(!n00b_option_is_set(n00b_result_get(gone_r)));
}

static void
test_local_catalog_reopen_and_sync(void)
{
    n00b_vfs_t   *vfs   = new_local_vfs();
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *entry = seal_one(store, 777);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));

    auto sync_r = n00b_vfs_sync(vfs, n00b_result_get(path_r));
    if (n00b_result_is_err(sync_r)
        && n00b_result_get_err(sync_r) == N00B_VFS_ERR_NOT_SUPPORTED) {
        printf("  [SKIP] local durable sync unavailable\n");
    }
    else {
        CHECK(n00b_result_is_ok(sync_r));
    }

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    n00b_store_t *reopened = open_store(vfs);
    auto count_r = n00b_store_catalog_get_entry_count(reopened);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);
    CHECK(n00b_result_is_ok(
        n00b_store_catalog_entry_verify_object(reopened,
                                               find_entry(reopened, 1))));

    rm_tmpdir();
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_position_token_roundtrip();
    test_memory_catalog_reopen();
    test_metadata_only_reopen();
    test_missing_shard_object_error();
    test_drop_missing_shard_object_prunes_catalog();
    test_existing_shard_object_blocks_seal();
    test_catalog_failure_rolls_back_visibility();
    test_corrupt_shard_length_error();
    test_corrupt_shard_does_not_poison_catalog_ops();
    test_quarantine_hides_and_persists();
    test_local_catalog_reopen_and_sync();

    n00b_shutdown();
    return 0;
}

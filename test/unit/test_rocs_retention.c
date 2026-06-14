/* test/unit/test_rocs_retention.c - WP-005 Phase 7 retention contracts. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static n00b_vfs_t *
new_memory_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    return vfs;
}

static n00b_store_schema_t *
new_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs) _kargs
{
    n00b_store_lifecycle_topic_t  *lifecycle_topic  = nullptr;
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
}
{
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       new_schema(),
                                       .lifecycle_topic  = lifecycle_topic,
                                       .partition_policy = partition_policy,
                                       .seal_policy      = seal_policy);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_with_id(int64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    return record;
}

static n00b_json_node_t *
record_with_id_ts(int64_t id, int64_t ts)
{
    n00b_json_node_t *record = record_with_id(id);
    n00b_json_object_put_n00b(record, r"ts", n00b_json_int_new(ts));
    return record;
}

static n00b_store_catalog_entry_t *
ingest_and_flush(n00b_store_t *store, int64_t id)
{
    auto ingest_r = n00b_store_ingest(store, record_with_id(id));
    CHECK(n00b_result_is_ok(ingest_r));

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    auto find_r = n00b_store_catalog_find_shard(store, (uint64_t)id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static n00b_store_catalog_entry_t *
find_entry(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static void
test_hot_resident_limit_seals_automatically(void)
{
    auto seal_r = n00b_store_seal_policy_new(.max_hot_bytes = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_store_t *store =
        open_store(new_memory_vfs(), .seal_policy = n00b_result_get(seal_r));

    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record_with_id(1))));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record_with_id(2))));

    count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);
}

static void
test_retention_deletes_shard_and_updates_boundary(void)
{
    n00b_vfs_t     *vfs = new_memory_vfs();
    n00b_conduit_t *c   = n00b_result_get(n00b_conduit_new());

    auto topic_r = n00b_store_lifecycle_topic_get(
        c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 7101));
    CHECK(n00b_result_is_ok(topic_r));

    auto inbox_r = n00b_store_lifecycle_inbox_new(c);
    CHECK(n00b_result_is_ok(inbox_r));

    auto sub_r = n00b_store_lifecycle_subscribe(n00b_result_get(topic_r),
                                                n00b_result_get(inbox_r));
    CHECK(n00b_result_is_ok(sub_r));

    n00b_store_t *store = open_store(vfs,
                                     .lifecycle_topic = n00b_result_get(topic_r));

    n00b_store_catalog_entry_t *entry1 = ingest_and_flush(store, 1);
    ingest_and_flush(store, 2);
    ingest_and_flush(store, 3);

    auto path_r = n00b_store_catalog_entry_get_object_path(entry1);
    CHECK(n00b_result_is_ok(path_r));
    n00b_string_t *shard1_path = n00b_result_get(path_r);

    auto policy_r = n00b_store_shard_retention_policy_new(
        .max_sealed_shards = 2,
        .drop_reason       = r"unit-retention");
    CHECK(n00b_result_is_ok(policy_r));

    auto drop_r = n00b_store_apply_shard_retention(store,
                                                   n00b_result_get(policy_r));
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r) == 1);

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    auto missing_r = n00b_store_catalog_find_shard(store, 1);
    CHECK(n00b_result_is_ok(missing_r));
    CHECK(!n00b_option_is_set(n00b_result_get(missing_r)));

    auto stat_r = n00b_vfs_stat(vfs, shard1_path);
    CHECK(n00b_result_is_err(stat_r));
    CHECK(n00b_result_get_err(stat_r) == N00B_VFS_ERR_NOT_FOUND);

    auto oldest_r = n00b_store_oldest_available_pos(store);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    n00b_store_pos_t oldest = n00b_option_get(n00b_result_get(oldest_r));
    CHECK(oldest.shard_id == 2);
    CHECK(oldest.ordinal == 0);

    auto stale_r = n00b_store_resume_check(
        store,
        (n00b_store_pos_t){.generation = 0, .shard_id = 1, .ordinal = 0});
    CHECK(n00b_result_is_ok(stale_r));
    CHECK(!n00b_result_get(stale_r).available);
    CHECK(n00b_result_get(stale_r).oldest_available.shard_id == 2);

    auto live_r = n00b_store_resume_check(
        store,
        (n00b_store_pos_t){.generation = 0, .shard_id = 2, .ordinal = 0});
    CHECK(n00b_result_is_ok(live_r));
    CHECK(n00b_result_get(live_r).available);

    CHECK(n00b_conduit_inbox_msg_count(n00b_store_lifecycle_t,
                                       n00b_result_get(inbox_r)) == 1);
    n00b_store_lifecycle_msg_t *msg =
        n00b_store_lifecycle_inbox_pop(n00b_result_get(inbox_r));
    CHECK(msg != nullptr);
    CHECK(msg->payload.kind == N00B_STORE_LIFECYCLE_DROPPED);
    CHECK(msg->payload.shard_id == 1);
    CHECK(n00b_unicode_str_eq(msg->payload.drop_reason, r"unit-retention"));

    n00b_conduit_sub_cancel(n00b_result_get(sub_r));
    n00b_conduit_destroy(c);
}

static void
test_pinned_resident_shard_blocks_drop(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);

    ingest_and_flush(store, 1);
    n00b_store_catalog_entry_t *entry = find_entry(store, 1);

    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));

    auto drop_r = n00b_store_drop_sealed_shard(store, 1);
    CHECK(n00b_result_is_err(drop_r));
    CHECK(n00b_result_get_err(drop_r) == N00B_STORE_ERR_PINNED);

    auto release_r = n00b_store_resident_shard_release(n00b_result_get(resident_r));
    CHECK(n00b_result_is_ok(release_r));

    drop_r = n00b_store_drop_sealed_shard(store, 1);
    CHECK(n00b_result_is_ok(drop_r));
}

static void
test_retained_boundary_survives_reopen(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);

    ingest_and_flush(store, 1);
    ingest_and_flush(store, 2);

    auto drop_r = n00b_store_drop_sealed_shard(store, 1);
    CHECK(n00b_result_is_ok(drop_r));

    n00b_store_t *reopened = open_store(vfs);
    auto oldest_r = n00b_store_oldest_available_pos(reopened);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    CHECK(n00b_option_get(n00b_result_get(oldest_r)).shard_id == 2);

    auto stale_r = n00b_store_resume_check(
        reopened,
        (n00b_store_pos_t){.generation = 0, .shard_id = 1, .ordinal = 0});
    CHECK(n00b_result_is_ok(stale_r));
    CHECK(!n00b_result_get(stale_r).available);
    CHECK(n00b_result_get(stale_r).oldest_available.shard_id == 2);
}

static void
test_event_time_watermark_and_late_arrival_reopen(void)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10);
    CHECK(n00b_result_is_ok(policy_r));

    n00b_store_t *store =
        open_store(new_memory_vfs(), .partition_policy = n00b_result_get(policy_r));

    CHECK(n00b_result_is_ok(n00b_store_ingest(store,
                                              record_with_id_ts(1, 5))));

    auto early_r = n00b_store_apply_event_time_watermark(store, 9);
    CHECK(n00b_result_is_ok(early_r));
    CHECK(!n00b_result_get(early_r));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);

    auto watermark_r = n00b_store_apply_event_time_watermark(store, 10);
    CHECK(n00b_result_is_ok(watermark_r));
    CHECK(n00b_result_get(watermark_r));

    count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    auto p1_r = n00b_store_catalog_entry_get_partition_key(find_entry(store, 1));
    CHECK(n00b_result_is_ok(p1_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p1_r), r"time/0"));

    CHECK(n00b_result_is_ok(n00b_store_ingest(store,
                                              record_with_id_ts(2, 3))));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store,
                                              record_with_id_ts(3, 15))));
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 3);

    auto p2_r = n00b_store_catalog_entry_get_partition_key(find_entry(store, 2));
    auto p3_r = n00b_store_catalog_entry_get_partition_key(find_entry(store, 3));
    CHECK(n00b_result_is_ok(p2_r));
    CHECK(n00b_result_is_ok(p3_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p2_r), r"time/0"));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p3_r), r"time/1"));

    auto c1_r = n00b_store_catalog_entry_get_record_count(find_entry(store, 1));
    auto c2_r = n00b_store_catalog_entry_get_record_count(find_entry(store, 2));
    CHECK(n00b_result_is_ok(c1_r));
    CHECK(n00b_result_is_ok(c2_r));
    CHECK(n00b_result_get(c1_r) == 1);
    CHECK(n00b_result_get(c2_r) == 1);

    n00b_store_t *non_time = open_store(new_memory_vfs());
    auto bad_policy_r = n00b_store_apply_event_time_watermark(non_time, 10);
    CHECK(n00b_result_is_err(bad_policy_r));
    CHECK(n00b_result_get_err(bad_policy_r) == N00B_STORE_ERR_POLICY);
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_retention_deletes_shard_and_updates_boundary();
    test_pinned_resident_shard_blocks_drop();
    test_retained_boundary_survives_reopen();
    test_event_time_watermark_and_late_arrival_reopen();
    test_hot_resident_limit_seals_automatically();

    n00b_print(r"rocs_retention: ok");
    return 0;
}

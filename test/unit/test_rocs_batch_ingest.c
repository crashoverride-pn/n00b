/* test/unit/test_rocs_batch_ingest.c - WP-005 Phase 6 batch ingest. */

#include <stdint.h>
#include <string.h>
#include <math.h>

#include "n00b.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static uint64_t
live_thread_count(void)
{
    return n00b_atomic_load(&n00b_get_runtime()->live_threads);
}

static n00b_vfs_t *
new_memory_vfs() _kargs
{
    n00b_vfs_mount_t **mount_out = nullptr;
}
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

static n00b_store_schema_t *
schema_with_level(bool required, n00b_store_index_kind_t index_kind)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    auto field_r = n00b_store_schema_add_field(schema,
                                               r"level",
                                               .required = required,
                                               .index_kind = index_kind);
    CHECK(n00b_result_is_ok(field_r));
    return schema;
}

static n00b_store_schema_t *
schema_with_level_and_ts(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"level")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"ts")));
    return schema;
}

static n00b_store_t *
open_store(n00b_store_schema_t *schema) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_retain_policy_t    *retain_policy    = nullptr;
    n00b_vfs_t                    *vfs              = nullptr;
    bool                           recovery_journal = false;
}
{
    if (vfs == nullptr) {
        vfs = new_memory_vfs();
    }
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .partition_policy = partition_policy,
                                       .retain_policy    = retain_policy,
                                       .recovery_journal = recovery_journal);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static void
close_store_ok(n00b_store_t *store)
{
    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static n00b_json_node_t *
record_with_level(n00b_string_t *level)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(level));
    return record;
}

static n00b_json_node_t *
record_with_level_ts(n00b_string_t *level, int64_t ts)
{
    n00b_json_node_t *record = record_with_level(level);
    n00b_json_object_put_n00b(record, r"ts", n00b_json_int_new(ts));
    return record;
}

static n00b_json_node_t *
record_with_nonfinite_level(void)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"level", n00b_json_double_new(NAN));
    return record;
}

static n00b_buffer_t *
buffer_from_literal(const char *s)
{
    return n00b_buffer_from_bytes((char *)s, (int64_t)strlen(s));
}

typedef struct {
    bool enabled;
} fail_shard_write_t;

static bool
path_contains(n00b_string_t *path, const char *needle)
{
    if (path == nullptr || needle == nullptr) {
        return false;
    }

    size_t needle_len = strlen(needle);
    if (needle_len == 0 || path->u8_bytes < needle_len) {
        return false;
    }

    for (size_t i = 0; i + needle_len <= path->u8_bytes; i++) {
        if (memcmp(path->data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static void
deny_shard_write_open(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    fail_shard_write_t *state = cookie;
    if (state == nullptr || !state->enabled || ctx == nullptr
        || (ctx->flags & N00B_VFS_OPEN_WRITE) == 0
        || !path_contains(ctx->path, "/shards/")) {
        return;
    }

    ctx->denied   = true;
    ctx->deny_err = N00B_VFS_ERR_IO;
}

static n00b_store_record_list_t *
record_list_new(void)
{
    n00b_store_record_list_t *records = n00b_alloc(n00b_store_record_list_t);
    *records = n00b_list_new_private(n00b_json_node_t *,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return records;
}

static n00b_store_source_list_t *
source_list_new(void)
{
    n00b_store_source_list_t *sources = n00b_alloc(n00b_store_source_list_t);
    *sources = n00b_list_new_private(n00b_buffer_t *,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return sources;
}

static n00b_store_catalog_entry_t *
catalog_shard(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    n00b_option_t(n00b_store_catalog_entry_t *) opt = n00b_result_get(find_r);
    CHECK(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static n00b_store_map_shard_t *
resident_root(n00b_store_t                *store,
              n00b_store_catalog_entry_t  *entry,
              n00b_store_resident_shard_t **handle_out)
{
    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    CHECK(n00b_result_is_ok(map_r));

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    if (handle_out != nullptr) {
        *handle_out = resident;
    }
    return n00b_result_get(root_r);
}

static void
check_postings_len(n00b_store_postings_t *postings, uint64_t expected)
{
    auto len_r = n00b_store_postings_len(postings);
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == expected);
}

static void
check_mapped_level_hit(n00b_store_map_shard_t *root,
                       n00b_string_t          *level,
                       uint64_t                shard_id,
                       uint64_t                ordinal)
{
    auto index_r = n00b_store_index_new(r"level", N00B_STORE_INDEX_TERM);
    CHECK(n00b_result_is_ok(index_r));

    n00b_json_node_t *value = n00b_json_string_new_from_n00b(level);
    auto lookup_r = n00b_store_index_lookup_mapped(n00b_result_get(index_r),
                                                   root,
                                                   value);
    CHECK(n00b_result_is_ok(lookup_r));
    n00b_store_postings_t *postings = n00b_result_get(lookup_r);
    check_postings_len(postings, 1);

    auto posting_r = n00b_store_postings_get(postings, 0);
    CHECK(n00b_result_is_ok(posting_r));
    n00b_option_t(n00b_store_posting_t) opt = n00b_result_get(posting_r);
    CHECK(n00b_option_is_set(opt));
    n00b_store_posting_t posting = n00b_option_get(opt);
    CHECK(posting.pos.shard_id == shard_id);
    CHECK(posting.pos.ordinal == ordinal);
}

static void
check_raw_buffer_equal(n00b_store_map_buffer_t *actual,
                       n00b_buffer_t           *expected)
{
    CHECK(actual != nullptr);
    CHECK(expected != nullptr);

    auto len_r = n00b_store_map_buffer_len(actual);
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == (uint64_t)n00b_buffer_len(expected));

    for (uint64_t i = 0; i < n00b_result_get(len_r); i++) {
        auto got_r = n00b_store_map_buffer_byte(actual, i);
        auto exp_r = n00b_buffer_get_index(expected, (int64_t)i);
        CHECK(n00b_result_is_ok(got_r));
        CHECK(n00b_result_is_ok(exp_r));
        CHECK(n00b_result_get(got_r) == n00b_result_get(exp_r));
    }
}

static void
test_empty_batch_returns_zero(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NONE));
    n00b_store_record_list_t *records = record_list_new();

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 2,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 0);

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
    close_store_ok(store);
}

static void
test_parsed_batch_preserves_order_and_indexes(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(true, N00B_STORE_INDEX_TERM));
    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_level(r"alpha"));
    n00b_list_push(*records, record_with_level(r"beta"));
    n00b_list_push(*records, record_with_level(r"gamma"));

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 2,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 3);
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(store, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 3);

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t      *root = resident_root(store, entry, &resident);
    auto list_r = n00b_store_map_shard_records(root);
    CHECK(n00b_result_is_ok(list_r));
    auto len_r = n00b_store_map_list_len(n00b_result_get(list_r));
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == 3);

    check_mapped_level_hit(root, r"alpha", 1, 0);
    check_mapped_level_hit(root, r"beta", 1, 1);
    check_mapped_level_hit(root, r"gamma", 1, 2);

    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
    close_store_ok(store);
}

static void
test_buf_batch_retains_raw_and_indexes(void)
{
    auto retain_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_INLINE);
    CHECK(n00b_result_is_ok(retain_r));

    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .retain_policy = n00b_result_get(retain_r));
    n00b_store_source_list_t *sources = source_list_new();
    n00b_buffer_t *first =
        buffer_from_literal("{\"level\":\"raw-a\",\"message\":\"a\"}");
    n00b_buffer_t *second =
        buffer_from_literal("{\"level\":\"raw-b\",\"message\":\"b\"}");
    n00b_list_push(*sources, first);
    n00b_list_push(*sources, second);

    auto batch_r = n00b_store_ingest_buf_batch(store,
                                               sources,
                                               .worker_count = 2,
                                               .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 2);
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t *root =
        resident_root(store, catalog_shard(store, 1), &resident);

    auto raw0_r = n00b_store_map_shard_raw_buffer(root, 0);
    auto raw1_r = n00b_store_map_shard_raw_buffer(root, 1);
    CHECK(n00b_result_is_ok(raw0_r));
    CHECK(n00b_result_is_ok(raw1_r));

    n00b_option_t(n00b_store_map_buffer_t *) raw0 = n00b_result_get(raw0_r);
    n00b_option_t(n00b_store_map_buffer_t *) raw1 = n00b_result_get(raw1_r);
    CHECK(n00b_option_is_set(raw0));
    CHECK(n00b_option_is_set(raw1));
    check_raw_buffer_equal(n00b_option_get(raw0), first);
    check_raw_buffer_equal(n00b_option_get(raw1), second);

    check_mapped_level_hit(root, r"raw-a", 1, 0);
    check_mapped_level_hit(root, r"raw-b", 1, 1);

    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
    close_store_ok(store);
}

static void
test_worker_parse_failure_rolls_back(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(true, N00B_STORE_INDEX_TERM));
    n00b_store_source_list_t *sources = source_list_new();
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"ok\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"later\"}"));

    auto batch_r = n00b_store_ingest_buf_batch(store,
                                               sources,
                                               .worker_count = 2,
                                               .queue_capacity = 1);
    CHECK(n00b_result_is_err(batch_r));
    CHECK(n00b_result_get_err(batch_r) == N00B_STORE_ERR_PARSE);
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
    close_store_ok(store);
}

static void
test_batch_index_error_rolls_back(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM));
    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_level(r"ok"));
    n00b_list_push(*records, record_with_nonfinite_level());
    n00b_list_push(*records, record_with_level(r"later"));

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 2,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_err(batch_r));
    CHECK(n00b_result_get_err(batch_r) == N00B_STORE_ERR_INDEX);
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
    close_store_ok(store);
}

static void
test_batch_partition_grouping(void)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy_r));

    n00b_store_t *store =
        open_store(schema_with_level_and_ts(),
                   .partition_policy = n00b_result_get(policy_r));
    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_level_ts(r"a", 5));
    n00b_list_push(*records, record_with_level_ts(r"b", 15));
    n00b_list_push(*records, record_with_level_ts(r"c", 16));

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 3,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 3);
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    n00b_store_catalog_entry_t *first = catalog_shard(store, 1);
    n00b_store_catalog_entry_t *second = catalog_shard(store, 2);
    auto p0_r = n00b_store_catalog_entry_get_partition_key(first);
    auto p1_r = n00b_store_catalog_entry_get_partition_key(second);
    CHECK(n00b_result_is_ok(p0_r));
    CHECK(n00b_result_is_ok(p1_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p0_r), r"time/0"));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p1_r), r"time/1"));

    auto c0_r = n00b_store_catalog_entry_get_record_count(first);
    auto c1_r = n00b_store_catalog_entry_get_record_count(second);
    CHECK(n00b_result_is_ok(c0_r));
    CHECK(n00b_result_is_ok(c1_r));
    CHECK(n00b_result_get(c0_r) == 1);
    CHECK(n00b_result_get(c1_r) == 2);
    close_store_ok(store);
}

static void
test_batch_pool_reuses_parked_workers(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NONE));
    uint64_t before = live_thread_count();

    n00b_store_record_list_t *first = record_list_new();
    n00b_list_push(*first, record_with_level(r"first"));
    auto first_r = n00b_store_ingest_batch(store,
                                           first,
                                           .worker_count = 4,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_ok(first_r));
    CHECK(n00b_result_get(first_r) == 1);

    uint64_t after_first = live_thread_count();
    CHECK(after_first >= before + 4);

    n00b_store_record_list_t *second = record_list_new();
    n00b_list_push(*second, record_with_level(r"second"));
    auto second_r = n00b_store_ingest_batch(store,
                                            second,
                                            .worker_count = 4,
                                            .queue_capacity = 1);
    CHECK(n00b_result_is_ok(second_r));
    CHECK(n00b_result_get(second_r) == 1);
    CHECK(live_thread_count() == after_first);

    close_store_ok(store);
    CHECK(live_thread_count() <= before);
}

// A durable seal failure mid-batch irreversibly drops the rotated shard (the
// rotation restructure made the seal non-blocking and one-way).  WITHOUT a
// recovery journal those records are truly lost, so ingest_batch must surface a
// durable error rather than reporting them as a committed prefix.
static void
test_batch_durable_failure_without_journal_errors(void)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);

    n00b_store_t *store =
        open_store(schema_with_level_and_ts(),
                   .vfs = vfs,
                   .partition_policy = n00b_result_get(policy_r));

    fail_shard_write_t fail_shards = {
        .enabled = false,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              deny_shard_write_open,
                                              &fail_shards,
                                              0)));

    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_level_ts(r"a", 5));
    n00b_list_push(*records, record_with_level_ts(r"b", 15));

    // Record a commits to hot shard 1; record b's route change seals shard 1,
    // whose write is denied -> shard 1's records are dropped (no journal).
    fail_shards.enabled = true;
    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 2,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_err(batch_r));
    CHECK(n00b_result_get_err(batch_r) == N00B_STORE_ERR_VFS);

    fail_shards.enabled = false;
    close_store_ok(store);
}

// With the recovery journal enabled, the same durable seal failure no longer
// loses data: record a's source bytes are journaled before commit, the dropped
// shard's journal is retained (the seal write is denied, the journal write is
// not), and reopening the store replays the journal into a sealed shard.  The
// batch still reports the committed prefix because the journal makes it durable.
static void
test_batch_durable_failure_recovered_via_journal(void)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);

    n00b_store_t *store =
        open_store(schema_with_level_and_ts(),
                   .vfs = vfs,
                   .partition_policy = n00b_result_get(policy_r),
                   .recovery_journal = true);

    fail_shard_write_t fail_shards = {
        .enabled = false,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              deny_shard_write_open,
                                              &fail_shards,
                                              0)));

    // Source-based ingest so the records carry the raw bytes the journal needs.
    n00b_store_source_list_t *sources = source_list_new();
    n00b_list_push(*sources,
                   buffer_from_literal("{\"level\":\"a\",\"ts\":5}"));
    n00b_list_push(*sources,
                   buffer_from_literal("{\"level\":\"b\",\"ts\":15}"));

    fail_shards.enabled = true;
    auto batch_r = n00b_store_ingest_buf_batch(store,
                                               sources,
                                               .worker_count = 2,
                                               .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 1);
    fail_shards.enabled = false;

    // Simulate a crash: abandon `store` without flush/seal/close, then reopen on
    // the same VFS.  Recovery replays journals/1.jrnl into a sealed shard.
    auto policy2_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy2_r));
    n00b_store_t *recovered =
        open_store(schema_with_level_and_ts(),
                   .vfs = vfs,
                   .partition_policy = n00b_result_get(policy2_r),
                   .recovery_journal = true);

    auto count_r = n00b_store_catalog_get_entry_count(recovered);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(recovered, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 1);
    close_store_ok(recovered);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_empty_batch_returns_zero();
    test_parsed_batch_preserves_order_and_indexes();
    test_buf_batch_retains_raw_and_indexes();
    test_worker_parse_failure_rolls_back();
    test_batch_index_error_rolls_back();
    test_batch_partition_grouping();
    test_batch_pool_reuses_parked_workers();
    test_batch_durable_failure_without_journal_errors();
    test_batch_durable_failure_recovered_via_journal();

    return 0;
}

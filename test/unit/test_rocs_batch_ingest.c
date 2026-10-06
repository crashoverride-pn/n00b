/* test/unit/test_rocs_batch_ingest.c - WP-005 Phase 6 batch ingest. */

#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "n00b.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>
#include "internal/rocs/store.h"
#include "test_check.h"

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
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
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
                                       .seal_policy      = seal_policy,
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

typedef struct {
    bool     enabled;
    uint64_t allowed;
    uint64_t seen;
} fail_journal_write_t;

// Lets the first `allowed` journal writes through and fails the rest.
static void
deny_journal_write(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    fail_journal_write_t *state = cookie;
    if (state == nullptr || !state->enabled || ctx == nullptr
        || !path_contains(ctx->path, "/journals/")) {
        return;
    }
    if (state->seen++ < state->allowed) {
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
check_mapped_hit(n00b_store_map_shard_t *root,
                 n00b_string_t          *field,
                 n00b_string_t          *term,
                 uint64_t                shard_id,
                 uint64_t                ordinal)
{
    auto index_r = n00b_store_index_new(field, N00B_STORE_INDEX_TERM);
    CHECK(n00b_result_is_ok(index_r));

    n00b_json_node_t *value = n00b_json_string_new_from_n00b(term);
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
check_mapped_level_hit(n00b_store_map_shard_t *root,
                       n00b_string_t          *level,
                       uint64_t                shard_id,
                       uint64_t                ordinal)
{
    check_mapped_hit(root, r"level", level, shard_id, ordinal);
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

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_live_index == 3);
    CHECK(memory.hot_ready_out_of_order_publications >= 2);
    CHECK(memory.hot_worker_range_commits == 3);
    CHECK(memory.hot_worker_range_tombstones == 0);
    CHECK(memory.hot_writer_reservations == 3);
    CHECK(memory.hot_writer_completions == 3);
    CHECK(memory.hot_byte_estimate
          == memory.hot_record_text_bytes
                 + (3 * N00B_STORE_SHARD_RECORD_OVERHEAD));

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

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_live_index == 2);
    CHECK(memory.hot_worker_range_commits == 2);
    CHECK(memory.hot_worker_range_tombstones == 0);
    CHECK(memory.hot_raw_bytes
          == (uint64_t)n00b_buffer_len(first)
                 + (uint64_t)n00b_buffer_len(second));

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
test_worker_range_handles_byte_seal_policy(void)
{
    auto seal_r = n00b_store_seal_policy_new(.max_bytes = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_store_t *store =
        open_store(schema_with_level(true, N00B_STORE_INDEX_TERM),
                   .seal_policy = n00b_result_get(seal_r));

    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_level(r"byte-a"));
    n00b_list_push(*records, record_with_level(r"byte-b"));
    n00b_list_push(*records, record_with_level(r"byte-c"));

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 2,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 3);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_worker_range_commits == 3);

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(store, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 3);

    close_store_ok(store);
}

static void
test_worker_range_handles_open_time_seal_policy(void)
{
    auto seal_r = n00b_store_seal_policy_new(.max_open_ns = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_store_t *store =
        open_store(schema_with_level(true, N00B_STORE_INDEX_TERM),
                   .seal_policy = n00b_result_get(seal_r));

    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_level(r"open-a"));
    n00b_list_push(*records, record_with_level(r"open-b"));

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count = 2,
                                           .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 2);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_worker_range_commits == 2);

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(store, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 2);

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

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_worker_range_commits == 3);
    CHECK(memory.hot_worker_range_tombstones == 0);
    CHECK(memory.hot_live_index == 2);

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
test_batch_ingest_worker_pool_drains(void)
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
    CHECK(after_first == before);

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
    CHECK(live_thread_count() == before);
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

    // Record a commits to hot shard 1; record b's route change attempts to
    // seal shard 1, whose write is denied. The batch reports a durability
    // error and the failed shard remains retained for retry.
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

// With the recovery journal enabled, the same durable seal failure has an
// additional recovery path: record a's source bytes are journaled before
// commit, the failed shard's journal is retained (the seal write is denied, the
// journal write is not), and reopening the store replays the journal into a
// sealed shard. The batch still reports the durability error because the failed
// shard is retained for retry/recovery instead of being presented as a clean
// committed prefix.
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
    CHECK(n00b_result_is_err(batch_r));
    CHECK(n00b_result_get_err(batch_r) == N00B_STORE_ERR_VFS);
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

static void
test_journaled_source_batch_uses_worker_range(void)
{
    n00b_vfs_t *vfs = new_memory_vfs();
    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .vfs = vfs,
                   .recovery_journal = true);

    n00b_store_source_list_t *sources = source_list_new();
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"jr-a\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"jr-b\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"jr-c\"}"));

    auto batch_r = n00b_store_ingest_buf_batch(store,
                                               sources,
                                               .worker_count = 2,
                                               .queue_capacity = 1);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 3);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_live_index == 3);
    CHECK(memory.hot_worker_range_commits == 3);
    CHECK(memory.hot_worker_range_tombstones == 0);

    // Simulate a crash: abandon the open store without close/flush. Recovery
    // must replay the worker-range journal into a sealed shard.
    n00b_store_t *recovered =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .vfs = vfs,
                   .recovery_journal = true);

    auto count_r = n00b_store_catalog_get_entry_count(recovered);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(recovered, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 3);

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t *root = resident_root(recovered, entry, &resident);
    check_mapped_level_hit(root, r"jr-a", 1, 0);
    check_mapped_level_hit(root, r"jr-b", 1, 1);
    check_mapped_level_hit(root, r"jr-c", 1, 2);

    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
    close_store_ok(recovered);
}

// A journal append that fails partway through a range commit stops it there.
// The records already journaled are committed and published, and the rest of
// the reservation is released, so the hot shard keeps publishing and the
// journal holds exactly what was committed.
static void
test_journal_failure_mid_range_commits_the_journaled_prefix(void)
{
    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);
    n00b_store_t     *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .vfs              = vfs,
                   .recovery_journal = true);

    fail_journal_write_t fail_journal = {
        .enabled = false,
        .allowed = 1,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_WRITE,
                                              deny_journal_write,
                                              &fail_journal,
                                              0)));

    n00b_store_source_list_t *sources = source_list_new();
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"jf-a\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"jf-b\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"jf-c\"}"));

    fail_journal.enabled = true;
    auto batch_r = n00b_store_ingest_buf_batch(store,
                                               sources,
                                               .worker_count   = 2,
                                               .queue_capacity = 1);
    fail_journal.enabled = false;

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_live_index == memory.hot_record_count);
    CHECK(memory.hot_active_writers == 0);

    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 1);
    CHECK(memory.hot_record_count == 1);
    CHECK(memory.hot_worker_range_commits == 1);

    CHECK(n00b_result_is_ok(
        n00b_store_ingest_buf(store,
                              buffer_from_literal("{\"level\":\"jf-d\"}"))));
    memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    CHECK(n00b_result_get(memory_r).hot_live_index == 2);

    // Abandoned without a close, so the reopen replays the journal.
    n00b_store_t *recovered =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .vfs              = vfs,
                   .recovery_journal = true);
    n00b_store_catalog_entry_t *entry = catalog_shard(recovered, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 2);

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t *root = resident_root(recovered, entry, &resident);
    check_mapped_level_hit(root, r"jf-a", 1, 0);
    check_mapped_level_hit(root, r"jf-d", 1, 1);
    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
    close_store_ok(recovered);
}

#ifdef N00B_DEBUG
static bool
fail_kind_boom(n00b_store_fault_t fault, n00b_json_node_t *record, void *ctx)
{
    (void)ctx;
    if (fault != N00B_STORE_FAULT_RANGE_PREPARE) {
        return false;
    }
    n00b_json_node_t *kind = n00b_json_object_get(record, r"kind");
    return n00b_json_is_string(kind)
        && strcmp(n00b_json_as_cstr(kind), "boom") == 0;
}

static n00b_json_node_t *
record_with_kind(n00b_string_t *kind)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record,
                              r"kind",
                              n00b_json_string_new_from_n00b(kind));
    return record;
}

// A record whose worker-side prepare fails is committed as a
// "rocs.ingest_error" tombstone, and is indexed like any other record.
static void
test_worker_range_tombstone_is_indexed(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"kind",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    n00b_store_t *store = open_store(schema);

    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_kind(r"auth"));
    n00b_list_push(*records, record_with_kind(r"boom"));
    n00b_list_push(*records, record_with_kind(r"login"));

    n00b_store_fault_hook_set(fail_kind_boom, nullptr);
    auto batch_r = n00b_store_ingest_batch(store, records, .worker_count = 2);
    n00b_store_fault_hook_set(nullptr, nullptr);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 3);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_worker_range_commits == 2);
    CHECK(memory.hot_worker_range_tombstones == 1);

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t      *root     =
        resident_root(store, catalog_shard(store, 1), &resident);
    check_mapped_hit(root, r"kind", r"auth", 1, 0);
    check_mapped_hit(root, r"kind", r"rocs.ingest_error", 1, 1);
    check_mapped_hit(root, r"kind", r"login", 1, 2);

    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
    close_store_ok(store);
}

static n00b_result_t(bool)
reject_ingest_error_term(n00b_store_index_emit_t *emit,
                         n00b_string_t           *field_path,
                         n00b_json_node_t        *field_value,
                         void                    *ctx,
                         n00b_allocator_t        *scratch)
{
    (void)emit;
    (void)field_path;
    (void)ctx;
    (void)scratch;
    if (n00b_json_is_string(field_value)
        && strcmp(n00b_json_as_cstr(field_value), "rocs.ingest_error") == 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }
    return n00b_result_ok(bool, true);
}

// A tombstone whose index terms cannot be built is stored unindexed. Its slot
// is already reserved, so failing the batch there would leave the slot
// unfilled and every later record in the hot shard unpublished.
static void
test_worker_range_tombstone_survives_an_index_failure(void)
{
    n00b_store_index_options_t options = {
        .exact_full_string = true,
        .split_terms       = true,
        .term_hook         = reject_ingest_error_term,
    };
    auto schema_r = n00b_store_schema_new(.search_text   = true,
                                          .index_options = &options);
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"kind",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    n00b_store_t *store = open_store(schema);

    n00b_store_record_list_t *records = record_list_new();
    n00b_list_push(*records, record_with_kind(r"auth"));
    n00b_list_push(*records, record_with_kind(r"boom"));
    n00b_list_push(*records, record_with_kind(r"login"));

    n00b_store_fault_hook_set(fail_kind_boom, nullptr);
    auto batch_r = n00b_store_ingest_batch(store, records, .worker_count = 2);
    n00b_store_fault_hook_set(nullptr, nullptr);
    CHECK(n00b_result_is_ok(batch_r));
    CHECK(n00b_result_get(batch_r) == 3);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_worker_range_tombstones == 1);
    CHECK(memory.hot_live_index == 3);

    // A record after the batch is published too.
    auto after_r = n00b_store_ingest(store, record_with_kind(r"zeta"));
    CHECK(n00b_result_is_ok(after_r));
    memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    CHECK(n00b_result_get(memory_r).hot_live_index == 4);

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));
    auto records_r = n00b_store_catalog_entry_get_record_count(
        catalog_shard(store, 1));
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 4);
    close_store_ok(store);
}
#endif

#ifdef N00B_DEBUG
typedef struct {
    n00b_vfs_t                   *vfs;
    n00b_store_t                 *store;
    n00b_result_t(uint64_t)       batch_r;
} held_tail_t;

static bool
fail_range_cancel(n00b_store_fault_t fault, n00b_json_node_t *record, void *ctx)
{
    (void)record;
    (void)ctx;
    return fault == N00B_STORE_FAULT_RANGE_CANCEL;
}

// Journal writes after the first `journaled` fail, and the unready tail
// cannot be canceled, so every slot after the journaled ones stays reserved.
static held_tail_t
batch_with_a_held_tail(uint64_t journaled)
{
    held_tail_t       out   = {};
    n00b_vfs_mount_t *mount = nullptr;
    out.vfs   = new_memory_vfs(.mount_out = &mount);
    out.store = open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                           .vfs              = out.vfs,
                           .recovery_journal = true);

    static fail_journal_write_t fail_journal;
    fail_journal = (fail_journal_write_t){.enabled = false,
                                          .allowed = journaled};
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_WRITE,
                                              deny_journal_write,
                                              &fail_journal,
                                              0)));

    n00b_store_source_list_t *sources = source_list_new();
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"ht-a\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"ht-b\"}"));
    n00b_list_push(*sources, buffer_from_literal("{\"level\":\"ht-c\"}"));

    fail_journal.enabled = true;
    n00b_store_fault_hook_set(fail_range_cancel, nullptr);
    out.batch_r = n00b_store_ingest_buf_batch(out.store,
                                              sources,
                                              .worker_count   = 2,
                                              .queue_capacity = 1);
    n00b_store_fault_hook_set(nullptr, nullptr);
    fail_journal.enabled = false;
    return out;
}

// The journaled prefix is committed even when the tail stays reserved, so the
// live shard holds what the journal holds, and the batch reports that prefix.
// The store is abandoned rather than closed: its tail is still reserved.
static void
test_held_tail_still_commits_the_journaled_prefix(void)
{
    held_tail_t held = batch_with_a_held_tail(1);
    CHECK(n00b_result_is_ok(held.batch_r));
    CHECK(n00b_result_get(held.batch_r) == 1);

    auto memory_r = n00b_store_memory_stats(held.store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_live_index == 1);
    CHECK(memory.hot_record_count == 3);
    CHECK(memory.hot_active_writers == 0);

    n00b_store_t *recovered =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .vfs              = held.vfs,
                   .recovery_journal = true);
    n00b_store_catalog_entry_t *entry = catalog_shard(recovered, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 1);
    close_store_ok(recovered);
}

// With nothing committed, the batch reports the journal error that stopped
// the range, not the failed cancel that followed it.
static void
test_held_tail_reports_the_failure_that_stopped_it(void)
{
    held_tail_t held = batch_with_a_held_tail(0);
    CHECK(n00b_result_is_err(held.batch_r));
    CHECK(n00b_result_get_err(held.batch_r) == N00B_STORE_ERR_VFS);
}
#endif

#ifdef N00B_DEBUG
#define FAULT_RECORDS 5

typedef struct {
    const char        *name;
    n00b_store_fault_t fault;
    // Also fail the target's prepare, so it takes the tombstone path.
    bool               via_tombstone;
    // Also fail the target's journal append, so the range stops there.
    bool               via_journal;
} fault_case_t;

static const fault_case_t fault_cases[] = {
    {"job array", N00B_STORE_FAULT_RANGE_JOB_ARRAY, false, false},
    {"job", N00B_STORE_FAULT_RANGE_JOB, false, false},
    {"raw span", N00B_STORE_FAULT_RANGE_RAW_SPAN, false, false},
    {"workers", N00B_STORE_FAULT_RANGE_WORKERS, false, false},
    {"prepare", N00B_STORE_FAULT_RANGE_PREPARE, false, false},
    {"tombstone", N00B_STORE_FAULT_RANGE_TOMBSTONE, true, false},
    {"tombstone slot", N00B_STORE_FAULT_RANGE_TOMBSTONE_SLOT, true, false},
    {"record text", N00B_STORE_FAULT_RANGE_RECORD_TEXT, false, false},
    {"journal buffer", N00B_STORE_FAULT_RANGE_JOURNAL_BUFFER, true, false},
    {"journal", N00B_STORE_FAULT_JOURNAL, false, false},
    {"fill", N00B_STORE_FAULT_FILL, false, false},
    {"cancel", N00B_STORE_FAULT_RANGE_CANCEL, false, true},
    {"publish", N00B_STORE_FAULT_PUBLISH, false, false},
};

static const uint64_t fault_targets[] = {0, FAULT_RECORDS / 2, FAULT_RECORDS - 1};

typedef struct {
    const fault_case_t *c;
    char                target[16];
} fault_plan_t;

static bool
record_level_is(n00b_json_node_t *record, const char *level)
{
    if (record == nullptr) {
        return false;
    }
    n00b_json_node_t *value = n00b_json_object_get(record, r"level");
    return n00b_json_is_string(value)
        && strcmp(n00b_json_as_cstr(value), level) == 0;
}

static bool
planned_fault(n00b_store_fault_t fault, n00b_json_node_t *record, void *ctx)
{
    fault_plan_t *plan = ctx;
    if (fault == plan->c->fault) {
        return record == nullptr || record_level_is(record, plan->target);
    }
    if (fault == N00B_STORE_FAULT_RANGE_PREPARE && plan->c->via_tombstone) {
        return record_level_is(record, plan->target);
    }
    if (fault == N00B_STORE_FAULT_JOURNAL && plan->c->via_journal) {
        return record_level_is(record, plan->target);
    }
    return false;
}

// Whether a fault leaves the shard unable to publish past it. Both need a
// broken invariant: the tail cancel and the publish each act on slots this
// commit reserved under the commit lock.
static bool
fault_holds_the_shard(const fault_case_t *c)
{
    return c->fault == N00B_STORE_FAULT_RANGE_CANCEL
        || c->fault == N00B_STORE_FAULT_PUBLISH;
}

// Records the range commits when the fault hits record k.
static uint64_t
range_committed(const fault_case_t *c, uint64_t k)
{
    switch (c->fault) {
    case N00B_STORE_FAULT_RANGE_JOB_ARRAY:
    case N00B_STORE_FAULT_RANGE_JOB:
    case N00B_STORE_FAULT_RANGE_RAW_SPAN:
    case N00B_STORE_FAULT_RANGE_WORKERS:
        return 0;
    case N00B_STORE_FAULT_RANGE_PREPARE:
    case N00B_STORE_FAULT_PUBLISH:
        return FAULT_RECORDS;
    default:
        return k;
    }
}

static n00b_store_schema_t *
fault_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"level",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"kind",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

// Journaled and retaining raw source, so every fault step is reachable.
static n00b_store_t *
open_fault_store(void)
{
    auto retain_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_INLINE);
    CHECK(n00b_result_is_ok(retain_r));
    return open_store(fault_schema(),
                      .retain_policy    = n00b_result_get(retain_r),
                      .recovery_journal = true);
}

static n00b_buffer_t *
level_source(const char *level)
{
    char buf[64];
    int  len = snprintf(buf, sizeof(buf), "{\"level\":\"%s\"}", level);
    return n00b_buffer_from_bytes(buf, len);
}

static n00b_buffer_t *
fault_source(uint64_t i)
{
    char level[16];
    snprintf(level, sizeof(level), "f%llu", (unsigned long long)i);
    return level_source(level);
}

static n00b_store_source_list_t *
fault_sources(void)
{
    n00b_store_source_list_t *sources = source_list_new();
    for (uint64_t i = 0; i < FAULT_RECORDS; i++) {
        n00b_list_push(*sources, fault_source(i));
    }
    return sources;
}

static n00b_result_t(uint64_t)
faulted_batch(n00b_store_t             *store,
              n00b_store_source_list_t *sources,
              const fault_case_t       *c,
              uint64_t                  k,
              int32_t                   workers)
{
    fault_plan_t plan = {.c = c};
    snprintf(plan.target, sizeof(plan.target), "f%llu", (unsigned long long)k);
    n00b_store_fault_hook_set(planned_fault, &plan);
    auto r = n00b_store_ingest_buf_batch(store,
                                         sources,
                                         .worker_count   = workers,
                                         .queue_capacity = 1);
    n00b_store_fault_hook_set(nullptr, nullptr);
    return r;
}

static uint64_t
result_committed(n00b_result_t(uint64_t) r)
{
    return n00b_result_is_ok(r) ? n00b_result_get(r) : 0;
}

static n00b_store_memory_stats_t
memory_of(n00b_store_t *store)
{
    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    return n00b_result_get(memory_r);
}

// A failure at any step of the range commit, on any record, leaves a batch
// result that names exactly the records committed, and a shard that goes on
// publishing: a record ingested afterward is visible and indexed.
static void
test_range_faults_leave_the_shard_publishing(void)
{
    size_t ncases = sizeof(fault_cases) / sizeof(fault_cases[0]);
    size_t ntargets = sizeof(fault_targets) / sizeof(fault_targets[0]);
    for (size_t ci = 0; ci < ncases; ci++) {
        const fault_case_t *c = &fault_cases[ci];
        for (size_t ti = 0; ti < ntargets; ti++) {
            uint64_t k = fault_targets[ti];
            fprintf(stderr, "  range fault: %s at %llu\n", c->name,
                    (unsigned long long)k);

            n00b_store_t *store = open_fault_store();
            auto batch_r = faulted_batch(store, fault_sources(), c, k, 2);
            uint64_t n = range_committed(c, k);
            CHECK(n00b_result_is_ok(batch_r) == (n != 0));
            CHECK(result_committed(batch_r) == n);

            n00b_store_memory_stats_t memory = memory_of(store);
            CHECK(memory.hot_active_writers == 0);
            if (fault_holds_the_shard(c)) {
                // Every reserved slot stays in the shard, and nothing past
                // the failed one publishes, then or later. The store is
                // abandoned, since a seal would meet the held slots.
                CHECK(memory.hot_record_count == FAULT_RECORDS);
                CHECK(memory.hot_live_index <= k);
                uint64_t live = memory.hot_live_index;
                CHECK(n00b_result_is_ok(
                    n00b_store_ingest_buf(store, level_source("after"))));
                CHECK(memory_of(store).hot_live_index == live);
                continue;
            }
            CHECK(memory.hot_live_index == memory.hot_record_count);
            CHECK(memory.hot_record_count == n);

            CHECK(n00b_result_is_ok(
                n00b_store_ingest_buf(store, level_source("after"))));
            CHECK(memory_of(store).hot_live_index == n + 1);
            CHECK(n00b_result_is_ok(n00b_store_flush(store)));

            n00b_store_catalog_entry_t *entry = catalog_shard(store, 1);
            auto records_r = n00b_store_catalog_entry_get_record_count(entry);
            CHECK(n00b_result_is_ok(records_r));
            CHECK(n00b_result_get(records_r) == n + 1);

            n00b_store_resident_shard_t *resident = nullptr;
            n00b_store_map_shard_t *root = resident_root(store, entry, &resident);
            for (uint64_t i = 0; i < n; i++) {
                if (c->fault == N00B_STORE_FAULT_RANGE_PREPARE && i == k) {
                    check_mapped_hit(root, r"kind", r"rocs.ingest_error", 1, i);
                    continue;
                }
                char level[16];
                snprintf(level, sizeof(level), "f%llu", (unsigned long long)i);
                check_mapped_hit(root,
                                 r"level",
                                 n00b_string_from_cstr(level),
                                 1,
                                 i);
            }
            check_mapped_hit(root, r"level", r"after", 1, n);
            CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
            close_store_ok(store);
        }
    }
}

static uint64_t
mapped_postings(n00b_store_map_shard_t *root,
                n00b_string_t          *field,
                n00b_string_t          *term,
                uint64_t               *ordinals,
                uint64_t                cap)
{
    auto index_r = n00b_store_index_new(field, N00B_STORE_INDEX_TERM);
    CHECK(n00b_result_is_ok(index_r));
    auto lookup_r = n00b_store_index_lookup_mapped(
        n00b_result_get(index_r),
        root,
        n00b_json_string_new_from_n00b(term));
    if (n00b_result_is_err(lookup_r)) {
        return 0;
    }
    n00b_store_postings_t *postings = n00b_result_get(lookup_r);
    auto len_r = n00b_store_postings_len(postings);
    CHECK(n00b_result_is_ok(len_r));
    uint64_t len = n00b_result_get(len_r);
    CHECK(len <= cap);
    for (uint64_t i = 0; i < len; i++) {
        auto posting_r = n00b_store_postings_get(postings, i);
        CHECK(n00b_result_is_ok(posting_r));
        auto opt = n00b_result_get(posting_r);
        CHECK(n00b_option_is_set(opt));
        ordinals[i] = n00b_option_get(opt).pos.ordinal;
    }
    return len;
}

static void
check_same_postings(n00b_store_map_shard_t *a,
                    n00b_store_map_shard_t *b,
                    n00b_string_t          *field,
                    n00b_string_t          *term)
{
    uint64_t in_a[FAULT_RECORDS + 1];
    uint64_t in_b[FAULT_RECORDS + 1];
    uint64_t len = mapped_postings(a, field, term, in_a, FAULT_RECORDS + 1);
    CHECK(mapped_postings(b, field, term, in_b, FAULT_RECORDS + 1) == len);
    for (uint64_t i = 0; i < len; i++) {
        CHECK(in_a[i] == in_b[i]);
    }
}

// The single shard each store seals holds the same records, byte for byte,
// under the same postings.
static void
check_same_shard(n00b_store_t *a, n00b_store_t *b)
{
    n00b_store_resident_shard_t *ra = nullptr;
    n00b_store_resident_shard_t *rb = nullptr;
    n00b_store_map_shard_t *root_a = resident_root(a, catalog_shard(a, 1), &ra);
    n00b_store_map_shard_t *root_b = resident_root(b, catalog_shard(b, 1), &rb);

    auto len_a = n00b_store_map_shard_records_len(root_a);
    auto len_b = n00b_store_map_shard_records_len(root_b);
    CHECK(n00b_result_is_ok(len_a) && n00b_result_is_ok(len_b));
    CHECK(n00b_result_get(len_a) == n00b_result_get(len_b));
    for (uint64_t i = 0; i < n00b_result_get(len_a); i++) {
        auto span_a = n00b_store_map_shard_record_span(root_a, i);
        auto span_b = n00b_store_map_shard_record_span(root_b, i);
        CHECK(n00b_result_is_ok(span_a) && n00b_result_is_ok(span_b));
        n00b_store_byte_span_t sa = n00b_result_get(span_a);
        n00b_store_byte_span_t sb = n00b_result_get(span_b);
        CHECK(sa.byte_len == sb.byte_len);
        CHECK(memcmp(sa.data, sb.data, sa.byte_len) == 0);
    }

    for (uint64_t i = 0; i < FAULT_RECORDS; i++) {
        char level[16];
        snprintf(level, sizeof(level), "f%llu", (unsigned long long)i);
        check_same_postings(root_a, root_b, r"level",
                            n00b_string_from_cstr(level));
    }
    check_same_postings(root_a, root_b, r"level", r"after");
    check_same_postings(root_a, root_b, r"kind", r"rocs.ingest_error");

    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(ra)));
    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(rb)));
}

// The source the range commit's tombstone for a failed prepare is equal to.
static n00b_buffer_t *
prepare_tombstone_source(void)
{
    char buf[160];
    int  len = snprintf(buf,
                        sizeof(buf),
                        "{\"kind\":\"rocs.ingest_error\",\"rocs_tombstone\":true,"
                        "\"error_code\":%d,\"error_stage\":\"reserved_slot_worker\"}",
                        (int)N00B_STORE_ERR_INTERNAL);
    return n00b_buffer_from_bytes(buf, len);
}

// Batch ingest through the range commit against the same records committed
// one at a time (worker_count 1 commits each with the single-record commit
// n00b_store_ingest uses), under the same fault. Each must report exactly the
// records it appended, so a caller resuming from that count duplicates none.
// A journal or fill fault must give both the same result. For a range-only
// fault, the single-record side commits what the range should have: the
// records before the failure, or for a failed prepare all of them with its
// tombstone in place. Either way the two shards must match, a later record
// included. A failed publish holds both shards, so only the counts are
// compared; the range appends every record before it publishes any.
static void
test_range_commit_matches_single_record_commit(void)
{
    size_t ncases = sizeof(fault_cases) / sizeof(fault_cases[0]);
    size_t ntargets = sizeof(fault_targets) / sizeof(fault_targets[0]);
    for (size_t ci = 0; ci < ncases; ci++) {
        const fault_case_t *c = &fault_cases[ci];
        if (c->fault == N00B_STORE_FAULT_RANGE_CANCEL) {
            continue;
        }
        bool both = c->fault == N00B_STORE_FAULT_JOURNAL
                 || c->fault == N00B_STORE_FAULT_FILL;
        for (size_t ti = 0; ti < ntargets; ti++) {
            uint64_t k = fault_targets[ti];
            fprintf(stderr, "  range against single: %s at %llu\n", c->name,
                    (unsigned long long)k);

            n00b_store_t *range = open_fault_store();
            auto range_r = faulted_batch(range, fault_sources(), c, k, 2);
            CHECK(result_committed(range_r)
                  == memory_of(range).hot_record_count);

            n00b_store_t *single = open_fault_store();
            if (c->fault == N00B_STORE_FAULT_PUBLISH) {
                auto single_r = faulted_batch(single, fault_sources(), c, k, 1);
                CHECK(result_committed(single_r)
                      == memory_of(single).hot_record_count);
                CHECK(result_committed(single_r) == k + 1);
                continue;
            }
            if (both) {
                auto single_r = faulted_batch(single, fault_sources(), c, k, 1);
                CHECK(n00b_result_is_ok(range_r)
                      == n00b_result_is_ok(single_r));
                CHECK(result_committed(single_r)
                      == memory_of(single).hot_record_count);
                if (n00b_result_is_ok(range_r)) {
                    CHECK(n00b_result_get(range_r)
                          == n00b_result_get(single_r));
                }
                else {
                    CHECK(n00b_result_get_err(range_r)
                          == n00b_result_get_err(single_r));
                }
            }
            else {
                uint64_t n = range_committed(c, k);
                CHECK(result_committed(range_r) == n);
                n00b_store_source_list_t *expected = source_list_new();
                for (uint64_t i = 0; i < n; i++) {
                    bool tombstone =
                        c->fault == N00B_STORE_FAULT_RANGE_PREPARE && i == k;
                    n00b_list_push(*expected,
                                   tombstone ? prepare_tombstone_source()
                                             : fault_source(i));
                }
                if (n != 0) {
                    auto single_r = n00b_store_ingest_buf_batch(
                        single,
                        expected,
                        .worker_count = 1);
                    CHECK(n00b_result_is_ok(single_r));
                    CHECK(n00b_result_get(single_r) == n);
                }
            }

            CHECK(n00b_result_is_ok(
                n00b_store_ingest_buf(range, level_source("after"))));
            CHECK(n00b_result_is_ok(
                n00b_store_ingest_buf(single, level_source("after"))));
            CHECK(memory_of(range).hot_live_index
                  == memory_of(range).hot_record_count);
            CHECK(n00b_result_is_ok(n00b_store_flush(range)));
            CHECK(n00b_result_is_ok(n00b_store_flush(single)));
            check_same_shard(range, single);
            close_store_ok(range);
            close_store_ok(single);
        }
    }
}
#endif

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_empty_batch_returns_zero();
    test_parsed_batch_preserves_order_and_indexes();
    test_buf_batch_retains_raw_and_indexes();
    test_worker_range_handles_byte_seal_policy();
    test_worker_range_handles_open_time_seal_policy();
    test_worker_parse_failure_rolls_back();
    test_batch_index_error_rolls_back();
    test_batch_partition_grouping();
    test_batch_ingest_worker_pool_drains();
    test_batch_durable_failure_without_journal_errors();
    test_batch_durable_failure_recovered_via_journal();
    test_journaled_source_batch_uses_worker_range();
    test_journal_failure_mid_range_commits_the_journaled_prefix();
#ifdef N00B_DEBUG
    test_worker_range_tombstone_is_indexed();
    test_worker_range_tombstone_survives_an_index_failure();
    test_held_tail_still_commits_the_journaled_prefix();
    test_held_tail_reports_the_failure_that_stopped_it();
    test_range_faults_leave_the_shard_publishing();
    test_range_commit_matches_single_record_commit();
#endif

    return 0;
}

/* test/unit/test_rocs_ingest.c - WP-005 Phase 5 ingest contracts. */

#include <stdint.h>
#include <string.h>
#include <math.h>

#include "n00b.h"
#include "conduit/conduit.h"
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

static n00b_store_t *
open_store(n00b_store_schema_t *schema) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_retain_policy_t    *retain_policy    = nullptr;
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
    n00b_store_commit_topic_t     *commit_topic     = nullptr;
}
{
    n00b_vfs_t *vfs = new_memory_vfs();
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .partition_policy = partition_policy,
                                       .retain_policy    = retain_policy,
                                       .seal_policy      = seal_policy,
                                       .commit_topic     = commit_topic);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
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

static n00b_json_node_t *
record_without_level(void)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record,
                              r"message",
                              n00b_json_string_new("missing"));
    return record;
}

static n00b_buffer_t *
buffer_from_literal(const char *s)
{
    return n00b_buffer_from_bytes((char *)s, (int64_t)strlen(s));
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
resident_root(n00b_store_t               *store,
              n00b_store_catalog_entry_t *entry,
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
test_parsed_ingest_flushes_records_and_index(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(true, N00B_STORE_INDEX_TERM));

    auto ingest_r = n00b_store_ingest(store, record_with_level(r"error"));
    CHECK(n00b_result_is_ok(ingest_r));

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(store, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 1);

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t      *root = resident_root(store, entry, &resident);
    auto list_r = n00b_store_map_shard_records(root);
    CHECK(n00b_result_is_ok(list_r));
    auto len_r = n00b_store_map_list_len(n00b_result_get(list_r));
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == 1);
    check_mapped_level_hit(root, r"error", 1, 0);

    auto release_r = n00b_store_resident_shard_release(resident);
    CHECK(n00b_result_is_ok(release_r));
}

static void
test_buffer_ingest_retains_raw(void)
{
    auto retain_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_INLINE);
    CHECK(n00b_result_is_ok(retain_r));

    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM),
                   .retain_policy = n00b_result_get(retain_r));

    n00b_buffer_t *source =
        buffer_from_literal("{\"level\":\"raw\",\"message\":\"hello\"}");
    auto ingest_r = n00b_store_ingest_buf(store, source);
    CHECK(n00b_result_is_ok(ingest_r));

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t *root =
        resident_root(store, catalog_shard(store, 1), &resident);

    auto raw_r = n00b_store_map_shard_raw_buffer(root, 0);
    CHECK(n00b_result_is_ok(raw_r));
    n00b_option_t(n00b_store_map_buffer_t *) raw_opt = n00b_result_get(raw_r);
    CHECK(n00b_option_is_set(raw_opt));
    check_raw_buffer_equal(n00b_option_get(raw_opt), source);
    check_mapped_level_hit(root, r"raw", 1, 0);

    auto release_r = n00b_store_resident_shard_release(resident);
    CHECK(n00b_result_is_ok(release_r));
}

static void
test_ingest_errors_are_typed(void)
{
    n00b_store_t *required_store =
        open_store(schema_with_level(true, N00B_STORE_INDEX_TERM));
    auto missing_r = n00b_store_ingest(required_store, record_without_level());
    CHECK(n00b_result_is_err(missing_r));
    CHECK(n00b_result_get_err(missing_r) == N00B_STORE_ERR_FIELD);

    auto parse_r = n00b_store_ingest_buf(required_store,
                                         buffer_from_literal("{\"level\":"));
    CHECK(n00b_result_is_err(parse_r));
    CHECK(n00b_result_get_err(parse_r) == N00B_STORE_ERR_PARSE);

    auto non_object_r = n00b_store_ingest(required_store, n00b_json_array_new());
    CHECK(n00b_result_is_err(non_object_r));
    CHECK(n00b_result_get_err(non_object_r) == N00B_STORE_ERR_ARG);

    n00b_store_t *unsupported_store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NUMERIC));
    auto unsupported_r =
        n00b_store_ingest(unsupported_store, record_with_level(r"info"));
    CHECK(n00b_result_is_err(unsupported_r));
    CHECK(n00b_result_get_err(unsupported_r) == N00B_STORE_ERR_INDEX);

    auto retain_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_INLINE);
    CHECK(n00b_result_is_ok(retain_r));
    n00b_store_t *inline_store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NONE),
                   .retain_policy = n00b_result_get(retain_r));
    auto parsed_inline_r =
        n00b_store_ingest(inline_store, record_with_level(r"raw"));
    CHECK(n00b_result_is_err(parsed_inline_r));
    CHECK(n00b_result_get_err(parsed_inline_r) == N00B_STORE_ERR_ARG);

    auto external_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_EXTERNAL);
    CHECK(n00b_result_is_ok(external_r));
    n00b_store_t *external_store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NONE),
                   .retain_policy = n00b_result_get(external_r));
    auto external_ingest_r =
        n00b_store_ingest_buf(external_store,
                              buffer_from_literal("{\"level\":\"x\"}"));
    CHECK(n00b_result_is_err(external_ingest_r));
    CHECK(n00b_result_get_err(external_ingest_r) == N00B_STORE_ERR_POLICY);
}

static void
test_index_error_does_not_append(void)
{
    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_TERM));

    auto ingest_r = n00b_store_ingest(store, record_with_nonfinite_level());
    CHECK(n00b_result_is_err(ingest_r));
    CHECK(n00b_result_get_err(ingest_r) == N00B_STORE_ERR_INDEX);

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
}

static void
test_partition_route_catalog_keys(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"level")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"ts")));

    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10);
    CHECK(n00b_result_is_ok(policy_r));

    n00b_store_t *store =
        open_store(schema, .partition_policy = n00b_result_get(policy_r));

    CHECK(n00b_result_is_ok(
        n00b_store_ingest(store, record_with_level_ts(r"a", 5))));
    CHECK(n00b_result_is_ok(
        n00b_store_ingest(store, record_with_level_ts(r"b", 15))));
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    auto p0_r = n00b_store_catalog_entry_get_partition_key(catalog_shard(store,
                                                                         1));
    auto p1_r = n00b_store_catalog_entry_get_partition_key(catalog_shard(store,
                                                                         2));
    CHECK(n00b_result_is_ok(p0_r));
    CHECK(n00b_result_is_ok(p1_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p0_r), r"time/0"));
    CHECK(n00b_unicode_str_eq(n00b_result_get(p1_r), r"time/1"));
}

static void
test_commit_topic_is_bounded_fire_and_forget(void)
{
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    n00b_conduit_t *conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_commit_topic_get(
        conduit,
        N00B_CONDUIT_URI_USER_EVENT(9001));
    CHECK(n00b_result_is_ok(topic_r));

    auto inbox_r = n00b_store_commit_inbox_new(
        conduit,
        .backpressure = N00B_CONDUIT_BP_DROP_NEWEST,
        .limit        = 2);
    CHECK(n00b_result_is_ok(inbox_r));

    auto sub_r = n00b_store_commit_subscribe(n00b_result_get(topic_r),
                                             n00b_result_get(inbox_r));
    CHECK(n00b_result_is_ok(sub_r));

    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NONE),
                   .commit_topic = n00b_result_get(topic_r));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record_with_level(r"a"))));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record_with_level(r"b"))));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record_with_level(r"c"))));

    n00b_store_commit_inbox_t *inbox = n00b_result_get(inbox_r);
    CHECK(n00b_store_commit_inbox_msg_count(inbox) == 2);

    n00b_store_commit_msg_t *first = n00b_store_commit_inbox_pop(inbox);
    n00b_store_commit_msg_t *second = n00b_store_commit_inbox_pop(inbox);
    CHECK(first != nullptr);
    CHECK(second != nullptr);
    CHECK(first->payload.kind == N00B_STORE_COMMIT_RECORD);
    CHECK(first->payload.ordinal == 0);
    CHECK(second->payload.kind == N00B_STORE_COMMIT_RECORD);
    CHECK(second->payload.ordinal == 1);
    CHECK(!n00b_store_commit_inbox_has_messages(inbox));

    n00b_conduit_sub_cancel(n00b_result_get(sub_r));
    n00b_conduit_destroy(conduit);
}

static void
test_auto_seal_commit_event_uses_sentinel_ordinal(void)
{
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    n00b_conduit_t *conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_commit_topic_get(
        conduit,
        N00B_CONDUIT_URI_USER_EVENT(9002));
    CHECK(n00b_result_is_ok(topic_r));

    auto inbox_r = n00b_store_commit_inbox_new(conduit, .limit = 4);
    CHECK(n00b_result_is_ok(inbox_r));

    auto sub_r = n00b_store_commit_subscribe(n00b_result_get(topic_r),
                                             n00b_result_get(inbox_r));
    CHECK(n00b_result_is_ok(sub_r));

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_store_t *store =
        open_store(schema_with_level(false, N00B_STORE_INDEX_NONE),
                   .seal_policy  = n00b_result_get(seal_r),
                   .commit_topic = n00b_result_get(topic_r));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record_with_level(r"a"))));

    n00b_store_commit_inbox_t *inbox = n00b_result_get(inbox_r);
    CHECK(n00b_store_commit_inbox_msg_count(inbox) == 2);

    n00b_store_commit_msg_t *record = n00b_store_commit_inbox_pop(inbox);
    n00b_store_commit_msg_t *seal = n00b_store_commit_inbox_pop(inbox);
    CHECK(record != nullptr);
    CHECK(seal != nullptr);
    CHECK(record->payload.kind == N00B_STORE_COMMIT_RECORD);
    CHECK(record->payload.ordinal == 0);
    CHECK(seal->payload.kind == N00B_STORE_COMMIT_SEAL);
    CHECK(seal->payload.ordinal == UINT64_MAX);

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_conduit_sub_cancel(n00b_result_get(sub_r));
    n00b_conduit_destroy(conduit);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_parsed_ingest_flushes_records_and_index();
    test_buffer_ingest_retains_raw();
    test_ingest_errors_are_typed();
    test_index_error_does_not_append();
    test_partition_route_catalog_keys();
    test_commit_topic_is_bounded_fire_and_forget();
    test_auto_seal_commit_event_uses_sentinel_ordinal();

    return 0;
}

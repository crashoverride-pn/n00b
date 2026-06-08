/* test/unit/test_rocs_query_topn.c - WP-011 Phase 5 top-N integration. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_CODE_ERR(expr, expected)                                         \
    do {                                                                       \
        auto _bl_query_topn_err_result = (expr);                               \
        CHECK(n00b_result_is_err(_bl_query_topn_err_result));                  \
        CHECK(n00b_result_get_err(_bl_query_topn_err_result) == (expected));   \
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
topn_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"id")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"message",
        .index_kind     = N00B_STORE_INDEX_FULLTEXT,
        .include_in_all = true)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"group")));
    return schema;
}

static n00b_store_t *
open_store(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       topn_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_filter_field_t *
field_ok(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
filter_ok(n00b_result_t(n00b_filter_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_query_t *
query_ok(n00b_result_t(n00b_query_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_query_result_t *
result_ok(n00b_result_t(n00b_query_result_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_json_node_t *
record_new(int64_t        id,
           n00b_string_t *message,
           n00b_string_t *group)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    if (message != nullptr) {
        n00b_json_object_put_n00b(
            record,
            r"message",
            n00b_json_string_new_from_n00b(message));
    }
    if (group != nullptr) {
        n00b_json_object_put_n00b(
            record,
            r"group",
            n00b_json_string_new_from_n00b(group));
    }
    return record;
}

static void
ingest_record(n00b_store_t *store,
              int64_t       id,
              n00b_string_t *message,
              n00b_string_t *group)
{
    auto ingest_r = n00b_store_ingest(store,
                                      record_new(id, message, group));
    CHECK(n00b_result_is_ok(ingest_r));
}

static n00b_store_catalog_entry_t *
seal_current(n00b_store_t *store, uint64_t seal_ts)
{
    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static n00b_store_pos_t
entry_pos(n00b_store_catalog_entry_t *entry, uint64_t ordinal)
{
    auto id_r  = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r = n00b_store_catalog_entry_get_generation(entry);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_is_ok(gen_r));
    return (n00b_store_pos_t){
        .generation = n00b_result_get(gen_r),
        .shard_id   = n00b_result_get(id_r),
        .ordinal    = ordinal,
    };
}

static n00b_filter_t *
contains(n00b_string_t *field, n00b_string_t *term)
{
    return filter_ok(n00b_filter_contains(field_ok(field), term));
}

static n00b_filter_t *
or2(n00b_filter_t *left, n00b_filter_t *right)
{
    return filter_ok(n00b_filter_or(left, right, kw_func(n00b_filter_or)));
}

static n00b_filter_t *
all_records_filter(void)
{
    return filter_ok(n00b_filter_exists(field_ok(r"id")));
}

static n00b_query_group_by_list_t *
group_by_list_new(void)
{
    n00b_query_group_by_list_t *list = n00b_alloc(n00b_query_group_by_list_t);
    *list = n00b_list_new_private(n00b_filter_field_t *,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_agg_spec_list_t *
agg_list_new(void)
{
    n00b_query_agg_spec_list_t *list =
        n00b_alloc(n00b_query_agg_spec_list_t);
    *list = n00b_list_new_private(n00b_query_agg_spec_t *,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_agg_spec_t *
agg_ok(n00b_query_agg_op_t op, n00b_filter_field_t *field)
{
    auto agg_r = n00b_query_agg(op, field);
    CHECK(n00b_result_is_ok(agg_r));
    return n00b_result_get(agg_r);
}

static n00b_query_result_t *
run_ranked(n00b_store_t    *store,
           n00b_filter_t   *filter,
           uint64_t         limit,
           n00b_store_pos_t *as_of)
{
    n00b_query_t *query = query_ok(n00b_query_new(filter,
                                                  .ranked = true,
                                                  .limit  = limit,
                                                  .as_of  = as_of));
    return result_ok(n00b_query_run(store, query));
}

static n00b_query_result_t *
run_group_count(n00b_store_t    *store,
                uint64_t         limit,
                n00b_store_pos_t *as_of)
{
    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_list_push(*groups, field_ok(r"group"));

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_COUNT, nullptr));

    n00b_query_t *query = query_ok(n00b_query_new(all_records_filter(),
                                                  .group_by   = groups,
                                                  .aggregates = aggs,
                                                  .limit      = limit,
                                                  .as_of      = as_of));
    return result_ok(n00b_query_run(store, query));
}

static n00b_query_hit_list_t *
records_ok(n00b_query_result_t *result)
{
    auto records_r = n00b_query_records(result);
    CHECK(n00b_result_is_ok(records_r));
    return n00b_result_get(records_r);
}

static n00b_query_hit_t *
hit_at(n00b_query_result_t *result, uint64_t index)
{
    n00b_query_hit_list_t *records = records_ok(result);
    CHECK(index < (uint64_t)n00b_list_len(*records));
    return n00b_list_get(*records, (size_t)index);
}

static double
hit_score(n00b_query_hit_t *hit)
{
    auto score_r = n00b_query_hit_score(hit);
    CHECK(n00b_result_is_ok(score_r));
    return n00b_result_get(score_r);
}

static int64_t
hit_id(n00b_query_hit_t *hit)
{
    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));

    auto json_r = n00b_store_record_view_json(n00b_result_get(record_r));
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *id =
        n00b_json_object_get(n00b_result_get(json_r), r"id");
    CHECK(id != nullptr);
    CHECK(n00b_json_is_int(id));
    return n00b_json_as_i64(id);
}

static n00b_query_agg_row_t *
row_at(n00b_query_result_t *result, uint64_t index)
{
    auto rows_r = n00b_query_rows(result);
    CHECK(n00b_result_is_ok(rows_r));
    n00b_query_agg_row_list_t *rows = n00b_result_get(rows_r);
    CHECK(index < (uint64_t)n00b_list_len(*rows));
    return n00b_list_get(*rows, (size_t)index);
}

static n00b_query_group_key_t *
row_key(n00b_query_agg_row_t *row, uint64_t index)
{
    auto key_r = n00b_query_row_group_key_at(row, index);
    CHECK(n00b_result_is_ok(key_r));
    CHECK(n00b_option_is_set(n00b_result_get(key_r)));
    return n00b_option_get(n00b_result_get(key_r));
}

static n00b_query_value_t
key_value(n00b_query_group_key_t *key)
{
    auto value_r = n00b_query_group_key_value(key);
    CHECK(n00b_result_is_ok(value_r));
    return n00b_result_get(value_r);
}

static n00b_query_value_t
row_value(n00b_query_agg_row_t *row, uint64_t index)
{
    auto value_r = n00b_query_row_value_at(row, index);
    CHECK(n00b_result_is_ok(value_r));
    CHECK(n00b_option_is_set(n00b_result_get(value_r)));
    return n00b_option_get(n00b_result_get(value_r));
}

static void
check_string(n00b_query_value_t value, n00b_string_t *expected)
{
    CHECK(n00b_variant_is_type(value, n00b_string_t *));
    CHECK(n00b_unicode_str_eq(n00b_variant_get(value, n00b_string_t *),
                              expected));
}

static void
check_u64(n00b_query_value_t value, uint64_t expected)
{
    CHECK(n00b_variant_is_type(value, uint64_t));
    CHECK(n00b_variant_get(value, uint64_t) == expected);
}

static bool
approx(double left, double right, double epsilon)
{
    double delta = left - right;
    if (delta < 0.0) {
        delta = -delta;
    }
    return delta <= epsilon;
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static void
close_result_true(n00b_query_result_t *result)
{
    auto close_r = n00b_query_result_close(result);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
test_ranked_topn_matches_unbounded_prefix_and_full_snapshot(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", r"a");
    ingest_record(store, 2, r"alpha", r"a");
    ingest_record(store, 3, r"alpha rare", r"a");
    ingest_record(store, 4, r"alpha rare", r"a");
    ingest_record(store, 5, r"alpha", r"a");
    seal_current(store, 5101);

    n00b_filter_t *filter =
        or2(contains(r"message", r"alpha"), contains(r"message", r"rare"));
    n00b_query_result_t *unbounded = run_ranked(store, filter, 0, nullptr);
    n00b_query_result_t *top2      = run_ranked(store, filter, 2, nullptr);

    CHECK(n00b_query_count(unbounded) == 5);
    CHECK(n00b_query_count(top2) == 2);
    for (uint64_t i = 0; i < 2; i++) {
        CHECK(hit_id(hit_at(top2, i)) == hit_id(hit_at(unbounded, i)));
        CHECK(approx(hit_score(hit_at(top2, i)),
                     hit_score(hit_at(unbounded, i)),
                     0.000001));
    }
    CHECK(hit_id(hit_at(top2, 0)) == 3);
    CHECK(hit_id(hit_at(top2, 1)) == 4);
    CHECK(active_pins(store) > 0);

    close_result_true(top2);
    close_result_true(unbounded);
    CHECK(active_pins(store) == 0);
}

static void
test_ranked_tie_break_deterministic_with_limit(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", r"a");
    ingest_record(store, 2, r"alpha", r"a");
    ingest_record(store, 3, r"alpha", r"a");
    ingest_record(store, 4, r"alpha", r"a");
    seal_current(store, 5201);

    n00b_filter_t *filter = contains(r"message", r"alpha");
    n00b_query_result_t *first  = run_ranked(store, filter, 2, nullptr);
    n00b_query_result_t *second = run_ranked(store, filter, 2, nullptr);

    CHECK(n00b_query_count(first) == 2);
    CHECK(n00b_query_count(second) == 2);
    CHECK(hit_id(hit_at(first, 0)) == 1);
    CHECK(hit_id(hit_at(first, 1)) == 2);
    CHECK(hit_id(hit_at(second, 0)) == 1);
    CHECK(hit_id(hit_at(second, 1)) == 2);
    CHECK(approx(hit_score(hit_at(first, 0)),
                 hit_score(hit_at(first, 1)),
                 0.000001));

    close_result_true(first);
    close_result_true(second);
    CHECK(active_pins(store) == 0);
}

static void
test_aggregate_ordering_applies_before_limit(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", r"c");
    ingest_record(store, 2, r"alpha", r"a");
    ingest_record(store, 3, r"alpha", r"b");
    seal_current(store, 5301);

    n00b_query_result_t *result = run_group_count(store, 2, nullptr);
    CHECK(n00b_query_count(result) == 2);
    check_string(key_value(row_key(row_at(result, 0), 0)), r"a");
    check_string(key_value(row_key(row_at(result, 1), 0)), r"b");
    check_u64(row_value(row_at(result, 0), 0), 1);
    check_u64(row_value(row_at(result, 1), 0), 1);
    close_result_true(result);
    CHECK(active_pins(store) == 0);
}

static void
test_ranked_as_of_partial_boundary(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", r"a");
    ingest_record(store, 2, r"alpha rare", r"a");
    n00b_store_catalog_entry_t *first = seal_current(store, 5401);

    ingest_record(store, 3, r"alpha rare", r"a");
    ingest_record(store, 4, r"alpha rare", r"a");
    seal_current(store, 5402);

    n00b_store_pos_t as_of = entry_pos(first, 1);
    n00b_query_result_t *result =
        run_ranked(store, contains(r"message", r"rare"), 2, &as_of);
    CHECK(n00b_query_count(result) == 1);
    CHECK(hit_id(hit_at(result, 0)) == 2);
    CHECK(hit_score(hit_at(result, 0)) > 1.0);
    close_result_true(result);
    CHECK(active_pins(store) == 0);
}

static void
test_aggregate_as_of_partial_boundary(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", r"b");
    ingest_record(store, 2, r"alpha", r"a");
    n00b_store_catalog_entry_t *first = seal_current(store, 5501);

    ingest_record(store, 3, r"alpha", r"a");
    seal_current(store, 5502);

    n00b_store_pos_t as_of = entry_pos(first, 0);
    n00b_query_result_t *result = run_group_count(store, 0, &as_of);
    CHECK(n00b_query_count(result) == 1);
    check_string(key_value(row_key(row_at(result, 0), 0)), r"b");
    check_u64(row_value(row_at(result, 0), 0), 1);
    close_result_true(result);
    CHECK(active_pins(store) == 0);
}

static void
test_live_view_keeps_cursor_order_and_zero_scores(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", r"a");
    ingest_record(store, 2, r"alpha rare", r"a");
    n00b_store_catalog_entry_t *entry = seal_current(store, 5601);

    n00b_filter_t *filter =
        or2(contains(r"message", r"alpha"), contains(r"message", r"rare"));
    n00b_store_pos_t as_of = entry_pos(entry, 1);
    CHECK_CODE_ERR(n00b_query_view(store,
                                   filter,
                                   .mode  = N00B_QUERY_MODE_LIVE,
                                   .as_of = &as_of),
                   N00B_QUERY_ERR_INVALID_OPTION);

    auto view_r = n00b_query_view(store,
                                  filter,
                                  .mode  = N00B_QUERY_MODE_LIVE,
                                  .limit = 1);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(n00b_option_is_set(n00b_result_get(next_r)));
    n00b_query_hit_t *hit = n00b_option_get(n00b_result_get(next_r));
    CHECK(hit_id(hit) == 1);
    CHECK(hit_score(hit) == 0.0);

    auto none_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    auto close_cursor_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_cursor_r));
    CHECK(n00b_result_get(close_cursor_r));
    auto close_view_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_view_r));
    CHECK(n00b_result_get(close_view_r));
    CHECK(active_pins(store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_ranked_topn_matches_unbounded_prefix_and_full_snapshot();
    test_ranked_tie_break_deterministic_with_limit();
    test_aggregate_ordering_applies_before_limit();
    test_ranked_as_of_partial_boundary();
    test_aggregate_as_of_partial_boundary();
    test_live_view_keeps_cursor_order_and_zero_scores();

    n00b_shutdown();
    return 0;
}

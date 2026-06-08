/* test/unit/test_rocs_query_agg.c - WP-011 Phase 2 aggregation rows. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "internal/rocs/query.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_CODE_ERR(expr, expected)                                         \
    do {                                                                       \
        auto _bl_query_agg_err_result = (expr);                                \
        CHECK(n00b_result_is_err(_bl_query_agg_err_result));                   \
        CHECK(n00b_result_get_err(_bl_query_agg_err_result) == (expected));    \
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

static n00b_store_t *
open_store(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       n00b_result_get(schema_r));
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
all_records_filter(void)
{
    auto filter_r = n00b_filter_exists(field_ok(r"id"));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
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

static n00b_query_boost_list_t *
boost_list_new(void)
{
    n00b_query_boost_list_t *list = n00b_alloc(n00b_query_boost_list_t);
    *list = n00b_list_new_private(n00b_query_boost_t *,
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

static n00b_query_agg_row_t *
row_at(n00b_query_result_t *result, uint64_t index)
{
    auto rows_r = n00b_query_rows(result);
    CHECK(n00b_result_is_ok(rows_r));
    n00b_query_agg_row_list_t *rows = n00b_result_get(rows_r);
    CHECK(index < (uint64_t)n00b_list_len(*rows));
    return n00b_list_get(*rows, (size_t)index);
}

static n00b_query_value_t
row_value(n00b_query_agg_row_t *row, uint64_t index)
{
    auto value_r = n00b_query_row_value_at(row, index);
    CHECK(n00b_result_is_ok(value_r));
    CHECK(n00b_option_is_set(n00b_result_get(value_r)));
    return n00b_option_get(n00b_result_get(value_r));
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

static n00b_query_note_t *
note_at(n00b_query_result_t *result, uint64_t index)
{
    auto notes_r = n00b_query_result_notes(result);
    CHECK(n00b_result_is_ok(notes_r));
    n00b_query_note_list_t *notes = n00b_result_get(notes_r);
    CHECK(index < (uint64_t)n00b_list_len(*notes));
    return n00b_list_get(*notes, (size_t)index);
}

static uint64_t
note_count(n00b_query_result_t *result)
{
    auto notes_r = n00b_query_result_notes(result);
    CHECK(n00b_result_is_ok(notes_r));
    return (uint64_t)n00b_list_len(*n00b_result_get(notes_r));
}

static void
close_result_true(n00b_query_result_t *result)
{
    auto close_r = n00b_query_result_close(result);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static uint64_t
entry_shard_id(n00b_store_catalog_entry_t *entry)
{
    auto id_r = n00b_store_catalog_entry_get_shard_id(entry);
    CHECK(n00b_result_is_ok(id_r));
    return n00b_result_get(id_r);
}

static void
check_missing(n00b_query_value_t value)
{
    CHECK(n00b_variant_is_type(value, n00b_query_missing_t));
}

static void
check_null(n00b_query_value_t value)
{
    CHECK(n00b_variant_is_type(value, n00b_query_null_t));
}

static void
check_i64(n00b_query_value_t value, int64_t expected)
{
    CHECK(n00b_variant_is_type(value, int64_t));
    CHECK(n00b_variant_get(value, int64_t) == expected);
}

static void
check_u64(n00b_query_value_t value, uint64_t expected)
{
    CHECK(n00b_variant_is_type(value, uint64_t));
    CHECK(n00b_variant_get(value, uint64_t) == expected);
}

static void
check_f64(n00b_query_value_t value, double expected)
{
    CHECK(n00b_variant_is_type(value, double));
    double got = n00b_variant_get(value, double);
    CHECK(got >= expected - 0.000001);
    CHECK(got <= expected + 0.000001);
}

static void
check_string(n00b_query_value_t value, n00b_string_t *expected)
{
    CHECK(n00b_variant_is_type(value, n00b_string_t *));
    CHECK(n00b_unicode_str_eq(n00b_variant_get(value, n00b_string_t *),
                              expected));
}

static n00b_json_node_t *
base_record(int64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    return record;
}

static void
put_group_string(n00b_json_node_t *record, n00b_string_t *group)
{
    n00b_json_object_put_n00b(record,
                              r"group",
                              n00b_json_string_new_from_n00b(group));
}

static void
put_common_numeric(n00b_json_node_t *record,
                   n00b_json_node_t *qty,
                   n00b_json_node_t *mixed)
{
    n00b_json_object_put_n00b(record, r"qty", qty);
    n00b_json_object_put_n00b(record, r"mixed", mixed);
}

static n00b_store_catalog_entry_t *
seal_current(n00b_store_t *store, uint64_t seal_ts)
{
    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static void
ingest_agg_fixture(n00b_store_t *store)
{
    n00b_json_node_t *r1 = base_record(1);
    put_group_string(r1, r"b");
    put_common_numeric(r1, n00b_json_int_new(10), n00b_json_int_new(1));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, r1)));

    n00b_json_node_t *r2 = base_record(2);
    put_group_string(r2, r"a");
    put_common_numeric(r2, n00b_json_int_new(20), n00b_json_double_new(2.5));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, r2)));

    n00b_json_node_t *r3 = base_record(3);
    n00b_json_object_put_n00b(r3, r"group", n00b_json_null_new());
    put_common_numeric(r3, n00b_json_int_new(-5), n00b_json_int_new(3));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, r3)));

    n00b_json_node_t *r4 = base_record(4);
    put_common_numeric(r4,
                       n00b_json_string_new("bad"),
                       n00b_json_string_new("bad"));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, r4)));

    n00b_json_node_t *r5 = base_record(5);
    put_group_string(r5, r"__missing__");
    put_common_numeric(r5, n00b_json_int_new(7), n00b_json_int_new(4));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, r5)));
}

static n00b_query_agg_spec_list_t *
count_sum_aggs(void)
{
    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_COUNT, nullptr));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_SUM, field_ok(r"qty")));
    return aggs;
}

static void
test_group_by_rows_order_keys_notes_and_close(void)
{
    n00b_store_t *store = open_store();
    ingest_agg_fixture(store);
    n00b_store_catalog_entry_t *entry = seal_current(store, 2101);
    uint64_t shard_id = entry_shard_id(entry);

    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_list_push(*groups, field_ok(r"group"));

    n00b_query_t *query = query_ok(n00b_query_new(all_records_filter(),
                                                  .group_by   = groups,
                                                  .aggregates = count_sum_aggs(),
                                                  .limit      = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    CHECK(active_pins(store) == 0);
    CHECK(n00b_query_count(result) == 5);
    CHECK(note_count(result) == 1);

    n00b_query_agg_row_t *missing = row_at(result, 0);
    n00b_query_agg_row_t *nullrow = row_at(result, 1);
    n00b_query_agg_row_t *magic   = row_at(result, 2);
    n00b_query_agg_row_t *a       = row_at(result, 3);
    n00b_query_agg_row_t *b       = row_at(result, 4);

    CHECK(n00b_result_get(n00b_query_row_group_key_count(missing)) == 1);
    check_missing(key_value(row_key(missing, 0)));
    check_u64(row_value(missing, 0), 1);
    check_missing(row_value(missing, 1));

    check_null(key_value(row_key(nullrow, 0)));
    check_i64(row_value(nullrow, 1), -5);

    check_string(key_value(row_key(magic, 0)), r"__missing__");
    check_i64(row_value(magic, 1), 7);

    check_string(key_value(row_key(a, 0)), r"a");
    check_i64(row_value(a, 1), 20);

    check_string(key_value(row_key(b, 0)), r"b");
    check_i64(row_value(b, 1), 10);

    n00b_query_note_t *note = note_at(result, 0);
    auto note_pos_r = n00b_query_note_pos(note);
    CHECK(n00b_result_is_ok(note_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(note_pos_r)));
    CHECK(n00b_option_get(n00b_result_get(note_pos_r)).ordinal == 3);
    auto note_msg_r = n00b_query_note_message(note);
    CHECK(n00b_result_is_ok(note_msg_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(note_msg_r),
                              r"non_numeric_aggregate_operand"));
    auto note_value_r = n00b_query_note_value(note);
    CHECK(n00b_result_is_ok(note_value_r));
    CHECK(n00b_option_is_set(n00b_result_get(note_value_r)));
    check_string(n00b_option_get(n00b_result_get(note_value_r)), r"bad");

    auto drop_r = n00b_store_drop_sealed_shard(store, shard_id);
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));

    n00b_query_group_key_t *saved_key = row_key(missing, 0);
    close_result_true(result);
    CHECK_CODE_ERR(n00b_query_row_value_at(missing, 0),
                   N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_group_key_value(saved_key),
                   N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_note_message(note), N00B_QUERY_ERR_CLOSED);
}

static void
test_numeric_aggregates_and_mixed_values(void)
{
    n00b_store_t *store = open_store();
    ingest_agg_fixture(store);
    (void)seal_current(store, 2201);

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_COUNT, nullptr));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_SUM, field_ok(r"qty")));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_MIN, field_ok(r"qty")));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_MAX, field_ok(r"qty")));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_AVG, field_ok(r"qty")));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_SUM, field_ok(r"mixed")));

    n00b_query_t *query = query_ok(n00b_query_new(all_records_filter(),
                                                  .aggregates = aggs,
                                                  .limit      = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    CHECK(n00b_query_count(result) == 1);
    CHECK(note_count(result) == 5);

    n00b_query_agg_row_t *row = row_at(result, 0);
    CHECK(n00b_result_get(n00b_query_row_group_key_count(row)) == 0);
    CHECK(n00b_result_get(n00b_query_row_value_count(row)) == 6);
    check_u64(row_value(row, 0), 5);
    check_i64(row_value(row, 1), 32);
    check_i64(row_value(row, 2), -5);
    check_i64(row_value(row, 3), 20);
    check_f64(row_value(row, 4), 8.0);
    check_f64(row_value(row, 5), 10.5);

    close_result_true(result);
    CHECK(active_pins(store) == 0);
}

static void
test_min_max_ties_preserve_first_operand_type(void)
{
    n00b_store_t *store = open_store();

    n00b_json_node_t *first = base_record(1);
    n00b_json_object_put_n00b(first, r"v", n00b_json_int_new(1));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, first)));

    n00b_json_node_t *second = base_record(2);
    n00b_json_object_put_n00b(second, r"v", n00b_json_double_new(1.0));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, second)));
    (void)seal_current(store, 2301);

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_MIN, field_ok(r"v")));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_MAX, field_ok(r"v")));

    n00b_query_t *query = query_ok(n00b_query_new(all_records_filter(),
                                                  .aggregates = aggs,
                                                  .limit      = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    n00b_query_agg_row_t *row = row_at(result, 0);
    check_i64(row_value(row, 0), 1);
    check_i64(row_value(row, 1), 1);
    close_result_true(result);
}

static void
test_mixed_min_max_compare_ints_exactly(void)
{
    n00b_store_t *store = open_store();

    n00b_json_node_t *large_int = base_record(1);
    n00b_json_object_put_n00b(large_int,
                              r"v",
                              n00b_json_int_new(INT64_C(9007199254740993)));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, large_int)));

    n00b_json_node_t *lower_double = base_record(2);
    n00b_json_object_put_n00b(lower_double,
                              r"v",
                              n00b_json_double_new(9007199254740992.0));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, lower_double)));
    (void)seal_current(store, 2351);

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_MIN, field_ok(r"v")));
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_MAX, field_ok(r"v")));

    n00b_query_t *query = query_ok(n00b_query_new(all_records_filter(),
                                                  .aggregates = aggs,
                                                  .limit      = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    n00b_query_agg_row_t *row = row_at(result, 0);
    check_f64(row_value(row, 0), 9007199254740992.0);
    check_i64(row_value(row, 1), INT64_C(9007199254740993));
    close_result_true(result);
}

static void
test_integer_overflow_error(void)
{
    n00b_store_t *store = open_store();

    n00b_json_node_t *first = base_record(1);
    n00b_json_object_put_n00b(first, r"big", n00b_json_int_new(INT64_MAX));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, first)));

    n00b_json_node_t *second = base_record(2);
    n00b_json_object_put_n00b(second, r"big", n00b_json_int_new(1));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, second)));
    (void)seal_current(store, 2401);

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, agg_ok(N00B_QUERY_AGG_SUM, field_ok(r"big")));
    n00b_query_t *query = query_ok(n00b_query_new(all_records_filter(),
                                                  .aggregates = aggs,
                                                  .limit      = 0));
    CHECK_CODE_ERR(n00b_query_run(store, query), N00B_QUERY_ERR_RANGE);
    CHECK(active_pins(store) == 0);
}

static void
test_empty_grouped_and_global_results(void)
{
    n00b_store_t *store = open_store();

    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_list_push(*groups, field_ok(r"group"));

    n00b_query_agg_spec_list_t *count_aggs = agg_list_new();
    n00b_list_push(*count_aggs, agg_ok(N00B_QUERY_AGG_COUNT, nullptr));

    n00b_query_t *grouped = query_ok(n00b_query_new(all_records_filter(),
                                                    .group_by   = groups,
                                                    .aggregates = count_aggs,
                                                    .limit      = 0));
    n00b_query_result_t *grouped_result =
        result_ok(n00b_query_run(store, grouped));
    CHECK(n00b_query_count(grouped_result) == 0);
    CHECK(note_count(grouped_result) == 0);
    close_result_true(grouped_result);

    n00b_query_agg_spec_list_t *global_aggs = agg_list_new();
    n00b_list_push(*global_aggs, agg_ok(N00B_QUERY_AGG_COUNT, nullptr));
    n00b_query_t *global = query_ok(n00b_query_new(all_records_filter(),
                                                   .aggregates = global_aggs,
                                                   .limit      = 0));
    n00b_query_result_t *global_result =
        result_ok(n00b_query_run(store, global));
    CHECK(n00b_query_count(global_result) == 1);
    check_u64(row_value(row_at(global_result, 0), 0), 0);
    close_result_true(global_result);
}

static void
test_deterministic_order_across_input_order(void)
{
    n00b_store_t *store1 = open_store();
    n00b_store_t *store2 = open_store();

    n00b_json_node_t *b1 = base_record(1);
    put_group_string(b1, r"b");
    CHECK(n00b_result_is_ok(n00b_store_ingest(store1, b1)));
    n00b_json_node_t *a1 = base_record(2);
    put_group_string(a1, r"a");
    CHECK(n00b_result_is_ok(n00b_store_ingest(store1, a1)));
    (void)seal_current(store1, 2501);

    n00b_json_node_t *a2 = base_record(1);
    put_group_string(a2, r"a");
    CHECK(n00b_result_is_ok(n00b_store_ingest(store2, a2)));
    n00b_json_node_t *b2 = base_record(2);
    put_group_string(b2, r"b");
    CHECK(n00b_result_is_ok(n00b_store_ingest(store2, b2)));
    (void)seal_current(store2, 2502);

    n00b_query_group_by_list_t *groups1 = group_by_list_new();
    n00b_list_push(*groups1, field_ok(r"group"));
    n00b_query_group_by_list_t *groups2 = group_by_list_new();
    n00b_list_push(*groups2, field_ok(r"group"));

    n00b_query_t *q1 = query_ok(n00b_query_new(all_records_filter(),
                                               .group_by = groups1,
                                               .limit    = 0));
    n00b_query_t *q2 = query_ok(n00b_query_new(all_records_filter(),
                                               .group_by = groups2,
                                               .limit    = 0));
    n00b_query_result_t *r1 = result_ok(n00b_query_run(store1, q1));
    n00b_query_result_t *r2 = result_ok(n00b_query_run(store2, q2));

    CHECK(n00b_query_count(r1) == 2);
    CHECK(n00b_query_count(r2) == 2);
    check_string(key_value(row_key(row_at(r1, 0), 0)), r"a");
    check_string(key_value(row_key(row_at(r1, 1), 0)), r"b");
    check_string(key_value(row_key(row_at(r2, 0), 0)), r"a");
    check_string(key_value(row_key(row_at(r2, 1), 0)), r"b");

    close_result_true(r1);
    close_result_true(r2);
}

static void
test_grouped_ranked_and_boosted_still_not_ready(void)
{
    n00b_store_t *store = open_store();
    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_list_push(*groups, field_ok(r"group"));

    n00b_query_t *ranked = query_ok(n00b_query_new(all_records_filter(),
                                                   .group_by = groups,
                                                   .ranked = true));
    CHECK_CODE_ERR(n00b_query_run(store, ranked), N00B_QUERY_ERR_NOT_READY);

    n00b_query_boost_list_t *boosts = boost_list_new();
    auto boost_r = n00b_query_boost(field_ok(r"id"), 2.0);
    CHECK(n00b_result_is_ok(boost_r));
    n00b_list_push(*boosts, n00b_result_get(boost_r));

    n00b_query_t *boosted = query_ok(n00b_query_new(all_records_filter(),
                                                    .group_by = groups,
                                                    .boosts = boosts));
    CHECK_CODE_ERR(n00b_query_run(store, boosted), N00B_QUERY_ERR_NOT_READY);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_group_by_rows_order_keys_notes_and_close();
    test_numeric_aggregates_and_mixed_values();
    test_min_max_ties_preserve_first_operand_type();
    test_mixed_min_max_compare_ints_exactly();
    test_integer_overflow_error();
    test_empty_grouped_and_global_results();
    test_deterministic_order_across_input_order();
    test_grouped_ranked_and_boosted_still_not_ready();

    n00b_shutdown();
    return 0;
}

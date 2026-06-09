/* test/unit/test_rocs_query_spec.c - WP-011 Phase 1 query spec/result shell. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/query.h must not include internal query declarations"
#endif

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "rocs/query.h must not include internal planner declarations"
#endif

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/n00b_rocs.h must not include internal query declarations"
#endif

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "rocs/n00b_rocs.h must not include internal planner declarations"
#endif

#include "internal/rocs/query.h"
#include "internal/rocs/index.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_CODE_ERR(expr, expected)                                         \
    do {                                                                       \
        auto _bl_query_spec_err_result = (expr);                               \
        CHECK(n00b_result_is_err(_bl_query_spec_err_result));                  \
        CHECK(n00b_result_get_err(_bl_query_spec_err_result) == (expected));   \
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
open_store(n00b_vfs_t *vfs)
{
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", new_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_filter_field_t *
field_ok(n00b_result_t(n00b_filter_field_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_field_t *field = n00b_result_get(r);
    CHECK(field != nullptr);
    return field;
}

static n00b_filter_t *
filter_ok(n00b_result_t(n00b_filter_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_t *filter = n00b_result_get(r);
    CHECK(filter != nullptr);
    return filter;
}

static n00b_query_t *
query_ok(n00b_result_t(n00b_query_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_t *query = n00b_result_get(r);
    CHECK(query != nullptr);
    return query;
}

static n00b_query_result_t *
result_ok(n00b_result_t(n00b_query_result_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_result_t *result = n00b_result_get(r);
    CHECK(result != nullptr);
    return result;
}

static n00b_query_agg_spec_t *
agg_ok(n00b_result_t(n00b_query_agg_spec_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_agg_spec_t *agg = n00b_result_get(r);
    CHECK(agg != nullptr);
    return agg;
}

static n00b_query_boost_t *
boost_ok(n00b_result_t(n00b_query_boost_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_boost_t *boost = n00b_result_get(r);
    CHECK(boost != nullptr);
    return boost;
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

static n00b_filter_t *
exists_filter(n00b_string_t *name)
{
    return filter_ok(n00b_filter_exists(field_ok(n00b_filter_field(name))));
}

static n00b_filter_t *
level_error_filter(void)
{
    return filter_ok(n00b_filter_eq(field_ok(n00b_filter_field(r"level")),
                                    n00b_fv_utf8(r"error")));
}

static n00b_json_node_t *
record_with_level(int64_t id, n00b_string_t *level)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(level));
    return record;
}

static void
ingest_record(n00b_store_t *store, int64_t id, n00b_string_t *level)
{
    auto ingest_r = n00b_store_ingest(store, record_with_level(id, level));
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
        .shard_id   = n00b_result_get(id_r),
        .ordinal    = ordinal,
        .generation = n00b_result_get(gen_r),
    };
}

static uint64_t
entry_shard_id(n00b_store_catalog_entry_t *entry)
{
    auto id_r = n00b_store_catalog_entry_get_shard_id(entry);
    CHECK(n00b_result_is_ok(id_r));
    return n00b_result_get(id_r);
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
check_record_id(n00b_query_hit_t *hit, int64_t expected_id)
{
    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));

    auto json_r = n00b_store_record_view_json(n00b_result_get(record_r));
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *json = n00b_result_get(json_r);
    CHECK(n00b_json_is_object(json));

    n00b_json_node_t *id = n00b_json_object_get(json, r"id");
    CHECK(id != nullptr);
    CHECK(n00b_json_is_int(id));
    CHECK(n00b_json_as_i64(id) == expected_id);
}

static void
test_query_spec_construction_and_list_copy(void)
{
    n00b_filter_field_t *level = field_ok(n00b_filter_field(r"level"));
    n00b_filter_field_t *id    = field_ok(n00b_filter_field(r"id"));
    n00b_filter_t       *filter = exists_filter(r"id");
    n00b_query_agg_spec_t *agg =
        agg_ok(n00b_query_agg(N00B_QUERY_AGG_SUM, id, .name = r"sum_id"));
    n00b_query_boost_t *boost = boost_ok(n00b_query_boost(level, 2.0));

    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_query_agg_spec_list_t *aggs   = agg_list_new();
    n00b_query_boost_list_t    *boosts = boost_list_new();
    n00b_list_push(*groups, level);
    n00b_list_push(*aggs, agg);
    n00b_list_push(*boosts, boost);

    n00b_store_pos_t as_of = {
        .generation = 7,
        .shard_id   = 8,
        .ordinal    = 9,
    };
    n00b_query_t *query = query_ok(n00b_query_new(filter,
                                                  .group_by   = groups,
                                                  .aggregates = aggs,
                                                  .ranked     = true,
                                                  .boosts     = boosts,
                                                  .as_of      = &as_of,
                                                  .limit      = 12));

    n00b_list_push(*groups, id);
    n00b_list_push(*aggs, agg_ok(n00b_query_agg(N00B_QUERY_AGG_COUNT,
                                                nullptr)));
    n00b_list_push(*boosts, boost_ok(n00b_query_boost(id, 3.0)));
    as_of.ordinal = 99;

    CHECK(n00b_result_get(n00b_query_spec_ranked(query)));
    CHECK(n00b_result_get(n00b_query_spec_limit(query)) == 12);
    CHECK(n00b_result_get(n00b_query_spec_group_by_count(query)) == 1);
    CHECK(n00b_result_get(n00b_query_spec_aggregate_count(query)) == 1);
    CHECK(n00b_result_get(n00b_query_spec_boost_count(query)) == 1);

    auto as_of_r = n00b_query_spec_as_of(query);
    CHECK(n00b_result_is_ok(as_of_r));
    CHECK(n00b_option_is_set(n00b_result_get(as_of_r)));
    CHECK(n00b_option_get(n00b_result_get(as_of_r)).ordinal == 9);

    auto group_r = n00b_query_spec_group_by_at(query, 0);
    CHECK(n00b_result_is_ok(group_r));
    CHECK(n00b_option_is_set(n00b_result_get(group_r)));
    CHECK(n00b_option_get(n00b_result_get(group_r)) == level);
    CHECK(!n00b_option_is_set(n00b_result_get(
        n00b_query_spec_group_by_at(query, 1))));

    auto agg_r = n00b_query_spec_aggregate_at(query, 0);
    CHECK(n00b_result_is_ok(agg_r));
    CHECK(n00b_option_is_set(n00b_result_get(agg_r)));
    CHECK(n00b_option_get(n00b_result_get(agg_r)) == agg);
    CHECK(n00b_result_get(n00b_query_agg_spec_op(agg))
          == N00B_QUERY_AGG_SUM);
    CHECK(n00b_option_is_set(n00b_result_get(n00b_query_agg_spec_name(agg))));

    auto boost_r = n00b_query_spec_boost_at(query, 0);
    CHECK(n00b_result_is_ok(boost_r));
    CHECK(n00b_option_is_set(n00b_result_get(boost_r)));
    CHECK(n00b_option_get(n00b_result_get(boost_r)) == boost);
    CHECK(n00b_result_get(n00b_query_boost_spec_field(boost)) == level);
    CHECK(n00b_result_get(n00b_query_boost_spec_value(boost)) == 2.0);
}

static void
test_invalid_options(void)
{
    n00b_filter_field_t *id = field_ok(n00b_filter_field(r"id"));
    n00b_filter_t       *filter = exists_filter(r"id");

    CHECK_CODE_ERR(n00b_query_new(nullptr), N00B_QUERY_ERR_ARG);
    CHECK_CODE_ERR(n00b_query_agg((n00b_query_agg_op_t)999, id),
                   N00B_QUERY_ERR_INVALID_OPTION);
    CHECK_CODE_ERR(n00b_query_agg(N00B_QUERY_AGG_SUM, nullptr),
                   N00B_QUERY_ERR_ARG);
    CHECK(n00b_result_is_ok(n00b_query_agg(N00B_QUERY_AGG_COUNT, nullptr)));

    CHECK_CODE_ERR(n00b_query_boost(nullptr, 1.0), N00B_QUERY_ERR_ARG);
    CHECK_CODE_ERR(n00b_query_boost(id, 0.0),
                   N00B_QUERY_ERR_INVALID_OPTION);
    CHECK_CODE_ERR(n00b_query_boost(id, -1.0),
                   N00B_QUERY_ERR_INVALID_OPTION);
    CHECK_CODE_ERR(n00b_query_boost(id, __builtin_nan("")),
                   N00B_QUERY_ERR_INVALID_OPTION);
    CHECK_CODE_ERR(n00b_query_boost(id, __builtin_inf()),
                   N00B_QUERY_ERR_INVALID_OPTION);

    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_list_push(*groups, (n00b_filter_field_t *)nullptr);
    CHECK_CODE_ERR(n00b_query_new(filter, .group_by = groups),
                   N00B_QUERY_ERR_INVALID_OPTION);

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs, (n00b_query_agg_spec_t *)nullptr);
    CHECK_CODE_ERR(n00b_query_new(filter, .aggregates = aggs),
                   N00B_QUERY_ERR_INVALID_OPTION);

    n00b_query_boost_list_t *boosts = boost_list_new();
    n00b_list_push(*boosts, (n00b_query_boost_t *)nullptr);
    CHECK_CODE_ERR(n00b_query_new(filter, .boosts = boosts),
                   N00B_QUERY_ERR_INVALID_OPTION);
}

static void
test_empty_result_and_close(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    n00b_query_t *query = query_ok(n00b_query_new(exists_filter(r"id"),
                                                  .limit = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    CHECK(active_pins(store) == 0);
    CHECK(n00b_query_count(result) == 0);

    auto records_r = n00b_query_records(result);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_list_len(*n00b_result_get(records_r)) == 0);

    auto rows_r = n00b_query_rows(result);
    CHECK(n00b_result_is_ok(rows_r));
    CHECK(n00b_list_len(*n00b_result_get(rows_r)) == 0);

    auto notes_r = n00b_query_result_notes(result);
    CHECK(n00b_result_is_ok(notes_r));
    CHECK(n00b_list_len(*n00b_result_get(notes_r)) == 0);

    close_result_true(result);
    CHECK(n00b_result_get(n00b_query_result_is_closed(result)));
    CHECK(n00b_query_count(result) == 0);
    CHECK_CODE_ERR(n00b_query_records(result), N00B_QUERY_ERR_CLOSED);

    auto close_again_r = n00b_query_result_close(result);
    CHECK(n00b_result_is_ok(close_again_r));
    CHECK(!n00b_result_get(close_again_r));
}

static void
test_snapshot_result_records_limit_and_resource_release(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    ingest_record(store, 1, r"error");
    ingest_record(store, 2, r"info");
    ingest_record(store, 3, r"error");
    n00b_store_catalog_entry_t *entry = seal_current(store, 1101);
    uint64_t shard_id = entry_shard_id(entry);

    n00b_query_t *limited = query_ok(n00b_query_new(level_error_filter(),
                                                    .limit = 1));
    n00b_query_result_t *one = result_ok(n00b_query_run(store, limited));
    CHECK(n00b_query_count(one) == 1);
    close_result_true(one);
    CHECK(active_pins(store) == 0);

    n00b_query_t *query = query_ok(n00b_query_new(level_error_filter(),
                                                  .limit = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    CHECK(n00b_query_count(result) == 2);
    CHECK(active_pins(store) == 2);

    auto records_r = n00b_query_records(result);
    CHECK(n00b_result_is_ok(records_r));
    n00b_query_hit_list_t *records = n00b_result_get(records_r);
    CHECK(n00b_list_len(*records) == 2);

    n00b_query_hit_t *first = n00b_list_get(*records, 0);
    auto first_pos_r = n00b_query_hit_pos(first);
    CHECK(n00b_result_is_ok(first_pos_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(first_pos_r),
                                 entry_pos(entry, 0)) == 0);
    CHECK(n00b_result_get(n00b_query_hit_score(first)) == 0.0);
    check_record_id(first, 1);

    n00b_list_push(*records, (n00b_query_hit_t *)nullptr);
    auto records_again_r = n00b_query_records(result);
    CHECK(n00b_result_is_ok(records_again_r));
    CHECK(n00b_list_len(*n00b_result_get(records_again_r)) == 2);

    auto pinned_drop_r = n00b_store_drop_sealed_shard(store, shard_id);
    CHECK(n00b_result_is_err(pinned_drop_r));
    CHECK(n00b_result_get_err(pinned_drop_r) == N00B_STORE_ERR_PINNED);

    close_result_true(result);
    CHECK(active_pins(store) == 0);
    CHECK_CODE_ERR(n00b_query_hit_pos(first), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_records(result), N00B_QUERY_ERR_CLOSED);

    auto drop_r = n00b_store_drop_sealed_shard(store, shard_id);
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));
}

static void
test_as_of_copy_snapshot_only_and_not_ready(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    ingest_record(store, 10, r"error");
    n00b_store_catalog_entry_t *first = seal_current(store, 1201);
    ingest_record(store, 11, r"error");
    (void)seal_current(store, 1202);

    n00b_store_pos_t as_of = entry_pos(first, 0);
    n00b_query_t *bounded = query_ok(n00b_query_new(level_error_filter(),
                                                    .as_of = &as_of,
                                                    .limit = 0));
    as_of.ordinal = 99;
    n00b_query_result_t *result = result_ok(n00b_query_run(store, bounded));
    CHECK(n00b_query_count(result) == 1);
    close_result_true(result);
    CHECK(active_pins(store) == 0);

    n00b_query_group_by_list_t *groups = group_by_list_new();
    n00b_list_push(*groups, field_ok(n00b_filter_field(r"level")));
    n00b_query_t *grouped = query_ok(n00b_query_new(level_error_filter(),
                                                    .group_by = groups));
    n00b_query_result_t *grouped_result =
        result_ok(n00b_query_run(store, grouped));
    CHECK(n00b_query_count(grouped_result) == 1);
    close_result_true(grouped_result);

    n00b_query_agg_spec_list_t *aggs = agg_list_new();
    n00b_list_push(*aggs,
                   agg_ok(n00b_query_agg(N00B_QUERY_AGG_COUNT, nullptr)));
    n00b_query_t *aggregated = query_ok(n00b_query_new(level_error_filter(),
                                                       .aggregates = aggs));
    n00b_query_result_t *aggregated_result =
        result_ok(n00b_query_run(store, aggregated));
    CHECK(n00b_query_count(aggregated_result) == 1);
    close_result_true(aggregated_result);

    n00b_query_t *ranked = query_ok(n00b_query_new(level_error_filter(),
                                                   .ranked = true));
    n00b_query_result_t *ranked_result =
        result_ok(n00b_query_run(store, ranked));
    CHECK(n00b_query_count(ranked_result) == 2);
    close_result_true(ranked_result);

    n00b_query_boost_list_t *boosts = boost_list_new();
    n00b_list_push(*boosts,
                   boost_ok(n00b_query_boost(field_ok(n00b_filter_field(r"id")),
                                             1.5)));
    n00b_query_t *boosted = query_ok(n00b_query_new(level_error_filter(),
                                                    .boosts = boosts));
    n00b_query_result_t *boosted_result =
        result_ok(n00b_query_run(store, boosted));
    CHECK(n00b_query_count(boosted_result) == 2);
    close_result_true(boosted_result);

    CHECK_CODE_ERR(n00b_query_view(store,
                                   level_error_filter(),
                                   .mode  = N00B_QUERY_MODE_LIVE,
                                   .as_of = &as_of),
                   N00B_QUERY_ERR_INVALID_OPTION);
    CHECK(active_pins(store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_query_spec_construction_and_list_copy();
    test_invalid_options();
    test_empty_result_and_close();
    test_snapshot_result_records_limit_and_resource_release();
    test_as_of_copy_snapshot_only_and_not_ready();

    n00b_shutdown();
    return 0;
}

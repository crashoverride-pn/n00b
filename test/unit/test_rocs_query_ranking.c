/* test/unit/test_rocs_query_ranking.c - WP-011 Phase 3 ranking. */

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
        auto _bl_query_rank_err_result = (expr);                               \
        CHECK(n00b_result_is_err(_bl_query_rank_err_result));                  \
        CHECK(n00b_result_get_err(_bl_query_rank_err_result) == (expected));   \
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
ranking_schema(void)
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
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"title",
        .index_kind     = N00B_STORE_INDEX_FULLTEXT,
        .include_in_all = true)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"body",
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
                                       ranking_schema());
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
           n00b_string_t *title,
           n00b_string_t *body,
           n00b_string_t *group)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    if (message != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"message",
                                  n00b_json_string_new_from_n00b(message));
    }
    if (title != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"title",
                                  n00b_json_string_new_from_n00b(title));
    }
    if (body != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"body",
                                  n00b_json_string_new_from_n00b(body));
    }
    if (group != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"group",
                                  n00b_json_string_new_from_n00b(group));
    }
    return record;
}

static void
ingest_record(n00b_store_t *store,
              int64_t       id,
              n00b_string_t *message,
              n00b_string_t *title,
              n00b_string_t *body)
{
    auto ingest_r = n00b_store_ingest(
        store,
        record_new(id, message, title, body, r"g"));
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
any_contains(n00b_string_t *term)
{
    return filter_ok(n00b_filter_contains(n00b_filter_any(), term));
}

static n00b_filter_t *
or2(n00b_filter_t *left, n00b_filter_t *right)
{
    return filter_ok(n00b_filter_or(left, right, kw_func(n00b_filter_or)));
}

static n00b_query_result_t *
run_ranked(n00b_store_t *store, n00b_filter_t *filter, uint64_t limit)
{
    n00b_query_t *query = query_ok(n00b_query_new(filter,
                                                  .ranked = true,
                                                  .limit  = limit));
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
    n00b_json_node_t *id_node =
        n00b_json_object_get(n00b_result_get(json_r), r"id");
    CHECK(id_node != nullptr);
    CHECK(n00b_json_type(id_node) == N00B_JSON_INT);
    return n00b_json_as_i64(id_node);
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
test_idf_order_and_multishard_record_count(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha common", nullptr, nullptr);
    ingest_record(store, 2, r"alpha", nullptr, nullptr);
    seal_current(store, 3101);
    ingest_record(store, 3, r"alpha", nullptr, nullptr);
    ingest_record(store, 4, r"alpha rare", nullptr, nullptr);
    seal_current(store, 3102);

    n00b_query_result_t *ranked = run_ranked(
        store,
        or2(contains(r"message", r"alpha"), contains(r"message", r"rare")),
        0);
    CHECK(n00b_query_count(ranked) == 4);
    CHECK(hit_id(hit_at(ranked, 0)) == 4);
    CHECK(hit_score(hit_at(ranked, 0)) > hit_score(hit_at(ranked, 1)));
    CHECK(hit_id(hit_at(ranked, 1)) == 1);
    CHECK(hit_id(hit_at(ranked, 2)) == 2);
    CHECK(hit_id(hit_at(ranked, 3)) == 3);
    close_result_true(ranked);

    n00b_query_result_t *rare =
        run_ranked(store, contains(r"message", r"rare"), 0);
    CHECK(n00b_query_count(rare) == 1);
    CHECK(hit_id(hit_at(rare, 0)) == 4);
    CHECK(hit_score(hit_at(rare, 0)) > 1.8);
    CHECK(hit_score(hit_at(rare, 0)) < 2.0);
    close_result_true(rare);
    CHECK(active_pins(store) == 0);
}

static void
test_field_boost_changes_order(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, nullptr, r"alpha", r"zzz");
    ingest_record(store, 2, nullptr, r"zzz", r"alpha");
    seal_current(store, 3201);

    n00b_query_boost_list_t *boosts = n00b_alloc(n00b_query_boost_list_t);
    *boosts = n00b_list_new_private(n00b_query_boost_t *,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    auto boost_r = n00b_query_boost(field_ok(r"title"), 4.0);
    CHECK(n00b_result_is_ok(boost_r));
    n00b_list_push(*boosts, n00b_result_get(boost_r));

    n00b_query_t *query = query_ok(n00b_query_new(
        or2(contains(r"title", r"alpha"), contains(r"body", r"alpha")),
        .ranked = true,
        .boosts = boosts,
        .limit  = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    CHECK(n00b_query_count(result) == 2);
    CHECK(hit_id(hit_at(result, 0)) == 1);
    CHECK(hit_id(hit_at(result, 1)) == 2);
    CHECK(hit_score(hit_at(result, 0)) > hit_score(hit_at(result, 1)));
    close_result_true(result);
}

static void
test_duplicate_occurrences_do_not_increase_score(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha alpha alpha", nullptr, nullptr);
    ingest_record(store, 2, r"alpha", nullptr, nullptr);
    seal_current(store, 3301);

    n00b_query_result_t *result =
        run_ranked(store, contains(r"message", r"alpha"), 0);
    CHECK(n00b_query_count(result) == 2);
    CHECK(hit_id(hit_at(result, 0)) == 1);
    CHECK(hit_id(hit_at(result, 1)) == 2);
    CHECK(approx(hit_score(hit_at(result, 0)),
                 hit_score(hit_at(result, 1)),
                 0.000001));
    close_result_true(result);
}

static void
test_catch_all_contains_scores_once(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, nullptr, r"alpha", r"none");
    ingest_record(store, 2, nullptr, r"none", r"alpha alpha");
    seal_current(store, 3401);

    n00b_query_result_t *result = run_ranked(store, any_contains(r"alpha"), 0);
    CHECK(n00b_query_count(result) == 2);
    CHECK(hit_id(hit_at(result, 0)) == 1);
    CHECK(hit_id(hit_at(result, 1)) == 2);
    CHECK(hit_score(hit_at(result, 0)) > 0.0);
    CHECK(approx(hit_score(hit_at(result, 0)),
                 hit_score(hit_at(result, 1)),
                 0.000001));
    close_result_true(result);
}

static void
test_non_scoreable_prefix_filters_without_scores(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha one", nullptr, nullptr);
    ingest_record(store, 2, r"alpha two", nullptr, nullptr);
    seal_current(store, 3501);

    n00b_query_result_t *result = run_ranked(
        store,
        filter_ok(n00b_filter_prefix(field_ok(r"message"), r"alpha")),
        0);
    CHECK(n00b_query_count(result) == 2);
    CHECK(hit_id(hit_at(result, 0)) == 1);
    CHECK(hit_id(hit_at(result, 1)) == 2);
    CHECK(hit_score(hit_at(result, 0)) == 0.0);
    CHECK(hit_score(hit_at(result, 1)) == 0.0);
    close_result_true(result);
}

static void
test_ranked_limit_applies_after_sort_and_close_invalidates(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", nullptr, nullptr);
    ingest_record(store, 2, r"alpha rare", nullptr, nullptr);
    ingest_record(store, 3, r"alpha", nullptr, nullptr);
    seal_current(store, 3601);

    n00b_query_result_t *result = run_ranked(
        store,
        or2(contains(r"message", r"alpha"), contains(r"message", r"rare")),
        1);
    CHECK(n00b_query_count(result) == 1);
    n00b_query_hit_t *hit = hit_at(result, 0);
    CHECK(hit_id(hit) == 2);
    CHECK(hit_score(hit) > 0.0);
    CHECK(active_pins(store) > 0);
    close_result_true(result);
    CHECK_CODE_ERR(n00b_query_hit_score(hit), N00B_QUERY_ERR_CLOSED);
    CHECK(active_pins(store) == 0);
}

static void
test_as_of_ranking_uses_visible_snapshot_counts(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", nullptr, nullptr);
    ingest_record(store, 2, r"later", nullptr, nullptr);
    ingest_record(store, 3, r"later", nullptr, nullptr);
    n00b_store_catalog_entry_t *entry = seal_current(store, 3651);

    n00b_store_pos_t as_of = entry_pos(entry, 0);
    n00b_query_t *query = query_ok(n00b_query_new(contains(r"message",
                                                           r"alpha"),
                                                  .ranked = true,
                                                  .as_of  = &as_of,
                                                  .limit  = 0));
    n00b_query_result_t *result = result_ok(n00b_query_run(store, query));
    CHECK(n00b_query_count(result) == 1);
    CHECK(hit_id(hit_at(result, 0)) == 1);
    CHECK(approx(hit_score(hit_at(result, 0)), 1.0, 0.000001));
    close_result_true(result);
    CHECK(active_pins(store) == 0);
}

static void
test_cursor_scores_stay_zero(void)
{
    n00b_store_t *store = open_store();
    ingest_record(store, 1, r"alpha", nullptr, nullptr);
    seal_current(store, 3701);

    n00b_filter_t *filter = contains(r"message", r"alpha");
    n00b_query_result_t *result = run_ranked(store, filter, 0);
    CHECK(hit_score(hit_at(result, 0)) > 0.0);
    close_result_true(result);

    auto view_r = n00b_query_view(store, filter);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(n00b_option_is_set(n00b_result_get(next_r)));
    CHECK(hit_score(n00b_option_get(n00b_result_get(next_r))) == 0.0);
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_idf_order_and_multishard_record_count();
    test_field_boost_changes_order();
    test_duplicate_occurrences_do_not_increase_score();
    test_catch_all_contains_scores_once();
    test_non_scoreable_prefix_filters_without_scores();
    test_ranked_limit_applies_after_sort_and_close_invalidates();
    test_as_of_ranking_uses_visible_snapshot_counts();
    test_cursor_scores_stay_zero();

    n00b_shutdown();
    return 0;
}

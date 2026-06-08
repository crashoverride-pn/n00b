/* test/unit/test_rocs_ranked_records.c - WP-011 Phase 4 ranked hits. */

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
        auto _bl_ranked_records_err_result = (expr);                           \
        CHECK(n00b_result_is_err(_bl_ranked_records_err_result));              \
        CHECK(n00b_result_get_err(_bl_ranked_records_err_result)               \
              == (expected));                                                  \
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
ranked_schema(void)
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
    return schema;
}

static n00b_store_t *
open_store(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       ranked_schema());
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
record_new(int64_t id, n00b_string_t *message)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record,
                              r"message",
                              n00b_json_string_new_from_n00b(message));
    return record;
}

static void
ingest_record(n00b_store_t *store, int64_t id, n00b_string_t *message)
{
    auto ingest_r = n00b_store_ingest(store, record_new(id, message));
    CHECK(n00b_result_is_ok(ingest_r));
}

static void
seal_current(n00b_store_t *store, uint64_t seal_ts)
{
    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
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

static n00b_query_result_t *
run_query(n00b_store_t *store, n00b_filter_t *filter, bool ranked)
{
    n00b_query_t *query = query_ok(n00b_query_new(filter,
                                                  .ranked = ranked,
                                                  .limit  = 0));
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
hit_at(n00b_query_hit_list_t *records, uint64_t index)
{
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
    n00b_json_node_t *json = n00b_result_get(json_r);
    CHECK(n00b_json_is_object(json));

    n00b_json_node_t *id = n00b_json_object_get(json, r"id");
    CHECK(id != nullptr);
    CHECK(n00b_json_is_int(id));
    return n00b_json_as_i64(id);
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

static void
check_hit_id(n00b_query_hit_t *hit, int64_t expected_id)
{
    CHECK(hit_id(hit) == expected_id);
}

static void
close_result_true(n00b_query_result_t *result)
{
    auto close_r = n00b_query_result_close(result);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
populate_ranked_sample(n00b_store_t *store)
{
    ingest_record(store, 1, r"alpha");
    ingest_record(store, 2, r"alpha rare");
    ingest_record(store, 3, r"alpha");
    seal_current(store, 4101);
}

static n00b_filter_t *
ranked_sample_filter(void)
{
    return or2(contains(r"message", r"alpha"), contains(r"message", r"rare"));
}

static void
check_ranked_sample_order(n00b_query_result_t *result)
{
    n00b_query_hit_list_t *records = records_ok(result);
    CHECK(n00b_list_len(*records) == 3);
    CHECK(hit_id(hit_at(records, 0)) == 2);
    CHECK(hit_id(hit_at(records, 1)) == 1);
    CHECK(hit_id(hit_at(records, 2)) == 3);
    CHECK(hit_score(hit_at(records, 0)) > hit_score(hit_at(records, 1)));
    CHECK(approx(hit_score(hit_at(records, 1)),
                 hit_score(hit_at(records, 2)),
                 0.000001));
}

static void
test_ranked_result_records_are_result_owned(void)
{
    n00b_store_t *store = open_store();
    populate_ranked_sample(store);

    n00b_filter_t       *filter = ranked_sample_filter();
    n00b_query_result_t *result = run_query(store, filter, true);
    CHECK(n00b_query_count(result) == 3);

    n00b_query_hit_list_t *primary = records_ok(result);
    n00b_query_hit_list_t *copy    = records_ok(result);
    CHECK(primary != copy);
    CHECK(n00b_list_len(*primary) == 3);
    CHECK(n00b_list_len(*copy) == 3);

    n00b_list_push(*primary, (n00b_query_hit_t *)nullptr);
    CHECK(n00b_list_len(*primary) == 4);
    CHECK(n00b_list_len(*copy) == 3);
    CHECK(n00b_list_len(*records_ok(result)) == 3);

    n00b_query_hit_t *first  = hit_at(copy, 0);
    n00b_query_hit_t *second = hit_at(copy, 1);
    n00b_query_hit_t *third  = hit_at(copy, 2);
    check_hit_id(first, 2);
    check_hit_id(second, 1);
    check_hit_id(third, 3);
    CHECK(hit_score(first) > hit_score(second));
    CHECK(approx(hit_score(second), hit_score(third), 0.000001));

    auto pos_r = n00b_query_hit_pos(first);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(active_pins(store) > 0);

    close_result_true(result);
    CHECK(active_pins(store) == 0);
    CHECK(n00b_list_len(*primary) == 4);
    CHECK(n00b_list_len(*copy) == 3);
    CHECK_CODE_ERR(n00b_query_hit_score(first), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_hit_record(first), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_hit_pos(first), N00B_QUERY_ERR_CLOSED);

    n00b_query_result_t *repeat = run_query(store, filter, true);
    check_ranked_sample_order(repeat);
    close_result_true(repeat);
}

static void
test_unranked_result_scores_zero_and_invalidate_on_close(void)
{
    n00b_store_t *store = open_store();
    populate_ranked_sample(store);

    n00b_query_result_t *result =
        run_query(store, contains(r"message", r"alpha"), false);
    CHECK(n00b_query_count(result) == 3);
    n00b_query_hit_list_t *records = records_ok(result);
    CHECK(n00b_list_len(*records) == 3);

    for (uint64_t i = 0; i < 3; i++) {
        n00b_query_hit_t *hit = hit_at(records, i);
        CHECK(hit_score(hit) == 0.0);
        check_hit_id(hit, (int64_t)i + 1);
    }

    n00b_query_hit_t *first = hit_at(records, 0);
    CHECK(active_pins(store) > 0);
    close_result_true(result);
    CHECK(active_pins(store) == 0);
    CHECK_CODE_ERR(n00b_query_hit_score(first), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_hit_record(first), N00B_QUERY_ERR_CLOSED);
}

static void
test_cursor_hits_are_borrowed_and_zero_scored(void)
{
    n00b_store_t *store = open_store();
    populate_ranked_sample(store);

    n00b_filter_t *filter = contains(r"message", r"alpha");
    auto view_r = n00b_query_view(store, filter);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    auto first_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(first_r));
    CHECK(n00b_option_is_set(n00b_result_get(first_r)));
    n00b_query_hit_t *first = n00b_option_get(n00b_result_get(first_r));
    CHECK(hit_score(first) == 0.0);
    check_hit_id(first, 1);

    auto second_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(second_r));
    CHECK(n00b_option_is_set(n00b_result_get(second_r)));
    n00b_query_hit_t *second = n00b_option_get(n00b_result_get(second_r));
    CHECK_CODE_ERR(n00b_query_hit_score(first), N00B_QUERY_ERR_CLOSED);
    CHECK(hit_score(second) == 0.0);
    check_hit_id(second, 2);

    auto close_cursor_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_cursor_r));
    CHECK(n00b_result_get(close_cursor_r));
    CHECK_CODE_ERR(n00b_query_hit_record(second), N00B_QUERY_ERR_CLOSED);

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

    test_ranked_result_records_are_result_owned();
    test_unranked_result_scores_zero_and_invalidate_on_close();
    test_cursor_hits_are_borrowed_and_zero_scored();

    n00b_shutdown();
    return 0;
}

/* test/unit/test_rocs_query_cursor.c - WP-008 Phase 2 cursor/hit behavior. */

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

#include "internal/rocs/index.h"
#include "internal/rocs/query.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_CODE_ERR(expr, expected)                                         \
    do {                                                                       \
        auto _bl_query_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_query_err_result));                       \
        CHECK(n00b_result_get_err(_bl_query_err_result) == (expected));        \
    } while (0)

typedef struct {
    n00b_store_t               *store;
    n00b_filter_t              *filter;
    n00b_store_catalog_entry_t *first;
    n00b_store_catalog_entry_t *second;
    n00b_store_pos_t            first_match;
    n00b_store_pos_t            second_first;
    n00b_store_pos_t            second_second;
} sample_store_t;

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

static n00b_filter_t *
error_filter(void)
{
    auto field_r = n00b_filter_field(r"level");
    CHECK(n00b_result_is_ok(field_r));

    auto filter_r = n00b_filter_eq(n00b_result_get(field_r),
                                   n00b_fv_utf8(r"error"));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
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

static sample_store_t
new_sample_store(void)
{
    sample_store_t sample = {};
    sample.store  = open_store(new_memory_vfs());
    sample.filter = error_filter();

    ingest_record(sample.store, 1, r"info");
    ingest_record(sample.store, 2, r"error");
    sample.first = seal_current(sample.store, 501);

    ingest_record(sample.store, 3, r"error");
    ingest_record(sample.store, 4, r"error");
    sample.second = seal_current(sample.store, 502);

    sample.first_match   = entry_pos(sample.first, 1);
    sample.second_first  = entry_pos(sample.second, 0);
    sample.second_second = entry_pos(sample.second, 1);
    return sample;
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static n00b_query_view_t *
view_ok(n00b_result_t(n00b_query_view_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_view_t *view = n00b_result_get(r);
    CHECK(view != nullptr);
    return view;
}

static n00b_query_cursor_t *
cursor_ok(n00b_result_t(n00b_query_cursor_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_cursor_t *cursor = n00b_result_get(r);
    CHECK(cursor != nullptr);
    return cursor;
}

static n00b_query_hit_t *
expect_hit(n00b_query_cursor_t *cursor,
           n00b_store_pos_t     expected,
           int64_t              expected_id,
           uint64_t             seal_ts)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
    CHECK(n00b_option_is_set(hit_opt));
    n00b_query_hit_t *hit = n00b_option_get(hit_opt);

    auto pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(pos_r));
    n00b_store_pos_t pos = n00b_result_get(pos_r);
    CHECK(n00b_store_pos_compare(pos, expected) == 0);
    CHECK(pos.generation != seal_ts);

    auto score_r = n00b_query_hit_score(hit);
    CHECK(n00b_result_is_ok(score_r));
    CHECK(n00b_result_get(score_r) == 0.0);

    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));
    n00b_store_record_t *record = n00b_result_get(record_r);

    auto record_pos_r = n00b_store_record_pos(record);
    CHECK(n00b_result_is_ok(record_pos_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(record_pos_r), expected) == 0);

    auto json_r = n00b_store_record_view_json(record);
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *json = n00b_result_get(json_r);
    CHECK(n00b_json_is_object(json));

    n00b_json_node_t *id = n00b_json_object_get(json, r"id");
    CHECK(id != nullptr);
    CHECK(n00b_json_is_int(id));
    CHECK(n00b_json_as_i64(id) == expected_id);

    auto cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
    CHECK(n00b_store_pos_compare(n00b_option_get(n00b_result_get(cursor_pos_r)),
                                 expected) == 0);

    return hit;
}

static void
expect_none(n00b_query_cursor_t *cursor)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));
}

static void
close_cursor_true(n00b_query_cursor_t *cursor)
{
    auto close_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
close_view_true(n00b_query_view_t *view)
{
    auto close_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
test_order_filter_later_commit_and_pin_lifetime(void)
{
    sample_store_t sample = new_sample_store();
    CHECK(active_pins(sample.store) == 0);

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    CHECK(active_pins(sample.store) == 1);

    ingest_record(sample.store, 5, r"error");
    seal_current(sample.store, 503);

    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));
    CHECK(active_pins(sample.store) == 1);

    n00b_query_hit_t *first =
        expect_hit(cursor, sample.first_match, 2, 501);
    CHECK(active_pins(sample.store) == 2);
    n00b_query_hit_t *second =
        expect_hit(cursor, sample.second_first, 3, 502);
    CHECK(active_pins(sample.store) == 3);
    CHECK_CODE_ERR(n00b_query_hit_pos(first), N00B_QUERY_ERR_CLOSED);

    n00b_query_hit_t *third =
        expect_hit(cursor, sample.second_second, 4, 502);
    CHECK_CODE_ERR(n00b_query_hit_record(second), N00B_QUERY_ERR_CLOSED);

    expect_none(cursor);
    CHECK_CODE_ERR(n00b_query_hit_score(third), N00B_QUERY_ERR_CLOSED);

    auto pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(pos_r)));
    CHECK(n00b_store_pos_compare(n00b_option_get(n00b_result_get(pos_r)),
                                 sample.second_second) == 0);

    close_cursor_true(cursor);
    CHECK(active_pins(sample.store) == 1);
    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_limit_resume_as_of_and_empty_window(void)
{
    sample_store_t sample = new_sample_store();

    n00b_query_view_t *limited = view_ok(n00b_query_view(sample.store,
                                                         sample.filter,
                                                         .limit = 2));
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(limited));
    expect_hit(cursor, sample.first_match, 2, 501);
    expect_hit(cursor, sample.second_first, 3, 502);
    expect_none(cursor);
    close_cursor_true(cursor);
    close_view_true(limited);

    n00b_store_pos_t resume = sample.first_match;
    n00b_query_view_t *resumed = view_ok(n00b_query_view(sample.store,
                                                         sample.filter,
                                                         .resume = &resume));
    cursor = cursor_ok(n00b_query_cursor(resumed));
    expect_hit(cursor, sample.second_first, 3, 502);
    expect_hit(cursor, sample.second_second, 4, 502);
    expect_none(cursor);
    close_cursor_true(cursor);
    close_view_true(resumed);

    n00b_store_pos_t as_of = sample.second_first;
    n00b_query_view_t *bounded = view_ok(n00b_query_view(sample.store,
                                                         sample.filter,
                                                         .as_of = &as_of));
    cursor = cursor_ok(n00b_query_cursor(bounded));
    expect_hit(cursor, sample.first_match, 2, 501);
    expect_hit(cursor, sample.second_first, 3, 502);
    expect_none(cursor);
    close_cursor_true(cursor);
    close_view_true(bounded);

    n00b_store_pos_t empty_resume = sample.second_second;
    n00b_store_pos_t empty_as_of  = sample.second_first;
    n00b_query_view_t *empty = view_ok(n00b_query_view(sample.store,
                                                       sample.filter,
                                                       .resume = &empty_resume,
                                                       .as_of = &empty_as_of));
    cursor = cursor_ok(n00b_query_cursor(empty));
    auto pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(!n00b_option_is_set(n00b_result_get(pos_r)));
    expect_none(cursor);
    close_cursor_true(cursor);
    close_view_true(empty);

    CHECK(active_pins(sample.store) == 0);
}

static void
test_cursor_and_view_close_invalidation(void)
{
    sample_store_t sample = new_sample_store();

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));
    n00b_query_hit_t *hit = expect_hit(cursor, sample.first_match, 2, 501);

    close_cursor_true(cursor);
    CHECK(active_pins(sample.store) == 1);
    CHECK_CODE_ERR(n00b_query_hit_pos(hit), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_cursor_next(cursor), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_cursor_position(cursor), N00B_QUERY_ERR_CLOSED);
    auto cursor_again_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(cursor_again_r));
    CHECK(!n00b_result_get(cursor_again_r));
    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);

    view = view_ok(n00b_query_view(sample.store, sample.filter));
    cursor = cursor_ok(n00b_query_cursor(view));
    hit = expect_hit(cursor, sample.first_match, 2, 501);
    CHECK(active_pins(sample.store) == 2);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
    CHECK_CODE_ERR(n00b_query_hit_record(hit), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_cursor_next(cursor), N00B_QUERY_ERR_CLOSED);
    cursor_again_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(cursor_again_r));
    CHECK(!n00b_result_get(cursor_again_r));

    auto view_again_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(view_again_r));
    CHECK(!n00b_result_get(view_again_r));
}

static void
expect_cursor_retention_payload(n00b_result_t(n00b_query_cursor_t *) r,
                                n00b_store_pos_t                    requested,
                                uint64_t                            oldest_shard)
{
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));
    n00b_query_retention_error_t *payload =
        n00b_result_get_err_payload(n00b_query_retention_error_t *, r);

    auto code_r = n00b_query_retention_error_code(payload);
    CHECK(n00b_result_is_ok(code_r));
    CHECK(n00b_result_get(code_r) == N00B_QUERY_ERR_RETENTION);

    auto boundary_r = n00b_query_retention_error_boundary(payload);
    CHECK(n00b_result_is_ok(boundary_r));
    CHECK(n00b_result_get(boundary_r) == N00B_QUERY_BOUNDARY_SNAPSHOT);

    auto requested_r = n00b_query_retention_error_requested(payload);
    CHECK(n00b_result_is_ok(requested_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(requested_r),
                                 requested) == 0);

    auto oldest_r = n00b_query_retention_error_oldest_available(payload);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    CHECK(n00b_option_get(n00b_result_get(oldest_r)).shard_id
          == oldest_shard);
}

static void
test_dropped_boundary_cursor_failure_releases_pins(void)
{
    sample_store_t sample = new_sample_store();
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    CHECK(active_pins(sample.store) == 1);

    auto drop_r = n00b_store_drop_sealed_shard(sample.store,
                                               entry_shard_id(sample.first));
    CHECK(n00b_result_is_ok(drop_r));

    expect_cursor_retention_payload(n00b_query_cursor(view),
                                    entry_pos(sample.first, 0),
                                    entry_shard_id(sample.second));
    CHECK(active_pins(sample.store) == 1);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_order_filter_later_commit_and_pin_lifetime();
    test_limit_resume_as_of_and_empty_window();
    test_cursor_and_view_close_invalidation();
    test_dropped_boundary_cursor_failure_releases_pins();

    n00b_shutdown();
    return 0;
}

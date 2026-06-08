/* test/unit/test_rocs_query_resume.c - WP-008 Phase 4 resume hardening. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
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

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal query handoffs must not include planner declarations"
#endif

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
    n00b_store_catalog_entry_t *third;
    n00b_store_pos_t            first_first;
    n00b_store_pos_t            first_second;
    n00b_store_pos_t            second_first;
    n00b_store_pos_t            second_second;
    n00b_store_pos_t            third_first;
} resume_sample_t;

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
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs-resume", new_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_new(int64_t id, n00b_string_t *level)
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
    auto ingest_r = n00b_store_ingest(store, record_new(id, level));
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

static n00b_filter_t *
exists_id_filter(void)
{
    auto field_r = n00b_filter_field(r"id");
    CHECK(n00b_result_is_ok(field_r));

    auto filter_r = n00b_filter_exists(n00b_result_get(field_r));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static resume_sample_t
new_resume_sample(void)
{
    resume_sample_t sample = {};
    sample.store  = open_store(new_memory_vfs());
    sample.filter = exists_id_filter();

    ingest_record(sample.store, 1, r"error");
    ingest_record(sample.store, 2, r"error");
    sample.first = seal_current(sample.store, 801);

    ingest_record(sample.store, 3, r"error");
    ingest_record(sample.store, 4, r"error");
    sample.second = seal_current(sample.store, 802);

    ingest_record(sample.store, 5, r"error");
    sample.third = seal_current(sample.store, 803);

    sample.first_first   = entry_pos(sample.first, 0);
    sample.first_second  = entry_pos(sample.first, 1);
    sample.second_first  = entry_pos(sample.second, 0);
    sample.second_second = entry_pos(sample.second, 1);
    sample.third_first   = entry_pos(sample.third, 0);
    return sample;
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
check_position(n00b_store_pos_t actual, n00b_store_pos_t expected)
{
    CHECK(n00b_store_pos_compare(actual, expected) == 0);
}

static void
check_upper_bound(n00b_query_view_t *view, n00b_store_pos_t expected)
{
    auto upper_r = n00b_query_view_snapshot_upper_bound(view);
    CHECK(n00b_result_is_ok(upper_r));
    CHECK(n00b_option_is_set(n00b_result_get(upper_r)));
    check_position(n00b_option_get(n00b_result_get(upper_r)), expected);
}

static void
check_upper_bound_none(n00b_query_view_t *view)
{
    auto upper_r = n00b_query_view_snapshot_upper_bound(view);
    CHECK(n00b_result_is_ok(upper_r));
    CHECK(!n00b_option_is_set(n00b_result_get(upper_r)));
}

static void
expect_cursor_positions(n00b_query_view_t *view,
                        n00b_store_pos_t  *expected,
                        uint64_t           count)
{
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));

    for (uint64_t i = 0; i < count; i++) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        CHECK(n00b_option_is_set(hit_opt));

        auto pos_r = n00b_query_hit_pos(n00b_option_get(hit_opt));
        CHECK(n00b_result_is_ok(pos_r));
        check_position(n00b_result_get(pos_r), expected[i]);

        auto cursor_pos_r = n00b_query_cursor_position(cursor);
        CHECK(n00b_result_is_ok(cursor_pos_r));
        CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
        check_position(n00b_option_get(n00b_result_get(cursor_pos_r)),
                       expected[i]);
    }

    auto none_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    if (count != 0) {
        auto pos_r = n00b_query_cursor_position(cursor);
        CHECK(n00b_result_is_ok(pos_r));
        CHECK(n00b_option_is_set(n00b_result_get(pos_r)));
        check_position(n00b_option_get(n00b_result_get(pos_r)),
                       expected[count - 1]);
    }

    close_cursor_true(cursor);
}

static void
expect_empty_cursor(n00b_query_view_t *view)
{
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));
    auto pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(!n00b_option_is_set(n00b_result_get(pos_r)));

    auto none_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(!n00b_option_is_set(n00b_result_get(pos_r)));
    close_cursor_true(cursor);
}

static void
expect_view_retention_payload(n00b_result_t(n00b_query_view_t *) r,
                              n00b_query_boundary_kind_t         boundary,
                              n00b_store_pos_t                   requested,
                              n00b_store_pos_t                   oldest)
{
    CHECK(n00b_result_is_err(r));
    n00b_result_error_t carrier = n00b_result_get_error(r);
    CHECK(carrier.kind == N00B_RESULT_ERROR_PAYLOAD);
    CHECK(carrier.payload_type == typehash(n00b_query_retention_error_t *));
    CHECK(carrier.payload != nullptr);
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));

    n00b_query_retention_error_t *payload =
        n00b_result_get_err_payload(n00b_query_retention_error_t *, r);

    auto code_r = n00b_query_retention_error_code(payload);
    CHECK(n00b_result_is_ok(code_r));
    CHECK(n00b_result_get(code_r) == N00B_QUERY_ERR_RETENTION);

    auto boundary_r = n00b_query_retention_error_boundary(payload);
    CHECK(n00b_result_is_ok(boundary_r));
    CHECK(n00b_result_get(boundary_r) == boundary);

    auto requested_r = n00b_query_retention_error_requested(payload);
    CHECK(n00b_result_is_ok(requested_r));
    check_position(n00b_result_get(requested_r), requested);

    auto oldest_r = n00b_query_retention_error_oldest_available(payload);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    check_position(n00b_option_get(n00b_result_get(oldest_r)), oldest);
}

static void
expect_cursor_retention_payload(n00b_result_t(n00b_query_cursor_t *) r,
                                n00b_store_pos_t                    requested,
                                n00b_store_pos_t                    oldest)
{
    CHECK(n00b_result_is_err(r));
    n00b_result_error_t carrier = n00b_result_get_error(r);
    CHECK(carrier.kind == N00B_RESULT_ERROR_PAYLOAD);
    CHECK(carrier.payload_type == typehash(n00b_query_retention_error_t *));
    CHECK(carrier.payload != nullptr);
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));

    n00b_query_retention_error_t *payload =
        n00b_result_get_err_payload(n00b_query_retention_error_t *, r);

    auto boundary_r = n00b_query_retention_error_boundary(payload);
    CHECK(n00b_result_is_ok(boundary_r));
    CHECK(n00b_result_get(boundary_r) == N00B_QUERY_BOUNDARY_SNAPSHOT);

    auto requested_r = n00b_query_retention_error_requested(payload);
    CHECK(n00b_result_is_ok(requested_r));
    check_position(n00b_result_get(requested_r), requested);

    auto oldest_r = n00b_query_retention_error_oldest_available(payload);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    check_position(n00b_option_get(n00b_result_get(oldest_r)), oldest);
}

static void
test_as_of_boundaries_and_hot_exclusion(void)
{
    resume_sample_t sample = new_resume_sample();
    ingest_record(sample.store, 6, r"error");

    n00b_store_pos_t first_window[] = {
        sample.first_first,
        sample.first_second,
    };
    n00b_store_pos_t as_of = sample.first_second;
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter,
                                                      .as_of = &as_of));
    check_upper_bound(view, sample.first_second);
    expect_cursor_positions(view, first_window, 2);
    close_view_true(view);

    n00b_store_pos_t through_second_boundary[] = {
        sample.first_first,
        sample.first_second,
        sample.second_first,
    };
    as_of = sample.second_first;
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .as_of = &as_of));
    check_upper_bound(view, sample.second_first);
    expect_cursor_positions(view, through_second_boundary, 3);
    close_view_true(view);

    n00b_store_pos_t all_sealed[] = {
        sample.first_first,
        sample.first_second,
        sample.second_first,
        sample.second_second,
        sample.third_first,
    };
    as_of = sample.third_first;
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .as_of = &as_of));
    check_upper_bound(view, sample.third_first);
    expect_cursor_positions(view, all_sealed, 5);
    close_view_true(view);

    CHECK(active_pins(sample.store) == 0);
}

static void
test_resume_exact_after_boundaries(void)
{
    resume_sample_t sample = new_resume_sample();
    n00b_store_pos_t expected_all[] = {
        sample.first_first,
        sample.first_second,
        sample.second_first,
        sample.second_second,
        sample.third_first,
    };

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    expect_cursor_positions(view, expected_all, 5);
    close_view_true(view);

    n00b_store_pos_t resume = sample.first_first;
    n00b_store_pos_t after_matching_hit[] = {
        sample.first_second,
        sample.second_first,
        sample.second_second,
        sample.third_first,
    };
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .resume = &resume));
    expect_cursor_positions(view, after_matching_hit, 4);
    close_view_true(view);

    resume = sample.first_second;
    n00b_store_pos_t after_first_shard[] = {
        sample.second_first,
        sample.second_second,
        sample.third_first,
    };
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .resume = &resume));
    expect_cursor_positions(view, after_first_shard, 3);
    close_view_true(view);

    resume = sample.second_first;
    n00b_store_pos_t after_boundary_crossed[] = {
        sample.second_second,
        sample.third_first,
    };
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .resume = &resume));
    expect_cursor_positions(view, after_boundary_crossed, 2);
    close_view_true(view);

    resume = sample.third_first;
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .resume = &resume));
    expect_empty_cursor(view);
    close_view_true(view);

    CHECK(active_pins(sample.store) == 0);
}

static void
test_retention_payloads_preserve_carrier(void)
{
    resume_sample_t sample = new_resume_sample();
    n00b_store_pos_t stale = sample.first_first;

    auto drop_r = n00b_store_drop_sealed_shard(sample.store,
                                               entry_shard_id(sample.first));
    CHECK(n00b_result_is_ok(drop_r));
    expect_view_retention_payload(n00b_query_view(sample.store,
                                                  sample.filter,
                                                  .resume = &stale),
                                  N00B_QUERY_BOUNDARY_RESUME,
                                  stale,
                                  sample.second_first);
    CHECK(active_pins(sample.store) == 0);

    sample = new_resume_sample();
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    CHECK(active_pins(sample.store) == 1);
    drop_r = n00b_store_drop_sealed_shard(sample.store,
                                          entry_shard_id(sample.first));
    CHECK(n00b_result_is_ok(drop_r));
    expect_cursor_retention_payload(n00b_query_cursor(view),
                                    sample.first_first,
                                    sample.second_first);
    CHECK(active_pins(sample.store) == 1);
    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_cursor_position_and_handoff_helpers_do_not_advance(void)
{
    resume_sample_t sample = new_resume_sample();
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));

    auto count_r = n00b_query_cursor_hit_count(cursor);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 5);

    auto cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(!n00b_option_is_set(n00b_result_get(cursor_pos_r)));

    auto at_r = n00b_query_cursor_hit_position_at(cursor, 2);
    CHECK(n00b_result_is_ok(at_r));
    CHECK(n00b_option_is_set(n00b_result_get(at_r)));
    check_position(n00b_option_get(n00b_result_get(at_r)),
                   sample.second_first);

    cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(!n00b_option_is_set(n00b_result_get(cursor_pos_r)));

    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(n00b_option_is_set(n00b_result_get(next_r)));
    auto hit_pos_r = n00b_query_hit_pos(n00b_option_get(n00b_result_get(next_r)));
    CHECK(n00b_result_is_ok(hit_pos_r));
    check_position(n00b_result_get(hit_pos_r), sample.first_first);

    cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
    check_position(n00b_option_get(n00b_result_get(cursor_pos_r)),
                   sample.first_first);

    at_r = n00b_query_cursor_hit_position_at(cursor, 4);
    CHECK(n00b_result_is_ok(at_r));
    CHECK(n00b_option_is_set(n00b_result_get(at_r)));
    check_position(n00b_option_get(n00b_result_get(at_r)),
                   sample.third_first);

    cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
    check_position(n00b_option_get(n00b_result_get(cursor_pos_r)),
                   sample.first_first);

    at_r = n00b_query_cursor_hit_position_at(cursor, 99);
    CHECK(n00b_result_is_ok(at_r));
    CHECK(!n00b_option_is_set(n00b_result_get(at_r)));

    n00b_store_pos_t expected_tail[] = {
        sample.first_second,
        sample.second_first,
        sample.second_second,
        sample.third_first,
    };
    for (uint64_t i = 0; i < 4; i++) {
        next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        CHECK(n00b_option_is_set(n00b_result_get(next_r)));
        hit_pos_r = n00b_query_hit_pos(n00b_option_get(n00b_result_get(next_r)));
        CHECK(n00b_result_is_ok(hit_pos_r));
        check_position(n00b_result_get(hit_pos_r), expected_tail[i]);
    }

    next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));

    cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
    check_position(n00b_option_get(n00b_result_get(cursor_pos_r)),
                   sample.third_first);

    close_cursor_true(cursor);
    CHECK_CODE_ERR(n00b_query_cursor_position(cursor), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_cursor_hit_count(cursor),
                   N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_cursor_hit_position_at(cursor, 0),
                   N00B_QUERY_ERR_CLOSED);
    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_snapshot_upper_bound_uses_copied_boundary_only(void)
{
    resume_sample_t sample = new_resume_sample();
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    check_upper_bound(view, sample.third_first);
    CHECK(active_pins(sample.store) == 1);

    auto drop_r = n00b_store_drop_sealed_shard(sample.store,
                                               entry_shard_id(sample.third));
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(active_pins(sample.store) == 1);
    check_upper_bound(view, sample.third_first);
    CHECK(active_pins(sample.store) == 1);
    close_view_true(view);

    n00b_store_pos_t empty_resume = sample.second_second;
    n00b_store_pos_t empty_as_of  = sample.second_first;
    view = view_ok(n00b_query_view(sample.store,
                                   sample.filter,
                                   .resume = &empty_resume,
                                   .as_of = &empty_as_of));
    check_upper_bound_none(view);
    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_as_of_boundaries_and_hot_exclusion();
    test_resume_exact_after_boundaries();
    test_retention_payloads_preserve_carrier();
    test_cursor_position_and_handoff_helpers_do_not_advance();
    test_snapshot_upper_bound_uses_copied_boundary_only();

    n00b_shutdown();
    return 0;
}

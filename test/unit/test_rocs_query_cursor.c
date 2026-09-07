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
    n00b_vfs_t                 *vfs;
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

static void
write_vfs_string(n00b_vfs_t *vfs, n00b_string_t *path, n00b_string_t *data)
{
    auto open_r = n00b_vfs_open(vfs, path, N00B_VFS_O_W);
    CHECK(n00b_result_is_ok(open_r));

    n00b_buffer_t *buf = n00b_buffer_from_bytes(data->data,
                                                (int64_t)data->u8_bytes);
    auto write_r = n00b_vfs_write(vfs, n00b_result_get(open_r), buf);
    CHECK(n00b_result_is_ok(write_r));
    CHECK(n00b_result_get(write_r) == data->u8_bytes);

    auto close_r = n00b_vfs_close(vfs, n00b_result_get(open_r));
    CHECK(n00b_result_is_ok(close_r));
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
    sample.vfs    = new_memory_vfs();
    sample.store  = open_store(sample.vfs);
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

    auto copy_r = n00b_query_hit_json_copy(hit);
    CHECK(n00b_result_is_ok(copy_r));
    n00b_json_node_t *copy = n00b_result_get(copy_r);
    CHECK(n00b_json_is_object(copy));
    n00b_json_node_t *copy_id = n00b_json_object_get(copy, r"id");
    CHECK(copy_id != nullptr);
    CHECK(n00b_json_is_int(copy_id));
    CHECK(n00b_json_as_i64(copy_id) == expected_id);

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
test_open_view_blocks_boundary_drop_until_close(void)
{
    sample_store_t sample = new_sample_store();
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter));
    CHECK(active_pins(sample.store) == 1);

    auto drop_r = n00b_store_drop_sealed_shard(sample.store,
                                               entry_shard_id(sample.first));
    CHECK(n00b_result_is_err(drop_r));
    CHECK(n00b_result_get_err(drop_r) == N00B_STORE_ERR_PINNED);

    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));
    expect_hit(cursor, sample.first_match, 2, 501);
    close_cursor_true(cursor);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);

    drop_r = n00b_store_drop_sealed_shard(sample.store,
                                          entry_shard_id(sample.first));
    CHECK(n00b_result_is_ok(drop_r));
}

static void
test_corrupt_skipped_shard_does_not_block_resume_window(void)
{
    sample_store_t sample = new_sample_store();

    auto path_r = n00b_store_catalog_entry_get_object_path(sample.first);
    CHECK(n00b_result_is_ok(path_r));
    write_vfs_string(sample.vfs, n00b_result_get(path_r), r"bad");

    auto verify_r = n00b_store_catalog_entry_verify_object(sample.store,
                                                           sample.first);
    CHECK(n00b_result_is_err(verify_r));
    CHECK(n00b_result_get_err(verify_r) == N00B_STORE_ERR_CORRUPT);

    n00b_store_pos_t resume = sample.first_match;

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      sample.filter,
                                                      .resume = &resume));
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));
    n00b_query_cursor_set_streaming(cursor, true);
    expect_hit(cursor, sample.second_first, 3, 502);
    expect_hit(cursor, sample.second_second, 4, 502);
    expect_none(cursor);
    close_cursor_true(cursor);
    close_view_true(view);

    auto stream_r = n00b_store_record_stream_open(sample.store, &resume);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    auto next_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(n00b_option_is_set(n00b_result_get(next_r)));
    n00b_store_record_stream_item_t item = n00b_option_get(n00b_result_get(next_r));
    CHECK(n00b_store_pos_compare(item.pos, sample.second_first) == 0);
    CHECK(item.bytes.data != nullptr);
    CHECK(item.bytes.byte_len > 0);

    auto close_r = n00b_store_record_stream_close(stream);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

// #251. N00B_QUERY_ERR_EXECUTION (-8) collapses eight distinct errors. #254
// recorded the underlying error and #256 tagged it with its enum, but nothing
// read either, so the operator-visible symptom was unchanged: -8 in a log with
// the cause discarded. This asserts the detail is actually usable -- that two
// different underlying failures are distinguishable through the public API,
// and that the rendered form names the enum it came from.
//
// Uses only <rocs/query.h>, deliberately: if the detail is not reachable from
// the public surface, it does not help the gateway that reports -8.
static void
test_execution_detail_distinguishes_causes(void)
{
    // A store-sourced detail and a plan-sourced detail must not render the
    // same, even when the raw codes collide. That collision is real:
    // N00B_PLAN_ERR_CANCELED and N00B_STORE_ERR_VFS are both -7.
    n00b_query_execution_detail_t store_detail = {
        .source = N00B_QUERY_DETAIL_STORE,
        .err    = (n00b_err_t)-7,
    };
    n00b_query_execution_detail_t plan_detail = {
        .source = N00B_QUERY_DETAIL_PLAN,
        .err    = (n00b_err_t)-7,
    };

    n00b_string_t *store_str = n00b_query_execution_detail_str(store_detail);
    n00b_string_t *plan_str  = n00b_query_execution_detail_str(plan_detail);

    CHECK(store_str != NULL);
    CHECK(plan_str != NULL);

    // The whole point of #256: same numeric code, different meaning, and the
    // rendered form has to say which.
    CHECK(!n00b_unicode_str_eq(store_str, plan_str));
    CHECK(n00b_unicode_str_starts_with(store_str, r"store:"));
    CHECK(n00b_unicode_str_starts_with(plan_str, r"plan:"));

    // A thread that has seen no execution failure renders as "none" rather
    // than as a misleading code-zero.
    n00b_query_execution_detail_t empty = {
        .source = N00B_QUERY_DETAIL_NONE,
        .err    = 0,
    };
    CHECK(n00b_unicode_str_eq(n00b_query_execution_detail_str(empty), r"none"));

    // The accessor is reachable from the public header and safe to call
    // before any failure has occurred.
    n00b_query_execution_detail_t current = n00b_query_execution_detail();
    CHECK(n00b_query_execution_detail_str(current) != NULL);

    printf("  [PASS] execution detail distinguishes store vs plan (#251)\n");
}

// ---------------------------------------------------------------------------
// n00b#255: the SNAPSHOT path must be cancellable.
//
// rocs's service handler holds ONE global store_mutex across the whole of
// n00b_query_run: scan, ranking, record materialization, response
// serialization and the residency trim. So an unbounded query does not merely
// run long, it blocks every other query, both ingest handlers, /v1/flush and
// /v1/status. The measured field signature was exactly that: GET /v1/query 200
// in 0.21s (never reaches the locked section), POST /v1/query hanging, GET
// /v1/sessions fast because it takes the mutex zero times.
//
// The defect was NOT a missing mechanism. rocs_query_run_records and
// rocs_query_run_aggregate are both implemented on n00b_query_cursor, which has
// always accepted .cancel_cb/.cancel_ctx and polls it every 1024 ordinals
// during a boundary scan, threading it into n00b_plan_catalog_entry_sealed.
// Both call sites built that cursor with .allocator ALONE, so every one of
// those polls was a no-op and the hook was unreachable from n00b_query_run.
//
// That is what makes this a regression test rather than a feature test: before
// the fix these cases return Ok having scanned everything, because the cancel
// predicate is never consulted. Restore the two-argument cursor construction
// and they go red.
// ---------------------------------------------------------------------------

// One sealed shard holding several times the 1024-ordinal poll cadence. A
// single boundary is the point: with only one, a poll count above the number
// of distinct entry polls can only have come from a loop INSIDE the scan, so
// the test can tell interior polling from a check on the way in without
// knowing where the poll sites are.
#define CANCEL_PROBE_RECORDS 4096

typedef struct {
    uint64_t polls;
    uint64_t cancel_after;
} cancel_probe_t;

// Returns true once it has been consulted `cancel_after` times, so the same
// probe expresses "give up immediately" (0) and "give up after n polls", and
// doubles as a counter proving the hook was reached at all.
static bool
cancel_after_n_polls(void *ctx)
{
    cancel_probe_t *probe = (cancel_probe_t *)ctx;
    return probe->polls++ >= probe->cancel_after;
}

static n00b_store_t *
cancel_probe_store(n00b_vfs_t *vfs)
{
    n00b_store_t *store = open_store(vfs);

    for (int64_t i = 0; i < CANCEL_PROBE_RECORDS; i++) {
        ingest_record(store, i, r"error");
    }
    seal_current(store, 2550);

    return store;
}

// Ranking only extracts terms from CONTAINS leaves, so an eq filter would skip
// the scoring loop entirely and leave the phase this exercises untested.
static n00b_filter_t *
error_contains_filter(void)
{
    auto field_r = n00b_filter_field(r"level");
    CHECK(n00b_result_is_ok(field_r));

    auto filter_r = n00b_filter_contains(n00b_result_get(field_r), r"error");
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static void
test_snapshot_query_honours_cancellation(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = cancel_probe_store(vfs);

    n00b_filter_t *filter = error_filter();

    // ---- 1. Cancel immediately: the query must report CANCELED, not Ok.
    cancel_probe_t immediate = {.polls = 0, .cancel_after = 0};
    auto q1_r = n00b_query_new(filter,
                               .limit      = 0,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &immediate);
    CHECK(n00b_result_is_ok(q1_r));

    auto r1 = n00b_query_run(store, n00b_result_get(q1_r));
    CHECK(n00b_result_is_err(r1));
    CHECK(n00b_result_get_err(r1) == N00B_QUERY_ERR_CANCELED);
    // The hook was actually consulted. Without this a null-hook regression
    // that happened to error for another reason would still pass above.
    CHECK(immediate.polls > 0);
    printf("  [PASS] snapshot query cancels, polls=%llu (#255)\n",
           (unsigned long long)immediate.polls);

    // ---- 2. Measure a COMPLETE scan. This is both the control (an
    // uncancelled query still answers) and the calibration for case 3: the
    // threshold there is derived from what this scan actually polls rather
    // than hardcoded, so sealing cadence or poll placement can change without
    // making the next case fail for an unrelated reason.
    cancel_probe_t full = {.polls = 0, .cancel_after = UINT64_MAX};
    auto q2_r = n00b_query_new(filter,
                               .limit      = 0,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &full);
    CHECK(n00b_result_is_ok(q2_r));

    auto r2 = n00b_query_run(store, n00b_result_get(q2_r));
    CHECK(n00b_result_is_ok(r2));
    n00b_query_result_t *complete = n00b_result_get(r2);
    CHECK(n00b_query_count(complete) == CANCEL_PROBE_RECORDS);
    CHECK(n00b_result_is_ok(n00b_query_result_close(complete)));

    // The store is one boundary, so a handful of polls cannot be explained by
    // per-boundary entry checks; they come from the 1024-step loops inside the
    // scan. This is the assertion that the hook is live DURING execution.
    CHECK(full.polls > 4);
    printf("  [PASS] full scan polls %llu times over one boundary (#255)\n",
           (unsigned long long)full.polls);

    // ---- 3. Cancel mid-scan. Half of a measured full scan is unambiguously
    // inside it: past the first poll, well short of the last.
    cancel_probe_t midway = {.polls = 0, .cancel_after = full.polls / 2};
    auto q3_r = n00b_query_new(filter,
                               .limit      = 0,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &midway);
    CHECK(n00b_result_is_ok(q3_r));

    auto r3 = n00b_query_run(store, n00b_result_get(q3_r));
    CHECK(n00b_result_is_err(r3));
    CHECK(n00b_result_get_err(r3) == N00B_QUERY_ERR_CANCELED);
    CHECK(midway.polls > 1);
    CHECK(midway.polls < full.polls);
    printf("  [PASS] snapshot query cancels mid-scan at poll %llu of %llu"
           " (#255)\n",
           (unsigned long long)midway.polls,
           (unsigned long long)full.polls);

    // ---- 4. CONTROL. No hook at all must still answer normally. Without this
    // the cases above are satisfied by a query that is simply broken, which is
    // the failure mode this whole file exists to avoid.
    auto q4_r = n00b_query_new(filter, .limit = 0);
    CHECK(n00b_result_is_ok(q4_r));

    auto r4 = n00b_query_run(store, n00b_result_get(q4_r));
    CHECK(n00b_result_is_ok(r4));
    n00b_query_result_t *ok = n00b_result_get(r4);
    CHECK(n00b_query_count(ok) == CANCEL_PROBE_RECORDS);
    CHECK(n00b_result_is_ok(n00b_query_result_close(ok)));
    printf("  [PASS] uncancelled query still answers (#255 control)\n");

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

// The HOT shard is the other half of n00b#255, and the one a live service hits
// most: its most recent records have not been sealed yet.
//
// n00b_store_hot_tail_scan_after runs the whole scan and returns every match
// before the caller sees one, so the cursor's per-match poll cannot bound it.
// Polling only what the scan returns leaves the scan itself uninterruptible,
// which for a hot shard is where nearly all of the time goes: measured over
// the service, a 4000-record hot query spent about 1.6s scanning and under
// 100ms emitting.
//
// The scan already had somewhere to poll. n00b_plan_exec_hot takes a cancel
// hook and the tail scan simply did not pass one, the same omission this issue
// started from one layer up.
//
// The assertion is a count, not a clock. With CANCEL_PROBE_RECORDS matches the
// emission loop polls every 1024, so it alone can produce exactly four. Any
// more than that came from inside the scan.
#define CANCEL_PROBE_EMIT_POLLS (CANCEL_PROBE_RECORDS / 1024)

static n00b_store_t *
cancel_probe_hot_store(n00b_vfs_t *vfs)
{
    n00b_store_t *store = open_store(vfs);

    // Deliberately not sealed: this must stay the hot path.
    for (int64_t i = 0; i < CANCEL_PROBE_RECORDS; i++) {
        ingest_record(store, i, r"error");
    }

    return store;
}

static void
test_hot_snapshot_query_honours_cancellation(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = cancel_probe_hot_store(vfs);

    n00b_filter_t *filter = error_filter();

    cancel_probe_t full = {.polls = 0, .cancel_after = UINT64_MAX};
    auto q1_r = n00b_query_new(filter,
                               .limit      = 0,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &full);
    CHECK(n00b_result_is_ok(q1_r));

    auto r1 = n00b_query_run(store, n00b_result_get(q1_r));
    CHECK(n00b_result_is_ok(r1));
    n00b_query_result_t *complete = n00b_result_get(r1);
    CHECK(n00b_query_count(complete) == CANCEL_PROBE_RECORDS);
    CHECK(n00b_result_is_ok(n00b_query_result_close(complete)));

    // Restore the omission (drop .cancel_cb from the tail scan call in
    // rocs_query_cursor_add_hot_boundary) and this drops to exactly
    // CANCEL_PROBE_EMIT_POLLS.
    CHECK(full.polls > CANCEL_PROBE_EMIT_POLLS);
    printf("  [PASS] hot scan polls %llu times, emission alone would poll %d"
           " (#255)\n",
           (unsigned long long)full.polls,
           CANCEL_PROBE_EMIT_POLLS);

    // Cancelling before the emission loop could possibly have run proves the
    // scan gave up rather than completing and being discarded afterwards.
    cancel_probe_t during = {.polls = 0, .cancel_after = 0};
    auto q2_r = n00b_query_new(filter,
                               .limit      = 0,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &during);
    CHECK(n00b_result_is_ok(q2_r));

    auto r2 = n00b_query_run(store, n00b_result_get(q2_r));
    CHECK(n00b_result_is_err(r2));
    CHECK(n00b_result_get_err(r2) == N00B_QUERY_ERR_CANCELED);
    CHECK(during.polls > 0);
    printf("  [PASS] hot snapshot query cancels, polls=%llu (#255)\n",
           (unsigned long long)during.polls);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

// A ranked query builds its view with NO limit, collects every match, and only
// then scores and sorts. That second half runs inside the same lock as the
// scan, so it answers to the same hook; before the fix it ran to completion
// however long it took.
static void
test_ranked_snapshot_query_honours_cancellation(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = cancel_probe_store(vfs);

    n00b_filter_t *filter = error_contains_filter();

    // How many polls the SCAN alone performs. Ranking is the difference
    // between this and the ranked run below, so the two numbers together say
    // where a cancellation landed without hardcoding either.
    cancel_probe_t scan = {.polls = 0, .cancel_after = UINT64_MAX};
    auto q1_r = n00b_query_new(filter,
                               .limit      = 0,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &scan);
    CHECK(n00b_result_is_ok(q1_r));

    auto r1 = n00b_query_run(store, n00b_result_get(q1_r));
    CHECK(n00b_result_is_ok(r1));
    CHECK(n00b_result_is_ok(n00b_query_result_close(n00b_result_get(r1))));
    CHECK(scan.polls > 4);

    cancel_probe_t ranked = {.polls = 0, .cancel_after = UINT64_MAX};
    auto q2_r = n00b_query_new(filter,
                               .limit      = 0,
                               .ranked     = true,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &ranked);
    CHECK(n00b_result_is_ok(q2_r));

    auto r2 = n00b_query_run(store, n00b_result_get(q2_r));
    CHECK(n00b_result_is_ok(r2));
    CHECK(n00b_result_is_ok(n00b_query_result_close(n00b_result_get(r2))));

    // The ranked run polls strictly more over the same store and the same
    // scan. Those extra polls are the ranking phase; before the fix there were
    // none and this is the assertion that goes red.
    CHECK(ranked.polls > scan.polls);
    printf("  [PASS] ranking adds %llu polls over a %llu-poll scan (#255)\n",
           (unsigned long long)(ranked.polls - scan.polls),
           (unsigned long long)scan.polls);

    // Trip on the first poll AFTER the scan's last one. That is inside the
    // ranking phase by construction rather than by arithmetic on a constant.
    cancel_probe_t late = {.polls = 0, .cancel_after = scan.polls};
    auto q3_r = n00b_query_new(filter,
                               .limit      = 0,
                               .ranked     = true,
                               .cancel_cb  = cancel_after_n_polls,
                               .cancel_ctx = &late);
    CHECK(n00b_result_is_ok(q3_r));

    auto r3 = n00b_query_run(store, n00b_result_get(q3_r));
    CHECK(n00b_result_is_err(r3));
    CHECK(n00b_result_get_err(r3) == N00B_QUERY_ERR_CANCELED);
    CHECK(late.polls > scan.polls);
    CHECK(late.polls <= ranked.polls);
    printf("  [PASS] ranked query cancels in ranking at poll %llu of %llu"
           " (#255)\n",
           (unsigned long long)late.polls,
           (unsigned long long)ranked.polls);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_order_filter_later_commit_and_pin_lifetime();
    test_limit_resume_as_of_and_empty_window();
    test_cursor_and_view_close_invalidation();
    test_open_view_blocks_boundary_drop_until_close();
    test_corrupt_skipped_shard_does_not_block_resume_window();
    test_execution_detail_distinguishes_causes();
    test_snapshot_query_honours_cancellation();
    test_hot_snapshot_query_honours_cancellation();
    test_ranked_snapshot_query_honours_cancellation();

    n00b_shutdown();
    return 0;
}

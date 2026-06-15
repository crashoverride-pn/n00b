/* test/unit/test_rocs_live_cursor.c - WP-009 Phase 3 live cursor behavior. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/query.h must not include internal query declarations"
#endif

#include <rocs/n00b_rocs.h>
#include "internal/rocs/index.h"
#include "internal/rocs/query.h"
#include "internal/rocs/store.h"

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
    n00b_conduit_t            *conduit;
    n00b_store_commit_topic_t *topic;
    n00b_store_t              *store;
    n00b_filter_t             *filter;
} live_cursor_ctx_t;

typedef struct {
    n00b_query_cursor_t *cursor;
    n00b_thread_t       *thread;
    n00b_result_t(n00b_option_t(n00b_query_hit_t *)) result;
} next_worker_t;

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

static live_cursor_ctx_t
new_live_cursor_ctx(uint32_t topic_id)
{
    live_cursor_ctx_t ctx = {};
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    ctx.conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_commit_topic_get(
        ctx.conduit,
        N00B_CONDUIT_URI_USER_EVENT(topic_id));
    CHECK(n00b_result_is_ok(topic_r));
    ctx.topic = n00b_result_get(topic_r);

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs-live-cursor",
                                       new_schema(),
                                       .commit_topic = ctx.topic);
    CHECK(n00b_result_is_ok(store_r));
    ctx.store  = n00b_result_get(store_r);
    ctx.filter = error_filter();
    return ctx;
}

static void
destroy_live_cursor_ctx(live_cursor_ctx_t *ctx)
{
    if (ctx != nullptr && ctx->conduit != nullptr) {
        n00b_conduit_destroy(ctx->conduit);
        ctx->conduit = nullptr;
    }
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
ingest_hot(n00b_store_t *store, int64_t id, n00b_string_t *level)
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

static n00b_store_catalog_entry_t *
ingest_and_seal(n00b_store_t  *store,
                int64_t        id,
                n00b_string_t *level,
                uint64_t       seal_ts)
{
    ingest_hot(store, id, level);
    return seal_current(store, seal_ts);
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

static n00b_store_pos_t
hot_pos_after_ingest(n00b_store_t *store)
{
    auto snapshot_r = n00b_store_tail_snapshot(store);
    CHECK(n00b_result_is_ok(snapshot_r));
    n00b_store_tail_snapshot_t snapshot = n00b_result_get(snapshot_r);
    CHECK(snapshot.has_hot_through);
    return snapshot.hot_through;
}

static void
check_same_pos(n00b_store_pos_t actual, n00b_store_pos_t expected)
{
    CHECK(n00b_store_pos_compare(actual, expected) == 0);
}

static void
check_hit_record_id(n00b_query_hit_t *hit, int64_t expected_id)
{
    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));
    n00b_store_record_t *record = n00b_result_get(record_r);

    auto json_r = n00b_store_record_view_json(record);
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *json = n00b_result_get(json_r);
    CHECK(n00b_json_is_object(json));

    n00b_json_node_t *id = n00b_json_object_get(json, r"id");
    CHECK(id != nullptr);
    CHECK(n00b_json_is_int(id));
    CHECK(n00b_json_as_i64(id) == expected_id);
}

static n00b_query_view_t *
live_view(live_cursor_ctx_t *ctx)
{
    auto view_r = n00b_query_view(ctx->store,
                                  ctx->filter,
                                  .mode = N00B_QUERY_MODE_LIVE);
    CHECK(n00b_result_is_ok(view_r));
    return n00b_result_get(view_r);
}

static n00b_query_cursor_t *
cursor_ok(n00b_query_view_t *view)
{
    auto cursor_r = n00b_query_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    return n00b_result_get(cursor_r);
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

static n00b_query_hit_t *
check_hit_option(n00b_option_t(n00b_query_hit_t *) hit_opt,
                 n00b_store_pos_t                  expected,
                 int64_t                           expected_id)
{
    CHECK(n00b_option_is_set(hit_opt));
    n00b_query_hit_t *hit = n00b_option_get(hit_opt);

    auto pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(pos_r));
    check_same_pos(n00b_result_get(pos_r), expected);

    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));
    n00b_store_record_t *record = n00b_result_get(record_r);

    auto record_pos_r = n00b_store_record_pos(record);
    CHECK(n00b_result_is_ok(record_pos_r));
    check_same_pos(n00b_result_get(record_pos_r), expected);

    check_hit_record_id(hit, expected_id);
    return hit;
}

static n00b_query_hit_t *
expect_hit(n00b_query_cursor_t *cursor,
           n00b_store_pos_t     expected,
           int64_t              expected_id)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    n00b_query_hit_t *hit = check_hit_option(n00b_result_get(next_r),
                                             expected,
                                             expected_id);

    auto cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
    check_same_pos(n00b_option_get(n00b_result_get(cursor_pos_r)),
                   expected);
    return hit;
}

static void
expect_none(n00b_query_cursor_t *cursor)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));
}

static void *
next_worker_main(void *arg)
{
    next_worker_t *worker = (next_worker_t *)arg;
    worker->result = n00b_query_cursor_next(worker->cursor);
    return worker;
}

static next_worker_t *
start_next_worker(n00b_query_cursor_t *cursor)
{
    next_worker_t *worker = n00b_alloc(next_worker_t);
    worker->cursor = cursor;
    auto thread_r = n00b_thread_spawn(next_worker_main, worker);
    CHECK(n00b_result_is_ok(thread_r));
    worker->thread = n00b_result_get(thread_r);
    return worker;
}

static void
wait_until_cursor_blocked(n00b_query_cursor_t *cursor)
{
    auto wait_r = n00b_query_cursor_live_wait_until_waiting(cursor);
    CHECK(n00b_result_is_ok(wait_r));
    CHECK(n00b_result_get(wait_r));
}

static void
join_next_worker(next_worker_t *worker)
{
    void *joined = n00b_thread_join(worker->thread);
    CHECK(joined == worker);
}

static n00b_query_hit_t *
expect_worker_hit(next_worker_t   *worker,
                  n00b_store_pos_t expected,
                  int64_t          expected_id)
{
    join_next_worker(worker);
    CHECK(n00b_result_is_ok(worker->result));
    return check_hit_option(n00b_result_get(worker->result),
                            expected,
                            expected_id);
}

static void
expect_worker_none(next_worker_t *worker)
{
    join_next_worker(worker);
    CHECK(n00b_result_is_ok(worker->result));
    CHECK(!n00b_option_is_set(n00b_result_get(worker->result)));
}

static void
test_history_first_then_hot_live_in_durable_order(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9201);
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 1, r"error", 2001);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 2, r"error", 2002);

    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    auto pos_before_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_before_r));
    CHECK(!n00b_option_is_set(n00b_result_get(pos_before_r)));

    ingest_hot(ctx.store, 3, r"error");
    n00b_store_pos_t live_pos = hot_pos_after_ingest(ctx.store);

    n00b_query_hit_t *first_hit = expect_hit(cursor, entry_pos(first, 0), 1);
    n00b_query_hit_t *second_hit = expect_hit(cursor, entry_pos(second, 0), 2);
    CHECK_CODE_ERR(n00b_query_hit_pos(first_hit), N00B_QUERY_ERR_CLOSED);

    n00b_query_hit_t *live_hit = expect_hit(cursor, live_pos, 3);
    CHECK_CODE_ERR(n00b_query_hit_record(second_hit), N00B_QUERY_ERR_CLOSED);

    close_cursor_true(cursor);
    CHECK_CODE_ERR(n00b_query_hit_pos(live_hit), N00B_QUERY_ERR_CLOSED);
    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_cutover_commit_has_no_gap_or_duplicate(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9202);
    n00b_store_catalog_entry_t *historical =
        ingest_and_seal(ctx.store, 10, r"error", 2101);

    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    ingest_hot(ctx.store, 11, r"error");
    n00b_store_pos_t live_pos = hot_pos_after_ingest(ctx.store);

    expect_hit(cursor, entry_pos(historical, 0), 10);
    expect_hit(cursor, live_pos, 11);
    CHECK(n00b_store_pos_compare(entry_pos(historical, 0), live_pos) < 0);

    close_cursor_true(cursor);
    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_blocking_until_later_matching_hit_arrives(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9203);
    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    next_worker_t *worker = start_next_worker(cursor);
    wait_until_cursor_blocked(cursor);

    ingest_hot(ctx.store, 20, r"error");
    n00b_store_pos_t live_pos = hot_pos_after_ingest(ctx.store);
    n00b_query_hit_t *hit = expect_worker_hit(worker, live_pos, 20);

    close_cursor_true(cursor);
    CHECK_CODE_ERR(n00b_query_hit_pos(hit), N00B_QUERY_ERR_CLOSED);
    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_multiple_live_cursors_share_one_live_hit_once(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9209);
    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *first = cursor_ok(view);
    n00b_query_cursor_t *second = cursor_ok(view);

    next_worker_t *first_worker = start_next_worker(first);
    next_worker_t *second_worker = start_next_worker(second);
    wait_until_cursor_blocked(first);
    wait_until_cursor_blocked(second);

    ingest_hot(ctx.store, 50, r"error");
    n00b_store_pos_t live_pos = hot_pos_after_ingest(ctx.store);

    (void)expect_worker_hit(first_worker, live_pos, 50);
    (void)expect_worker_hit(second_worker, live_pos, 50);

    auto pending_r = n00b_query_live_tail_pending_count(view);
    CHECK(n00b_result_is_ok(pending_r));
    CHECK(n00b_result_get(pending_r) == 1);

    auto stats_r = n00b_query_live_tail_stats(view);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_query_live_tail_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.matched_positions == 1);
    CHECK(stats.has_last_observed);
    check_same_pos(stats.last_observed, live_pos);

    first_worker = start_next_worker(first);
    second_worker = start_next_worker(second);
    wait_until_cursor_blocked(first);
    wait_until_cursor_blocked(second);

    close_view_true(view);
    expect_worker_none(first_worker);
    expect_worker_none(second_worker);

    CHECK_CODE_ERR(n00b_query_cursor_next(first), N00B_QUERY_ERR_CLOSED);
    CHECK_CODE_ERR(n00b_query_cursor_next(second), N00B_QUERY_ERR_CLOSED);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_blocked_next_wakes_on_cursor_close(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9204);
    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    next_worker_t *worker = start_next_worker(cursor);
    wait_until_cursor_blocked(cursor);
    close_cursor_true(cursor);
    expect_worker_none(worker);

    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_blocked_next_wakes_on_view_close(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9205);
    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    next_worker_t *worker = start_next_worker(cursor);
    wait_until_cursor_blocked(cursor);
    close_view_true(view);
    expect_worker_none(worker);

    auto cursor_again_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(cursor_again_r));
    CHECK(!n00b_result_get(cursor_again_r));
    destroy_live_cursor_ctx(&ctx);
}

static void
test_limit_spans_historical_and_live_hits(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9206);
    n00b_store_catalog_entry_t *historical =
        ingest_and_seal(ctx.store, 30, r"error", 2201);

    auto view_r = n00b_query_view(ctx.store,
                                  ctx.filter,
                                  .mode = N00B_QUERY_MODE_LIVE,
                                  .limit = 2);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    ingest_hot(ctx.store, 31, r"error");
    n00b_store_pos_t first_live = hot_pos_after_ingest(ctx.store);
    ingest_hot(ctx.store, 32, r"error");

    expect_hit(cursor, entry_pos(historical, 0), 30);
    expect_hit(cursor, first_live, 31);
    expect_none(cursor);

    auto pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(pos_r)));
    check_same_pos(n00b_option_get(n00b_result_get(pos_r)), first_live);

    close_cursor_true(cursor);
    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_delivered_hot_live_hit_survives_shard_seal_until_advance(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9207);
    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    ingest_hot(ctx.store, 40, r"error");
    n00b_store_pos_t live_pos = hot_pos_after_ingest(ctx.store);

    n00b_query_hit_t *hit = expect_hit(cursor, live_pos, 40);
    (void)seal_current(ctx.store, 2301);

    auto stats_r = n00b_store_residency_stats(ctx.store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_residency_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.active_pins == 1);
    CHECK(stats.retired_hot_allocators == 0);

    check_hit_record_id(hit, 40);

    close_cursor_true(cursor);
    CHECK_CODE_ERR(n00b_query_hit_record(hit), N00B_QUERY_ERR_CLOSED);
    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

static void
test_snapshot_cursor_regression(void)
{
    live_cursor_ctx_t ctx = new_live_cursor_ctx(9208);
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 40, r"error", 2301);
    ingest_and_seal(ctx.store, 41, r"info", 2302);

    auto view_r = n00b_query_view(ctx.store, ctx.filter);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    expect_hit(cursor, entry_pos(first, 0), 40);
    expect_none(cursor);

    close_cursor_true(cursor);
    close_view_true(view);
    destroy_live_cursor_ctx(&ctx);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_history_first_then_hot_live_in_durable_order();
    test_cutover_commit_has_no_gap_or_duplicate();
    test_blocking_until_later_matching_hit_arrives();
    test_multiple_live_cursors_share_one_live_hit_once();
    test_blocked_next_wakes_on_cursor_close();
    test_blocked_next_wakes_on_view_close();
    test_limit_spans_historical_and_live_hits();
    test_delivered_hot_live_hit_survives_shard_seal_until_advance();
    test_snapshot_cursor_regression();

    n00b_shutdown();
    return 0;
}

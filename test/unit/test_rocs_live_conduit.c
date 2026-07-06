/* test/unit/test_rocs_live_conduit.c - WP-009 Phase 5 live output. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/time.h"
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
    n00b_store_commit_topic_t *commit_topic;
    n00b_store_t              *store;
    n00b_filter_t             *filter;
} live_output_ctx_t;

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

static live_output_ctx_t
new_live_output_ctx(uint32_t topic_id)
{
    live_output_ctx_t ctx = {};
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    ctx.conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_commit_topic_get(
        ctx.conduit,
        N00B_CONDUIT_URI_USER_EVENT(topic_id));
    CHECK(n00b_result_is_ok(topic_r));
    ctx.commit_topic = n00b_result_get(topic_r);

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs-live-conduit",
                                       new_schema(),
                                       .commit_topic = ctx.commit_topic);
    CHECK(n00b_result_is_ok(store_r));
    ctx.store  = n00b_result_get(store_r);
    ctx.filter = error_filter();
    return ctx;
}

static void
destroy_live_output_ctx(live_output_ctx_t *ctx)
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

static uint64_t
entry_shard_id(n00b_store_catalog_entry_t *entry)
{
    auto id_r = n00b_store_catalog_entry_get_shard_id(entry);
    CHECK(n00b_result_is_ok(id_r));
    return n00b_result_get(id_r);
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

static int64_t
now_ms(void)
{
    return (int64_t)(n00b_ns_timestamp() / N00B_NS_PER_MS);
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
live_output_view_ok(live_output_ctx_t *ctx) _kargs
{
    uint64_t limit = 0;
}
{
    auto view_r = n00b_query_view(ctx->store,
                                  ctx->filter,
                                  .mode  = N00B_QUERY_MODE_LIVE,
                                  .out   = ctx->conduit,
                                  .limit = limit);
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

static n00b_query_hit_topic_t *
output_topic_ok(n00b_query_view_t *view)
{
    auto topic_r = n00b_query_view_output_topic(view);
    CHECK(n00b_result_is_ok(topic_r));
    return n00b_result_get(topic_r);
}

static n00b_query_hit_inbox_t *
output_inbox_ok(live_output_ctx_t *ctx) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_DROP_NEWEST;
    uint32_t                    limit        = 1024;
}
{
    auto inbox_r = n00b_query_hit_inbox_new(ctx->conduit,
                                            .backpressure = backpressure,
                                            .limit        = limit);
    CHECK(n00b_result_is_ok(inbox_r));
    return n00b_result_get(inbox_r);
}

static n00b_conduit_sub_handle_t
subscribe_ok(n00b_query_hit_topic_t *topic, n00b_query_hit_inbox_t *inbox)
{
    auto sub_r = n00b_query_hit_subscribe(topic, inbox);
    CHECK(n00b_result_is_ok(sub_r));
    return n00b_result_get(sub_r);
}

static void
start_output_true(n00b_query_view_t *view)
{
    auto start_r = n00b_query_view_output_start(view);
    CHECK(n00b_result_is_ok(start_r));
    CHECK(n00b_result_get(start_r));
}

static n00b_query_hit_t *
expect_cursor_hit(n00b_query_cursor_t *cursor,
                  n00b_store_pos_t     expected,
                  int64_t              expected_id)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
    CHECK(n00b_option_is_set(hit_opt));

    n00b_query_hit_t *hit = n00b_option_get(hit_opt);
    auto pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(pos_r));
    check_same_pos(n00b_result_get(pos_r), expected);
    check_hit_record_id(hit, expected_id);
    return hit;
}

static void
expect_cursor_none(n00b_query_cursor_t *cursor)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));
}

static bool
wait_for_query_messages(n00b_query_hit_inbox_t *inbox, uint32_t needed)
{
    int64_t deadline_ms = now_ms() + 3000;
    while (n00b_query_hit_inbox_msg_count(inbox) < needed
           && !n00b_conduit_inbox_has_sys(inbox)) {
        int64_t remain_ms = deadline_ms - now_ms();
        if (remain_ms <= 0) {
            break;
        }

        n00b_condition_lock(&inbox->cv);
        if (n00b_query_hit_inbox_msg_count(inbox) < needed
            && !n00b_conduit_inbox_has_sys(inbox)) {
            n00b_condition_wait(&inbox->cv,
                                .timeout_ms  = remain_ms,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&inbox->cv);
        }
    }

    return n00b_query_hit_inbox_msg_count(inbox) >= needed;
}

static bool
wait_for_query_sys(n00b_query_hit_inbox_t *inbox)
{
    int64_t deadline_ms = now_ms() + 3000;
    while (!n00b_conduit_inbox_has_sys(inbox)) {
        int64_t remain_ms = deadline_ms - now_ms();
        if (remain_ms <= 0) {
            break;
        }

        n00b_condition_lock(&inbox->cv);
        if (!n00b_conduit_inbox_has_sys(inbox)) {
            n00b_condition_wait(&inbox->cv,
                                .timeout_ms  = remain_ms,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&inbox->cv);
        }
    }

    return n00b_conduit_inbox_has_sys(inbox);
}

static n00b_query_output_stats_t
wait_for_output_emitted(n00b_query_view_t      *view,
                        n00b_query_hit_inbox_t *inbox,
                        uint64_t                emitted)
{
    int64_t deadline_ms = now_ms() + 3000;
    while (true) {
        auto stats_r = n00b_query_output_stats(view);
        CHECK(n00b_result_is_ok(stats_r));
        n00b_query_output_stats_t stats = n00b_result_get(stats_r);
        if (stats.emitted_positions >= emitted || stats.closed) {
            return stats;
        }

        int64_t remain_ms = deadline_ms - now_ms();
        if (remain_ms <= 0) {
            return stats;
        }

        n00b_condition_lock(&inbox->cv);
        n00b_condition_wait(&inbox->cv,
                            .timeout_ms  = remain_ms < 25 ? remain_ms : 25,
                            .auto_unlock = true);
    }
}

static n00b_query_output_stats_t
wait_for_output_error(n00b_query_view_t      *view,
                      n00b_query_hit_inbox_t *inbox)
{
    int64_t deadline_ms = now_ms() + 3000;
    while (true) {
        auto stats_r = n00b_query_output_stats(view);
        CHECK(n00b_result_is_ok(stats_r));
        n00b_query_output_stats_t stats = n00b_result_get(stats_r);
        if (stats.has_last_error || stats.closed) {
            return stats;
        }

        int64_t remain_ms = deadline_ms - now_ms();
        if (remain_ms <= 0) {
            return stats;
        }

        n00b_condition_lock(&inbox->cv);
        n00b_condition_wait(&inbox->cv,
                            .timeout_ms  = remain_ms < 25 ? remain_ms : 25,
                            .auto_unlock = true);
    }
}

static void
expect_retention_payload(n00b_result_error_t         carrier,
                         n00b_query_boundary_kind_t  boundary,
                         n00b_store_pos_t            requested,
                         n00b_store_pos_t            oldest)
{
    CHECK(carrier.kind == N00B_RESULT_ERROR_PAYLOAD);
    CHECK(carrier.payload_type == typehash(n00b_query_retention_error_t *));
    CHECK(carrier.payload != nullptr);

    n00b_query_retention_error_t *payload =
        (n00b_query_retention_error_t *)carrier.payload;

    auto code_r = n00b_query_retention_error_code(payload);
    CHECK(n00b_result_is_ok(code_r));
    CHECK(n00b_result_get(code_r) == N00B_QUERY_ERR_RETENTION);

    auto boundary_r = n00b_query_retention_error_boundary(payload);
    CHECK(n00b_result_is_ok(boundary_r));
    CHECK(n00b_result_get(boundary_r) == boundary);

    auto requested_r = n00b_query_retention_error_requested(payload);
    CHECK(n00b_result_is_ok(requested_r));
    check_same_pos(n00b_result_get(requested_r), requested);

    auto oldest_r = n00b_query_retention_error_oldest_available(payload);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    check_same_pos(n00b_option_get(n00b_result_get(oldest_r)), oldest);
}

static n00b_query_hit_msg_t *
pop_output_msg(n00b_query_hit_inbox_t *inbox,
               n00b_store_pos_t       expected,
               int64_t                expected_id)
{
    CHECK(wait_for_query_messages(inbox, 1));

    n00b_query_hit_msg_t *msg = n00b_query_hit_inbox_pop(inbox);
    CHECK(msg != nullptr);
    CHECK(n00b_conduit_msg_type(msg) == N00B_CONDUIT_MSG_USER);
    n00b_query_hit_t *hit = n00b_conduit_msg_payload(msg);
    CHECK(hit != nullptr);

    auto pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(pos_r));
    check_same_pos(n00b_result_get(pos_r), expected);
    check_hit_record_id(hit, expected_id);
    return msg;
}

static void
drop_msg_ok(n00b_query_hit_msg_t *msg)
{
    auto drop_r = n00b_query_hit_msg_drop(msg);
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));
}

static void
drain_ok(n00b_query_hit_inbox_t *inbox)
{
    auto drain_r = n00b_query_hit_inbox_drain(inbox);
    CHECK(n00b_result_is_ok(drain_r));
}

static void
test_historical_prefix_multiple_subscribers(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9501);
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 1, r"error", 5001);
    ingest_and_seal(ctx.store, 2, r"info", 5002);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 3, r"error", 5003);

    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *first_inbox = output_inbox_ok(&ctx);
    n00b_query_hit_inbox_t *second_inbox = output_inbox_ok(&ctx);
    (void)subscribe_ok(topic, first_inbox);
    (void)subscribe_ok(topic, second_inbox);

    start_output_true(view);
    CHECK(wait_for_query_messages(first_inbox, 2));
    CHECK(wait_for_query_messages(second_inbox, 2));

    n00b_query_hit_msg_t *m1 =
        pop_output_msg(first_inbox, entry_pos(first, 0), 1);
    n00b_query_hit_msg_t *m2 =
        pop_output_msg(first_inbox, entry_pos(second, 0), 3);
    n00b_query_hit_msg_t *m3 =
        pop_output_msg(second_inbox, entry_pos(first, 0), 1);
    n00b_query_hit_msg_t *m4 =
        pop_output_msg(second_inbox, entry_pos(second, 0), 3);

    CHECK(n00b_conduit_msg_payload(m1) != n00b_conduit_msg_payload(m3));

    drop_msg_ok(m1);
    drop_msg_ok(m2);
    drop_msg_ok(m3);
    drop_msg_ok(m4);
    close_view_true(view);
    drain_ok(first_inbox);
    drain_ok(second_inbox);
    destroy_live_output_ctx(&ctx);
}

static void
test_live_output_after_later_commits(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9502);
    n00b_store_catalog_entry_t *historical =
        ingest_and_seal(ctx.store, 10, r"error", 5101);

    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
    (void)subscribe_ok(topic, inbox);
    start_output_true(view);

    n00b_query_hit_msg_t *history =
        pop_output_msg(inbox, entry_pos(historical, 0), 10);
    drop_msg_ok(history);

    ingest_hot(ctx.store, 11, r"info");
    ingest_hot(ctx.store, 12, r"error");
    n00b_store_pos_t live_pos = hot_pos_after_ingest(ctx.store);

    n00b_query_hit_msg_t *live =
        pop_output_msg(inbox, live_pos, 12);
    drop_msg_ok(live);

    close_view_true(view);
    drain_ok(inbox);
    destroy_live_output_ctx(&ctx);
}

static void
test_cursor_output_limit_coexistence(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9503);
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 20, r"error", 5201);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 21, r"error", 5202);
    ingest_and_seal(ctx.store, 22, r"error", 5203);

    n00b_query_view_t *view = live_output_view_ok(&ctx, .limit = 2);
    n00b_query_cursor_t *cursor = cursor_ok(view);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
    (void)subscribe_ok(topic, inbox);
    start_output_true(view);

    expect_cursor_hit(cursor, entry_pos(first, 0), 20);
    expect_cursor_hit(cursor, entry_pos(second, 0), 21);
    expect_cursor_none(cursor);

    n00b_query_hit_msg_t *m1 =
        pop_output_msg(inbox, entry_pos(first, 0), 20);
    n00b_query_hit_msg_t *m2 =
        pop_output_msg(inbox, entry_pos(second, 0), 21);
    drop_msg_ok(m1);
    drop_msg_ok(m2);

    n00b_query_output_stats_t stats =
        wait_for_output_emitted(view, inbox, 2);
    CHECK(stats.emitted_positions == 2);
    CHECK(stats.limit == 2);

    close_cursor_true(cursor);
    close_view_true(view);
    drain_ok(inbox);
    destroy_live_output_ctx(&ctx);
}

static void
test_output_hit_lifetime_after_cursor_and_view_close(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9504);
    n00b_store_catalog_entry_t *entry =
        ingest_and_seal(ctx.store, 30, r"error", 5301);

    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
    (void)subscribe_ok(topic, inbox);
    start_output_true(view);

    n00b_query_hit_msg_t *msg =
        pop_output_msg(inbox, entry_pos(entry, 0), 30);
    n00b_query_hit_t *output_hit = n00b_conduit_msg_payload(msg);

    n00b_query_hit_t *cursor_hit =
        expect_cursor_hit(cursor, entry_pos(entry, 0), 30);

    close_cursor_true(cursor);
    CHECK_CODE_ERR(n00b_query_hit_pos(cursor_hit), N00B_QUERY_ERR_CLOSED);

    close_view_true(view);
    CHECK(wait_for_query_sys(inbox));

    check_hit_record_id(output_hit, 30);
    drop_msg_ok(msg);
    CHECK_CODE_ERR(n00b_query_hit_pos(output_hit), N00B_QUERY_ERR_CLOSED);

    drain_ok(inbox);
    destroy_live_output_ctx(&ctx);
}

static void
test_sealed_output_hit_pins_retention_until_drop(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9505);
    n00b_store_catalog_entry_t *entry =
        ingest_and_seal(ctx.store, 40, r"error", 5401);
    uint64_t shard_id = entry_shard_id(entry);

    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
    (void)subscribe_ok(topic, inbox);
    start_output_true(view);

    n00b_query_hit_msg_t *msg =
        pop_output_msg(inbox, entry_pos(entry, 0), 40);

    auto pinned_r = n00b_store_drop_sealed_shard(ctx.store, shard_id);
    CHECK(n00b_result_is_err(pinned_r));
    CHECK(n00b_result_get_err(pinned_r) == N00B_STORE_ERR_PINNED);

    drop_msg_ok(msg);
    close_view_true(view);

    auto drop_r = n00b_store_drop_sealed_shard(ctx.store, shard_id);
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));

    drain_ok(inbox);
    destroy_live_output_ctx(&ctx);
}

static void
test_bounded_drop_newest_releases_dropped_hits(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9506);
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 50, r"error", 5501);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 51, r"error", 5502);
    ingest_and_seal(ctx.store, 52, r"error", 5503);

    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox =
        output_inbox_ok(&ctx,
                        .backpressure = N00B_CONDUIT_BP_DROP_NEWEST,
                        .limit        = 1);
    (void)subscribe_ok(topic, inbox);
    start_output_true(view);

    CHECK(wait_for_query_messages(inbox, 1));
    n00b_query_output_stats_t stats =
        wait_for_output_emitted(view, inbox, 3);
    CHECK(stats.emitted_positions == 3);
    CHECK(stats.dropped_messages >= 2);
    CHECK(n00b_query_hit_inbox_msg_count(inbox) == 1);

    auto dropped_pin_r =
        n00b_store_drop_sealed_shard(ctx.store, entry_shard_id(second));
    CHECK(n00b_result_is_err(dropped_pin_r));
    CHECK(n00b_result_get_err(dropped_pin_r) == N00B_STORE_ERR_PINNED);

    n00b_query_hit_msg_t *queued =
        pop_output_msg(inbox, entry_pos(first, 0), 50);
    auto pinned_r =
        n00b_store_drop_sealed_shard(ctx.store, entry_shard_id(first));
    CHECK(n00b_result_is_err(pinned_r));
    CHECK(n00b_result_get_err(pinned_r) == N00B_STORE_ERR_PINNED);

    drop_msg_ok(queued);
    close_view_true(view);

    auto first_drop_r =
        n00b_store_drop_sealed_shard(ctx.store, entry_shard_id(first));
    CHECK(n00b_result_is_ok(first_drop_r));
    CHECK(n00b_result_get(first_drop_r));

    dropped_pin_r =
        n00b_store_drop_sealed_shard(ctx.store, entry_shard_id(second));
    CHECK(n00b_result_is_ok(dropped_pin_r));
    CHECK(n00b_result_get(dropped_pin_r));

    drain_ok(inbox);
    destroy_live_output_ctx(&ctx);
}

static void
test_unsubscribe_close_and_snapshot_out(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9507);
    n00b_store_catalog_entry_t *entry =
        ingest_and_seal(ctx.store, 60, r"error", 5601);

    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
    n00b_conduit_sub_handle_t sub = subscribe_ok(topic, inbox);

    auto unsub_r = n00b_query_hit_unsubscribe(topic, sub);
    CHECK(n00b_result_is_ok(unsub_r));
    CHECK(n00b_result_get(unsub_r));

    start_output_true(view);
    n00b_query_output_stats_t stats =
        wait_for_output_emitted(view, inbox, 1);
    CHECK(stats.emitted_positions == 1);
    CHECK(n00b_query_hit_inbox_msg_count(inbox) == 0);

    close_view_true(view);
    CHECK_CODE_ERR(n00b_query_view_output_topic(view), N00B_QUERY_ERR_CLOSED);
    drain_ok(inbox);

    auto snapshot_view_r = n00b_query_view(ctx.store,
                                           ctx.filter,
                                           .out = ctx.conduit);
    CHECK(n00b_result_is_err(snapshot_view_r));
    CHECK(n00b_result_get_err(snapshot_view_r)
          == N00B_QUERY_ERR_UNSUPPORTED_MODE);

    auto snapshot_r = n00b_query_view(ctx.store, ctx.filter);
    CHECK(n00b_result_is_ok(snapshot_r));
    n00b_query_view_t *snapshot = n00b_result_get(snapshot_r);
    n00b_query_cursor_t *cursor = cursor_ok(snapshot);
    expect_cursor_hit(cursor, entry_pos(entry, 0), 60);
    expect_cursor_none(cursor);
    close_cursor_true(cursor);
    close_view_true(snapshot);
    destroy_live_output_ctx(&ctx);
}

static void
test_output_view_pin_blocks_retention_until_close(void)
{
    live_output_ctx_t ctx = new_live_output_ctx(9508);
    n00b_query_view_t *view = live_output_view_ok(&ctx);
    n00b_query_hit_topic_t *topic = output_topic_ok(view);
    n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
    (void)subscribe_ok(topic, inbox);

    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 70, r"error", 5701);
    ingest_and_seal(ctx.store, 71, r"error", 5702);

    auto scan_r = n00b_query_live_tail_scan_once(view);
    CHECK(n00b_result_is_ok(scan_r));
    CHECK(n00b_result_get(scan_r) == 2);

    auto drop_r = n00b_store_drop_sealed_shard(ctx.store,
                                               entry_shard_id(first));
    CHECK(n00b_result_is_err(drop_r));
    CHECK(n00b_result_get_err(drop_r) == N00B_STORE_ERR_PINNED);

    start_output_true(view);
    n00b_query_output_stats_t stats =
        wait_for_output_emitted(view, inbox, 2);
    CHECK(stats.emitted_positions == 2);

    close_view_true(view);
    drain_ok(inbox);

    drop_r = n00b_store_drop_sealed_shard(ctx.store,
                                          entry_shard_id(first));
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));

    destroy_live_output_ctx(&ctx);
}

static void
test_output_start_close_joins_thread(void)
{
    for (uint64_t i = 0; i < 25; i++) {
        live_output_ctx_t ctx = new_live_output_ctx((uint32_t)(9510 + i));
        n00b_query_view_t *view = live_output_view_ok(&ctx);
        n00b_query_hit_topic_t *topic = output_topic_ok(view);
        n00b_query_hit_inbox_t *inbox = output_inbox_ok(&ctx);
        (void)subscribe_ok(topic, inbox);

        start_output_true(view);
        close_view_true(view);

        auto stats_r = n00b_query_output_stats(view);
        CHECK(n00b_result_is_ok(stats_r));
        n00b_query_output_stats_t stats = n00b_result_get(stats_r);
        CHECK(stats.closed);
        CHECK(stats.joined);
        CHECK(!stats.has_thread);
        CHECK_CODE_ERR(n00b_query_view_output_start(view),
                       N00B_QUERY_ERR_CLOSED);

        drain_ok(inbox);
        destroy_live_output_ctx(&ctx);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_historical_prefix_multiple_subscribers();
    test_live_output_after_later_commits();
    test_cursor_output_limit_coexistence();
    test_output_hit_lifetime_after_cursor_and_view_close();
    test_sealed_output_hit_pins_retention_until_drop();
    test_bounded_drop_newest_releases_dropped_hits();
    test_unsubscribe_close_and_snapshot_out();
    test_output_view_pin_blocks_retention_until_close();
    test_output_start_close_joins_thread();

    n00b_print(r"rocs_live_conduit: ok");
    n00b_shutdown();
    return 0;
}

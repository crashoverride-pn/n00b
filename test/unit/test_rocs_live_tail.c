/* test/unit/test_rocs_live_tail.c - WP-009 Phase 2 live-tail internals. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/query.h must not include internal query declarations"
#endif

#include <rocs/n00b_rocs.h>
#include "internal/rocs/filter.h"
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
} live_tail_ctx_t;

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

static live_tail_ctx_t
new_live_tail_ctx(uint32_t topic_id, bool with_topic)
{
    live_tail_ctx_t ctx = {};
    if (with_topic) {
        auto conduit_r = n00b_conduit_new();
        CHECK(n00b_result_is_ok(conduit_r));
        ctx.conduit = n00b_result_get(conduit_r);

        auto topic_r = n00b_store_commit_topic_get(
            ctx.conduit,
            N00B_CONDUIT_URI_USER_EVENT(topic_id));
        CHECK(n00b_result_is_ok(topic_r));
        ctx.topic = n00b_result_get(topic_r);
    }

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs-live-tail",
                                       new_schema(),
                                       .commit_topic = ctx.topic);
    CHECK(n00b_result_is_ok(store_r));
    ctx.store  = n00b_result_get(store_r);
    ctx.filter = error_filter();
    return ctx;
}

static void
destroy_live_tail_ctx(live_tail_ctx_t *ctx)
{
    if (ctx != nullptr && ctx->conduit != nullptr) {
        n00b_conduit_destroy(ctx->conduit);
        ctx->conduit = nullptr;
    }
}

static n00b_store_catalog_entry_t *
ingest_and_seal(n00b_store_t  *store,
                int64_t        id,
                n00b_string_t *level,
                uint64_t       seal_ts)
{
    auto ingest_r = n00b_store_ingest(store, record_with_level(id, level));
    CHECK(n00b_result_is_ok(ingest_r));

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static void
ingest_hot(n00b_store_t *store, int64_t id, n00b_string_t *level)
{
    auto ingest_r = n00b_store_ingest(store, record_with_level(id, level));
    CHECK(n00b_result_is_ok(ingest_r));
}

static void
seal_current_hot_and_ingest_new_hot(n00b_store_t *store)
{
    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 1701);
    CHECK(n00b_result_is_ok(seal_r));
    ingest_hot(store, 1702, r"error");
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

static n00b_query_view_t *
live_view(live_tail_ctx_t *ctx)
{
    auto view_r = n00b_query_view(ctx->store,
                                  ctx->filter,
                                  .mode = N00B_QUERY_MODE_LIVE);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    CHECK(view != nullptr);
    return view;
}

static void
close_view_true(n00b_query_view_t *view)
{
    auto close_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
close_view_false(n00b_query_view_t *view)
{
    auto close_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(!n00b_result_get(close_r));
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

static n00b_query_live_tail_stats_t
tail_stats(n00b_query_view_t *view)
{
    auto stats_r = n00b_query_live_tail_stats(view);
    CHECK(n00b_result_is_ok(stats_r));
    return n00b_result_get(stats_r);
}

static uint64_t
drain_wakeups(n00b_query_view_t *view)
{
    auto drain_r = n00b_query_live_tail_drain_wakeups(view);
    CHECK(n00b_result_is_ok(drain_r));
    return n00b_result_get(drain_r);
}

static uint64_t
scan_once(n00b_query_view_t *view)
{
    auto scan_r = n00b_query_live_tail_scan_once(view);
    CHECK(n00b_result_is_ok(scan_r));
    return n00b_result_get(scan_r);
}

static uint64_t
pending_count(n00b_query_view_t *view)
{
    auto count_r = n00b_query_live_tail_pending_count(view);
    CHECK(n00b_result_is_ok(count_r));
    return n00b_result_get(count_r);
}

static n00b_store_pos_t
pending_pos(n00b_query_view_t *view, uint64_t index)
{
    auto pos_r = n00b_query_live_tail_pending_position_at(view, index);
    CHECK(n00b_result_is_ok(pos_r));
    n00b_option_t(n00b_store_pos_t) pos_opt = n00b_result_get(pos_r);
    CHECK(n00b_option_is_set(pos_opt));
    return n00b_option_get(pos_opt);
}

static uint64_t
catalog_count(n00b_store_t *store)
{
    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    return n00b_result_get(count_r);
}

static void
check_same_pos(n00b_store_pos_t actual, n00b_store_pos_t expected)
{
    CHECK(n00b_store_pos_compare(actual, expected) == 0);
}

static void
test_live_subscribes_and_close_unsubscribes(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9101, true);
    n00b_query_view_t *view = live_view(&ctx);

    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.subscribed);
    CHECK(stats.subscription_active);
    CHECK(stats.has_inbox);
    CHECK(stats.inbox_limit == 64);
    CHECK(stats.queued_wakeups == 0);

    close_view_true(view);
    stats = tail_stats(view);
    CHECK(!stats.subscribed);
    CHECK(!stats.subscription_active);
    CHECK(!stats.has_inbox);
    close_view_false(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_live_without_topic_poll_scans_authoritative_state(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9102, false);
    n00b_query_view_t *view = live_view(&ctx);
    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(!stats.subscribed);
    CHECK(!stats.has_inbox);

    n00b_store_catalog_entry_t *entry =
        ingest_and_seal(ctx.store, 1, r"error", 1101);
    CHECK(drain_wakeups(view) == 0);
    CHECK(scan_once(view) == 1);
    CHECK(pending_count(view) == 1);
    check_same_pos(pending_pos(view, 0), entry_pos(entry, 0));

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_wakeups_lead_catchup_scan_to_matching_position(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9103, true);
    n00b_query_view_t *view = live_view(&ctx);

    n00b_store_catalog_entry_t *entry =
        ingest_and_seal(ctx.store, 2, r"error", 1201);
    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.queued_wakeups > 0);
    CHECK(drain_wakeups(view) > 0);
    CHECK(scan_once(view) == 1);
    CHECK(pending_count(view) == 1);
    check_same_pos(pending_pos(view, 0), entry_pos(entry, 0));

    stats = tail_stats(view);
    CHECK(stats.scans == 1);
    CHECK(stats.observed_positions == 1);
    CHECK(stats.matched_positions == 1);
    CHECK(stats.has_last_observed);
    check_same_pos(stats.last_observed, entry_pos(entry, 0));

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_dropped_wakeups_still_catch_up_from_store_state(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9104, true);
    n00b_query_view_t *view = live_view(&ctx);

    n00b_store_catalog_entry_t *last = nullptr;
    for (uint64_t i = 0; i < 70; i++) {
        last = ingest_and_seal(ctx.store,
                               (int64_t)i,
                               r"error",
                               1300 + i);
    }

    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.queued_wakeups == stats.inbox_limit);
    CHECK(drain_wakeups(view) == stats.inbox_limit);
    CHECK(tail_stats(view).wakeup_full_observations == 1);
    CHECK(scan_once(view) == 70);
    CHECK(pending_count(view) == 70);
    check_same_pos(pending_pos(view, 69), entry_pos(last, 0));

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_multiple_commits_scan_in_durable_order(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9105, true);
    n00b_query_view_t *view = live_view(&ctx);

    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 1, r"error", 1401);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 2, r"error", 1402);
    n00b_store_catalog_entry_t *third =
        ingest_and_seal(ctx.store, 3, r"error", 1403);

    CHECK(drain_wakeups(view) > 0);
    CHECK(scan_once(view) == 3);
    CHECK(pending_count(view) == 3);
    check_same_pos(pending_pos(view, 0), entry_pos(first, 0));
    check_same_pos(pending_pos(view, 1), entry_pos(second, 0));
    check_same_pos(pending_pos(view, 2), entry_pos(third, 0));

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_nonmatching_record_advances_last_observed(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9106, true);
    n00b_query_view_t *view = live_view(&ctx);

    n00b_store_catalog_entry_t *info =
        ingest_and_seal(ctx.store, 1, r"info", 1501);
    CHECK(scan_once(view) == 0);
    CHECK(pending_count(view) == 0);
    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.observed_positions == 1);
    CHECK(stats.has_last_observed);
    check_same_pos(stats.last_observed, entry_pos(info, 0));

    n00b_store_catalog_entry_t *error =
        ingest_and_seal(ctx.store, 2, r"error", 1502);
    CHECK(scan_once(view) == 1);
    CHECK(pending_count(view) == 1);
    check_same_pos(pending_pos(view, 0), entry_pos(error, 0));

    stats = tail_stats(view);
    CHECK(stats.observed_positions == 2);
    CHECK(scan_once(view) == 0);
    CHECK(pending_count(view) == 1);
    CHECK(tail_stats(view).observed_positions == 2);

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_full_wakeup_inbox_does_not_block_commits(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9107, true);
    n00b_query_view_t *view = live_view(&ctx);
    uint64_t limit = tail_stats(view).inbox_limit;

    for (uint64_t i = 0; i < limit + 16; i++) {
        (void)ingest_and_seal(ctx.store, (int64_t)i, r"error", 1600 + i);
    }

    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.queued_wakeups == limit);
    CHECK(catalog_count(ctx.store) == limit + 16);
    CHECK(drain_wakeups(view) == limit);
    CHECK(tail_stats(view).wakeup_full_observations == 1);

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_hot_tail_scan_catches_unsealed_commits_in_order(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9109, true);
    n00b_query_view_t *view = live_view(&ctx);

    ingest_hot(ctx.store, 1, r"error");
    ingest_hot(ctx.store, 2, r"info");
    ingest_hot(ctx.store, 3, r"error");

    CHECK(scan_once(view) == 2);
    CHECK(pending_count(view) == 2);

    n00b_store_pos_t first = pending_pos(view, 0);
    n00b_store_pos_t second = pending_pos(view, 1);
    CHECK(first.ordinal == 0);
    CHECK(second.ordinal == 2);
    CHECK(first.shard_id == second.shard_id);
    CHECK(first.generation == second.generation);
    CHECK(n00b_store_pos_compare(first, second) < 0);

    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.scans == 1);
    CHECK(stats.observed_positions == 3);
    CHECK(stats.matched_positions == 2);
    CHECK(stats.has_last_observed);
    CHECK(stats.last_observed.shard_id == first.shard_id);
    CHECK(stats.last_observed.ordinal == 2);

    CHECK(scan_once(view) == 0);
    CHECK(pending_count(view) == 2);
    CHECK(tail_stats(view).observed_positions == 3);

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_hot_nonmatch_advances_before_later_match(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9110, true);
    n00b_query_view_t *view = live_view(&ctx);

    ingest_hot(ctx.store, 1, r"info");
    CHECK(scan_once(view) == 0);
    CHECK(pending_count(view) == 0);
    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.observed_positions == 1);
    CHECK(stats.has_last_observed);
    CHECK(stats.last_observed.ordinal == 0);

    ingest_hot(ctx.store, 2, r"error");
    CHECK(scan_once(view) == 1);
    CHECK(pending_count(view) == 1);
    CHECK(pending_pos(view, 0).ordinal == 1);

    stats = tail_stats(view);
    CHECK(stats.observed_positions == 2);
    CHECK(stats.matched_positions == 1);
    CHECK(stats.last_observed.ordinal == 1);

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_seal_between_tail_snapshot_and_hot_scan_does_not_skip(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9111, true);
    n00b_query_view_t *view = live_view(&ctx);

    ingest_hot(ctx.store, 1701, r"error");
    auto snapshot_r = n00b_store_tail_snapshot(ctx.store);
    CHECK(n00b_result_is_ok(snapshot_r));
    n00b_store_tail_snapshot_t snapshot = n00b_result_get(snapshot_r);
    CHECK(snapshot.has_hot_through);

    auto lowered_r = n00b_filter_lower_to_plan(ctx.filter);
    CHECK(n00b_result_is_ok(lowered_r));

    seal_current_hot_and_ingest_new_hot(ctx.store);
    auto capped_r = n00b_store_hot_tail_scan_after(
        ctx.store,
        n00b_result_get(lowered_r),
        nullptr,
        .through = &snapshot.hot_through);
    CHECK(n00b_result_is_ok(capped_r));
    n00b_store_hot_tail_scan_t capped = n00b_result_get(capped_r);
    CHECK(!capped.has_last_observed);
    CHECK(capped.matches != nullptr);
    CHECK(n00b_list_len(*capped.matches) == 0);

    CHECK(scan_once(view) == 2);
    CHECK(pending_count(view) == 2);
    n00b_store_pos_t first  = pending_pos(view, 0);
    n00b_store_pos_t second = pending_pos(view, 1);
    CHECK(first.ordinal == 0);
    CHECK(second.ordinal == 0);
    CHECK(first.shard_id != second.shard_id);
    CHECK(n00b_store_pos_compare(first, second) < 0);

    n00b_query_live_tail_stats_t stats = tail_stats(view);
    CHECK(stats.scans == 1);
    CHECK(stats.observed_positions == 2);
    CHECK(stats.matched_positions == 2);
    CHECK(stats.has_last_observed);
    check_same_pos(stats.last_observed, second);

    CHECK(scan_once(view) == 0);
    CHECK(pending_count(view) == 2);

    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

static void
test_public_live_cursor_creation_succeeds(void)
{
    live_tail_ctx_t ctx = new_live_tail_ctx(9108, true);
    n00b_query_view_t *view = live_view(&ctx);
    close_cursor_true(cursor_ok(n00b_query_cursor(view)));
    close_view_true(view);
    destroy_live_tail_ctx(&ctx);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_live_subscribes_and_close_unsubscribes();
    test_live_without_topic_poll_scans_authoritative_state();
    test_wakeups_lead_catchup_scan_to_matching_position();
    test_dropped_wakeups_still_catch_up_from_store_state();
    test_multiple_commits_scan_in_durable_order();
    test_nonmatching_record_advances_last_observed();
    test_full_wakeup_inbox_does_not_block_commits();
    test_hot_tail_scan_catches_unsealed_commits_in_order();
    test_hot_nonmatch_advances_before_later_match();
    test_seal_between_tail_snapshot_and_hot_scan_does_not_skip();
    test_public_live_cursor_creation_succeeds();

    n00b_shutdown();
    return 0;
}

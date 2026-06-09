/* test/unit/test_rocs_live_resume.c - WP-009 Phase 4 live resume hardening. */

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

#include <rocs/n00b_rocs.h>
#include "internal/rocs/query.h"
#include "internal/rocs/store.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    n00b_store_t  *store;
    n00b_filter_t *filter;
} live_resume_ctx_t;

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

static live_resume_ctx_t
new_live_resume_ctx(void)
{
    live_resume_ctx_t ctx = {};
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs-live-resume",
                                       new_schema());
    CHECK(n00b_result_is_ok(store_r));
    ctx.store  = n00b_result_get(store_r);
    ctx.filter = error_filter();
    return ctx;
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

static void
check_same_pos(n00b_store_pos_t actual, n00b_store_pos_t expected)
{
    CHECK(n00b_store_pos_compare(actual, expected) == 0);
}

static n00b_query_view_t *
live_view_ok(live_resume_ctx_t *ctx)
{
    auto view_r = n00b_query_view(ctx->store,
                                  ctx->filter,
                                  .mode = N00B_QUERY_MODE_LIVE);
    CHECK(n00b_result_is_ok(view_r));
    return n00b_result_get(view_r);
}

static n00b_query_view_t *
live_resume_view_ok(live_resume_ctx_t *ctx, n00b_store_pos_t *resume)
{
    auto view_r = n00b_query_view(ctx->store,
                                  ctx->filter,
                                  .mode   = N00B_QUERY_MODE_LIVE,
                                  .resume = resume);
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
expect_hit(n00b_query_cursor_t *cursor, n00b_store_pos_t expected)
{
    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
    CHECK(n00b_option_is_set(hit_opt));

    n00b_query_hit_t *hit = n00b_option_get(hit_opt);
    auto hit_pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(hit_pos_r));
    check_same_pos(n00b_result_get(hit_pos_r), expected);

    auto cursor_pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cursor_pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cursor_pos_r)));
    check_same_pos(n00b_option_get(n00b_result_get(cursor_pos_r)),
                   expected);
    return hit;
}

static n00b_store_pos_t
cursor_position_some(n00b_query_cursor_t *cursor)
{
    auto pos_r = n00b_query_cursor_position(cursor);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(n00b_option_is_set(n00b_result_get(pos_r)));
    return n00b_option_get(n00b_result_get(pos_r));
}

static n00b_store_pos_t
encode_decode_pos(n00b_store_pos_t pos)
{
    auto token_r = n00b_store_pos_encode(pos);
    CHECK(n00b_result_is_ok(token_r));

    auto decoded_r = n00b_store_pos_decode(n00b_result_get(token_r));
    CHECK(n00b_result_is_ok(decoded_r));
    check_same_pos(n00b_result_get(decoded_r), pos);
    return n00b_result_get(decoded_r);
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

static void
expect_view_resume_retention(n00b_result_t(n00b_query_view_t *) r,
                             n00b_store_pos_t                   requested,
                             n00b_store_pos_t                   oldest)
{
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));
    expect_retention_payload(n00b_result_get_error(r),
                             N00B_QUERY_BOUNDARY_RESUME,
                             requested,
                             oldest);
}

static void
expect_next_snapshot_retention(
    n00b_result_t(n00b_option_t(n00b_query_hit_t *)) r,
    n00b_store_pos_t                                requested,
    n00b_store_pos_t                                oldest)
{
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));
    expect_retention_payload(n00b_result_get_error(r),
                             N00B_QUERY_BOUNDARY_SNAPSHOT,
                             requested,
                             oldest);
}

static void
test_retained_live_resume_after_historical_cursor_token(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 1, r"error", 3001);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 2, r"error", 3002);

    n00b_query_view_t *view = live_view_ok(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);
    n00b_store_pos_t first_pos = entry_pos(first, 0);
    n00b_store_pos_t second_pos = entry_pos(second, 0);

    expect_hit(cursor, first_pos);
    n00b_store_pos_t resume = encode_decode_pos(cursor_position_some(cursor));
    close_cursor_true(cursor);
    close_view_true(view);

    view = live_resume_view_ok(&ctx, &resume);
    cursor = cursor_ok(view);
    expect_hit(cursor, second_pos);
    close_cursor_true(cursor);
    close_view_true(view);
}

static void
test_live_hit_cursor_token_resumes_after_hot_position(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();
    n00b_query_view_t *view = live_view_ok(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    ingest_hot(ctx.store, 10, r"error");
    n00b_store_pos_t first_live = hot_pos_after_ingest(ctx.store);
    expect_hit(cursor, first_live);
    n00b_store_pos_t resume = encode_decode_pos(cursor_position_some(cursor));
    close_cursor_true(cursor);
    close_view_true(view);

    view = live_resume_view_ok(&ctx, &resume);
    cursor = cursor_ok(view);
    ingest_hot(ctx.store, 11, r"error");
    n00b_store_pos_t second_live = hot_pos_after_ingest(ctx.store);
    expect_hit(cursor, second_live);
    close_cursor_true(cursor);
    close_view_true(view);
}

static void
test_live_resume_unavailable_positions_are_typed(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 20, r"error", 3101);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 21, r"error", 3102);

    n00b_store_pos_t first_pos = entry_pos(first, 0);
    n00b_store_pos_t second_pos = entry_pos(second, 0);

    n00b_store_pos_t missing = first_pos;
    missing.shard_id = 999;
    expect_view_resume_retention(
        n00b_query_view(ctx.store,
                        ctx.filter,
                        .mode   = N00B_QUERY_MODE_LIVE,
                        .resume = &missing),
        missing,
        first_pos);

    n00b_store_pos_t out_of_range = first_pos;
    out_of_range.ordinal = 1;
    expect_view_resume_retention(
        n00b_query_view(ctx.store,
                        ctx.filter,
                        .mode   = N00B_QUERY_MODE_LIVE,
                        .resume = &out_of_range),
        out_of_range,
        first_pos);

    n00b_store_pos_t generation_mismatch = first_pos;
    generation_mismatch.generation++;
    expect_view_resume_retention(
        n00b_query_view(ctx.store,
                        ctx.filter,
                        .mode   = N00B_QUERY_MODE_LIVE,
                        .resume = &generation_mismatch),
        generation_mismatch,
        first_pos);

    auto drop_r = n00b_store_drop_sealed_shard(ctx.store,
                                               entry_shard_id(first));
    CHECK(n00b_result_is_ok(drop_r));
    expect_view_resume_retention(
        n00b_query_view(ctx.store,
                        ctx.filter,
                        .mode   = N00B_QUERY_MODE_LIVE,
                        .resume = &first_pos),
        first_pos,
        second_pos);
}

static void
test_live_sealed_materialization_retention_error_does_not_skip(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();
    n00b_query_view_t *view = live_view_ok(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);

    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 30, r"error", 3201);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(ctx.store, 31, r"error", 3202);
    n00b_store_pos_t first_pos = entry_pos(first, 0);
    n00b_store_pos_t second_pos = entry_pos(second, 0);

    auto scan_r = n00b_query_live_tail_scan_once(view);
    CHECK(n00b_result_is_ok(scan_r));
    CHECK(n00b_result_get(scan_r) == 2);

    auto pending_r = n00b_query_live_tail_pending_count(view);
    CHECK(n00b_result_is_ok(pending_r));
    CHECK(n00b_result_get(pending_r) == 2);

    auto drop_r = n00b_store_drop_sealed_shard(ctx.store,
                                               entry_shard_id(first));
    CHECK(n00b_result_is_ok(drop_r));

    expect_next_snapshot_retention(n00b_query_cursor_next(cursor),
                                   first_pos,
                                   second_pos);
    close_cursor_true(cursor);
    close_view_true(view);
}

static void
test_live_cursor_resident_pin_blocks_retention_until_cursor_close(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(ctx.store, 40, r"error", 3301);
    n00b_store_pos_t first_pos = entry_pos(first, 0);

    n00b_query_view_t *view = live_view_ok(&ctx);
    n00b_query_cursor_t *cursor = cursor_ok(view);
    expect_hit(cursor, first_pos);

    auto policy_r = n00b_store_shard_retention_policy_new(
        .drop_before_seal_ts = 4000);
    CHECK(n00b_result_is_ok(policy_r));

    auto retention_r = n00b_store_apply_shard_retention(ctx.store,
                                                        n00b_result_get(policy_r));
    CHECK(n00b_result_is_err(retention_r));
    CHECK(n00b_result_get_err(retention_r) == N00B_STORE_ERR_PINNED);

    close_cursor_true(cursor);

    retention_r = n00b_store_apply_shard_retention(ctx.store,
                                                   n00b_result_get(policy_r));
    CHECK(n00b_result_is_ok(retention_r));
    CHECK(n00b_result_get(retention_r) == 1);

    close_view_true(view);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_retained_live_resume_after_historical_cursor_token();
    test_live_hit_cursor_token_resumes_after_hot_position();
    test_live_resume_unavailable_positions_are_typed();
    test_live_sealed_materialization_retention_error_does_not_skip();
    test_live_cursor_resident_pin_blocks_retention_until_cursor_close();

    n00b_shutdown();
    return 0;
}

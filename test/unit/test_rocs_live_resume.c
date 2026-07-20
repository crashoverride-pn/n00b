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
test_live_pending_view_pin_blocks_manual_drop(void)
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
    CHECK(n00b_result_is_err(drop_r));
    CHECK(n00b_result_get_err(drop_r) == N00B_STORE_ERR_PINNED);

    expect_hit(cursor, first_pos);
    expect_hit(cursor, second_pos);
    close_cursor_true(cursor);
    close_view_true(view);
}

static void
test_live_view_pin_blocks_retention_until_view_close(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();
    ingest_and_seal(ctx.store, 35, r"error", 3351);
    ingest_and_seal(ctx.store, 36, r"error", 3352);

    n00b_query_view_t *view = live_view_ok(&ctx);

    auto policy_r = n00b_store_shard_retention_policy_new(
        .max_sealed_shards = 1);
    CHECK(n00b_result_is_ok(policy_r));

    auto retention_r = n00b_store_apply_shard_retention(ctx.store,
                                                        n00b_result_get(policy_r));
    CHECK(n00b_result_is_err(retention_r));
    CHECK(n00b_result_get_err(retention_r) == N00B_STORE_ERR_PINNED);

    close_view_true(view);

    retention_r = n00b_store_apply_shard_retention(ctx.store,
                                                   n00b_result_get(policy_r));
    CHECK(n00b_result_is_ok(retention_r));
    CHECK(n00b_result_get(retention_r) == 1);
}

static void
test_live_cursor_resident_pin_blocks_retention_until_view_close(void)
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
    CHECK(n00b_result_is_err(retention_r));
    CHECK(n00b_result_get_err(retention_r) == N00B_STORE_ERR_PINNED);

    close_view_true(view);

    retention_r = n00b_store_apply_shard_retention(ctx.store,
                                                   n00b_result_get(policy_r));
    CHECK(n00b_result_is_ok(retention_r));
    CHECK(n00b_result_get(retention_r) == 1);
}

// A resume token carries seal_ts through a full round-trip, and a legacy
// 48-char token (predating seal_ts) still decodes, reporting seal_ts 0.
static void
test_store_pos_seal_ts_encode_roundtrip(void)
{
    n00b_store_pos_t pos = {
        .generation = 3,
        .shard_id   = 7,
        .ordinal    = 11,
        .seal_ts    = 1784000000000000000ULL,
    };
    auto enc = n00b_store_pos_encode(pos);
    CHECK(n00b_result_is_ok(enc));
    n00b_string_t *tok = n00b_result_get(enc);
    CHECK(tok->u8_bytes == 64);

    auto dec = n00b_store_pos_decode(tok);
    CHECK(n00b_result_is_ok(dec));
    n00b_store_pos_t back = n00b_result_get(dec);
    CHECK(back.generation == pos.generation);
    CHECK(back.shard_id == pos.shard_id);
    CHECK(back.ordinal == pos.ordinal);
    CHECK(back.seal_ts == pos.seal_ts);

    // A legacy 48-char token (generation 0, shard_id 5, ordinal 10 = 0xa, no
    // seal_ts word) must still decode, reporting seal_ts 0. The length CHECK
    // guards the hand-written literal against a miscount.
    n00b_string_t *legacy =
        r"00000000000000000000000000000005000000000000000a";
    CHECK(legacy->u8_bytes == 48);
    auto legacy_dec = n00b_store_pos_decode(legacy);
    CHECK(n00b_result_is_ok(legacy_dec));
    n00b_store_pos_t lp = n00b_result_get(legacy_dec);
    CHECK(lp.generation == 0);
    CHECK(lp.shard_id == 5);
    CHECK(lp.ordinal == 10);
    CHECK(lp.seal_ts == 0);
}

// A watermark stranded ahead of the store (shard-id rewind after a rebuild)
// resumes by seal_ts: position-based resume finds nothing, but shards sealed
// strictly after the watermark's seal_ts are still surfaced. Normal (valid,
// mid-store) watermarks keep using position semantics and are unaffected.
static void
test_seal_ts_rewind_resume(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();

    n00b_store_catalog_entry_t *s1 = ingest_and_seal(ctx.store, 1, r"error", 1000);
    n00b_store_catalog_entry_t *s2 = ingest_and_seal(ctx.store, 2, r"error", 2000);
    n00b_store_catalog_entry_t *s3 = ingest_and_seal(ctx.store, 3, r"error", 3000);
    (void)s1;

    // From the beginning, all three sealed shards are backlog.
    auto bl0 = n00b_store_catalog_backlog(ctx.store, nullptr);
    CHECK(n00b_result_is_ok(bl0));
    CHECK(n00b_result_get(bl0).shards_remaining == 3);

    // Stranded watermark: shard_id past every catalog shard (rewind), seal_ts
    // between s1 and s2 (delivered through ~1500ns).
    n00b_store_pos_t base = entry_pos(s3, 0);
    n00b_store_pos_t stranded = {
        .generation = base.generation,
        .shard_id   = entry_shard_id(s3) + 1000,
        .ordinal    = 0,
        .seal_ts    = 1500,
    };

    // Position-only resume would report 0; the seal_ts fallback reports the two
    // shards sealed strictly after 1500: s2 (2000) and s3 (3000).
    auto bl = n00b_store_catalog_backlog(ctx.store, &stranded);
    CHECK(n00b_result_is_ok(bl));
    CHECK(n00b_result_get(bl).shards_remaining == 2);

    // Resume lands at the OLDEST shard sealed after 1500 = s2, from ordinal 0.
    auto after = n00b_store_catalog_visible_entry_after(ctx.store, &stranded);
    CHECK(n00b_result_is_ok(after));
    auto after_opt = n00b_result_get(after);
    CHECK(n00b_option_is_set(after_opt));
    n00b_store_catalog_resume_entry_t re = n00b_option_get(after_opt);
    CHECK(re.shard_id == entry_shard_id(s2));
    CHECK(re.start_ordinal == 0);

    // Normal, position-valid watermark (at s2) still resumes by position: only
    // s3 remains. The seal_ts fallback must NOT engage here.
    n00b_store_pos_t mid = entry_pos(s2, 0);
    mid.seal_ts = 2000;
    auto blm = n00b_store_catalog_backlog(ctx.store, &mid);
    CHECK(n00b_result_is_ok(blm));
    CHECK(n00b_result_get(blm).shards_remaining == 1);
}

// End-to-end record-stream resume for a stranded watermark: the stream skips
// shards sealed at/before the watermark's seal_ts, delivers the newer sealed
// shards AND the live hot tail, and stamps emitted sealed positions with their
// shard's seal_ts so the next watermark self-anchors.
static void
test_seal_ts_rewind_stream_open(void)
{
    live_resume_ctx_t ctx = new_live_resume_ctx();

    n00b_store_catalog_entry_t *s1 = ingest_and_seal(ctx.store, 1, r"error", 1000);
    n00b_store_catalog_entry_t *s2 = ingest_and_seal(ctx.store, 2, r"error", 2000);
    n00b_store_catalog_entry_t *s3 = ingest_and_seal(ctx.store, 3, r"error", 3000);
    (void)s1;
    (void)s2;
    ingest_hot(ctx.store, 4, r"error"); // live, unsealed

    n00b_store_pos_t base = entry_pos(s3, 0);
    n00b_store_pos_t stranded = {
        .generation = base.generation,
        .shard_id   = entry_shard_id(s3) + 1000,
        .ordinal    = 0,
        .seal_ts    = 1500,
    };

    auto stream_r = n00b_store_record_stream_open(ctx.store, &stranded);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    int      count               = 0;
    bool     saw_hot             = false;
    uint64_t last_sealed_seal_ts = 0;
    for (;;) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto item_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(item_opt)) {
            break;
        }
        n00b_store_record_stream_item_t item = n00b_option_get(item_opt);
        count++;
        if (item.hot) {
            saw_hot = true;
        } else {
            last_sealed_seal_ts = item.pos.seal_ts;
        }
    }
    // s1 (sealed 1000 <= 1500) skipped; s2 + s3 + hot delivered.
    CHECK(count == 3);
    CHECK(saw_hot);
    CHECK(last_sealed_seal_ts == 3000);

    auto close_r = n00b_store_record_stream_close(stream);
    CHECK(n00b_result_is_ok(close_r));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_retained_live_resume_after_historical_cursor_token();
    test_live_hit_cursor_token_resumes_after_hot_position();
    test_live_resume_unavailable_positions_are_typed();
    test_live_pending_view_pin_blocks_manual_drop();
    test_live_view_pin_blocks_retention_until_view_close();
    test_live_cursor_resident_pin_blocks_retention_until_view_close();
    test_store_pos_seal_ts_encode_roundtrip();
    test_seal_ts_rewind_resume();
    test_seal_ts_rewind_stream_open();

    n00b_shutdown();
    return 0;
}

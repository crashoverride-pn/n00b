/* test/unit/test_rocs_linear_cursor.c - bidirectional linear record cursor.
 *
 * Covers: a store with MULTIPLE sealed shards; seek to an arbitrary record;
 * step forward to the end and backward to the start verifying record identity
 * and order both directions; resume n00b_store_pos_t round-trip; and that
 * stepping does NOT depend on the per-batch snapshot ordset (the linear cursor
 * uses its own next/prev/seek surface and never calls n00b_query_cursor_next).
 */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#define CHECK(expr)                                                           \
    do {                                                                      \
        n00b_require((expr), "test check failed: " #expr);                   \
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
new_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs)
{
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs-linear", new_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_new(int64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    return record;
}

static void
ingest_record(n00b_store_t *store, int64_t id)
{
    auto ingest_r = n00b_store_ingest(store, record_new(id));
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
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

// store->active_pins counts every active resource pin: the query view holds one
// for its whole lifetime, and each held resident-shard handle adds one more.
// So with one open view, this is 1 (view) + (resident handles currently held).
static uint64_t
resident_pins(n00b_store_t *store)
{
    auto stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    return n00b_result_get(stats_r).active_pins;
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

typedef struct {
    n00b_store_t               *store;
    n00b_filter_t              *filter;
    // Five records across three sealed shards, in seal/durable order:
    // shard A: id 10 (ord 0), id 11 (ord 1)
    // shard B: id 20 (ord 0), id 21 (ord 1)
    // shard C: id 30 (ord 0)
    n00b_store_pos_t            pos[5];
    int64_t                     id[5];
} sample_t;

static sample_t
new_sample(void)
{
    sample_t s = {};
    s.store  = open_store(new_memory_vfs());
    s.filter = exists_id_filter();

    ingest_record(s.store, 10);
    ingest_record(s.store, 11);
    n00b_store_catalog_entry_t *a = seal_current(s.store, 901);

    ingest_record(s.store, 20);
    ingest_record(s.store, 21);
    n00b_store_catalog_entry_t *b = seal_current(s.store, 902);

    ingest_record(s.store, 30);
    n00b_store_catalog_entry_t *c = seal_current(s.store, 903);

    s.pos[0] = entry_pos(a, 0);
    s.pos[1] = entry_pos(a, 1);
    s.pos[2] = entry_pos(b, 0);
    s.pos[3] = entry_pos(b, 1);
    s.pos[4] = entry_pos(c, 0);
    s.id[0]  = 10;
    s.id[1]  = 11;
    s.id[2]  = 20;
    s.id[3]  = 21;
    s.id[4]  = 30;
    return s;
}

static n00b_query_view_t *
open_view(sample_t *s)
{
    auto view_r = n00b_query_view(s->store, s->filter);
    CHECK(n00b_result_is_ok(view_r));
    return n00b_result_get(view_r);
}

static int64_t
hit_id(n00b_query_hit_t *hit)
{
    auto json_r = n00b_query_hit_json_copy(hit);
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *json = n00b_result_get(json_r);
    CHECK(n00b_json_is_object(json));
    n00b_json_node_t *id = n00b_json_object_get(json, r"id");
    CHECK(id != nullptr);
    CHECK(n00b_json_is_int(id));
    return n00b_json_as_i64(id);
}

// Step next, require some(hit), and require it to be (id[i], pos[i]).
static n00b_query_hit_t *
expect_next(n00b_query_linear_cursor_t *cursor, sample_t *s, int i)
{
    auto next_r = n00b_query_linear_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    n00b_option_t(n00b_query_hit_t *) opt = n00b_result_get(next_r);
    CHECK(n00b_option_is_set(opt));
    n00b_query_hit_t *hit = n00b_option_get(opt);

    auto pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(pos_r), s->pos[i]) == 0);
    CHECK(hit_id(hit) == s->id[i]);
    return hit;
}

static n00b_query_hit_t *
expect_prev(n00b_query_linear_cursor_t *cursor, sample_t *s, int i)
{
    auto prev_r = n00b_query_linear_cursor_prev(cursor);
    CHECK(n00b_result_is_ok(prev_r));
    n00b_option_t(n00b_query_hit_t *) opt = n00b_result_get(prev_r);
    CHECK(n00b_option_is_set(opt));
    n00b_query_hit_t *hit = n00b_option_get(opt);

    auto pos_r = n00b_query_hit_pos(hit);
    CHECK(n00b_result_is_ok(pos_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(pos_r), s->pos[i]) == 0);
    CHECK(hit_id(hit) == s->id[i]);
    return hit;
}

static void
expect_next_none(n00b_query_linear_cursor_t *cursor)
{
    auto next_r = n00b_query_linear_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));
}

static void
expect_prev_none(n00b_query_linear_cursor_t *cursor)
{
    auto prev_r = n00b_query_linear_cursor_prev(cursor);
    CHECK(n00b_result_is_ok(prev_r));
    CHECK(!n00b_option_is_set(n00b_result_get(prev_r)));
}

// Forward to the end then backward to the start; record identity/order in both
// directions across all three sealed shards.
static void
test_forward_then_backward(void)
{
    sample_t            s    = new_sample();
    n00b_query_view_t  *view = open_view(&s);

    auto cursor_r = n00b_query_linear_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_linear_cursor_t *cursor = n00b_result_get(cursor_r);

    // Baseline: the open view holds exactly one resource pin.
    CHECK(resident_pins(s.store) == 1);

    // The cursor holds at most one resident shard pin during the walk, so the
    // store-wide pin count never exceeds the view pin (1) plus one resident (1).
    expect_prev_none(cursor); // before-first: prev is none.
    for (int i = 0; i < 5; i++) {
        expect_next(cursor, &s, i);
        CHECK(resident_pins(s.store) <= 2);
    }
    expect_next_none(cursor); // after-last.
    expect_next_none(cursor); // idempotent at end.

    // Backward from after-last to start.
    for (int i = 4; i >= 0; i--) {
        expect_prev(cursor, &s, i);
        CHECK(resident_pins(s.store) <= 2);
    }
    expect_prev_none(cursor); // before-first.

    auto close_r = n00b_query_linear_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
    // Cursor's resident pin released on close; only the view pin remains.
    CHECK(resident_pins(s.store) == 1);

    auto vclose_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(vclose_r));
    CHECK(active_pins(s.store) == 0);
}

// Seek to an arbitrary record, then verify next yields strictly-after and prev
// yields at-or-before, matching resume watermark semantics.
static void
test_seek_arbitrary(void)
{
    sample_t            s    = new_sample();
    n00b_query_view_t  *view = open_view(&s);

    auto cursor_r = n00b_query_linear_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_linear_cursor_t *cursor = n00b_result_get(cursor_r);

    // Seek to pos[2] (shard B ord 0, id 20). next must yield pos[3] (id 21).
    auto seek_r = n00b_query_linear_cursor_seek(cursor, s.pos[2]);
    CHECK(n00b_result_is_ok(seek_r));
    CHECK(n00b_result_get(seek_r));

    expect_next(cursor, &s, 3); // strictly after pos[2].
    // prev from on-record(3) -> 2.
    expect_prev(cursor, &s, 2);
    // prev again -> 1 (crosses shard B -> A boundary).
    expect_prev(cursor, &s, 1);

    // Re-seek to the very last record and confirm next is none, prev is itself.
    seek_r = n00b_query_linear_cursor_seek(cursor, s.pos[4]);
    CHECK(n00b_result_is_ok(seek_r));
    expect_next_none(cursor);       // nothing strictly after the last record.
    expect_prev(cursor, &s, 4);     // at-or-before pos[4] is pos[4].

    // Seek then prev as the FIRST step (no next first): prev must yield the
    // record at-or-before pos, i.e. the anchor itself. This is the seek
    // watermark contract for backward draining. pos[2] is the first ordinal of
    // shard B, so a buggy implementation crosses into shard A and returns
    // pos[1] instead of pos[2].
    seek_r = n00b_query_linear_cursor_seek(cursor, s.pos[2]);
    CHECK(n00b_result_is_ok(seek_r));
    expect_prev(cursor, &s, 2);     // at-or-before pos[2] is pos[2].
    expect_prev(cursor, &s, 1);     // then the record before it.

    // Same first-step-prev contract at the very first record (anchor at ord 0
    // of the first shard): prev yields pos[0], then prev is none.
    seek_r = n00b_query_linear_cursor_seek(cursor, s.pos[0]);
    CHECK(n00b_result_is_ok(seek_r));
    expect_prev(cursor, &s, 0);     // at-or-before pos[0] is pos[0].
    expect_prev_none(cursor);       // nothing before the first record.

    // After seek+prev to the anchor, next must still yield strictly-after the
    // seek pos (not re-yield the anchor): seek(pos[2]) then prev (=pos[2]) then
    // next must be pos[3].
    seek_r = n00b_query_linear_cursor_seek(cursor, s.pos[2]);
    CHECK(n00b_result_is_ok(seek_r));
    expect_prev(cursor, &s, 2);
    expect_next(cursor, &s, 3);     // strictly after the seek pos.

    // Seek before everything: a synthetic position whose shard sorts before the
    // first sealed shard (shard ids start at 1, so shard 0 sorts first).
    n00b_store_pos_t before = s.pos[0];
    before.shard_id         = 0;
    before.ordinal          = 0;
    seek_r = n00b_query_linear_cursor_seek(cursor, before);
    CHECK(n00b_result_is_ok(seek_r));
    expect_next(cursor, &s, 0); // first in-window record.

    auto close_r = n00b_query_linear_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_r));
    auto vclose_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(vclose_r));
}

// The position emitted by the linear cursor round-trips through encode/decode
// and resumes strictly-after when passed to a fresh view's .resume.
static void
test_position_round_trip(void)
{
    sample_t            s    = new_sample();
    n00b_query_view_t  *view = open_view(&s);

    auto cursor_r = n00b_query_linear_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_linear_cursor_t *cursor = n00b_result_get(cursor_r);

    // Advance to pos[2] (id 20).
    expect_next(cursor, &s, 0);
    expect_next(cursor, &s, 1);
    n00b_query_hit_t *hit = expect_next(cursor, &s, 2);
    (void)hit;

    auto cpos_r = n00b_query_linear_cursor_position(cursor);
    CHECK(n00b_result_is_ok(cpos_r));
    CHECK(n00b_option_is_set(n00b_result_get(cpos_r)));
    n00b_store_pos_t emitted = n00b_option_get(n00b_result_get(cpos_r));
    CHECK(n00b_store_pos_compare(emitted, s.pos[2]) == 0);

    // Encode -> decode round-trip.
    auto enc_r = n00b_store_pos_encode(emitted);
    CHECK(n00b_result_is_ok(enc_r));
    auto dec_r = n00b_store_pos_decode(n00b_result_get(enc_r));
    CHECK(n00b_result_is_ok(dec_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(dec_r), emitted) == 0);

    auto close_r = n00b_query_linear_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_r));
    auto vclose_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(vclose_r));

    // A new view resumed at the emitted position; a linear cursor over it must
    // start strictly AFTER pos[2], i.e. its first next is pos[3] (id 21).
    n00b_store_pos_t resume = n00b_result_get(dec_r);
    auto rview_r = n00b_query_view(s.store, s.filter, .resume = &resume);
    CHECK(n00b_result_is_ok(rview_r));
    n00b_query_view_t *rview = n00b_result_get(rview_r);

    auto rcursor_r = n00b_query_linear_cursor(rview);
    CHECK(n00b_result_is_ok(rcursor_r));
    n00b_query_linear_cursor_t *rcursor = n00b_result_get(rcursor_r);

    expect_next(rcursor, &s, 3); // strictly after the resume position.
    expect_next(rcursor, &s, 4);
    expect_next_none(rcursor);
    // prev from before pos[3] is none (resume window excludes pos[2] and older).
    expect_prev(rcursor, &s, 4);
    expect_prev(rcursor, &s, 3);
    expect_prev_none(rcursor);

    auto rclose_r = n00b_query_linear_cursor_close(rcursor);
    CHECK(n00b_result_is_ok(rclose_r));
    auto rvclose_r = n00b_query_view_close(rview);
    CHECK(n00b_result_is_ok(rvclose_r));
    CHECK(active_pins(s.store) == 0);
}

// Demonstrate the linear walk does not go through the snapshot cursor path:
// it never constructs an n00b_query_cursor_t and never calls
// n00b_query_cursor_next (which is the O(records) snapshot/ordset path). The
// whole multi-shard store drains via next() only, and view close shows no
// leaked snapshot cursor pins. Two independent linear cursors over the same
// view step independently (no shared ordset / shared scan state).
static void
test_no_snapshot_ordset_path(void)
{
    sample_t            s    = new_sample();
    n00b_query_view_t  *view = open_view(&s);

    auto c1_r = n00b_query_linear_cursor(view);
    CHECK(n00b_result_is_ok(c1_r));
    n00b_query_linear_cursor_t *c1 = n00b_result_get(c1_r);

    auto c2_r = n00b_query_linear_cursor(view);
    CHECK(n00b_result_is_ok(c2_r));
    n00b_query_linear_cursor_t *c2 = n00b_result_get(c2_r);

    // c1 walks fully forward; c2 stays at its seek anchor. Independent state.
    auto seek_r = n00b_query_linear_cursor_seek(c2, s.pos[3]);
    CHECK(n00b_result_is_ok(seek_r));

    for (int i = 0; i < 5; i++) {
        expect_next(c1, &s, i);
    }
    expect_next_none(c1);

    // c2 is independent: its next is strictly after pos[3] -> pos[4].
    expect_next(c2, &s, 4);
    expect_next_none(c2);

    auto vclose_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(vclose_r));
    CHECK(active_pins(s.store) == 0);
    CHECK(resident_pins(s.store) == 0);

    // Cursors are invalidated by view close; further steps report closed.
    auto after_r = n00b_query_linear_cursor_next(c1);
    CHECK(n00b_result_is_err(after_r));
    CHECK(n00b_result_get_err(after_r) == N00B_QUERY_ERR_CLOSED);
}

// Live views must reject linear-cursor construction (snapshot-only).
static void
test_live_rejected(void)
{
    sample_t s = new_sample();

    auto view_r = n00b_query_view(s.store,
                                  s.filter,
                                  .mode = N00B_QUERY_MODE_LIVE);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_linear_cursor(view);
    CHECK(n00b_result_is_err(cursor_r));
    CHECK(n00b_result_get_err(cursor_r) == N00B_QUERY_ERR_UNSUPPORTED_MODE);

    auto vclose_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(vclose_r));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_forward_then_backward();
    test_seek_arbitrary();
    test_position_round_trip();
    test_no_snapshot_ordset_path();
    test_live_rejected();

    n00b_shutdown();
    return 0;
}

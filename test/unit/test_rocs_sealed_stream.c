/* test/unit/test_rocs_sealed_stream.c - sealed-only bounded record streams.
 *
 * Contracts under test for n00b_store_record_stream_open_sealed and
 * n00b_store_record_stream_sealed_bound:
 *
 *   1. Sealed only. The hot shard (still accepting writes) never appears in
 *      the slice, even when it holds records at open time.
 *   2. Bounds. `after` is a strict resume position; `through` is inclusive
 *      and caps the through-shard's record count exactly. A `through` that
 *      does not resolve to a visible sealed record fails with
 *      N00B_STORE_ERR_RETENTION instead of short-reading.
 *   3. Order. Items arrive in ascending position order.
 *   4. Stability. sealed_bound names the newest position in the slice, is
 *      none for an empty slice, and does not move when later seals land.
 *   5. Pinning. Retention cannot drop a shard inside an open stream's slice;
 *      residency trim cannot make the slice unreadable.
 */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
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
make_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_store(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       make_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static void
ingest_marker(n00b_store_t *store, int64_t shard_tag, int64_t i)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_string_t    *marker =
        n00b_cformat("sealed-[|#|]-[|#|]-end", shard_tag, i);
    n00b_json_object_put_n00b(record,
                              r"marker",
                              n00b_json_string_new_from_n00b(marker));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record)));
}

static n00b_store_catalog_entry_t *
seal_shard(n00b_store_t *store,
           int64_t       shard_tag,
           int64_t       record_count,
           uint64_t      seal_ts)
{
    for (int64_t i = 0; i < record_count; i++) {
        ingest_marker(store, shard_tag, i);
    }
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

// Walk a sealed stream to exhaustion: every item must be non-hot, carry a
// valid span, and arrive in strictly ascending position order. Returns the
// item count and (optionally) the positions seen.
static int64_t
drain_sealed(n00b_store_record_stream_t *stream,
             n00b_store_pos_t           *positions,
             int64_t                     positions_cap)
{
    int64_t          count    = 0;
    bool             have_pos = false;
    n00b_store_pos_t last_pos = {};
    while (true) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next = n00b_result_get(next_r);
        if (!n00b_option_is_set(next)) {
            break;
        }
        n00b_store_record_stream_item_t item = n00b_option_get(next);
        CHECK(!item.hot);
        CHECK(item.bytes.data != nullptr);
        CHECK(item.bytes.byte_len != 0);
        if (have_pos) {
            CHECK(n00b_store_pos_compare(last_pos, item.pos) < 0);
        }
        last_pos = item.pos;
        have_pos = true;
        if (positions != nullptr && count < positions_cap) {
            positions[count] = item.pos;
        }
        count++;
    }
    return count;
}

static n00b_store_pos_t
bound_pos(n00b_store_record_stream_t *stream)
{
    auto bound_r = n00b_store_record_stream_sealed_bound(stream);
    CHECK(n00b_result_is_ok(bound_r));
    auto bound = n00b_result_get(bound_r);
    CHECK(n00b_option_is_set(bound));
    return n00b_option_get(bound);
}

static void
check_bound_none(n00b_store_record_stream_t *stream)
{
    auto bound_r = n00b_store_record_stream_sealed_bound(stream);
    CHECK(n00b_result_is_ok(bound_r));
    CHECK(!n00b_option_is_set(n00b_result_get(bound_r)));
}

static void
check_no_pins(n00b_store_t *store)
{
    auto stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    CHECK(n00b_result_get(stats_r).active_pins == 0);
}

static void
test_empty_store_yields_empty_slice(void)
{
    n00b_store_t *store = open_store();

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    check_bound_none(stream);
    CHECK(drain_sealed(stream, nullptr, 0) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));
    check_no_pins(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_slice_excludes_hot_shard(void)
{
    n00b_store_t *store = open_store();

    // Hot-only store: the slice must be empty, not expose hot records.
    ingest_marker(store, 0, 0);
    ingest_marker(store, 0, 1);

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    check_bound_none(stream);
    CHECK(drain_sealed(stream, nullptr, 0) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 100);
    CHECK(n00b_result_is_ok(seal_r));
    n00b_store_catalog_entry_t *sealed = n00b_result_get(seal_r);

    // New hot tail on top of one sealed shard: only the sealed records show.
    ingest_marker(store, 1, 0);

    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    stream = n00b_result_get(stream_r);

    n00b_store_pos_t positions[4] = {};
    CHECK(drain_sealed(stream, positions, 4) == 2);
    CHECK(n00b_store_pos_compare(positions[0], entry_pos(sealed, 0)) == 0);
    CHECK(n00b_store_pos_compare(positions[1], entry_pos(sealed, 1)) == 0);
    n00b_store_pos_t bound = bound_pos(stream);
    CHECK(n00b_store_pos_compare(bound, entry_pos(sealed, 1)) == 0);
    // pos_compare ignores seal_ts; the bound must carry the shard's seal
    // timestamp so a watermark built from it self-anchors.
    CHECK(bound.seal_ts == 100);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));
    check_no_pins(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_after_and_through_bounds(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 2, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 3, 200);
    n00b_store_catalog_entry_t *c = seal_shard(store, 3, 2, 300);

    // Unbounded: the whole sealed history, ascending, bound at the newest.
    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    n00b_store_pos_t positions[8] = {};
    CHECK(drain_sealed(stream, positions, 8) == 7);
    CHECK(n00b_store_pos_compare(positions[0], entry_pos(a, 0)) == 0);
    CHECK(n00b_store_pos_compare(positions[6], entry_pos(c, 1)) == 0);
    CHECK(n00b_store_pos_compare(bound_pos(stream), entry_pos(c, 1)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // `after` is strict: resuming at (a,0) starts at (a,1).
    n00b_store_pos_t after = entry_pos(a, 0);
    stream_r = n00b_store_record_stream_open_sealed(store, &after, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    stream = n00b_result_get(stream_r);
    CHECK(drain_sealed(stream, positions, 8) == 6);
    CHECK(n00b_store_pos_compare(positions[0], entry_pos(a, 1)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // `through` is inclusive and caps the through-shard's record count: the
    // slice ends at exactly (b,1) even though b holds a third record.
    after                    = entry_pos(a, 1);
    n00b_store_pos_t through = entry_pos(b, 1);
    stream_r = n00b_store_record_stream_open_sealed(store, &after, &through);
    CHECK(n00b_result_is_ok(stream_r));
    stream = n00b_result_get(stream_r);
    CHECK(n00b_store_pos_compare(bound_pos(stream), entry_pos(b, 1)) == 0);
    CHECK(drain_sealed(stream, positions, 8) == 2);
    CHECK(n00b_store_pos_compare(positions[0], entry_pos(b, 0)) == 0);
    CHECK(n00b_store_pos_compare(positions[1], entry_pos(b, 1)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // Bound at the through-shard's first record: later shards drop out too.
    through  = entry_pos(b, 0);
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, &through);
    CHECK(n00b_result_is_ok(stream_r));
    stream = n00b_result_get(stream_r);
    CHECK(drain_sealed(stream, positions, 8) == 3);
    CHECK(n00b_store_pos_compare(positions[2], entry_pos(b, 0)) == 0);
    CHECK(n00b_store_pos_compare(bound_pos(stream), entry_pos(b, 0)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // A resume past the whole slice yields an empty stream, bound none.
    after    = entry_pos(c, 1);
    stream_r = n00b_store_record_stream_open_sealed(store, &after, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    stream = n00b_result_get(stream_r);
    check_bound_none(stream);
    CHECK(drain_sealed(stream, nullptr, 0) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    check_no_pins(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_unresolvable_through_fails_typed(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 2, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 1, 200);

    // Ordinal past the through-shard's record count.
    n00b_store_pos_t through = entry_pos(a, 2);
    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // Shard id that never existed.
    through = (n00b_store_pos_t){
        .generation = entry_pos(a, 0).generation,
        .shard_id   = 999999,
        .ordinal    = 0,
    };
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // An id one past the newest sealed shard -- the hot shard's id when ids
    // run sequentially, and an unknown id otherwise; both must be
    // unresolvable even while the hot shard holds live records.
    ingest_marker(store, 3, 0);
    through = (n00b_store_pos_t){
        .generation = entry_pos(b, 0).generation,
        .shard_id   = entry_shard_id(b) + 1,
        .ordinal    = 0,
    };
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // A shard retention already dropped.
    auto drop_r = n00b_store_drop_sealed_shard(store,
                                               entry_shard_id(a),
                                               .drop_reason = r"test");
    CHECK(n00b_result_is_ok(drop_r));
    through  = entry_pos(a, 0);
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // A quarantined shard: still in the catalog, no longer visible sealed.
    auto quarantine_r = n00b_store_quarantine_shard(store,
                                                    entry_shard_id(b),
                                                    .reason = r"test");
    CHECK(n00b_result_is_ok(quarantine_r));
    through  = entry_pos(b, 0);
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_retention_refused_inside_open_slice(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 1, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 1, 200);

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    auto drop_r = n00b_store_drop_sealed_shard(store,
                                               entry_shard_id(a),
                                               .drop_reason = r"test");
    CHECK(n00b_result_is_err(drop_r));
    CHECK(n00b_result_get_err(drop_r) == N00B_STORE_ERR_PINNED);

    auto policy_r = n00b_store_shard_retention_policy_new(
        .drop_before_seal_ts = 10000,
        .drop_reason         = r"test");
    CHECK(n00b_result_is_ok(policy_r));
    auto retention_r = n00b_store_apply_shard_retention(
        store,
        n00b_result_get(policy_r));
    CHECK(n00b_result_is_err(retention_r));
    CHECK(n00b_result_get_err(retention_r) == N00B_STORE_ERR_PINNED);

    // Both shards must still be present and fully readable via the stream.
    n00b_store_pos_t positions[2] = {};
    CHECK(drain_sealed(stream, positions, 2) == 2);
    CHECK(n00b_store_pos_compare(positions[0], entry_pos(a, 0)) == 0);
    CHECK(n00b_store_pos_compare(positions[1], entry_pos(b, 0)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // With the stream closed the same retention pass drains the store.
    retention_r = n00b_store_apply_shard_retention(store,
                                                   n00b_result_get(policy_r));
    CHECK(n00b_result_is_ok(retention_r));
    CHECK(n00b_result_get(retention_r) == 2);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_interior_drop_refuses_resume(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 2, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 2, 200);
    n00b_store_catalog_entry_t *c = seal_shard(store, 3, 2, 300);

    // A projection consumed through a's last record, then retention dropped
    // the interior shard before the next run.
    n00b_store_pos_t watermark = entry_pos(a, 1);
    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(
        store,
        entry_shard_id(b),
        .drop_reason = r"test")));

    // Resuming above the gap must refuse -- bounded or not -- rather than
    // deliver only c and let the watermark advance past b unread.
    n00b_store_pos_t through  = entry_pos(c, 1);
    auto             stream_r = n00b_store_record_stream_open_sealed(store,
                                                                     &watermark,
                                                                     &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    stream_r = n00b_store_record_stream_open_sealed(store,
                                                    &watermark,
                                                    nullptr);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // A fresh full read makes no continuity claim: it sees what survives.
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    n00b_store_pos_t positions[4] = {};
    CHECK(drain_sealed(stream, positions, 4) == 4);
    CHECK(n00b_store_pos_compare(positions[1], entry_pos(a, 1)) == 0);
    CHECK(n00b_store_pos_compare(positions[2], entry_pos(c, 0)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // Once the caller has explicitly re-anchored past the loss, resuming
    // works again: the refusal is a policy gate, not a wedge.
    n00b_store_pos_t reanchored = entry_pos(c, 1);
    stream_r = n00b_store_record_stream_open_sealed(store,
                                                    &reanchored,
                                                    nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    stream = n00b_result_get(stream_r);
    check_bound_none(stream);
    CHECK(drain_sealed(stream, nullptr, 0) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    check_no_pins(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_mid_shard_drop_refuses_resume(void)
{
    n00b_store_t *store = open_store();

    (void)seal_shard(store, 1, 2, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 2, 200);

    // A bounded projection stopped mid-shard, then retention dropped that
    // shard: only a watermark at the shard's LAST record proves it was fully
    // consumed, so resuming from the middle must refuse.
    n00b_store_pos_t mid_watermark = entry_pos(b, 0);
    n00b_store_pos_t end_watermark = entry_pos(b, 1);
    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(
        store,
        entry_shard_id(b),
        .drop_reason = r"test")));

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         &mid_watermark,
                                                         nullptr);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // From the dropped shard's final record the resume is legitimate.
    stream_r = n00b_store_record_stream_open_sealed(store,
                                                    &end_watermark,
                                                    nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    check_bound_none(stream);
    CHECK(drain_sealed(stream, nullptr, 0) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    check_no_pins(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_interior_quarantine_refuses_resume(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 2, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 2, 200);
    n00b_store_catalog_entry_t *c = seal_shard(store, 3, 2, 300);

    // A projection consumed through a, then the interior shard was
    // quarantined: its records are as unreadable as a retention gap, and the
    // through endpoint still resolving must not mask that.
    n00b_store_pos_t watermark = entry_pos(a, 1);
    CHECK(n00b_result_is_ok(n00b_store_quarantine_shard(
        store,
        entry_shard_id(b),
        .reason = r"test")));

    n00b_store_pos_t through  = entry_pos(c, 1);
    auto             stream_r = n00b_store_record_stream_open_sealed(store,
                                                                     &watermark,
                                                                     &through);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    stream_r = n00b_store_record_stream_open_sealed(store,
                                                    &watermark,
                                                    nullptr);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    // A full re-baseline is the explicit escape hatch: it sees a and c.
    stream_r = n00b_store_record_stream_open_sealed(store, nullptr, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    n00b_store_pos_t positions[4] = {};
    CHECK(drain_sealed(stream, positions, 4) == 4);
    CHECK(n00b_store_pos_compare(positions[2], entry_pos(c, 0)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    // Dropping the quarantined shard hands the gap to the drop guard: the
    // stale watermark keeps refusing.
    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(
        store,
        entry_shard_id(b),
        .drop_reason = r"test")));
    stream_r = n00b_store_record_stream_open_sealed(store,
                                                    &watermark,
                                                    nullptr);
    CHECK(n00b_result_is_err(stream_r));
    CHECK(n00b_result_get_err(stream_r) == N00B_STORE_ERR_RETENTION);
    check_no_pins(store);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_consumed_drop_does_not_refuse_resume(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 2, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 2, 200);

    // Dropping a shard the watermark already covers is routine retention of
    // consumed history, not a gap; the resume must keep working.
    n00b_store_pos_t watermark = entry_pos(a, 1);
    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(
        store,
        entry_shard_id(a),
        .drop_reason = r"test")));

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         &watermark,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    n00b_store_pos_t positions[2] = {};
    CHECK(drain_sealed(stream, positions, 2) == 2);
    CHECK(n00b_store_pos_compare(positions[0], entry_pos(b, 0)) == 0);
    CHECK(n00b_store_pos_compare(bound_pos(stream), entry_pos(b, 1)) == 0);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    check_no_pins(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_sealed_bound_stable_across_later_seals(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 2, 100);

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    CHECK(n00b_store_pos_compare(bound_pos(stream), entry_pos(a, 1)) == 0);

    // Later seals and a fresh hot tail must not move the bound or leak new
    // records into the already-open slice.
    (void)seal_shard(store, 2, 2, 200);
    ingest_marker(store, 3, 0);

    CHECK(n00b_store_pos_compare(bound_pos(stream), entry_pos(a, 1)) == 0);
    CHECK(drain_sealed(stream, nullptr, 0) == 2);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_residency_trim_keeps_open_slice_readable(void)
{
    n00b_store_t *store = open_store();

    n00b_store_catalog_entry_t *a = seal_shard(store, 1, 1, 100);
    n00b_store_catalog_entry_t *b = seal_shard(store, 2, 1, 200);

    // Make b resident (then released) so the trim below has an unpinned image
    // to unload; without this it can no-op and the re-acquire path would go
    // untested.
    auto resident_r = n00b_store_resident_shard_acquire(store, b);
    CHECK(n00b_result_is_ok(resident_r));
    CHECK(n00b_result_is_ok(
        n00b_store_resident_shard_map(n00b_result_get(resident_r))));
    CHECK(n00b_result_is_ok(
        n00b_store_resident_shard_release(n00b_result_get(resident_r))));

    auto stream_r = n00b_store_record_stream_open_sealed(store,
                                                         nullptr,
                                                         nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    // Read a's record first so the stream is mid-slice when the trim lands.
    auto next_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(next_r));
    auto next = n00b_result_get(next_r);
    CHECK(n00b_option_is_set(next));
    CHECK(n00b_store_pos_compare(n00b_option_get(next).pos,
                                 entry_pos(a, 0)) == 0);

    // Trim must actually unload b's image, and the open slice must stay
    // readable afterward (b re-acquires from its backing object, which the
    // stream's pins keep alive).
    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) != 0);

    next_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(next_r));
    next = n00b_result_get(next_r);
    CHECK(n00b_option_is_set(next));
    n00b_store_record_stream_item_t item = n00b_option_get(next);
    CHECK(n00b_store_pos_compare(item.pos, entry_pos(b, 0)) == 0);
    CHECK(item.bytes.data != nullptr);
    CHECK(item.bytes.byte_len != 0);

    next_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));

    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_empty_store_yields_empty_slice();
    test_slice_excludes_hot_shard();
    test_after_and_through_bounds();
    test_unresolvable_through_fails_typed();
    test_retention_refused_inside_open_slice();
    test_interior_drop_refuses_resume();
    test_mid_shard_drop_refuses_resume();
    test_interior_quarantine_refuses_resume();
    test_consumed_drop_does_not_refuse_resume();
    test_sealed_bound_stable_across_later_seals();
    test_residency_trim_keeps_open_slice_readable();

    n00b_print(r"rocs_sealed_stream: ok");
    return 0;
}

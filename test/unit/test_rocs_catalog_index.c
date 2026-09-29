/* test/unit/test_rocs_catalog_index.c - catalog reads must not walk the
 * catalog.
 *
 * A shard-id lookup, the i-th visible entry, the tail snapshot a query copies,
 * the backlog, and the stats behind health probes all read a sorted index of
 * the catalog. Each test checks the answer against a brute-force walk over
 * the raw catalog and bounds the number of catalog entries the read
 * examined, using the debug-only visit counter.
 */
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include "internal/rocs/store.h"
#include <rocs/shard.h>
#include <rocs/store.h>
#include "test_check.h"

#ifndef N00B_DEBUG
#error "test_rocs_catalog_index requires N00B_DEBUG for the visit counter"
#endif

enum { SHARDS = 160 };

// A binary search over SHARDS entries probes at most ceil(log2(160)) = 8.
enum { LOG_PROBES = 8 };

typedef struct {
    n00b_store_t               *store;
    n00b_store_catalog_entry_t *entries[SHARDS];
    uint64_t                    ids[SHARDS];
    uint64_t                    records[SHARDS];
} catalog_t;

static n00b_vfs_t *
new_memory_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);
    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));
    CHECK(n00b_result_is_ok(
        n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0)));
    return vfs;
}

static uint64_t
entry_u64(n00b_result_t(uint64_t) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static void
ingest(n00b_store_t *store, int64_t id)
{
    n00b_json_node_t *rec = n00b_json_object_new();
    n00b_json_object_put(rec, "id", n00b_json_int_new(id));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, rec)));
}

// Shard i holds (i % 3) + 1 records and is sealed at 1000 + 10 * i, so seal
// time rises with shard id.
static catalog_t
new_catalog(void)
{
    catalog_t cat = {};
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       n00b_result_get(schema_r));
    CHECK(n00b_result_is_ok(store_r));
    cat.store = n00b_result_get(store_r);

    int64_t next_id = 0;
    for (int i = 0; i < SHARDS; i++) {
        cat.records[i] = (uint64_t)(i % 3) + 1;
        for (uint64_t r = 0; r < cat.records[i]; r++) {
            ingest(cat.store, next_id++);
        }
        auto seal_r = n00b_store_seal_hot_shard(cat.store,
                                                .seal_ts = 1000 + 10 * i);
        CHECK(n00b_result_is_ok(seal_r));
        cat.entries[i] = n00b_result_get(seal_r);
        cat.ids[i] = entry_u64(
            n00b_store_catalog_entry_get_shard_id(cat.entries[i]));
    }
    return cat;
}

static n00b_store_pos_t
pos_of(catalog_t *cat, int i, uint64_t ordinal)
{
    return (n00b_store_pos_t){
        .generation = entry_u64(
            n00b_store_catalog_entry_get_generation(cat->entries[i])),
        .shard_id   = cat->ids[i],
        .ordinal    = ordinal,
    };
}

static void
test_find_shard_is_a_binary_search(void)
{
    catalog_t cat = new_catalog();

    int probes[] = {0, 1, SHARDS / 2, SHARDS - 2, SHARDS - 1};
    for (size_t p = 0; p < sizeof(probes) / sizeof(probes[0]); p++) {
        int i = probes[p];
        n00b_store_catalog_entries_visited_reset();
        auto find_r = n00b_store_catalog_find_shard(cat.store, cat.ids[i]);
        uint64_t visited = n00b_store_catalog_entries_visited();
        CHECK(n00b_result_is_ok(find_r));
        CHECK(n00b_option_is_set(n00b_result_get(find_r)));
        CHECK(n00b_option_get(n00b_result_get(find_r)) == cat.entries[i]);
        CHECK(visited <= LOG_PROBES);

        n00b_store_catalog_entries_visited_reset();
        auto any_r = n00b_store_catalog_find_any_shard(cat.store, cat.ids[i]);
        CHECK(n00b_result_is_ok(any_r));
        CHECK(n00b_option_get(n00b_result_get(any_r)) == cat.entries[i]);
        CHECK(n00b_store_catalog_entries_visited() <= LOG_PROBES);
    }

    n00b_store_catalog_entries_visited_reset();
    auto miss_r = n00b_store_catalog_find_shard(cat.store,
                                                cat.ids[SHARDS - 1] + 1000);
    CHECK(n00b_result_is_ok(miss_r));
    CHECK(!n00b_option_is_set(n00b_result_get(miss_r)));
    CHECK(n00b_store_catalog_entries_visited() <= LOG_PROBES);

    // A quarantined shard is still found by find_any, not by find.
    CHECK(n00b_result_is_ok(
        n00b_store_quarantine_shard(cat.store, cat.ids[7])));
    auto q_r = n00b_store_catalog_find_shard(cat.store, cat.ids[7]);
    CHECK(n00b_result_is_ok(q_r));
    CHECK(!n00b_option_is_set(n00b_result_get(q_r)));
    auto q_any_r = n00b_store_catalog_find_any_shard(cat.store, cat.ids[7]);
    CHECK(n00b_option_get(n00b_result_get(q_any_r)) == cat.entries[7]);

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static void
test_resume_check_on_hot_does_not_search_the_catalog(void)
{
    catalog_t cat = new_catalog();
    ingest(cat.store, 99999);

    auto tail_r = n00b_store_tail_snapshot(cat.store);
    CHECK(n00b_result_is_ok(tail_r));
    n00b_store_tail_snapshot_t tail = n00b_result_get(tail_r);
    CHECK(tail.has_hot_through);

    n00b_store_catalog_entries_visited_reset();
    auto check_r = n00b_store_resume_check(cat.store, tail.hot_through);
    CHECK(n00b_result_is_ok(check_r));
    CHECK(n00b_result_get(check_r).available);
    // Was a full miss over the catalog before the hot shard was considered.
    CHECK(n00b_store_catalog_entries_visited() == 0);

    n00b_store_catalog_entries_visited_reset();
    check_r = n00b_store_resume_check(cat.store, pos_of(&cat, SHARDS / 2, 0));
    CHECK(n00b_result_is_ok(check_r));
    CHECK(n00b_result_get(check_r).available);
    CHECK(n00b_store_catalog_entries_visited() <= LOG_PROBES);

    check_r = n00b_store_resume_check(cat.store,
                                      pos_of(&cat, SHARDS / 2, 50));
    CHECK(n00b_result_is_ok(check_r));
    CHECK(!n00b_result_get(check_r).available);

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static void
test_visible_enumeration_is_linear_and_ordered(void)
{
    catalog_t cat = new_catalog();

    uint64_t count = entry_u64(n00b_store_catalog_visible_entry_count(cat.store));
    CHECK(count == SHARDS);

    // The planner's loop shape: count once, then entry_at for each index.
    // The loop examines each entry once.
    n00b_store_catalog_entries_visited_reset();
    for (uint64_t i = 0; i < count; i++) {
        auto at_r = n00b_store_catalog_visible_entry_at(cat.store, i);
        CHECK(n00b_result_is_ok(at_r));
        CHECK(n00b_option_get(n00b_result_get(at_r)) == cat.entries[i]);
    }
    CHECK(n00b_store_catalog_entries_visited() == SHARDS);

    n00b_store_catalog_entries_visited_reset();
    auto list_r = n00b_store_catalog_visible_entries(cat.store);
    CHECK(n00b_result_is_ok(list_r));
    n00b_store_catalog_entry_list_t *list = n00b_result_get(list_r);
    CHECK(n00b_store_catalog_entries_visited() == SHARDS);
    CHECK(n00b_list_len(*list) == SHARDS);

    // The copied list is one catalog version: a drop after it was taken
    // neither shortens nor shifts it.
    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(cat.store,
                                                         cat.ids[3])));
    CHECK(n00b_list_len(*list) == SHARDS);
    for (int i = 0; i < SHARDS; i++) {
        CHECK(n00b_list_get(*list, (size_t)i) == cat.entries[i]);
    }
    auto after_r = n00b_store_catalog_visible_entry_at(cat.store, 3);
    CHECK(n00b_option_get(n00b_result_get(after_r)) == cat.entries[4]);
    CHECK(entry_u64(n00b_store_catalog_visible_entry_count(cat.store))
          == SHARDS - 1);

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static uint64_t
brute_window_count(catalog_t        *cat,
                   n00b_store_pos_t *resume,
                   n00b_store_pos_t *as_of,
                   uint64_t          min_seal_ts)
{
    uint64_t count = 0;
    for (int i = 0; i < SHARDS; i++) {
        n00b_store_pos_t first = pos_of(cat, i, 0);
        if (resume != nullptr
            && (first.generation < resume->generation
                || (first.generation == resume->generation
                    && first.shard_id < resume->shard_id))) {
            continue;
        }
        if (as_of != nullptr && n00b_store_pos_compare(first, *as_of) > 0) {
            continue;
        }
        uint64_t seal_ts = (uint64_t)(1000 + 10 * i);
        if (min_seal_ts != 0 && seal_ts < min_seal_ts) {
            continue;
        }
        count++;
    }
    return count;
}

static void
check_window(catalog_t        *cat,
             n00b_store_pos_t *resume,
             n00b_store_pos_t *as_of,
             uint64_t          min_seal_ts)
{
    n00b_store_catalog_entries_visited_reset();
    auto tail_r = n00b_store_tail_snapshot(cat->store,
                                           .resume      = resume,
                                           .as_of       = as_of,
                                           .min_seal_ts = min_seal_ts);
    uint64_t visited = n00b_store_catalog_entries_visited();
    CHECK(n00b_result_is_ok(tail_r));
    n00b_store_catalog_snapshot_t *sealed = n00b_result_get(tail_r).sealed;
    uint64_t expected = brute_window_count(cat, resume, as_of, min_seal_ts);
    CHECK(n00b_list_len(*sealed) == expected);

    // Ascending, and every copied entry is inside the window.
    for (size_t i = 0; i < n00b_list_len(*sealed); i++) {
        n00b_store_catalog_snapshot_entry_t e = n00b_list_get(*sealed, i);
        if (i > 0) {
            CHECK(n00b_list_get(*sealed, i - 1).shard_id < e.shard_id);
        }
        CHECK(min_seal_ts == 0 || e.seal_ts >= min_seal_ts);
        CHECK(e.partition_key != nullptr);
    }

    // Three binary searches to find the window, then only the window.
    CHECK(visited <= 3 * LOG_PROBES + expected);
}

static void
test_tail_snapshot_copies_only_the_window(void)
{
    catalog_t cat = new_catalog();

    check_window(&cat, nullptr, nullptr, 0);

    n00b_store_pos_t last  = pos_of(&cat, SHARDS - 1, 0);
    n00b_store_pos_t first = pos_of(&cat, 0, 0);
    n00b_store_pos_t mid   = pos_of(&cat, SHARDS / 2, 1);
    n00b_store_pos_t near  = pos_of(&cat, SHARDS / 2 + 4, 0);

    check_window(&cat, &last, nullptr, 0);   // a caught-up resume: one shard
    check_window(&cat, nullptr, &first, 0);  // an as_of at the start
    check_window(&cat, &mid, &near, 0);      // a pager's slice
    check_window(&cat, nullptr, nullptr, 1000 + 10 * (SHARDS - 3));
    check_window(&cat, &mid, nullptr, 1000 + 10 * (SHARDS / 4));

    n00b_store_catalog_entries_visited_reset();
    auto tail_r = n00b_store_tail_snapshot(cat.store, .resume = &last);
    CHECK(n00b_result_is_ok(tail_r));
    CHECK(n00b_list_len(*n00b_result_get(tail_r).sealed) == 1);
    printf("  tail snapshot resumed at the newest of %d shards visited %llu "
           "entries\n",
           SHARDS,
           (unsigned long long)n00b_store_catalog_entries_visited());

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static void
check_backlog(catalog_t *cat, n00b_store_pos_t *after)
{
    uint64_t shards  = 0;
    uint64_t records = 0;
    uint64_t left    = 0;
    for (int i = 0; i < SHARDS; i++) {
        if (after != nullptr && cat->ids[i] < after->shard_id) {
            continue;
        }
        if (after != nullptr && cat->ids[i] == after->shard_id) {
            left = cat->records[i] > after->ordinal + 1
                     ? cat->records[i] - after->ordinal - 1
                     : 0;
            records += left;
            shards += left > 0 ? 1 : 0;
            continue;
        }
        records += cat->records[i];
        shards++;
    }

    n00b_store_catalog_entries_visited_reset();
    auto backlog_r = n00b_store_catalog_backlog(cat->store, after);
    CHECK(n00b_result_is_ok(backlog_r));
    n00b_store_backlog_t backlog = n00b_result_get(backlog_r);
    CHECK(backlog.shards_remaining == shards);
    CHECK(backlog.records_remaining == records);
    CHECK(backlog.current_shard_records_left == left);
    CHECK(n00b_store_catalog_entries_visited() <= LOG_PROBES + 1);
}

static void
test_backlog_uses_running_totals(void)
{
    catalog_t cat = new_catalog();

    check_backlog(&cat, nullptr);
    for (int i = 0; i < SHARDS; i += 37) {
        for (uint64_t ord = 0; ord <= cat.records[i]; ord++) {
            n00b_store_pos_t after = pos_of(&cat, i, ord);
            check_backlog(&cat, &after);
        }
    }
    n00b_store_pos_t last = pos_of(&cat, SHARDS - 1, cat.records[SHARDS - 1]);
    check_backlog(&cat, &last);

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static void
check_stats_match_catalog(catalog_t *cat)
{
    uint64_t sealed = 0, records = 0, bytes = 0, quarantined = 0;
    uint64_t all = entry_u64(n00b_store_catalog_all_entry_count(cat->store));
    for (uint64_t i = 0; i < all; i++) {
        auto at_r = n00b_store_catalog_all_entry_at(cat->store, i);
        n00b_store_catalog_entry_t *e = n00b_option_get(n00b_result_get(at_r));
        auto state_r = n00b_store_catalog_entry_get_state(e);
        CHECK(n00b_result_is_ok(state_r));
        uint64_t len = entry_u64(n00b_store_catalog_entry_get_byte_len(e));
        if (n00b_result_get(state_r)
            == N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED) {
            quarantined++;
            continue;
        }
        sealed++;
        records += entry_u64(n00b_store_catalog_entry_get_record_count(e));
        bytes += len;
    }

    n00b_store_catalog_entries_visited_reset();
    auto stats_r = n00b_store_memory_stats(cat->store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    // Nothing is resident, so the stats touch no entry at all.
    CHECK(n00b_store_catalog_entries_visited() == 0);
    CHECK(stats.catalog_entries == all);
    CHECK(stats.sealed_shards == sealed);
    CHECK(stats.sealed_records == records);
    CHECK(stats.sealed_bytes == bytes);
    CHECK(stats.quarantined_shards == quarantined);
    CHECK(stats.resident_shards == 0);

    uint64_t visible_count =
        entry_u64(n00b_store_catalog_get_entry_count(cat->store));
    CHECK(visible_count == sealed);
}

static void
test_memory_stats_are_counters(void)
{
    catalog_t cat = new_catalog();
    check_stats_match_catalog(&cat);

    CHECK(n00b_result_is_ok(n00b_store_quarantine_shard(cat.store, cat.ids[5])));
    check_stats_match_catalog(&cat);
    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(cat.store,
                                                         cat.ids[9])));
    check_stats_match_catalog(&cat);

    // The hot record text counter agrees with the byte estimate it is a
    // component of, and resets when the hot shard seals.
    ingest(cat.store, 7);
    ingest(cat.store, 8);
    auto stats_r = n00b_store_memory_stats(cat.store);
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.hot_record_text_bytes != 0);
    CHECK(stats.hot_byte_estimate
          == stats.hot_record_text_bytes
                 + 2 * N00B_STORE_SHARD_RECORD_OVERHEAD);
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(cat.store,
                                                      .seal_ts = 99999)));
    stats = n00b_result_get(n00b_store_memory_stats(cat.store));
    CHECK(stats.hot_record_text_bytes == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static void
test_expiry_and_oldest_come_from_the_index(void)
{
    catalog_t cat = new_catalog();

    auto oldest_r = n00b_store_oldest_available_pos(cat.store);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_get(n00b_result_get(oldest_r)).shard_id == cat.ids[0]);

    CHECK(n00b_result_is_ok(n00b_store_drop_sealed_shard(cat.store,
                                                         cat.ids[0])));
    oldest_r = n00b_store_oldest_available_pos(cat.store);
    CHECK(n00b_option_get(n00b_result_get(oldest_r)).shard_id == cat.ids[1]);

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

// Quarantined shards stay in the catalog, so the oldest visible shard can sit
// behind all of them.
static void
test_expiry_does_not_walk_past_quarantined_shards(void)
{
    enum { WINDOW_SHIFT = 62 };
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    auto store_r = n00b_store_open_vfs(
        new_memory_vfs(),
        r"/rocs",
        n00b_result_get(schema_r),
        .retention_window_ns = UINT64_C(1) << WINDOW_SHIFT);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    uint64_t ids[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        ingest(store, i);
        auto seal_r = n00b_store_seal_hot_shard(store,
                                                .seal_ts = 1000 + 10 * i);
        CHECK(n00b_result_is_ok(seal_r));
        ids[i] = entry_u64(
            n00b_store_catalog_entry_get_shard_id(n00b_result_get(seal_r)));
    }
    for (int i = 0; i < SHARDS - 1; i++) {
        CHECK(n00b_result_is_ok(n00b_store_quarantine_shard(store, ids[i])));
    }

    n00b_store_catalog_entries_visited_reset();
    auto expires_r = n00b_store_oldest_available_expires_at_ns(store);
    uint64_t visited = n00b_store_catalog_entries_visited();
    CHECK(n00b_result_is_ok(expires_r));
    CHECK(n00b_option_is_set(n00b_result_get(expires_r)));
    CHECK(n00b_option_get(n00b_result_get(expires_r))
          == (uint64_t)(1000 + 10 * (SHARDS - 1))
                 + (UINT64_C(1) << WINDOW_SHIFT));
    printf("  expiry behind %d quarantined shards visited %llu entries\n",
           SHARDS - 1,
           (unsigned long long)visited);
    CHECK(visited <= 1);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_retention_drops_leave_the_index_current(void)
{
    catalog_t cat = new_catalog();

    // Nothing is older than the cutoff.
    auto keep_r = n00b_store_shard_retention_policy_new(
        .drop_before_seal_ts = 500,
        .drop_reason         = r"test");
    CHECK(n00b_result_is_ok(keep_r));
    auto applied_r = n00b_store_apply_shard_retention(cat.store,
                                                      n00b_result_get(keep_r));
    CHECK(n00b_result_is_ok(applied_r));
    CHECK(n00b_result_get(applied_r) == 0);

    // The age rule drops exactly the shards sealed before the cutoff, and the
    // index stops returning them.
    auto age_r = n00b_store_shard_retention_policy_new(
        .drop_before_seal_ts = 1000 + 10 * 4,
        .drop_reason         = r"test");
    applied_r = n00b_store_apply_shard_retention(cat.store,
                                                 n00b_result_get(age_r));
    CHECK(n00b_result_is_ok(applied_r));
    CHECK(n00b_result_get(applied_r) == 4);
    for (int i = 0; i < 4; i++) {
        auto find_r = n00b_store_catalog_find_shard(cat.store, cat.ids[i]);
        CHECK(!n00b_option_is_set(n00b_result_get(find_r)));
    }

    // The count cap drops from the oldest remaining shard.
    auto cap_r = n00b_store_shard_retention_policy_new(
        .max_sealed_shards = SHARDS - 6,
        .drop_reason       = r"test");
    applied_r = n00b_store_apply_shard_retention(cat.store,
                                                 n00b_result_get(cap_r));
    CHECK(n00b_result_is_ok(applied_r));
    CHECK(n00b_result_get(applied_r) == 2);
    CHECK(!n00b_option_is_set(n00b_result_get(
        n00b_store_catalog_find_shard(cat.store, cat.ids[5]))));
    CHECK(n00b_option_is_set(n00b_result_get(
        n00b_store_catalog_find_shard(cat.store, cat.ids[6]))));

    CHECK(n00b_result_is_ok(n00b_store_close(cat.store)));
}

static void
test_reopen_rebuilds_the_index(void)
{
    n00b_vfs_t *vfs      = new_memory_vfs();
    auto        schema_r = n00b_store_schema_new();
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", n00b_result_get(schema_r));
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);
    uint64_t ids[8];
    for (int i = 0; i < 8; i++) {
        ingest(store, i);
        auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 100 + i);
        ids[i] = entry_u64(
            n00b_store_catalog_entry_get_shard_id(n00b_result_get(seal_r)));
    }
    CHECK(n00b_result_is_ok(n00b_store_quarantine_shard(store, ids[2])));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    schema_r = n00b_store_schema_new();
    store_r  = n00b_store_open_vfs(vfs, r"/rocs", n00b_result_get(schema_r));
    CHECK(n00b_result_is_ok(store_r));
    store = n00b_result_get(store_r);
    CHECK(entry_u64(n00b_store_catalog_visible_entry_count(store)) == 7);
    for (int i = 0; i < 8; i++) {
        auto find_r = n00b_store_catalog_find_shard(store, ids[i]);
        CHECK(n00b_option_is_set(n00b_result_get(find_r)) == (i != 2));
    }
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

// The service keeps a store on a pool hidden from the GC, so whatever a
// catalog write allocates and does not free stays mapped. The whole catalog
// is re-encoded on every seal, so a retained encoding makes each seal cost
// more than the one before it. Batches of seals are compared within one run,
// against the difference such a leak would make.
static void
test_catalog_writes_release_their_encoding(void)
{
    enum { BATCH = 100 };
    n00b_pool_t       pool = {};
    n00b_allocator_t *al   = n00b_pool_init(&pool,
                                            .hidden            = true,
                                            .external_metadata = true,
                                            .name = "catalog_write_test");
    auto schema_r = n00b_store_schema_new(.allocator = al);
    CHECK(n00b_result_is_ok(schema_r));
    n00b_vfs_t *vfs     = new_memory_vfs();
    auto        store_r = n00b_store_open_vfs(vfs,
                                              r"/rocs",
                                              n00b_result_get(schema_r),
                                              .allocator = al);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    uint64_t mapped[4];
    uint64_t catalog_bytes[4];
    int64_t  id = 0;
    for (int batch = 0; batch < 4; batch++) {
        for (int i = 0; i < BATCH; i++) {
            ingest(store, id++);
            CHECK(n00b_result_is_ok(
                n00b_store_seal_hot_shard(store, .seal_ts = 1000 + id)));
        }
        mapped[batch] = n00b_pool_mapped_bytes(&pool);
        auto stat_r   = n00b_vfs_stat(vfs, r"/rocs/catalog.rocs");
        CHECK(n00b_result_is_ok(stat_r));
        catalog_bytes[batch] = n00b_result_get(stat_r).size;
    }
    uint64_t earlier = mapped[2] - mapped[1];
    uint64_t later   = mapped[3] - mapped[2];
    // Retaining every encoding would cost the later batch about
    // BATCH * (catalog_bytes[3] - catalog_bytes[1]) / 2 more than the earlier
    // one, since the average encoding in each batch is the midpoint of the
    // catalog sizes around it. Half of that separates a leak from page-sized
    // steps in the pool's mapped bytes.
    uint64_t leak_gap = (uint64_t)BATCH
                      * (catalog_bytes[3] - catalog_bytes[1]) / 2;
    printf("  store pool growth per %d seals: %llu then %llu bytes; a "
           "retained encoding would add about %llu\n",
           BATCH,
           (unsigned long long)earlier,
           (unsigned long long)later,
           (unsigned long long)leak_gap);
    CHECK(later <= earlier + leak_gap / 2);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    n00b_allocator_destroy(al);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    printf("test_rocs_catalog_index:\n");

    test_find_shard_is_a_binary_search();
    test_resume_check_on_hot_does_not_search_the_catalog();
    test_visible_enumeration_is_linear_and_ordered();
    test_tail_snapshot_copies_only_the_window();
    test_backlog_uses_running_totals();
    test_memory_stats_are_counters();
    test_expiry_and_oldest_come_from_the_index();
    test_expiry_does_not_walk_past_quarantined_shards();
    test_retention_drops_leave_the_index_current();
    test_reopen_rebuilds_the_index();
    test_catalog_writes_release_their_encoding();

    n00b_shutdown();
    return 0;
}

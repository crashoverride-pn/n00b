/* test/unit/test_rocs_query_scaling.c - bounded work for bounded queries.
 *
 * Each case asserts on work counted, never on time: records the query layer
 * read to build hits (n00b_query_records_read), records the planner verified
 * (n00b_plan_records_scanned), shard pins held, and bytes a caller-supplied
 * allocator retained.
 */

#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/gc.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/eval.h"
#include "internal/rocs/index.h"
#include "internal/rocs/query.h"
#include "test_check.h"

#define MANY_SHARDS      24
#define MANY_PER_SHARD   500
#define MANY_RECORDS     (MANY_SHARDS * MANY_PER_SHARD)
#define BIG_RECORDS      20000
// One record in TIMEOUT_EVERY carries "timeout" in its unindexed note, one in
// BETA_EVERY carries "beta" in its indexed message, and every record carries
// "alpha".
#define TIMEOUT_EVERY    100
#define BETA_EVERY       10
#define BUCKETS          1000
#define PAGE             10

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
scaling_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"id")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"message",
        .index_kind     = N00B_STORE_INDEX_FULLTEXT,
        .include_in_all = true)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"note")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"bucket")));
    return schema;
}

static void
ingest(n00b_store_t *store, int64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(
        record,
        r"message",
        n00b_json_string_new_from_n00b(id % BETA_EVERY == 0 ? r"alpha beta"
                                                             : r"alpha"));
    n00b_json_object_put_n00b(
        record,
        r"note",
        n00b_json_string_new_from_n00b(id % TIMEOUT_EVERY == 0 ? r"timeout"
                                                               : r"ok"));
    n00b_json_object_put_n00b(record,
                              r"bucket",
                              n00b_json_int_new(id % BUCKETS));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record)));
}

static n00b_store_t *
open_store(uint64_t shards, uint64_t per_shard)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       scaling_schema());
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    int64_t id = 0;
    for (uint64_t s = 0; s < shards; s++) {
        for (uint64_t r = 0; r < per_shard; r++) {
            ingest(store, id++);
        }
        auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 1000 + s);
        CHECK(n00b_result_is_ok(seal_r));
    }
    return store;
}

static n00b_filter_field_t *
field_ok(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
filter_ok(n00b_result_t(n00b_filter_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_filter_t *
contains(n00b_string_t *term)
{
    return filter_ok(n00b_filter_contains(field_ok(r"message"), term));
}

static n00b_filter_t *
note_regex(n00b_string_t *pattern)
{
    auto regex_r = n00b_regex_new(pattern);
    CHECK(n00b_result_is_ok(regex_r));
    return filter_ok(n00b_filter_regex(field_ok(r"note"),
                                       n00b_result_get(regex_r)));
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static int64_t
record_id(n00b_store_record_t *record)
{
    auto json_r = n00b_store_record_view_json(record);
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *id = n00b_json_object_get(n00b_result_get(json_r), r"id");
    CHECK(id != nullptr && n00b_json_is_int(id));
    return n00b_json_as_i64(id);
}

static int64_t
hit_id(n00b_query_hit_t *hit)
{
    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));
    return record_id(n00b_result_get(record_r));
}

static n00b_query_result_t *
run_ok(n00b_store_t *store, n00b_query_t *query)
{
    auto query_r = n00b_query_run(store, query);
    CHECK(n00b_result_is_ok(query_r));
    return n00b_result_get(query_r);
}

static n00b_query_t *
query_ok(n00b_result_t(n00b_query_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_query_hit_t *
record_at(n00b_query_result_t *result, uint64_t i)
{
    auto records_r = n00b_query_records(result);
    CHECK(n00b_result_is_ok(records_r));
    n00b_query_hit_list_t *records = n00b_result_get(records_r);
    CHECK(i < (uint64_t)n00b_list_len(*records));
    return n00b_list_get(*records, (size_t)i);
}

static void
close_result(n00b_query_result_t *result)
{
    CHECK(n00b_result_is_ok(n00b_query_result_close(result)));
}

typedef enum {
    ALLOC_ARENA,
    ALLOC_POOL,
} alloc_kind_t;

typedef struct {
    alloc_kind_t      kind;
    n00b_arena_t     *arena;
    n00b_pool_t       pool;
    n00b_allocator_t *allocator;
} test_alloc_t;

static void
test_alloc_init(test_alloc_t *a, alloc_kind_t kind)
{
    a->kind = kind;
    if (kind == ALLOC_ARENA) {
        a->arena     = n00b_new_arena(.size   = UINT64_C(1) << 22,
                                      .use_gc = false,
                                      .name   = "scaling-arena");
        a->allocator = (n00b_allocator_t *)a->arena;
    }
    else {
        a->allocator = n00b_pool_init(&a->pool, .name = "scaling-pool");
    }
}

static uint64_t
test_alloc_bytes(test_alloc_t *a)
{
    return a->kind == ALLOC_ARENA ? n00b_arena_used(a->arena)
                                  : n00b_pool_mapped_bytes(&a->pool);
}

// A snapshot scan across every shard holds one hit and one shard pin at a
// time, and a caller's allocator grows by nothing per hit, pool or arena.
static void
test_snapshot_scan_holds_one_hit(n00b_store_t *store, alloc_kind_t kind)
{
    test_alloc_t alloc = {};
    test_alloc_init(&alloc, kind);

    auto view_r = n00b_query_view(store,
                                  contains(r"alpha"),
                                  .allocator = alloc.allocator);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(view, .allocator = alloc.allocator);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    n00b_query_records_read_reset();
    uint64_t          count      = 0;
    uint64_t          max_pins   = 0;
    uint64_t          first_used = 0;
    n00b_query_hit_t *previous   = nullptr;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            break;
        }
        n00b_query_hit_t *hit = n00b_option_get(hit_opt);
        CHECK(hit_id(hit) == (int64_t)count);
        if (previous != nullptr) {
            auto stale_r = n00b_query_hit_pos(previous);
            CHECK(n00b_result_is_err(stale_r));
            CHECK(n00b_result_get_err(stale_r) == N00B_QUERY_ERR_CLOSED);
        }
        previous = hit;

        uint64_t pins = active_pins(store);
        max_pins      = pins > max_pins ? pins : max_pins;
        count++;
        if (count == MANY_PER_SHARD) {
            first_used = test_alloc_bytes(&alloc);
        }
    }
    uint64_t end_used = test_alloc_bytes(&alloc);

    printf("  snapshot scan (%s): hits=%llu records_read=%llu max_pins=%llu "
           "allocator bytes after 1 shard=%llu after %d shards=%llu\n",
           kind == ALLOC_ARENA ? "arena" : "pool",
           (unsigned long long)count,
           (unsigned long long)n00b_query_records_read(),
           (unsigned long long)max_pins,
           (unsigned long long)first_used,
           MANY_SHARDS,
           (unsigned long long)end_used);

    CHECK(count == MANY_RECORDS);
    CHECK(n00b_query_records_read() == MANY_RECORDS);
    // The view's pin plus the shard being read.
    CHECK(max_pins == 2);
    // Less than a byte per hit after the first shard: nothing per hit stays
    // in the caller's allocator.
    CHECK(end_used - first_used < MANY_RECORDS - MANY_PER_SHARD);

    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    CHECK(active_pins(store) == 0);
    n00b_allocator_destroy(alloc.allocator);
}

// A ranked query with a limit reads records only for the hits it returns, and
// returns what the unlimited query ranks first.
static void
test_ranked_limit_reads_only_winners(n00b_store_t *store)
{
    n00b_filter_t *filter = filter_ok(n00b_filter_or(contains(r"alpha"),
                                                     contains(r"beta"),
                                                     kw_func(n00b_filter_or)));

    n00b_query_records_read_reset();
    n00b_query_result_t *limited = run_ok(
        store,
        query_ok(n00b_query_new(filter, .ranked = true, .limit = PAGE)));
    uint64_t limited_read = n00b_query_records_read();
    uint64_t limited_pins = active_pins(store);
    CHECK(n00b_query_count(limited) == PAGE);

    n00b_query_records_read_reset();
    n00b_query_result_t *full = run_ok(
        store,
        query_ok(n00b_query_new(filter, .ranked = true, .limit = 0)));
    uint64_t full_read = n00b_query_records_read();
    CHECK(n00b_query_count(full) == MANY_RECORDS);

    for (uint64_t i = 0; i < PAGE; i++) {
        n00b_query_hit_t *l = record_at(limited, i);
        n00b_query_hit_t *f = record_at(full, i);
        CHECK(hit_id(l) == hit_id(f));
        CHECK(hit_id(l) == (int64_t)(i * BETA_EVERY));
        CHECK(n00b_result_get(n00b_query_hit_score(l))
              == n00b_result_get(n00b_query_hit_score(f)));
    }

    printf("  ranked limit %d over %d matches: records_read=%llu "
           "result pins=%llu; unlimited records_read=%llu\n",
           PAGE,
           MANY_RECORDS,
           (unsigned long long)limited_read,
           (unsigned long long)limited_pins,
           (unsigned long long)full_read);

    CHECK(limited_read == PAGE);
    // The ten best are ids 0..90 by tens, all on the first shard, which the
    // ten hits share.
    CHECK(limited_pins == 1);
    CHECK(full_read == MANY_RECORDS);
    CHECK(active_pins(store) == MANY_SHARDS + 1);
    close_result(full);
    close_result(limited);
    CHECK(active_pins(store) == 0);

    // No term the index can score: every score is zero, so the limit stops
    // the walk and the residual verify after the first ten matches.
    n00b_query_records_read_reset();
    n00b_plan_records_scanned_reset();
    n00b_query_result_t *unscored = run_ok(
        store,
        query_ok(n00b_query_new(note_regex(r"timeout"),
                                .ranked = true,
                                .limit  = PAGE)));
    printf("  ranked limit %d, no scoreable term: records_read=%llu "
           "records_scanned=%llu\n",
           PAGE,
           (unsigned long long)n00b_query_records_read(),
           (unsigned long long)n00b_plan_records_scanned());
    CHECK(n00b_query_count(unscored) == PAGE);
    CHECK(hit_id(record_at(unscored, PAGE - 1))
          == (int64_t)((PAGE - 1) * TIMEOUT_EVERY));
    CHECK(n00b_query_records_read() == PAGE);
    CHECK(n00b_plan_records_scanned() <= PAGE * TIMEOUT_EVERY);
    close_result(unscored);
}

// With an index answering the filter, the plan returns every match in the
// shard, so the cursor alone has to stop at the limit, partway through it.
static void
test_limit_stops_inside_indexed_boundary(n00b_store_t *store)
{
    auto view_r = n00b_query_view(store, contains(r"alpha"), .limit = PAGE);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);
    auto count_r = n00b_query_cursor_hit_count(cursor);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == PAGE);

    n00b_query_records_read_reset();
    uint64_t count = 0;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        if (!n00b_option_is_set(n00b_result_get(next_r))) {
            break;
        }
        CHECK(hit_id(n00b_option_get(n00b_result_get(next_r)))
              == (int64_t)count);
        count++;
    }
    CHECK(count == PAGE);
    CHECK(n00b_query_records_read() == PAGE);
    // The walk stopped inside the first shard and dropped its pin.
    CHECK(active_pins(store) == 1);
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));

    n00b_query_records_read_reset();
    n00b_query_result_t *result = run_ok(
        store,
        query_ok(n00b_query_new(contains(r"alpha"), .limit = PAGE)));
    CHECK(n00b_query_count(result) == PAGE);
    CHECK(hit_id(record_at(result, PAGE - 1)) == PAGE - 1);
    CHECK(n00b_query_records_read() == PAGE);
    close_result(result);
    CHECK(active_pins(store) == 0);
}

// COUNT over the same filter the walks below use.
static uint64_t
count_alpha(n00b_store_t *store)
{
    auto agg_r = n00b_query_agg(N00B_QUERY_AGG_COUNT, nullptr);
    CHECK(n00b_result_is_ok(agg_r));
    n00b_query_agg_spec_list_t *aggs = n00b_alloc(n00b_query_agg_spec_list_t);
    *aggs = n00b_list_new_private(n00b_query_agg_spec_t *,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    n00b_list_push(*aggs, n00b_result_get(agg_r));
    n00b_query_result_t *counted = run_ok(
        store,
        query_ok(n00b_query_new(contains(r"alpha"), .aggregates = aggs)));
    auto rows_r = n00b_query_rows(counted);
    CHECK(n00b_result_is_ok(rows_r));
    auto value_r = n00b_query_row_value_at(
        n00b_list_get(*n00b_result_get(rows_r), 0),
        0);
    CHECK(n00b_result_is_ok(value_r));
    n00b_query_value_t counted_value = n00b_option_get(n00b_result_get(value_r));
    uint64_t           count         = n00b_variant_get(counted_value, uint64_t);
    close_result(counted);
    return count;
}

// A hot record the cursor staged and whose shard seals before the cursor
// reads it comes from the sealed image, so the walk delivers what a COUNT over
// the same snapshot counts, with or without streaming requested.
static void
test_hot_records_sealed_mid_walk(bool streaming)
{
    n00b_store_t *store = open_store(0, 0);
    for (int64_t id = 0; id < MANY_PER_SHARD; id++) {
        ingest(store, id);
    }

    uint64_t expected = count_alpha(store);
    CHECK(expected == MANY_PER_SHARD);

    auto view_r = n00b_query_view(store, contains(r"alpha"));
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(view);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);
    n00b_query_cursor_set_streaming(cursor, streaming);

    uint64_t delivered = 0;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        if (!n00b_option_is_set(n00b_result_get(next_r))) {
            break;
        }
        CHECK(hit_id(n00b_option_get(n00b_result_get(next_r)))
              == (int64_t)delivered);
        delivered++;
        if (delivered == 1) {
            auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 2000);
            CHECK(n00b_result_is_ok(seal_r));
        }
    }

    printf("  hot shard sealed after the first of %llu hits (%s): "
           "delivered=%llu\n",
           (unsigned long long)expected,
           streaming ? "streaming" : "default",
           (unsigned long long)delivered);
    CHECK(delivered == expected);
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    CHECK(active_pins(store) == 0);
}

// A hot boundary whose shard seals after the cursor is created but before its
// first advance is read from the sealed image, in either direction.
static void
test_hot_records_sealed_before_first_advance(bool reverse)
{
    n00b_store_t *store = open_store(0, 0);
    for (int64_t id = 0; id < MANY_PER_SHARD; id++) {
        ingest(store, id);
    }
    uint64_t expected = count_alpha(store);
    CHECK(expected == MANY_PER_SHARD);

    auto view_r = n00b_query_view(store, contains(r"alpha"));
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(view, .reverse = reverse);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 2000);
    CHECK(n00b_result_is_ok(seal_r));

    uint64_t delivered = 0;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        if (!n00b_option_is_set(n00b_result_get(next_r))) {
            break;
        }
        int64_t want = reverse ? (int64_t)(expected - 1 - delivered)
                               : (int64_t)delivered;
        CHECK(hit_id(n00b_option_get(n00b_result_get(next_r))) == want);
        delivered++;
    }

    printf("  hot shard sealed before the first advance of %llu hits (%s): "
           "delivered=%llu\n",
           (unsigned long long)expected,
           reverse ? "reverse" : "forward",
           (unsigned long long)delivered);
    CHECK(delivered == expected);
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    CHECK(active_pins(store) == 0);
}

static uint64_t
walk_ids(n00b_query_view_t *view, bool reverse, int64_t *ids, uint64_t max)
{
    auto cursor_r = n00b_query_cursor(view, .reverse = reverse);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);
    uint64_t             count  = 0;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            break;
        }
        CHECK(count < max);
        ids[count++] = hit_id(n00b_option_get(hit_opt));
    }
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    return count;
}

// A limited query over a shard whose predicate no index serves verifies
// records only until the limit is met, in cursor order, both ways, and when
// the scan is the last operand of an intersection.
static void
test_limit_stops_residual_scan(n00b_store_t *store)
{
    int64_t ids[PAGE];

    n00b_plan_records_scanned_reset();
    auto view_r = n00b_query_view(store, note_regex(r"timeout"), .limit = PAGE);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    CHECK(walk_ids(view, false, ids, PAGE) == PAGE);
    uint64_t forward = n00b_plan_records_scanned();
    for (uint64_t i = 0; i < PAGE; i++) {
        CHECK(ids[i] == (int64_t)(i * TIMEOUT_EVERY));
    }

    n00b_plan_records_scanned_reset();
    CHECK(walk_ids(view, true, ids, PAGE) == PAGE);
    uint64_t backward = n00b_plan_records_scanned();
    for (uint64_t i = 0; i < PAGE; i++) {
        CHECK(ids[i] == (int64_t)(BIG_RECORDS - (i + 1) * TIMEOUT_EVERY));
    }
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));

    n00b_filter_t *both = filter_ok(n00b_filter_and(contains(r"alpha"),
                                                    note_regex(r"timeout"),
                                                    kw_func(n00b_filter_and)));
    n00b_plan_records_scanned_reset();
    view_r = n00b_query_view(store, both, .limit = PAGE);
    CHECK(n00b_result_is_ok(view_r));
    view = n00b_result_get(view_r);
    CHECK(walk_ids(view, false, ids, PAGE) == PAGE);
    uint64_t intersected = n00b_plan_records_scanned();
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));

    // Under a union no operand can stop early; the answer is still the first
    // ten matches.
    n00b_filter_t *either = filter_ok(n00b_filter_or(note_regex(r"timeout"),
                                                     note_regex(r"never"),
                                                     kw_func(n00b_filter_or)));
    view_r = n00b_query_view(store, either, .limit = PAGE);
    CHECK(n00b_result_is_ok(view_r));
    view = n00b_result_get(view_r);
    CHECK(walk_ids(view, false, ids, PAGE) == PAGE);
    for (uint64_t i = 0; i < PAGE; i++) {
        CHECK(ids[i] == (int64_t)(i * TIMEOUT_EVERY));
    }
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));

    printf("  limit %d on a %d-record shard: records_scanned forward=%llu "
           "reverse=%llu intersect=%llu\n",
           PAGE,
           BIG_RECORDS,
           (unsigned long long)forward,
           (unsigned long long)backward,
           (unsigned long long)intersected);

    // The tenth match is the 901st record from either end.
    CHECK(forward <= PAGE * TIMEOUT_EVERY);
    CHECK(backward <= PAGE * TIMEOUT_EVERY);
    CHECK(intersected <= PAGE * TIMEOUT_EVERY);
}

// Paging with resume tokens verifies only the records between the token and
// the page's last match, so a page costs the same wherever it starts.
static void
test_resume_pages_scan_one_window(n00b_store_t *store)
{
    int64_t          ids[PAGE];
    n00b_store_pos_t resume     = {};
    bool             has_resume = false;
    uint64_t         max_scan   = 0;

    for (uint64_t page = 0; page < 5; page++) {
        n00b_plan_records_scanned_reset();
        auto view_r = n00b_query_view(store,
                                      note_regex(r"timeout"),
                                      .resume = has_resume ? &resume : nullptr,
                                      .limit  = PAGE);
        CHECK(n00b_result_is_ok(view_r));
        n00b_query_view_t *view = n00b_result_get(view_r);

        auto cursor_r = n00b_query_cursor(view);
        CHECK(n00b_result_is_ok(cursor_r));
        n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);
        for (uint64_t i = 0; i < PAGE; i++) {
            auto next_r = n00b_query_cursor_next(cursor);
            CHECK(n00b_result_is_ok(next_r));
            CHECK(n00b_option_is_set(n00b_result_get(next_r)));
            n00b_query_hit_t *hit = n00b_option_get(n00b_result_get(next_r));
            ids[i]                = hit_id(hit);
            CHECK(ids[i] == (int64_t)((page * PAGE + i) * TIMEOUT_EVERY));
        }
        auto pos_r = n00b_query_cursor_position(cursor);
        CHECK(n00b_result_is_ok(pos_r));
        resume     = n00b_option_get(n00b_result_get(pos_r));
        has_resume = true;
        CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
        CHECK(n00b_result_is_ok(n00b_query_view_close(view)));

        uint64_t scanned = n00b_plan_records_scanned();
        max_scan         = scanned > max_scan ? scanned : max_scan;
    }

    printf("  resume paging %d per page on a %d-record shard: "
           "max records_scanned per page=%llu\n",
           PAGE,
           BIG_RECORDS,
           (unsigned long long)max_scan);
    CHECK(max_scan <= PAGE * TIMEOUT_EVERY);
}

static n00b_query_agg_spec_list_t *
agg_list(n00b_query_agg_op_t op, n00b_string_t *field)
{
    n00b_query_agg_spec_list_t *list =
        n00b_alloc(n00b_query_agg_spec_list_t);
    *list = n00b_list_new_private(n00b_query_agg_spec_t *,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    auto agg_r = n00b_query_agg(op, field == nullptr ? nullptr
                                                     : field_ok(field));
    CHECK(n00b_result_is_ok(agg_r));
    n00b_list_push(*list, n00b_result_get(agg_r));
    return list;
}

static uint64_t
row_u64(n00b_query_agg_row_t *row, uint64_t index)
{
    auto value_r = n00b_query_row_value_at(row, index);
    CHECK(n00b_result_is_ok(value_r));
    n00b_query_value_t value = n00b_option_get(n00b_result_get(value_r));
    CHECK(n00b_variant_is_type(value, uint64_t));
    return n00b_variant_get(value, uint64_t);
}

static n00b_query_agg_row_t *
row_at(n00b_query_result_t *result, uint64_t i)
{
    auto rows_r = n00b_query_rows(result);
    CHECK(n00b_result_is_ok(rows_r));
    n00b_query_agg_row_list_t *rows = n00b_result_get(rows_r);
    CHECK(i < (uint64_t)n00b_list_len(*rows));
    return n00b_list_get(*rows, (size_t)i);
}

// COUNT with nothing to group reads no record; a grouped query keeps only the
// groups its limit can report; non-numeric operands leave a bounded trail.
static void
test_aggregates_bounded(n00b_store_t *store)
{
    n00b_query_records_read_reset();
    n00b_plan_records_scanned_reset();
    n00b_query_result_t *counted = run_ok(
        store,
        query_ok(n00b_query_new(contains(r"alpha"),
                                .aggregates = agg_list(N00B_QUERY_AGG_COUNT,
                                                       nullptr))));
    uint64_t count_read    = n00b_query_records_read();
    uint64_t count_scanned = n00b_plan_records_scanned();
    CHECK(n00b_query_count(counted) == 1);
    CHECK(row_u64(row_at(counted, 0), 0) == MANY_RECORDS);
    close_result(counted);

    n00b_query_group_by_list_t *groups =
        n00b_alloc(n00b_query_group_by_list_t);
    *groups = n00b_list_new_private(n00b_filter_field_t *,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    n00b_list_push(*groups, field_ok(r"bucket"));
    n00b_query_result_t *grouped = run_ok(
        store,
        query_ok(n00b_query_new(contains(r"alpha"),
                                .group_by   = groups,
                                .aggregates = agg_list(N00B_QUERY_AGG_COUNT,
                                                       nullptr),
                                .limit      = 5)));
    CHECK(n00b_query_count(grouped) == 5);
    for (uint64_t i = 0; i < 5; i++) {
        n00b_query_agg_row_t *row = row_at(grouped, i);
        auto key_r = n00b_query_row_group_key_at(row, 0);
        CHECK(n00b_result_is_ok(key_r));
        auto value_r = n00b_query_group_key_value(
            n00b_option_get(n00b_result_get(key_r)));
        CHECK(n00b_result_is_ok(value_r));
        n00b_query_value_t key = n00b_result_get(value_r);
        CHECK(n00b_variant_is_type(key, int64_t));
        CHECK(n00b_variant_get(key, int64_t) == (int64_t)i);
        CHECK(row_u64(row, 0) == MANY_RECORDS / BUCKETS);
    }
    close_result(grouped);

    n00b_query_result_t *summed = run_ok(
        store,
        query_ok(n00b_query_new(contains(r"alpha"),
                                .aggregates = agg_list(N00B_QUERY_AGG_SUM,
                                                       r"message"))));
    auto notes_r = n00b_query_result_notes(summed);
    CHECK(n00b_result_is_ok(notes_r));
    n00b_query_note_list_t *notes = n00b_result_get(notes_r);
    uint64_t note_count = (uint64_t)n00b_list_len(*notes);
    auto occurrences_r = n00b_query_note_occurrences(n00b_list_get(*notes, 0));
    CHECK(n00b_result_is_ok(occurrences_r));

    printf("  COUNT over %d matches: records_read=%llu records_scanned=%llu; "
           "SUM over strings: notes=%llu occurrences=%llu\n",
           MANY_RECORDS,
           (unsigned long long)count_read,
           (unsigned long long)count_scanned,
           (unsigned long long)note_count,
           (unsigned long long)n00b_result_get(occurrences_r));

    CHECK(count_read == 0);
    CHECK(count_scanned == 0);
    CHECK(note_count == N00B_QUERY_NOTE_EXAMPLES);
    CHECK(n00b_result_get(occurrences_r) == MANY_RECORDS);
    close_result(summed);
}

// Each linear-cursor step reads one record and keeps nothing from the steps
// before it.
static void
test_linear_cursor_steps_in_place(n00b_store_t *store)
{
    test_alloc_t alloc = {};
    test_alloc_init(&alloc, ALLOC_ARENA);

    auto view_r = n00b_query_view(store, nullptr, .allocator = alloc.allocator);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_linear_cursor(view,
                                             .allocator = alloc.allocator);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_linear_cursor_t *cursor = n00b_result_get(cursor_r);

    uint64_t count      = 0;
    uint64_t first_used = 0;
    while (true) {
        auto next_r = n00b_query_linear_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        if (!n00b_option_is_set(n00b_result_get(next_r))) {
            break;
        }
        count++;
        if (count == MANY_PER_SHARD) {
            first_used = test_alloc_bytes(&alloc);
        }
    }
    uint64_t end_used = test_alloc_bytes(&alloc);

    printf("  linear cursor over %d records: arena bytes after 1 shard=%llu "
           "after %d shards=%llu\n",
           MANY_RECORDS,
           (unsigned long long)first_used,
           MANY_SHARDS,
           (unsigned long long)end_used);
    CHECK(count == MANY_RECORDS);
    // Per shard crossing the cursor keeps a root view; per step, nothing.
    CHECK(end_used - first_used < MANY_RECORDS - MANY_PER_SHARD);

    CHECK(n00b_result_is_ok(n00b_query_linear_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    n00b_allocator_destroy(alloc.allocator);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    n00b_store_t *many = open_store(MANY_SHARDS, MANY_PER_SHARD);
    test_snapshot_scan_holds_one_hit(many, ALLOC_ARENA);
    test_snapshot_scan_holds_one_hit(many, ALLOC_POOL);
    test_ranked_limit_reads_only_winners(many);
    test_limit_stops_inside_indexed_boundary(many);
    test_aggregates_bounded(many);
    test_linear_cursor_steps_in_place(many);

    test_hot_records_sealed_mid_walk(false);
    test_hot_records_sealed_mid_walk(true);
    test_hot_records_sealed_before_first_advance(false);
    test_hot_records_sealed_before_first_advance(true);

    n00b_store_t *big = open_store(1, BIG_RECORDS);
    test_limit_stops_residual_scan(big);
    test_resume_pages_scan_one_window(big);

    n00b_shutdown();
    return 0;
}

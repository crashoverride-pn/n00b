/* test/unit/test_rocs_query_stress.c - WP-008 Phase 5 query stress. */

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

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal query handoffs must not include planner declarations"
#endif

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define STRESS_SHARDS 12
#define STRESS_MATCHES 6
#define STRESS_BOUND 3

typedef struct {
    n00b_store_t               *store;
    n00b_store_catalog_entry_t *entries[STRESS_SHARDS];
    n00b_store_pos_t            matches[STRESS_MATCHES];
    int64_t                     ids[STRESS_MATCHES];
} stress_sample_t;

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
open_time_store(n00b_vfs_t *vfs)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy_r));

    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs-stress",
                                       new_schema(),
                                       .partition_policy =
                                           n00b_result_get(policy_r));
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_new(int64_t id, n00b_string_t *level, bool default_route)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(level));
    if (default_route) {
        n00b_json_object_put_n00b(record,
                                  r"ts",
                                  n00b_json_string_new_from_n00b(r"late"));
    }
    else {
        n00b_json_object_put_n00b(record,
                                  r"ts",
                                  n00b_json_int_new((id - 1) * 10 + 5));
    }
    return record;
}

static n00b_store_catalog_entry_t *
ingest_and_seal(n00b_store_t  *store,
                int64_t        id,
                n00b_string_t *level,
                bool           default_route,
                uint64_t       seal_ts)
{
    auto ingest_r = n00b_store_ingest(store,
                                      record_new(id, level, default_route));
    CHECK(n00b_result_is_ok(ingest_r));

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

static stress_sample_t
new_stress_sample(void)
{
    stress_sample_t sample = {};
    sample.store = open_time_store(new_memory_vfs());

    uint64_t match_index = 0;
    for (uint64_t i = 0; i < STRESS_SHARDS; i++) {
        int64_t id = (int64_t)i + 1;
        bool    is_match = (id % 2) == 0;
        bool    default_route = (id % 4) == 0;
        sample.entries[i] =
            ingest_and_seal(sample.store,
                            id,
                            is_match ? r"error" : r"info",
                            default_route,
                            900 + i);
        if (is_match) {
            CHECK(match_index < STRESS_MATCHES);
            sample.matches[match_index] = entry_pos(sample.entries[i], 0);
            sample.ids[match_index]     = id;
            match_index++;
        }
    }

    CHECK(match_index == STRESS_MATCHES);
    return sample;
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
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

static n00b_query_cache_stats_t
cache_stats(n00b_query_view_t *view)
{
    auto stats_r = n00b_query_cache_stats(view);
    CHECK(n00b_result_is_ok(stats_r));
    return n00b_result_get(stats_r);
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
check_position(n00b_store_pos_t actual, n00b_store_pos_t expected)
{
    CHECK(n00b_store_pos_compare(actual, expected) == 0);
}

static void
check_mixed_partition_routes(n00b_query_view_t *view)
{
    auto count_r = n00b_query_view_boundary_count(view);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == STRESS_SHARDS);

    bool saw_default = false;
    bool saw_time_0  = false;
    bool saw_time_1  = false;
    for (uint64_t i = 0; i < STRESS_SHARDS; i++) {
        auto entry_r = n00b_query_view_boundary_entry_at(view, i);
        CHECK(n00b_result_is_ok(entry_r));
        CHECK(n00b_option_is_set(n00b_result_get(entry_r)));
        n00b_query_boundary_entry_t entry =
            n00b_option_get(n00b_result_get(entry_r));
        saw_default = saw_default
            || n00b_unicode_str_eq(entry.partition_key, r"default");
        saw_time_0 = saw_time_0
            || n00b_unicode_str_eq(entry.partition_key, r"time/0");
        saw_time_1 = saw_time_1
            || n00b_unicode_str_eq(entry.partition_key, r"time/1");
    }

    CHECK(saw_default);
    CHECK(saw_time_0);
    CHECK(saw_time_1);
}

static void
expect_cursor_records(n00b_query_view_t *view,
                      n00b_store_t      *store,
                      n00b_store_pos_t  *positions,
                      int64_t           *ids,
                      uint64_t           count)
{
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));

    auto hit_count_r = n00b_query_cursor_hit_count(cursor);
    CHECK(n00b_result_is_ok(hit_count_r));
    CHECK(n00b_result_get(hit_count_r) == count);
    CHECK(active_pins(store) == count + 1);

    for (uint64_t i = 0; i < count; i++) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        CHECK(n00b_option_is_set(hit_opt));
        n00b_query_hit_t *hit = n00b_option_get(hit_opt);

        auto pos_r = n00b_query_hit_pos(hit);
        CHECK(n00b_result_is_ok(pos_r));
        check_position(n00b_result_get(pos_r), positions[i]);

        auto score_r = n00b_query_hit_score(hit);
        CHECK(n00b_result_is_ok(score_r));
        CHECK(n00b_result_get(score_r) == 0.0);

        auto record_r = n00b_query_hit_record(hit);
        CHECK(n00b_result_is_ok(record_r));
        auto json_r = n00b_store_record_view_json(n00b_result_get(record_r));
        CHECK(n00b_result_is_ok(json_r));
        n00b_json_node_t *id = n00b_json_object_get(n00b_result_get(json_r),
                                                    r"id");
        CHECK(id != nullptr);
        CHECK(n00b_json_is_int(id));
        CHECK(n00b_json_as_i64(id) == ids[i]);
    }

    auto none_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    close_cursor_true(cursor);
    CHECK(active_pins(store) == 1);
}

static void
test_many_shards_fifo_eviction_churn_and_pins(void)
{
    stress_sample_t sample = new_stress_sample();
    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      error_filter()));
    CHECK(active_pins(sample.store) == 1);
    check_mixed_partition_routes(view);

    auto bound_r = n00b_query_cache_set_max_entries(view, STRESS_BOUND);
    CHECK(n00b_result_is_ok(bound_r));
    CHECK(n00b_result_get(bound_r));

    n00b_query_cache_stats_t stats = cache_stats(view);
    CHECK(stats.max_entries == STRESS_BOUND);
    CHECK(stats.entries == 0);
    CHECK(stats.evictions == 0);

    expect_cursor_records(view,
                          sample.store,
                          sample.matches,
                          sample.ids,
                          STRESS_MATCHES);
    stats = cache_stats(view);
    CHECK(stats.lookups == STRESS_SHARDS);
    CHECK(stats.misses == STRESS_SHARDS);
    CHECK(stats.populates == STRESS_SHARDS);
    CHECK(stats.hits == 0);
    CHECK(stats.entries == STRESS_BOUND);
    CHECK(stats.evictions == STRESS_SHARDS - STRESS_BOUND);

    uint64_t second_hits   = STRESS_BOUND;
    uint64_t second_misses = STRESS_SHARDS - second_hits;
    expect_cursor_records(view,
                          sample.store,
                          sample.matches,
                          sample.ids,
                          STRESS_MATCHES);
    stats = cache_stats(view);
    CHECK(stats.lookups == STRESS_SHARDS * 2);
    CHECK(stats.misses == STRESS_SHARDS + second_misses);
    CHECK(stats.populates == STRESS_SHARDS + second_misses);
    CHECK(stats.hits == second_hits);
    CHECK(stats.entries == STRESS_BOUND);
    CHECK(stats.evictions == (STRESS_SHARDS - STRESS_BOUND)
                              + second_misses);

    bound_r = n00b_query_cache_set_max_entries(view, 2);
    CHECK(n00b_result_is_ok(bound_r));
    CHECK(n00b_result_get(bound_r));
    stats = cache_stats(view);
    CHECK(stats.max_entries == 2);
    CHECK(stats.entries == 2);
    CHECK(stats.evictions == (STRESS_SHARDS - STRESS_BOUND)
                              + second_misses + 1);

    uint64_t third_hits   = 2;
    uint64_t third_misses = STRESS_SHARDS - third_hits;
    expect_cursor_records(view,
                          sample.store,
                          sample.matches,
                          sample.ids,
                          STRESS_MATCHES);
    stats = cache_stats(view);
    CHECK(stats.lookups == STRESS_SHARDS * 3);
    CHECK(stats.misses == STRESS_SHARDS + second_misses + third_misses);
    CHECK(stats.populates == STRESS_SHARDS + second_misses + third_misses);
    CHECK(stats.hits == second_hits + third_hits);
    CHECK(stats.entries == 2);
    CHECK(stats.evictions == (STRESS_SHARDS - STRESS_BOUND)
                              + second_misses + 1 + third_misses);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_resume_and_as_of_under_eviction(void)
{
    stress_sample_t sample = new_stress_sample();
    n00b_store_pos_t resume = sample.matches[1];
    n00b_store_pos_t as_of  = sample.matches[4];
    n00b_store_pos_t expected[] = {
        sample.matches[2],
        sample.matches[3],
        sample.matches[4],
    };
    int64_t ids[] = {
        sample.ids[2],
        sample.ids[3],
        sample.ids[4],
    };

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      error_filter(),
                                                      .resume = &resume,
                                                      .as_of = &as_of));
    auto bound_r = n00b_query_cache_set_max_entries(view, 2);
    CHECK(n00b_result_is_ok(bound_r));
    CHECK(n00b_result_get(bound_r));

    auto upper_r = n00b_query_view_snapshot_upper_bound(view);
    CHECK(n00b_result_is_ok(upper_r));
    CHECK(n00b_option_is_set(n00b_result_get(upper_r)));
    check_position(n00b_option_get(n00b_result_get(upper_r)), as_of);

    expect_cursor_records(view, sample.store, expected, ids, 3);
    n00b_query_cache_stats_t stats = cache_stats(view);
    CHECK(stats.max_entries == 2);
    CHECK(stats.lookups == 7);
    CHECK(stats.misses == 7);
    CHECK(stats.populates == 7);
    CHECK(stats.hits == 0);
    CHECK(stats.entries == 2);
    CHECK(stats.evictions == 5);

    expect_cursor_records(view, sample.store, expected, ids, 3);
    stats = cache_stats(view);
    CHECK(stats.lookups == 14);
    CHECK(stats.misses == 12);
    CHECK(stats.populates == 12);
    CHECK(stats.hits == 2);
    CHECK(stats.entries == 2);
    CHECK(stats.evictions == 10);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_many_shards_fifo_eviction_churn_and_pins();
    test_resume_and_as_of_under_eviction();

    n00b_shutdown();
    return 0;
}

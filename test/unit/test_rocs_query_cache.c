/* test/unit/test_rocs_query_cache.c - WP-008 Phase 3 snapshot cache behavior. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/regex/regex.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/query.h must not include internal query declarations"
#endif

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/n00b_rocs.h must not include internal query declarations"
#endif

#include "internal/rocs/index.h"
#include "internal/rocs/query.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    n00b_store_t               *store;
    n00b_store_catalog_entry_t *first;
    n00b_store_catalog_entry_t *second;
    n00b_store_pos_t            first_match;
    n00b_store_pos_t            second_first;
    n00b_store_pos_t            second_second;
} cache_sample_t;

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
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs-cache", new_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_new(int64_t id, n00b_string_t *level, n00b_string_t *message)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(level));
    n00b_json_object_put_n00b(record,
                              r"message",
                              n00b_json_string_new_from_n00b(message));
    return record;
}

static void
ingest_record(n00b_store_t  *store,
              int64_t        id,
              n00b_string_t *level,
              n00b_string_t *message)
{
    auto ingest_r = n00b_store_ingest(store, record_new(id, level, message));
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

static cache_sample_t
new_cache_sample(void)
{
    cache_sample_t sample = {};
    sample.store = open_store(new_memory_vfs());

    ingest_record(sample.store, 1, r"info", r"ok");
    ingest_record(sample.store, 2, r"error", r"timeout");
    sample.first = seal_current(sample.store, 701);

    ingest_record(sample.store, 3, r"error", r"panic");
    ingest_record(sample.store, 4, r"error", r"ok");
    sample.second = seal_current(sample.store, 702);

    sample.first_match   = entry_pos(sample.first, 1);
    sample.second_first  = entry_pos(sample.second, 0);
    sample.second_second = entry_pos(sample.second, 1);
    return sample;
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static n00b_filter_field_t *
field_named(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
filter_ok(n00b_result_t(n00b_filter_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_t *filter = n00b_result_get(r);
    CHECK(filter != nullptr);
    return filter;
}

static n00b_regex_t *
regex_ok(n00b_result_t(n00b_regex_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_regex_t *regex = n00b_result_get(r);
    CHECK(regex != nullptr);
    return regex;
}

static n00b_filter_t *
error_filter(void)
{
    return filter_ok(n00b_filter_eq(field_named(r"level"),
                                    n00b_fv_utf8(r"error")));
}

static n00b_filter_t *
composed_filter(void)
{
    n00b_filter_t *error = error_filter();
    n00b_filter_t *id    = filter_ok(n00b_filter_exists(field_named(r"id")));
    return filter_ok(n00b_filter_and(error,
                                     id,
                                     kw_func(n00b_filter_and)));
}

static n00b_filter_t *
regex_filter(void)
{
    return filter_ok(n00b_filter_regex(field_named(r"message"),
                                       regex_ok(n00b_regex_new(r"timeout"))));
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
expect_cursor_records(n00b_query_view_t    *view,
                      n00b_store_pos_t     *positions,
                      int64_t              *ids,
                      uint64_t              count)
{
    n00b_query_cursor_t *cursor = cursor_ok(n00b_query_cursor(view));
    for (uint64_t i = 0; i < count; i++) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        CHECK(n00b_option_is_set(hit_opt));
        n00b_query_hit_t *hit = n00b_option_get(hit_opt);

        auto pos_r = n00b_query_hit_pos(hit);
        CHECK(n00b_result_is_ok(pos_r));
        CHECK(n00b_store_pos_compare(n00b_result_get(pos_r),
                                     positions[i]) == 0);

        auto score_r = n00b_query_hit_score(hit);
        CHECK(n00b_result_is_ok(score_r));
        CHECK(n00b_result_get(score_r) == 0.0);

        auto record_r = n00b_query_hit_record(hit);
        CHECK(n00b_result_is_ok(record_r));
        auto record_pos_r = n00b_store_record_pos(n00b_result_get(record_r));
        CHECK(n00b_result_is_ok(record_pos_r));
        CHECK(n00b_store_pos_compare(n00b_result_get(record_pos_r),
                                     positions[i]) == 0);

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
}

static void
test_repeated_cursor_hits_cache_without_answer_change(void)
{
    cache_sample_t sample = new_cache_sample();
    n00b_store_pos_t positions[] = {
        sample.first_match,
        sample.second_first,
        sample.second_second,
    };
    int64_t ids[] = {2, 3, 4};

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      error_filter()));
    CHECK(active_pins(sample.store) == 1);
    n00b_query_cache_stats_t initial = cache_stats(view);
    CHECK(initial.entries == 0);
    CHECK(!initial.disabled);

    expect_cursor_records(view, positions, ids, 3);
    CHECK(active_pins(sample.store) == 1);
    n00b_query_cache_stats_t after_miss = cache_stats(view);
    CHECK(after_miss.lookups == 2);
    CHECK(after_miss.misses == 2);
    CHECK(after_miss.populates == 2);
    CHECK(after_miss.hits == 0);
    CHECK(after_miss.entries == 2);

    expect_cursor_records(view, positions, ids, 3);
    CHECK(active_pins(sample.store) == 1);
    n00b_query_cache_stats_t after_hit = cache_stats(view);
    CHECK(after_hit.lookups == 4);
    CHECK(after_hit.misses == 2);
    CHECK(after_hit.populates == 2);
    CHECK(after_hit.hits == 2);
    CHECK(after_hit.entries == 2);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_disable_clear_and_stale_reject_preserve_answers(void)
{
    cache_sample_t sample = new_cache_sample();
    n00b_store_pos_t positions[] = {
        sample.first_match,
        sample.second_first,
        sample.second_second,
    };
    int64_t ids[] = {2, 3, 4};

    n00b_query_view_t *view = view_ok(n00b_query_view(sample.store,
                                                      error_filter()));
    CHECK(n00b_result_get(n00b_query_cache_set_disabled(view, true)));
    expect_cursor_records(view, positions, ids, 3);
    n00b_query_cache_stats_t disabled = cache_stats(view);
    CHECK(disabled.disabled);
    CHECK(disabled.bypasses == 1);
    CHECK(disabled.lookups == 0);
    CHECK(disabled.entries == 0);

    CHECK(n00b_result_get(n00b_query_cache_set_disabled(view, false)));
    CHECK(n00b_result_get(n00b_query_cache_clear(view)));
    n00b_query_cache_stats_t cleared = cache_stats(view);
    CHECK(!cleared.disabled);
    CHECK(cleared.clears == 1);
    CHECK(cleared.entries == 0);

    expect_cursor_records(view, positions, ids, 3);
    CHECK(cache_stats(view).entries == 2);

    auto corrupt_r = n00b_query_cache_test_corrupt_first_metadata(view);
    CHECK(n00b_result_is_ok(corrupt_r));
    CHECK(n00b_result_get(corrupt_r));

    expect_cursor_records(view, positions, ids, 3);
    n00b_query_cache_stats_t stale = cache_stats(view);
    CHECK(stale.stale_rejects >= 1);
    CHECK(stale.populates >= 3);
    CHECK(stale.hits >= 1);

    close_view_true(view);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_composed_cache_and_regex_bypass(void)
{
    cache_sample_t sample = new_cache_sample();
    n00b_store_pos_t all_positions[] = {
        sample.first_match,
        sample.second_first,
        sample.second_second,
    };
    int64_t all_ids[] = {2, 3, 4};

    n00b_query_view_t *composed = view_ok(n00b_query_view(sample.store,
                                                          composed_filter()));
    expect_cursor_records(composed, all_positions, all_ids, 3);
    expect_cursor_records(composed, all_positions, all_ids, 3);
    n00b_query_cache_stats_t composed_stats = cache_stats(composed);
    CHECK(composed_stats.populates == 2);
    CHECK(composed_stats.hits == 2);
    close_view_true(composed);

    n00b_store_pos_t regex_positions[] = {sample.first_match};
    int64_t regex_ids[] = {2};
    n00b_query_view_t *regex = view_ok(n00b_query_view(sample.store,
                                                       regex_filter()));
    expect_cursor_records(regex, regex_positions, regex_ids, 1);
    n00b_query_cache_stats_t regex_stats = cache_stats(regex);
    CHECK(regex_stats.bypasses == 1);
    CHECK(regex_stats.lookups == 0);
    CHECK(regex_stats.entries == 0);
    close_view_true(regex);
    CHECK(active_pins(sample.store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_repeated_cursor_hits_cache_without_answer_change();
    test_disable_clear_and_stale_reject_preserve_answers();
    test_composed_cache_and_regex_bypass();

    n00b_shutdown();
    return 0;
}

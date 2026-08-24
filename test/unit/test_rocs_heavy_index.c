/* test/unit/test_rocs_heavy_index.c - WP-010 Phase 5 sealed heavy indexes. */

#include <stdint.h>

#include "n00b.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#include "plan_oracle.h"
#include "rocs_test_support.h"

typedef struct {
    n00b_store_map_t       *map;
    n00b_store_map_shard_t *root;
} mapped_sample_t;

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *message_fulltext;
    n00b_store_index_t *message_ngram;
    n00b_store_index_t *title_fulltext;
    n00b_store_index_t *catch_all;
} heavy_sample_t;

static n00b_store_index_t *
index_ok(n00b_result_t(n00b_store_index_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_get(r) != nullptr);
    return n00b_result_get(r);
}

static n00b_plan_target_t *
target_ok(n00b_result_t(n00b_plan_target_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_get(r) != nullptr);
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_get(r) != nullptr);
    return n00b_result_get(r);
}

static n00b_plan_ordset_t *
ordset_ok(n00b_result_t(n00b_plan_ordset_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_get(r) != nullptr);
    return n00b_result_get(r);
}

static n00b_store_shard_t *
shard_ok(uint64_t shard_id)
{
    auto shard_r = n00b_store_shard_new(.shard_id = shard_id, .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));
    CHECK(n00b_result_get(shard_r) != nullptr);
    return n00b_result_get(shard_r);
}

static n00b_store_index_t *
index_for(n00b_string_t *field, n00b_store_index_kind_t kind)
{
    return index_ok(n00b_store_index_new(field, kind));
}

static n00b_store_index_t *
catch_all_index(void)
{
    n00b_store_index_field_list_t *fields =
        n00b_alloc(n00b_store_index_field_list_t);
    *fields = n00b_list_new_private(n00b_string_t *,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    n00b_list_push(*fields, r"message");
    n00b_list_push(*fields, r"title");
    return index_ok(n00b_store_index_new_catch_all(fields));
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    return target_ok(n00b_plan_target_field(field));
}

static n00b_plan_predicate_t *
message_contains(n00b_string_t *term)
{
    return predicate_ok(n00b_plan_predicate_contains(field_target(r"message"),
                                                     term));
}

static n00b_plan_predicate_t *
message_prefix(n00b_string_t *prefix)
{
    return predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                  prefix));
}

static n00b_plan_predicate_t *
any_contains(n00b_string_t *term)
{
    return predicate_ok(n00b_plan_predicate_contains(
        target_ok(n00b_plan_target_any()),
        term));
}

static n00b_plan_index_list_t *
index_list_new(void)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(indexes != nullptr);
    return indexes;
}

static void
index_list_add(n00b_plan_index_list_t *indexes, n00b_store_index_t *index)
{
    auto append_r = n00b_plan_index_list_append(indexes, index);
    CHECK(n00b_result_is_ok(append_r));
}

static n00b_plan_index_list_t *
sample_index_list(heavy_sample_t *sample)
{
    n00b_plan_index_list_t *indexes = index_list_new();
    index_list_add(indexes, sample->message_fulltext);
    index_list_add(indexes, sample->message_ngram);
    index_list_add(indexes, sample->title_fulltext);
    index_list_add(indexes, sample->catch_all);
    return indexes;
}

static n00b_json_node_t *
record_with(n00b_string_t *message, n00b_string_t *title)
{
    n00b_json_node_t *record = n00b_json_object_new();
    if (message != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"message",
                                  n00b_json_string_new_from_n00b(message));
    }
    if (title != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"title",
                                  n00b_json_string_new_from_n00b(title));
    }
    return record;
}

static uint64_t
append_record(n00b_store_shard_t *shard, n00b_json_node_t *record)
{
    auto append_r = n00b_store_shard_append(shard, record);
    CHECK(n00b_result_is_ok(append_r));
    return n00b_result_get(append_r);
}

static void
add_index(n00b_store_index_t *index,
          n00b_store_shard_t *shard,
          uint64_t            ordinal)
{
    auto add_r = n00b_store_index_add(index, shard, ordinal);
    CHECK(n00b_result_is_ok(add_r));
}

static void
append_indexed(heavy_sample_t *sample,
               n00b_string_t  *message,
               n00b_string_t  *title)
{
    uint64_t ordinal = append_record(sample->shard, record_with(message, title));
    add_index(sample->message_fulltext, sample->shard, ordinal);
    add_index(sample->message_ngram, sample->shard, ordinal);
    add_index(sample->title_fulltext, sample->shard, ordinal);
}

static heavy_sample_t
heavy_sample(uint64_t shard_id)
{
    heavy_sample_t sample = {
        .shard            = shard_ok(shard_id),
        .message_fulltext = index_for(r"message", N00B_STORE_INDEX_FULLTEXT),
        .message_ngram    = index_for(r"message", N00B_STORE_INDEX_NGRAM),
        .title_fulltext   = index_for(r"title", N00B_STORE_INDEX_FULLTEXT),
        .catch_all        = catch_all_index(),
    };

    append_indexed(&sample, r"Error opening alpha", r"Release note");
    append_indexed(&sample, r"Warning alpha", r"Error summary");
    append_indexed(&sample, r"Nominal beta", r"Quiet");
    append_indexed(&sample, r"Error closing beta", r"Other");
    return sample;
}

static mapped_sample_t
seal_and_map(n00b_store_shard_t *shard, uint64_t seal_ts)
{
    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = seal_ts,
                                        .base_address = 0x760000u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    return (mapped_sample_t){
        .map  = n00b_result_get(map_r),
        .root = n00b_result_get(root_r),
    };
}

static n00b_store_posting_t
posting_at(n00b_store_postings_t *postings, uint64_t ordinal)
{
    auto posting_r = n00b_store_postings_get(postings, ordinal);
    CHECK(n00b_result_is_ok(posting_r));
    n00b_option_t(n00b_store_posting_t) opt = n00b_result_get(posting_r);
    CHECK(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static void
check_postings(n00b_store_postings_t *postings,
               uint64_t               shard_id,
               uint64_t               generation,
               const uint64_t        *expected,
               uint64_t               expected_len)
{
    auto len_r = n00b_store_postings_len(postings);
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == expected_len);

    for (uint64_t i = 0; i < expected_len; i++) {
        n00b_store_posting_t posting = posting_at(postings, i);
        CHECK(posting.pos.shard_id == shard_id);
        CHECK(posting.pos.generation == generation);
        CHECK(posting.pos.ordinal == expected[i]);
        CHECK(posting.record != nullptr);
    }
}

static bool
expected_has(const uint64_t *expected, uint64_t len, uint64_t ordinal)
{
    for (uint64_t i = 0; i < len; i++) {
        if (expected[i] == ordinal) {
            return true;
        }
    }
    return false;
}

static void
check_set(n00b_plan_ordset_t *set,
          uint64_t            record_count,
          const uint64_t     *expected,
          uint64_t            expected_len)
{
    auto count_r = n00b_plan_ordset_count(set);
    auto records_r = n00b_plan_ordset_record_count(set);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == record_count);
    CHECK(n00b_result_get(count_r) == expected_len);

    for (uint64_t i = 0; i < expected_len; i++) {
        auto at_r = n00b_plan_ordset_at(set, i);
        CHECK(n00b_result_is_ok(at_r));
        CHECK(n00b_option_is_set(n00b_result_get(at_r)));
        CHECK(n00b_option_get(n00b_result_get(at_r)) == expected[i]);
    }
    for (uint64_t ordinal = 0; ordinal < record_count; ordinal++) {
        auto contains_r = n00b_plan_ordset_contains(set, ordinal);
        CHECK(n00b_result_is_ok(contains_r));
        CHECK(n00b_result_get(contains_r)
              == expected_has(expected, expected_len, ordinal));
    }
}

static void
check_plan(n00b_plan_node_t      *plan,
           n00b_plan_predicate_t *record_scan,
           bool                   uses_index)
{
    auto used_r = n00b_plan_uses_index(plan);
    CHECK(n00b_result_is_ok(used_r));
    CHECK(n00b_result_get(used_r) == uses_index);

    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    n00b_option_t(n00b_plan_predicate_t *) sole = n00b_result_get(sole_r);
    CHECK(n00b_option_is_set(sole) == (record_scan != nullptr));
    if (record_scan != nullptr) {
        CHECK(n00b_option_get(sole) == record_scan);
    }
}

static void
check_stats(n00b_store_index_stats_t stats,
            uint64_t                 record_count,
            uint64_t                 df,
            double                   min_selectivity,
            double                   max_selectivity)
{
    CHECK(stats.record_count == record_count);
    CHECK(stats.document_frequency == df);
    CHECK(stats.selectivity >= min_selectivity);
    CHECK(stats.selectivity <= max_selectivity);
}

static void
test_sealed_lookup_catch_all_stats_and_record_views(void)
{
    heavy_sample_t sample = heavy_sample(UINT64_C(0x7601));
    n00b_json_node_t *error = n00b_json_string_new_from_n00b(r"error");

    uint64_t message_error[] = {0, 3};
    auto hot_fulltext_r =
        n00b_store_index_lookup(sample.message_fulltext, sample.shard, error);
    CHECK(n00b_result_is_ok(hot_fulltext_r));
    check_postings(n00b_result_get(hot_fulltext_r),
                   UINT64_C(0x7601),
                   0,
                   message_error,
                   2);

    auto hot_stats_r =
        n00b_store_index_stats_hot(sample.message_fulltext,
                                   sample.shard,
                                   error);
    CHECK(n00b_result_is_ok(hot_stats_r));
    check_stats(n00b_result_get(hot_stats_r), 4, 2, 0.49, 0.51);

    uint64_t catch_all_error[] = {0, 1, 3};
    auto hot_catch_all_r =
        n00b_store_index_lookup(sample.catch_all, sample.shard, error);
    CHECK(n00b_result_is_ok(hot_catch_all_r));
    check_postings(n00b_result_get(hot_catch_all_r),
                   UINT64_C(0x7601),
                   0,
                   catch_all_error,
                   3);

    mapped_sample_t mapped = seal_and_map(sample.shard, 501);

    auto mapped_fulltext_r =
        n00b_store_index_lookup_mapped(sample.message_fulltext,
                                       mapped.root,
                                       error);
    CHECK(n00b_result_is_ok(mapped_fulltext_r));
    check_postings(n00b_result_get(mapped_fulltext_r),
                   UINT64_C(0x7601),
                   501,
                   message_error,
                   2);

    auto mapped_ngram_r =
        n00b_store_index_lookup_mapped(sample.message_ngram,
                                       mapped.root,
                                       error);
    CHECK(n00b_result_is_ok(mapped_ngram_r));
    check_postings(n00b_result_get(mapped_ngram_r),
                   UINT64_C(0x7601),
                   501,
                   message_error,
                   2);

    auto mapped_catch_all_r =
        n00b_store_index_lookup_mapped(sample.catch_all, mapped.root, error);
    CHECK(n00b_result_is_ok(mapped_catch_all_r));
    check_postings(n00b_result_get(mapped_catch_all_r),
                   UINT64_C(0x7601),
                   501,
                   catch_all_error,
                   3);

    auto mapped_stats_r =
        n00b_store_index_stats_mapped(sample.message_fulltext,
                                      mapped.root,
                                      error);
    CHECK(n00b_result_is_ok(mapped_stats_r));
    check_stats(n00b_result_get(mapped_stats_r), 4, 2, 0.49, 0.51);

    n00b_store_posting_t posting =
        posting_at(n00b_result_get(mapped_fulltext_r), 0);
    auto json_r = n00b_store_record_view_json(posting.record);
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *message =
        n00b_json_object_get(n00b_result_get(json_r), r"message");
    CHECK(message != nullptr);
    CHECK(n00b_json_is_string(message));
    CHECK(n00b_unicode_str_eq(n00b_json_as_string(message),
                              r"Error opening alpha"));

    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));
}

static void
test_hot_and_mapped_planner_parity(void)
{
    heavy_sample_t sample = heavy_sample(UINT64_C(0x7602));
    n00b_plan_index_list_t *indexes = sample_index_list(&sample);

    n00b_plan_predicate_t *contains = message_contains(r"error");
    n00b_plan_node_t *hot_contains
        = test_plan_hot(contains, indexes, sample.shard);
    uint64_t message_error[] = {0, 3};
    check_plan(hot_contains, nullptr, true);
    check_set(ordset_ok(n00b_plan_exec_hot(hot_contains, sample.shard)),
              4, message_error, 2);

    n00b_plan_predicate_t *prefix = message_prefix(r"Error");
    n00b_plan_node_t *hot_prefix
        = test_plan_hot(prefix, indexes, sample.shard);
    // Lossy n-gram scan paired with the record scan that settles it.
    check_plan(hot_prefix, prefix, true);
    n00b_plan_ordset_t *hot_prefix_verified =
        ordset_ok(n00b_plan_exec_hot(hot_prefix, sample.shard));
    check_set(hot_prefix_verified, 4, message_error, 2);

    n00b_plan_predicate_t *any = any_contains(r"error");
    n00b_plan_node_t *hot_any
        = test_plan_hot(any, indexes, sample.shard);
    uint64_t catch_all_error[] = {0, 1, 3};
    check_plan(hot_any, nullptr, true);
    check_set(ordset_ok(n00b_plan_exec_hot(hot_any, sample.shard)),
              4, catch_all_error, 3);

    mapped_sample_t mapped = seal_and_map(sample.shard, 502);

    n00b_plan_node_t *mapped_contains
        = test_plan_mapped(contains, indexes, mapped.root);
    check_plan(mapped_contains, nullptr, true);
    check_set(ordset_ok(n00b_plan_exec_mapped(mapped_contains, mapped.root)),
              4, message_error, 2);

    n00b_plan_node_t *mapped_prefix
        = test_plan_mapped(prefix, indexes, mapped.root);
    check_plan(mapped_prefix, prefix, true);
    n00b_plan_ordset_t *mapped_prefix_verified =
        ordset_ok(n00b_plan_exec_mapped(mapped_prefix, mapped.root));
    check_set(mapped_prefix_verified, 4, message_error, 2);

    n00b_plan_node_t *mapped_any
        = test_plan_mapped(any, indexes, mapped.root);
    check_plan(mapped_any, nullptr, true);
    check_set(ordset_ok(n00b_plan_exec_mapped(mapped_any, mapped.root)),
              4, catch_all_error, 3);

    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));
}

static void
test_catch_all_structured_ids_query_full_token_only(void)
{
    heavy_sample_t sample = {
        .shard            = shard_ok(UINT64_C(0x7604)),
        .message_fulltext = index_for(r"message", N00B_STORE_INDEX_FULLTEXT),
        .message_ngram    = index_for(r"message", N00B_STORE_INDEX_NGRAM),
        .title_fulltext   = index_for(r"title", N00B_STORE_INDEX_FULLTEXT),
        .catch_all        = catch_all_index(),
    };

    append_indexed(&sample, r"ai-session:55545:2", r"structured id");
    append_indexed(&sample, r"ai-session:99999:7", r"other id");
    append_indexed(&sample, r"session 55545 without tail", r"partial");
    append_indexed(&sample, r"ai session 55545 2", r"split legacy id");

    uint64_t exact[] = {0};
    n00b_json_node_t *full =
        n00b_json_string_new_from_n00b(r"ai-session:55545:2");
    auto hot_full_r =
        n00b_store_index_lookup(sample.catch_all, sample.shard, full);
    CHECK(n00b_result_is_ok(hot_full_r));
    check_postings(n00b_result_get(hot_full_r),
                   UINT64_C(0x7604),
                   0,
                   exact,
                   1);

    n00b_json_node_t *component = n00b_json_string_new_from_n00b(r"55545");
    uint64_t component_hits[] = {0, 2, 3};
    auto hot_component_r =
        n00b_store_index_lookup(sample.catch_all, sample.shard, component);
    CHECK(n00b_result_is_ok(hot_component_r));
    check_postings(n00b_result_get(hot_component_r),
                   UINT64_C(0x7604),
                   0,
                   component_hits,
                   3);

    mapped_sample_t mapped = seal_and_map(sample.shard, 504);
    auto mapped_full_r =
        n00b_store_index_lookup_mapped(sample.catch_all, mapped.root, full);
    CHECK(n00b_result_is_ok(mapped_full_r));
    check_postings(n00b_result_get(mapped_full_r),
                   UINT64_C(0x7604),
                   504,
                   exact,
                   1);


    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));
}

static n00b_store_shard_t *
broad_ngram_shard(n00b_store_index_t *index)
{
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7603));
    for (uint64_t i = 0; i < 7; i++) {
        n00b_string_t *text = n00b_cformat("Common [|#|]", (int64_t)i);
        uint64_t ordinal = append_record(shard, record_with(text, nullptr));
        add_index(index, shard, ordinal);
    }
    uint64_t rare = append_record(shard, record_with(r"Rare", nullptr));
    add_index(index, shard, rare);
    return shard;
}

static void
test_broad_ngram_candidates_drop_to_scan_verify(void)
{
    n00b_store_index_t     *index = index_for(r"message",
                                              N00B_STORE_INDEX_NGRAM);
    n00b_store_shard_t     *shard = broad_ngram_shard(index);
    n00b_plan_index_list_t *indexes = index_list_new();
    index_list_add(indexes, index);
    n00b_plan_predicate_t *prefix = message_prefix(r"Com");

    uint64_t verified[] = {0, 1, 2, 3, 4, 5, 6};

    // "Com" hits every record, so the lossy n-gram scan has narrowed nothing.
    // Execution notices that and drops to the universe, leaving the paired
    // record scan to do the work. The planner cannot make that call, since it
    // needs the size of the result to see it.
    n00b_plan_node_t *hot = test_plan_hot(prefix, indexes, shard);
    check_plan(hot, prefix, true);
    n00b_plan_ordset_t *hot_verified =
        ordset_ok(n00b_plan_exec_hot(hot, shard));
    check_set(hot_verified, 8, verified, 7);

    mapped_sample_t mapped = seal_and_map(shard, 503);
    n00b_plan_node_t *cold = test_plan_hot(prefix, indexes, shard);
    check_plan(cold, prefix, true);
    n00b_plan_ordset_t *cold_verified =
        ordset_ok(n00b_plan_exec_mapped(cold, mapped.root));
    check_set(cold_verified, 8, verified, 7);

    auto stats_r = n00b_store_index_stats_mapped(
        index,
        mapped.root,
        n00b_json_string_new_from_n00b(r"Com"));
    CHECK(n00b_result_is_ok(stats_r));
    check_stats(n00b_result_get(stats_r), 8, 7, 0.87, 0.88);

    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_sealed_lookup_catch_all_stats_and_record_views();
    test_hot_and_mapped_planner_parity();
    test_catch_all_structured_ids_query_full_token_only();
    test_broad_ngram_candidates_drop_to_scan_verify();

    n00b_shutdown();
    return 0;
}

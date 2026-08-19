/* test/unit/test_rocs_ngram_index.c - WP-010 Phase 2 n-gram index. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/normalizer.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "public rocs headers must not include internal planner declarations"
#endif

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#include "plan_oracle.h"

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_check_err_result));                       \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));        \
    } while (0)

static n00b_store_index_t *
index_ok(n00b_result_t(n00b_store_index_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_store_index_t *index = n00b_result_get(r);
    CHECK(index != nullptr);
    return index;
}

static n00b_store_index_t *
ngram_index(n00b_string_t *field)
{
    return index_ok(n00b_store_index_new(field, N00B_STORE_INDEX_NGRAM));
}

static n00b_store_index_t *
ngram_index_n(n00b_string_t *field, uint8_t ngram_n)
{
    return index_ok(n00b_store_index_new(field,
                                         N00B_STORE_INDEX_NGRAM,
                                         .ngram_n = ngram_n));
}

static n00b_store_index_t *
fulltext_index(n00b_string_t *field)
{
    return index_ok(n00b_store_index_new(field, N00B_STORE_INDEX_FULLTEXT));
}

static n00b_plan_target_t *
target_ok(n00b_result_t(n00b_plan_target_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_target_t *target = n00b_result_get(r);
    CHECK(target != nullptr);
    return target;
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_predicate_t *predicate = n00b_result_get(r);
    CHECK(predicate != nullptr);
    return predicate;
}

static n00b_plan_node_t *
plan_ok(n00b_result_t(n00b_plan_node_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_node_t *plan = n00b_result_get(r);
    CHECK(plan != nullptr);
    return plan;
}

static n00b_plan_ordset_t *
ordset_ok(n00b_result_t(n00b_plan_ordset_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_ordset_t *set = n00b_result_get(r);
    CHECK(set != nullptr);
    return set;
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    return target_ok(n00b_plan_target_field(field));
}

static n00b_plan_predicate_t *
message_contains(n00b_string_t *needle)
{
    return predicate_ok(n00b_plan_predicate_contains(field_target(r"message"),
                                                     needle));
}

static n00b_plan_predicate_t *
message_prefix(n00b_string_t *prefix)
{
    return predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                  prefix));
}

static n00b_plan_index_list_t *
index_list_new(void)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(indexes != nullptr);
    return indexes;
}

static n00b_plan_index_list_t *
index_list_with(n00b_store_index_t *index)
{
    n00b_plan_index_list_t *indexes = index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, index)));
    return indexes;
}

static n00b_plan_index_list_t *
index_list_with_two(n00b_store_index_t *first, n00b_store_index_t *second)
{
    n00b_plan_index_list_t *indexes = index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, first)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, second)));
    return indexes;
}

static n00b_json_node_t *
record_with_message_node(n00b_json_node_t *message)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"message", message);
    return record;
}

static n00b_json_node_t *
record_with_message(n00b_string_t *message)
{
    return record_with_message_node(n00b_json_string_new_from_n00b(message));
}

static n00b_json_node_t *
record_without_message(void)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(r"info"));
    return record;
}

static n00b_store_shard_t *
shard_ok(uint64_t shard_id)
{
    auto shard_r = n00b_store_shard_new(.shard_id = shard_id);
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);
    CHECK(shard != nullptr);
    return shard;
}

static uint64_t
append_record(n00b_store_shard_t *shard, n00b_json_node_t *record)
{
    auto append_r = n00b_store_shard_append(shard, record);
    CHECK(n00b_result_is_ok(append_r));
    return n00b_result_get(append_r);
}

static uint64_t
append_and_index_at_least(n00b_store_index_t *index,
                          n00b_store_shard_t *shard,
                          n00b_json_node_t   *record,
                          uint64_t            minimum_terms)
{
    uint64_t ordinal = append_record(shard, record);
    auto     add_r   = n00b_store_index_add(index, shard, ordinal);
    CHECK(n00b_result_is_ok(add_r));
    CHECK(n00b_result_get(add_r) >= minimum_terms);
    return ordinal;
}

static uint64_t
append_and_index_exact(n00b_store_index_t *index,
                       n00b_store_shard_t *shard,
                       n00b_json_node_t   *record,
                       uint64_t            expected_terms)
{
    uint64_t ordinal = append_record(shard, record);
    auto     add_r   = n00b_store_index_add(index, shard, ordinal);
    CHECK(n00b_result_is_ok(add_r));
    CHECK(n00b_result_get(add_r) == expected_terms);
    return ordinal;
}

static void
index_existing_record(n00b_store_index_t *index,
                      n00b_store_shard_t *shard,
                      uint64_t            ordinal)
{
    auto add_r = n00b_store_index_add(index, shard, ordinal);
    CHECK(n00b_result_is_ok(add_r));
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
check_posting_len(n00b_store_postings_t *postings, uint64_t expected)
{
    auto len_r = n00b_store_postings_len(postings);
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == expected);
}

static void
check_postings(n00b_store_postings_t *postings,
               uint64_t               shard_id,
               uint64_t               generation,
               const uint64_t        *expected,
               uint64_t               expected_len)
{
    check_posting_len(postings, expected_len);
    for (uint64_t i = 0; i < expected_len; i++) {
        n00b_store_posting_t posting = posting_at(postings, i);
        CHECK(posting.pos.shard_id == shard_id);
        CHECK(posting.pos.ordinal == expected[i]);
        CHECK(posting.pos.generation == generation);
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
    auto record_count_r = n00b_plan_ordset_record_count(set);
    CHECK(n00b_result_is_ok(record_count_r));
    CHECK(n00b_result_get(record_count_r) == record_count);

    auto count_r = n00b_plan_ordset_count(set);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == expected_len);

    for (uint64_t i = 0; i < expected_len; i++) {
        auto at_r = n00b_plan_ordset_at(set, i);
        CHECK(n00b_result_is_ok(at_r));
        CHECK(n00b_option_is_set(n00b_result_get(at_r)));
        CHECK(n00b_option_get(n00b_result_get(at_r)) == expected[i]);
    }

    auto none_r = n00b_plan_ordset_at(set, expected_len);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    for (uint64_t ordinal = 0; ordinal < record_count; ordinal++) {
        auto contains_r = n00b_plan_ordset_contains(set, ordinal);
        CHECK(n00b_result_is_ok(contains_r));
        CHECK(n00b_result_get(contains_r)
              == expected_has(expected, expected_len, ordinal));
    }
}

static void
check_plan_flags(n00b_plan_node_t      *plan,
                 n00b_plan_predicate_t *expected_record_scan,
                 bool                   expected_uses_index)
{
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    n00b_option_t(n00b_plan_predicate_t *) residual = n00b_result_get(sole_r);

    auto exact_r = n00b_plan_reads_no_records(plan);
    auto used_r  = n00b_plan_uses_index(plan);
    CHECK(n00b_result_is_ok(exact_r));
    CHECK(n00b_result_is_ok(used_r));
    CHECK(n00b_result_get(used_r) == expected_uses_index);

    if (expected_record_scan == nullptr) {
        CHECK(!n00b_option_is_set(residual));
        CHECK(n00b_result_get(exact_r));
    }
    else {
        CHECK(n00b_option_is_set(residual));
        CHECK(n00b_option_get(residual) == expected_record_scan);
        CHECK(!n00b_result_get(exact_r));
    }
}

static n00b_store_shard_t *
sample_ngram_shard(n00b_store_index_t *index)
{
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7200));
    append_and_index_exact(index, shard, record_with_message(r"aaaaa"), 1);
    append_and_index_at_least(index, shard, record_with_message(r"Error opening"), 1);
    append_and_index_at_least(index, shard, record_with_message(r"terror opening"), 1);
    append_and_index_at_least(index, shard, record_with_message(r"errand closed"), 1);
    append_and_index_exact(index, shard, record_without_message(), 0);
    append_and_index_exact(index,
                           shard,
                           record_with_message_node(n00b_json_int_new(7)),
                           0);
    return shard;
}

static void
test_ngram_descriptor_contract(void)
{
    n00b_store_index_t *index = ngram_index(r"message");

    n00b_store_advert_t contains =
        n00b_store_index_advertise(index,
                                   r"message",
                                   N00B_STORE_INDEX_OP_CONTAINS);
    CHECK(!contains.accelerates);
    CHECK(contains.kind == N00B_STORE_INDEX_NONE);

    n00b_store_advert_t prefix =
        n00b_store_index_advertise(index,
                                   r"message",
                                   N00B_STORE_INDEX_OP_PREFIX);
    CHECK(prefix.accelerates);
    CHECK(prefix.kind == N00B_STORE_INDEX_NGRAM);

    n00b_store_advert_t eq =
        n00b_store_index_advertise(index, r"message", N00B_STORE_INDEX_OP_EQ);
    CHECK(!eq.accelerates);
    CHECK(eq.kind == N00B_STORE_INDEX_NONE);

    n00b_store_advert_t default_op =
        n00b_store_index_advertise(index,
                                   r"message",
                                   N00B_STORE_INDEX_OP_UNSPECIFIED);
    CHECK(!default_op.accelerates);
    CHECK(default_op.kind == N00B_STORE_INDEX_NONE);

    n00b_store_advert_t mismatch =
        n00b_store_index_advertise(index,
                                   r"level",
                                   N00B_STORE_INDEX_OP_PREFIX);
    CHECK(!mismatch.accelerates);
    CHECK(mismatch.kind == N00B_STORE_INDEX_NONE);

    auto default_n_r = n00b_store_index_ngram_n(index);
    CHECK(n00b_result_is_ok(default_n_r));
    CHECK(n00b_result_get(default_n_r) == N00B_STORE_NGRAM_DEFAULT_N);

    n00b_store_index_t *bigram = ngram_index_n(r"message", 2);
    auto bigram_n_r = n00b_store_index_ngram_n(bigram);
    CHECK(n00b_result_is_ok(bigram_n_r));
    CHECK(n00b_result_get(bigram_n_r) == 2);

    CHECK_ERR(n00b_store_index_new(r"message",
                                   N00B_STORE_INDEX_NGRAM,
                                   .ngram_n = 1),
              N00B_STORE_INDEX_ERR_ARG);
    CHECK_ERR(n00b_store_index_new(r"message",
                                   N00B_STORE_INDEX_TERM,
                                   .ngram_n = 4),
              N00B_STORE_INDEX_ERR_ARG);
    CHECK_ERR(n00b_store_index_ngram_n(nullptr), N00B_STORE_INDEX_ERR_ARG);
    CHECK_ERR(n00b_store_index_ngram_n(fulltext_index(r"message")),
              N00B_STORE_INDEX_ERR_KIND);
}

static void
test_custom_ngram_width_lookup(void)
{
    n00b_store_index_t *index = ngram_index_n(r"message", 4);
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7205));
    append_and_index_exact(index, shard, record_with_message(r"abcdef"), 3);

    auto abcd_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"abcd"));
    CHECK(n00b_result_is_ok(abcd_r));
    uint64_t expected[] = {0};
    check_postings(n00b_result_get(abcd_r), UINT64_C(0x7205), 0, expected, 1);

    CHECK_ERR(n00b_store_index_lookup(
                  index,
                  shard,
                  n00b_json_string_new_from_n00b(r"abc")),
              N00B_STORE_INDEX_ERR_ARG);
}

static void
test_hot_ngram_lookup_candidates_and_dedup(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_ngram_shard(index);

    auto aaa_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"aaa"));
    CHECK(n00b_result_is_ok(aaa_r));
    uint64_t aaa_expected[] = {0};
    check_postings(n00b_result_get(aaa_r),
                   UINT64_C(0x7200),
                   0,
                   aaa_expected,
                   1);

    auto err_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"err"));
    CHECK(n00b_result_is_ok(err_r));
    uint64_t err_expected[] = {1, 2, 3};
    check_postings(n00b_result_get(err_r),
                   UINT64_C(0x7200),
                   0,
                   err_expected,
                   3);

    auto opening_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"opening"));
    CHECK(n00b_result_is_ok(opening_r));
    uint64_t opening_expected[] = {1, 2};
    check_postings(n00b_result_get(opening_r),
                   UINT64_C(0x7200),
                   0,
                   opening_expected,
                   2);

    auto miss_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"zzzz"));
    CHECK(n00b_result_is_ok(miss_r));
    check_posting_len(n00b_result_get(miss_r), 0);

    CHECK_ERR(n00b_store_index_lookup(
                  index,
                  shard,
                  n00b_json_string_new_from_n00b(r"er")),
              N00B_STORE_INDEX_ERR_ARG);
    CHECK_ERR(n00b_store_index_lookup(
                  index,
                  shard,
                  n00b_json_string_new_from_n00b(r"")),
              N00B_STORE_INDEX_ERR_ARG);
    CHECK_ERR(n00b_store_index_lookup(index, shard, n00b_json_int_new(1)),
              N00B_STORE_INDEX_ERR_ARG);
}

static void
test_mapped_ngram_readback_uses_sealed_index(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_ngram_shard(index);

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 92,
                                        .base_address = 0x720000u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    n00b_store_map_t *map = n00b_result_get(map_r);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));

    auto lookup_r = n00b_store_index_lookup_mapped(
        index,
        n00b_result_get(root_r),
        n00b_json_string_new_from_n00b(r"err"));
    CHECK(n00b_result_is_ok(lookup_r));
    uint64_t expected[] = {1, 2, 3};
    check_postings(n00b_result_get(lookup_r),
                   UINT64_C(0x7200),
                   92,
                   expected,
                   3);

    auto close_r = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close_r));
}

static n00b_plan_predicate_t *
message_substring(n00b_string_t *text)
{
    return predicate_ok(
        n00b_plan_predicate_substring(field_target(r"message"), text));
}

// "rror" sits inside "Error" and "terror" and is a whole token in neither, so
// it separates substring from contains.
static void
test_substring_matches_inside_a_word(void)
{
    n00b_store_index_t     *index   = ngram_index(r"message");
    n00b_store_shard_t     *shard   = sample_ngram_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    n00b_plan_predicate_t *sub  = message_substring(r"rror");
    n00b_plan_node_t      *plan = plan_ok(n00b_plan_build(sub, indexes));

    // Grams narrow, records settle.
    check_plan_flags(plan, sub, true);

    uint64_t expected[] = {1, 2};
    check_set(ordset_ok(n00b_plan_exec_hot(plan, shard)), 6, expected, 2);

    // The same text as a whole-token contains finds nothing.
    n00b_plan_predicate_t *whole = message_contains(r"rror");
    n00b_plan_node_t *whole_plan = plan_ok(n00b_plan_build(whole, indexes));
    check_set(ordset_ok(n00b_plan_exec_hot(whole_plan, shard)), 6, nullptr, 0);
}

// A schema without the index has to answer the same question the same way.
static void
test_substring_answers_alike_without_an_index(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_ngram_shard(index);

    n00b_plan_predicate_t *sub = message_substring(r"rror");

    n00b_plan_node_t *indexed = plan_ok(
        n00b_plan_build_raw(sub, index_list_with(index)));
    n00b_plan_node_t *scanned = plan_ok(
        n00b_plan_build_raw(sub, n00b_plan_index_list_new()));

    uint64_t expected[] = {1, 2};
    check_set(ordset_ok(n00b_plan_exec_hot(indexed, shard)), 6, expected, 2);
    check_set(ordset_ok(n00b_plan_exec_hot(scanned, shard)), 6, expected, 2);
}

// Shorter than the gram width, so the index has nothing to offer.
static void
test_short_substring_falls_back_to_scan_verify(void)
{
    n00b_store_index_t     *index   = ngram_index(r"message");
    n00b_store_shard_t     *shard   = sample_ngram_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    n00b_plan_predicate_t *sub  = message_substring(r"rr");
    n00b_plan_node_t      *plan = plan_ok(n00b_plan_build(sub, indexes));

    check_plan_flags(plan, sub, false);

    uint64_t expected[] = {1, 2, 3};
    check_set(ordset_ok(n00b_plan_exec_hot(plan, shard)), 6, expected, 3);
}

// The any-field identity carries whole-token postings and cannot answer this.
static void
test_substring_rejects_the_any_field_target(void)
{
    auto any_r = n00b_plan_target_any();
    CHECK(n00b_result_is_ok(any_r));
    CHECK_ERR(n00b_plan_predicate_substring(n00b_result_get(any_r), r"rror"),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_substring(field_target(r"message"), r""),
              N00B_PLAN_ERR_ARG);
}

static void
test_planner_prefix_uses_ngram_candidates_with_residual(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_ngram_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *prefix = message_prefix(r"Err");

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(prefix, indexes));

    check_plan_flags(plan, prefix, true);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {1};
    check_set(verified, 6, verified_expected, 1);
}

static void
test_short_prefix_falls_back_to_scan_verify(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_ngram_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *prefix = message_prefix(r"Er");

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(prefix, indexes));

    check_plan_flags(plan, prefix, false);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {1};
    check_set(verified, 6, verified_expected, 1);
}

static void
test_contains_with_ngram_only_falls_back_to_scan_verify(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_ngram_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    n00b_plan_predicate_t *short_contains = message_contains(r"err");
    n00b_plan_node_t *short_plan = plan_ok(
        n00b_plan_build(short_contains, indexes));
    check_plan_flags(short_plan, short_contains, false);
    n00b_plan_ordset_t *short_verified =
        ordset_ok(n00b_plan_exec_hot(short_plan, shard));
    check_set(short_verified, 6, nullptr, 0);

    n00b_plan_predicate_t *opening = message_contains(r"OPENING");
    n00b_plan_node_t *opening_plan = plan_ok(
        n00b_plan_build(opening, indexes));
    check_plan_flags(opening_plan, opening, false);
    n00b_plan_ordset_t *opening_verified =
        ordset_ok(n00b_plan_exec_hot(opening_plan, shard));
    uint64_t opening_expected[] = {1, 2};
    check_set(opening_verified, 6, opening_expected, 2);
}

static void
test_ngram_not_used_for_contains_false_negative_boundary(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = shard_ok(UINT64_C(0x7204));
    n00b_plan_index_list_t *indexes = index_list_with(index);

    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"error opening"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"error:opening"),
                              1);

    n00b_plan_predicate_t *contains = message_contains(r"error opening");
    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(contains, indexes));
    uint64_t full[] = {0, 1};
    check_plan_flags(plan, contains, false);
    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    // contains is token-normalized (separators ignored): both "error opening"
    // and "error:opening" tokenize to {error, opening}, so the multi-word
    // needle matches both.
    check_set(verified, 2, full, 2);

    n00b_plan_predicate_t *opening = message_contains(r"opening");
    n00b_plan_node_t *opening_plan = plan_ok(
        n00b_plan_build(opening, indexes));
    check_plan_flags(opening_plan, opening, false);
    n00b_plan_ordset_t *opening_verified =
        ordset_ok(n00b_plan_exec_hot(opening_plan, shard));
    check_set(opening_verified, 2, full, 2);
}

static void
test_direct_ngram_lookup_remains_candidate_only(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_ngram_shard(index);

    auto short_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"err"));
    CHECK(n00b_result_is_ok(short_r));
    uint64_t short_candidates[] = {1, 2, 3};
    check_postings(n00b_result_get(short_r),
                   UINT64_C(0x7200),
                   0,
                   short_candidates,
                   3);
}

static void
test_fulltext_priority_over_ngram_for_contains(void)
{
    n00b_store_index_t *ngram   = ngram_index(r"message");
    n00b_store_index_t *fulltext = fulltext_index(r"message");
    n00b_store_shard_t *shard   = shard_ok(UINT64_C(0x7201));

    uint64_t a = append_record(shard, record_with_message(r"Error opening"));
    index_existing_record(ngram, shard, a);
    index_existing_record(fulltext, shard, a);

    uint64_t b = append_record(shard, record_with_message(r"terror opening"));
    index_existing_record(ngram, shard, b);
    index_existing_record(fulltext, shard, b);

    uint64_t c = append_record(shard, record_with_message(r"disk error"));
    index_existing_record(ngram, shard, c);
    index_existing_record(fulltext, shard, c);

    n00b_plan_predicate_t *contains = message_contains(r"ERROR");
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(contains, index_list_with_two(ngram, fulltext)));

    uint64_t expected[] = {0, 2};
    check_plan_flags(plan, nullptr, true);
    check_set(ordset_ok(n00b_plan_exec_hot(plan, shard)), 3, expected, 2);
}

static void
test_no_false_negatives_across_hot_shards(void)
{
    n00b_store_index_t *index = ngram_index(r"message");

    n00b_store_shard_t *left = shard_ok(UINT64_C(0x7202));
    append_and_index_at_least(index,
                              left,
                              record_with_message(r"opening left"),
                              1);
    append_and_index_at_least(index,
                              left,
                              record_with_message(r"closed"),
                              1);

    n00b_store_shard_t *right = shard_ok(UINT64_C(0x7203));
    append_and_index_at_least(index,
                              right,
                              record_with_message(r"opening right"),
                              1);
    append_and_index_at_least(index,
                              right,
                              record_with_message(r"other"),
                              1);

    n00b_plan_predicate_t *prefix = message_prefix(r"opening");

    // One plan, both shards. It carries no shard state, so there is nothing
    // to rebuild between them.
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(prefix, index_list_with(index)));

    uint64_t expected[] = {0};
    check_set(ordset_ok(n00b_plan_exec_hot(plan, left)), 2, expected, 1);
    check_set(ordset_ok(n00b_plan_exec_hot(plan, right)), 2, expected, 1);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_ngram_descriptor_contract();
    test_custom_ngram_width_lookup();
    test_hot_ngram_lookup_candidates_and_dedup();
    test_mapped_ngram_readback_uses_sealed_index();
    test_substring_matches_inside_a_word();
    test_substring_answers_alike_without_an_index();
    test_short_substring_falls_back_to_scan_verify();
    test_substring_rejects_the_any_field_target();
    test_planner_prefix_uses_ngram_candidates_with_residual();
    test_short_prefix_falls_back_to_scan_verify();
    test_contains_with_ngram_only_falls_back_to_scan_verify();
    test_ngram_not_used_for_contains_false_negative_boundary();
    test_direct_ngram_lookup_remains_candidate_only();
    test_fulltext_priority_over_ngram_for_contains();
    test_no_false_negatives_across_hot_shards();

    n00b_shutdown();
    return 0;
}

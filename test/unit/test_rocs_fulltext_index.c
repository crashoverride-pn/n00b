/* test/unit/test_rocs_fulltext_index.c - WP-010 Phase 1 full-text index. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal planner declarations must not be included by rocs/n00b_rocs.h"
#endif

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

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

static n00b_plan_index_list_t *
index_list_with(n00b_store_index_t *index)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, index)));
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
append_and_index(n00b_store_index_t *index,
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

    auto exact_r = n00b_plan_is_exact(plan);
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
sample_text_shard(n00b_store_index_t *index)
{
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7101));
    append_and_index(index, shard, record_with_message(r"Error opening"), 3);
    append_and_index(index, shard, record_with_message(r"terror opening"), 3);
    append_and_index(index, shard, record_with_message(r"disk error"), 3);
    append_and_index(index, shard, record_without_message(), 0);
    append_and_index(index,
                     shard,
                     record_with_message_node(n00b_json_int_new(7)),
                     0);
    return shard;
}

static void
test_fulltext_descriptor_contract(void)
{
    n00b_store_index_t *index = fulltext_index(r"message");

    n00b_store_advert_t contains =
        n00b_store_index_advertise(index,
                                   r"message",
                                   N00B_STORE_INDEX_OP_CONTAINS);
    CHECK(contains.accelerates);
    CHECK(contains.kind == N00B_STORE_INDEX_FULLTEXT);
    CHECK(contains.selectivity_hint < 1.0);

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
                                   N00B_STORE_INDEX_OP_CONTAINS);
    CHECK(!mismatch.accelerates);
    CHECK(mismatch.kind == N00B_STORE_INDEX_NONE);
}

static void
test_hot_fulltext_lookup_and_normalization(void)
{
    n00b_store_index_t *index = fulltext_index(r"message");
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7100));

    append_and_index(index,
                     shard,
                     record_with_message(r"Error opening ERROR"),
                     3);
    append_and_index(index, shard, record_with_message(r"terror opening"), 3);
    append_and_index(index, shard, record_with_message(r"disk full"), 3);
    append_and_index(index, shard, record_without_message(), 0);
    append_and_index(index, shard, record_with_message(r""), 0);
    append_and_index(index,
                     shard,
                     record_with_message_node(n00b_json_int_new(7)),
                     0);

    auto error_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"ERROR"));
    CHECK(n00b_result_is_ok(error_r));
    uint64_t error_expected[] = {0};
    check_postings(n00b_result_get(error_r),
                   UINT64_C(0x7100),
                   0,
                   error_expected,
                   1);

    auto opening_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"opening"));
    CHECK(n00b_result_is_ok(opening_r));
    uint64_t opening_expected[] = {0, 1};
    check_postings(n00b_result_get(opening_r),
                   UINT64_C(0x7100),
                   0,
                   opening_expected,
                   2);

    auto miss_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"err"));
    CHECK(n00b_result_is_ok(miss_r));
    check_posting_len(n00b_result_get(miss_r), 0);

    auto exact_phrase_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"error opening error"));
    CHECK(n00b_result_is_ok(exact_phrase_r));
    uint64_t phrase_expected[] = {0};
    check_postings(n00b_result_get(exact_phrase_r),
                   UINT64_C(0x7100),
                   0,
                   phrase_expected,
                   1);

    auto partial_phrase_r = n00b_store_index_lookup(
        index,
        shard,
        n00b_json_string_new_from_n00b(r"error opening"));
    CHECK(n00b_result_is_ok(partial_phrase_r));
    check_posting_len(n00b_result_get(partial_phrase_r), 0);
    CHECK_ERR(n00b_store_index_lookup(index, shard, n00b_json_int_new(1)),
              N00B_STORE_INDEX_ERR_ARG);
    CHECK_ERR(n00b_store_index_lookup(
                  index,
                  shard,
                  n00b_json_string_new_from_n00b(r" !! ")),
              N00B_STORE_INDEX_ERR_ARG);
}

static void
test_mapped_fulltext_readback_uses_sealed_index(void)
{
    n00b_store_index_t *index = fulltext_index(r"message");
    n00b_store_shard_t *shard = sample_text_shard(index);

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 81,
                                        .base_address = 0x710000u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    n00b_store_map_t *map = n00b_result_get(map_r);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));

    auto lookup_r = n00b_store_index_lookup_mapped(
        index,
        n00b_result_get(root_r),
        n00b_json_string_new_from_n00b(r"error"));
    CHECK(n00b_result_is_ok(lookup_r));
    uint64_t expected[] = {0, 2};
    check_postings(n00b_result_get(lookup_r),
                   UINT64_C(0x7101),
                   81,
                   expected,
                   2);

    auto close_r = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_planner_uses_hot_fulltext_index_for_contains(void)
{
    n00b_store_index_t     *index = fulltext_index(r"message");
    n00b_store_shard_t     *shard = sample_text_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *contains = message_contains(r"ERROR");

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(contains, indexes));

    uint64_t expected[] = {0, 2};
    check_plan_flags(plan, nullptr, true);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    check_set(verified, 5, expected, 2);
}

static void
test_contains_fallbacks_scan_and_verify_whole_tokens(void)
{
    n00b_store_index_t *index = fulltext_index(r"message");
    n00b_store_shard_t *shard = sample_text_shard(index);

    n00b_plan_predicate_t *contains = message_contains(r"error");
    n00b_plan_node_t *no_index = plan_ok(n00b_plan_build(contains, nullptr));
    check_plan_flags(no_index, contains, false);

    uint64_t token_expected[] = {0, 2};
    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(no_index, shard));
    check_set(verified, 5, token_expected, 2);

    n00b_plan_predicate_t *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"Error"));
    n00b_plan_node_t *prefix_plan = plan_ok(
        n00b_plan_build(prefix, index_list_with(index)));
    check_plan_flags(prefix_plan, prefix, false);
    uint64_t prefix_expected[] = {0};
    n00b_plan_ordset_t *prefix_verified =
        ordset_ok(n00b_plan_exec_hot(prefix_plan, shard));
    check_set(prefix_verified, 5, prefix_expected, 1);

    n00b_plan_predicate_t *multi = message_contains(r"error opening");
    n00b_plan_node_t *multi_plan = plan_ok(
        n00b_plan_build(multi, index_list_with(index)));
    uint64_t multi_expected[] = {0};
    check_plan_flags(multi_plan, nullptr, true);
    n00b_plan_ordset_t *multi_verified =
        ordset_ok(n00b_plan_exec_hot(multi_plan, shard));
    check_set(multi_verified, 5, multi_expected, 1);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_fulltext_descriptor_contract();
    test_hot_fulltext_lookup_and_normalization();
    test_mapped_fulltext_readback_uses_sealed_index();
    test_planner_uses_hot_fulltext_index_for_contains();
    test_contains_fallbacks_scan_and_verify_whole_tokens();

    n00b_shutdown();
    return 0;
}

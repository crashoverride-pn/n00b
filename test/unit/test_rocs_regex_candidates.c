/* test/unit/test_rocs_regex_candidates.c - WP-010 Phase 3 regex candidates. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

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

static n00b_regex_t *
regex_ok(n00b_result_t(n00b_regex_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_regex_t *regex = n00b_result_get(r);
    CHECK(regex != nullptr);
    return regex;
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    return target_ok(n00b_plan_target_field(field));
}

static n00b_plan_predicate_t *
message_regex(n00b_regex_t *regex)
{
    return predicate_ok(n00b_plan_predicate_regex(field_target(r"message"),
                                                 regex));
}

static n00b_plan_index_list_t *
index_list_with(n00b_store_index_t *index)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(indexes != nullptr);
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

static n00b_store_shard_t *
sample_regex_shard(n00b_store_index_t *index)
{
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7300));
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"qzj42 open"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"prefix qzj900 close"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"qzj open"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"xqzjY open"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"QZJ77 uppercase"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"qz7 short"),
                              1);
    append_and_index_exact(index, shard, record_without_message(), 0);
    append_and_index_exact(index,
                           shard,
                           record_with_message_node(n00b_json_int_new(123)),
                           0);
    return shard;
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

static void
check_prefix_opt(n00b_regex_t *regex,
                 n00b_string_t *expected,
                 bool expected_set)
{
    n00b_option_t(n00b_string_t *) opt =
        n00b_regex_required_literal_prefix(regex);
    CHECK(n00b_option_is_set(opt) == expected_set);
    if (expected_set) {
        CHECK(n00b_unicode_str_eq(n00b_option_get(opt), expected));
    }
}

static void
test_regex_prefix_accessor_shape(void)
{
    check_prefix_opt(regex_ok(n00b_regex_new(r"qzj[0-9]+")), r"qzj", true);
    check_prefix_opt(regex_ok(n00b_regex_new(r"qz[0-9]+")), r"qz", true);
    check_prefix_opt(regex_ok(n00b_regex_new(r"[qQ]zj[0-9]+")),
                     nullptr,
                     false);
    check_prefix_opt(regex_ok(n00b_regex_new(r"[0-9]+")), nullptr, false);
}

static void
test_literal_regex_uses_ngram_candidates_with_residual(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex =
        message_regex(regex_ok(n00b_regex_new(r"qzj[0-9]+")));

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(regex, indexes));

    check_plan_flags(plan, regex, true);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {0, 1};
    check_set(verified, 8, verified_expected, 2);
}

static void
test_regex_without_usable_prefix_scans_and_verifies(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_regex_shard(index);

    n00b_plan_predicate_t *broad =
        message_regex(regex_ok(n00b_regex_new(r"[qQ]zj[0-9]+")));
    n00b_plan_node_t *broad_dispatch = plan_ok(
        n00b_plan_build(broad, index_list_with(index)));
    check_plan_flags(broad_dispatch, broad, false);
    n00b_plan_ordset_t *broad_verified =
        ordset_ok(n00b_plan_exec_hot(broad_dispatch, shard));
    uint64_t broad_expected[] = {0, 1};
    check_set(broad_verified, 8, broad_expected, 2);

    n00b_plan_predicate_t *digits =
        message_regex(regex_ok(n00b_regex_new(r"[0-9]+")));
    n00b_plan_node_t *digits_dispatch = plan_ok(
        n00b_plan_build(digits, index_list_with(index)));
    check_plan_flags(digits_dispatch, digits, false);
    n00b_plan_ordset_t *digits_verified =
        ordset_ok(n00b_plan_exec_hot(digits_dispatch, shard));
    uint64_t digits_expected[] = {0, 1, 4, 5};
    check_set(digits_verified, 8, digits_expected, 4);
}

static void
test_short_literal_regex_falls_back_to_scan_verify(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex =
        message_regex(regex_ok(n00b_regex_new(r"qz[0-9]+")));

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(regex, indexes));

    check_plan_flags(plan, regex, false);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {5};
    check_set(verified, 8, verified_expected, 1);
}

static void
test_one_plan_runs_against_any_shard(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex =
        message_regex(regex_ok(n00b_regex_new(r"qzj[0-9]+")));
    // A plan carries no shard, so one plan serves any shard. This is what
    // lets a sealed fan-out build once and execute per shard.
    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(regex, indexes));

    n00b_store_shard_t *other = shard_ok(UINT64_C(0x7301));
    append_record(other, record_with_message(r"qzj42 only"));

    n00b_plan_ordset_t *first = ordset_ok(n00b_plan_exec_hot(plan, shard));
    auto first_rc = n00b_plan_ordset_record_count(first);
    CHECK(n00b_result_is_ok(first_rc));
    CHECK(n00b_result_get(first_rc) == 8);

    n00b_plan_ordset_t *second = ordset_ok(n00b_plan_exec_hot(plan, other));
    auto second_rc = n00b_plan_ordset_record_count(second);
    CHECK(n00b_result_is_ok(second_rc));
    CHECK(n00b_result_get(second_rc) == 1);
}

static void
test_mapped_regex_uses_ngram_candidates_with_residual(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_regex_shard(index);

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 93,
                                        .base_address = 0x730000u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    n00b_store_map_t *map = n00b_result_get(map_r);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_predicate_t *regex =
        message_regex(regex_ok(n00b_regex_new(r"qzj[0-9]+")));
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(regex, index_list_with(index)));

    check_plan_flags(plan, regex, true);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_mapped(plan, n00b_result_get(root_r)));
    uint64_t verified_expected[] = {0, 1};
    check_set(verified, 8, verified_expected, 2);

    CHECK(n00b_result_is_ok(n00b_store_map_close(map)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_regex_prefix_accessor_shape();
    test_literal_regex_uses_ngram_candidates_with_residual();
    test_regex_without_usable_prefix_scans_and_verifies();
    test_short_literal_regex_falls_back_to_scan_verify();
    test_one_plan_runs_against_any_shard();
    test_mapped_regex_uses_ngram_candidates_with_residual();

    n00b_shutdown();
    return 0;
}

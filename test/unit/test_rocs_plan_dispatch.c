/* test/unit/test_rocs_plan_dispatch.c - WP-006 Phase 3 index dispatch. */

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

static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

static n00b_json_node_t *
record_with_fields(n00b_string_t *level, n00b_string_t *message)
{
    n00b_json_node_t *record = n00b_json_object_new();
    if (level != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"level",
                                  n00b_json_string_new_from_n00b(level));
    }
    n00b_json_object_put_n00b(record,
                              r"message",
                              n00b_json_string_new_from_n00b(message));
    return record;
}

static n00b_store_index_t *
index_ok(n00b_result_t(n00b_store_index_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_store_index_t *index = n00b_result_get(r);
    CHECK(index != nullptr);
    return index;
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
exec_hot_ok(n00b_plan_node_t *plan, n00b_store_shard_t *shard)
{
    auto r = n00b_plan_exec_hot(plan, shard);
    CHECK(n00b_result_is_ok(r));
    n00b_plan_ordset_t *set = n00b_result_get(r);
    CHECK(set != nullptr);
    return set;
}

static n00b_plan_ordset_t *
exec_mapped_ok(n00b_plan_node_t *plan, n00b_store_map_shard_t *root)
{
    auto r = n00b_plan_exec_mapped(plan, root);
    CHECK(n00b_result_is_ok(r));
    n00b_plan_ordset_t *set = n00b_result_get(r);
    CHECK(set != nullptr);
    return set;
}

static n00b_store_index_t *
term_index(n00b_string_t *field)
{
    return index_ok(n00b_store_index_new(field, N00B_STORE_INDEX_TERM));
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    return target_ok(n00b_plan_target_field(field));
}

static n00b_plan_index_list_t *
index_list_with(n00b_store_index_t *index)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    auto append_r = n00b_plan_index_list_append(indexes, index);
    CHECK(n00b_result_is_ok(append_r));
    return indexes;
}

static n00b_plan_predicate_t *
level_eq(n00b_string_t *level)
{
    return predicate_ok(
        n00b_plan_predicate_eq(field_target(r"level"),
                               json_value(n00b_json_string_new_from_n00b(level))));
}

static n00b_store_shard_t *
indexed_level_shard(n00b_store_index_t *index)
{
    auto shard_r = n00b_store_shard_new(.shard_id = UINT64_C(0x600d));
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);

    n00b_json_node_t *info =
        record_with_fields(r"info", r"startup complete");
    n00b_json_node_t *error_a =
        record_with_fields(r"error", r"timeout while opening");
    n00b_json_node_t *error_b =
        record_with_fields(r"error", r"timeout while reading");
    n00b_json_node_t *missing =
        record_with_fields(nullptr, r"message without level");

    auto a0 = n00b_store_shard_append(shard, info);
    auto a1 = n00b_store_shard_append(shard, error_a);
    auto a2 = n00b_store_shard_append(shard, error_b);
    auto a3 = n00b_store_shard_append(shard, missing);
    CHECK(n00b_result_is_ok(a0));
    CHECK(n00b_result_is_ok(a1));
    CHECK(n00b_result_is_ok(a2));
    CHECK(n00b_result_is_ok(a3));

    auto i0 = n00b_store_index_add(index, shard, n00b_result_get(a0));
    auto i1 = n00b_store_index_add(index, shard, n00b_result_get(a1));
    auto i2 = n00b_store_index_add(index, shard, n00b_result_get(a2));
    auto i3 = n00b_store_index_add(index, shard, n00b_result_get(a3));
    CHECK(n00b_result_is_ok(i0));
    CHECK(n00b_result_is_ok(i1));
    CHECK(n00b_result_is_ok(i2));
    CHECK(n00b_result_is_ok(i3));
    CHECK(n00b_result_get(i0) == 1);
    CHECK(n00b_result_get(i1) == 1);
    CHECK(n00b_result_get(i2) == 1);
    CHECK(n00b_result_get(i3) == 0);

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
check_ordinals(n00b_plan_ordset_t *set,
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
check_record_scan(n00b_plan_node_t      *plan,
                  n00b_plan_predicate_t *expected)
{
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    n00b_option_t(n00b_plan_predicate_t *) sole = n00b_result_get(sole_r);

    auto exact_r = n00b_plan_is_exact(plan);
    CHECK(n00b_result_is_ok(exact_r));

    if (expected == nullptr) {
        CHECK(!n00b_option_is_set(sole));
        CHECK(n00b_result_get(exact_r));
    }
    else {
        CHECK(n00b_option_is_set(sole));
        CHECK(n00b_option_get(sole) == expected);
        CHECK(!n00b_result_get(exact_r));
    }
}

static void
check_used_index(n00b_plan_node_t *plan, bool expected)
{
    auto used_r = n00b_plan_uses_index(plan);
    CHECK(n00b_result_is_ok(used_r));
    CHECK(n00b_result_get(used_r) == expected);
}

static void
test_hot_term_eq_uses_index(void)
{
    n00b_store_index_t     *index = term_index(r"level");
    n00b_store_shard_t     *shard = indexed_level_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *eq = level_eq(r"error");

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(eq, indexes));

    uint64_t expected[] = {1, 2};
    check_ordinals(exec_hot_ok(plan, shard), 4, expected, 2);
    check_record_scan(plan, nullptr);
    check_used_index(plan, true);
}

static void
test_mapped_term_eq_uses_index(void)
{
    n00b_store_index_t *index = term_index(r"level");
    n00b_store_shard_t *shard = indexed_level_shard(index);

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 72,
                                        .base_address = 0x7200u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    n00b_store_map_t *map = n00b_result_get(map_r);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(level_eq(r"error"), index_list_with(index)));

    uint64_t expected[] = {1, 2};
    check_ordinals(exec_mapped_ok(plan, n00b_result_get(root_r)),
                   4, expected, 2);
    check_record_scan(plan, nullptr);
    check_used_index(plan, true);

    auto close_r = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_unusable_index_plans_a_record_scan(void)
{
    n00b_store_index_t *level_index = term_index(r"level");
    n00b_store_shard_t *shard       = indexed_level_shard(level_index);

    n00b_plan_predicate_t *eq = level_eq(r"error");
    n00b_plan_node_t *mismatch = plan_ok(
        n00b_plan_build(eq, index_list_with(term_index(r"message"))));
    // Nothing accelerates this, so the plan is a bare record scan. Execution
    // answers with the matching records, not with the universe the old
    // dispatch handed to a separate verify step.
    uint64_t errors[] = {1, 2};
    check_ordinals(exec_hot_ok(mismatch, shard), 4, errors, 2);
    check_record_scan(mismatch, eq);
    check_used_index(mismatch, false);

    n00b_store_index_t *fulltext =
        index_ok(n00b_store_index_new(r"level", N00B_STORE_INDEX_FULLTEXT));
    n00b_plan_predicate_t *eq2 = level_eq(r"error");
    n00b_plan_node_t *unready = plan_ok(
        n00b_plan_build(eq2, index_list_with(fulltext)));
    check_ordinals(exec_hot_ok(unready, shard), 4, errors, 2);
    check_record_scan(unready, eq2);
    check_used_index(unready, false);
}

static void
test_index_miss_and_unusable_lookup(void)
{
    n00b_store_index_t     *index = term_index(r"level");
    n00b_store_shard_t     *shard = indexed_level_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    n00b_plan_node_t *miss = plan_ok(
        n00b_plan_build(level_eq(r"warn"), indexes));
    check_ordinals(exec_hot_ok(miss, shard), 4, nullptr, 0);
    check_record_scan(miss, nullptr);
    check_used_index(miss, true);

    union [[n00b::raw_union]] {
        uint64_t u;
        double   f;
    } inf = {
        .u = UINT64_C(0x7ff0000000000000),
    };
    n00b_plan_predicate_t *bad_value = predicate_ok(
        n00b_plan_predicate_eq(field_target(r"level"),
                               json_value(n00b_json_double_new(inf.f))));
    // The planner cannot know the lookup will fail, so it plans an exact
    // index scan and records how to recover. Execution hits the failure and
    // falls back to evaluating the predicate, which must narrow the universe;
    // returning it unfiltered would answer with the whole shard.
    n00b_plan_node_t *failed = plan_ok(n00b_plan_build(bad_value, indexes));
    check_ordinals(exec_hot_ok(failed, shard), 4, nullptr, 0);
    check_record_scan(failed, nullptr);
    check_used_index(failed, true);
}

static void
test_boolean_plan_shapes(void)
{
    n00b_store_index_t     *index = term_index(r"level");
    n00b_store_shard_t     *shard = indexed_level_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    n00b_plan_predicate_t *eq = level_eq(r"error");
    n00b_plan_predicate_t *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout"));

    n00b_plan_predicate_list_t *and_children =
        n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children, eq)));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, prefix)));
    n00b_plan_predicate_t *and =
        predicate_ok(n00b_plan_predicate_and(and_children));
    n00b_plan_node_t *and_plan = plan_ok(n00b_plan_build(and, indexes));
    check_record_scan(and_plan, prefix);
    check_used_index(and_plan, true);

    n00b_plan_predicate_list_t *or_children =
        n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, prefix)));
    n00b_plan_predicate_t *or =
        predicate_ok(n00b_plan_predicate_or(or_children));
    // The record scan now covers only the branch that needs it. The eq branch
    // is answered from its index, where the old dispatch re-tested the whole
    // OR against every record.
    n00b_plan_node_t *or_plan = plan_ok(n00b_plan_build(or, indexes));
    check_record_scan(or_plan, prefix);
    check_used_index(or_plan, true);

    n00b_plan_predicate_t *not_exact =
        predicate_ok(n00b_plan_predicate_not(level_eq(r"error")));
    n00b_plan_node_t *not_exact_plan =
        plan_ok(n00b_plan_build(not_exact, indexes));
    uint64_t not_errors[] = {0, 3};
    check_ordinals(exec_hot_ok(not_exact_plan, shard), 4, not_errors, 2);
    check_record_scan(not_exact_plan, nullptr);
    check_used_index(not_exact_plan, true);

    n00b_plan_predicate_t *not_prefix =
        predicate_ok(n00b_plan_predicate_not(prefix));
    n00b_plan_node_t *not_prefix_plan =
        plan_ok(n00b_plan_build(not_prefix, indexes));
    check_record_scan(not_prefix_plan, prefix);
    check_used_index(not_prefix_plan, false);
}

static void
test_invalid_plan_inputs(void)
{
    n00b_store_index_t *index = term_index(r"level");
    n00b_store_shard_t *shard = indexed_level_shard(index);
    CHECK_ERR(n00b_plan_build(nullptr, index_list_with(index)),
              N00B_PLAN_ERR_ARG);
    // The shard belongs to execution now, so a missing one is caught there.
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(level_eq(r"error"), index_list_with(index)));
    CHECK_ERR(n00b_plan_exec_hot(plan, nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_exec_hot(nullptr, shard), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_node_kind(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_node_child_count(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_node_child_at(nullptr, 0), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_uses_index(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_is_exact(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_sole_record_scan(nullptr), N00B_PLAN_ERR_ARG);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_hot_term_eq_uses_index();
    test_mapped_term_eq_uses_index();
    test_unusable_index_plans_a_record_scan();
    test_index_miss_and_unusable_lookup();
    test_boolean_plan_shapes();
    test_invalid_plan_inputs();

    n00b_shutdown();
    return 0;
}

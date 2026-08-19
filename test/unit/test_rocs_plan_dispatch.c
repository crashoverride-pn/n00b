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

#include "plan_oracle.h"

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

    auto exact_r = n00b_plan_reads_no_records(plan);
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

    // Boolean plans over a sealed shard, including the record-scan branch and
    // the complement, which the hot path covers separately.
    n00b_plan_predicate_t *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout"));
    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(children, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(children, prefix)));
    n00b_plan_node_t *and_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_and(children)),
                        index_list_with(index)));
    check_ordinals(exec_mapped_ok(and_plan, n00b_result_get(root_r)),
                   4, expected, 2);

    n00b_plan_node_t *not_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
                        index_list_with(index)));
    uint64_t others[] = {0, 3};
    check_ordinals(exec_mapped_ok(not_plan, n00b_result_get(root_r)),
                   4, others, 2);

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
    // Nothing accelerates this, so the plan is a bare record scan and
    // execution answers with the records that match.
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
    // Only the branch that needs a record scan gets one; the eq branch is
    // answered from its index.
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
    // Negating something indefinite cannot be a set complement, so the
    // negation itself becomes what the record scan tests.
    n00b_plan_node_t *not_prefix_plan =
        plan_ok(n00b_plan_build(not_prefix, indexes));
    check_record_scan(not_prefix_plan, not_prefix);
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
    CHECK_ERR(n00b_plan_reads_no_records(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_sole_record_scan(nullptr), N00B_PLAN_ERR_ARG);
}


static uint64_t scan_polls = 0;

static bool
count_poll(void *ctx)
{
    (void)ctx;
    scan_polls++;
    return false;
}

static n00b_plan_node_t *
child_at_ok(n00b_plan_node_t *node, uint64_t i)
{
    auto r = n00b_plan_node_child_at(node, i);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_option_is_set(n00b_result_get(r)));
    return n00b_option_get(n00b_result_get(r));
}

static void
check_kind(n00b_plan_node_t *node, n00b_plan_node_kind_t expected)
{
    auto r = n00b_plan_node_kind(node);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_get(r) == expected);
}

static void
check_child_count(n00b_plan_node_t *node, uint64_t expected)
{
    auto r = n00b_plan_node_child_count(node);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_get(r) == expected);
}

static void
test_plan_node_structure(void)
{
    n00b_store_index_t     *index   = term_index(r"level");
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout"));

    check_kind(plan_ok(n00b_plan_build(level_eq(r"error"), indexes)),
               N00B_PLAN_NODE_INDEX_SCAN);
    check_kind(plan_ok(n00b_plan_build(prefix, indexes)),
               N00B_PLAN_NODE_RECORD_SCAN);

    n00b_plan_predicate_list_t *and_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, prefix)));
    n00b_plan_node_t *and_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_and(and_children)),
                        indexes));
    check_kind(and_plan, N00B_PLAN_NODE_INTERSECT);
    check_child_count(and_plan, 2);
    check_kind(child_at_ok(and_plan, 0), N00B_PLAN_NODE_INDEX_SCAN);
    check_kind(child_at_ok(and_plan, 1), N00B_PLAN_NODE_RECORD_SCAN);

    n00b_plan_predicate_list_t *or_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, prefix)));
    n00b_plan_node_t *or_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_or(or_children)),
                        indexes));
    check_kind(or_plan, N00B_PLAN_NODE_UNION);
    check_child_count(or_plan, 2);

    n00b_plan_node_t *not_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
                        indexes));
    check_kind(not_plan, N00B_PLAN_NODE_COMPLEMENT);
    check_child_count(not_plan, 1);
    check_kind(child_at_ok(not_plan, 0), N00B_PLAN_NODE_INDEX_SCAN);

    check_kind(plan_ok(n00b_plan_build(predicate_ok(n00b_plan_predicate_false()),
                                       indexes)),
               N00B_PLAN_NODE_EMPTY);
}

static void
test_boolean_execution_results(void)
{
    n00b_store_index_t     *index   = term_index(r"level");
    n00b_store_shard_t     *shard   = indexed_level_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout"));

    // Both branches select the same two records by different means: the index
    // for level, a record scan for the message prefix.
    n00b_plan_predicate_list_t *or_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, prefix)));
    n00b_plan_node_t *or_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_or(or_children)),
                        indexes));
    uint64_t errors[] = {1, 2};
    check_ordinals(exec_hot_ok(or_plan, shard), 4, errors, 2);

    n00b_plan_predicate_list_t *and_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, prefix)));
    n00b_plan_node_t *and_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_and(and_children)),
                        indexes));
    check_ordinals(exec_hot_ok(and_plan, shard), 4, errors, 2);

    n00b_plan_node_t *not_prefix_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_not(prefix)),
                        indexes));
    uint64_t others[] = {0, 3};
    check_ordinals(exec_hot_ok(not_prefix_plan, shard), 4, others, 2);
}

static void
test_execution_short_circuits(void)
{
    n00b_store_index_t     *index   = term_index(r"level");
    n00b_store_shard_t     *shard   = indexed_level_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout"));

    // The cancel callback doubles as a probe: only a record scan polls it, so
    // a poll count of zero means no record was ever read.

    // An intersect whose index branch selects nothing cannot gain rows from
    // its record-scan sibling, so the sibling is not run.
    n00b_plan_predicate_list_t *and_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, level_eq(r"warn"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(and_children, prefix)));
    n00b_plan_node_t *and_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_and(and_children)),
                        indexes));
    n00b_plan_records_scanned_reset();
    auto and_r = n00b_plan_exec_hot(and_plan, shard);
    CHECK(n00b_result_is_ok(and_r));
    check_ordinals(n00b_result_get(and_r), 4, nullptr, 0);
    CHECK(n00b_plan_records_scanned() == 0);

    // A union that already holds every record cannot gain rows either.
    n00b_plan_predicate_list_t *or_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
        or_children,
        predicate_ok(n00b_plan_predicate_not(level_eq(r"warn"))))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(or_children, prefix)));
    n00b_plan_node_t *or_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_or(or_children)),
                        indexes));
    n00b_plan_records_scanned_reset();
    auto or_r = n00b_plan_exec_hot(or_plan, shard);
    CHECK(n00b_result_is_ok(or_r));
    uint64_t all[] = {0, 1, 2, 3};
    check_ordinals(n00b_result_get(or_r), 4, all, 4);
    CHECK(n00b_plan_records_scanned() == 0);

    // The same plan shape with a non-empty index branch does reach its record
    // scan, which is what makes the two zero counts above meaningful.
    n00b_plan_predicate_list_t *live = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(live, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(live, prefix)));
    n00b_plan_node_t *live_plan = plan_ok(
        n00b_plan_build(predicate_ok(n00b_plan_predicate_and(live)), indexes));
    n00b_plan_records_scanned_reset();
    auto live_r = n00b_plan_exec_hot(live_plan, shard);
    CHECK(n00b_result_is_ok(live_r));
    CHECK(n00b_plan_records_scanned() > 0);
}


static void
test_indexed_queries_read_no_records(void)
{
    n00b_store_index_t     *index   = term_index(r"level");
    n00b_store_shard_t     *shard   = indexed_level_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    // An index exists so the query can be answered from it alone. Reading a
    // record here would mean the plan gained a record scan it does not need,
    // which no assertion on the result would notice.

    n00b_plan_records_scanned_reset();
    auto hit_r = n00b_plan_exec_hot(plan_ok(n00b_plan_build(level_eq(r"error"),
                                                            indexes)),
                                    shard);
    CHECK(n00b_result_is_ok(hit_r));
    uint64_t errors[] = {1, 2};
    check_ordinals(n00b_result_get(hit_r), 4, errors, 2);
    CHECK(n00b_plan_records_scanned() == 0);

    n00b_plan_records_scanned_reset();
    auto miss_r = n00b_plan_exec_hot(plan_ok(n00b_plan_build(level_eq(r"warn"),
                                                             indexes)),
                                     shard);
    CHECK(n00b_result_is_ok(miss_r));
    check_ordinals(n00b_result_get(miss_r), 4, nullptr, 0);
    CHECK(n00b_plan_records_scanned() == 0);

    // Complementing an exact set is still exact.
    n00b_plan_records_scanned_reset();
    auto not_r = n00b_plan_exec_hot(
        plan_ok(n00b_plan_build(predicate_ok(
                                    n00b_plan_predicate_not(level_eq(r"error"))),
                                indexes)),
        shard);
    CHECK(n00b_result_is_ok(not_r));
    uint64_t others[] = {0, 3};
    check_ordinals(n00b_result_get(not_r), 4, others, 2);
    CHECK(n00b_plan_records_scanned() == 0);

    // Control: with no index for the field the same probe does fire, so the
    // zero counts above mean the index answered rather than the probe failing.
    n00b_plan_predicate_t *prefix =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout"));
    n00b_plan_records_scanned_reset();
    auto scan_r = n00b_plan_exec_hot(plan_ok(n00b_plan_build(prefix, indexes)),
                                     shard);
    CHECK(n00b_result_is_ok(scan_r));
    CHECK(n00b_plan_records_scanned() > 0);
}


typedef struct {
    n00b_store_shard_t     *shard;
    n00b_plan_index_list_t *indexes;
} counted_sample_t;

// Six records. A "timeout" prefix selects three of them, level "error" selects
// two, and their intersection is two. The prefix branch is deliberately the
// broader one so that the cost of applying it before or after its sibling is
// a different number rather than the same number.
static counted_sample_t
counted_sample(void)
{
    n00b_store_index_t *level_index = term_index(r"level");
    n00b_store_index_t *msg_index   = index_ok(
        n00b_store_index_new(r"message", N00B_STORE_INDEX_NGRAM));
    n00b_store_index_t *text_index  = index_ok(
        n00b_store_index_new(r"message", N00B_STORE_INDEX_FULLTEXT));

    auto shard_r = n00b_store_shard_new(.shard_id = UINT64_C(0x600e));
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);

    n00b_json_node_t *records[] = {
        record_with_fields(r"info", r"startup complete"),
        record_with_fields(r"error", r"timeout while opening"),
        record_with_fields(r"error", r"timeout while reading"),
        record_with_fields(r"info", r"timeout while shutting down"),
        record_with_fields(r"info", r"disk full"),
        record_with_fields(r"warn", r"retry scheduled"),
    };
    for (uint64_t i = 0; i < 6; i++) {
        auto append_r = n00b_store_shard_append(shard, records[i]);
        CHECK(n00b_result_is_ok(append_r));
        CHECK(n00b_result_is_ok(n00b_store_index_add(level_index, shard, i)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(msg_index, shard, i)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(text_index, shard, i)));
    }

    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, level_index)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, msg_index)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, text_index)));

    return (counted_sample_t){.shard = shard, .indexes = indexes};
}

static uint64_t
records_scanned_by(n00b_plan_predicate_t  *predicate,
                   counted_sample_t        sample)
{
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(predicate, sample.indexes));
    n00b_plan_records_scanned_reset();
    auto r = n00b_plan_exec_hot(plan, sample.shard);
    CHECK(n00b_result_is_ok(r));
    return n00b_plan_records_scanned();
}

static n00b_plan_predicate_t *
msg_prefix(n00b_string_t *literal)
{
    return predicate_ok(
        n00b_plan_predicate_prefix(field_target(r"message"), literal));
}

static n00b_plan_predicate_t *
two_of(n00b_plan_predicate_t *a, n00b_plan_predicate_t *b, bool conjunction)
{
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, a)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, b)));
    return predicate_ok(conjunction ? n00b_plan_predicate_and(kids)
                                    : n00b_plan_predicate_or(kids));
}

static void
test_record_scan_cost(void)
{
    counted_sample_t sample = counted_sample();

    // An index answers this outright.
    CHECK(records_scanned_by(level_eq(r"error"), sample) == 0);

    // A lossy prefix reads its own candidates, not the shard.
    CHECK(records_scanned_by(msg_prefix(r"timeout"), sample) == 3);

    // The selective sibling has to be applied first, or this costs 3.
    CHECK(records_scanned_by(two_of(msg_prefix(r"timeout"),
                                    level_eq(r"error"),
                                    true),
                             sample)
          == 2);

    // Two unindexed branches are one pass over the shard, not two.
    n00b_plan_predicate_t *has_level =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"level")));
    n00b_plan_predicate_t *has_msg =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"message")));
    CHECK(records_scanned_by(two_of(has_level, has_msg, false), sample) == 6);
    CHECK(records_scanned_by(two_of(
                                 predicate_ok(n00b_plan_predicate_exists(
                                     field_target(r"level"))),
                                 predicate_ok(n00b_plan_predicate_exists(
                                     field_target(r"message"))),
                                 true),
                             sample)
          == 6);
}

static void
test_nested_group_inherits_sibling_restriction(void)
{
    counted_sample_t sample = counted_sample();

    // A union that cannot collapse to a single record scan, because one branch
    // is index-served, sitting beside a selective term. The union's record scan
    // should see only what the term already selected.
    n00b_plan_predicate_t *branchy =
        two_of(level_eq(r"warn"),
               predicate_ok(n00b_plan_predicate_exists(field_target(r"message"))),
               false);
    CHECK(records_scanned_by(two_of(branchy, level_eq(r"error"), true), sample)
          == 2);
}


static void
test_index_served_shapes_read_nothing(void)
{
    counted_sample_t sample = counted_sample();

    // Whole-token contains is answerable from the full-text index.
    CHECK(records_scanned_by(
              predicate_ok(n00b_plan_predicate_contains(field_target(r"message"),
                                                        r"timeout")),
              sample)
          == 0);

    // Complementing an exact set stays exact.
    CHECK(records_scanned_by(
              predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
              sample)
          == 0);

    // An intersect whose index branch is empty stops before the record scan.
    CHECK(records_scanned_by(two_of(level_eq(r"nosuch"),
                                    msg_prefix(r"timeout"),
                                    true),
                             sample)
          == 0);

    // A union that already covers the shard stops before its other branch.
    CHECK(records_scanned_by(two_of(
                                 predicate_ok(n00b_plan_predicate_not(
                                     level_eq(r"nosuch"))),
                                 msg_prefix(r"timeout"),
                                 false),
                             sample)
          == 0);
}

static void
test_broad_lossy_scan_degrades_to_the_shard(void)
{
    // The degradation rule needs at least 8 records before it will fire, so
    // the smaller fixtures above cannot reach it. Nine of these ten share a
    // prefix, which is well past the three-quarters mark.
    n00b_store_index_t *msg_index = index_ok(
        n00b_store_index_new(r"message", N00B_STORE_INDEX_NGRAM));
    auto shard_r = n00b_store_shard_new(.shard_id = UINT64_C(0x600f));
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);

    n00b_string_t *messages[] = {
        r"connection reset alpha", r"connection reset bravo",
        r"connection reset delta", r"connection reset echo",
        r"connection reset gamma", r"connection reset hotel",
        r"connection reset india", r"connection reset juliet",
        r"connection reset kilo",  r"disk full",
    };
    for (uint64_t i = 0; i < 10; i++) {
        auto append_r = n00b_store_shard_append(
            shard, record_with_fields(r"info", messages[i]));
        CHECK(n00b_result_is_ok(append_r));
        CHECK(n00b_result_is_ok(n00b_store_index_add(msg_index, shard, i)));
    }
    n00b_plan_index_list_t *indexes = index_list_with(msg_index);
    counted_sample_t sample = {.shard = shard, .indexes = indexes};

    // A prefix almost every record shares. The n-gram scan narrows nothing
    // worth carrying, so execution drops it and reads the shard instead.
    n00b_plan_predicate_t *broad = msg_prefix(r"connection");
    n00b_plan_node_t      *broad_plan = plan_ok(
        n00b_plan_build(broad, indexes));
    check_kind(broad_plan, N00B_PLAN_NODE_INTERSECT);
    CHECK(records_scanned_by(msg_prefix(r"connection"), sample) == 10);

    // A selective one keeps its candidates, so the paired record scan sees
    // far less than the shard. Same plan shape, different amount of work.
    n00b_plan_node_t *narrow_plan = plan_ok(
        n00b_plan_build(msg_prefix(r"disk"), indexes));
    check_kind(narrow_plan, N00B_PLAN_NODE_INTERSECT);
    uint64_t narrow = records_scanned_by(msg_prefix(r"disk"), sample);
    CHECK(narrow > 0);
    CHECK(narrow < 10);
}

static void
test_same_kind_groups_flatten(void)
{
    counted_sample_t sample = counted_sample();

    // AND(a, AND(b, c)) is one group of three, not a group holding a group,
    // so every index scan resolves before any record scan runs.
    n00b_plan_predicate_t *inner = two_of(msg_prefix(r"timeout"),
                                          level_eq(r"error"),
                                          true);
    n00b_plan_node_t *nested = plan_ok(
        n00b_plan_build(two_of(level_eq(r"info"), inner, true),
                        sample.indexes));
    check_kind(nested, N00B_PLAN_NODE_INTERSECT);
    for (uint64_t i = 0; i < 3; i++) {
        auto kind_r = n00b_plan_node_kind(child_at_ok(nested, i));
        CHECK(n00b_result_is_ok(kind_r));
        CHECK(n00b_result_get(kind_r) != N00B_PLAN_NODE_INTERSECT);
    }

    // Unindexed siblings become a single record scan, so the group costs one
    // pass. With nothing indexed left, the group collapses to that scan.
    n00b_plan_predicate_t *has_level =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"level")));
    n00b_plan_predicate_t *has_msg =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"message")));
    check_kind(plan_ok(n00b_plan_build(two_of(has_level, has_msg, true),
                                       sample.indexes)),
               N00B_PLAN_NODE_RECORD_SCAN);
    check_kind(plan_ok(n00b_plan_build(two_of(
                                           predicate_ok(n00b_plan_predicate_exists(
                                               field_target(r"level"))),
                                           predicate_ok(n00b_plan_predicate_exists(
                                               field_target(r"message"))),
                                           false),
                                       sample.indexes)),
               N00B_PLAN_NODE_RECORD_SCAN);

    // One indexed sibling keeps the group, now two children: the index scan
    // and the single merged record scan.
    n00b_plan_node_t *mixed = plan_ok(
        n00b_plan_build(two_of(level_eq(r"error"),
                               two_of(predicate_ok(n00b_plan_predicate_exists(
                                          field_target(r"level"))),
                                      predicate_ok(n00b_plan_predicate_exists(
                                          field_target(r"message"))),
                                      true),
                               true),
                        sample.indexes));
    check_kind(mixed, N00B_PLAN_NODE_INTERSECT);
    check_child_count(mixed, 2);
}


static bool
refuse_immediately(void *ctx)
{
    (void)ctx;
    scan_polls++;
    return true;
}

static void
test_index_scans_are_cancellable(void)
{
    counted_sample_t sample = counted_sample();

    // An index-served query reads no records, so the record loop never runs.
    // Walking a posting list is still unbounded work, and has to answer a
    // cancel of its own.
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(level_eq(r"error"), sample.indexes));
    scan_polls = 0;
    CHECK_ERR(n00b_plan_exec_hot(plan,
                                 sample.shard,
                                 .cancel_cb = refuse_immediately),
              N00B_PLAN_ERR_CANCELED);
    CHECK(scan_polls > 0);

    // Declining leaves the answer intact, so the abort came from the callback.
    scan_polls = 0;
    n00b_plan_records_scanned_reset();
    auto ok_r = n00b_plan_exec_hot(plan, sample.shard, .cancel_cb = count_poll);
    CHECK(n00b_result_is_ok(ok_r));
    uint64_t errors[] = {1, 2};
    check_ordinals(n00b_result_get(ok_r), 6, errors, 2);
    CHECK(scan_polls > 0);
    CHECK(n00b_plan_records_scanned() == 0);
}


static void
test_negated_branches_inherit_sibling_restriction(void)
{
    counted_sample_t sample = counted_sample();

    n00b_plan_predicate_t *has_msg =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"message")));

    // A negated branch is still a branch: whatever the index already ruled out
    // is not worth reading. Each pair below costs the same with or without the
    // negation, because both see only what level = "error" selected.
    uint64_t plain = records_scanned_by(
        two_of(level_eq(r"error"), has_msg, true), sample);
    uint64_t negated = records_scanned_by(
        two_of(level_eq(r"error"),
               predicate_ok(n00b_plan_predicate_not(
                   predicate_ok(n00b_plan_predicate_exists(
                       field_target(r"message"))))),
               true),
        sample);
    CHECK(plain == 2);
    CHECK(negated == 2);

    uint64_t plain_prefix = records_scanned_by(
        two_of(level_eq(r"error"), msg_prefix(r"timeout"), true), sample);
    uint64_t negated_prefix = records_scanned_by(
        two_of(level_eq(r"error"),
               predicate_ok(n00b_plan_predicate_not(msg_prefix(r"timeout"))),
               true),
        sample);
    CHECK(plain_prefix == 2);
    CHECK(negated_prefix == 2);
}


static uint64_t
count_kind(n00b_plan_node_t *node, n00b_plan_node_kind_t want)
{
    uint64_t total = 0;
    auto     kind_r = n00b_plan_node_kind(node);
    CHECK(n00b_result_is_ok(kind_r));
    if (n00b_result_get(kind_r) == want) {
        total++;
    }
    auto count_r = n00b_plan_node_child_count(node);
    CHECK(n00b_result_is_ok(count_r));
    for (uint64_t i = 0; i < n00b_result_get(count_r); i++) {
        total += count_kind(child_at_ok(node, i), want);
    }
    return total;
}

static n00b_plan_target_t *
any_target(void)
{
    return target_ok(n00b_plan_target_any());
}

static n00b_plan_predicate_t *
has(n00b_string_t *field)
{
    return predicate_ok(n00b_plan_predicate_exists(field_target(field)));
}

static void
test_nested_predicates_simplify_recursively(void)
{
    counted_sample_t sample = counted_sample();

    // AND(a, AND(b, AND(c, d))) is one group, however deep the input nests,
    // and its unindexed leaves share a single pass.
    n00b_plan_predicate_t *deep = two_of(
        level_eq(r"error"),
        two_of(msg_prefix(r"timeout"),
               two_of(has(r"level"), has(r"message"), true),
               true),
        true);
    n00b_plan_node_t *deep_plan = plan_ok(n00b_plan_build(deep,
                                                          sample.indexes));
    check_kind(deep_plan, N00B_PLAN_NODE_INTERSECT);
    CHECK(count_kind(deep_plan, N00B_PLAN_NODE_INTERSECT) == 1);
    CHECK(count_kind(deep_plan, N00B_PLAN_NODE_RECORD_SCAN) == 1);
    // level = "error" selects two, and every record scan runs only on those.
    CHECK(records_scanned_by(deep, sample) == 2);

    // OR(OR(a,b), OR(c,d)) likewise collapses to one group.
    n00b_plan_predicate_t *wide = two_of(
        two_of(level_eq(r"error"), level_eq(r"info"), false),
        two_of(level_eq(r"warn"), level_eq(r"nosuch"), false),
        false);
    n00b_plan_node_t *wide_plan = plan_ok(n00b_plan_build(wide,
                                                          sample.indexes));
    check_kind(wide_plan, N00B_PLAN_NODE_UNION);
    CHECK(count_kind(wide_plan, N00B_PLAN_NODE_UNION) == 1);
    check_child_count(wide_plan, 4);
    CHECK(records_scanned_by(wide, sample) == 0);

    // A union whose branches all narrow shares one candidate set and one pass,
    // rather than reading the overlap once per branch.
    n00b_plan_predicate_t *lossy_or = two_of(msg_prefix(r"timeout"),
                                             msg_prefix(r"time"),
                                             false);
    CHECK(count_kind(plan_ok(n00b_plan_build(lossy_or, sample.indexes)),
                     N00B_PLAN_NODE_RECORD_SCAN)
          == 1);
    CHECK(records_scanned_by(lossy_or, sample) == 3);

    // Adding an unrestricted branch makes the union shard-wide, so the lossy
    // branch stops paying for candidates it cannot use: still one pass.
    n00b_plan_predicate_t *mixed_or = two_of(msg_prefix(r"timeout"),
                                             has(r"level"),
                                             false);
    n00b_plan_node_t *mixed_plan = plan_ok(
        n00b_plan_build(mixed_or, sample.indexes));
    check_kind(mixed_plan, N00B_PLAN_NODE_RECORD_SCAN);
    CHECK(records_scanned_by(mixed_or, sample) == 6);

    // Negation nested inside a conjunction still inherits the restriction, and
    // a doubly negated exact leaf needs no record scan at all.
    n00b_plan_predicate_t *double_not = predicate_ok(
        n00b_plan_predicate_not(
            predicate_ok(n00b_plan_predicate_not(level_eq(r"error")))));
    CHECK(records_scanned_by(double_not, sample) == 0);
    CHECK(records_scanned_by(two_of(level_eq(r"error"),
                                    predicate_ok(n00b_plan_predicate_not(
                                        two_of(has(r"level"),
                                               msg_prefix(r"timeout"),
                                               false))),
                                    true),
                             sample)
          == 2);
}


static void
test_one_record_pass_per_query(void)
{
    counted_sample_t sample = counted_sample();

    // Six records, so a single pass over the shard costs six. Every shape
    // below reads the shard at most once, however many unindexed pieces it
    // is made of.
    CHECK(records_scanned_by(two_of(has(r"level"), has(r"message"), true),
                             sample)
          == 6);
    CHECK(records_scanned_by(two_of(has(r"level"), has(r"message"), false),
                             sample)
          == 6);

    // Two negations used to cost a pass each, because a complement is not a
    // record scan and so could not merge with one.
    CHECK(records_scanned_by(
              two_of(predicate_ok(n00b_plan_predicate_not(has(r"level"))),
                     predicate_ok(n00b_plan_predicate_not(has(r"message"))),
                     true),
              sample)
          == 6);

    // A negation beside a plain scan is still one pass.
    CHECK(records_scanned_by(
              two_of(has(r"level"),
                     predicate_ok(n00b_plan_predicate_not(has(r"message"))),
                     true),
              sample)
          == 6);

    // And nesting does not multiply passes either.
    CHECK(records_scanned_by(
              two_of(has(r"level"),
                     two_of(has(r"message"),
                            predicate_ok(n00b_plan_predicate_not(
                                has(r"level"))),
                            true),
                     true),
              sample)
          == 6);
}

static void
test_index_only_branches_never_meet_a_record(void)
{
    counted_sample_t sample = counted_sample();

    // An index-served branch beside an unindexed one keeps its own answer.
    // Folding it into the shared residual would be wrong as well as slower:
    // an any-field predicate evaluates false against a record, so a catch-all
    // branch swept into a residual would silently lose its hits.
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(two_of(level_eq(r"error"), has(r"message"), false),
                        sample.indexes));

    // Whatever the record scan tests, it is not the indexed branch.
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    CHECK(n00b_option_is_set(n00b_result_get(sole_r)));
    CHECK(n00b_option_get(n00b_result_get(sole_r)) != level_eq(r"error"));

    // Every record has a message, so the union is the whole shard, and it
    // costs exactly one pass rather than one per branch.
    n00b_plan_records_scanned_reset();
    auto r = n00b_plan_exec_hot(plan, sample.shard);
    CHECK(n00b_result_is_ok(r));
    uint64_t all[] = {0, 1, 2, 3, 4, 5};
    check_ordinals(n00b_result_get(r), 6, all, 6);
    CHECK(n00b_plan_records_scanned() == 6);

    // An index-served query on its own still touches nothing.
    CHECK(records_scanned_by(level_eq(r"error"), sample) == 0);
    CHECK(records_scanned_by(
              predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
              sample)
          == 0);
}


static void
test_any_field_predicates_never_become_a_record_scan(void)
{
    counted_sample_t sample = counted_sample();

    // An any-field predicate is meaningless against a single record: the leaf
    // evaluator rejects it, so a negation around one would match everything.
    // It has to stay on the set-based path even when its sibling does not.
    n00b_plan_predicate_t *any =
        predicate_ok(n00b_plan_predicate_contains(any_target(), r"timeout"));
    n00b_plan_predicate_t *negated = predicate_ok(
        n00b_plan_predicate_not(two_of(any, has(r"level"), false)));

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(negated,
                                                     sample.indexes));
    check_kind(plan, N00B_PLAN_NODE_COMPLEMENT);

    // Whatever record scan survives inside tests the ordinary sibling, never
    // the any-field branch.
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    if (n00b_option_is_set(n00b_result_get(sole_r))) {
        CHECK(n00b_option_get(n00b_result_get(sole_r)) != negated);
        CHECK(n00b_option_get(n00b_result_get(sole_r)) != any);
    }
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
    test_plan_node_structure();
    test_boolean_execution_results();
    test_execution_short_circuits();
    test_indexed_queries_read_no_records();
    test_record_scan_cost();
    test_nested_group_inherits_sibling_restriction();
    test_index_served_shapes_read_nothing();
    test_broad_lossy_scan_degrades_to_the_shard();
    test_same_kind_groups_flatten();
    test_index_scans_are_cancellable();
    test_negated_branches_inherit_sibling_restriction();
    test_nested_predicates_simplify_recursively();
    test_one_record_pass_per_query();
    test_index_only_branches_never_meet_a_record();
    test_any_field_predicates_never_become_a_record_scan();

    n00b_shutdown();
    return 0;
}

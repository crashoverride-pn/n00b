/* test/unit/test_rocs_plan_dispatch.c - WP-006 Phase 3 index dispatch. */

#include <stdint.h>

#include "n00b.h"
#include "core/pool.h"
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
#include "rocs_test_support.h"

// This test asserts on n00b_plan_records_scanned(), which is declared inside
// #ifdef N00B_DEBUG in include/internal/rocs/eval.h -- counting records costs
// a write on the scan path, so it is not in a release build.
//
// Every check here is a bound on records scanned; stubbing the counter out
// would leave those assertions passing vacuously, which is worse than not
// building. So the requirement is stated instead.
//
// meson defines N00B_DEBUG whenever build_tests is on (meson.build:131), so
// this only fires if the target is built in a build dir configured without
// -Dbuild_tests=true -- where the target still exists, because
// build_by_default: n00b_build_tests makes it non-default rather than absent.
#ifndef N00B_DEBUG
#error "test_rocs_plan_dispatch requires N00B_DEBUG; configure the build dir with -Dbuild_tests=true"
#endif

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_check_err_result));                       \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));        \
    } while (0)

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

// As exec_mapped_ok, but supplying the seal-time schema watermark the sealed
// fan-out normally reads off the store.
static n00b_plan_ordset_t *
exec_mapped_watermark_ok(n00b_plan_node_t       *plan,
                         n00b_store_map_shard_t *root,
                         uint64_t                watermark)
{
    auto r = n00b_plan_exec_mapped(plan,
                                  root,
                                  .schema_declared_since_ns = watermark);
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
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0x600d),
                                        .allocator = test_shard_allocator());
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

// A synthetic watermark for the gate tests. Deliberately NOT the shipped
// constant: these cases test the mechanism, and one separate case tests the
// shipped value against its derivation. Well above the small seal_ts values the
// other fixtures use so they keep scanning as they always have.
#define WATERMARK_TEST_NS (UINT64_C(1000000000000))

// The same records as indexed_level_shard, with nothing indexed. Sealing this
// gives a shard whose records DO populate `level` and which carries no column
// for it -- a legacy shard in the n00b#202 sense, as opposed to Case A's
// declared-and-genuinely-empty one. The two are indistinguishable from the
// column table alone, which is the whole difficulty.
static n00b_store_shard_t *
plain_level_shard(void)
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

    CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, info)));
    CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, error_a)));
    CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, error_b)));
    CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, missing)));

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

    n00b_plan_node_t *plan = test_plan_hot(eq, indexes, shard);

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

    n00b_plan_node_t *plan = test_plan_hot(level_eq(r"error"),
                                           index_list_with(index),
                                           shard);

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
    n00b_plan_node_t *and_plan = test_plan_hot(
            predicate_ok(n00b_plan_predicate_and(children)),

                                               index_list_with(index),
                                               shard);
    check_ordinals(exec_mapped_ok(and_plan, n00b_result_get(root_r)),
                   4, expected, 2);

    n00b_plan_node_t *not_plan
        = test_plan_hot(
                predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),

                        index_list_with(index),
                        shard);
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
    n00b_plan_node_t      *mismatch
        = test_plan_hot(eq, index_list_with(term_index(r"message")), shard);
    // Nothing accelerates this, so the plan is a bare record scan and
    // execution answers with the records that match.
    uint64_t errors[] = {1, 2};
    check_ordinals(exec_hot_ok(mismatch, shard), 4, errors, 2);
    check_record_scan(mismatch, eq);
    check_used_index(mismatch, false);

    n00b_store_index_t *fulltext
        = index_ok(n00b_store_index_new(r"level", N00B_STORE_INDEX_FULLTEXT));
    n00b_plan_predicate_t *eq2     = level_eq(r"error");
    n00b_plan_node_t      *unready = test_plan_hot(eq2,
                                                   index_list_with(fulltext),
                                                   shard);
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

    n00b_plan_node_t *miss = test_plan_hot(level_eq(r"warn"), indexes, shard);
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
    n00b_plan_node_t *failed = test_plan_hot(bad_value, indexes, shard);
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
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children,
                                                            prefix)));
    n00b_plan_predicate_t *and = predicate_ok(
            n00b_plan_predicate_and(and_children));
    n00b_plan_node_t *and_plan = test_plan_hot(and, indexes, shard);
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
    n00b_plan_node_t *or_plan  = test_plan_hot(or, indexes, shard);
    check_record_scan(or_plan, prefix);
    check_used_index(or_plan, true);

    n00b_plan_predicate_t *not_exact
        = predicate_ok(n00b_plan_predicate_not(level_eq(r"error")));
    n00b_plan_node_t *not_exact_plan = test_plan_hot(not_exact, indexes, shard);
    uint64_t          not_errors[]   = {0, 3};
    check_ordinals(exec_hot_ok(not_exact_plan, shard), 4, not_errors, 2);
    check_record_scan(not_exact_plan, nullptr);
    check_used_index(not_exact_plan, true);

    n00b_plan_predicate_t *not_prefix =
        predicate_ok(n00b_plan_predicate_not(prefix));
    // Negating something indefinite cannot be a set complement, so the
    // negation itself becomes what the record scan tests.
    n00b_plan_node_t      *not_prefix_plan = test_plan_hot(not_prefix,
                                                           indexes,
                                                           shard);
    check_record_scan(not_prefix_plan, not_prefix);
    check_used_index(not_prefix_plan, false);
}

static void
test_invalid_plan_inputs(void)
{
    n00b_store_index_t     *index = term_index(r"level");
    n00b_store_shard_t     *shard = indexed_level_shard(index);
    n00b_plan_index_list_t *ix    = index_list_with(index);
    CHECK_ERR(
        n00b_plan_build(nullptr, ix),
        N00B_PLAN_ERR_ARG);
    // The shard belongs to execution now, so a missing one is caught there.
    n00b_plan_node_t *plan = test_plan_hot(level_eq(r"error"),
                                           index_list_with(index),
                                           shard);
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

    check_kind(test_plan_shape(level_eq(r"error"), indexes),
               N00B_PLAN_NODE_INDEX_SCAN);
    check_kind(test_plan_shape(prefix, indexes), N00B_PLAN_NODE_RECORD_SCAN);

    n00b_plan_predicate_list_t *and_children = n00b_plan_predicate_list_new();
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(and_children,
                                                          level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children,
                                                            prefix)));
    n00b_plan_node_t *and_plan
        = test_plan_shape(predicate_ok(n00b_plan_predicate_and(and_children)),
                          indexes);
    check_kind(and_plan, N00B_PLAN_NODE_INTERSECT);
    check_child_count(and_plan, 2);
    check_kind(child_at_ok(and_plan, 0), N00B_PLAN_NODE_INDEX_SCAN);
    check_kind(child_at_ok(and_plan, 1), N00B_PLAN_NODE_RECORD_SCAN);

    n00b_plan_predicate_list_t *or_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            or_children,
            level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(or_children,
                                                            prefix)));
    n00b_plan_node_t *or_plan
        = test_plan_shape(predicate_ok(n00b_plan_predicate_or(or_children)),
                          indexes);
    check_kind(or_plan, N00B_PLAN_NODE_UNION);
    check_child_count(or_plan, 2);

    n00b_plan_node_t *not_plan = test_plan_shape(
            predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
            indexes);
    check_kind(not_plan, N00B_PLAN_NODE_COMPLEMENT);
    check_child_count(not_plan, 1);
    check_kind(child_at_ok(not_plan, 0), N00B_PLAN_NODE_INDEX_SCAN);

    check_kind(
            test_plan_shape(predicate_ok(n00b_plan_predicate_false()), indexes),

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
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            or_children,
            level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(or_children,
                                                            prefix)));
    n00b_plan_node_t *or_plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_or(or_children)),
                        indexes,
                        shard);
    uint64_t errors[] = {1, 2};
    check_ordinals(exec_hot_ok(or_plan, shard), 4, errors, 2);

    n00b_plan_predicate_list_t *and_children = n00b_plan_predicate_list_new();
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(and_children,
                                                          level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children,
                                                            prefix)));
    n00b_plan_node_t *and_plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_and(and_children)),
                        indexes,
                        shard);
    check_ordinals(exec_hot_ok(and_plan, shard), 4, errors, 2);

    n00b_plan_node_t *not_prefix_plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_not(prefix)),
                        indexes,
                        shard);
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
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            and_children,
            level_eq(r"warn"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children,
                                                            prefix)));
    n00b_plan_node_t *and_plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_and(and_children)),
                        indexes,
                        shard);
    WORK_RESET();
    auto and_r = n00b_plan_exec_hot(and_plan, shard);
    CHECK(n00b_result_is_ok(and_r));
    check_ordinals(n00b_result_get(and_r), 4, nullptr, 0);
    WORK_CHECK(WORK_READ() == 0);

    // A union that already holds every record cannot gain rows either.
    n00b_plan_predicate_list_t *or_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
        or_children,
        predicate_ok(n00b_plan_predicate_not(level_eq(r"warn"))))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(or_children,
                                                            prefix)));
    n00b_plan_node_t *or_plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_or(or_children)),
                        indexes,
                        shard);
    WORK_RESET();
    auto or_r = n00b_plan_exec_hot(or_plan, shard);
    CHECK(n00b_result_is_ok(or_r));
    uint64_t all[] = {0, 1, 2, 3};
    check_ordinals(n00b_result_get(or_r), 4, all, 4);
    WORK_CHECK(WORK_READ() == 0);

    // The same plan shape with a non-empty index branch does reach its record
    // scan, which is what makes the two zero counts above meaningful.
    n00b_plan_predicate_list_t *live = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(live, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(live, prefix)));
    n00b_plan_node_t *live_plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_and(live)),
                        indexes,
                        shard);
    WORK_RESET();
    auto live_r = n00b_plan_exec_hot(live_plan, shard);
    CHECK(n00b_result_is_ok(live_r));
    WORK_CHECK(WORK_READ() > 0);
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

    WORK_RESET();
    auto hit_r = n00b_plan_exec_hot(
            test_plan_hot(level_eq(r"error"), indexes, shard),
            shard);
    CHECK(n00b_result_is_ok(hit_r));
    uint64_t errors[] = {1, 2};
    check_ordinals(n00b_result_get(hit_r), 4, errors, 2);
    WORK_CHECK(WORK_READ() == 0);

    WORK_RESET();
    auto miss_r = n00b_plan_exec_hot(
            test_plan_hot(level_eq(r"warn"), indexes, shard),
            shard);
    CHECK(n00b_result_is_ok(miss_r));
    check_ordinals(n00b_result_get(miss_r), 4, nullptr, 0);
    WORK_CHECK(WORK_READ() == 0);

    // Complementing an exact set is still exact.
    WORK_RESET();
    auto not_r = n00b_plan_exec_hot(
        test_plan_hot(predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
                      indexes,
                      shard),
        shard);
    CHECK(n00b_result_is_ok(not_r));
    uint64_t others[] = {0, 3};
    check_ordinals(n00b_result_get(not_r), 4, others, 2);
    WORK_CHECK(WORK_READ() == 0);

    // Control: with no index for the field the same probe does fire, so the
    // zero counts above mean the index answered rather than the probe failing.
    n00b_plan_predicate_t *prefix
        = predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                  r"timeout"));
    WORK_RESET();
    auto scan_r = n00b_plan_exec_hot(test_plan_hot(prefix, indexes, shard),
                                     shard);
    CHECK(n00b_result_is_ok(scan_r));
    WORK_CHECK(WORK_READ() > 0);
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

    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0x600e),
                                        .allocator = test_shard_allocator());
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
    n00b_plan_node_t *plan = test_plan_hot(predicate,
                                           sample.indexes,
                                           sample.shard);
    WORK_RESET();
    auto r = n00b_plan_exec_hot(plan, sample.shard);
    CHECK(n00b_result_is_ok(r));
    return WORK_READ();
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
    WORK_CHECK(records_scanned_by(level_eq(r"error"), sample) == 0);

    // A lossy prefix reads its own candidates, not the shard.
    WORK_CHECK(records_scanned_by(msg_prefix(r"timeout"), sample) == 3);

    // The selective sibling has to be applied first, or this costs 3.
    WORK_CHECK(
        records_scanned_by(
                two_of(msg_prefix(r"timeout"), level_eq(r"error"), true),
                sample)
        == 2);

    // Two unindexed branches are one pass over the shard, not two.
    n00b_plan_predicate_t *has_level
        = predicate_ok(n00b_plan_predicate_exists(field_target(r"level")));
    n00b_plan_predicate_t *has_msg
        = predicate_ok(n00b_plan_predicate_exists(field_target(r"message")));
    WORK_CHECK(
            records_scanned_by(two_of(has_level, has_msg, false), sample) == 6);
    WORK_CHECK(records_scanned_by(
                   two_of(
                           predicate_ok(
                                   n00b_plan_predicate_exists(
                                           field_target(r"level"))),
                          predicate_ok(
                                  n00b_plan_predicate_exists(
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
    n00b_plan_predicate_t *branchy
        = two_of(level_eq(r"warn"),
                 predicate_ok(
                         n00b_plan_predicate_exists(field_target(r"message"))),
                 false);
    WORK_CHECK(records_scanned_by(two_of(branchy, level_eq(r"error"), true),
                                  sample) == 2);
}


static void
test_index_served_shapes_read_nothing(void)
{
    counted_sample_t sample = counted_sample();

    // Whole-token contains is answerable from the full-text index.
    WORK_CHECK(
        records_scanned_by(
            predicate_ok(n00b_plan_predicate_contains(field_target(r"message"),
                                                      r"timeout")),
            sample)
        == 0);

    // Complementing an exact set stays exact.
    WORK_CHECK(
        records_scanned_by(
                predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
                sample)
        == 0);

    // An intersect whose index branch is empty stops before the record scan.
    WORK_CHECK(
        records_scanned_by(
                two_of(level_eq(r"nosuch"), msg_prefix(r"timeout"), true),
                sample)
        == 0);

    // A union that already covers the shard stops before its other branch.
    WORK_CHECK(
        records_scanned_by(two_of(
                predicate_ok(n00b_plan_predicate_not(level_eq(r"nosuch"))),

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
    n00b_store_index_t *msg_index
        = index_ok(n00b_store_index_new(r"message", N00B_STORE_INDEX_NGRAM));
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0x600f),
                                        .allocator = test_shard_allocator());
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
    n00b_plan_predicate_t *broad      = msg_prefix(r"connection");
    n00b_plan_node_t      *broad_plan = test_plan_hot(broad, indexes, shard);
    check_kind(broad_plan, N00B_PLAN_NODE_INTERSECT);
    WORK_CHECK(records_scanned_by(msg_prefix(r"connection"), sample) == 10);

    // A selective one keeps its candidates, so the paired record scan sees
    // far less than the shard. Same plan shape, different amount of work.
    n00b_plan_node_t *narrow_plan = test_plan_hot(msg_prefix(r"disk"),
                                                  indexes,
                                                  shard);
    check_kind(narrow_plan, N00B_PLAN_NODE_INTERSECT);
    uint64_t narrow = records_scanned_by(msg_prefix(r"disk"), sample);
    WORK_CHECK(narrow > 0);
    WORK_CHECK(narrow < 10);
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
    n00b_plan_node_t      *nested
        = test_plan_shape(two_of(level_eq(r"info"), inner, true),
                          sample.indexes);
    check_kind(nested, N00B_PLAN_NODE_INTERSECT);
    for (uint64_t i = 0; i < 3; i++) {
        auto kind_r = n00b_plan_node_kind(child_at_ok(nested, i));
        CHECK(n00b_result_is_ok(kind_r));
        CHECK(n00b_result_get(kind_r) != N00B_PLAN_NODE_INTERSECT);
    }

    // Unindexed siblings become a single record scan, so the group costs one
    // pass. With nothing indexed left, the group collapses to that scan.
    n00b_plan_predicate_t *has_level
        = predicate_ok(n00b_plan_predicate_exists(field_target(r"level")));
    n00b_plan_predicate_t *has_msg
        = predicate_ok(n00b_plan_predicate_exists(field_target(r"message")));
    check_kind(
            test_plan_shape(two_of(has_level, has_msg, true), sample.indexes),

               N00B_PLAN_NODE_RECORD_SCAN);
    check_kind(test_plan_shape(
                   two_of(
                           predicate_ok(
                                   n00b_plan_predicate_exists(
                                           field_target(r"level"))),
                          predicate_ok(
                                  n00b_plan_predicate_exists(
                                          field_target(r"message"))),
                          false),
                   sample.indexes),
               N00B_PLAN_NODE_RECORD_SCAN);

    // One indexed sibling keeps the group, now two children: the index scan
    // and the single merged record scan.
    n00b_plan_node_t *mixed = test_plan_shape(
        two_of(level_eq(r"error"),
               two_of(
                       predicate_ok(
                               n00b_plan_predicate_exists(
                                       field_target(r"level"))),
                      predicate_ok(
                              n00b_plan_predicate_exists(
                                      field_target(r"message"))),
                      true),
               true),
        sample.indexes);
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
    n00b_plan_node_t *plan = test_plan_hot(level_eq(r"error"),
                                           sample.indexes,
                                           sample.shard);
    scan_polls             = 0;
    CHECK_ERR(n00b_plan_exec_hot(plan,
                                 sample.shard,
                                 .cancel_cb = refuse_immediately),
              N00B_PLAN_ERR_CANCELED);
    CHECK(scan_polls > 0);

    // Declining leaves the answer intact, so the abort came from the callback.
    scan_polls = 0;
    WORK_RESET();
    auto ok_r = n00b_plan_exec_hot(plan, sample.shard, .cancel_cb = count_poll);
    CHECK(n00b_result_is_ok(ok_r));
    uint64_t errors[] = {1, 2};
    check_ordinals(n00b_result_get(ok_r), 6, errors, 2);
    CHECK(scan_polls > 0);
    WORK_CHECK(WORK_READ() == 0);
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
    WORK_CHECK(plain == 2);
    WORK_CHECK(negated == 2);

    uint64_t plain_prefix = records_scanned_by(
        two_of(level_eq(r"error"), msg_prefix(r"timeout"), true), sample);
    uint64_t negated_prefix = records_scanned_by(
        two_of(level_eq(r"error"),
               predicate_ok(n00b_plan_predicate_not(msg_prefix(r"timeout"))),
               true),
        sample);
    WORK_CHECK(plain_prefix == 2);
    WORK_CHECK(negated_prefix == 2);
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
    n00b_plan_node_t *deep_plan = test_plan_shape(deep, sample.indexes);
    check_kind(deep_plan, N00B_PLAN_NODE_INTERSECT);
    CHECK(count_kind(deep_plan, N00B_PLAN_NODE_INTERSECT) == 1);
    CHECK(count_kind(deep_plan, N00B_PLAN_NODE_RECORD_SCAN) == 1);
    // level = "error" selects two, and every record scan runs only on those.
    WORK_CHECK(records_scanned_by(deep, sample) == 2);

    // OR(OR(a,b), OR(c,d)) likewise collapses to one group.
    n00b_plan_predicate_t *wide
        = two_of(two_of(level_eq(r"error"), level_eq(r"info"), false),
                 two_of(level_eq(r"warn"), level_eq(r"nosuch"), false),
                 false);
    n00b_plan_node_t *wide_plan = test_plan_shape(wide, sample.indexes);
    check_kind(wide_plan, N00B_PLAN_NODE_UNION);
    CHECK(count_kind(wide_plan, N00B_PLAN_NODE_UNION) == 1);
    check_child_count(wide_plan, 4);
    WORK_CHECK(records_scanned_by(wide, sample) == 0);

    // A union whose branches all narrow shares one candidate set and one pass,
    // rather than reading the overlap once per branch.
    n00b_plan_predicate_t *lossy_or
        = two_of(msg_prefix(r"timeout"), msg_prefix(r"time"), false);
    CHECK(count_kind(test_plan_shape(lossy_or, sample.indexes),
                     N00B_PLAN_NODE_RECORD_SCAN)
          == 1);
    WORK_CHECK(records_scanned_by(lossy_or, sample) == 3);

    // Adding an unrestricted branch makes the union shard-wide, so the lossy
    // branch stops paying for candidates it cannot use: still one pass.
    n00b_plan_predicate_t *mixed_or   = two_of(msg_prefix(r"timeout"),
                                               has(r"level"),
                                               false);
    n00b_plan_node_t      *mixed_plan = test_plan_shape(mixed_or,
                                                        sample.indexes);
    check_kind(mixed_plan, N00B_PLAN_NODE_RECORD_SCAN);
    WORK_CHECK(records_scanned_by(mixed_or, sample) == 6);

    // Negation nested inside a conjunction still inherits the restriction, and
    // a doubly negated exact leaf needs no record scan at all.
    n00b_plan_predicate_t *double_not = predicate_ok(
        n00b_plan_predicate_not(
                predicate_ok(n00b_plan_predicate_not(level_eq(r"error")))));
    WORK_CHECK(records_scanned_by(double_not, sample) == 0);
    WORK_CHECK(
        records_scanned_by(two_of(level_eq(r"error"),
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
    WORK_CHECK(records_scanned_by(two_of(has(r"level"), has(r"message"), true),
                                  sample) == 6);
    WORK_CHECK(records_scanned_by(two_of(has(r"level"), has(r"message"), false),
                                  sample)
               == 6);

    // Two negations used to cost a pass each, because a complement is not a
    // record scan and so could not merge with one.
    WORK_CHECK(
        records_scanned_by(two_of(
                predicate_ok(n00b_plan_predicate_not(has(r"level"))),

                                  predicate_ok(
                                          n00b_plan_predicate_not(
                                                  has(r"message"))),
                                  true),
                           sample)
        == 6);

    // A negation beside a plain scan is still one pass.
    WORK_CHECK(
        records_scanned_by(two_of(has(r"level"),
                                  predicate_ok(
                                          n00b_plan_predicate_not(
                                                  has(r"message"))),
                                  true),
                           sample)
        == 6);

    // And nesting does not multiply passes either.
    WORK_CHECK(
        records_scanned_by(two_of(has(r"level"),
                                  two_of(has(r"message"),
                                         predicate_ok(
                                                 n00b_plan_predicate_not(
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
    n00b_plan_node_t *plan = test_plan_hot(
            two_of(level_eq(r"error"), has(r"message"), false),

                          sample.indexes,
                          sample.shard);

    // Whatever the record scan tests, it is not the indexed branch.
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    CHECK(n00b_option_is_set(n00b_result_get(sole_r)));
    CHECK(n00b_option_get(n00b_result_get(sole_r)) != level_eq(r"error"));

    // Every record has a message, so the union is the whole shard, and it
    // costs exactly one pass rather than one per branch.
    WORK_RESET();
    auto r = n00b_plan_exec_hot(plan, sample.shard);
    CHECK(n00b_result_is_ok(r));
    uint64_t all[] = {0, 1, 2, 3, 4, 5};
    check_ordinals(n00b_result_get(r), 6, all, 6);
    WORK_CHECK(WORK_READ() == 6);

    // An index-served query on its own still touches nothing.
    WORK_CHECK(records_scanned_by(level_eq(r"error"), sample) == 0);
    WORK_CHECK(
        records_scanned_by(
                predicate_ok(n00b_plan_predicate_not(level_eq(r"error"))),
                sample)
        == 0);
}

// ---------------------------------------------------------------------------
// wax#686 / n00b#202 — the sparse-field EQ pair.
//
// These two cases look identical to a sealed shard and MUST NOT be collapsed.
// #223 (df904c03, "scan sealed shards missing indexes") collapsed them in the
// safe direction: everything scans. That fixed #202's wrong answers and is what
// makes wax#686 unbearable — a shard with no column for the field is read and
// JSON-parsed record by record.
//
//   A. shard sealed WITH the field declared, no record populated it
//      -> genuinely empty. Scanning it is correct but wasteful. This is #686.
//
//   B. shard sealed BEFORE the field was declared (legacy)
//      -> records may populate it and no index exists. Scanning is the ONLY
//         correct answer. This is #202, and asserting 0 here re-breaks it.
//
// A test that asserts records_scanned == 0 for "declared but no column in this
// shard" without distinguishing B is a #202 regression wearing a #686 fix.
// Distinguishing them needs a shard-format change (an empty index descriptor
// written at seal time for every declared field), which is what #202's body
// proposed. Case B is the guard rail for that work.
// ---------------------------------------------------------------------------

// The #686/#202 dual. Cases A and B query the SAME field with the SAME plan
// index list, so the only thing that differs is what the sealed image carries:
// an empty column (the field was declared when this shard sealed) or no column
// at all (it sealed before the declaration). If a change makes Case A pass by
// keying off "declared but no column" rather than off the empty column itself,
// Case B fails -- which is precisely the #202 regression that #223 fixed.
static void
test_mapped_sparse_eq_declared_but_absent_column(void)
{
    // Case A. `session` is declared term-indexed at seal time and no record in
    // this shard populates it, so seal writes an EMPTY column for it.
    n00b_store_index_t *declared = term_index(r"session");
    n00b_store_shard_t *shard    = indexed_level_shard(term_index(r"level"));

    // What rocs_store_declare_indexed_columns does for every declared-indexed
    // field on the real seal path.
    auto declare_r = n00b_store_index_declare(declared, shard);
    CHECK(n00b_result_is_ok(declare_r));
    CHECK(n00b_result_get(declare_r));

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 86,
                                        .base_address = 0x8600u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_eq(
                            field_target(r"session"),
                            json_value(
                                    n00b_json_string_new_from_n00b(
                                            r"64302c47")))),
                        index_list_with(declared),
                        shard);

    WORK_RESET();
    n00b_plan_ordset_t *set = exec_mapped_ok(plan, n00b_result_get(root_r));

    // Right answer...
    check_ordinals(set, 4, NULL, 0);
    // ...and now for free: the empty column is present, so the mapped lookup
    // resolves to an exact empty set instead of recovering into a full scan.
    WORK_CHECK(WORK_READ() == 0);
}

static void
test_mapped_sparse_eq_legacy_shard_must_scan(void)
{
    // Case B. Same field and same index list as Case A -- but this shard sealed
    // BEFORE the declaration existed, so nothing wrote a column for it. Records
    // here may populate `session`; no index was ever built over them, so
    // scanning is the only sound answer.
    n00b_store_index_t *declared = term_index(r"session");
    n00b_store_shard_t *shard    = indexed_level_shard(term_index(r"level"));

    // Deliberately NO n00b_store_index_declare: that is what "legacy" means.

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 87,
                                        .base_address = 0x8700u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_eq(
                            field_target(r"session"),
                            json_value(
                                    n00b_json_string_new_from_n00b(
                                            r"64302c47")))),
                        index_list_with(declared),
                        shard);

    WORK_RESET();
    (void)exec_mapped_ok(plan, n00b_result_get(root_r));

    // Scanning is CORRECT here. This is the #202 regression guard, and it must
    // keep passing after #686 is fixed.
    WORK_CHECK(WORK_READ() > 0);
}

// ---------------------------------------------------------------------------
// The seal_ts schema watermark (n00b#202 / #223 / wax#686).
//
// Cases A and B above are indistinguishable from the column table alone, and
// #223 resolved that by scanning both -- correct, and measured at 1.2s -> >240s
// on a 0.8.44-sealed store. The watermark resolves them using the one piece of
// vintage the image carries: seal_ts. Both directions are tested, and the
// pre-watermark direction is the one that keeps this honest: it is the #202
// guard, and it must fail if someone later "simplifies" the gate away.
// ---------------------------------------------------------------------------

// A shard sealed AT OR ABOVE the watermark declared the field, so a missing
// column means no record populated it. Answer exact-empty, read nothing. This
// is what 0.8.44 did and what #223 gave up globally.
static void
test_post_watermark_declared_absent_answers_empty(void)
{
    n00b_store_index_t *declared = term_index(r"session");
    n00b_store_shard_t *shard    = indexed_level_shard(term_index(r"level"));

    // No n00b_store_index_declare: this shard carries no column for `session`,
    // exactly like a legacy shard. The ONLY thing distinguishing it from the
    // case below is its seal_ts.
    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = WATERMARK_TEST_NS + 1,
                                        .base_address = 0x9100u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_eq(
                            field_target(r"session"),
                            json_value(
                                    n00b_json_string_new_from_n00b(
                                            r"64302c47")))),
                        index_list_with(declared),
                        shard);

    WORK_RESET();
    check_ordinals(exec_mapped_watermark_ok(plan,
                                            n00b_result_get(root_r),
                                            WATERMARK_TEST_NS),
                   4,
                   NULL,
                   0);
    WORK_CHECK(WORK_READ() == 0);
}

// THE #202 GUARD. Same field, same plan, same absent column -- only the seal_ts
// differs. Below the watermark this shard may predate the declaration, so its
// records may populate the field with no index over them, and scanning is the
// only sound answer. If this goes green with zero scans, #202 is back.
static void
test_pre_watermark_declared_absent_still_scans(void)
{
    n00b_store_index_t *declared = term_index(r"level");
    // `level` IS populated by every record here and the shard carries no column
    // for it -- the #202 shape: rows that must still be found by scanning.
    n00b_store_shard_t *shard = plain_level_shard();

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = WATERMARK_TEST_NS - 1,
                                        .base_address = 0x9200u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan
        = test_plan_hot(level_eq(r"error"), index_list_with(declared), shard);

    // Scans, AND finds the rows. Asserting only "scanned > 0" would pass for a
    // gate that scanned and then threw the answer away.
    WORK_RESET();
    uint64_t errors[] = {1, 2};
    check_ordinals(exec_mapped_watermark_ok(plan,
                                            n00b_result_get(root_r),
                                            WATERMARK_TEST_NS),
                   4,
                   errors,
                   2);
    WORK_CHECK(WORK_READ() > 0);
}

// The absent-column hazard, reaching the planner instead of the executor.
//
// A shard sealed before `level` was declared indexed has records populating the
// field and no column over them. Asked for a count, both df readers answer
// zero, because a term absent from a column and a column that does not exist
// are the same number. Execution separates them before acting; the collector
// must too, or a conjunction settles to EMPTY at plan time and the rows that
// are there are never looked for.
//
// The single-leaf case cannot catch this: empty propagation only fires on an
// intersection, so a solo scan answers correctly no matter what the count said.
static void
test_absent_column_does_not_settle_a_conjunction(void)
{
    n00b_store_index_t *declared = term_index(r"level");
    n00b_store_shard_t *shard    = plain_level_shard();

    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(kids, level_eq(r"error"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
        kids,
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                r"timeout")))));
    n00b_plan_predicate_t *conj = predicate_ok(n00b_plan_predicate_and(kids));

    n00b_plan_index_list_t *indexes = index_list_with(declared);

    // The hot collector reaches the same conclusion about the same shard: no
    // column means no count. Only the shape is asserted here, because hot
    // execution has no recovery for a missing column the way the mapped side
    // does, and that is a separate question from what the planner believed.
    n00b_plan_node_t *hot_plan = test_plan_hot(conj, indexes, shard);
    auto              hot_kind = n00b_plan_node_kind(hot_plan);
    CHECK(n00b_result_is_ok(hot_kind));
    CHECK(n00b_result_get(hot_kind) != N00B_PLAN_NODE_EMPTY);

    uint64_t both[] = {1, 2};

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = WATERMARK_TEST_NS - 1,
                                        .base_address = 0x9400u);
    CHECK(n00b_result_is_ok(seal_r));
    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));
    n00b_store_map_shard_t *root = n00b_result_get(root_r);

    // And planned from the sealed image. Same conclusion: no column means no
    // count, not a zero count.
    n00b_plan_node_t *sealed_plan = test_plan_mapped(conj, indexes, root);
    auto              sealed_kind = n00b_plan_node_kind(sealed_plan);
    CHECK(n00b_result_is_ok(sealed_kind));
    CHECK(n00b_result_get(sealed_kind) != N00B_PLAN_NODE_EMPTY);

    check_ordinals(exec_mapped_watermark_ok(sealed_plan, root,
                                            WATERMARK_TEST_NS),
                   4,
                   both,
                   2);
}

// A zero watermark is the kill switch, and it must fail SAFE: every
// declared-absent shard scans regardless of how new it is. This is also what an
// exec caller that never passes the store's value gets, which is why the kwarg
// defaults to zero rather than to the build constant.
static void
test_zero_watermark_scans_even_a_new_shard(void)
{
    n00b_store_index_t *declared = term_index(r"level");
    n00b_store_shard_t *shard    = plain_level_shard();

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = WATERMARK_TEST_NS * 2,
                                        .base_address = 0x9300u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan
        = test_plan_hot(level_eq(r"error"), index_list_with(declared), shard);

    WORK_RESET();
    uint64_t errors[] = {1, 2};
    check_ordinals(exec_mapped_watermark_ok(plan, n00b_result_get(root_r), 0),
                   4,
                   errors,
                   2);
    WORK_CHECK(WORK_READ() > 0);
}

// The shipped constant must sit where its derivation says it does. If someone
// edits it without re-deriving, this is what notices: below the first wax pin
// carrying n00b#203 it would trust pre-declaration shards (#202 returns), and at
// or above the observed 0.8.44 build stamp it would stop helping the shards this
// change exists to fix.
static void
test_shipped_watermark_is_inside_its_derived_window(void)
{
    // wax c21ce091, first pin of a libn00b containing #203: 2026-08-14 17:55:24Z
    static const uint64_t first_declaring_build_ns
        = UINT64_C(1786730124000000000);
    // Observed 0.8.44 crayon-gw build stamp (n00b#264): 2026-08-27 02:07:56Z
    static const uint64_t observed_0844_build_ns
        = UINT64_C(1787796476000000000);

    CHECK(N00B_STORE_SCHEMA_DECLARED_SINCE_NS > first_declaring_build_ns);
    CHECK(N00B_STORE_SCHEMA_DECLARED_SINCE_NS < observed_0844_build_ns);
}

// Case C, for completeness: the field is not declared at all, so there is no
// index descriptor and the plan is a record scan from the start.
static void
test_mapped_undeclared_field_eq_scans(void)
{
    n00b_store_shard_t *shard = indexed_level_shard(term_index(r"level"));

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 88,
                                        .base_address = 0x8800u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_node_t *plan
        = test_plan_hot(predicate_ok(n00b_plan_predicate_eq(
                            field_target(r"session"),
                            json_value(
                                    n00b_json_string_new_from_n00b(
                                            r"64302c47")))),
                        n00b_plan_index_list_new(),
                        shard);

    WORK_RESET();
    (void)exec_mapped_ok(plan, n00b_result_get(root_r));

    WORK_CHECK(WORK_READ() > 0);
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

    n00b_plan_node_t *plan = test_plan_hot(negated,
                                           sample.indexes,
                                           sample.shard);
    check_kind(plan, N00B_PLAN_NODE_COMPLEMENT);

    // Whatever record scan survives inside tests the ordinary sibling, never
    // the any-field branch.
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    if (n00b_option_is_set(n00b_result_get(sole_r))) {
        WORK_CHECK(n00b_option_get(n00b_result_get(sole_r)) != negated);
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
    test_mapped_sparse_eq_declared_but_absent_column();
    test_mapped_sparse_eq_legacy_shard_must_scan();
    test_mapped_undeclared_field_eq_scans();
    test_post_watermark_declared_absent_answers_empty();
    test_pre_watermark_declared_absent_still_scans();
    test_absent_column_does_not_settle_a_conjunction();
    test_zero_watermark_scans_even_a_new_shard();
    test_shipped_watermark_is_inside_its_derived_window();
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

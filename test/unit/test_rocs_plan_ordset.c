/* test/unit/test_rocs_plan_ordset.c - WP-006 Phase 2 ordinal set algebra. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal planner declarations must not be included by rocs/n00b_rocs.h"
#endif

#include "internal/rocs/plan_ir.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_ERR(expr, expected)                                               \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                     \
        CHECK(n00b_result_is_err(_bl_check_err_result));                        \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));         \
    } while (0)

static n00b_plan_ordset_t *
ordset_ok(n00b_result_t(n00b_plan_ordset_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_ordset_t *set = n00b_result_get(r);
    CHECK(set != nullptr);
    return set;
}

static void
check_record_count(n00b_plan_ordset_t *set, uint64_t expected)
{
    auto record_count_r = n00b_plan_ordset_record_count(set);
    CHECK(n00b_result_is_ok(record_count_r));
    CHECK(n00b_result_get(record_count_r) == expected);
}

static void
check_count(n00b_plan_ordset_t *set, uint64_t expected)
{
    auto count_r = n00b_plan_ordset_count(set);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == expected);
}

static void
check_contains(n00b_plan_ordset_t *set, uint64_t ordinal, bool expected)
{
    auto contains_r = n00b_plan_ordset_contains(set, ordinal);
    CHECK(n00b_result_is_ok(contains_r));
    CHECK(n00b_result_get(contains_r) == expected);
}

static void
check_at_some(n00b_plan_ordset_t *set, uint64_t index, uint64_t expected)
{
    auto at_r = n00b_plan_ordset_at(set, index);
    CHECK(n00b_result_is_ok(at_r));
    n00b_option_t(uint64_t) opt = n00b_result_get(at_r);
    CHECK(n00b_option_is_set(opt));
    CHECK(n00b_option_get(opt) == expected);
}

static void
check_at_none(n00b_plan_ordset_t *set, uint64_t index)
{
    auto at_r = n00b_plan_ordset_at(set, index);
    CHECK(n00b_result_is_ok(at_r));
    CHECK(!n00b_option_is_set(n00b_result_get(at_r)));
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
check_members(n00b_plan_ordset_t *set,
              uint64_t            record_count,
              const uint64_t     *expected,
              uint64_t            len)
{
    check_record_count(set, record_count);
    check_count(set, len);

    for (uint64_t i = 0; i < len; i++) {
        check_at_some(set, i, expected[i]);
    }
    check_at_none(set, len);

    for (uint64_t ordinal = 0; ordinal < record_count; ordinal++) {
        check_contains(set, ordinal, expected_has(expected, len, ordinal));
    }
    check_contains(set, record_count, false);
}

static n00b_plan_ordset_t *
make_set(uint64_t record_count, const uint64_t *members, uint64_t len)
{
    n00b_plan_ordset_t *set =
        ordset_ok(n00b_plan_ordset_empty(record_count));

    for (uint64_t i = 0; i < len; i++) {
        auto inserted_r = n00b_plan_ordset_insert(set, members[i]);
        CHECK(n00b_result_is_ok(inserted_r));
        CHECK(n00b_result_get(inserted_r));
    }

    return set;
}

static void
test_empty_full_and_zero_universe(void)
{
    CHECK(n00b_plan_err_str(N00B_PLAN_ERR_ORDINAL) != nullptr);
    CHECK(n00b_plan_err_str(N00B_PLAN_ERR_UNIVERSE) != nullptr);

    n00b_plan_ordset_t *zero = ordset_ok(n00b_plan_ordset_empty(0));
    check_members(zero, 0, nullptr, 0);
    CHECK_ERR(n00b_plan_ordset_insert(zero, 0), N00B_PLAN_ERR_ORDINAL);

    n00b_plan_ordset_t *zero_full = ordset_ok(n00b_plan_ordset_full(0));
    check_members(zero_full, 0, nullptr, 0);

    n00b_plan_ordset_t *zero_comp =
        ordset_ok(n00b_plan_ordset_complement(zero));
    check_members(zero_comp, 0, nullptr, 0);

    n00b_plan_ordset_t *full = ordset_ok(n00b_plan_ordset_full(10));
    uint64_t full_members[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    check_members(full, 10, full_members, 10);
}

static void
test_insert_contains_and_ordered_access(void)
{
    n00b_plan_ordset_t *set = ordset_ok(n00b_plan_ordset_empty(10));
    uint64_t            inserted[] = {7, 1, 4};

    for (uint64_t i = 0; i < 3; i++) {
        auto inserted_r = n00b_plan_ordset_insert(set, inserted[i]);
        CHECK(n00b_result_is_ok(inserted_r));
        CHECK(n00b_result_get(inserted_r));
    }

    auto duplicate_r = n00b_plan_ordset_insert(set, 4);
    CHECK(n00b_result_is_ok(duplicate_r));
    CHECK(!n00b_result_get(duplicate_r));
    CHECK_ERR(n00b_plan_ordset_insert(set, 10), N00B_PLAN_ERR_ORDINAL);

    uint64_t expected[] = {1, 4, 7};
    check_members(set, 10, expected, 3);
}

static void
test_sparse_dense_and_singleton_edges(void)
{
    uint64_t sparse_members[] = {0, 7, 8, 63, 64, 69};
    n00b_plan_ordset_t *sparse =
        make_set(70, sparse_members, 6);
    check_members(sparse, 70, sparse_members, 6);

    n00b_plan_ordset_t *full = ordset_ok(n00b_plan_ordset_full(70));
    check_record_count(full, 70);
    check_count(full, 70);
    check_at_some(full, 0, 0);
    check_at_some(full, 69, 69);
    check_at_none(full, 70);
    check_contains(full, 69, true);
    check_contains(full, 70, false);

    n00b_plan_ordset_t *one_empty = ordset_ok(n00b_plan_ordset_empty(1));
    check_members(one_empty, 1, nullptr, 0);
    n00b_plan_ordset_t *one_full = ordset_ok(n00b_plan_ordset_full(1));
    uint64_t one[] = {UINT64_C(0)};
    check_members(one_full, 1, one, 1);
    n00b_plan_ordset_t *one_comp =
        ordset_ok(n00b_plan_ordset_complement(one_full));
    check_members(one_comp, 1, nullptr, 0);
}

static void
test_boolean_algebra_and_complement(void)
{
    uint64_t a_members[] = {1, 3, 5};
    uint64_t b_members[] = {3, 4, 5, 7};

    n00b_plan_ordset_t *a = make_set(8, a_members, 3);
    n00b_plan_ordset_t *b = make_set(8, b_members, 4);

    n00b_plan_ordset_t *u = ordset_ok(n00b_plan_ordset_union(a, b));
    uint64_t union_expected[] = {1, 3, 4, 5, 7};
    check_members(u, 8, union_expected, 5);

    n00b_plan_ordset_t *i =
        ordset_ok(n00b_plan_ordset_intersection(a, b));
    uint64_t intersection_expected[] = {3, 5};
    check_members(i, 8, intersection_expected, 2);

    n00b_plan_ordset_t *d = ordset_ok(n00b_plan_ordset_difference(a, b));
    uint64_t difference_expected[] = {1};
    check_members(d, 8, difference_expected, 1);

    n00b_plan_ordset_t *comp = ordset_ok(n00b_plan_ordset_complement(a));
    uint64_t complement_expected[] = {0, 2, 4, 6, 7};
    check_members(comp, 8, complement_expected, 5);

    n00b_plan_ordset_t *empty = ordset_ok(n00b_plan_ordset_empty(8));
    n00b_plan_ordset_t *full  = ordset_ok(n00b_plan_ordset_full(8));

    check_members(ordset_ok(n00b_plan_ordset_union(a, empty)),
                  8,
                  a_members,
                  3);
    check_members(ordset_ok(n00b_plan_ordset_intersection(a, full)),
                  8,
                  a_members,
                  3);
    check_members(ordset_ok(n00b_plan_ordset_difference(a, a)),
                  8,
                  nullptr,
                  0);
    check_members(ordset_ok(n00b_plan_ordset_union(a, comp)),
                  8,
                  (uint64_t[]){0, 1, 2, 3, 4, 5, 6, 7},
                  8);
    check_members(ordset_ok(n00b_plan_ordset_intersection(a, comp)),
                  8,
                  nullptr,
                  0);
    check_members(ordset_ok(n00b_plan_ordset_complement(comp)),
                  8,
                  a_members,
                  3);
}

static void
test_mismatched_universes_and_null_inputs(void)
{
    uint64_t a_members[] = {0, 2};
    uint64_t b_members[] = {0, 2};
    n00b_plan_ordset_t *a = make_set(4, a_members, 2);
    n00b_plan_ordset_t *b = make_set(5, b_members, 2);

    CHECK_ERR(n00b_plan_ordset_union(a, b), N00B_PLAN_ERR_UNIVERSE);
    CHECK_ERR(n00b_plan_ordset_intersection(a, b),
              N00B_PLAN_ERR_UNIVERSE);
    CHECK_ERR(n00b_plan_ordset_difference(a, b), N00B_PLAN_ERR_UNIVERSE);

    CHECK_ERR(n00b_plan_ordset_record_count(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_count(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_insert(nullptr, 0), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_contains(nullptr, 0), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_at(nullptr, 0), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_union(nullptr, a), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_intersection(a, nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_difference(nullptr, a), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_ordset_complement(nullptr), N00B_PLAN_ERR_ARG);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_empty_full_and_zero_universe();
    test_insert_contains_and_ordered_access();
    test_sparse_dense_and_singleton_edges();
    test_boolean_algebra_and_complement();
    test_mismatched_universes_and_null_inputs();

    n00b_shutdown();
    return 0;
}

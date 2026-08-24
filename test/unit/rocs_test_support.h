/*
 * Fixtures every rocs test needs and none of them owns.
 *
 * One copy of each, because a second that drifts is a test of the wrong thing:
 * a shard allocator configured differently exercises a memory model production
 * does not use, and a counter assertion left unwrapped breaks the release
 * build alone.
 */

#pragma once

#include <stdint.h>
#include <time.h>

#include "core/pool.h"

#include "util/assert.h"

#include "internal/rocs/eval.h"
#include "internal/rocs/index.h"
#include "internal/rocs/plan.h"
#include "internal/rocs/plan_ir.h"

// Shards built by a store allocate from its hot pool, configured exactly as
// below: hidden, inline headers, no external metadata. Inline headers keep the
// allocations resolvable by n00b_find_alloc_info, and the pool never moves, so
// the rwlocks guarding a shard's lists stay put while a futex wait is keyed on
// their address. A shard built with no allocator would get the default moving
// heap instead. Tests should exercise the memory model production uses.
[[maybe_unused]] static n00b_allocator_t *
test_shard_allocator(void)
{
    static n00b_pool_t       pool;
    static n00b_allocator_t *shared = nullptr;

    if (shared == nullptr) {
        shared = n00b_pool_init(&pool,
                                .hidden            = true,
                                .external_metadata = false,
                                .inline_headers    = true,
                                .name              = "rocs_test_shard_pool");
    }
    return shared;
}

// Predicate and value construction every rocs plan test repeats. These call
// n00b_require rather than a test's own CHECK: most files define that macro
// below their include of this header, so it is not in scope here.

[[maybe_unused]] static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

[[maybe_unused]] static n00b_plan_target_t *
target(n00b_string_t *field)
{
    auto r = n00b_plan_target_field(field);
    n00b_require(n00b_result_is_ok(r), "plan target field failed");
    return n00b_result_get(r);
}

[[maybe_unused]] static n00b_plan_predicate_t *
eq(n00b_string_t *field, n00b_string_t *value)
{
    auto r = n00b_plan_predicate_eq(
        target(field),
        json_value(n00b_json_string_new_from_n00b(value)));
    n00b_require(n00b_result_is_ok(r), "eq predicate failed");
    return n00b_result_get(r);
}

[[maybe_unused]] static n00b_plan_predicate_t *
group(n00b_plan_predicate_t *a, n00b_plan_predicate_t *b, bool conjunction)
{
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    n00b_require(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, a)),
                 "group append failed");
    n00b_require(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, b)),
                 "group append failed");
    auto r = conjunction ? n00b_plan_predicate_and(kids)
                         : n00b_plan_predicate_or(kids);
    n00b_require(n00b_result_is_ok(r), "group predicate failed");
    return n00b_result_get(r);
}

// Takes the kind explicitly. A test that indexes a field is choosing how it
// will be searched, and reading that off the call is the point.
[[maybe_unused]] static n00b_store_index_t *
index_of(n00b_string_t *field, n00b_store_index_kind_t kind)
{
    auto r = n00b_store_index_new(field, kind);
    n00b_require(n00b_result_is_ok(r), "index new failed");
    return n00b_result_get(r);
}

[[maybe_unused]] static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

// Counts, then the plan those counts decide. A plan is built for one shard
// (plan.h rule 4), so the shard it will run against is what supplies them;
// taking both in one call is what stops a test from building a plan that
// decides ordering with nothing to decide it from.
// Structure, counts, decisions: the three steps a query takes, in order.
// Taking them together here is what stops a test from running a plan nothing
// ever folded counts into.
[[maybe_unused]] static n00b_plan_node_t *
test_plan_hot(n00b_plan_predicate_t  *predicate,
              n00b_plan_index_list_t *indexes,
              n00b_store_shard_t     *shard)
{
    auto plan_r = n00b_plan_build(predicate, indexes);
    n00b_require(n00b_result_is_ok(plan_r), "plan build failed");
    n00b_plan_node_t *plan = n00b_result_get(plan_r);

    auto c_r = n00b_plan_collect_hot(plan, shard);
    n00b_require(n00b_result_is_ok(c_r), "hot collect failed");

    (void)n00b_plan_settle(plan, shard->record_count);
    return plan;
}

[[maybe_unused]] static n00b_plan_node_t *
test_plan_mapped(n00b_plan_predicate_t  *predicate,
                 n00b_plan_index_list_t *indexes,
                 n00b_store_map_shard_t *shard)
{
    auto plan_r = n00b_plan_build(predicate, indexes);
    n00b_require(n00b_result_is_ok(plan_r), "plan build failed");
    n00b_plan_node_t *plan = n00b_result_get(plan_r);

    auto c_r = n00b_plan_collect_mapped(plan, shard);
    n00b_require(n00b_result_is_ok(c_r), "mapped collect failed");

    auto rc_r = _rocs_plan_mapped_record_count(shard);
    (void)n00b_plan_settle(plan,
                           n00b_result_is_ok(rc_r) ? n00b_result_get(rc_r) : 0);
    return plan;
}

// A plan nothing folded counts into. Every leaf stays unseeded, so ordering
// and the empty short circuit both decline and the shape is the planner's
// structural answer alone. Do not execute what this returns for a work-count
// assertion; use test_plan_hot or test_plan_mapped for anything measured.
[[maybe_unused]] static n00b_plan_node_t *
test_plan_shape(n00b_plan_predicate_t *predicate, n00b_plan_index_list_t *ix)
{
    auto r = n00b_plan_build(predicate, ix);
    n00b_require(n00b_result_is_ok(r), "structural plan build failed");
    return n00b_result_get(r);
}

// The work counters exist only under N00B_DEBUG, where counting costs a write
// on the scan path. Without them a test still runs and still checks every
// answer; only the assertions about how much work a plan did sit out. Wrapping
// them here rather than at each site is what keeps a release build compiling,
// and clear about what it verified.
#ifdef N00B_DEBUG
#define WORK_CHECK(expr)  CHECK(expr)
#define WORK_RESET()      n00b_plan_records_scanned_reset()
#define WORK_READ()       n00b_plan_records_scanned()
#define WORK_COST_RESET() n00b_plan_predicate_cost_spent_reset()
#define WORK_COST_READ()  n00b_plan_predicate_cost_spent()
#else
#define WORK_CHECK(expr)  ((void)0)
#define WORK_RESET()      ((void)0)
#define WORK_READ()       UINT64_C(0)
#define WORK_COST_RESET() ((void)0)
#define WORK_COST_READ()  UINT64_C(0)
#endif

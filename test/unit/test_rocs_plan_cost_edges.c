/*
 * Cost-planning edges the other cost suites do not reach.
 *
 *   sealed   A mapped shard prices a probe differently from a hot one, since a
 *            binary search there walks pages rather than memory this process
 *            already owns.
 *   shared   Resolved lookup keys are published onto a plan's nodes lazily,
 *            under a CAS, so several plans running at once are what exercise
 *            the publication.
 *   empty    A shard with no records. Ordering compares child counts against
 *            record_count, and zero is the value every such comparison has an
 *            edge at.
 */

// n00b_thread_spawn workers, not pthread_create.
#define __N00B_THREAD_INTERNAL

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/codegen_abi_inject.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"
#include "rocs_test_support.h"

#define CHECK(expr)                                                                            \
    do {                                                                                       \
        n00b_require((expr), "test check failed: " #expr);                                     \
    } while (0)

#define RECORDS UINT64_C(1024)
#define SHARDS  4

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *level;
    n00b_store_index_t *trace;
    n00b_store_index_t *kind;
    n00b_store_index_t *message;
} sample_t;

// `rows` of 0 builds an indexed shard with nothing in it.
static sample_t
sample_of(uint64_t shard_id, uint64_t rows)
{
    auto shard_r
        = n00b_store_shard_new(.shard_id = shard_id, .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    sample_t s = {
        .shard = n00b_result_get(shard_r),
        .level = index_of(r"level", N00B_STORE_INDEX_TERM),
        .trace = index_of(r"trace", N00B_STORE_INDEX_TERM),
        .kind  = index_of(r"kind", N00B_STORE_INDEX_TERM),
        // A lossy descriptor, so a leaf that is not eq can be planned. The
        // count-driven decisions apply to those too, and only an eq leaf
        // proves it for eq.
        .message = index_of(r"message", N00B_STORE_INDEX_FULLTEXT),
    };

    for (uint64_t i = 0; i < rows; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(
            rec,
            r"level",
            n00b_json_string_new_from_n00b(i + 1 < rows ? r"info" : r"error"));
        n00b_json_object_put_n00b(rec, r"kind", n00b_json_string_new_from_n00b(r"log"));
        n00b_json_object_put_n00b(
            rec,
            r"trace",
            n00b_json_string_new_from_n00b(n00b_cformat("t-«#»", (int64_t)i)));
        n00b_json_object_put_n00b(
            rec,
            r"message",
            n00b_json_string_new_from_n00b(r"an error opening the log"));

        auto a_r = n00b_store_shard_append(s.shard, rec);
        CHECK(n00b_result_is_ok(a_r));
        uint64_t ord = n00b_result_get(a_r);
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.level, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.trace, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.kind, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.message, s.shard, ord)));
    }
    return s;
}

static n00b_plan_node_t *
plan_of(sample_t *s, n00b_plan_predicate_t *pred)
{
    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->kind)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->message)));
    auto r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(r), s->shard)));
    (void)n00b_plan_settle(n00b_result_get(r), s->shard->record_count);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static void
check_same_members(n00b_plan_ordset_t *a, n00b_plan_ordset_t *b, uint64_t rows)
{
    for (uint64_t i = 0; i < rows; i++) {
        auto in_a = n00b_plan_ordset_contains(a, i);
        auto in_b = n00b_plan_ordset_contains(b, i);
        CHECK(n00b_result_is_ok(in_a) && n00b_result_is_ok(in_b));
        CHECK(n00b_result_get(in_a) == n00b_result_get(in_b));
    }
}

// ---------------------------------------------------------------------------
// empty
// ---------------------------------------------------------------------------

// Ordering weighs a group's child count against record_count, and skips
// bounding when there are more children than records. With no records that
// comparison holds for every group, which is the branch nothing else takes.
static void
test_empty_shard_answers_and_does_not_order(void)
{
    sample_t s = sample_of(UINT64_C(0xE0), 0);

    n00b_plan_predicate_t *shapes[] = {
        eq(r"level", r"info"),
        group(eq(r"level", r"info"), eq(r"kind", r"log"), true),
        group(eq(r"level", r"info"), eq(r"kind", r"log"), false),
    };

    for (uint64_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        n00b_plan_node_t *plan = plan_of(&s, shapes[i]);

        for (int cost = 0; cost < 2; cost++) {
            n00b_plan_cost_set_enabled(cost != 0);
            auto set_r = n00b_plan_exec_hot(plan, s.shard);
            CHECK(n00b_result_is_ok(set_r));
            auto count_r = n00b_plan_ordset_count(n00b_result_get(set_r));
            CHECK(n00b_result_is_ok(count_r));
            CHECK(n00b_result_get(count_r) == 0);
        }
    }
    n00b_plan_cost_set_enabled(true);

    n00b_printf("  [PASS] an empty shard answers empty, either way");
}

// ---------------------------------------------------------------------------
// sealed
// ---------------------------------------------------------------------------

// Wide and deep shapes against a mapped shard. The hot pathological suite
// covers the same structures over memory this process owns; here the postings
// live in a mapping, which is where the probe-versus-walk arithmetic is least
// certain.
static void
test_sealed_shapes_answer_like_hot(void)
{
    sample_t s = sample_of(UINT64_C(0xE1), RECORDS);

    // Wide: one group, many children. Deep: alternating kinds so the planner
    // keeps the levels apart instead of splicing them.
    n00b_plan_predicate_list_t *wide = n00b_plan_predicate_list_new();
    for (int i = 0; i < 64; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            wide,
            eq(r"trace", n00b_cformat("t-«#»", (int64_t)(i * 7))))));
    }
    auto wide_r = n00b_plan_predicate_or(wide);
    CHECK(n00b_result_is_ok(wide_r));

    n00b_plan_predicate_t *deep = eq(r"kind", r"log");
    for (int i = 0; i < 24; i++) {
        deep = group(deep, eq(r"level", i % 2 == 0 ? r"info" : r"error"), i % 2 == 0);
    }

    n00b_plan_predicate_t *shapes[] = {
        n00b_result_get(wide_r),
        deep,
        group(eq(r"level", r"info"), eq(r"kind", r"log"), true),
    };

    n00b_plan_node_t   *plans[3];
    n00b_plan_ordset_t *hot[3];

    for (uint64_t i = 0; i < 3; i++) {
        plans[i] = plan_of(&s, shapes[i]);
        n00b_plan_cost_set_enabled(true);
        auto set_r = n00b_plan_exec_hot(plans[i], s.shard);
        CHECK(n00b_result_is_ok(set_r));
        hot[i] = n00b_result_get(set_r);
    }

    // Hot execution refuses a sealed shard, so seal only once the hot answers
    // are in hand.
    auto seal_r = n00b_store_shard_seal(s.shard, .seal_ts = 77, .base_address = 0xE10000u);
    CHECK(n00b_result_is_ok(seal_r));
    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));
    n00b_store_map_shard_t *sealed = n00b_result_get(root_r);

    for (uint64_t i = 0; i < 3; i++) {
        for (int cost = 0; cost < 2; cost++) {
            n00b_plan_cost_set_enabled(cost != 0);
            auto set_r = n00b_plan_exec_mapped(plans[i], sealed);
            CHECK(n00b_result_is_ok(set_r));
            check_same_members(hot[i], n00b_result_get(set_r), RECORDS);
        }
    }
    n00b_plan_cost_set_enabled(true);

    CHECK(n00b_result_is_ok(n00b_store_map_close(n00b_result_get(map_r))));
    n00b_printf("  [PASS] sealed shapes answer like hot, either way");
}

// ---------------------------------------------------------------------------
// absent column
// ---------------------------------------------------------------------------

// A field declared with an index that no record here populated, so this shard
// carries no column for it. Its posting count reads zero, which is the number
// a present column reports for a term it simply does not carry, and the two
// want opposite orderings. Zero normally means "matches nothing, run me first
// and the intersect is settled". An absent column means the scan recovers into
// a record scan instead, so running it first is running the most expensive
// child with nothing to narrow it.
//
// The observable is records read. Ordered first, the recovery scans the shard;
// ordered behind a selective sibling, it scans what that sibling left.
static void
test_absent_column_does_not_order_first(void)
{
    sample_t            s     = sample_of(UINT64_C(0xAB5), RECORDS);
    n00b_store_index_t *ghost = index_of(r"ghost", N00B_STORE_INDEX_TERM);

    // `level = error` is on exactly one record, so a correctly ordered
    // intersect leaves the recovery almost nothing to read.
    n00b_plan_predicate_t *pred
        = group(eq(r"level", r"error"), eq(r"ghost", r"anything"), true);

    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s.level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s.trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s.kind)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, ghost)));
    auto plan_r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(plan_r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(plan_r), s.shard)));
    (void)n00b_plan_settle(n00b_result_get(plan_r), s.shard->record_count);
    CHECK(n00b_result_is_ok(plan_r));
    n00b_plan_node_t *plan = n00b_result_get(plan_r);

    auto seal_r = n00b_store_shard_seal(s.shard, .seal_ts = 91, .base_address = 0xAB50000u);
    CHECK(n00b_result_is_ok(seal_r));
    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));
    n00b_store_map_shard_t *sealed = n00b_result_get(root_r);

    // No watermark is passed, so a missing column is never trusted to mean
    // empty and the scan is the only correct answer for it.
    n00b_plan_cost_set_enabled(true);
    WORK_RESET();
    auto set_r = n00b_plan_exec_mapped(plan, sealed);
    CHECK(n00b_result_is_ok(set_r));

    // Nothing populated `ghost`, so nothing matches.
    auto count_r = n00b_plan_ordset_count(n00b_result_get(set_r));
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);

    // The point of the test. Ordering the absent column first reads every
    // record; ordering it behind `level = error` reads the one that matched.
    WORK_CHECK(n00b_plan_records_scanned() < RECORDS);

    CHECK(n00b_result_is_ok(n00b_store_map_close(n00b_result_get(map_r))));
    n00b_printf("  [PASS] an absent column is not ordered ahead of a sibling");
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

// Every index scan in the plan must carry its resolved keys. Without this the
// concurrency check below passes whether or not the keys are shared: a null
// `resolved` is a legal fallback that makes each caller resolve its own, which
// is correct and simply slower. Asserting the field is populated is what makes
// the threads below a test of the shared state rather than of nothing.
static uint64_t
count_unresolved(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return 0;
    }
    if (node->kind == N00B_PLAN_NODE_INDEX_SCAN) {
        return node->resolved == nullptr ? 1 : 0;
    }

    uint64_t missing = count_unresolved(node->child);
    if (node->children != nullptr) {
        size_t kids = n00b_list_len(*node->children);
        for (size_t i = 0; i < kids; i++) {
            missing += count_unresolved(n00b_list_get(*node->children, i));
        }
    }
    return missing;
}

static n00b_plan_node_t *
first_index_scan(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return nullptr;
    }
    if (node->kind == N00B_PLAN_NODE_INDEX_SCAN) {
        return node;
    }

    n00b_plan_node_t *found = first_index_scan(node->child);
    if (found != nullptr) {
        return found;
    }
    if (node->children != nullptr) {
        size_t kids = n00b_list_len(*node->children);
        for (size_t i = 0; i < kids; i++) {
            found = first_index_scan(n00b_list_get(*node->children, i));
            if (found != nullptr) {
                return found;
            }
        }
    }
    return nullptr;
}

static void
clear_resolved(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return;
    }
    if (node->kind == N00B_PLAN_NODE_INDEX_SCAN) {
        atomic_store_explicit(&node->resolved, nullptr, memory_order_relaxed);
        return;
    }
    clear_resolved(node->child);
    if (node->children != nullptr) {
        size_t kids = n00b_list_len(*node->children);
        for (size_t i = 0; i < kids; i++) {
            clear_resolved(n00b_list_get(*node->children, i));
        }
    }
}

static uint64_t
count_index_scans(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return 0;
    }
    if (node->kind == N00B_PLAN_NODE_INDEX_SCAN) {
        return 1;
    }

    uint64_t found = count_index_scans(node->child);
    if (node->children != nullptr) {
        size_t kids = n00b_list_len(*node->children);
        for (size_t i = 0; i < kids; i++) {
            found += count_index_scans(n00b_list_get(*node->children, i));
        }
    }
    return found;
}

typedef struct {
    n00b_plan_node_t   *plan;
    n00b_store_shard_t *shard;
    n00b_plan_ordset_t *answer;
} worker_arg_t;

static void *
run_one(void *raw)
{
    worker_arg_t *arg = (worker_arg_t *)raw;

    // Several rounds, so the threads overlap on the shared plan rather than
    // finishing before the next one starts.
    for (int i = 0; i < 16; i++) {
        auto set_r = n00b_plan_exec_hot(arg->plan, arg->shard);
        CHECK(n00b_result_is_ok(set_r));
        arg->answer = n00b_result_get(set_r);
    }
    return nullptr;
}

// A plan per shard, all running at the same time. A plan belongs to its own
// shard (plan.h rule 4), so what is checked here is not that one plan is
// shared but that several plans executing concurrently answer what running
// them one after another does. Resolved lookup keys are published lazily under
// a CAS, so concurrent execution is what exercises that.
static void
test_plans_execute_concurrently_across_shards(void)
{
    sample_t s[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        s[i] = sample_of(UINT64_C(0xE200) + (uint64_t)i, RECORDS);
    }

    n00b_plan_node_t *plan
        = plan_of(&s[0],
                  group(eq(r"level", r"info"),
                        group(eq(r"kind", r"log"), eq(r"trace", r"t-9"), false),
                        true));

    // The state the threads share. Resolved once at plan build, read by every
    // shard, never written again.
    CHECK(count_index_scans(plan) > 0);
    CHECK(count_unresolved(plan) == 0);

    n00b_plan_cost_set_enabled(true);

    // Serial answers first, as the reference.
    n00b_plan_ordset_t *serial[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        auto set_r = n00b_plan_exec_hot(plan, s[i].shard);
        CHECK(n00b_result_is_ok(set_r));
        serial[i] = n00b_result_get(set_r);
    }

    worker_arg_t   args[SHARDS];
    n00b_thread_t *workers[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        args[i]  = (worker_arg_t){.plan = plan, .shard = s[i].shard};
        auto t_r = n00b_thread_spawn(run_one, &args[i]);
        CHECK(n00b_result_is_ok(t_r));
        workers[i] = n00b_result_get(t_r);
    }
    for (int i = 0; i < SHARDS; i++) {
        n00b_thread_join(workers[i]);
    }

    for (int i = 0; i < SHARDS; i++) {
        CHECK(args[i].answer != nullptr);
        check_same_members(serial[i], args[i].answer, RECORDS);
    }

    n00b_printf("  [PASS] a plan per shard, executed concurrently, agrees");
}

// ---------------------------------------------------------------------------
// posting counts are read once
// ---------------------------------------------------------------------------

// Ordering a group reads a posting count per indexed child, and then every
// child reads its own again on the way down. A count is fixed for a node on a
// shard, so reading it twice is waste: three indexed children should cost
// three reads, not three plus the two that were not picked.
static void
test_posting_counts_are_read_once_per_node(void)
{
    sample_t s = sample_of(UINT64_C(0x0C17), RECORDS);

    // Three distinct indexed leaves, none of them empty, so ordering reads all
    // three rather than stopping early on a child that matches nothing.
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, eq(r"level", r"info"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, eq(r"kind", r"log"))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, eq(r"trace", r"t-3"))));
    auto pred_r = n00b_plan_predicate_and(kids);
    CHECK(n00b_result_is_ok(pred_r));

    n00b_plan_node_t *plan = plan_of(&s, n00b_result_get(pred_r));

    n00b_plan_cost_set_enabled(true);
#ifdef N00B_DEBUG
    n00b_plan_index_df_reads_reset();
#endif
    auto set_r = n00b_plan_exec_hot(plan, s.shard);
    CHECK(n00b_result_is_ok(set_r));

#ifdef N00B_DEBUG
    // Two, not one per node: settling ordered the group before execution
    // began, and the child that ordering put first answers the intersection
    // without the third ever being asked for its count. Without the per-node
    // reuse the children that lost the ordering read their counts again when
    // they run, and this is five.
    CHECK(n00b_plan_index_df_reads() == 2);
#endif

    n00b_printf("  [PASS] a posting count is read once per node and shard");
}

// ---------------------------------------------------------------------------
// nested groups
// ---------------------------------------------------------------------------

// Ordering a group whose children include another group answers the same as
// not ordering it. Coverage of the shape, not of the reentrancy hazard in it:
// a permutation escaping an inner group into its parent only misbehaves for
// particular combinations of inner width, outer width and relative costs, and
// reproducing one by hand means predicting exactly what the planner emits
// after it merges and flattens. test_rocs_plan_oracle catches that by
// generating shapes rather than guessing at one, and it is what found it.
static void
test_nested_group_answers_like_an_unordered_one(void)
{
    sample_t s = sample_of(UINT64_C(0x0E57), RECORDS);

    // The inner group is deliberately WIDER than the outer. A permutation
    // leaking outward then carries indices past the outer group's child count,
    // so the outer loop reads past the end of its own list rather than merely
    // picking the wrong child. A narrower inner group only produces a wrong
    // choice, which the data may absorb without the answer changing.
    // The costs must differ, or the stable sort returns the identity and the
    // leaked permutation is indistinguishable from the one the outer group
    // wanted. An expensive leaf written first is what makes the inner order a
    // real permutation: [1,2,3,4,0], whose second entry is 2, which is past
    // the end of a two-child outer group.
    auto rex_r = n00b_regex_new(r"^t-[0-9]+$");
    CHECK(n00b_result_is_ok(rex_r));
    auto inner_rex_r = n00b_plan_predicate_regex(target(r"trace"), n00b_result_get(rex_r));
    CHECK(n00b_result_is_ok(inner_rex_r));

    n00b_plan_predicate_list_t *inner_kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(inner_kids, n00b_result_get(inner_rex_r))));
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(inner_kids, eq(r"trace", r"t-2"))));
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(inner_kids, eq(r"trace", r"t-3"))));
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(inner_kids, eq(r"trace", r"t-4"))));
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(inner_kids, eq(r"trace", r"t-5"))));
    auto inner_r = n00b_plan_predicate_or(inner_kids);
    CHECK(n00b_result_is_ok(inner_r));

    n00b_plan_predicate_list_t *outer = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(outer, n00b_result_get(inner_r))));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(outer, eq(r"kind", r"log"))));
    auto outer_r = n00b_plan_predicate_and(outer);
    CHECK(n00b_result_is_ok(outer_r));

    // No indexes, so the whole thing lands in one record scan and the nesting
    // is evaluated by the predicate walker rather than split across nodes.
    n00b_plan_index_list_t *none = n00b_plan_index_list_new();
    auto plan_r = n00b_plan_build(n00b_result_get(outer_r), none);
    CHECK(n00b_result_is_ok(plan_r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(plan_r), s.shard)));
    (void)n00b_plan_settle(n00b_result_get(plan_r), s.shard->record_count);
    CHECK(n00b_result_is_ok(plan_r));

    n00b_plan_cost_set_enabled(true);
    auto on_r = n00b_plan_exec_hot(n00b_result_get(plan_r), s.shard);
    CHECK(n00b_result_is_ok(on_r));

    n00b_plan_cost_set_enabled(false);
    auto off_r = n00b_plan_exec_hot(n00b_result_get(plan_r), s.shard);
    CHECK(n00b_result_is_ok(off_r));
    n00b_plan_cost_set_enabled(true);

    // Ordering a nested shape may reorder the work and may never change the
    // answer, which is the property the reordering has to preserve.
    check_same_members(n00b_result_get(on_r), n00b_result_get(off_r), RECORDS);

    n00b_printf("  [PASS] a nested group answers like an unordered one");
}

// ---------------------------------------------------------------------------
// predicate ordering
// ---------------------------------------------------------------------------

// A conjunction of two unindexed leaves, written expensive-first. Both become
// one record scan, so the whole cost is which leaf each record pays for: a
// conjunction stops at its first false, and the cheap leaf rejects every
// record on its own.
//
// Ordering happens twice over, once when the plan merges the scans it owns and
// again when execution walks the merged group, so disabling either alone
// leaves the other covering for it. A control for this has to disable both.
static void
test_expensive_predicate_runs_on_fewer_records(void)
{
    sample_t s = sample_of(UINT64_C(0x0DE4), RECORDS);

    auto compiled_r = n00b_regex_new(r"^t-[0-9]+$");
    CHECK(n00b_result_is_ok(compiled_r));
    auto rex_r = n00b_plan_predicate_regex(target(r"trace"), n00b_result_get(compiled_r));
    CHECK(n00b_result_is_ok(rex_r));

    // "ghost" is on no record, so the cheap leaf is false everywhere and the
    // regex should never be reached.
    n00b_plan_predicate_t *pred = group(n00b_result_get(rex_r), eq(r"ghost", r"never"), true);

    n00b_plan_index_list_t *ix      = n00b_plan_index_list_new();
    auto plan_r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(plan_r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(plan_r), s.shard)));
    (void)n00b_plan_settle(n00b_result_get(plan_r), s.shard->record_count);
    CHECK(n00b_result_is_ok(plan_r));

    n00b_plan_cost_set_enabled(true);
    WORK_COST_RESET();
    auto set_r = n00b_plan_exec_hot(n00b_result_get(plan_r), s.shard);
    CHECK(n00b_result_is_ok(set_r));

    auto count_r = n00b_plan_ordset_count(n00b_result_get(set_r));
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);

#ifdef N00B_DEBUG
    // Every record pays the cheap leaf and nothing else.
    uint64_t ordered = WORK_COST_READ();
    uint64_t cheap   = n00b_plan_cost_predicate(eq(r"ghost", r"never"));
    CHECK(ordered == RECORDS * cheap);
#endif

    // The same query with ordering off, which is what makes the check above
    // mean something: both halves of the ordering answer to this switch, so
    // turning it off is a control the test runs on itself rather than one
    // somebody has to reproduce by editing the source.
    n00b_plan_cost_set_enabled(false);
    auto plain_r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(plain_r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(plain_r), s.shard)));
    (void)n00b_plan_settle(n00b_result_get(plain_r), s.shard->record_count);
    CHECK(n00b_result_is_ok(plain_r));
    WORK_COST_RESET();
    auto plain_set_r = n00b_plan_exec_hot(n00b_result_get(plain_r), s.shard);
    CHECK(n00b_result_is_ok(plain_set_r));
    n00b_plan_cost_set_enabled(true);

    // Same answer either way. That is the property ordering may never break.
    check_same_members(n00b_result_get(set_r), n00b_result_get(plain_set_r), RECORDS);

#ifdef N00B_DEBUG
    // And strictly more work, because the regex now runs on every record.
    CHECK(WORK_COST_READ() > ordered);
#endif

    n00b_printf("  [PASS] a cheap leaf keeps an expensive one off records");
}

// ---------------------------------------------------------------------------
// dedup vs recovery
// ---------------------------------------------------------------------------

// Dropping a duplicate operand is only safe if the survivor answers for both,
// and the two differ in how they answer: the index half matches normalized
// values, the fallback that recovery runs matches raw ones. These pin the two
// facts that make that equivalent, because a normalizer change would break
// either one with nothing else in the suite failing.

// A repeated condition on a field this shard has no column for, so the
// survivor's fallback is what produces the answer. If dedup dropped an operand
// whose fallback was not equivalent, the recovered scan would answer for the
// wrong predicate.
static void
test_dedup_survivor_recovers_for_both(void)
{
    sample_t            s     = sample_of(UINT64_C(0xDED), RECORDS);
    n00b_store_index_t *ghost = index_of(r"ghost", N00B_STORE_INDEX_TERM);

    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s.level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, ghost)));

    // The same condition twice: dedup collapses it, recovery runs the one left.
    n00b_plan_node_t *dup
        = test_plan_hot(group(eq(r"ghost", r"x"), eq(r"ghost", r"x"), false), ix, s.shard);
    n00b_plan_node_t *one
        = test_plan_hot(group(eq(r"ghost", r"x"), eq(r"level", r"nothing-matches"), false),
                        ix,
                        s.shard);

    n00b_plan_cost_set_enabled(true);
    auto dup_set = n00b_plan_exec_hot(dup, s.shard);
    auto one_set = n00b_plan_exec_hot(one, s.shard);
    CHECK(n00b_result_is_ok(dup_set) && n00b_result_is_ok(one_set));
    check_same_members(n00b_result_get(dup_set), n00b_result_get(one_set), RECORDS);

    n00b_printf("  [PASS] a deduped operand recovers to the same answer");
}

// Term normalization keeps case, so two conditions differing only in case are
// different keys and both must survive dedup. Were term values folded, they
// would collapse to one operand whose fallback compares raw and answers for
// only one of them. This fails the moment that changes.
static void
test_case_variant_terms_are_not_deduped(void)
{
    sample_t s = sample_of(UINT64_C(0xCA5E), RECORDS);

    // Records carry "info" and "error" lowercase. The upper-case operand can
    // only contribute matches if it is kept and evaluated on its own terms.
    n00b_plan_predicate_t *pred
        = group(eq(r"level", r"ERROR"), eq(r"level", r"error"), false);
    n00b_plan_node_t *plan = plan_of(&s, pred);

    n00b_plan_cost_set_enabled(true);
    auto set_r = n00b_plan_exec_hot(plan, s.shard);
    CHECK(n00b_result_is_ok(set_r));
    auto count_r = n00b_plan_ordset_count(n00b_result_get(set_r));
    CHECK(n00b_result_is_ok(count_r));

    // sample_of makes exactly the last record "error". A dedup that folded
    // case could keep the upper-case operand and answer zero.
    CHECK(n00b_result_get(count_r) == 1);

    n00b_printf("  [PASS] case-variant term operands both survive dedup");
}

// ---------------------------------------------------------------------------
// two large shards
// ---------------------------------------------------------------------------

// Ingest, seal and map two shards big enough to matter in one process. The
// sealed cost test builds only one and said in a comment that two tripped an
// ingest fault, which is the kind of claim that needs a test or nothing.
//
// Sizes are deliberately past the point where a posting list turns dense and a
// seal writes real descriptors, so this exercises the ingest path rather than
// the bookkeeping around it.
#define BIG_ROWS UINT64_C(5000)

static void
test_two_large_shards_in_one_process(void)
{
    n00b_store_map_t *maps[2];

    for (int n = 0; n < 2; n++) {
        auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0xB16) + n,
                                            .allocator = test_shard_allocator());
        CHECK(n00b_result_is_ok(shard_r));
        n00b_store_shard_t *shard = n00b_result_get(shard_r);
        n00b_store_index_t *level = index_of(r"level", N00B_STORE_INDEX_TERM);
        n00b_store_index_t *trace = index_of(r"trace", N00B_STORE_INDEX_TERM);

        for (uint64_t i = 0; i < BIG_ROWS; i++) {
            n00b_json_node_t *rec = n00b_json_object_new();
            n00b_json_object_put_n00b(
                rec,
                r"level",
                n00b_json_string_new_from_n00b(i % 3 == 0 ? r"error" : r"info"));
            n00b_json_object_put_n00b(
                rec,
                r"trace",
                n00b_json_string_new_from_n00b(n00b_cformat("t-«#»", (int64_t)i)));

            auto a_r = n00b_store_shard_append(shard, rec);
            CHECK(n00b_result_is_ok(a_r));
            uint64_t ord = n00b_result_get(a_r);
            CHECK(n00b_result_is_ok(n00b_store_index_add(level, shard, ord)));
            CHECK(n00b_result_is_ok(n00b_store_index_add(trace, shard, ord)));
        }

        auto seal_r
            = n00b_store_shard_seal(shard,
                                    .seal_ts      = 500 + n,
                                    .base_address = 0xB160000u + (uint64_t)n * 0x100000u);
        CHECK(n00b_result_is_ok(seal_r));
        auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
        CHECK(n00b_result_is_ok(map_r));
        maps[n] = n00b_result_get(map_r);

        // Query it, so a shard damaged by building the one before it is caught
        // here rather than surviving as an image nobody read.
        auto root_r = n00b_store_map_root(maps[n]);
        CHECK(n00b_result_is_ok(root_r));
        auto found_r
            = n00b_store_index_lookup_mapped(level,
                                             n00b_result_get(root_r),
                                             n00b_json_string_new_from_n00b(r"error"));
        CHECK(n00b_result_is_ok(found_r));
    }

    for (int n = 0; n < 2; n++) {
        CHECK(n00b_result_is_ok(n00b_store_map_close(maps[n])));
    }

    n00b_printf("  [PASS] two large shards ingest and seal in one process");
}

// ---------------------------------------------------------------------------
// fan-out
// ---------------------------------------------------------------------------

// Collect the resolved-keys pointers in plan order, so a fan-out can be asked
// whether it resolved once or once per shard.
static void
collect_resolved(n00b_plan_node_t *node, void **out, uint64_t *n, uint64_t cap)
{
    if (node == nullptr || *n >= cap) {
        return;
    }
    if (node->kind == N00B_PLAN_NODE_INDEX_SCAN) {
        out[(*n)++] = (void *)node->resolved;
        return;
    }
    collect_resolved(node->child, out, n, cap);
    if (node->children != nullptr) {
        size_t kids = n00b_list_len(*node->children);
        for (size_t i = 0; i < kids; i++) {
            collect_resolved(n00b_list_get(*node->children, i), out, n, cap);
        }
    }
}

// One plan across several shards in turn, which is the shape the resolved-keys
// memo exists for and the one the suite otherwise skips: the bench and the
// sealed test uses a single shard.
//
// A plan belongs to one shard, so a fan-out builds one per shard. What is
// checked is that doing so answers the same as building a plan for each shard
// in isolation, which is the property the fan-out depends on, and that a plan
// built for one shard is never the plan another shard runs.
// An indexed operand no record satisfies. Its count is zero, so the whole
// conjunction is decided at plan time and the group is never built.
// The count-driven decisions are not eq-only.
//
// A contains leaf builds its lookup value from text rather than carrying the
// predicate's own node, so for a long time the count collected for it could
// not be matched back to the leaf that needed it, and every decision went
// dark for full-text and n-gram leaves while still being paid for. Counts now
// land on the plan's own nodes, so there is nothing to match. Asserted on the
// zero short circuit because that one is visible in the plan's shape.
static void
test_lossy_leaf_settles_an_intersection(void)
{
    sample_t s = sample_of(UINT64_C(0x105), RECORDS);

    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s.level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s.message)));

    // No record contains this, so the n-gram lookup has a count of zero.
    auto absent_r = n00b_plan_predicate_contains(target(r"message"),
                                                 r"zzqqxx");
    CHECK(n00b_result_is_ok(absent_r));

    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(kids, n00b_result_get(absent_r))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(kids, eq(r"level", r"info"))));
    auto pred_r = n00b_plan_predicate_and(kids);
    CHECK(n00b_result_is_ok(pred_r));
    n00b_plan_predicate_t *pred = n00b_result_get(pred_r);

    n00b_plan_cost_set_enabled(true);

    auto plan_r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(plan_r));
    n00b_plan_node_t *plan = n00b_result_get(plan_r);
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(plan, s.shard)));
    (void)n00b_plan_settle(plan, s.shard->record_count);

    auto kind_r = n00b_plan_node_kind(plan);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == N00B_PLAN_NODE_EMPTY);

    auto set_r = n00b_plan_exec_hot(plan, s.shard);
    CHECK(n00b_result_is_ok(set_r));
    auto count_r = n00b_plan_ordset_count(n00b_result_get(set_r));
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);

    // The control: with nothing reading the count, the group is planned and
    // run, and reaches the same answer the long way.
    n00b_plan_cost_set_enabled(false);
    n00b_plan_node_t *ran = plan_of(&s, pred);
    auto ran_kind = n00b_plan_node_kind(ran);
    CHECK(n00b_result_is_ok(ran_kind));
    CHECK(n00b_result_get(ran_kind) != N00B_PLAN_NODE_EMPTY);

    auto ran_set = n00b_plan_exec_hot(ran, s.shard);
    CHECK(n00b_result_is_ok(ran_set));
    check_same_members(n00b_result_get(set_r), n00b_result_get(ran_set),
                       RECORDS);

    n00b_plan_cost_set_enabled(true);
    n00b_printf("  [PASS] a lossy leaf's count settles a conjunction too");
}

static void
test_absent_value_settles_an_intersection(void)
{
    sample_t s = sample_of(UINT64_C(0xE3B), RECORDS);

    n00b_plan_predicate_t *pred = group(eq(r"level", r"nothing-matches"),
                                        eq(r"kind", r"log"),
                                        true);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *settled = plan_of(&s, pred);

    auto settled_kind = n00b_plan_node_kind(settled);
    CHECK(n00b_result_is_ok(settled_kind));
    CHECK(n00b_result_get(settled_kind) == N00B_PLAN_NODE_EMPTY);

    auto settled_set = n00b_plan_exec_hot(settled, s.shard);
    CHECK(n00b_result_is_ok(settled_set));
    auto settled_count
        = n00b_plan_ordset_count(n00b_result_get(settled_set));
    CHECK(n00b_result_is_ok(settled_count));
    CHECK(n00b_result_get(settled_count) == 0);

    // The control. With the switch off nothing reads the count, so the group
    // is planned and run. It has to reach the same answer the long way, which
    // is what makes the shape above an optimization rather than a difference
    // in meaning.
    n00b_plan_cost_set_enabled(false);
    n00b_plan_node_t *ran = plan_of(&s, pred);

    auto ran_kind = n00b_plan_node_kind(ran);
    CHECK(n00b_result_is_ok(ran_kind));
    CHECK(n00b_result_get(ran_kind) != N00B_PLAN_NODE_EMPTY);

    auto ran_set = n00b_plan_exec_hot(ran, s.shard);
    CHECK(n00b_result_is_ok(ran_set));
    check_same_members(n00b_result_get(settled_set),
                       n00b_result_get(ran_set),
                       RECORDS);

    n00b_plan_cost_set_enabled(true);
}

// A conjunction nested deeper than the estimator will descend. It declines to
// bound the group rather than bounding it from a partial view, so the operands
// keep the order they were written in and the answer is unchanged.
static void
test_nesting_past_the_estimate_depth_is_left_unordered(void)
{
    sample_t s = sample_of(UINT64_C(0xDEE9), RECORDS);

    // Broad first, narrow last: the order costing would reverse.
    n00b_plan_predicate_t *deep = group(eq(r"level", r"info"),
                                        eq(r"trace", r"trace-3"),
                                        true);
    for (int i = 0; i < 8; i++) {
        deep = group(deep, eq(r"kind", r"log"), true);
    }

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *nested = plan_of(&s, deep);
    auto              nested_set = n00b_plan_exec_hot(nested, s.shard);
    CHECK(n00b_result_is_ok(nested_set));

    n00b_plan_cost_set_enabled(false);
    n00b_plan_node_t *plain = plan_of(&s, deep);
    auto              plain_set = n00b_plan_exec_hot(plain, s.shard);
    CHECK(n00b_result_is_ok(plain_set));

    check_same_members(n00b_result_get(nested_set),
                       n00b_result_get(plain_set),
                       RECORDS);

    n00b_plan_cost_set_enabled(true);
}

static void
test_fan_out_builds_a_plan_per_shard(void)
{
    sample_t s[SHARDS];
    uint64_t rows[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        // Differing row counts, so a plan that carried a record count or a
        // posting count between shards answers wrongly rather than slowly.
        rows[i] = RECORDS - (uint64_t)i * 64;
        s[i]    = sample_of(UINT64_C(0xFA0) + (uint64_t)i, rows[i]);
    }

    n00b_plan_predicate_t *pred = group(eq(r"level", r"info"), eq(r"kind", r"log"), true);

    n00b_plan_cost_set_enabled(true);

    n00b_plan_node_t *plans[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        // One per shard, which is what a fan-out does.
        plans[i] = plan_of(&s[i], pred);

        auto fanned_r = n00b_plan_exec_hot(plans[i], s[i].shard);
        CHECK(n00b_result_is_ok(fanned_r));

        // Against a plan built for this shard in isolation, which is the
        // property the fan-out relies on.
        n00b_plan_node_t *alone   = plan_of(&s[i], pred);
        auto              alone_r = n00b_plan_exec_hot(alone, s[i].shard);
        CHECK(n00b_result_is_ok(alone_r));

        check_same_members(n00b_result_get(fanned_r), n00b_result_get(alone_r), rows[i]);
    }

    // Distinct plans, not one object reused. A fan-out that shared a plan
    // would still answer correctly today and would stop doing so the moment
    // the planner decides anything from a shard's counts.
    for (int i = 0; i < SHARDS; i++) {
        for (int j = i + 1; j < SHARDS; j++) {
            CHECK(plans[i] != plans[j]);
        }
    }

    // Each plan resolves its own keys, and keeps them: a node resolves once
    // and republishes nothing.
    for (int i = 0; i < SHARDS; i++) {
        void    *before[16];
        void    *after[16];
        uint64_t n_before = 0;
        uint64_t n_after  = 0;
        collect_resolved(plans[i], before, &n_before, 16);
        CHECK(n_before > 0);
        auto again_r = n00b_plan_exec_hot(plans[i], s[i].shard);
        CHECK(n00b_result_is_ok(again_r));
        collect_resolved(plans[i], after, &n_after, 16);
        CHECK(n_after == n_before);
        for (uint64_t k = 0; k < n_after; k++) {
            CHECK(after[k] != nullptr && after[k] == before[k]);
        }
    }

    n00b_printf("  [PASS] a fan-out builds a plan per shard");
}

// ---------------------------------------------------------------------------
// writer vs probe
// ---------------------------------------------------------------------------
// contended key resolution
// ---------------------------------------------------------------------------

// The concurrent-plan test above asserts every index scan is already resolved
// before it spawns, which is the state a built plan is normally in and is also
// the one state in which the publishing CAS never runs. So it exercises the
// read of `resolved` and never the write.
//
// This starts from the other end: clear the field, then have every thread
// reach the same node at once. Whoever loses the CAS drops the key set it
// built and returns the published one, so the property to check is that all of
// them come back with the same pointer, not merely an equal one, since two
// equal key sets would answer queries identically and hide a lost publish.

#define KEY_THREADS 8

typedef struct {
    n00b_plan_node_t        *node;
    _Atomic(bool)           *start;
    n00b_store_index_keys_t *got;
} key_arg_t;

static void *
key_racer(void *raw)
{
    key_arg_t *arg = (key_arg_t *)raw;

    while (!atomic_load(arg->start)) {
        ;
    }
    arg->got = n00b_plan_node_keys(arg->node);
    return nullptr;
}

static void
test_key_resolution_publishes_one_object(void)
{
    sample_t          s    = sample_of(1, 64);
    n00b_plan_node_t *plan = plan_of(&s, eq(r"kind", r"log"));

    n00b_plan_node_t *scan = first_index_scan(plan);
    CHECK(scan != nullptr);

    // The state a plan is in before anyone has asked it for keys. Building it
    // is what the CAS below is racing to publish.
    clear_resolved(plan);
    CHECK(count_unresolved(plan) > 0);

    _Atomic(bool)   start = false;
    key_arg_t       args[KEY_THREADS];
    n00b_thread_t  *workers[KEY_THREADS];

    for (int i = 0; i < KEY_THREADS; i++) {
        args[i]  = (key_arg_t){.node = scan, .start = &start, .got = nullptr};
        auto t_r = n00b_thread_spawn(key_racer, &args[i]);
        CHECK(n00b_result_is_ok(t_r));
        workers[i] = n00b_result_get(t_r);
    }
    atomic_store(&start, true);
    for (int i = 0; i < KEY_THREADS; i++) {
        n00b_thread_join(workers[i]);
    }

    CHECK(args[0].got != nullptr);
    for (int i = 1; i < KEY_THREADS; i++) {
        CHECK(args[i].got == args[0].got);
    }
    // And the winner is what the node now holds, so a later single-threaded
    // caller joins the same object rather than resolving a ninth.
    CHECK(atomic_load(&scan->resolved) == args[0].got);
    CHECK(n00b_plan_node_keys(scan) == args[0].got);

    n00b_printf("  [PASS] «#» threads resolving one node share one key set",
                (int64_t)KEY_THREADS);
}

// ---------------------------------------------------------------------------

// Out-of-order arrival is supported by n00b_store_index_add, so a posting list
// grows by inserting below its tail, which shifts every element above the
// insertion point. A membership search that re-read the list between its steps
// would be searching a list that moved: the halves it ruled out stop
// describing what is there, and an ordinal that is present reads as absent.
//
// The existing coverage misses this from both sides. The out-of-order test is
// single-threaded, and the concurrency test gives each thread its own shard
// and no writer at all. This is the pair.

#define RACE_ROWS UINT64_C(512)

// How many passes each reader must complete while the writer is still writing.
// A fixed insert count does not bound this from below: the writer can finish
// its whole run before either reader is scheduled, and the test then passes
// having overlapped nothing. Driving the writer off the readers' counters
// makes the overlap a precondition of the run ending rather than a hope.
//
// Two floors, because the readers are not the same price. A probe binary
// searches and lands around 180k passes in the time a lookup, which walks the
// whole list and builds a posting object per element, manages under 200.
#define RACE_MIN_PROBES  UINT64_C(2000)
#define RACE_MIN_LOOKUPS UINT64_C(50)

// A ceiling, so a reader that cannot make progress fails the assertion below
// instead of hanging the suite.
#define RACE_DEADLINE_NS UINT64_C(20000000000)   // 20s

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *index;
    n00b_json_node_t   *value;
    _Atomic(bool)       start;
    _Atomic(bool)       done;
    _Atomic(uint64_t)   misses;
    _Atomic(uint64_t)   probes;
    _Atomic(uint64_t)   lookups;
    _Atomic(uint64_t)   lost;
    _Atomic(uint64_t)   writes;
} race_arg_t;

static void
race_wait_for_start(race_arg_t *arg)
{
    while (!atomic_load(&arg->start)) {
        ;
    }
}

// Descending, so every add inserts at position 0 and shifts the whole list.
//
// Keeps going until both readers have logged enough passes, rather than for a
// fixed number of inserts: the point is that they ran against a list that was
// moving, and only the readers can say whether that happened.
static void *
race_writer(void *raw)
{
    race_arg_t *arg      = (race_arg_t *)raw;
    uint64_t    deadline = now_ns() + RACE_DEADLINE_NS;

    race_wait_for_start(arg);

    do {
        for (uint64_t i = RACE_ROWS; i-- > 0;) {
            CHECK(n00b_result_is_ok(
                n00b_store_index_add(arg->index, arg->shard, i)));
            atomic_fetch_add(&arg->writes, 1);
        }
    } while ((atomic_load(&arg->probes) < RACE_MIN_PROBES
              || atomic_load(&arg->lookups) < RACE_MIN_LOOKUPS)
             && now_ns() < deadline);

    atomic_store(&arg->done, true);
    return nullptr;
}

// The enumeration half. probe_contains searches the list; a lookup walks it,
// and a walk is what a shifting insert breaks differently: an element can be
// read twice and the one pushed past the sampled length never read at all, so
// a record that matches goes missing from the answer rather than being found
// twice. The prober below cannot see that, which is why this exists.
static void *
race_lookuper(void *raw)
{
    race_arg_t *arg    = (race_arg_t *)raw;
    uint64_t    target = RACE_ROWS - 1;

    race_wait_for_start(arg);
    while (!atomic_load(&arg->done)) {
        auto found_r = n00b_store_index_lookup(arg->index, arg->shard, arg->value);
        if (n00b_result_is_err(found_r)) {
            continue;
        }
        n00b_store_postings_t *postings = n00b_result_get(found_r);
        auto                   len_r    = n00b_store_postings_len(postings);
        if (n00b_result_is_err(len_r)) {
            continue;
        }

        // Walk the answer looking for the ordinal that is always a member. A
        // dropped element is what a shifting insert costs a walk, so its
        // absence here is the failure this thread exists to catch.
        bool     seen = false;
        uint64_t len  = n00b_result_get(len_r);
        for (uint64_t i = 0; i < len && !seen; i++) {
            auto posting_r = n00b_store_postings_get(postings, i);
            if (n00b_result_is_err(posting_r)) {
                break;
            }
            n00b_option_t(n00b_store_posting_t) opt = n00b_result_get(posting_r);
            if (n00b_option_is_set(opt) && n00b_option_get(opt).pos.ordinal == target) {
                seen = true;
            }
        }

        atomic_fetch_add(&arg->lookups, 1);
        if (!seen) {
            atomic_fetch_add(&arg->lost, 1);
        }
    }
    return nullptr;
}

// Ordinal RACE_ROWS-1 goes in first and never moves out of the list, so every
// probe for it must say yes, whatever the writer is doing to the rest.
static void *
race_prober(void *raw)
{
    race_arg_t *arg    = (race_arg_t *)raw;
    uint64_t    target = RACE_ROWS - 1;

    race_wait_for_start(arg);
    while (!atomic_load(&arg->done)) {
        auto probe_r = n00b_store_index_probe_hot(arg->index, arg->shard, arg->value);
        if (n00b_result_is_err(probe_r)) {
            continue;
        }
        auto has_r = n00b_store_index_probe_contains(n00b_result_get(probe_r), target);
        if (n00b_result_is_err(has_r)) {
            continue;
        }
        atomic_fetch_add(&arg->probes, 1);
        if (!n00b_result_get(has_r)) {
            atomic_fetch_add(&arg->misses, 1);
        }
    }
    return nullptr;
}

static void
test_probe_survives_a_concurrent_writer(void)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0xACE5),
                                        .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    race_arg_t arg = {
        .shard = n00b_result_get(shard_r),
        .index = index_of(r"kind", N00B_STORE_INDEX_TERM),
        .value = n00b_json_string_new_from_n00b(r"log"),
    };

    // Every record carries the same value, so all of them land in one posting
    // list and the writer's inserts all contend on it.
    for (uint64_t i = 0; i < RACE_ROWS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(rec, r"kind", n00b_json_string_new_from_n00b(r"log"));
        CHECK(n00b_result_is_ok(n00b_store_shard_append(arg.shard, rec)));
    }

    // Seed the target so the prober has something to find from its first pass.
    CHECK(n00b_result_is_ok(n00b_store_index_add(arg.index, arg.shard, RACE_ROWS - 1)));

    auto w_r = n00b_thread_spawn(race_writer, &arg);
    CHECK(n00b_result_is_ok(w_r));
    auto p_r = n00b_thread_spawn(race_prober, &arg);
    CHECK(n00b_result_is_ok(p_r));
    auto l_r = n00b_thread_spawn(race_lookuper, &arg);
    CHECK(n00b_result_is_ok(l_r));

    // All three are up; let them go together rather than staggered by however
    // long a spawn took.
    atomic_store(&arg.start, true);

    n00b_thread_join(n00b_result_get(w_r));
    n00b_thread_join(n00b_result_get(p_r));
    n00b_thread_join(n00b_result_get(l_r));

    // A reader that never ran would pass the miss check by doing nothing, and
    // one that ran only after the writer finished would pass it by reading a
    // list that had stopped moving. The writer does not stop until both of
    // these are met, so falling short means it hit the deadline instead.
    CHECK(atomic_load(&arg.probes) >= RACE_MIN_PROBES);
    CHECK(atomic_load(&arg.lookups) >= RACE_MIN_LOOKUPS);
    CHECK(atomic_load(&arg.writes) > 0);
    CHECK(atomic_load(&arg.misses) == 0);
    CHECK(atomic_load(&arg.lost) == 0);

    n00b_printf("  [PASS] probe and lookup hold a present ordinal across "
                "«#» probes and «#» lookups over «#» inserts",
                (int64_t)atomic_load(&arg.probes),
                (int64_t)atomic_load(&arg.lookups),
                (int64_t)atomic_load(&arg.writes));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_empty_shard_answers_and_does_not_order();
    test_sealed_shapes_answer_like_hot();
    test_absent_column_does_not_order_first();
    test_plans_execute_concurrently_across_shards();
    test_posting_counts_are_read_once_per_node();
    test_nested_group_answers_like_an_unordered_one();
    test_expensive_predicate_runs_on_fewer_records();
    test_dedup_survivor_recovers_for_both();
    test_case_variant_terms_are_not_deduped();
    test_two_large_shards_in_one_process();
    test_absent_value_settles_an_intersection();
    test_lossy_leaf_settles_an_intersection();
    test_nesting_past_the_estimate_depth_is_left_unordered();
    test_fan_out_builds_a_plan_per_shard();
    test_key_resolution_publishes_one_object();
    test_probe_survives_a_concurrent_writer();

    n00b_shutdown();
    return 0;
}

/*
 * Which conjunct an INTERSECT runs first.
 *
 * Every child of an INTERSECT narrows the accumulator for the children after
 * it, so the order they run in is worth something even though it cannot change
 * the answer. Building alone cannot choose that order, since it reads no shard
 * and so cannot tell a term matching one record from a term matching all of
 * them. n00b_plan_collect_hot folds a shard's posting counts onto the plan and
 * n00b_plan_settle orders the group from them, which is what these tests
 * measure.
 */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#define CHECK(expr)                                                                            \
    do {                                                                                       \
        n00b_require((expr), "test check failed: " #expr);                                     \
    } while (0)

// plan_oracle.h wants CHECK already defined.
#include "plan_oracle.h"
#include "rocs_test_support.h"

#define SHARD_ID UINT64_C(0xC057)
#define RECORDS  UINT64_C(200)
// Every record but the last carries this level, so its posting list is the
// expensive one to walk and the useless one to walk first.
#define BROAD    (RECORDS - 1)

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *level;
    n00b_store_index_t *trace;
    n00b_store_index_t *message;
    n00b_store_index_t *kind;
    n00b_store_index_t *bucket;
    n00b_store_index_t *pair;
} sample_t;

static n00b_store_index_t *
index_for(n00b_string_t *field)
{
    auto index_r = n00b_store_index_new(field, N00B_STORE_INDEX_TERM);
    CHECK(n00b_result_is_ok(index_r));
    return n00b_result_get(index_r);
}

static n00b_store_index_t *
ngram_for(n00b_string_t *field)
{
    auto index_r = n00b_store_index_new(field, N00B_STORE_INDEX_NGRAM);
    CHECK(n00b_result_is_ok(index_r));
    return n00b_result_get(index_r);
}

static sample_t
sample_shell(uint64_t shard_id)
{
    auto shard_r
        = n00b_store_shard_new(.shard_id = shard_id, .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    return (sample_t){
        .shard   = n00b_result_get(shard_r),
        .level   = index_for(r"level"),
        .trace   = index_for(r"trace"),
        .message = ngram_for(r"message"),
        .kind    = index_for(r"kind"),
        .bucket  = index_for(r"bucket"),
        .pair    = index_for(r"pair"),
    };
}

static n00b_json_node_t *
sample_record(uint64_t i)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(
        record,
        r"level",
        n00b_json_string_new_from_n00b(i < BROAD ? r"info" : r"error"));
    // One distinct trace per record, so any trace lookup matches at most
    // one and is always the cheaper conjunct.
    n00b_json_object_put_n00b(
        record,
        r"trace",
        n00b_json_string_new_from_n00b(n00b_cformat("trace-«#»", (int64_t)i)));
    // Every message opens the same way, so a prefix over that opening
    // matches the whole shard and its n-grams rule out nothing.
    // Carried by every record, so a lookup for it covers the shard and can
    // saturate a union on its own.
    n00b_json_object_put_n00b(record, r"kind", n00b_json_string_new_from_n00b(r"log"));
    // Sized for the probe-versus-walk crossover: 30 records share a
    // bucket, 2 share a pair, against a 200-bit candidate bitmap.
    n00b_json_object_put_n00b(record,
                              r"bucket",
                              n00b_json_string_new_from_n00b(i < 30 ? r"b0" : r"b1"));
    n00b_json_object_put_n00b(
        record,
        r"pair",
        n00b_json_string_new_from_n00b(i < 2 ? r"p0" : n00b_cformat("p«#»", (int64_t)i)));
    n00b_json_object_put_n00b(
        record,
        r"message",
        n00b_json_string_new_from_n00b(n00b_cformat("common prefix «#»", (int64_t)i)));
    return record;
}

static void
sample_index_ordinal(sample_t *out, uint64_t ordinal)
{
    CHECK(n00b_result_is_ok(n00b_store_index_add(out->level, out->shard, ordinal)));
    CHECK(n00b_result_is_ok(n00b_store_index_add(out->trace, out->shard, ordinal)));
    CHECK(n00b_result_is_ok(n00b_store_index_add(out->message, out->shard, ordinal)));
    CHECK(n00b_result_is_ok(n00b_store_index_add(out->kind, out->shard, ordinal)));
    CHECK(n00b_result_is_ok(n00b_store_index_add(out->bucket, out->shard, ordinal)));
    CHECK(n00b_result_is_ok(n00b_store_index_add(out->pair, out->shard, ordinal)));
}

static sample_t
sample(void)
{
    sample_t out = sample_shell(SHARD_ID);

    for (uint64_t i = 0; i < RECORDS; i++) {
        auto append_r = n00b_store_shard_append(out.shard, sample_record(i));
        CHECK(n00b_result_is_ok(append_r));
        sample_index_ordinal(&out, n00b_result_get(append_r));
    }

    return out;
}

// The same records, indexed highest ordinal first.
//
// Every index_add then lands below the tail of the posting list it touches,
// which clears N00B_STORE_POSTINGS_ORDERED and leaves membership answered by a
// scan rather than a search until the shard is sealed.
// n00b_store_index_add constrains arrival order in no way, so this is a
// caller's choice rather than a corrupt shard, and the contents are identical
// either way.
static sample_t
sample_indexed_descending(void)
{
    sample_t out = sample_shell(SHARD_ID + 1);

    for (uint64_t i = 0; i < RECORDS; i++) {
        auto append_r = n00b_store_shard_append(out.shard, sample_record(i));
        CHECK(n00b_result_is_ok(append_r));
        CHECK(n00b_result_get(append_r) == i);
    }
    for (uint64_t i = RECORDS; i-- > 0;) {
        sample_index_ordinal(&out, i);
    }

    return out;
}

// Children are listed broad-first, which is the order the planner emits and
// the order a cost-blind interpreter would run them in.
static n00b_plan_node_t *
plan_broad_then_narrow(sample_t *s, n00b_string_t *trace_value)
{
    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    CHECK(
        n00b_result_is_ok(n00b_plan_predicate_list_append(children, eq(r"level", r"info"))));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(children, eq(r"trace", trace_value))));

    auto and_r = n00b_plan_predicate_and(children);
    CHECK(n00b_result_is_ok(and_r));

    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->trace)));

    auto plan_r = n00b_plan_build(n00b_result_get(and_r), indexes);
    CHECK(n00b_result_is_ok(plan_r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(plan_r), s->shard)));
    (void)n00b_plan_settle(n00b_result_get(plan_r), s->shard->record_count);
    CHECK(n00b_result_is_ok(plan_r));
    return n00b_result_get(plan_r);
}

static uint64_t
count_of(n00b_plan_ordset_t *set)
{
    auto count_r = n00b_plan_ordset_count(set);
    CHECK(n00b_result_is_ok(count_r));
    return n00b_result_get(count_r);
}

typedef struct {
    n00b_plan_ordset_t *set;
    uint64_t            records;
    uint64_t            postings;
    uint64_t            probes;
    uint64_t            df_reads;
} run_t;

// One execution, with ordering on or off, and what it cost. Running the same
// plan both ways in one process is the whole point of the switch: the answers
// have to match and the work does not.
static run_t
run_with_cost(n00b_plan_node_t *plan, n00b_store_shard_t *shard, bool cost)
{
    n00b_plan_cost_set_enabled(cost);
    CHECK(n00b_plan_cost_enabled() == cost);

#ifdef N00B_DEBUG
    n00b_plan_records_scanned_reset();
    n00b_plan_postings_walked_reset();
    n00b_plan_index_probes_reset();
    n00b_plan_index_df_reads_reset();
#endif

    auto set_r = n00b_plan_exec_hot(plan, shard);
    CHECK(n00b_result_is_ok(set_r));

    run_t out = {.set = n00b_result_get(set_r)};
#ifdef N00B_DEBUG
    out.records  = n00b_plan_records_scanned();
    out.postings = n00b_plan_postings_walked();
    out.probes   = n00b_plan_index_probes();
    out.df_reads = n00b_plan_index_df_reads();
#endif
    return out;
}

static bool
set_contains(n00b_plan_ordset_t *set, uint64_t ordinal)
{
    auto has_r = n00b_plan_ordset_contains(set, ordinal);
    CHECK(n00b_result_is_ok(has_r));
    return n00b_result_get(has_r);
}

// Same members, not merely the same number of them.
static void
check_same_answer(run_t a, run_t b, uint64_t expected)
{
    CHECK(count_of(a.set) == expected);
    CHECK(count_of(b.set) == expected);
    for (uint64_t i = 0; i < RECORDS; i++) {
        CHECK(set_contains(a.set, i) == set_contains(b.set, i));
    }
}

static n00b_plan_predicate_list_t *
children_of(n00b_plan_predicate_t *a, n00b_plan_predicate_t *b)
{
    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(children, a)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(children, b)));
    return children;
}

static n00b_plan_predicate_t *
all_of(n00b_plan_predicate_t *a, n00b_plan_predicate_t *b)
{
    auto and_r = n00b_plan_predicate_and(children_of(a, b));
    CHECK(n00b_result_is_ok(and_r));
    return n00b_result_get(and_r);
}

static n00b_plan_predicate_t *
any_of(n00b_plan_predicate_t *a, n00b_plan_predicate_t *b)
{
    auto or_r = n00b_plan_predicate_or(children_of(a, b));
    CHECK(n00b_result_is_ok(or_r));
    return n00b_result_get(or_r);
}

static n00b_plan_node_t *
plan_with_every_index(sample_t *s, n00b_plan_predicate_t *predicate)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->kind)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->bucket)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s->pair)));

    auto plan_r = n00b_plan_build(predicate, indexes);
    CHECK(n00b_result_is_ok(plan_r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(plan_r), s->shard)));
    (void)n00b_plan_settle(n00b_result_get(plan_r), s->shard->record_count);
    CHECK(n00b_result_is_ok(plan_r));
    return n00b_result_get(plan_r);
}

// An AND whose narrow conjunct matches nothing answers empty whichever order
// it runs in. Ordered, the narrow conjunct settles it before the broad posting
// list is touched at all.
static void
test_unsatisfiable_conjunct_short_circuits_the_broad_scan(void)
{
    sample_t s = sample();

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_broad_then_narrow(&s, r"trace-nosuchvalue"), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_broad_then_narrow(&s, r"trace-nosuchvalue");
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 0);
#ifdef N00B_DEBUG
    CHECK(off.postings == BROAD);
    CHECK(on.postings == 0);
#endif

    n00b_printf("  [PASS] an empty conjunct short-circuits the broad scan");
}

// Ordering may not change an answer, and the same plan against a trace that
// does match returns exactly the record carrying it either way.
//
// This is also where the second rule shows up. The narrow conjunct runs first
// and leaves one candidate, so the broad conjunct has a posting list far
// longer than the candidate set it has to intersect with. Asking the index
// about that one candidate replaces the walk.
static void
test_narrow_first_lets_the_broad_scan_probe_instead_of_walk(void)
{
    sample_t s = sample();

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_broad_then_narrow(&s, r"trace-42"), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_broad_then_narrow(&s, r"trace-42");
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 1);
    CHECK(set_contains(on.set, 42));
#ifdef N00B_DEBUG
    // Unordered: walk the broad list, then the narrow one.
    CHECK(off.postings == BROAD + 1);
    CHECK(off.probes == 0);
    // Ordered: walk the narrow list, then probe its one survivor.
    CHECK(on.postings == 1);
    CHECK(on.probes == 1);
#endif

    n00b_printf("  [PASS] a narrow conjunct first lets the broad one probe");
}

// The same shape over a shard whose posting lists were built out of order.
//
// The arithmetic behind the probe above prices a membership test at
// ceil(log2(df)) steps, which is a binary search. A sparse list that lost its
// order flag answers by scanning instead, at df steps, so the estimate the
// choice was made from understates the work by df/log2(df) per candidate: 199
// comparisons here rather than the 8 it charged for, and unboundedly worse as
// the term widens. The decision has to see that and walk the list.
//
// Walking is what the query would have done with cost planning off, so the
// refusal costs nothing beyond the probe it declined to build.
static void
test_an_unordered_posting_list_is_walked_not_probed(void)
{
    sample_t asc  = sample();
    sample_t desc = sample_indexed_descending();

    n00b_plan_cost_set_enabled(true);
    run_t ordered = run_with_cost(plan_broad_then_narrow(&asc, r"trace-42"),
                                  asc.shard, true);
    run_t scanned = run_with_cost(plan_broad_then_narrow(&desc, r"trace-42"),
                                  desc.shard, true);

    // Arrival order changes no answer, which is the property under everything
    // below it.
    check_same_answer(ordered, scanned, 1);
    CHECK(set_contains(scanned.set, 42));

#ifdef N00B_DEBUG
    // Ascending: the narrow list is walked and its one survivor probed.
    CHECK(ordered.probes == 1);
    // Descending: the same one candidate, and no probe. The broad list is
    // enumerated instead, which is BROAD postings on top of the narrow one.
    CHECK(scanned.probes == 0);
    CHECK(scanned.postings == BROAD + 1);
#endif

    n00b_printf("  [PASS] an unordered posting list is walked, not probed");
}

// Record 199 is the only one at level "error", so level="info" excludes it and
// the answer is empty despite the trace existing.
static void
test_narrow_conjunct_runs_first_on_a_match(void)
{
    sample_t s = sample();

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_broad_then_narrow(&s, r"trace-199"), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_broad_then_narrow(&s, r"trace-199");
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 0);

    n00b_printf("  [PASS] a matching narrow conjunct still filters correctly");
}

// An n-gram scan is lossy: it narrows a candidate set and a record scan
// settles what it leaves. A term carried by every record narrows nothing, and
// the posting counts say so before a single posting is read.
static void
test_lossy_scan_that_cannot_narrow_is_skipped(void)
{
    sample_t s = sample();

    auto target_r = n00b_plan_target_field(r"message");
    CHECK(n00b_result_is_ok(target_r));
    auto prefix_r = n00b_plan_predicate_prefix(n00b_result_get(target_r), r"com");
    CHECK(n00b_result_is_ok(prefix_r));

    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s.message)));

    // Each arm settles its own plan. The decisions are made by settle, not by
    // build, so one plan settled once and executed twice would compare
    // execution alone and pass on a planner that already discarded the answer.
    n00b_plan_cost_set_enabled(false);
    n00b_plan_node_t *plain = test_plan_hot(n00b_result_get(prefix_r),
                                            indexes,
                                            s.shard);
    run_t off = run_with_cost(plain, s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = test_plan_hot(n00b_result_get(prefix_r),
                                           indexes,
                                           s.shard);
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, RECORDS);
#ifdef N00B_DEBUG
    CHECK(off.postings > 0);
    CHECK(on.postings == 0);
    // The record scan that settles the prefix reads the same either way.
    CHECK(off.records == RECORDS);
    CHECK(on.records == RECORDS);
#endif

    n00b_printf("  [PASS] a lossy scan that cannot narrow is skipped");
}

// What widest-first buys, and its limit.
//
// The planner already emits a group's index scans ahead of the single record
// scan it merges the unindexed leaves into, so ordering never has to rescue a
// record scan from running first. What is left is the order among the index
// branches, which matters only when a union saturates: reaching the ceiling
// ends it, and every branch behind the one that got there is skipped.
//
// Both branches here are indexed and the wider is listed second, which is the
// only shape where the rule changes anything.
static void
test_widest_union_branch_first_saturates_sooner(void)
{
    sample_t          s = sample();
    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(&s, any_of(eq(r"level", r"info"), eq(r"kind", r"log"))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(&s, any_of(eq(r"level", r"info"), eq(r"kind", r"log")));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, RECORDS);
#ifdef N00B_DEBUG
    // Narrow-first walks both posting lists to learn it covered everything.
    CHECK(off.postings == BROAD + RECORDS);
    // Widest-first covers the shard with the first branch and stops.
    CHECK(on.postings == RECORDS);
#endif

    n00b_printf("  [PASS] the widest union branch saturates sooner");
}

// A union whose branches do not cover the candidate set runs every branch
// whichever order it picks, so ordering costs a probe per branch and saves
// nothing. Worth pinning: this is the common case, and the rule has to be
// harmless in it rather than merely useful elsewhere.
static void
test_union_that_cannot_saturate_costs_the_same(void)
{
    sample_t          s = sample();
    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(&s,
                                any_of(eq(r"trace", r"trace-7"), eq(r"level", r"error"))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(&s,
                                any_of(eq(r"trace", r"trace-7"), eq(r"level", r"error")));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 2);
    CHECK(set_contains(on.set, 7));
    CHECK(set_contains(on.set, RECORDS - 1));
#ifdef N00B_DEBUG
    CHECK(on.postings == off.postings);
#endif

    n00b_printf("  [PASS] a union that cannot saturate costs the same");
}

// The rules compose: the intersect ordering produces the restriction the
// nested union saturates against. The union's ceiling is what the intersect
// left, not the whole shard, which is what lets one branch reach it.
static void
test_union_nested_under_intersect_saturates_against_the_restriction(void)
{
    sample_t s = sample();

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(
        &s,
        all_of(eq(r"level", r"info"),
               any_of(eq(r"trace", r"trace-7"), eq(r"kind", r"log")))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(
        &s,
        all_of(eq(r"level", r"info"),
               any_of(eq(r"trace", r"trace-7"), eq(r"kind", r"log"))));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, BROAD);
    CHECK(set_contains(on.set, 0));
    CHECK(!set_contains(on.set, RECORDS - 1));
#ifdef N00B_DEBUG
    CHECK(on.postings < off.postings);
#endif

    n00b_printf(
        "  [PASS] a nested union saturates against an intersect's"
        " restriction");
}

// An intersect under a union, the other nesting direction. Ordering runs
// inside each branch independently and the answer is the union of what the
// branches match.
static void
test_intersect_nested_under_union_answers_correctly(void)
{
    sample_t s = sample();

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(
        &s,
        any_of(all_of(eq(r"level", r"error"), eq(r"kind", r"log")),
               all_of(eq(r"trace", r"trace-7"), eq(r"kind", r"log")))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(
        &s,
        any_of(all_of(eq(r"level", r"error"), eq(r"kind", r"log")),
               all_of(eq(r"trace", r"trace-7"), eq(r"kind", r"log"))));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 2);
    CHECK(set_contains(on.set, 7));
    CHECK(set_contains(on.set, RECORDS - 1));

    n00b_printf("  [PASS] an intersect nested under a union answers correctly");
}

// Three levels, so a group's bound is the bound of a group of groups. The
// estimator recurses to reach the leaves; this catches that recursion
// terminating somewhere other than the right answer.
static void
test_three_level_nesting_answers_correctly(void)
{
    sample_t s = sample();

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(
        &s,
        all_of(eq(r"kind", r"log"),
               any_of(all_of(eq(r"level", r"info"), eq(r"trace", r"trace-3")),
                      eq(r"level", r"error")))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(
        &s,
        all_of(eq(r"kind", r"log"),
               any_of(all_of(eq(r"level", r"info"), eq(r"trace", r"trace-3")),
                      eq(r"level", r"error"))));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 2);
    CHECK(set_contains(on.set, 3));
    CHECK(set_contains(on.set, RECORDS - 1));

    n00b_printf("  [PASS] three levels of nesting answer correctly");
}

// Probing is not free and is not always right. Getting at the candidate
// ordinals means walking the candidate bitmap once, and against a short
// posting list that walk costs more than reading the list would have.
//
// Two candidates against thirty postings on a two-hundred-record shard sits
// just inside that: counting only the binary searches says probe, counting the
// bitmap walk says read the list.
static void
test_short_posting_list_is_walked_not_probed(void)
{
    sample_t          s = sample();
    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(&s, all_of(eq(r"pair", r"p0"), eq(r"bucket", r"b0"))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(&s, all_of(eq(r"pair", r"p0"), eq(r"bucket", r"b0")));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, 2);
    CHECK(set_contains(on.set, 0));
    CHECK(set_contains(on.set, 1));
#ifdef N00B_DEBUG
    // Both posting lists read, neither probed.
    CHECK(on.probes == 0);
    CHECK(on.postings == 32);
#endif

    n00b_printf("  [PASS] a short posting list is walked, not probed");
}

// What ordering spends, as opposed to what it saves. The other counters only
// go down when ordering helps, so a suite built on them alone passes while
// wall time regresses: a group that reads a posting count per child and then
// changes nothing shows as flat.
//
// The bound is one read per indexed child of a group. Reading more than that
// means a child is being priced twice, which is the shape the memo exists to
// prevent and the shape that would reappear unnoticed if it were bypassed.
static void
test_deciding_costs_one_posting_count_per_child(void)
{
    sample_t s = sample();

    // Four indexed leaves across two groups, so at most four reads.
    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(
        &s,
        all_of(all_of(eq(r"level", r"info"), eq(r"kind", r"log")),
               any_of(eq(r"trace", r"trace-9"), eq(r"bucket", r"b0")))), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(
        &s,
        all_of(all_of(eq(r"level", r"info"), eq(r"kind", r"log")),
               any_of(eq(r"trace", r"trace-9"), eq(r"bucket", r"b0"))));
    run_t on = run_with_cost(plan, s.shard, true);

    check_same_answer(off, on, count_of(off.set));
#ifdef N00B_DEBUG
    // Ordering off reads none: nothing is deciding anything.
    CHECK(off.df_reads == 0);
    CHECK(on.df_reads <= 4);
#endif

    n00b_printf("  [PASS] deciding costs one posting count per indexed child");
}

// Everything above compares ordering against no ordering, which shows the two
// agree without showing either is right. The oracle answers the same predicate
// by scanning rows with no plan at all, so running it under both settings
// checks each against something that shares none of this machinery.
static void
test_ordering_agrees_with_an_unplanned_scan(void)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, index_for(r"level"))));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, index_for(r"kind"))));

    n00b_plan_predicate_t *shapes[] = {
        all_of(eq(r"level", r"info"), eq(r"kind", r"log")),
        any_of(eq(r"level", r"info"), eq(r"kind", r"log")),
        all_of(eq(r"level", r"error"),
               any_of(eq(r"kind", r"log"), eq(r"level", r"info"))),
        any_of(all_of(eq(r"level", r"info"), eq(r"kind", r"log")),
               eq(r"level", r"error")),
    };

    for (int cost = 0; cost < 2; cost++) {
        n00b_plan_cost_set_enabled(cost != 0);
        for (uint64_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
            n00b_plan_oracle_check(shapes[i], indexes);
        }
    }
    n00b_plan_cost_set_enabled(true);

    n00b_printf("  [PASS] ordering agrees with an unplanned scan");
}

// A predicate naming the same condition several times reads the same posting
// list once. A filter lowered from a generated query can repeat a condition
// without anything upstream folding it, and intersecting a set with itself
// changes nothing, so the extra copies are pure cost.
//
// The oracle runs alongside because this is a planner rewrite: dropping an
// operand has to answer the same as keeping it, and comparing against an
// unplanned scan says that in a way comparing plans to each other cannot.
static void
test_repeated_leaves_read_their_index_once(void)
{
    sample_t s = sample();

    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    for (int i = 0; i < 8; i++) {
        CHECK(
            n00b_result_is_ok(n00b_plan_predicate_list_append(kids, eq(r"level", r"info"))));
    }
    auto and_r = n00b_plan_predicate_and(kids);
    CHECK(n00b_result_is_ok(and_r));

    n00b_plan_node_t *repeated = plan_with_every_index(&s, n00b_result_get(and_r));
    n00b_plan_node_t *once     = plan_with_every_index(&s, eq(r"level", r"info"));

    run_t many = run_with_cost(repeated, s.shard, true);
    run_t one  = run_with_cost(once, s.shard, true);

    // Eight copies of a condition cost exactly what one costs.
    check_same_answer(many, one, BROAD);
#ifdef N00B_DEBUG
    CHECK(many.postings == one.postings);
    CHECK(many.df_reads <= one.df_reads);
#endif

    // The same shape under a union, where the identity is A | A = A.
    n00b_plan_predicate_list_t *ors = n00b_plan_predicate_list_new();
    for (int i = 0; i < 8; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(ors, eq(r"kind", r"log"))));
    }
    auto or_r = n00b_plan_predicate_or(ors);
    CHECK(n00b_result_is_ok(or_r));

    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s.level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, s.kind)));
    n00b_plan_oracle_check(n00b_result_get(or_r), indexes);

    n00b_printf("  [PASS] repeated leaves read their index once");
}

// The case the dedup costs most and saves nothing on: many distinct
// conditions, which is what `field IN (...)` lowers to. Every operand is a
// different lookup, so nothing collapses, and a pairwise dedup would compare
// every pair to learn that. Bucketing by digest makes it one lookup each.
//
// Correctness is the assertion here; the shape of the cost is measured in
// test_rocs_plan_pathological, which times plan build across widths.
static void
test_disjunction_of_distinct_conditions_keeps_all_operands(void)
{
    sample_t s = sample();

    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    uint64_t                    want = 24;
    for (uint64_t i = 0; i < want; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            kids,
            eq(r"trace", n00b_cformat("trace-«#»", (int64_t)i)))));
    }
    auto or_r = n00b_plan_predicate_or(kids);
    CHECK(n00b_result_is_ok(or_r));

    // Each arm builds its own plan. Two of the three cost decisions are
    // made while the plan is built, so one plan executed twice compares
    // execution alone and passes on a planner that already discarded the
    // answer.
    n00b_plan_cost_set_enabled(false);
    run_t off = run_with_cost(plan_with_every_index(&s, n00b_result_get(or_r)), s.shard, false);

    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *plan = plan_with_every_index(&s, n00b_result_get(or_r));
    run_t on = run_with_cost(plan, s.shard, true);

    // Distinct conditions: none may be dropped, so every record matches.
    check_same_answer(off, on, want);
    for (uint64_t i = 0; i < want; i++) {
        CHECK(set_contains(on.set, i));
    }

    // And one that repeats a condition inside the same disjunction still
    // collapses, so bucketing did not simply stop deduping.
    n00b_plan_predicate_list_t *dup = n00b_plan_predicate_list_new();
    for (int i = 0; i < 8; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(dup, eq(r"kind", r"log"))));
    }
    auto dup_r = n00b_plan_predicate_or(dup);
    CHECK(n00b_result_is_ok(dup_r));

    run_t many
        = run_with_cost(plan_with_every_index(&s, n00b_result_get(dup_r)), s.shard, true);
    run_t once = run_with_cost(plan_with_every_index(&s, eq(r"kind", r"log")), s.shard, true);
#ifdef N00B_DEBUG
    CHECK(many.postings == once.postings);
#endif

    n00b_printf("  [PASS] a disjunction of distinct conditions keeps them all");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_unsatisfiable_conjunct_short_circuits_the_broad_scan();
    test_narrow_first_lets_the_broad_scan_probe_instead_of_walk();
    test_an_unordered_posting_list_is_walked_not_probed();
    test_narrow_conjunct_runs_first_on_a_match();
    test_lossy_scan_that_cannot_narrow_is_skipped();
    test_widest_union_branch_first_saturates_sooner();
    test_union_that_cannot_saturate_costs_the_same();
    test_union_nested_under_intersect_saturates_against_the_restriction();
    test_intersect_nested_under_union_answers_correctly();
    test_three_level_nesting_answers_correctly();
    test_short_posting_list_is_walked_not_probed();
    test_deciding_costs_one_posting_count_per_child();
    test_ordering_agrees_with_an_unplanned_scan();
    test_repeated_leaves_read_their_index_once();
    test_disjunction_of_distinct_conditions_keeps_all_operands();

    n00b_shutdown();
    return 0;
}

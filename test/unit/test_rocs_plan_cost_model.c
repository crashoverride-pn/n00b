/*
 * The cost model as a table of numbers.
 *
 * Every decision the executor makes about a scan reduces to one of these, and
 * none of them needs a shard. Exercising them directly is what separates "the
 * policy is wrong" from "the query was slow", which a timing test cannot tell
 * apart.
 *
 * The cases that matter here are the boundaries and the overflow guards. A
 * cost model that answers wrongly at 2^63 candidates does not crash: it picks
 * the expensive plan and stays correct, so nothing else in the suite notices.
 */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/plan.h"
#include "internal/rocs/plan_ir.h"

#include "rocs_test_support.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

// A term the whole shard carries cannot narrow anything, but only a lossy scan
// may skip its walk on that basis.
static void
test_term_covers_shard(void)
{
    // Lossy, and the term is on every record.
    CHECK(n00b_plan_cost_term_covers_shard(true, 100, 100));
    CHECK(n00b_plan_cost_term_covers_shard(true, 101, 100));

    // Lossy, but the term leaves something out.
    CHECK(!n00b_plan_cost_term_covers_shard(true, 99, 100));

    // Exact scans never skip: reading records instead is more work.
    CHECK(!n00b_plan_cost_term_covers_shard(false, 100, 100));
    CHECK(!n00b_plan_cost_term_covers_shard(false, 101, 100));

    // An empty shard makes df >= record_count vacuously true, which would skip
    // every lossy scan on it.
    CHECK(!n00b_plan_cost_term_covers_shard(true, 0, 0));

    n00b_printf("  [PASS] a covering term is skipped only for a lossy scan");
}

static void
test_probe_possible(void)
{
    // 8 candidates in 4096 records: 8 * 12 steps = 96 < 4096.
    CHECK(n00b_plan_cost_probe_possible(8, 4096));

    // Half the shard is never worth probing.
    CHECK(!n00b_plan_cost_probe_possible(2048, 4096));

    // Degenerate counts.
    CHECK(!n00b_plan_cost_probe_possible(0, 4096));
    CHECK(!n00b_plan_cost_probe_possible(8, 0));

    // Overflow guard: candidates * steps must not wrap into a small number and
    // report a probe as cheap.
    CHECK(!n00b_plan_cost_probe_possible(UINT64_MAX, UINT64_MAX));
    CHECK(!n00b_plan_cost_probe_possible(UINT64_MAX / 2, UINT64_MAX));

    n00b_printf("  [PASS] probe screening holds at the boundaries");
}

static void
test_bitmap_walk(void)
{
    // A set that already holds its ordinals costs nothing to enumerate.
    CHECK(n00b_plan_cost_bitmap_walk(4096, true) == 0);

    // Otherwise it is one pass over the bitmap, a bit per record.
    CHECK(n00b_plan_cost_bitmap_walk(4096, false) == (4096 / 64) * 80);
    CHECK(n00b_plan_cost_bitmap_walk(0, false) == 0);

    n00b_printf("  [PASS] a cached set is free to enumerate");
}

#define HOT    false
#define MAPPED true

// Whether every term of the lookup answers membership by binary search. A
// sparse posting list that lost its order bit is scanned instead, at df steps
// where the model prices log2(df).
#define SEARCHABLE true
#define SCANNED    false

static void
test_probe_beats_walk(void)
{
    // 4 candidates against 100000 postings: cheap either way.
    CHECK(n00b_plan_cost_probe_beats_walk(100000, 4, 0, 1, HOT, SEARCHABLE));
    CHECK(n00b_plan_cost_probe_beats_walk(100000, 4, 0, 1, MAPPED, SEARCHABLE));

    // The same candidates against a term that is already tiny.
    CHECK(!n00b_plan_cost_probe_beats_walk(8, 4, 0, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(8, 4, 0, 1, MAPPED, SEARCHABLE));

    // Multi-term lookups pay a search per term, which can flip the verdict.
    CHECK(n00b_plan_cost_probe_beats_walk(100000, 100, 0, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(100000, 100, 0, 64, HOT, SEARCHABLE));

    // The bitmap walk is charged to the probe, and can flip it back.
    CHECK(n00b_plan_cost_probe_beats_walk(100000, 4, 1000, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(100000, 4, 9999999, 1, HOT, SEARCHABLE));

    // Degenerate counts never probe.
    CHECK(!n00b_plan_cost_probe_beats_walk(0, 4, 0, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(100000, 0, 0, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(100000, 4, 0, 0, HOT, SEARCHABLE));

    // Overflow guards, each on a different multiply.
    CHECK(!n00b_plan_cost_probe_beats_walk(UINT64_MAX, UINT64_MAX, 0, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(UINT64_MAX, 1, 0, UINT64_MAX, HOT, SEARCHABLE));

    n00b_printf("  [PASS] the crossover holds, including where it overflows");
}

// A list that has to be scanned costs df per candidate, not log2(df), so the
// arithmetic above describes work nobody does. The refusal has to hold at
// every input the searchable version accepts, including the ones where the
// margin looked widest: a wide term against a narrow candidate set is both the
// most attractive probe and the most expensive scan.
static void
test_a_scanned_list_is_never_probed(void)
{
    CHECK(n00b_plan_cost_probe_beats_walk(100000, 4, 0, 1, HOT, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(100000, 4, 0, 1, HOT, SCANNED));

    CHECK(n00b_plan_cost_probe_beats_walk(100000, 4, 0, 1, MAPPED, SEARCHABLE));
    CHECK(!n00b_plan_cost_probe_beats_walk(100000, 4, 0, 1, MAPPED, SCANNED));

    // Everything the searchable model says yes to, the scanned one says no to.
    for (uint64_t df = 2; df < 1000000; df *= 4) {
        for (uint64_t cand = 1; cand < df; cand *= 3) {
            CHECK(!n00b_plan_cost_probe_beats_walk(df, cand, 0, 1, HOT,
                                                   SCANNED));
            CHECK(!n00b_plan_cost_probe_beats_walk(df, cand, 0, 1, MAPPED,
                                                   SCANNED));
        }
    }

    n00b_printf("  [PASS] a list that must be scanned is never probed");
}

// The distinction the one-unit model could not make. A sealed image walks
// faster and searches slower, so there is a band where probing is right on a
// hot shard and wrong on a mapped one. Nothing expressed that before.
static void
test_residency_changes_the_crossover(void)
{
    CHECK(n00b_plan_cost_walk_step(MAPPED) < n00b_plan_cost_walk_step(HOT));
    CHECK(n00b_plan_cost_search_step(MAPPED) > n00b_plan_cost_search_step(HOT));

    // Search costs more than a walk step in both residencies, and the gap is
    // far wider once the pages are mapped.
    CHECK(n00b_plan_cost_search_step(HOT) > n00b_plan_cost_walk_step(HOT));
    CHECK(n00b_plan_cost_search_step(MAPPED)
          > 5 * n00b_plan_cost_walk_step(MAPPED));

    // Somewhere between the two verdicts there is a band that only one
    // residency probes. Find it rather than asserting a hand-picked number.
    bool found = false;
    for (uint64_t df = 16; df < 4096 && !found; df *= 2) {
        for (uint64_t cand = 1; cand < df; cand *= 2) {
            bool hot = n00b_plan_cost_probe_beats_walk(df, cand, 0, 1, HOT, SEARCHABLE);
            bool map = n00b_plan_cost_probe_beats_walk(df, cand, 0, 1, MAPPED, SEARCHABLE);
            if (hot && !map) {
                found = true;
                break;
            }
        }
    }
    CHECK(found);

    // And never the other way round: a mapped probe that a hot one declines
    // would mean the dearer search was being preferred.
    for (uint64_t df = 2; df < 100000; df *= 2) {
        for (uint64_t cand = 1; cand < df; cand *= 3) {
            if (n00b_plan_cost_probe_beats_walk(df, cand, 0, 1, MAPPED, SEARCHABLE)) {
                CHECK(n00b_plan_cost_probe_beats_walk(df, cand, 0, 1, HOT, SEARCHABLE));
            }
        }
    }

    n00b_printf("  [PASS] residency moves the crossover, and only one way");
}

// Ordering. `bound` is the child's estimated size; the second argument is what
// running it costs, which breaks ties between children of equal size.
static void
test_prefers(void)
{
    // With no standing pick, anything wins.
    CHECK(n00b_plan_cost_prefers(50, 50, 0, 0, false, false));
    CHECK(n00b_plan_cost_prefers(50, 50, 0, 0, true, false));

    // Intersect takes the narrowest, union the widest.
    CHECK(n00b_plan_cost_prefers(10, 10, 50, 50, false, true));
    CHECK(!n00b_plan_cost_prefers(90, 90, 50, 50, false, true));
    CHECK(n00b_plan_cost_prefers(90, 90, 50, 50, true, true));
    CHECK(!n00b_plan_cost_prefers(10, 10, 50, 50, true, true));

    // Equal sizes, so the cost decides. A complement is the case that needs
    // it: as wide as its child is narrow, but costing what that child costs.
    CHECK(n00b_plan_cost_prefers(50, 60, 50, 900, false, true));
    CHECK(!n00b_plan_cost_prefers(50, 900, 50, 60, false, true));
    CHECK(n00b_plan_cost_prefers(50, 900, 50, 60, true, true));

    // A genuine tie does not displace the standing pick, so ordering is
    // stable and plan order survives where the counts say nothing.
    CHECK(!n00b_plan_cost_prefers(50, 60, 50, 60, false, true));
    CHECK(!n00b_plan_cost_prefers(50, 60, 50, 60, true, true));

    n00b_printf("  [PASS] ordering prefers correctly and ties are stable");
}

// A complement holds what its child does not, so a selective child makes a
// broad complement. Without this the ordering reads a negated leaf as unknown
// and can lead an intersect with its widest operand.
static void
test_complement_df_inverts_its_child(void)
{
    // A child matching nothing complements to the whole shard.
    CHECK(n00b_plan_cost_complement_df(0, 1000) == 1000);
    // And one matching everything complements to nothing.
    CHECK(n00b_plan_cost_complement_df(1000, 1000) == 0);
    // A selective child is a broad complement, which is the whole point.
    CHECK(n00b_plan_cost_complement_df(1, 1000) == 999);
    CHECK(n00b_plan_cost_complement_df(999, 1000) == 1);

    // A child count above the shard's size clamps rather than wrapping. It
    // should not happen; underflowing to near UINT64_MAX would read as the
    // widest possible operand and invert every ordering it took part in.
    CHECK(n00b_plan_cost_complement_df(1001, 1000) == 0);
    CHECK(n00b_plan_cost_complement_df(UINT64_MAX, 1000) == 0);

    // An empty shard complements to nothing whatever the child says.
    CHECK(n00b_plan_cost_complement_df(0, 0) == 0);

    n00b_printf("  [PASS] a complement is as wide as its child is narrow");
}

// Composing sizes up a tree. Bounds rather than estimates: a bound that is too
// large orders conservatively, where an estimate that is too small orders a
// group ahead of things it does not actually narrow past.
static void
test_group_sizes_compose_as_bounds(void)
{
    // An intersection is no bigger than its smallest operand.
    CHECK(n00b_plan_cost_intersect_size(10, 1000) == 10);
    CHECK(n00b_plan_cost_intersect_size(1000, 10) == 10);
    CHECK(n00b_plan_cost_intersect_size(0, 1000) == 0);

    // Deliberately not the independence product, which would be 1 here and is
    // wrong the moment the two operands correlate.
    CHECK(n00b_plan_cost_intersect_size(100, 100) == 100);

    // A union is no bigger than the sum, and never bigger than the shard.
    CHECK(n00b_plan_cost_union_size(10, 20, 1000) == 30);
    CHECK(n00b_plan_cost_union_size(600, 600, 1000) == 1000);
    CHECK(n00b_plan_cost_union_size(0, 0, 1000) == 0);

    // Saturating: two counts near the maximum must not wrap to nearly nothing
    // and read as the narrowest operand in the group.
    CHECK(n00b_plan_cost_union_size(UINT64_MAX, UINT64_MAX, 1000) == 1000);
    CHECK(n00b_plan_cost_union_size(UINT64_MAX, 1, 1000) == 1000);

    n00b_printf("  [PASS] group sizes compose as bounds, not estimates");
}

// The switch is the one piece of state here, so the tests that flip it have to
// put it back.
static void
test_enable_switch(void)
{
    bool was = n00b_plan_cost_enabled();

    n00b_plan_cost_set_enabled(false);
    CHECK(!n00b_plan_cost_enabled());
    n00b_plan_cost_set_enabled(true);
    CHECK(n00b_plan_cost_enabled());

    n00b_plan_cost_set_enabled(was);
    CHECK(n00b_plan_cost_enabled() == was);

    n00b_printf("  [PASS] the cost switch round-trips");
}

// ---------------------------------------------------------------------------
// predicate cost
// ---------------------------------------------------------------------------

static n00b_plan_predicate_t *
eq_str(n00b_string_t *field, n00b_string_t *value)
{
    auto r = n00b_plan_predicate_eq(
        target(field),
        n00b_variant_set(n00b_plan_value_t,
                         n00b_json_node_t *,
                         n00b_json_string_new_from_n00b(value)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
eq_int(n00b_string_t *field, int64_t value)
{
    auto r = n00b_plan_predicate_eq(
        target(field),
        n00b_variant_set(n00b_plan_value_t,
                         n00b_json_node_t *,
                         n00b_json_int_new(value)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
regex_on(n00b_string_t *field, n00b_string_t *pattern)
{
    auto compiled_r = n00b_regex_new(pattern);
    CHECK(n00b_result_is_ok(compiled_r));
    auto r = n00b_plan_predicate_regex(target(field),
                                       n00b_result_get(compiled_r));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
exists_on(n00b_string_t *field)
{
    auto r = n00b_plan_predicate_exists(target(field));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
group_of(n00b_plan_predicate_t **kids, size_t n, bool conjunction)
{
    n00b_plan_predicate_list_t *list = n00b_plan_predicate_list_new();
    for (size_t i = 0; i < n; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(list, kids[i])));
    }
    auto r = conjunction ? n00b_plan_predicate_and(list)
                         : n00b_plan_predicate_or(list);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// The ordering this drives is only as good as the ratios. An integer compare
// and a regex over text counted the same before, which is the gap this closes.
static void
test_predicate_cost_ranks_by_work(void)
{
    uint64_t exists = n00b_plan_cost_predicate(exists_on(r"level"));
    uint64_t inteq  = n00b_plan_cost_predicate(eq_int(r"code", 500));
    uint64_t streq  = n00b_plan_cost_predicate(eq_str(r"level", r"error"));
    uint64_t rex    = n00b_plan_cost_predicate(regex_on(r"msg", r"^a.*z$"));

    // Presence is the floor, then a scalar compare, then a string, then a
    // regex by a wide margin.
    CHECK(exists < inteq);
    CHECK(inteq < streq);
    CHECK(streq < rex);
    CHECK(rex > streq * 5);

    // A null predicate has no cost rather than an undefined one.
    CHECK(n00b_plan_cost_predicate(nullptr) == 0);

    n00b_printf("  [PASS] predicate cost ranks presence < int < string < regex");
}

static void
test_group_cost_sums_children(void)
{
    n00b_plan_predicate_t *kids[2] = {eq_int(r"code", 500),
                                      regex_on(r"msg", r"^a.*z$")};
    uint64_t a = n00b_plan_cost_predicate(kids[0]);
    uint64_t b = n00b_plan_cost_predicate(kids[1]);

    // A group costs what evaluating it costs, not what its cheapest child
    // costs: short-circuiting is what the ordering is for, not an assumption
    // the cost is allowed to bake in.
    CHECK(n00b_plan_cost_predicate(group_of(kids, 2, true)) == a + b);
    CHECK(n00b_plan_cost_predicate(group_of(kids, 2, false)) == a + b);

    n00b_printf("  [PASS] a group costs the sum of its children");
}

static void
test_order_children_is_cheapest_first_and_stable(void)
{
    uint16_t order[8];

    // Written expensive-first, so plan order and cost order disagree.
    n00b_plan_predicate_t *kids[3] = {regex_on(r"msg", r"^a.*z$"),
                                      eq_str(r"level", r"error"),
                                      eq_int(r"code", 500)};
    n00b_plan_predicate_t *conj    = group_of(kids, 3, true);

    CHECK(n00b_plan_cost_order_children(conj, order, 8) == 3);
    CHECK(order[0] == 2);
    CHECK(order[1] == 1);
    CHECK(order[2] == 0);

    // Equal cost keeps the written order, so ordering never reshuffles
    // children the model cannot tell apart.
    n00b_plan_predicate_t *same[3] = {eq_int(r"a", 1),
                                      eq_int(r"b", 2),
                                      eq_int(r"c", 3)};
    CHECK(n00b_plan_cost_order_children(group_of(same, 3, true), order, 8) == 3);
    CHECK(order[0] == 0 && order[1] == 1 && order[2] == 2);

    // A group larger than the caller's buffer declines rather than truncating,
    // and the caller falls back to plan order.
    CHECK(n00b_plan_cost_order_children(conj, order, 2) == 0);

    // A leaf has no children to order.
    CHECK(n00b_plan_cost_order_children(kids[0], order, 8) == 0);
    CHECK(n00b_plan_cost_order_children(nullptr, order, 8) == 0);

    n00b_printf("  [PASS] children order cheapest-first, stable on ties");
}

// Index selection is the planner's alone, so it is worth pinning down what it
// promises. The advert table gives every (kind, op) pair a fixed hint, so two
// indexes of the same kind on the same field always tie: selection is by kind
// and field, and the tiebreak is list order. Nothing here discriminates
// between two term indexes on "level", and a caller expecting it to is wrong.
static n00b_store_index_t *
model_index(n00b_string_t *field, n00b_store_index_kind_t kind)
{
    auto r = n00b_store_index_new(field, kind);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_index_list_t *
model_list(n00b_store_index_t **items, size_t len)
{
    n00b_plan_index_list_t *list = n00b_plan_index_list_new();
    for (size_t i = 0; i < len; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_index_list_append(list, items[i])));
    }
    return list;
}

static void
test_choose_index_matches_field_kind_and_op(void)
{
    n00b_store_index_t *level    = model_index(r"level", N00B_STORE_INDEX_TERM);
    n00b_store_index_t *fulltext = model_index(r"message",
                                               N00B_STORE_INDEX_FULLTEXT);
    n00b_store_index_t *ngram    = model_index(r"message",
                                               N00B_STORE_INDEX_NGRAM);

    n00b_store_index_t     *all[] = {level, fulltext, ngram};
    n00b_plan_index_list_t *list  = model_list(all, 3);

    // Each accelerator is reachable by its own field, kind, and operator.
    CHECK(_rocs_plan_choose_index(list, r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == level);
    CHECK(_rocs_plan_choose_index(list, r"message",
                                  N00B_STORE_INDEX_OP_CONTAINS,
                                  N00B_STORE_INDEX_FULLTEXT)
          == fulltext);
    CHECK(_rocs_plan_choose_index(list, r"message",
                                  N00B_STORE_INDEX_OP_PREFIX,
                                  N00B_STORE_INDEX_NGRAM)
          == ngram);

    // A term index answers an unspecified operator; the text kinds do not.
    CHECK(_rocs_plan_choose_index(list, r"level",
                                  N00B_STORE_INDEX_OP_UNSPECIFIED,
                                  N00B_STORE_INDEX_TERM)
          == level);
    CHECK(_rocs_plan_choose_index(list, r"message",
                                  N00B_STORE_INDEX_OP_UNSPECIFIED,
                                  N00B_STORE_INDEX_FULLTEXT)
          == nullptr);

    // Right field, wrong kind for the operator asked about.
    CHECK(_rocs_plan_choose_index(list, r"message",
                                  N00B_STORE_INDEX_OP_CONTAINS,
                                  N00B_STORE_INDEX_NGRAM)
          == nullptr);
    CHECK(_rocs_plan_choose_index(list, r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_FULLTEXT)
          == nullptr);

    // A field nothing covers, and the argument guards.
    CHECK(_rocs_plan_choose_index(list, r"absent",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == nullptr);
    CHECK(_rocs_plan_choose_index(nullptr, r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == nullptr);
    CHECK(_rocs_plan_choose_index(list, nullptr,
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == nullptr);
}

// Two indexes that both serve the query. They advertise the same hint, so the
// choice is list order, and it does not drift with list length or position.
static void
test_choose_index_breaks_ties_by_list_order(void)
{
    n00b_store_index_t *first  = model_index(r"level", N00B_STORE_INDEX_TERM);
    n00b_store_index_t *second = model_index(r"level", N00B_STORE_INDEX_TERM);

    n00b_store_index_t     *forward[]  = {first, second};
    n00b_store_index_t     *backward[] = {second, first};

    CHECK(_rocs_plan_choose_index(model_list(forward, 2), r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == first);
    CHECK(_rocs_plan_choose_index(model_list(backward, 2), r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == second);

    // A non-matching index ahead of both does not become the answer.
    n00b_store_index_t *other = model_index(r"trace", N00B_STORE_INDEX_TERM);
    n00b_store_index_t *led[] = {other, first, second};
    CHECK(_rocs_plan_choose_index(model_list(led, 3), r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == first);

    // An empty list has nothing to offer.
    CHECK(_rocs_plan_choose_index(n00b_plan_index_list_new(), r"level",
                                  N00B_STORE_INDEX_OP_EQ,
                                  N00B_STORE_INDEX_TERM)
          == nullptr);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    n00b_printf("cost model:");
    test_term_covers_shard();
    test_probe_possible();
    test_bitmap_walk();
    test_probe_beats_walk();
    test_a_scanned_list_is_never_probed();
    test_residency_changes_the_crossover();
    test_prefers();
    test_complement_df_inverts_its_child();
    test_group_sizes_compose_as_bounds();
    test_enable_switch();
    test_predicate_cost_ranks_by_work();
    test_group_cost_sums_children();
    test_order_children_is_cheapest_first_and_stable();
    test_choose_index_matches_field_kind_and_op();
    test_choose_index_breaks_ties_by_list_order();
    n00b_printf("all cost-model cases pass");

    n00b_shutdown();
    return 0;
}

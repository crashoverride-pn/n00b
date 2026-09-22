/* test/unit/test_rocs_plan_rewrite.c - predicate rewriting.
 *
 * The oracle (test_rocs_plan_oracle) already proves the rewrite does not
 * change answers, by planning through it and comparing against a reference
 * built with .rewrite = false. What it cannot prove is that any rewrite
 * happened: a pass that returned its input unchanged would satisfy it
 * completely. These check the other half, that each rule fires and produces
 * the shape it claims.
 */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/plan_ir.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_predicate_t *predicate = n00b_result_get(r);
    CHECK(predicate != nullptr);
    return predicate;
}

static n00b_plan_target_t *
field(n00b_string_t *name)
{
    auto r = n00b_plan_target_field(name);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_value_t
num(int64_t value)
{
    return json_value(n00b_json_int_new(value));
}

static n00b_plan_predicate_t *
eq(n00b_string_t *name, int64_t value)
{
    return predicate_ok(n00b_plan_predicate_eq(field(name), num(value)));
}

static n00b_plan_predicate_t *
range(n00b_string_t *name, int64_t lower, int64_t upper)
{
    return predicate_ok(n00b_plan_predicate_range(field(name),
                                                  num(lower),
                                                  num(upper)));
}

// A range with the bounds spelled out. `range` above takes the closed
// defaults, which never reach the inclusivity arms of the merge rules.
static n00b_plan_predicate_t *
range_x(n00b_string_t *name,
        int64_t        lower,
        bool           include_lower,
        int64_t        upper,
        bool           include_upper)
{
    return predicate_ok(
        n00b_plan_predicate_range(field(name),
                                  num(lower),
                                  num(upper),
                                  .include_lower = include_lower,
                                  .include_upper = include_upper));
}

static n00b_plan_predicate_t *
exists(n00b_string_t *name)
{
    return predicate_ok(n00b_plan_predicate_exists(field(name)));
}

static n00b_plan_predicate_t *
contains(n00b_string_t *name, n00b_string_t *term)
{
    return predicate_ok(n00b_plan_predicate_contains(field(name), term));
}

static n00b_plan_predicate_t *
prefix(n00b_string_t *name, n00b_string_t *text)
{
    return predicate_ok(n00b_plan_predicate_prefix(field(name), text));
}

static n00b_plan_predicate_t *
substring(n00b_string_t *name, n00b_string_t *text)
{
    return predicate_ok(n00b_plan_predicate_substring(field(name), text));
}

// An IN leaf over the values given, in the order given.
static n00b_plan_predicate_t *
in_of(n00b_string_t *name, const int64_t *values, size_t count)
{
    n00b_plan_value_list_t *list = n00b_plan_value_list_new();
    for (size_t i = 0; i < count; i++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_value_list_append(list, num(values[i]))));
    }
    return predicate_ok(n00b_plan_predicate_in(field(name), list));
}

// An UNDER leaf over a single object key.
static n00b_plan_predicate_t *
under(n00b_string_t *name, n00b_string_t *key)
{
    n00b_plan_path_component_list_t *parts = n00b_plan_path_component_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_path_component_list_append_key(parts, key)));
    auto path_r = n00b_plan_path_new(parts);
    CHECK(n00b_result_is_ok(path_r));
    return predicate_ok(
        n00b_plan_predicate_under(field(name), n00b_result_get(path_r)));
}

static n00b_plan_predicate_t *
negate(n00b_plan_predicate_t *child)
{
    return predicate_ok(n00b_plan_predicate_not(child));
}

// A group of exactly the predicates passed, in order.
static n00b_plan_predicate_t *
group(bool conjunction, n00b_plan_predicate_t **members, size_t count)
{
    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    for (size_t i = 0; i < count; i++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(children, members[i])));
    }
    return predicate_ok(conjunction
                            ? n00b_plan_predicate_and(children)
                            : n00b_plan_predicate_or(children));
}

#define AND(...)                                                               \
    group(true,                                                                \
          (n00b_plan_predicate_t *[]){__VA_ARGS__},                            \
          sizeof((n00b_plan_predicate_t *[]){__VA_ARGS__})                     \
              / sizeof(n00b_plan_predicate_t *))

#define OR(...)                                                                \
    group(false,                                                               \
          (n00b_plan_predicate_t *[]){__VA_ARGS__},                            \
          sizeof((n00b_plan_predicate_t *[]){__VA_ARGS__})                     \
              / sizeof(n00b_plan_predicate_t *))

static n00b_plan_predicate_t *
rewrite(n00b_plan_predicate_t *predicate)
{
    return predicate_ok(n00b_plan_rewrite(predicate));
}

static n00b_plan_predicate_kind_t
kind_of(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_kind(predicate);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static uint64_t
child_count(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_child_count(predicate);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
child_at(n00b_plan_predicate_t *predicate, uint64_t i)
{
    auto r = n00b_plan_predicate_child_at(predicate, i);
    CHECK(n00b_result_is_ok(r));
    auto opt = n00b_result_get(r);
    CHECK(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static n00b_plan_leaf_op_t
leaf_op(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_leaf_op(predicate);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static int64_t
lower_of(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_range_lower(predicate);
    CHECK(n00b_result_is_ok(r));
    n00b_plan_value_t v = n00b_option_get(n00b_result_get(r));
    return n00b_json_as_i64(n00b_variant_get(v, n00b_json_node_t *));
}

static int64_t
upper_of(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_range_upper(predicate);
    CHECK(n00b_result_is_ok(r));
    n00b_plan_value_t v = n00b_option_get(n00b_result_get(r));
    return n00b_json_as_i64(n00b_variant_get(v, n00b_json_node_t *));
}

static bool
incl_lower(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_range_include_lower(predicate);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static bool
incl_upper(n00b_plan_predicate_t *predicate)
{
    auto r = n00b_plan_predicate_range_include_upper(predicate);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// ---------------------------------------------------------------------------

static void
test_flatten_and_absorb(void)
{
    // AND(a, AND(b, c)) -> AND(a, b, c), one group of three.
    n00b_plan_predicate_t *nested = AND(exists(r"a"),
                                        AND(exists(r"b"), exists(r"c")));
    n00b_plan_predicate_t *flat   = rewrite(nested);
    CHECK(kind_of(flat) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(flat) == 3);

    // A FALSE operand ends a conjunction outright.
    auto false_p = n00b_plan_predicate_false();
    CHECK(n00b_result_is_ok(false_p));
    n00b_plan_predicate_t *dead = rewrite(AND(exists(r"a"),
                                              n00b_result_get(false_p)));
    CHECK(kind_of(dead) == N00B_PLAN_PREDICATE_FALSE);

    // ... and passes straight through a disjunction, leaving one operand,
    // which is then not a group at all.
    auto false_q = n00b_plan_predicate_false();
    CHECK(n00b_result_is_ok(false_q));
    n00b_plan_predicate_t *lone = rewrite(OR(exists(r"a"),
                                             n00b_result_get(false_q)));
    CHECK(kind_of(lone) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(lone) == N00B_PLAN_LEAF_EXISTS);
}

static void
test_dedupe_and_contradiction(void)
{
    // The same leaf written twice reads one posting list, not two.
    n00b_plan_predicate_t *twice = rewrite(AND(eq(r"level", 1),
                                               exists(r"msg"),
                                               eq(r"level", 1)));
    CHECK(kind_of(twice) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(twice) == 2);

    // a AND NOT a matches nothing, and FALSE is how the vocabulary says so.
    n00b_plan_predicate_t *never = rewrite(AND(eq(r"level", 1),
                                               negate(eq(r"level", 1))));
    CHECK(kind_of(never) == N00B_PLAN_PREDICATE_FALSE);

    // a OR NOT a matches everything. This is the half that needed TRUE added.
    n00b_plan_predicate_t *always = rewrite(OR(eq(r"level", 1),
                                               negate(eq(r"level", 1))));
    CHECK(kind_of(always) == N00B_PLAN_PREDICATE_TRUE);

    // NOT(NOT a) is a.
    n00b_plan_predicate_t *doubled = rewrite(negate(negate(eq(r"level", 1))));
    CHECK(kind_of(doubled) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(doubled) == N00B_PLAN_LEAF_EQ);
}

static void
test_range_merge(void)
{
    // Two ranges on one field are one range: [3,9] AND [5,20] is [5,9].
    n00b_plan_predicate_t *merged = rewrite(AND(range(r"ts", 3, 9),
                                                range(r"ts", 5, 20)));
    CHECK(kind_of(merged) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(merged) == N00B_PLAN_LEAF_RANGE);

    auto lower_r = n00b_plan_predicate_range_lower(merged);
    auto upper_r = n00b_plan_predicate_range_upper(merged);
    CHECK(n00b_result_is_ok(lower_r) && n00b_result_is_ok(upper_r));
    n00b_plan_value_t lower = n00b_option_get(n00b_result_get(lower_r));
    n00b_plan_value_t upper = n00b_option_get(n00b_result_get(upper_r));
    CHECK(n00b_json_as_i64(n00b_variant_get(lower, n00b_json_node_t *)) == 5);
    CHECK(n00b_json_as_i64(n00b_variant_get(upper, n00b_json_node_t *)) == 9);

    // Disjoint ranges on one field cannot both hold.
    n00b_plan_predicate_t *empty = rewrite(AND(range(r"ts", 1, 2),
                                               range(r"ts", 8, 9)));
    CHECK(kind_of(empty) == N00B_PLAN_PREDICATE_FALSE);

    // Ranges on different fields stay two leaves; nothing merges across them.
    n00b_plan_predicate_t *apart = rewrite(AND(range(r"ts", 1, 2),
                                               range(r"size", 8, 9)));
    CHECK(kind_of(apart) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(apart) == 2);

    // An equality outside a range on the same field is a contradiction; one
    // inside it makes the range redundant.
    CHECK(kind_of(rewrite(AND(eq(r"ts", 40), range(r"ts", 1, 9))))
          == N00B_PLAN_PREDICATE_FALSE);

    n00b_plan_predicate_t *inside = rewrite(AND(eq(r"ts", 4),
                                                range(r"ts", 1, 9)));
    CHECK(kind_of(inside) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(inside) == N00B_PLAN_LEAF_EQ);

    // Two different equalities on one field, likewise.
    CHECK(kind_of(rewrite(AND(eq(r"level", 1), eq(r"level", 2))))
          == N00B_PLAN_PREDICATE_FALSE);
}

static void
test_incomparable_bounds_fold_nothing(void)
{
    // A string equality against a numeric range. The two have no order
    // between them, so nothing is proven: the conjunction is not provably
    // empty here, and the range is certainly not implied by the equality.
    //
    // Dropping the range on a comparison that did not happen is the failure
    // this guards. `ts = "abc"` alone matches a record the original rejected,
    // because a record whose ts is a string satisfies no numeric range.
    n00b_plan_predicate_t *mixed =
        AND(predicate_ok(
                n00b_plan_predicate_eq(
                    field(r"ts"),
                    json_value(n00b_json_string_new_from_n00b(r"abc")))),
            range(r"ts", 1, 9));

    n00b_plan_predicate_t *out = rewrite(mixed);
    CHECK(kind_of(out) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(out) == 2);

    // Two ranges that cannot be ordered against each other stay two ranges
    // rather than merging into bounds no comparison produced.
    n00b_plan_predicate_t *both =
        AND(range(r"ts", 1, 9),
            predicate_ok(n00b_plan_predicate_range(
                field(r"ts"),
                json_value(n00b_json_string_new_from_n00b(r"a")),
                json_value(n00b_json_string_new_from_n00b(r"z")))));
    n00b_plan_predicate_t *kept = rewrite(both);
    CHECK(kind_of(kept) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(kept) == 2);
}

static void
test_or_of_ranges_merges_when_they_meet(void)
{
    // Overlapping windows over one field are one window.
    n00b_plan_predicate_t *merged = rewrite(OR(range(r"ts", 1, 5),
                                               range(r"ts", 3, 9)));
    CHECK(kind_of(merged) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(merged) == N00B_PLAN_LEAF_RANGE);
    n00b_plan_value_t ulo = n00b_option_get(
        n00b_result_get(n00b_plan_predicate_range_lower(merged)));
    n00b_plan_value_t uhi = n00b_option_get(
        n00b_result_get(n00b_plan_predicate_range_upper(merged)));
    CHECK(n00b_json_as_i64(n00b_variant_get(ulo, n00b_json_node_t *)) == 1);
    CHECK(n00b_json_as_i64(n00b_variant_get(uhi, n00b_json_node_t *)) == 9);

    // Disjoint windows are not one window. Merging them would admit every
    // value in the gap, which is the one way this rule could lose the plot.
    n00b_plan_predicate_t *apart = rewrite(OR(range(r"ts", 1, 2),
                                              range(r"ts", 8, 9)));
    CHECK(kind_of(apart) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(apart) == 2);

    // Touching windows leave no gap, so they do merge.
    n00b_plan_predicate_t *touching = rewrite(OR(range(r"ts", 1, 5),
                                                 range(r"ts", 5, 9)));
    CHECK(kind_of(touching) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(touching) == N00B_PLAN_LEAF_RANGE);

    // Three windows where the middle one joins the outer two: the merge has
    // to keep going after the first join rather than stopping at one pass.
    n00b_plan_predicate_t *chained = rewrite(OR(range(r"ts", 1, 3),
                                                range(r"ts", 7, 9),
                                                range(r"ts", 2, 8)));
    CHECK(kind_of(chained) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(chained) == N00B_PLAN_LEAF_RANGE);

    // Different fields never merge.
    n00b_plan_predicate_t *fields = rewrite(OR(range(r"ts", 1, 5),
                                               range(r"size", 3, 9)));
    CHECK(kind_of(fields) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(fields) == 2);
}

static void
test_or_of_equalities_collapses_to_in(void)
{
    // This is the fan-out asymmetry. Written as a disjunction, the equality
    // list reached the planner as a union of any width; written as IN, the
    // same list was capped at ROCS_PLAN_IN_FANOUT_MAX. After collapsing there
    // is one spelling, so there is one cap.
    n00b_plan_predicate_t *collapsed = rewrite(OR(eq(r"level", 1),
                                                  eq(r"level", 2),
                                                  eq(r"level", 3)));
    CHECK(kind_of(collapsed) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(collapsed) == N00B_PLAN_LEAF_IN);

    auto values_r = n00b_plan_predicate_values(collapsed);
    CHECK(n00b_result_is_ok(values_r));
    n00b_plan_value_list_t *values =
        n00b_option_get(n00b_result_get(values_r));
    CHECK(n00b_list_len(*values) == 3);

    // Equalities on different fields are not one IN.
    n00b_plan_predicate_t *mixed = rewrite(OR(eq(r"level", 1),
                                              eq(r"code", 2)));
    CHECK(kind_of(mixed) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(mixed) == 2);

    // A field named once stays an equality rather than becoming a one-value
    // IN, which would be the same read through an extra node.
    n00b_plan_predicate_t *single = rewrite(OR(eq(r"level", 1),
                                               eq(r"code", 2),
                                               eq(r"code", 3)));
    CHECK(kind_of(single) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(single) == 2);
    CHECK(leaf_op(child_at(single, 0)) == N00B_PLAN_LEAF_EQ);
    CHECK(leaf_op(child_at(single, 1)) == N00B_PLAN_LEAF_IN);
}

static void
test_factoring(void)
{
    // (a AND b) OR (a AND c) -> a AND (b OR c). The distributed form runs `a`
    // against the whole shard twice; the factored form runs it once and `b OR
    // c` sees only what it selected.
    n00b_plan_predicate_t *factored =
        rewrite(OR(AND(eq(r"tenant", 7), exists(r"b")),
                   AND(eq(r"tenant", 7), exists(r"c"))));

    CHECK(kind_of(factored) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(factored) == 2);
    CHECK(leaf_op(child_at(factored, 0)) == N00B_PLAN_LEAF_EQ);

    n00b_plan_predicate_t *residual = child_at(factored, 1);
    CHECK(kind_of(residual) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(residual) == 2);

    // Nothing shared by every branch, nothing hoisted.
    n00b_plan_predicate_t *unfactored =
        rewrite(OR(AND(eq(r"tenant", 7), exists(r"b")),
                   AND(eq(r"tenant", 8), exists(r"c"))));
    CHECK(kind_of(unfactored) == N00B_PLAN_PREDICATE_OR);

    // (a AND b) OR a is a: the residual of the second branch is empty, so the
    // disjunction is TRUE and only the hoisted conjunct remains. Absorption
    // falls out of factoring rather than being a rule of its own.
    n00b_plan_predicate_t *absorbed =
        rewrite(OR(AND(eq(r"tenant", 7), exists(r"b")), eq(r"tenant", 7)));
    CHECK(kind_of(absorbed) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(absorbed) == N00B_PLAN_LEAF_EQ);
}

static void
test_commuted_operands_are_one_condition(void)
{
    // AND and OR commute, so these are the same condition twice. Before the
    // operands were put in a fixed order the comparison was positional and
    // called them different, so nothing deduped and nothing factored.
    n00b_plan_predicate_t *commuted =
        rewrite(AND(AND(eq(r"level", 1), exists(r"a")),
                    AND(exists(r"a"), eq(r"level", 1))));
    CHECK(kind_of(commuted) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(commuted) == 2);

    // Two spellings of one query are recognized as one condition, and each
    // keeps the operand order it was written in. The recognition is what the
    // rewriter needs; reordering the query is not its business, and the
    // planner's own ordering is documented to leave operands a count cannot
    // separate where the caller put them.
    n00b_plan_predicate_t *one = rewrite(AND(exists(r"b"),
                                             eq(r"level", 1),
                                             exists(r"a")));
    n00b_plan_predicate_t *two = rewrite(AND(exists(r"a"),
                                             exists(r"b"),
                                             eq(r"level", 1)));
    CHECK(child_count(one) == 3);
    CHECK(child_count(two) == 3);
    CHECK(leaf_op(child_at(one, 0)) == N00B_PLAN_LEAF_EXISTS);
    CHECK(leaf_op(child_at(one, 1)) == N00B_PLAN_LEAF_EQ);
    CHECK(leaf_op(child_at(two, 0)) == N00B_PLAN_LEAF_EXISTS);
    CHECK(leaf_op(child_at(two, 2)) == N00B_PLAN_LEAF_EQ);

    // Nesting one inside the other collapses, which is the recognition the
    // order-insensitive comparison buys: the inner group is the outer group's
    // operands in a different order.
    n00b_plan_predicate_t *nested =
        rewrite(AND(AND(exists(r"b"), eq(r"level", 1), exists(r"a")),
                    AND(exists(r"a"), exists(r"b"), eq(r"level", 1))));
    CHECK(kind_of(nested) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(nested) == 3);

    // Commuted branches factor, which they could not before: the shared
    // conjunct sits in a different position in each branch.
    n00b_plan_predicate_t *factored =
        rewrite(OR(AND(eq(r"tenant", 7), exists(r"b")),
                   AND(exists(r"c"), eq(r"tenant", 7))));
    CHECK(kind_of(factored) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(factored) == 2);

    // And a commuted contradiction is still a contradiction.
    CHECK(kind_of(rewrite(AND(AND(eq(r"level", 1), exists(r"a")),
                              negate(AND(exists(r"a"), eq(r"level", 1))))))
          == N00B_PLAN_PREDICATE_FALSE);
}

static void
test_regex_dedupes_by_program(void)
{
    // Separately compiled, same source: one predicate, so one of them goes.
    auto a_r = n00b_regex_new(r"tim.*ut");
    auto b_r = n00b_regex_new(r"tim.*ut");
    CHECK(n00b_result_is_ok(a_r) && n00b_result_is_ok(b_r));
    CHECK(n00b_result_get(a_r) != n00b_result_get(b_r));

    n00b_plan_predicate_t *same = rewrite(AND(
        predicate_ok(n00b_plan_predicate_regex(field(r"msg"),
                                               n00b_result_get(a_r))),
        predicate_ok(n00b_plan_predicate_regex(field(r"msg"),
                                               n00b_result_get(b_r)))));
    CHECK(kind_of(same) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(same) == N00B_PLAN_LEAF_REGEX);

    // Same source, different options: two predicates matching different
    // records, so both stay. Deduping here would drop records.
    auto plain_r = n00b_regex_new(r"tim.*ut");
    auto fold_r  = n00b_regex_new(r"tim.*ut", .case_insensitive = true);
    CHECK(n00b_result_is_ok(plain_r) && n00b_result_is_ok(fold_r));

    n00b_plan_predicate_t *differing = rewrite(AND(
        predicate_ok(n00b_plan_predicate_regex(field(r"msg"),
                                               n00b_result_get(plain_r))),
        predicate_ok(n00b_plan_predicate_regex(field(r"msg"),
                                               n00b_result_get(fold_r)))));
    CHECK(kind_of(differing) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(differing) == 2);
}

static void
test_partial_factoring(void)
{
    // Shared by two of three branches. Nothing is common to all three, so the
    // full hoist declines and `a` ran once per branch that names it against
    // the whole shard. Hoisting over just those two runs it once.
    n00b_plan_predicate_t *partial =
        rewrite(OR(AND(eq(r"tenant", 7), exists(r"b")),
                   AND(eq(r"tenant", 7), exists(r"c")),
                   AND(eq(r"other", 9), exists(r"d"))));

    CHECK(kind_of(partial) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(partial) == 2);

    // One branch is the untouched odd one out, the other is the hoist. Which
    // sits where is the canonical order's business, so find rather than
    // assume.
    uint64_t hoists    = 0;
    uint64_t untouched = 0;
    for (uint64_t i = 0; i < 2; i++) {
        n00b_plan_predicate_t *branch = child_at(partial, i);
        CHECK(kind_of(branch) == N00B_PLAN_PREDICATE_AND);
        CHECK(child_count(branch) == 2);

        // The hoisted branch carries the shared equality beside a
        // disjunction of what was left of the two branches; the untouched one
        // is two leaves. Counted per branch rather than latched across both,
        // so this says "one of each" whichever position they land in.
        bool is_hoist = false;
        for (uint64_t j = 0; j < 2; j++) {
            if (kind_of(child_at(branch, j)) == N00B_PLAN_PREDICATE_OR) {
                is_hoist = true;
            }
        }
        if (is_hoist) {
            hoists++;
        }
        else {
            untouched++;
        }
    }
    CHECK(hoists == 1);
    CHECK(untouched == 1);

    // Nothing shared by two or more: left alone.
    n00b_plan_predicate_t *nothing =
        rewrite(OR(AND(eq(r"tenant", 1), exists(r"b")),
                   AND(eq(r"tenant", 2), exists(r"c")),
                   AND(eq(r"tenant", 3), exists(r"d"))));
    CHECK(kind_of(nothing) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(nothing) == 3);
}

// Every other case here builds closed intervals, which is what the range
// helpers default to. An open bound is the only thing that reaches the
// inclusivity arms of intersection, union and emptiness, and those are the
// places where a merge can quietly start or stop matching one exact value.
static void
test_exclusive_bounds(void)
{
    // Intersecting at a shared endpoint both sides admit leaves that point.
    n00b_plan_predicate_t *point = rewrite(
        AND(range(r"ts", 1, 5), range_x(r"ts", 5, true, 9, false)));
    CHECK(leaf_op(point) == N00B_PLAN_LEAF_RANGE);
    CHECK(lower_of(point) == 5 && upper_of(point) == 5);
    CHECK(incl_lower(point) && incl_upper(point));

    // The same pair with the left interval open at 5 shares nothing.
    CHECK(kind_of(rewrite(AND(range_x(r"ts", 1, true, 5, false),
                              range(r"ts", 5, 9))))
          == N00B_PLAN_PREDICATE_FALSE);

    // Equal bounds keep the stricter side: excluded on either side is
    // excluded from the intersection.
    n00b_plan_predicate_t *strict = rewrite(
        AND(range(r"ts", 1, 9), range_x(r"ts", 1, false, 9, false)));
    CHECK(leaf_op(strict) == N00B_PLAN_LEAF_RANGE);
    CHECK(lower_of(strict) == 1 && upper_of(strict) == 9);
    CHECK(!incl_lower(strict) && !incl_upper(strict));

    // A range whose bounds are equal and whose upper is open admits nothing,
    // with no second range to merge it against.
    CHECK(kind_of(rewrite(AND(range_x(r"ts", 5, true, 5, false),
                              exists(r"a"))))
          == N00B_PLAN_PREDICATE_FALSE);

    // Union: [1,5) and (5,9] touch at 5 and neither admits it, so their
    // union has a hole there and is not one range. The bounds meeting is
    // exactly what makes this the case the merge could get wrong.
    n00b_plan_predicate_t *hole = rewrite(
        OR(range_x(r"ts", 1, true, 5, false), range_x(r"ts", 5, false, 9, true)));
    CHECK(kind_of(hole) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(hole) == 2);

    // One side admitting the shared point closes it.
    n00b_plan_predicate_t *joined = rewrite(
        OR(range(r"ts", 1, 5), range_x(r"ts", 5, false, 9, true)));
    CHECK(leaf_op(joined) == N00B_PLAN_LEAF_RANGE);
    CHECK(lower_of(joined) == 1 && upper_of(joined) == 9);
    CHECK(incl_lower(joined) && incl_upper(joined));

    // Equal bounds in a union keep the looser side, which is the mirror of
    // the intersection rule above.
    n00b_plan_predicate_t *loose = rewrite(
        OR(range_x(r"ts", 1, false, 9, false), range(r"ts", 1, 9)));
    CHECK(leaf_op(loose) == N00B_PLAN_LEAF_RANGE);
    CHECK(incl_lower(loose) && incl_upper(loose));

    // An equality sitting on an excluded endpoint is outside the range, so
    // the conjunction is empty rather than the equality alone.
    CHECK(kind_of(rewrite(AND(eq(r"ts", 9), range_x(r"ts", 1, true, 9, false))))
          == N00B_PLAN_PREDICATE_FALSE);
    CHECK(kind_of(rewrite(AND(eq(r"ts", 1), range_x(r"ts", 1, false, 9, true))))
          == N00B_PLAN_PREDICATE_FALSE);

    // And one strictly inside still makes the range redundant.
    CHECK(leaf_op(rewrite(AND(eq(r"ts", 8), range_x(r"ts", 1, true, 9, false))))
          == N00B_PLAN_LEAF_EQ);

    // Two ranges that differ only in a bound's inclusivity are not the same
    // leaf, so nothing dedupes them out from under the merge.
    n00b_plan_predicate_t *differing = rewrite(
        OR(range_x(r"ts", 1, true, 9, true), range_x(r"ts", 1, true, 9, false)));
    CHECK(leaf_op(differing) == N00B_PLAN_LEAF_RANGE);
    CHECK(incl_upper(differing));
}

// Ints and doubles order against each other, which the interpreter relies on
// for a range and which the folds therefore have to match.
static void
test_mixed_numeric_bounds(void)
{
    n00b_plan_value_t half = json_value(n00b_json_double_new(4.5));

    // 4.5 falls inside [1, 9], so the range drops out and the equality stays.
    n00b_plan_predicate_t *inside = rewrite(
        AND(predicate_ok(n00b_plan_predicate_eq(field(r"ts"), half)),
            range(r"ts", 1, 9)));
    CHECK(leaf_op(inside) == N00B_PLAN_LEAF_EQ);

    // And outside it the conjunction is empty.
    CHECK(kind_of(rewrite(
              AND(predicate_ok(n00b_plan_predicate_eq(field(r"ts"), half)),
                  range(r"ts", 10, 20))))
          == N00B_PLAN_PREDICATE_FALSE);

    // A double bound and an int bound merge, because the comparison the
    // rewriter uses is the one the interpreter uses.
    n00b_plan_predicate_t *merged = rewrite(
        AND(range(r"ts", 1, 9),
            predicate_ok(n00b_plan_predicate_range(
                field(r"ts"),
                json_value(n00b_json_double_new(4.5)),
                json_value(n00b_json_double_new(20.5))))));
    CHECK(leaf_op(merged) == N00B_PLAN_LEAF_RANGE);
    CHECK(upper_of(merged) == 9);

    // An int equality against a double of the same magnitude is a different
    // value, because equality is typed where ordering is not. Both leaves
    // stay: nothing here may decide that 1 and 1.0 are one condition.
    n00b_plan_predicate_t *typed = rewrite(
        AND(eq(r"ts", 1),
            predicate_ok(n00b_plan_predicate_eq(
                field(r"ts"),
                json_value(n00b_json_double_new(1.0))))));
    CHECK(kind_of(typed) == N00B_PLAN_PREDICATE_FALSE);
}

// The leaf kinds whose equality has an arm of its own in the rewriter. Each
// one decides whether a dedupe fires, and a wrong answer in the true
// direction drops a leaf that matches different records.
static void
test_leaf_equality_by_kind(void)
{
    // Text leaves compare on their text, and not across operators.
    CHECK(child_count(rewrite(AND(contains(r"msg", r"timeout"),
                                  contains(r"msg", r"timeout"),
                                  exists(r"a"))))
          == 2);
    CHECK(child_count(rewrite(AND(contains(r"msg", r"timeout"),
                                  contains(r"msg", r"refused"),
                                  exists(r"a"))))
          == 3);
    CHECK(child_count(rewrite(AND(prefix(r"msg", r"time"),
                                  prefix(r"msg", r"time"),
                                  exists(r"a"))))
          == 2);
    CHECK(child_count(rewrite(AND(substring(r"msg", r"imeou"),
                                  substring(r"msg", r"imeou"),
                                  exists(r"a"))))
          == 2);
    // Same field, same text, different operator: a prefix is anchored and a
    // substring is not, so these are two conditions.
    CHECK(child_count(rewrite(AND(prefix(r"msg", r"time"),
                                  substring(r"msg", r"time"),
                                  exists(r"a"))))
          == 3);

    // An existence test carries nothing but its field.
    CHECK(child_count(rewrite(AND(exists(r"a"), exists(r"a"), exists(r"b"))))
          == 2);
    CHECK(child_count(rewrite(AND(exists(r"a"), exists(r"b"), exists(r"c"))))
          == 3);

    // Paths compare component by component.
    CHECK(child_count(rewrite(AND(under(r"attrs", r"k"),
                                  under(r"attrs", r"k"),
                                  exists(r"a"))))
          == 2);
    CHECK(child_count(rewrite(AND(under(r"attrs", r"k"),
                                  under(r"attrs", r"j"),
                                  exists(r"a"))))
          == 3);

    // IN leaves compare positionally, which is documented and one-sided: the
    // same values in a different order are the same condition and this calls
    // them different, costing a dedupe and never an answer.
    int64_t                a[] = {1, 2, 3};
    int64_t                b[] = {3, 2, 1};
    int64_t                c[] = {1, 2};
    n00b_plan_predicate_t *same
        = rewrite(AND(in_of(r"level", a, 3), in_of(r"level", a, 3), exists(r"x")));
    CHECK(child_count(same) == 2);
    CHECK(child_count(rewrite(AND(in_of(r"level", a, 3),
                                  in_of(r"level", b, 3),
                                  exists(r"x"))))
          == 3);
    CHECK(child_count(rewrite(AND(in_of(r"level", a, 3),
                                  in_of(r"level", c, 2),
                                  exists(r"x"))))
          == 3);
}

// `AND(a, b, NOT(AND(a, b)))` after flattening, and its disjunctive mirror.
// A pairwise scan cannot see either: the contradiction is between a negated
// group and the set of operands beside it.
static void
test_negation_subsumed_by_siblings(void)
{
    CHECK(kind_of(rewrite(AND(eq(r"level", 1),
                              exists(r"a"),
                              negate(AND(eq(r"level", 1), exists(r"a"))))))
          == N00B_PLAN_PREDICATE_FALSE);

    CHECK(kind_of(rewrite(OR(eq(r"level", 1),
                             exists(r"a"),
                             negate(OR(eq(r"level", 1), exists(r"a"))))))
          == N00B_PLAN_PREDICATE_TRUE);

    // A negated group naming something the siblings do not assert is not a
    // contradiction: `a AND NOT(a AND b)` is satisfied by a record with `a`
    // and without `b`.
    n00b_plan_predicate_t *partial = rewrite(
        AND(eq(r"level", 1), negate(AND(eq(r"level", 1), exists(r"b")))));
    CHECK(kind_of(partial) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(partial) == 2);

    // And the connectives have to agree. `a AND NOT(a OR b)` is a
    // contradiction too, but by a different route, and this pass does not
    // claim it: it must be left alone rather than folded on a rule that does
    // not apply.
    CHECK(kind_of(rewrite(AND(eq(r"level", 1),
                              negate(OR(eq(r"level", 1), exists(r"b"))))))
          == N00B_PLAN_PREDICATE_AND);
}

// Past ROCS_REWRITE_PAIRWISE_MAX the pairwise rules switch off and group
// comparison degrades to positional. Both sides of that line are worth
// pinning, because what happens past it is a silent loss of optimization
// rather than an error.
#define REWRITE_CAP 64

static void
test_group_width_cap(void)
{
    // Exactly one duplicated operand, at the two ends of the group, so the
    // dedupe has to look the whole width to find it.
    // At the cap it does, and the pair collapses.
    n00b_plan_predicate_list_t *at = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < REWRITE_CAP; i++) {
        bool dup = i == 0 || i == REWRITE_CAP - 1;
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            at,
            exists(dup ? r"a" : n00b_cformat("f[|#|]", (int64_t)i)))));
    }
    n00b_plan_predicate_t *capped
        = rewrite(predicate_ok(n00b_plan_predicate_and(at)));
    CHECK(kind_of(capped) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(capped) == REWRITE_CAP - 1);

    // One operand past it the pairwise rules switch off, so the same
    // duplicated pair survives and the group comes back as written.
    n00b_plan_predicate_list_t *over = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < REWRITE_CAP + 1; i++) {
        bool dup = i == 0 || i == REWRITE_CAP;
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            over,
            exists(dup ? r"a" : n00b_cformat("f[|#|]", (int64_t)i)))));
    }
    n00b_plan_predicate_t *uncapped
        = rewrite(predicate_ok(n00b_plan_predicate_and(over)));
    CHECK(kind_of(uncapped) == N00B_PLAN_PREDICATE_AND);
    CHECK(child_count(uncapped) == REWRITE_CAP + 1);

    // The IN collapse is deliberately not capped on width, because the width
    // is what it exists to bound: a disjunction of equalities wider than the
    // pairwise cap still becomes one IN, and the fan-out cap then applies to
    // it as it would to the spelling somebody wrote by hand.
    n00b_plan_predicate_list_t *wide = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < REWRITE_CAP + 40; i++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(wide, eq(r"level", (int64_t)i))));
    }
    n00b_plan_predicate_t *collapsed
        = rewrite(predicate_ok(n00b_plan_predicate_or(wide)));
    CHECK(kind_of(collapsed) == N00B_PLAN_PREDICATE_LEAF);
    CHECK(leaf_op(collapsed) == N00B_PLAN_LEAF_IN);

    auto values_r = n00b_plan_predicate_values(collapsed);
    CHECK(n00b_result_is_ok(values_r));
    CHECK(n00b_list_len(*n00b_option_get(n00b_result_get(values_r)))
          == REWRITE_CAP + 40);

    // A disjunction naming more distinct equality fields than the collapse
    // will group is left as written rather than half-collapsed, so it reaches
    // a fixpoint in one round instead of making progress for as many rounds
    // as it has fields.
    n00b_plan_predicate_list_t *fields = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < REWRITE_CAP + 1; i++) {
        n00b_string_t *name = n00b_cformat("g[|#|]", (int64_t)i);
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(fields, eq(name, 1))));
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(fields, eq(name, 2))));
    }
    n00b_plan_predicate_t *many
        = rewrite(predicate_ok(n00b_plan_predicate_or(fields)));
    CHECK(kind_of(many) == N00B_PLAN_PREDICATE_OR);
    CHECK(child_count(many) == 2 * (REWRITE_CAP + 1));
    CHECK(rewrite(many) == many);
}

static void
test_idempotent(void)
{
    // n00b_plan_build rewrites, and the fan-out rewrites before it, so every
    // predicate that reaches a build has been through the pass twice. The
    // second pass must be a walk that changes nothing.
    n00b_plan_predicate_t *once =
        rewrite(OR(AND(eq(r"tenant", 7), range(r"ts", 3, 9), exists(r"b")),
                   AND(eq(r"tenant", 7), range(r"ts", 5, 20), exists(r"c"))));
    n00b_plan_predicate_t *twice = rewrite(once);

    CHECK(kind_of(twice) == kind_of(once));
    CHECK(child_count(twice) == child_count(once));

    n00b_plan_predicate_t *thrice = rewrite(twice);
    CHECK(kind_of(thrice) == kind_of(twice));
    CHECK(child_count(thrice) == child_count(twice));
}

static void
test_untouched_shapes(void)
{
    // A predicate with nothing to rewrite comes back as itself. Rebuilding an
    // equivalent tree would be correct and would also mean every plan built
    // from a cached predicate allocated a fresh one.
    n00b_plan_predicate_t *plain = AND(exists(r"a"), exists(r"b"));
    CHECK(rewrite(plain) == plain);

    n00b_plan_predicate_t *leaf = eq(r"level", 1);
    CHECK(rewrite(leaf) == leaf);

    // Null in, error out.
    CHECK(n00b_result_is_err(n00b_plan_rewrite(nullptr)));
}

// ---------------------------------------------------------------------------
// Properties over random predicates.
//
// The cases above each pin one rule against one tree somebody wrote out. What
// they cannot say is whether the rules compose: a rewrite that fires only
// because another one just did, or one that undoes another's work, shows up as
// a tree that never settles rather than as any single rule misbehaving.
// ---------------------------------------------------------------------------

typedef struct {
    uint64_t state;
} rw_rng_t;

static uint64_t
rw_next(rw_rng_t *rng)
{
    uint64_t x = rng->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng->state = x;
    return x;
}

static uint64_t
rw_below(rw_rng_t *rng, uint64_t bound)
{
    return rw_next(rng) % bound;
}

// Leaves drawn from a small pool, so duplicates and contradictions are common
// rather than rare. A generator over distinct leaves would almost never build
// the shapes the folding rules exist for.
static n00b_plan_predicate_t *
rw_leaf(rw_rng_t *rng)
{
    switch (rw_below(rng, 8)) {
    case 0:
        return eq(r"level", 1);
    case 1:
        return eq(r"level", 2);
    case 2:
        return eq(r"code", 1);
    case 3:
        return range(r"ts", 3, 9);
    case 4:
        return range(r"ts", 5, 20);
    case 5:
        return exists(r"a");
    case 6:
        return exists(r"b");
    default:
        return predicate_ok(n00b_plan_predicate_eq(
            field(r"ts"),
            json_value(n00b_json_string_new_from_n00b(r"zzqq"))));
    }
}

static n00b_plan_predicate_t *
rw_tree(rw_rng_t *rng, uint64_t depth)
{
    if (depth == 0 || rw_below(rng, 4) == 0) {
        return rw_leaf(rng);
    }
    if (rw_below(rng, 6) == 0) {
        return negate(rw_tree(rng, depth - 1));
    }

    uint64_t                    arity = 2 + rw_below(rng, 3);
    n00b_plan_predicate_list_t *kids  = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < arity; i++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(kids, rw_tree(rng, depth - 1))));
    }
    return predicate_ok(rw_below(rng, 2) == 0
                            ? n00b_plan_predicate_and(kids)
                            : n00b_plan_predicate_or(kids));
}

#define RW_SHAPES 2000

static void
test_rewrite_reaches_a_fixpoint(void)
{
    // Pointer identity, not structural equality. The pass returns its input
    // unchanged when no rule fires, so a second run over an already-rewritten
    // tree must hand back the very same node. Anything else means the first
    // run stopped before it was finished, which is what a round cap does
    // silently.
    rw_rng_t rng = {.state = UINT64_C(0x243f6a8885a308d3)};
    for (uint64_t i = 0; i < RW_SHAPES; i++) {
        n00b_plan_predicate_t *tree  = rw_tree(&rng, 3 + (i % 4));
        n00b_plan_predicate_t *once  = rewrite(tree);
        n00b_plan_predicate_t *twice = rewrite(once);
        CHECK(once == twice);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_flatten_and_absorb();
    test_dedupe_and_contradiction();
    test_range_merge();
    test_exclusive_bounds();
    test_mixed_numeric_bounds();
    test_leaf_equality_by_kind();
    test_negation_subsumed_by_siblings();
    test_group_width_cap();
    test_incomparable_bounds_fold_nothing();
    test_or_of_ranges_merges_when_they_meet();
    test_or_of_equalities_collapses_to_in();
    test_factoring();
    test_commuted_operands_are_one_condition();
    test_partial_factoring();
    test_regex_dedupes_by_program();
    test_idempotent();
    test_untouched_shapes();
    test_rewrite_reaches_a_fixpoint();

    n00b_shutdown();
    return 0;
}

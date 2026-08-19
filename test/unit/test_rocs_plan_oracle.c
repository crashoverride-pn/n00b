/* test/unit/test_rocs_plan_oracle.c - planned execution against an
   unoptimized reference scan. */

#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"
#include "internal/rocs/index.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

#include "plan_oracle.h"

static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    auto r = n00b_plan_target_field(field);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_node_t *
plan_ok(n00b_result_t(n00b_plan_node_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_store_index_t *
index_ok(n00b_result_t(n00b_store_index_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
level_eq(n00b_string_t *level)
{
    return predicate_ok(n00b_plan_predicate_eq(
        field_target(r"level"),
        json_value(n00b_json_string_new_from_n00b(level))));
}

static n00b_plan_predicate_t *
msg_contains(n00b_string_t *text)
{
    return predicate_ok(
        n00b_plan_predicate_contains(field_target(r"message"), text));
}

static n00b_plan_predicate_t *
msg_prefix(n00b_string_t *text)
{
    return predicate_ok(
        n00b_plan_predicate_prefix(field_target(r"message"), text));
}

static n00b_plan_predicate_t *
any_contains(n00b_string_t *text)
{
    auto target_r = n00b_plan_target_any();
    CHECK(n00b_result_is_ok(target_r));
    return predicate_ok(
        n00b_plan_predicate_contains(n00b_result_get(target_r), text));
}

static n00b_plan_predicate_t *
exists(n00b_string_t *field)
{
    return predicate_ok(n00b_plan_predicate_exists(field_target(field)));
}

static n00b_plan_predicate_t *
negate(n00b_plan_predicate_t *child)
{
    return predicate_ok(n00b_plan_predicate_not(child));
}

static n00b_plan_predicate_t *
group(n00b_plan_predicate_t *a, n00b_plan_predicate_t *b, bool conjunction)
{
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, a)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, b)));
    return predicate_ok(conjunction ? n00b_plan_predicate_and(kids)
                                    : n00b_plan_predicate_or(kids));
}

static n00b_plan_index_list_t *
sample_indexes(bool with_catch_all)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(
        indexes,
        index_ok(n00b_store_index_new(r"level", N00B_STORE_INDEX_TERM)))));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(
        indexes,
        index_ok(n00b_store_index_new(r"message", N00B_STORE_INDEX_NGRAM)))));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(
        indexes,
        index_ok(n00b_store_index_new(r"message",
                                      N00B_STORE_INDEX_FULLTEXT)))));

    if (with_catch_all) {
        // Catch-all resolves through fulltext-keyed column postings, so every
        // field it claims to cover needs a fulltext index writing them.
        CHECK(n00b_result_is_ok(n00b_plan_index_list_append(
            indexes,
            index_ok(n00b_store_index_new(r"level",
                                          N00B_STORE_INDEX_FULLTEXT)))));

        n00b_store_index_field_list_t *fields =
            n00b_alloc(n00b_store_index_field_list_t);
        *fields = n00b_list_new_private(n00b_string_t *,
                                        .scan_kind = N00B_GC_SCAN_KIND_ALL);
        n00b_list_push(*fields, r"level");
        n00b_list_push(*fields, r"message");
        CHECK(n00b_result_is_ok(n00b_plan_index_list_append(
            indexes,
            index_ok(n00b_store_index_new_catch_all(fields)))));
    }
    return indexes;
}

static void
test_field_predicates_match_a_plain_scan(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(false);

    n00b_plan_oracle_check(level_eq(r"error"), indexes);
    n00b_plan_oracle_check(msg_contains(r"timeout"), indexes);
    n00b_plan_oracle_check(msg_prefix(r"time"), indexes);
    n00b_plan_oracle_check(negate(level_eq(r"error")), indexes);
    n00b_plan_oracle_check(negate(msg_contains(r"timeout")), indexes);
}

static void
test_boolean_shapes_match_a_plain_scan(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(false);

    n00b_plan_oracle_check(group(level_eq(r"error"),
                                 msg_contains(r"timeout"),
                                 true),
                           indexes);
    n00b_plan_oracle_check(group(level_eq(r"error"),
                                 msg_contains(r"timeout"),
                                 false),
                           indexes);
    // A negation beside a selective sibling: the shape whose restriction and
    // whose record pass both regressed.
    n00b_plan_oracle_check(group(level_eq(r"error"),
                                 negate(msg_contains(r"timeout")),
                                 true),
                           indexes);
    n00b_plan_oracle_check(group(msg_prefix(r"time"),
                                 negate(msg_contains(r"timeout")),
                                 true),
                           indexes);
}

static void
test_nested_shapes_match_a_plain_scan(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(false);

    n00b_plan_oracle_check(
        negate(group(level_eq(r"error"), msg_contains(r"timeout"), true)),
        indexes);
    n00b_plan_oracle_check(
        negate(group(level_eq(r"error"), msg_contains(r"timeout"), false)),
        indexes);
    n00b_plan_oracle_check(
        group(negate(level_eq(r"error")),
              group(msg_prefix(r"time"), msg_contains(r"timeout"), false),
              true),
        indexes);
    n00b_plan_oracle_check(negate(negate(msg_contains(r"timeout"))), indexes);
}

static void
test_any_field_shapes_match_an_expanded_scan(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(true);

    n00b_plan_oracle_check(any_contains(r"timeout"), indexes);
    // The shape that returned the whole shard when the negation was pushed
    // into a record scan.
    n00b_plan_oracle_check(negate(any_contains(r"timeout")), indexes);
    n00b_plan_oracle_check(group(any_contains(r"timeout"),
                                 level_eq(r"error"),
                                 true),
                           indexes);
    n00b_plan_oracle_check(group(negate(any_contains(r"timeout")),
                                 level_eq(r"error"),
                                 true),
                           indexes);

    // A negation over an indefinite branch that mentions an any-field target.
    // Pushing this one into a record scan is what made it match everything:
    // an any-field leaf tested against a record answers false, so negating it
    // answers true for the whole shard.
    n00b_plan_oracle_check(
        negate(group(any_contains(r"timeout"), exists(r"level"), false)),
        indexes);
    n00b_plan_oracle_check(
        negate(group(any_contains(r"timeout"), exists(r"message"), true)),
        indexes);
    n00b_plan_oracle_check(
        negate(group(any_contains(r"timeout"), msg_prefix(r"time"), false)),
        indexes);
}


// Every ordered pair of leaves, under both connectives, with the negation in
// each position. Shapes nobody would write out by hand are where the
// composition rules stop agreeing with each other.
static n00b_plan_predicate_t *
msg_regex(n00b_string_t *pattern)
{
    auto regex_r = n00b_regex_new(pattern);
    CHECK(n00b_result_is_ok(regex_r));
    return predicate_ok(n00b_plan_predicate_regex(field_target(r"message"),
                                                  n00b_result_get(regex_r)));
}

static n00b_plan_predicate_t *
level_in(n00b_string_t *a, n00b_string_t *b)
{
    n00b_plan_value_list_t *values = n00b_plan_value_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_value_list_append(
        values,
        json_value(n00b_json_string_new_from_n00b(a)))));
    CHECK(n00b_result_is_ok(n00b_plan_value_list_append(
        values,
        json_value(n00b_json_string_new_from_n00b(b)))));
    return predicate_ok(n00b_plan_predicate_in(field_target(r"level"),
                                               values));
}

static n00b_plan_predicate_t *
sweep_leaf(uint64_t which)
{
    switch (which) {
    case 0:
        return level_eq(r"error");
    case 1:
        return level_eq(r"info");
    case 2:
        return msg_contains(r"timeout");
    case 3:
        return msg_prefix(r"time");
    case 4:
        return exists(r"level");
    case 5:
        return exists(r"message");
    case 6:
        return any_contains(r"timeout");
    case 7:
        return msg_contains(r"disk");
    case 8:
        return level_eq(r"warn");
    case 9:
        return msg_regex(r"tim.*ut");
    case 10:
        return level_in(r"error", r"warn");
    default:
        return any_contains(r"disk");
    }
}

#define SWEEP_LEAVES 12

static void
test_pairwise_shapes_match_a_plain_scan(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(true);
    uint64_t                checked = 0;

    // Every leaf's literals in one fixture, so the whole sweep shares a shard.
    n00b_plan_predicate_t *seeds[SWEEP_LEAVES];
    for (uint64_t i = 0; i < SWEEP_LEAVES; i++) {
        seeds[i] = sweep_leaf(i);
    }
    oracle_fixture_t fixture = n00b_plan_oracle_fixture(seeds,
                                                        SWEEP_LEAVES,
                                                        indexes);

    for (uint64_t a = 0; a < SWEEP_LEAVES; a++) {
        for (uint64_t b = 0; b < SWEEP_LEAVES; b++) {
            for (uint64_t conj = 0; conj < 2; conj++) {
                for (uint64_t shape = 0; shape < 4; shape++) {
                    n00b_plan_predicate_t *left  = sweep_leaf(a);
                    n00b_plan_predicate_t *right = sweep_leaf(b);
                    if (shape == 1 || shape == 3) {
                        left = negate(left);
                    }
                    if (shape == 2 || shape == 3) {
                        right = negate(right);
                    }
                    n00b_plan_predicate_t *pair = group(left,
                                                        right,
                                                        conj == 0);
                    n00b_plan_oracle_check_in(fixture, pair);
                    checked++;
                }
            }
        }
    }
    n00b_printf("pairwise shapes checked: [|#|]", (int64_t)checked);
}




static void
dump_plan(n00b_plan_node_t *n, int indent)
{
    for (int i = 0; i < indent; i++) {
        fprintf(stderr, "  ");
    }
    auto k_r = n00b_plan_node_kind(n);
    if (n00b_result_is_err(k_r)) {
        fprintf(stderr, "<err>\n");
        return;
    }
    int k = (int)n00b_result_get(k_r);
    const char *name = k == 1 ? "INDEX_SCAN"
                     : k == 2 ? "RECORD_SCAN"
                     : k == 3 ? "INTERSECT"
                     : k == 4 ? "UNION"
                     : k == 5 ? "COMPLEMENT"
                              : "EMPTY";
    fprintf(stderr, "%s\n", name);
    auto c_r = n00b_plan_node_child_count(n);
    if (n00b_result_is_err(c_r)) {
        return;
    }
    uint64_t count = n00b_result_get(c_r);
    for (uint64_t i = 0; i < count; i++) {
        auto ch = n00b_plan_node_child_at(n, i);
        if (n00b_result_is_ok(ch) && n00b_option_is_set(n00b_result_get(ch))) {
            dump_plan(n00b_option_get(n00b_result_get(ch)), indent + 1);
        }
    }
}

static void
dump_predicate(n00b_plan_predicate_t *p, int indent)
{
    for (int i = 0; i < indent; i++) {
        fprintf(stderr, "  ");
    }
    auto kind_r = n00b_plan_predicate_kind(p);
    CHECK(n00b_result_is_ok(kind_r));
    n00b_plan_predicate_kind_t kind = n00b_result_get(kind_r);

    if (kind == N00B_PLAN_PREDICATE_LEAF) {
        auto op_r     = n00b_plan_predicate_leaf_op(p);
        auto target_r = n00b_plan_predicate_target(p);
        int  op       = n00b_result_is_ok(op_r) ? (int)n00b_result_get(op_r) : -1;
        n00b_string_t *field = r"<any>";
        if (n00b_result_is_ok(target_r)) {
            n00b_option_t(n00b_plan_target_t *) t = n00b_result_get(target_r);
            if (n00b_option_is_set(t)) {
                auto n_r = n00b_plan_target_field_name(n00b_option_get(t));
                if (n00b_result_is_ok(n_r)
                    && n00b_option_is_set(n00b_result_get(n_r))) {
                    field = n00b_option_get(n00b_result_get(n_r));
                }
            }
        }
        n00b_eprintf("LEAF op=[|#|] field=[|#|]", (int64_t)op, field);
        return;
    }

    const char *name = kind == N00B_PLAN_PREDICATE_AND   ? "AND"
                     : kind == N00B_PLAN_PREDICATE_OR    ? "OR"
                     : kind == N00B_PLAN_PREDICATE_NOT   ? "NOT"
                                                         : "OTHER";
    fprintf(stderr, "%s\n", name);
    auto count_r = n00b_plan_predicate_child_count(p);
    if (n00b_result_is_err(count_r)) {
        return;
    }
    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto c_r = n00b_plan_predicate_child_at(p, i);
        if (n00b_result_is_ok(c_r)
            && n00b_option_is_set(n00b_result_get(c_r))) {
            dump_predicate(n00b_option_get(n00b_result_get(c_r)), indent + 1);
        }
    }
}

// Randomly nested trees, seeded so a failure reproduces. Pairs cover which
// operators meet; depth covers how the rewrite rules compose once a group
// contains another group.
typedef struct {
    uint64_t state;
} sweep_rng_t;

static uint64_t
sweep_next(sweep_rng_t *rng)
{
    uint64_t x = rng->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng->state = x;
    return x;
}

static uint64_t
sweep_below(sweep_rng_t *rng, uint64_t bound)
{
    return sweep_next(rng) % bound;
}

static n00b_plan_predicate_t *
sweep_tree(sweep_rng_t *rng, uint64_t depth)
{
    if (depth == 0 || sweep_below(rng, 5) == 0) {
        return sweep_leaf(sweep_below(rng, SWEEP_LEAVES));
    }

    uint64_t pick = sweep_below(rng, 5);
    if (pick == 0) {
        return negate(sweep_tree(rng, depth - 1));
    }

    uint64_t                    arity = 2 + sweep_below(rng, 2);
    n00b_plan_predicate_list_t *kids  = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < arity; i++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(kids, sweep_tree(rng, depth - 1))));
    }
    return predicate_ok(pick < 3 ? n00b_plan_predicate_and(kids)
                                 : n00b_plan_predicate_or(kids));
}

#define SWEEP_DEEP_SHAPES 400

static void
test_deep_shapes_match_a_plain_scan(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(true);

    n00b_plan_predicate_t *seeds[SWEEP_LEAVES];
    for (uint64_t i = 0; i < SWEEP_LEAVES; i++) {
        seeds[i] = sweep_leaf(i);
    }
    oracle_fixture_t fixture = n00b_plan_oracle_fixture(seeds,
                                                        SWEEP_LEAVES,
                                                        indexes);

    sweep_rng_t rng = {.state = UINT64_C(0x9e3779b97f4a7c15)};
    for (uint64_t i = 0; i < SWEEP_DEEP_SHAPES; i++) {
        n00b_plan_oracle_check_in(fixture, sweep_tree(&rng, 4));
    }
    n00b_printf("deep shapes checked: [|#|]", (int64_t)SWEEP_DEEP_SHAPES);
}


// OR whose one branch is an AND holding a record scan, and whose other branch
// is a record scan of its own. Two scans in different subtrees, neither under
// a complement.
static void
test_minimal_two_scan_shape(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(false);
    n00b_plan_predicate_t  *shape   = group(
        group(msg_prefix(r"time"), msg_contains(r"timeout"), true),
        msg_contains(r"disk"),
        false);
    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(shape, indexes));
    auto              sole = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole));
    n00b_eprintf("minimal shape: single record scan = [|#|]",
                 (int64_t)(n00b_option_is_set(n00b_result_get(sole)) ? 1 : 0));
}


// Both union rewrites assume a lossy index over-approximates: its candidates
// must contain every record that truly matches, or folding branches together
// drops answers. Asserted directly against the index rather than inferred from
// a final answer that a paired record scan would have corrected anyway.
static void
check_over_approximates(oracle_fixture_t       fixture,
                        n00b_plan_predicate_t *predicate)
{
    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(predicate, fixture.indexes));

    auto kind_r = n00b_plan_node_kind(plan);
    CHECK(n00b_result_is_ok(kind_r));
    if (n00b_result_get(kind_r) != N00B_PLAN_NODE_INTERSECT) {
        return;
    }

    n00b_plan_node_t *scan_node = nullptr;
    auto              count_r   = n00b_plan_node_child_count(plan);
    CHECK(n00b_result_is_ok(count_r));
    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto child_r = n00b_plan_node_child_at(plan, i);
        CHECK(n00b_result_is_ok(child_r));
        n00b_option_t(n00b_plan_node_t *) child = n00b_result_get(child_r);
        if (!n00b_option_is_set(child)) {
            continue;
        }
        n00b_plan_node_t *node = n00b_option_get(child);
        auto              k_r  = n00b_plan_node_kind(node);
        if (n00b_result_is_ok(k_r)
            && n00b_result_get(k_r) == N00B_PLAN_NODE_INDEX_SCAN) {
            scan_node = node;
        }
    }
    if (scan_node == nullptr) {
        return;
    }

    auto cand_r = n00b_plan_exec_hot(scan_node, fixture.shard);
    CHECK(n00b_result_is_ok(cand_r));

    n00b_plan_index_list_t *none    = n00b_plan_index_list_new();
    auto                    truth_r = n00b_plan_build(predicate, none);
    CHECK(n00b_result_is_ok(truth_r));
    auto truth_set_r = n00b_plan_exec_hot(n00b_result_get(truth_r),
                                          fixture.shard);
    CHECK(n00b_result_is_ok(truth_set_r));

    n00b_plan_ordset_t *candidates = n00b_result_get(cand_r);
    n00b_plan_ordset_t *matches    = n00b_result_get(truth_set_r);
    uint64_t            missed     = 0;
    for (uint64_t row = 0; row < fixture.rows; row++) {
        auto m_r = n00b_plan_ordset_contains(matches, row);
        auto c_r = n00b_plan_ordset_contains(candidates, row);
        CHECK(n00b_result_is_ok(m_r));
        CHECK(n00b_result_is_ok(c_r));
        if (n00b_result_get(m_r) && !n00b_result_get(c_r)) {
            n00b_eprintf("index under-approximates: row [|#|] matches but is "
                         "not a candidate",
                         (int64_t)row);
            missed++;
        }
    }
    CHECK(missed == 0);
}

static void
test_lossy_indexes_over_approximate(void)
{
    n00b_plan_index_list_t *indexes = sample_indexes(true);

    n00b_plan_predicate_t *probes[] = {
        msg_prefix(r"time"),
        msg_prefix(r"dis"),
        msg_regex(r"tim.*ut"),
        msg_contains(r"timeout"),
        msg_contains(r"disk"),
    };
    uint64_t         n       = sizeof(probes) / sizeof(probes[0]);
    oracle_fixture_t fixture = n00b_plan_oracle_fixture(probes, n, indexes);

    for (uint64_t i = 0; i < n; i++) {
        check_over_approximates(fixture, probes[i]);
    }
    n00b_printf("lossy over-approximation probes: [|#|]", (int64_t)n);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_minimal_two_scan_shape();
    test_field_predicates_match_a_plain_scan();
    test_boolean_shapes_match_a_plain_scan();
    test_nested_shapes_match_a_plain_scan();
    test_any_field_shapes_match_an_expanded_scan();
    test_lossy_indexes_over_approximate();
    test_pairwise_shapes_match_a_plain_scan();
    test_deep_shapes_match_a_plain_scan();

    n00b_shutdown();
    return 0;
}

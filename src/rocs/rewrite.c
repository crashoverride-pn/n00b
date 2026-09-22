/*
 * Predicate rewriting, between lowering and planning.
 *
 * Lowering is a structural transcription: whatever shape a caller wrote is the
 * shape the planner gets. That is the right contract for filter.c, which has
 * no business deciding that two conditions are the same condition, but it
 * leaves the planner reading the query's spelling rather than its meaning. A
 * generated filter names one condition many times, writes an equality list as
 * a disjunction, and nests groups that flatten; none of that changes what
 * matches, and all of it changes what gets read.
 *
 * This pass sits in between and answers only questions about the predicate
 * itself. It touches no shard, no index and no catalog, so it runs before any
 * of them are consulted and its result is good for every shard the query will
 * reach.
 *
 * Rule 3 in plan.h governs everything here: cost may change, answers may not.
 * Every rewrite below is an equivalence, not an approximation, and the two
 * places that could tempt otherwise are called out where they sit: an
 * incomparable pair of values is left alone rather than guessed at, and a
 * regex is compared by identity rather than by pattern.
 *
 * What it does
 * ------------
 *
 *   flatten        AND(a, AND(b, c))            -> AND(a, b, c)
 *   absorb         AND(a, FALSE)                -> FALSE
 *                  OR(a, TRUE)                  -> TRUE
 *                  AND(a, TRUE)                 -> a
 *                  OR(a, FALSE)                 -> a
 *   dedupe         AND(a, b, a)                 -> AND(a, b)
 *   contradict     AND(a, NOT a)                -> FALSE
 *                  OR(a, NOT a)                 -> TRUE
 *   double negate  NOT(NOT a)                   -> a
 *   range merge    AND(x in [3,9], x in [5,20]) -> x in [5,9]
 *                  AND(x in [1,2], x in [8,9])  -> FALSE
 *   eq conflict    AND(x = 1, x = 2)            -> FALSE
 *                  AND(x = 1, x in [5,9])       -> FALSE
 *   in collapse    OR(x = 1, x = 2, x = 3)      -> x IN (1, 2, 3)
 *   factor         OR(AND(a,b), AND(a,c))       -> AND(a, OR(b,c))
 *
 * The last two are the ones with teeth.
 *
 * Collapsing a disjunction of equalities is what makes the IN fan-out cap mean
 * something. `field IN (v1..vN)` and the written-out OR of N equalities plan to
 * the same union (plan.h), but only the IN spelling was measured against
 * ROCS_PLAN_IN_FANOUT_MAX, so the same query written the other way built a
 * union of any width at all. Collapsing first means there is one spelling by
 * the time the cap is applied, and the cap applies to both.
 *
 * Factoring is worth more than it looks. The distributed form runs the shared
 * conjunct once per branch against the whole shard; the factored form runs it
 * once and every branch after it sees only what it selected. That is the same
 * accumulator effect the planner's operand ordering is for, except no ordering
 * can produce it: in the distributed form the shared work is two separate
 * subtrees, and nothing may reorder one into the other.
 *
 * What it deliberately does not do
 * --------------------------------
 *
 * Negation normal form. Pushing NOT down to the leaves would make more
 * subterms syntactically comparable, and it would also turn COMPLEMENT over
 * one intersection into a union of two complements, which reads more postings
 * for the same answer. The analysis that wants NNF is done without rewriting
 * to it: contradiction detection looks through a NOT rather than moving it.
 *
 * Common subexpression elimination across branches that do not factor. Two OR
 * branches naming the same expensive leaf read its posting list twice, and
 * sharing it would need the plan to be a DAG with a result cache rather than a
 * tree. Factoring covers the cases where the shared term is a conjunct of
 * every branch, which is the shape that shows up in generated queries.
 */
#include "internal/rocs/plan.h"
#include "internal/rocs/plan_ir.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

// A group wider than this is left unfactored and undeduped.
//
// Both walks compare every operand against every other, so both are quadratic
// in the group's width, and a rewrite that costs more than the read it saves
// is not a saving. The cap matches ROCS_PLAN_IN_FANOUT_MAX and
// ROCS_COST_ORDER_MAX at 64 rather than picking a third number: past that
// width the planner has already decided the group is wide enough to read
// records over, and narrowing a plan nobody will use is wasted work.
//
// Absorption, flattening and the IN collapse are linear and stay on at any
// width, which matters because the width is exactly what the IN collapse is
// there to bound.
#define ROCS_REWRITE_PAIRWISE_MAX 64

// Distinct equality fields the IN collapse will handle in one disjunction.
//
// The collapse itself is uncapped on width, on purpose: see
// rocs_rw_or_collapse_eq. Each distinct field costs one scan of the remaining
// operands, so this is what bounds the work at a fixed number of passes over
// the group rather than one per operand. Sixty-four fields in a single
// disjunction is already past any query shape this has seen; past it the
// leaves are left as written and plan as the union they always did.
#define ROCS_REWRITE_FIELD_GROUPS_MAX 64

// A ceiling on rounds, reached by nothing and asserted against.
//
// One rewrite enables another: factoring produces an AND that wants
// flattening, flattening exposes duplicate conjuncts, deduping can leave a
// one-child group that folds to its operand. Rather than order the rules so
// one pass suffices, which is a proof obligation every future rule would
// inherit, the pass runs until a round changes nothing.
//
// That terminates because every rule strictly decreases the pair
//
//     (leaf occurrences, node count)
//
// read lexicographically. Dedupe, absorption, the IN collapse, range merging
// and both contradiction folds remove leaf occurrences outright. Flattening
// keeps them and removes a group node. Factoring is the one worth checking:
// it can leave the node count equal, as `OR(AND(a,b,c), AND(a,d,e))` does,
// but it removes k-1 copies of each hoisted conjunct, so the first component
// falls. No rule increases either, and neither can fall below zero.
//
// So the loop below is a fixpoint iteration with a proof, and the cap is a
// guard against a future rule that breaks the measure rather than a budget
// anything spends. Hitting it means such a rule now exists, which is a bug in
// that rule and not a predicate to truncate: a debug build says so, and a
// release build stops rewriting rather than spinning.
#define ROCS_REWRITE_MAX_ROUNDS 32

typedef struct {
    n00b_allocator_t *allocator;
    bool              changed;
} rocs_rw_ctx_t;

static n00b_plan_predicate_t *
rocs_rw_predicate(rocs_rw_ctx_t *ctx, n00b_plan_predicate_t *predicate);

// ---------------------------------------------------------------------------
// Structural equality.
//
// "The same condition written twice", which is what dedupe, contradiction
// detection and factoring all ask. Conservative in one direction only: two
// predicates this calls equal must match the same records, while two it calls
// different are free to be equivalent. Every caller either removes or shares a
// subterm on a true answer and leaves the tree alone on a false one, so the
// safe error is to answer false.
// ---------------------------------------------------------------------------

static bool
rocs_rw_target_eq(n00b_plan_target_t *left, n00b_plan_target_t *right)
{
    if (left == right) {
        return true;
    }
    if (left == nullptr || right == nullptr || left->kind != right->kind) {
        return false;
    }
    if (left->kind != N00B_PLAN_TARGET_FIELD) {
        return true;
    }
    return left->field != nullptr && right->field != nullptr
        && n00b_unicode_str_eq(left->field, right->field);
}

static bool
rocs_rw_value_eq(rocs_rw_ctx_t     *ctx,
                 n00b_plan_value_t  left,
                 n00b_plan_value_t  right)
{
    auto left_r  = _rocs_plan_value_node(left);
    auto right_r = _rocs_plan_value_node(right);
    if (n00b_result_is_err(left_r) || n00b_result_is_err(right_r)) {
        // An unset slot on both sides is the same absence; one set and one not
        // is a difference. Neither is an error here, because the leaf kinds
        // that leave a slot empty are exactly the ones that never read it.
        return n00b_result_is_err(left_r) && n00b_result_is_err(right_r);
    }

    auto eq_r = _rocs_plan_json_equal(ctx->allocator,
                                      n00b_result_get(left_r),
                                      n00b_result_get(right_r));
    return n00b_result_is_ok(eq_r) && n00b_result_get(eq_r);
}

static bool
rocs_rw_path_eq(n00b_plan_path_t *left, n00b_plan_path_t *right)
{
    if (left == right) {
        return true;
    }
    if (left == nullptr || right == nullptr || left->components == nullptr
        || right->components == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*left->components);
    if (len != n00b_list_len(*right->components)) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        n00b_plan_path_component_t *l = n00b_list_get(*left->components, i);
        n00b_plan_path_component_t *r = n00b_list_get(*right->components, i);
        if (l == nullptr || r == nullptr || l->kind != r->kind) {
            return false;
        }
        if (l->kind == N00B_PLAN_PATH_INDEX) {
            if (l->index != r->index) {
                return false;
            }
            continue;
        }
        if (l->key == nullptr || r->key == nullptr
            || !n00b_unicode_str_eq(l->key, r->key)) {
            return false;
        }
    }

    return true;
}

static bool
rocs_rw_leaf_eq(rocs_rw_ctx_t         *ctx,
                n00b_plan_predicate_t *left,
                n00b_plan_predicate_t *right)
{
    if (left->leaf_op != right->leaf_op
        || !rocs_rw_target_eq(left->target, right->target)) {
        return false;
    }

    switch (left->leaf_op) {
    case N00B_PLAN_LEAF_EQ:
        return rocs_rw_value_eq(ctx, left->value, right->value);

    case N00B_PLAN_LEAF_IN: {
        if (left->values == nullptr || right->values == nullptr) {
            return false;
        }
        size_t len = n00b_list_len(*left->values);
        if (len != n00b_list_len(*right->values)) {
            return false;
        }
        // Positional. Two IN leaves holding the same values in a different
        // order match the same records, and this calls them different, which
        // costs a dedupe nobody asked for and never an answer.
        for (size_t i = 0; i < len; i++) {
            if (!rocs_rw_value_eq(ctx,
                                  n00b_list_get(*left->values, i),
                                  n00b_list_get(*right->values, i))) {
                return false;
            }
        }
        return true;
    }

    case N00B_PLAN_LEAF_RANGE:
        return left->include_lower == right->include_lower
            && left->include_upper == right->include_upper
            && rocs_rw_value_eq(ctx, left->lower, right->lower)
            && rocs_rw_value_eq(ctx, left->upper, right->upper);

    case N00B_PLAN_LEAF_EXISTS:
        return true;

    case N00B_PLAN_LEAF_CONTAINS:
    case N00B_PLAN_LEAF_PREFIX:
    case N00B_PLAN_LEAF_SUBSTRING:
        return left->text != nullptr && right->text != nullptr
            && n00b_unicode_str_eq(left->text, right->text);

    case N00B_PLAN_LEAF_REGEX:
        // Pattern and compile options both, which is what makes this sound:
        // the engine bakes its options into the graph and does not keep them,
        // so comparing the pattern alone would call `/a/` and `/a/i` one
        // predicate and drop a leaf that matches different records.
        return n00b_regex_same_program(left->regex, right->regex);

    case N00B_PLAN_LEAF_UNDER:
        return rocs_rw_path_eq(left->path, right->path);
    }

    return false;
}

static bool
rocs_rw_pred_eq(rocs_rw_ctx_t         *ctx,
                n00b_plan_predicate_t *left,
                n00b_plan_predicate_t *right)
{
    if (left == right) {
        return true;
    }
    if (left == nullptr || right == nullptr || left->kind != right->kind) {
        return false;
    }

    switch (left->kind) {
    case N00B_PLAN_PREDICATE_FALSE:
    case N00B_PLAN_PREDICATE_TRUE:
        return true;

    case N00B_PLAN_PREDICATE_LEAF:
        return rocs_rw_leaf_eq(ctx, left, right);

    case N00B_PLAN_PREDICATE_NOT:
        return rocs_rw_pred_eq(ctx, left->child, right->child);

    case N00B_PLAN_PREDICATE_AND:
    case N00B_PLAN_PREDICATE_OR: {
        if (left->children == nullptr || right->children == nullptr) {
            return false;
        }
        size_t len = n00b_list_len(*left->children);
        if (len != n00b_list_len(*right->children)) {
            return false;
        }

        // As multisets, because AND and OR commute: `AND(a, b)` and
        // `AND(b, a)` are one condition written two ways, and a generated
        // query is exactly where the same operands arrive in whatever order
        // the generator walked them.
        //
        // Compared rather than sorted. Sorting the operands would be cheaper
        // here and would also reorder the caller's query on the way through,
        // which costs more than it saves: the planner's own ordering is
        // documented to leave operands a count cannot separate in the order
        // they were written, and the control arm that runs a query with cost
        // disabled depends on that order still being the written one. An
        // analysis device has no business rewriting what it is analyzing.
        //
        // Quadratic, inside walks that are already quadratic, so it is capped
        // the same way they are. Past the cap two groups compare positionally
        // and a commuted pair is simply not recognized, which costs a dedupe
        // and never an answer.
        if (len > ROCS_REWRITE_PAIRWISE_MAX) {
            for (size_t i = 0; i < len; i++) {
                if (!rocs_rw_pred_eq(ctx,
                                     n00b_list_get(*left->children, i),
                                     n00b_list_get(*right->children, i))) {
                    return false;
                }
            }
            return true;
        }

        bool used[ROCS_REWRITE_PAIRWISE_MAX] = {};
        for (size_t i = 0; i < len; i++) {
            n00b_plan_predicate_t *want = n00b_list_get(*left->children, i);
            bool                   hit  = false;
            for (size_t j = 0; j < len && !hit; j++) {
                if (used[j]) {
                    continue;
                }
                if (rocs_rw_pred_eq(ctx,
                                    want,
                                    n00b_list_get(*right->children, j))) {
                    used[j] = true;
                    hit     = true;
                }
            }
            if (!hit) {
                return false;
            }
        }
        return true;
    }
    }

    return false;
}

// `left` and `right` are a predicate and its exact negation, in either order.
static bool
rocs_rw_is_negation(rocs_rw_ctx_t         *ctx,
                    n00b_plan_predicate_t *left,
                    n00b_plan_predicate_t *right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    if (left->kind == N00B_PLAN_PREDICATE_NOT
        && rocs_rw_pred_eq(ctx, left->child, right)) {
        return true;
    }
    if (right->kind == N00B_PLAN_PREDICATE_NOT
        && rocs_rw_pred_eq(ctx, right->child, left)) {
        return true;
    }
    return false;
}

// Whether a negated group inside `children` is negating what the rest of
// `children` already assert.
//
// `A AND NOT A` is caught by the pairwise check, but only while `A` is a
// single operand. Flattening splices a conjunction into its parent, so
// `AND(AND(a, b), NOT(AND(a, b)))` arrives here as `AND(a, b, NOT(AND(a, b)))`
// and the contradiction is now between a set of operands and one negated
// group. Nothing pairwise can see that.
//
// Cheap because the operands are in canonical order: the conjuncts of the
// negated group are compared against the siblings directly, and a group whose
// every conjunct is also a sibling cannot hold while they do.
//
// `want_kind` is the connective whose operands are being subsumed: a
// conjunction is contradicted by a negated conjunction of its own operands, and
// a disjunction is made true by a negated disjunction of its own.
static bool
rocs_rw_negation_subsumed(rocs_rw_ctx_t              *ctx,
                          n00b_plan_predicate_list_t *children,
                          n00b_plan_predicate_kind_t  want_kind)
{
    size_t len = n00b_list_len(*children);
    if (len > ROCS_REWRITE_PAIRWISE_MAX) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*children, i);
        if (child == nullptr || child->kind != N00B_PLAN_PREDICATE_NOT
            || child->child == nullptr
            || child->child->kind != want_kind
            || child->child->children == nullptr) {
            continue;
        }

        size_t inner = n00b_list_len(*child->child->children);
        if (inner == 0 || inner > ROCS_REWRITE_PAIRWISE_MAX) {
            continue;
        }

        bool all_present = true;
        for (size_t j = 0; j < inner && all_present; j++) {
            n00b_plan_predicate_t *needed = n00b_list_get(*child->child->children,
                                                          j);
            bool found = false;
            for (size_t k = 0; k < len && !found; k++) {
                if (k == i) {
                    continue;
                }
                found = rocs_rw_pred_eq(ctx, needed, n00b_list_get(*children, k));
            }
            all_present = found;
        }

        if (all_present) {
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Constant construction.
//
// The constructors validate, so a rewrite that builds something malformed is
// caught where it is built rather than in the planner. Every one of these
// returns nullptr on a constructor error and every caller treats nullptr as
// "leave the tree alone", so a rewrite that cannot be expressed is skipped
// rather than half-applied.
// ---------------------------------------------------------------------------

static n00b_plan_predicate_t *
rocs_rw_false(rocs_rw_ctx_t *ctx)
{
    auto r = n00b_plan_predicate_false(.allocator = ctx->allocator);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : nullptr;
}

static n00b_plan_predicate_t *
rocs_rw_true(rocs_rw_ctx_t *ctx)
{
    auto r = n00b_plan_predicate_true(.allocator = ctx->allocator);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : nullptr;
}

// A group of `kind` over `children`, folded when it does not need to be one.
//
// An empty group is the kind's identity (an AND of nothing holds, an OR of
// nothing does not) and a one-operand group is that operand. Both cases exist
// because the rules above remove operands, and the constructors reject a group
// under two children, so this is where a shrinking group stops being a group.
static n00b_plan_predicate_t *
rocs_rw_group(rocs_rw_ctx_t              *ctx,
              n00b_plan_predicate_kind_t  kind,
              n00b_plan_predicate_list_t *children)
{
    size_t len = n00b_list_len(*children);
    if (len == 0) {
        return kind == N00B_PLAN_PREDICATE_AND ? rocs_rw_true(ctx)
                                               : rocs_rw_false(ctx);
    }
    if (len == 1) {
        return n00b_list_get(*children, 0);
    }

    auto r = kind == N00B_PLAN_PREDICATE_AND
               ? n00b_plan_predicate_and(children, .allocator = ctx->allocator)
               : n00b_plan_predicate_or(children, .allocator = ctx->allocator);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : nullptr;
}

static n00b_plan_predicate_list_t *
rocs_rw_list(rocs_rw_ctx_t *ctx)
{
    return n00b_plan_predicate_list_new(.allocator = ctx->allocator);
}

// Whether a rebuilt operand list holds exactly what the original group held.
//
// By pointer, not by rocs_rw_pred_eq: the question is whether any rule
// actually fired, and every rule that fires either removes an operand or
// substitutes a new node for one. A group this reports unchanged is returned
// as itself rather than as an equivalent copy, which keeps a predicate that
// nothing rewrites from allocating a fresh tree on each of the rounds below,
// on each build, on each partition of a fan-out.
static bool
rocs_rw_members_unchanged(n00b_plan_predicate_list_t *before,
                          n00b_plan_predicate_list_t *after)
{
    if (before == nullptr) {
        return false;
    }
    size_t len = n00b_list_len(*before);
    if (len != n00b_list_len(*after)) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*before, i) != n00b_list_get(*after, i)) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Range arithmetic.
//
// A range leaf always carries both bounds, so an intersection is a pair of
// pointwise choices: the greater lower bound and the lesser upper bound, with
// inclusivity settled by whichever bound won, or by both when they are equal.
// ---------------------------------------------------------------------------

typedef struct {
    n00b_plan_value_t lower;
    n00b_plan_value_t upper;
    bool              include_lower;
    bool              include_upper;
} rocs_rw_range_t;

// Ok(false) means the pair cannot be ordered, which is not an error: a string
// bound and a numeric one describe records no single comparison covers, and
// the interpreter treats such a record as no match. Every caller here responds
// by declining to fold.
static bool
rocs_rw_cmp(n00b_plan_value_t left, n00b_plan_value_t right, int32_t *cmp)
{
    auto left_r  = _rocs_plan_value_node(left);
    auto right_r = _rocs_plan_value_node(right);
    if (n00b_result_is_err(left_r) || n00b_result_is_err(right_r)) {
        return false;
    }

    auto r = _rocs_plan_json_order_cmp(n00b_result_get(left_r),
                                       n00b_result_get(right_r),
                                       cmp);
    return n00b_result_is_ok(r) && n00b_result_get(r);
}

// The intersection of `into` and `with`, written back into `into`.
//
// Returns false when the two cannot be ordered, leaving `into` untouched so
// the caller keeps both leaves rather than merging on a comparison that did
// not happen.
static bool
rocs_rw_range_intersect(rocs_rw_range_t *into, const rocs_rw_range_t *with)
{
    int32_t cmp = 0;

    if (!rocs_rw_cmp(with->lower, into->lower, &cmp)) {
        return false;
    }
    if (cmp > 0) {
        into->lower         = with->lower;
        into->include_lower = with->include_lower;
    }
    else if (cmp == 0) {
        // Equal bounds keep the stricter one: excluding a point either side
        // excludes it from the intersection.
        into->include_lower = into->include_lower && with->include_lower;
    }

    if (!rocs_rw_cmp(with->upper, into->upper, &cmp)) {
        return false;
    }
    if (cmp < 0) {
        into->upper         = with->upper;
        into->include_upper = with->include_upper;
    }
    else if (cmp == 0) {
        into->include_upper = into->include_upper && with->include_upper;
    }

    return true;
}

// The union of `into` and `with`, written back into `into`, when the two
// overlap or touch.
//
// Returns false when they are disjoint, or cannot be ordered, leaving `into`
// untouched. Two disjoint ranges have no single-range union: `OR(x in [1,2],
// x in [8,9])` admits 1 and 8 but not 5, and merging them to [1,9] would start
// matching records that never matched. That is the direction this must never
// get wrong, so the overlap test is what gates the merge rather than an
// afterthought to it.
//
// Touching counts. `[1,5]` and `(5,9]` share no point but leave no gap, and
// their union is exactly `[1,9]`.
static bool
rocs_rw_range_union(rocs_rw_range_t *into, const rocs_rw_range_t *with)
{
    int32_t cmp = 0;

    // Disjoint when one ends before the other starts. A shared endpoint joins
    // them only if at least one side includes it; excluded on both sides it
    // leaves a hole of exactly that value.
    if (!rocs_rw_cmp(with->lower, into->upper, &cmp)) {
        return false;
    }
    if (cmp > 0
        || (cmp == 0 && !with->include_lower && !into->include_upper)) {
        return false;
    }
    if (!rocs_rw_cmp(into->lower, with->upper, &cmp)) {
        return false;
    }
    if (cmp > 0
        || (cmp == 0 && !into->include_lower && !with->include_upper)) {
        return false;
    }

    if (!rocs_rw_cmp(with->lower, into->lower, &cmp)) {
        return false;
    }
    if (cmp < 0) {
        into->lower         = with->lower;
        into->include_lower = with->include_lower;
    }
    else if (cmp == 0) {
        // Equal bounds keep the looser one: a point either side admits is in
        // the union.
        into->include_lower = into->include_lower || with->include_lower;
    }

    if (!rocs_rw_cmp(with->upper, into->upper, &cmp)) {
        return false;
    }
    if (cmp > 0) {
        into->upper         = with->upper;
        into->include_upper = with->include_upper;
    }
    else if (cmp == 0) {
        into->include_upper = into->include_upper || with->include_upper;
    }

    return true;
}

// Whether a range admits nothing: an inverted pair of bounds, or a single
// point that at least one side excludes.
//
// An unorderable pair answers false, since nothing has been proven about it.
static bool
rocs_rw_range_is_empty(const rocs_rw_range_t *range)
{
    int32_t cmp = 0;
    if (!rocs_rw_cmp(range->lower, range->upper, &cmp)) {
        return false;
    }
    if (cmp > 0) {
        return true;
    }
    return cmp == 0 && !(range->include_lower && range->include_upper);
}

// Whether `value` falls inside `range`, when that can be decided at all.
//
// False means the value and the bounds have no order between them, and
// *inside is left alone. That case has to be distinct from "inside", because
// the caller's two outcomes are to fold the conjunction to FALSE or to drop
// the range as implied by the equality, and an incomparable pair justifies
// neither: `AND(ts = "abc", ts in [1, 9])` matches nothing, since a record
// whose ts is a string satisfies no numeric range, so dropping the range
// there would start matching records that never matched.
static bool
rocs_rw_range_decides(const rocs_rw_range_t *range,
                      n00b_plan_value_t      value,
                      bool                  *inside)
{
    int32_t cmp = 0;
    if (!rocs_rw_cmp(value, range->lower, &cmp)) {
        return false;
    }
    if (range->include_lower ? cmp < 0 : cmp <= 0) {
        *inside = false;
        return true;
    }
    if (!rocs_rw_cmp(value, range->upper, &cmp)) {
        return false;
    }
    *inside = range->include_upper ? cmp <= 0 : cmp < 0;
    return true;
}

static n00b_plan_predicate_t *
rocs_rw_range_leaf(rocs_rw_ctx_t         *ctx,
                   n00b_plan_target_t    *target,
                   const rocs_rw_range_t *range)
{
    auto r = n00b_plan_predicate_range(target,
                                       range->lower,
                                       range->upper,
                                       .include_lower = range->include_lower,
                                       .include_upper = range->include_upper,
                                       .allocator     = ctx->allocator);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : nullptr;
}

static bool
rocs_rw_is_leaf_op(n00b_plan_predicate_t *predicate, n00b_plan_leaf_op_t op)
{
    return predicate != nullptr
        && predicate->kind == N00B_PLAN_PREDICATE_LEAF
        && predicate->leaf_op == op
        && predicate->target != nullptr
        && predicate->target->kind == N00B_PLAN_TARGET_FIELD
        && predicate->target->field != nullptr;
}

static bool
rocs_rw_same_field(n00b_plan_predicate_t *left, n00b_plan_predicate_t *right)
{
    return n00b_unicode_str_eq(left->target->field, right->target->field);
}

// ---------------------------------------------------------------------------
// Conjunctions.
// ---------------------------------------------------------------------------

// Every operand of `predicate`, with the operands of any nested group of the
// same kind spliced in place of it.
//
// The planner splices too, but it does so on plan nodes, after index selection
// has already run on the unflattened shape. Flattening here is what lets the
// rules below see conjuncts that a nested group was hiding.
static bool
rocs_rw_flatten_into(rocs_rw_ctx_t              *ctx,
                     n00b_plan_predicate_list_t *out,
                     n00b_plan_predicate_t      *predicate,
                     n00b_plan_predicate_kind_t  kind)
{
    bool flattened = false;

    size_t len = n00b_list_len(*predicate->children);
    for (size_t i = 0; i < len; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*predicate->children, i);
        if (child == nullptr) {
            return false;
        }
        if (child->kind == kind && child->children != nullptr) {
            size_t sub = n00b_list_len(*child->children);
            for (size_t j = 0; j < sub; j++) {
                (void)n00b_plan_predicate_list_append(
                    out,
                    n00b_list_get(*child->children, j));
            }
            flattened = true;
            continue;
        }
        (void)n00b_plan_predicate_list_append(out, child);
    }

    if (flattened) {
        ctx->changed = true;
    }
    return true;
}

// Merge the range leaves of one conjunction per field, and test the equality
// leaves against what they merge to.
//
// Returns FALSE when the conjunction is unsatisfiable, the rebuilt operand
// list when something merged, and nullptr when there was nothing to do.
static n00b_plan_predicate_t *
rocs_rw_and_scalars(rocs_rw_ctx_t              *ctx,
                    n00b_plan_predicate_list_t *children,
                    n00b_plan_predicate_list_t **out)
{
    size_t len     = n00b_list_len(*children);
    bool   merged  = false;

    n00b_plan_predicate_list_t *kept = rocs_rw_list(ctx);

    // One pass per distinct range field. The field count is bounded by the
    // group width, and the group width is capped by the caller, so this is the
    // same quadratic budget the other pairwise walks spend.
    bool *consumed = n00b_alloc_array_with_opts(
        bool, len == 0 ? 1 : len,
        &(n00b_alloc_opts_t){.allocator = ctx->allocator,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});

    for (size_t i = 0; i < len; i++) {
        if (consumed[i]) {
            continue;
        }
        n00b_plan_predicate_t *child = n00b_list_get(*children, i);
        if (!rocs_rw_is_leaf_op(child, N00B_PLAN_LEAF_RANGE)) {
            continue;
        }

        rocs_rw_range_t range = {
            .lower         = child->lower,
            .upper         = child->upper,
            .include_lower = child->include_lower,
            .include_upper = child->include_upper,
        };
        bool folded = false;

        for (size_t j = i + 1; j < len; j++) {
            if (consumed[j]) {
                continue;
            }
            n00b_plan_predicate_t *other = n00b_list_get(*children, j);
            if (!rocs_rw_is_leaf_op(other, N00B_PLAN_LEAF_RANGE)
                || !rocs_rw_same_field(child, other)) {
                continue;
            }

            rocs_rw_range_t with = {
                .lower         = other->lower,
                .upper         = other->upper,
                .include_lower = other->include_lower,
                .include_upper = other->include_upper,
            };
            if (!rocs_rw_range_intersect(&range, &with)) {
                continue;
            }
            consumed[j] = true;
            folded      = true;
        }

        if (rocs_rw_range_is_empty(&range)) {
            return rocs_rw_false(ctx);
        }

        // An equality on the same field must land inside the merged range, so
        // the range settles it either way: outside, the conjunction is empty;
        // inside, the range is implied by the equality and drops out.
        for (size_t j = 0; j < len; j++) {
            if (consumed[j] || j == i) {
                continue;
            }
            n00b_plan_predicate_t *other = n00b_list_get(*children, j);
            if (!rocs_rw_is_leaf_op(other, N00B_PLAN_LEAF_EQ)
                || !rocs_rw_same_field(child, other)) {
                continue;
            }
            bool inside = false;
            if (!rocs_rw_range_decides(&range, other->value, &inside)) {
                // Nothing proven either way, so both leaves stay and the
                // interpreter settles it per record.
                continue;
            }
            if (!inside) {
                return rocs_rw_false(ctx);
            }
            consumed[i] = true;
            folded      = true;
            break;
        }

        if (consumed[i]) {
            // Subsumed by the equality that stays in the list.
            merged = true;
            continue;
        }
        if (folded) {
            n00b_plan_predicate_t *leaf = rocs_rw_range_leaf(ctx,
                                                             child->target,
                                                             &range);
            if (leaf == nullptr) {
                return nullptr;
            }
            (void)n00b_plan_predicate_list_append(kept, leaf);
            consumed[i] = true;
            merged      = true;
            continue;
        }
    }

    // Two equalities on one field cannot both hold unless they are the same
    // value, and the same value would already have been deduped.
    for (size_t i = 0; i < len; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*children, i);
        if (consumed[i] || !rocs_rw_is_leaf_op(child, N00B_PLAN_LEAF_EQ)) {
            continue;
        }
        for (size_t j = i + 1; j < len; j++) {
            n00b_plan_predicate_t *other = n00b_list_get(*children, j);
            if (consumed[j] || !rocs_rw_is_leaf_op(other, N00B_PLAN_LEAF_EQ)
                || !rocs_rw_same_field(child, other)) {
                continue;
            }
            if (!rocs_rw_value_eq(ctx, child->value, other->value)) {
                return rocs_rw_false(ctx);
            }
        }
    }

    if (!merged) {
        return nullptr;
    }

    for (size_t i = 0; i < len; i++) {
        if (!consumed[i]) {
            (void)n00b_plan_predicate_list_append(kept,
                                                  n00b_list_get(*children, i));
        }
    }

    ctx->changed = true;
    *out         = kept;
    return nullptr;
}

static n00b_plan_predicate_t *
rocs_rw_and(rocs_rw_ctx_t *ctx, n00b_plan_predicate_t *predicate)
{
    n00b_plan_predicate_list_t *flat = rocs_rw_list(ctx);
    if (!rocs_rw_flatten_into(ctx, flat, predicate, N00B_PLAN_PREDICATE_AND)) {
        return predicate;
    }

    // Absorption, and the constant that ends the group outright.
    n00b_plan_predicate_list_t *kept = rocs_rw_list(ctx);
    size_t                      len  = n00b_list_len(*flat);
    for (size_t i = 0; i < len; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*flat, i);
        if (child->kind == N00B_PLAN_PREDICATE_FALSE) {
            ctx->changed = true;
            return rocs_rw_false(ctx);
        }
        if (child->kind == N00B_PLAN_PREDICATE_TRUE) {
            ctx->changed = true;
            continue;
        }
        (void)n00b_plan_predicate_list_append(kept, child);
    }

    len = n00b_list_len(*kept);
    if (len <= ROCS_REWRITE_PAIRWISE_MAX) {
        n00b_plan_predicate_list_t *unique = rocs_rw_list(ctx);
        for (size_t i = 0; i < len; i++) {
            n00b_plan_predicate_t *child = n00b_list_get(*kept, i);
            bool                   drop  = false;

            for (size_t j = 0; j < i; j++) {
                n00b_plan_predicate_t *prior = n00b_list_get(*kept, j);
                if (rocs_rw_pred_eq(ctx, child, prior)) {
                    drop = true;
                    break;
                }
            }
            for (size_t j = 0; !drop && j < len; j++) {
                if (j != i
                    && rocs_rw_is_negation(ctx,
                                           child,
                                           n00b_list_get(*kept, j))) {
                    ctx->changed = true;
                    return rocs_rw_false(ctx);
                }
            }

            if (drop) {
                ctx->changed = true;
                continue;
            }
            (void)n00b_plan_predicate_list_append(unique, child);
        }
        kept = unique;

        if (rocs_rw_negation_subsumed(ctx, kept, N00B_PLAN_PREDICATE_AND)) {
            ctx->changed = true;
            return rocs_rw_false(ctx);
        }

        n00b_plan_predicate_list_t *folded = nullptr;
        n00b_plan_predicate_t      *constant =
            rocs_rw_and_scalars(ctx, kept, &folded);
        if (constant != nullptr) {
            return constant;
        }
        if (folded != nullptr) {
            kept = folded;
        }
    }

    if (rocs_rw_members_unchanged(predicate->children, kept)) {
        return predicate;
    }
    return rocs_rw_group(ctx, N00B_PLAN_PREDICATE_AND, kept);
}

// ---------------------------------------------------------------------------
// Disjunctions.
// ---------------------------------------------------------------------------

// Ranges on one field that overlap, merged into the one range they cover.
//
// The conjunction side of this merges by intersecting; this is the mirror. A
// disjunction of overlapping windows over the same field is what a query
// written from several time buckets looks like, and left alone each window
// costs its own pass.
//
// Returns the rebuilt operand list, or nullptr when nothing merged.
static n00b_plan_predicate_list_t *
rocs_rw_or_merge_ranges(rocs_rw_ctx_t              *ctx,
                        n00b_plan_predicate_list_t *children)
{
    size_t len = n00b_list_len(*children);
    if (len > ROCS_REWRITE_PAIRWISE_MAX) {
        return nullptr;
    }

    bool *consumed = n00b_alloc_array_with_opts(
        bool, len == 0 ? 1 : len,
        &(n00b_alloc_opts_t){.allocator = ctx->allocator,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});

    n00b_plan_predicate_list_t *out    = rocs_rw_list(ctx);
    bool                        merged = false;

    for (size_t i = 0; i < len; i++) {
        if (consumed[i]) {
            continue;
        }
        n00b_plan_predicate_t *child = n00b_list_get(*children, i);
        if (!rocs_rw_is_leaf_op(child, N00B_PLAN_LEAF_RANGE)) {
            (void)n00b_plan_predicate_list_append(out, child);
            continue;
        }

        rocs_rw_range_t range = {
            .lower         = child->lower,
            .upper         = child->upper,
            .include_lower = child->include_lower,
            .include_upper = child->include_upper,
        };
        bool folded = false;

        // Repeated until nothing more joins: merging two windows can widen
        // the result into a third that neither reached on its own.
        bool grew = true;
        while (grew) {
            grew = false;
            for (size_t j = i + 1; j < len; j++) {
                if (consumed[j]) {
                    continue;
                }
                n00b_plan_predicate_t *other = n00b_list_get(*children, j);
                if (!rocs_rw_is_leaf_op(other, N00B_PLAN_LEAF_RANGE)
                    || !rocs_rw_same_field(child, other)) {
                    continue;
                }

                rocs_rw_range_t with = {
                    .lower         = other->lower,
                    .upper         = other->upper,
                    .include_lower = other->include_lower,
                    .include_upper = other->include_upper,
                };
                if (!rocs_rw_range_union(&range, &with)) {
                    continue;
                }
                consumed[j] = true;
                folded      = true;
                grew        = true;
            }
        }

        if (!folded) {
            (void)n00b_plan_predicate_list_append(out, child);
            continue;
        }

        n00b_plan_predicate_t *leaf = rocs_rw_range_leaf(ctx,
                                                         child->target,
                                                         &range);
        if (leaf == nullptr) {
            return nullptr;
        }
        (void)n00b_plan_predicate_list_append(out, leaf);
        merged = true;
    }

    if (!merged) {
        return nullptr;
    }

    ctx->changed = true;
    return out;
}

// Two or more equalities on one field, rewritten as the IN leaf that says the
// same thing.
//
// This is the asymmetry fix. Until the two spellings are one spelling, only
// the one somebody wrote as IN is measured against the fan-out cap.
//
// Runs at any group width, unlike the pairwise walks above, because the width
// is what it is there to bound. A width cap would leave the widest
// disjunctions with two spellings, which are the ones that most need one.
// What is capped instead is the number of distinct fields it will open a
// value group for, since each one costs a scan of the remaining operands and
// a disjunction naming a field per operand is the shape where that squares.
//
// Past the cap the whole rule declines rather than collapsing the first
// ROCS_REWRITE_FIELD_GROUPS_MAX fields and leaving the rest. A partial
// collapse would report a change, and the next round would collapse the next
// batch and report another, so a wide enough group would still be making
// progress when the round cap fired and would accuse a rule of breaking the
// termination measure. Declining is a decision about the group rather than
// about how many rounds it has had.
static n00b_plan_predicate_list_t *
rocs_rw_or_collapse_eq(rocs_rw_ctx_t              *ctx,
                       n00b_plan_predicate_list_t *children)
{
    size_t len = n00b_list_len(*children);

    bool *consumed = n00b_alloc_array_with_opts(
        bool, len == 0 ? 1 : len,
        &(n00b_alloc_opts_t){.allocator = ctx->allocator,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});

    n00b_plan_predicate_list_t *out       = rocs_rw_list(ctx);
    bool                        collapsed = false;
    size_t                      groups    = 0;

    for (size_t i = 0; i < len; i++) {
        if (consumed[i]) {
            continue;
        }
        n00b_plan_predicate_t *child = n00b_list_get(*children, i);
        if (!rocs_rw_is_leaf_op(child, N00B_PLAN_LEAF_EQ)) {
            (void)n00b_plan_predicate_list_append(out, child);
            continue;
        }
        if (++groups > ROCS_REWRITE_FIELD_GROUPS_MAX) {
            return nullptr;
        }

        n00b_plan_value_list_t *values =
            n00b_plan_value_list_new(.allocator = ctx->allocator);
        (void)n00b_plan_value_list_append(values, child->value);

        for (size_t j = i + 1; j < len; j++) {
            if (consumed[j]) {
                continue;
            }
            n00b_plan_predicate_t *other = n00b_list_get(*children, j);
            if (!rocs_rw_is_leaf_op(other, N00B_PLAN_LEAF_EQ)
                || !rocs_rw_same_field(child, other)) {
                continue;
            }
            (void)n00b_plan_value_list_append(values, other->value);
            consumed[j] = true;
        }

        if (n00b_list_len(*values) == 1) {
            // A field named once stays an equality. An IN of one value plans
            // to a union of one branch, which is the same read through an
            // extra node.
            (void)n00b_plan_predicate_list_append(out, child);
            continue;
        }

        auto in_r = n00b_plan_predicate_in(child->target,
                                           values,
                                           .allocator = ctx->allocator);
        if (n00b_result_is_err(in_r)) {
            return nullptr;
        }
        (void)n00b_plan_predicate_list_append(out, n00b_result_get(in_r));
        collapsed = true;
    }

    if (!collapsed) {
        return nullptr;
    }

    ctx->changed = true;
    return out;
}

// The conjuncts of one disjunct: its operands when it is an AND, otherwise
// itself. A bare leaf is a conjunction of one, which is what lets
// `OR(AND(a, b), a)` factor down to `a`.
static n00b_plan_predicate_list_t *
rocs_rw_conjuncts(rocs_rw_ctx_t *ctx, n00b_plan_predicate_t *predicate)
{
    if (predicate->kind == N00B_PLAN_PREDICATE_AND
        && predicate->children != nullptr) {
        return predicate->children;
    }

    n00b_plan_predicate_list_t *one = rocs_rw_list(ctx);
    (void)n00b_plan_predicate_list_append(one, predicate);
    return one;
}

// (a AND b) OR (a AND c)  ->  a AND (b OR c)
//
// Every conjunct shared by every branch is hoisted out of the disjunction. The
// residual of a branch that was nothing but shared conjuncts is TRUE, which
// makes the disjunction TRUE, which leaves the hoisted conjuncts alone: that
// is `(a AND b) OR a` collapsing to `a`, and it falls out rather than being a
// rule of its own.
// The conjunct shared by the most branches, and which branches those are.
//
// Full factoring needs a conjunct in every branch, which a query with one
// odd branch never has: `OR(AND(a,b), AND(a,c), AND(d,e))` shares `a` across
// two of three and nothing across all three, so `a` ran twice against the
// whole shard. Hoisting over the branches that do share it turns that into
//
//     OR(AND(a, OR(b, c)), AND(d, e))
//
// which runs `a` once. The branches that do not share it are carried through
// untouched, so this is still a rewrite of the whole disjunction.
//
// Picks the conjunct with the widest share, and on a tie the first one
// written, so the choice does not depend on operand order beyond what the
// canonical order already fixed. Two or more branches are required: hoisting
// out of one branch rebuilds it unchanged and would never terminate.
static n00b_plan_predicate_t *
rocs_rw_or_factor_partial(rocs_rw_ctx_t              *ctx,
                          n00b_plan_predicate_list_t *children);

static n00b_plan_predicate_t *
rocs_rw_or_widest_common(rocs_rw_ctx_t              *ctx,
                         n00b_plan_predicate_list_t *children,
                         bool                       *in_branch,
                         size_t                     *share_out)
{
    size_t branches = n00b_list_len(*children);

    // One conjunct list per branch, built once. rocs_rw_conjuncts allocates a
    // fresh single-element list for a branch that is not a conjunction, and
    // the scan below reads every branch's list once per candidate, so calling
    // it from in there is branches-squared-times-width allocations to produce
    // the same lists over and over.
    n00b_plan_predicate_list_t **conjuncts = n00b_alloc_array_with_opts(
        n00b_plan_predicate_list_t *,
        branches == 0 ? 1 : branches,
        &(n00b_alloc_opts_t){.allocator = ctx->allocator});

    for (size_t b = 0; b < branches; b++) {
        conjuncts[b] = rocs_rw_conjuncts(ctx, n00b_list_get(*children, b));
        if (n00b_list_len(*conjuncts[b]) > ROCS_REWRITE_PAIRWISE_MAX) {
            return nullptr;
        }
    }

    n00b_plan_predicate_t *best   = nullptr;
    size_t                 best_n = 0;

    for (size_t b = 0; b < branches; b++) {
        size_t conj_len = n00b_list_len(*conjuncts[b]);

        for (size_t i = 0; i < conj_len; i++) {
            n00b_plan_predicate_t *candidate = n00b_list_get(*conjuncts[b], i);

            size_t share = 0;
            for (size_t o = 0; o < branches; o++) {
                size_t other_len = n00b_list_len(*conjuncts[o]);
                for (size_t j = 0; j < other_len; j++) {
                    if (rocs_rw_pred_eq(ctx,
                                        candidate,
                                        n00b_list_get(*conjuncts[o], j))) {
                        share++;
                        break;
                    }
                }
            }

            if (share > best_n) {
                best   = candidate;
                best_n = share;
            }
        }
    }

    if (best == nullptr || best_n < 2) {
        return nullptr;
    }

    for (size_t b = 0; b < branches; b++) {
        size_t conj_len = n00b_list_len(*conjuncts[b]);
        in_branch[b]    = false;
        for (size_t j = 0; j < conj_len && !in_branch[b]; j++) {
            in_branch[b] = rocs_rw_pred_eq(ctx,
                                           best,
                                           n00b_list_get(*conjuncts[b], j));
        }
    }

    *share_out = best_n;
    return best;
}

static n00b_plan_predicate_t *
rocs_rw_or_factor(rocs_rw_ctx_t              *ctx,
                  n00b_plan_predicate_list_t *children)
{
    size_t branches = n00b_list_len(*children);
    if (branches < 2) {
        return nullptr;
    }

    n00b_plan_predicate_list_t *first =
        rocs_rw_conjuncts(ctx, n00b_list_get(*children, 0));
    size_t first_len = n00b_list_len(*first);
    if (first_len > ROCS_REWRITE_PAIRWISE_MAX) {
        return nullptr;
    }

    n00b_plan_predicate_list_t *common = rocs_rw_list(ctx);
    for (size_t i = 0; i < first_len; i++) {
        n00b_plan_predicate_t *candidate = n00b_list_get(*first, i);
        bool                   in_all    = true;

        for (size_t b = 1; b < branches && in_all; b++) {
            n00b_plan_predicate_list_t *conj =
                rocs_rw_conjuncts(ctx, n00b_list_get(*children, b));
            size_t conj_len = n00b_list_len(*conj);
            if (conj_len > ROCS_REWRITE_PAIRWISE_MAX) {
                return nullptr;
            }

            bool found = false;
            for (size_t j = 0; j < conj_len && !found; j++) {
                found = rocs_rw_pred_eq(ctx, candidate, n00b_list_get(*conj, j));
            }
            in_all = found;
        }

        if (in_all) {
            (void)n00b_plan_predicate_list_append(common, candidate);
        }
    }

    if (n00b_list_len(*common) == 0) {
        return rocs_rw_or_factor_partial(ctx, children);
    }

    n00b_plan_predicate_list_t *residuals = rocs_rw_list(ctx);
    for (size_t b = 0; b < branches; b++) {
        n00b_plan_predicate_list_t *conj =
            rocs_rw_conjuncts(ctx, n00b_list_get(*children, b));
        size_t conj_len = n00b_list_len(*conj);

        n00b_plan_predicate_list_t *rest = rocs_rw_list(ctx);
        for (size_t j = 0; j < conj_len; j++) {
            n00b_plan_predicate_t *member = n00b_list_get(*conj, j);
            bool                   shared = false;
            size_t                 common_len = n00b_list_len(*common);
            for (size_t k = 0; k < common_len && !shared; k++) {
                shared = rocs_rw_pred_eq(ctx, member, n00b_list_get(*common, k));
            }
            if (!shared) {
                (void)n00b_plan_predicate_list_append(rest, member);
            }
        }

        n00b_plan_predicate_t *residual = rocs_rw_group(ctx,
                                                        N00B_PLAN_PREDICATE_AND,
                                                        rest);
        if (residual == nullptr) {
            return nullptr;
        }
        (void)n00b_plan_predicate_list_append(residuals, residual);
    }

    n00b_plan_predicate_t *disjunction = rocs_rw_group(ctx,
                                                       N00B_PLAN_PREDICATE_OR,
                                                       residuals);
    if (disjunction == nullptr) {
        return nullptr;
    }
    if (disjunction->kind != N00B_PLAN_PREDICATE_TRUE) {
        (void)n00b_plan_predicate_list_append(common, disjunction);
    }

    ctx->changed = true;
    return rocs_rw_group(ctx, N00B_PLAN_PREDICATE_AND, common);
}

// One conjunct, hoisted over the branches that share it.
//
// Rebuilds the disjunction as
//
//     OR( AND(shared, OR(residual...)), untouched... )
//
// where the residuals come from the branches that carried the shared conjunct
// and the untouched branches are copied across. Every branch appears exactly
// once on each side, so this is the distributive law applied to a subset.
static n00b_plan_predicate_t *
rocs_rw_or_factor_partial(rocs_rw_ctx_t              *ctx,
                          n00b_plan_predicate_list_t *children)
{
    size_t branches = n00b_list_len(*children);
    if (branches < 3 || branches > ROCS_REWRITE_PAIRWISE_MAX) {
        // With two branches, a conjunct shared by two is shared by all, and
        // the full hoist above already took it.
        return nullptr;
    }

    bool *in_branch = n00b_alloc_array_with_opts(
        bool, branches,
        &(n00b_alloc_opts_t){.allocator = ctx->allocator,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});

    size_t                 share  = 0;
    n00b_plan_predicate_t *shared = rocs_rw_or_widest_common(ctx,
                                                             children,
                                                             in_branch,
                                                             &share);
    if (shared == nullptr || share >= branches) {
        // Shared by every branch is the full hoist's business, and it already
        // declined, so there is nothing here.
        return nullptr;
    }

    n00b_plan_predicate_list_t *residuals = rocs_rw_list(ctx);
    n00b_plan_predicate_list_t *untouched = rocs_rw_list(ctx);

    for (size_t b = 0; b < branches; b++) {
        n00b_plan_predicate_t *branch = n00b_list_get(*children, b);
        if (!in_branch[b]) {
            (void)n00b_plan_predicate_list_append(untouched, branch);
            continue;
        }

        n00b_plan_predicate_list_t *conj = rocs_rw_conjuncts(ctx, branch);
        size_t                      len  = n00b_list_len(*conj);
        n00b_plan_predicate_list_t *rest = rocs_rw_list(ctx);
        for (size_t j = 0; j < len; j++) {
            n00b_plan_predicate_t *member = n00b_list_get(*conj, j);
            if (!rocs_rw_pred_eq(ctx, member, shared)) {
                (void)n00b_plan_predicate_list_append(rest, member);
            }
        }

        n00b_plan_predicate_t *residual = rocs_rw_group(ctx,
                                                        N00B_PLAN_PREDICATE_AND,
                                                        rest);
        if (residual == nullptr) {
            return nullptr;
        }
        (void)n00b_plan_predicate_list_append(residuals, residual);
    }

    n00b_plan_predicate_t *inner = rocs_rw_group(ctx,
                                                 N00B_PLAN_PREDICATE_OR,
                                                 residuals);
    if (inner == nullptr) {
        return nullptr;
    }

    n00b_plan_predicate_list_t *hoisted = rocs_rw_list(ctx);
    (void)n00b_plan_predicate_list_append(hoisted, shared);
    if (inner->kind != N00B_PLAN_PREDICATE_TRUE) {
        (void)n00b_plan_predicate_list_append(hoisted, inner);
    }

    n00b_plan_predicate_t *factored = rocs_rw_group(ctx,
                                                    N00B_PLAN_PREDICATE_AND,
                                                    hoisted);
    if (factored == nullptr) {
        return nullptr;
    }

    (void)n00b_plan_predicate_list_append(untouched, factored);

    ctx->changed = true;
    return rocs_rw_group(ctx, N00B_PLAN_PREDICATE_OR, untouched);
}

static n00b_plan_predicate_t *
rocs_rw_or(rocs_rw_ctx_t *ctx, n00b_plan_predicate_t *predicate)
{
    n00b_plan_predicate_list_t *flat = rocs_rw_list(ctx);
    if (!rocs_rw_flatten_into(ctx, flat, predicate, N00B_PLAN_PREDICATE_OR)) {
        return predicate;
    }

    n00b_plan_predicate_list_t *kept = rocs_rw_list(ctx);
    size_t                      len  = n00b_list_len(*flat);
    for (size_t i = 0; i < len; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*flat, i);
        if (child->kind == N00B_PLAN_PREDICATE_TRUE) {
            ctx->changed = true;
            return rocs_rw_true(ctx);
        }
        if (child->kind == N00B_PLAN_PREDICATE_FALSE) {
            ctx->changed = true;
            continue;
        }
        (void)n00b_plan_predicate_list_append(kept, child);
    }

    len = n00b_list_len(*kept);
    if (len <= ROCS_REWRITE_PAIRWISE_MAX) {
        n00b_plan_predicate_list_t *unique = rocs_rw_list(ctx);
        for (size_t i = 0; i < len; i++) {
            n00b_plan_predicate_t *child = n00b_list_get(*kept, i);
            bool                   drop  = false;

            for (size_t j = 0; j < i; j++) {
                if (rocs_rw_pred_eq(ctx, child, n00b_list_get(*kept, j))) {
                    drop = true;
                    break;
                }
            }
            for (size_t j = 0; !drop && j < len; j++) {
                if (j != i
                    && rocs_rw_is_negation(ctx,
                                           child,
                                           n00b_list_get(*kept, j))) {
                    ctx->changed = true;
                    return rocs_rw_true(ctx);
                }
            }

            if (drop) {
                ctx->changed = true;
                continue;
            }
            (void)n00b_plan_predicate_list_append(unique, child);
        }
        kept = unique;

        if (rocs_rw_negation_subsumed(ctx, kept, N00B_PLAN_PREDICATE_OR)) {
            ctx->changed = true;
            return rocs_rw_true(ctx);
        }

        n00b_plan_predicate_t *factored = rocs_rw_or_factor(ctx, kept);
        if (factored != nullptr) {
            return factored;
        }
    }

    n00b_plan_predicate_list_t *unioned = rocs_rw_or_merge_ranges(ctx, kept);
    if (unioned != nullptr) {
        kept = unioned;
    }

    n00b_plan_predicate_list_t *collapsed = rocs_rw_or_collapse_eq(ctx, kept);
    if (collapsed != nullptr) {
        kept = collapsed;
    }

    if (rocs_rw_members_unchanged(predicate->children, kept)) {
        return predicate;
    }
    return rocs_rw_group(ctx, N00B_PLAN_PREDICATE_OR, kept);
}

// ---------------------------------------------------------------------------

static n00b_plan_predicate_t *
rocs_rw_not(rocs_rw_ctx_t *ctx, n00b_plan_predicate_t *predicate)
{
    n00b_plan_predicate_t *child = predicate->child;
    if (child == nullptr) {
        return predicate;
    }

    switch (child->kind) {
    case N00B_PLAN_PREDICATE_NOT:
        if (child->child != nullptr) {
            ctx->changed = true;
            return child->child;
        }
        return predicate;

    case N00B_PLAN_PREDICATE_FALSE:
        ctx->changed = true;
        return rocs_rw_true(ctx);

    case N00B_PLAN_PREDICATE_TRUE:
        ctx->changed = true;
        return rocs_rw_false(ctx);

    default:
        break;
    }

    if (child == predicate->child) {
        return predicate;
    }

    auto r = n00b_plan_predicate_not(child, .allocator = ctx->allocator);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : predicate;
}

// Children first, then the node, so every rule sees operands that are already
// as folded as they are going to get on this round.
static n00b_plan_predicate_t *
rocs_rw_predicate(rocs_rw_ctx_t *ctx, n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return nullptr;
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
    case N00B_PLAN_PREDICATE_FALSE:
    case N00B_PLAN_PREDICATE_TRUE:
        return predicate;

    case N00B_PLAN_PREDICATE_NOT: {
        n00b_plan_predicate_t *child = rocs_rw_predicate(ctx,
                                                         predicate->child);
        if (child == nullptr) {
            return predicate;
        }
        if (child != predicate->child) {
            auto r = n00b_plan_predicate_not(child,
                                             .allocator = ctx->allocator);
            if (n00b_result_is_err(r)) {
                return predicate;
            }
            predicate = n00b_result_get(r);
        }
        return rocs_rw_not(ctx, predicate);
    }

    case N00B_PLAN_PREDICATE_AND:
    case N00B_PLAN_PREDICATE_OR: {
        if (predicate->children == nullptr) {
            return predicate;
        }

        n00b_plan_predicate_list_t *rewritten = rocs_rw_list(ctx);
        size_t                      len = n00b_list_len(*predicate->children);
        bool                        any = false;
        for (size_t i = 0; i < len; i++) {
            n00b_plan_predicate_t *child =
                n00b_list_get(*predicate->children, i);
            n00b_plan_predicate_t *next = rocs_rw_predicate(ctx, child);
            if (next == nullptr) {
                return predicate;
            }
            any = any || next != child;
            (void)n00b_plan_predicate_list_append(rewritten, next);
        }

        if (any) {
            n00b_plan_predicate_t *rebuilt = rocs_rw_group(ctx,
                                                           predicate->kind,
                                                           rewritten);
            if (rebuilt == nullptr) {
                return predicate;
            }
            predicate = rebuilt;
            // Folding a child can leave something that is not a group.
            if (predicate->kind != N00B_PLAN_PREDICATE_AND
                && predicate->kind != N00B_PLAN_PREDICATE_OR) {
                return predicate;
            }
        }

        return predicate->kind == N00B_PLAN_PREDICATE_AND
                 ? rocs_rw_and(ctx, predicate)
                 : rocs_rw_or(ctx, predicate);
    }
    }

    return predicate;
}

// Whether the pass rewrites at all.
//
// A control arm, in the same shape as the cost model's ROCS_PLAN_NO_COST and
// the zone map's ROCS_NO_ZONE_MAPS. Off, every rewrite below is skipped and
// the planner sees the predicate exactly as it was written, which is the only
// way to measure what the rewriting is worth end to end: n00b_plan_build's
// `rewrite` keyword covers one call site, and the fan-out rewrites before it
// on another.
//
// It cannot change an answer. Every rule here is an equivalence, so skipping
// them all costs work and never correctness.
static _Atomic(int) rocs_rewrite_state = -1;

bool
n00b_plan_rewrite_enabled(void)
{
    int state = atomic_load_explicit(&rocs_rewrite_state,
                                     memory_order_relaxed);
    if (state < 0) {
        state = getenv("ROCS_PLAN_NO_REWRITE") != nullptr ? 0 : 1;
        atomic_store_explicit(&rocs_rewrite_state,
                              state,
                              memory_order_relaxed);
    }
    return state != 0;
}

void
n00b_plan_rewrite_set_enabled(bool enabled)
{
    atomic_store_explicit(&rocs_rewrite_state,
                          enabled ? 1 : 0,
                          memory_order_relaxed);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_rewrite(n00b_plan_predicate_t *predicate) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }
    if (!n00b_plan_rewrite_enabled()) {
        return n00b_result_ok(n00b_plan_predicate_t *, predicate);
    }

    rocs_rw_ctx_t ctx = {.allocator = allocator};

    uint32_t round = 0;
    for (; round < ROCS_REWRITE_MAX_ROUNDS; round++) {
        ctx.changed                 = false;
        n00b_plan_predicate_t *next = rocs_rw_predicate(&ctx, predicate);
        if (next == nullptr) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_PLAN_ERR_STATE);
        }
        predicate = next;
        if (!ctx.changed) {
            break;
        }
    }

    // Reaching the cap means some rule no longer decreases the measure above.
    // The result is still correct, because every rule is an equivalence
    // however many times it runs; it is merely less rewritten than it should
    // be, which is exactly the kind of thing that goes unnoticed. The
    // fixpoint property test drives random trees through here, so this fires
    // in the suite rather than in production.
    n00b_assert(round < ROCS_REWRITE_MAX_ROUNDS);

    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

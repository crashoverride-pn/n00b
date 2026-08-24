/*
 * The record interpreter, and the tactics only a running query can choose.
 *
 * The split with plan.c is not "indexes there, records here": this file reads
 * indexes too. It is that plan.c decides from counts collected once per shard,
 * and this file decides from what the query has accumulated by the time a node
 * runs, which the planner cannot know. Unbounded work lives here, which is why
 * the cancel callback is threaded through these entry points and not through
 * planning.
 *
 * Adaptive execution
 * ------------------
 *
 * Node order inside a group is NOT re-decided here. The planner set it from
 * counts on this shard (plan.h rule 4), and a second implementation here would
 * be free to disagree with it. Four things are decided here instead, each one
 * re-taken per node on every run:
 *
 *   1. Probe an index, or walk its postings.
 *   2. Skip a lossy scan whose term already covers the shard.
 *   3. Order a group's predicate leaves cheapest-first.
 *   4. Stop a group once its answer can no longer change.
 *
 * (1) is the one that pays. An INTERSECT accumulates, so each child narrows
 * what the next child sees, and the same leaf wants opposite tactics depending
 * on how much is left in play:
 *
 *     AND( trace = "abc123", level = "info" )     hot shard, 100000 records
 *                                                 df 3          df 60000
 *
 *     acc = universe                      100000 candidates
 *       |
 *       |   trace = "abc123"    probe refused, 100000 * 17 >= 100000
 *       |                       walk  3 * 10 = 30
 *       v
 *     acc                                      3 candidates
 *       |
 *       |   level = "info"      probe 3 * 1 * 16 * 20 =    960   <- chosen
 *       |                       walk  60000 * 10      = 600000
 *       v
 *     acc                                     <= 3 candidates
 *
 * Run the same two leaves in the other order and the broad one meets the full
 * universe, where a probe is refused and its 60000 postings are walked: same
 * answer, at 600030 units of walking instead of 30 of walking and 960 of
 * searching. The
 * planner is what puts the narrow child first. This file is what notices that
 * the second leaf now has only three ordinals to test.
 *
 * The cost model, its units, and both formulas live in plan.h. Nothing here
 * decides what a number means; it reads the numbers and applies the verdict.
 *
 * Supporting machinery, none of which changes an answer:
 *
 *   . Posting counts are memoized per node for the life of one execution
 *     (df_cache, ROCS_DF_CACHE_MAX). Reading a count is a dict probe and a
 *     field load, and a node is visited once per group pass.
 *   . A group's leaf ordering is a function of its predicate alone, so it is
 *     settled once per scan rather than once per record tested
 *     (ROCS_ORDER_MAX, ROCS_ORDER_CACHE_MAX).
 *   . An INTERSECT runs children that read no records before those that do,
 *     so a record scan inherits everything the indexes already ruled out.
 *     That follows from the node kinds, not from any count, which is why it
 *     is here and not in the planner.
 *   . An INTERSECT returns as soon as its accumulator is empty; a UNION
 *     returns as soon as it covers every candidate still in play.
 *
 * With cost disabled (ROCS_PLAN_NO_COST, or n00b_plan_cost_set_enabled), 1
 * through 3 do not happen and every group runs in the order the query wrote
 * it. 4 still applies: stopping early is not an ordering choice.
 */
#include "internal/rocs/plan.h"
#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "internal/rocs/index.h"
#include "internal/rocs/json_field.h"
#include "internal/rocs/store.h"
#include "rocs/map.h"
#include "rocs/normalizer.h"
#include "text/strings/string_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum : int32_t {
    _rocs_plan_scan_src_hot,
    _rocs_plan_scan_src_mapped,
} _rocs_plan_scan_source_t;

// A group's evaluation order is a function of its predicate and nothing else,
// so it is settled once for a scan rather than once for every record the scan
// tests. One entry per group, never one buffer shared between them: a group
// whose children include another group evaluates that one in the middle of its
// own loop, and a shared buffer would be rewritten under the outer loop, which
// would then index its children by the inner group's permutation.
#define ROCS_ORDER_MAX       64
#define ROCS_ORDER_CACHE_MAX 16

typedef struct {
    n00b_plan_predicate_t *predicate;
    uint16_t               order[ROCS_ORDER_MAX];
    bool                   usable;
} _rocs_plan_order_entry_t;

typedef struct {
    _rocs_plan_scan_source_t source;
    n00b_store_shard_t        *hot_shard;
    n00b_store_map_shard_t    *mapped_shard;
    uint64_t                   record_count;
    n00b_allocator_t          *allocator;
    n00b_plan_cancel_fn        cancel_cb;
    void                      *cancel_ctx;
    // Bounded: a group past the bound orders into the caller's scratch, so
    // the bound costs repeated work and never order.
    _rocs_plan_order_entry_t   order_cache[ROCS_ORDER_CACHE_MAX];
    size_t                     order_cached;
} _rocs_plan_scan_ctx_t;

// The indices to evaluate `predicate`'s children in, cheapest first, or nullptr
// to walk in plan order.
//
// Answered from the scan's cache when this group has been ordered already,
// which is every record after the first. `scratch` is the caller's own storage
// and is used only when the cache is full; the returned pointer is either that
// scratch or an entry belonging to this group alone, so an enclosing loop's
// order survives a nested group being ordered mid-walk.
static const uint16_t *
_rocs_plan_group_order(_rocs_plan_scan_ctx_t *ctx,
                       n00b_plan_predicate_t *predicate,
                       size_t                 len,
                       uint16_t              *scratch)
{
    if (len < 2 || len > ROCS_ORDER_MAX || !n00b_plan_cost_enabled()) {
        return nullptr;
    }

    for (size_t i = 0; i < ctx->order_cached; i++) {
        if (ctx->order_cache[i].predicate == predicate) {
            return ctx->order_cache[i].usable ? ctx->order_cache[i].order
                                              : nullptr;
        }
    }

    if (ctx->order_cached == ROCS_ORDER_CACHE_MAX) {
        return n00b_plan_cost_order_children(predicate, scratch,
                                             ROCS_ORDER_MAX)
                    == len
                 ? scratch
                 : nullptr;
    }

    _rocs_plan_order_entry_t *entry = &ctx->order_cache[ctx->order_cached++];
    entry->predicate                = predicate;
    entry->usable = n00b_plan_cost_order_children(predicate, entry->order,
                                                  ROCS_ORDER_MAX)
                 == len;
    return entry->usable ? entry->order : nullptr;
}

static n00b_result_t(bool)
_rocs_plan_eval_predicate(_rocs_plan_scan_ctx_t *ctx,
                          n00b_plan_predicate_t   *predicate,
                          n00b_json_node_t        *record);

static n00b_result_t(bool)
_rocs_plan_json_equal(_rocs_plan_scan_ctx_t *ctx,
                      n00b_json_node_t        *left,
                      n00b_json_node_t        *right)
{
    if (left == nullptr || right == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    n00b_json_type_t left_type  = n00b_json_type(left);
    n00b_json_type_t right_type = n00b_json_type(right);
    if (left_type != right_type) {
        return n00b_result_ok(bool, false);
    }

    switch (left_type) {
    case N00B_JSON_NULL:
        return n00b_result_ok(bool, true);
    case N00B_JSON_BOOL:
        return n00b_result_ok(bool,
                              n00b_json_as_bool(left)
                                  == n00b_json_as_bool(right));
    case N00B_JSON_INT:
        return n00b_result_ok(bool,
                              n00b_json_as_i64(left)
                                  == n00b_json_as_i64(right));
    case N00B_JSON_DOUBLE: {
        double l = n00b_json_as_f64(left);
        double r = n00b_json_as_f64(right);
        return n00b_result_ok(bool, l == r);
    }
    case N00B_JSON_STRING: {
        n00b_string_t *l = n00b_json_as_string(left);
        n00b_string_t *r = n00b_json_as_string(right);
        return n00b_result_ok(bool,
                              l != nullptr && r != nullptr
                                  && n00b_unicode_str_eq(l, r));
    }
    case N00B_JSON_ARRAY: {
        size_t len = n00b_json_array_len(left);
        if (len != n00b_json_array_len(right)) {
            return n00b_result_ok(bool, false);
        }
        for (size_t i = 0; i < len; i++) {
            auto item_r =
                _rocs_plan_json_equal(ctx,
                                      n00b_json_array_get(left, i),
                                      n00b_json_array_get(right, i));
            if (n00b_result_is_err(item_r) || !n00b_result_get(item_r)) {
                return item_r;
            }
        }
        return n00b_result_ok(bool, true);
    }
    case N00B_JSON_OBJECT: {
        if (n00b_json_length(left) != n00b_json_length(right)) {
            return n00b_result_ok(bool, false);
        }

        auto entries_r =
            n00b_json_object_entries(left, .allocator = ctx->allocator);
        if (n00b_result_is_err(entries_r)) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }

        n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
        size_t                         len     = n00b_list_len(*entries);
        for (size_t i = 0; i < len; i++) {
            n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
            if (entry == nullptr || entry->key == nullptr
                || entry->value == nullptr) {
                return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
            }

            n00b_json_node_t *other =
                n00b_json_object_get(right, entry->key);
            if (other == nullptr) {
                return n00b_result_ok(bool, false);
            }

            auto item_r = _rocs_plan_json_equal(ctx, entry->value, other);
            if (n00b_result_is_err(item_r) || !n00b_result_get(item_r)) {
                return item_r;
            }
        }

        return n00b_result_ok(bool, true);
    }
    }

    return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
}

static bool
_rocs_plan_json_numeric(n00b_json_node_t *node, double *out)
{
    if (node == nullptr || out == nullptr) {
        return false;
    }
    if (n00b_json_is_int(node)) {
        *out = (double)n00b_json_as_i64(node);
        return true;
    }
    if (n00b_json_is_double(node)) {
        double value = n00b_json_as_f64(node);
        if (value != value) {
            return false;
        }
        *out = value;
        return true;
    }
    return false;
}

static n00b_result_t(bool)
_rocs_plan_json_order_cmp(n00b_json_node_t *value,
                          n00b_json_node_t *bound,
                          int32_t          *cmp)
{
    if (value == nullptr || bound == nullptr || cmp == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    if (n00b_json_is_int(value) && n00b_json_is_int(bound)) {
        int64_t l = n00b_json_as_i64(value);
        int64_t r = n00b_json_as_i64(bound);
        *cmp = l < r ? -1 : (l > r ? 1 : 0);
        return n00b_result_ok(bool, true);
    }

    double lv = 0.0;
    double rv = 0.0;
    if (_rocs_plan_json_numeric(value, &lv)
        && _rocs_plan_json_numeric(bound, &rv)) {
        *cmp = lv < rv ? -1 : (lv > rv ? 1 : 0);
        return n00b_result_ok(bool, true);
    }

    if (n00b_json_is_string(value) && n00b_json_is_string(bound)) {
        n00b_string_t *l = n00b_json_as_string(value);
        n00b_string_t *r = n00b_json_as_string(bound);
        if (l == nullptr || r == nullptr) {
            return n00b_result_ok(bool, false);
        }
        int raw = n00b_unicode_str_cmp(l, r);
        *cmp = raw < 0 ? -1 : (raw > 0 ? 1 : 0);
        return n00b_result_ok(bool, true);
    }

    return n00b_result_ok(bool, false);
}

static n00b_result_t(bool)
_rocs_plan_json_range_match(n00b_json_node_t        *value,
                            n00b_plan_predicate_t  *predicate)
{
    auto lower_r = _rocs_plan_value_node(predicate->lower);
    if (n00b_result_is_err(lower_r)) {
        return n00b_result_err(bool, n00b_result_get_err(lower_r));
    }
    auto upper_r = _rocs_plan_value_node(predicate->upper);
    if (n00b_result_is_err(upper_r)) {
        return n00b_result_err(bool, n00b_result_get_err(upper_r));
    }

    int32_t lower_cmp = 0;
    auto    lower_order_r =
        _rocs_plan_json_order_cmp(value, n00b_result_get(lower_r), &lower_cmp);
    if (n00b_result_is_err(lower_order_r) || !n00b_result_get(lower_order_r)) {
        return lower_order_r;
    }

    int32_t upper_cmp = 0;
    auto    upper_order_r =
        _rocs_plan_json_order_cmp(value, n00b_result_get(upper_r), &upper_cmp);
    if (n00b_result_is_err(upper_order_r) || !n00b_result_get(upper_order_r)) {
        return upper_order_r;
    }

    bool above_lower = predicate->include_lower ? lower_cmp >= 0
                                                : lower_cmp > 0;
    bool below_upper = predicate->include_upper ? upper_cmp <= 0
                                                : upper_cmp < 0;
    return n00b_result_ok(bool, above_lower && below_upper);
}

static n00b_result_t(n00b_option_t(n00b_json_node_t *))
_rocs_plan_field_value(n00b_json_node_t    *record,
                       n00b_plan_target_t  *target)
{
    if (record == nullptr || target == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                               N00B_PLAN_ERR_STATE);
    }
    if (target->kind != N00B_PLAN_TARGET_FIELD || target->field == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                               N00B_PLAN_ERR_STATE);
    }
    if (!n00b_json_is_object(record)) {
        return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                              n00b_option_none(n00b_json_node_t *));
    }

    n00b_json_node_t *field =
        rocs_json_object_get_field(record, target->field);
    if (field == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                              n00b_option_none(n00b_json_node_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                          n00b_option_set(n00b_json_node_t *, field));
}

static n00b_result_t(n00b_option_t(n00b_json_node_t *))
_rocs_plan_path_resolve(n00b_json_node_t *root, n00b_plan_path_t *path)
{
    if (root == nullptr || path == nullptr || path->components == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                               N00B_PLAN_ERR_STATE);
    }

    n00b_json_node_t *current = root;
    size_t            len     = n00b_list_len(*path->components);
    for (size_t i = 0; i < len; i++) {
        n00b_plan_path_component_t *component =
            n00b_list_get(*path->components, i);
        if (!_rocs_plan_path_component_is_valid(component)) {
            return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                                   N00B_PLAN_ERR_STATE);
        }

        switch (component->kind) {
        case N00B_PLAN_PATH_KEY:
            if (!n00b_json_is_object(current)) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            current = n00b_json_object_get(current, component->key);
            if (current == nullptr) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            break;
        case N00B_PLAN_PATH_INDEX:
            if (!n00b_json_is_array(current)
                || component->index > (uint64_t)SIZE_MAX) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            current = n00b_json_array_get(current, (size_t)component->index);
            if (current == nullptr) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            break;
        }
    }

    return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                          n00b_option_set(n00b_json_node_t *, current));
}

static n00b_err_t
_rocs_plan_norm_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_NORM_ERR_ARG:
        return N00B_PLAN_ERR_ARG;
    case N00B_STORE_NORM_ERR_TYPE:
    case N00B_STORE_NORM_ERR_NUMERIC:
    case N00B_STORE_NORM_ERR_STATE:
    default:
        return N00B_PLAN_ERR_STATE;
    }
}

static n00b_result_t(n00b_store_normalized_list_t *)
_rocs_plan_tokens_from_string(n00b_string_t *text,
                              n00b_allocator_t *allocator)
{
    if (text == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_PLAN_ERR_STATE);
    }

    n00b_json_node_t *node =
        n00b_json_string_new_from_n00b(text, .allocator = allocator);
    if (node == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_PLAN_ERR_STATE);
    }

    auto tokens_r =
        n00b_store_normalize_text_tokens(node, .allocator = allocator);
    if (n00b_result_is_err(tokens_r)) {
        return n00b_result_err(
            n00b_store_normalized_list_t *,
            _rocs_plan_norm_err(n00b_result_get_err(tokens_r)));
    }
    return tokens_r;
}

static n00b_result_t(n00b_string_t *)
_rocs_plan_term_string(n00b_store_normalized_t *term)
{
    if (term == nullptr || term->value == nullptr
        || !n00b_json_is_string(term->value)) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_string_t *s = n00b_json_as_string(term->value);
    if (s == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_string_t *, s);
}

static n00b_result_t(bool)
_rocs_plan_string_contains_token(_rocs_plan_scan_ctx_t *ctx,
                                 n00b_string_t           *haystack,
                                 n00b_string_t           *needle)
{
    if (ctx == nullptr || haystack == nullptr || needle == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    auto needle_tokens_r =
        _rocs_plan_tokens_from_string(needle, ctx->allocator);
    if (n00b_result_is_err(needle_tokens_r)) {
        return n00b_result_err(bool, n00b_result_get_err(needle_tokens_r));
    }

    n00b_store_normalized_list_t *needle_tokens =
        n00b_result_get(needle_tokens_r);
    size_t needle_len = n00b_list_len(*needle_tokens);
    if (needle_len == 0) {
        return n00b_result_ok(bool, false);
    }

    auto haystack_tokens_r =
        _rocs_plan_tokens_from_string(haystack, ctx->allocator);
    if (n00b_result_is_err(haystack_tokens_r)) {
        return n00b_result_err(bool, n00b_result_get_err(haystack_tokens_r));
    }

    n00b_store_normalized_list_t *haystack_tokens =
        n00b_result_get(haystack_tokens_r);
    size_t haystack_len = n00b_list_len(*haystack_tokens);

    auto full_needle_r =
        _rocs_plan_term_string(n00b_list_get(*needle_tokens, 0));
    if (n00b_result_is_err(full_needle_r)) {
        return n00b_result_err(bool, n00b_result_get_err(full_needle_r));
    }
    n00b_string_t *full_needle = n00b_result_get(full_needle_r);
    for (size_t i = 0; i < haystack_len; i++) {
        auto token_r = _rocs_plan_term_string(n00b_list_get(*haystack_tokens, i));
        if (n00b_result_is_err(token_r)) {
            return n00b_result_err(bool, n00b_result_get_err(token_r));
        }
        if (n00b_unicode_str_eq(n00b_result_get(token_r), full_needle)) {
            return n00b_result_ok(bool, true);
        }
    }

    if (needle_len == 1) {
        return n00b_result_ok(bool, false);
    }

    for (size_t needle_i = 1; needle_i < needle_len; needle_i++) {
        auto needle_r =
            _rocs_plan_term_string(n00b_list_get(*needle_tokens, needle_i));
        if (n00b_result_is_err(needle_r)) {
            return n00b_result_err(bool, n00b_result_get_err(needle_r));
        }
        n00b_string_t *needle_token = n00b_result_get(needle_r);
        bool          found        = false;
        for (size_t hay_i = 0; hay_i < haystack_len; hay_i++) {
            auto token_r =
                _rocs_plan_term_string(n00b_list_get(*haystack_tokens, hay_i));
            if (n00b_result_is_err(token_r)) {
                return n00b_result_err(bool, n00b_result_get_err(token_r));
            }
            if (n00b_unicode_str_eq(n00b_result_get(token_r), needle_token)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return n00b_result_ok(bool, false);
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
_rocs_plan_json_string_contains_token(_rocs_plan_scan_ctx_t *ctx,
                                      n00b_json_node_t        *node,
                                      n00b_string_t           *needle)
{
    if (node == nullptr || needle == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    if (!n00b_json_is_string(node)) {
        return n00b_result_ok(bool, false);
    }

    n00b_string_t *s = n00b_json_as_string(node);
    if (s == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    return _rocs_plan_string_contains_token(ctx, s, needle);
}

#ifdef N00B_DEBUG
// Cost units spent on leaves actually evaluated. Ordering claims to reduce
// exactly this, so it is what a test should assert on: counting evaluations
// instead would stay flat, since reordering a conjunction trades an expensive
// evaluation for a cheap one rather than removing one.
static _Atomic(uint64_t) rocs_predicate_cost_spent = 0;

uint64_t
n00b_plan_predicate_cost_spent(void)
{
    return atomic_load_explicit(&rocs_predicate_cost_spent,
                                memory_order_relaxed);
}

void
n00b_plan_predicate_cost_spent_reset(void)
{
    atomic_store_explicit(&rocs_predicate_cost_spent, 0, memory_order_relaxed);
}
#endif

static n00b_result_t(bool)
_rocs_plan_eval_leaf(_rocs_plan_scan_ctx_t *ctx,
                     n00b_plan_predicate_t   *predicate,
                     n00b_json_node_t        *record)
{
    if (predicate == nullptr || predicate->target == nullptr
        || record == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    n00b_plan_target_t *target = predicate->target;

    if (predicate->leaf_op == N00B_PLAN_LEAF_CONTAINS
        && target->kind == N00B_PLAN_TARGET_ANY) {
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        return n00b_result_ok(bool, false);
    }
    if (target->kind != N00B_PLAN_TARGET_FIELD) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    auto field_r = _rocs_plan_field_value(record, target);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(bool, n00b_result_get_err(field_r));
    }

    n00b_option_t(n00b_json_node_t *) field_opt = n00b_result_get(field_r);
    bool field_present = n00b_option_is_set(field_opt);
    n00b_json_node_t *field =
        field_present ? n00b_option_get(field_opt) : nullptr;

#ifdef N00B_DEBUG
    atomic_fetch_add_explicit(&rocs_predicate_cost_spent,
                              n00b_plan_cost_predicate(predicate),
                              memory_order_relaxed);
#endif

    switch (predicate->leaf_op) {
    case N00B_PLAN_LEAF_EQ: {
        auto value_r = _rocs_plan_value_node(predicate->value);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_err(bool, n00b_result_get_err(value_r));
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        return _rocs_plan_json_equal(ctx, field, n00b_result_get(value_r));
    }
    case N00B_PLAN_LEAF_IN: {
        if (predicate->values == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->values);
        if (len == 0) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }

        for (size_t i = 0; i < len; i++) {
            auto value_r =
                _rocs_plan_value_node(n00b_list_get(*predicate->values, i));
            if (n00b_result_is_err(value_r)) {
                return n00b_result_err(bool, n00b_result_get_err(value_r));
            }
            auto equal_r =
                _rocs_plan_json_equal(ctx, field, n00b_result_get(value_r));
            if (n00b_result_is_err(equal_r) || n00b_result_get(equal_r)) {
                return equal_r;
            }
        }
        return n00b_result_ok(bool, false);
    }
    case N00B_PLAN_LEAF_RANGE:
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        return _rocs_plan_json_range_match(field, predicate);

    case N00B_PLAN_LEAF_EXISTS:
        return n00b_result_ok(bool, field_present);

    case N00B_PLAN_LEAF_CONTAINS:
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        return _rocs_plan_json_string_contains_token(ctx,
                                                    field,
                                                    predicate->text);

    case N00B_PLAN_LEAF_SUBSTRING: {
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present || !n00b_json_is_string(field)) {
            return n00b_result_ok(bool, false);
        }
        n00b_string_t *s = n00b_json_as_string(field);
        // Gram containment cannot show the grams were contiguous, so the
        // literal is looked for here.
        return n00b_result_ok(bool,
                              s != nullptr
                                  && n00b_unicode_str_contains(s,
                                                               predicate->text));
    }

    case N00B_PLAN_LEAF_PREFIX: {
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present || !n00b_json_is_string(field)) {
            return n00b_result_ok(bool, false);
        }
        n00b_string_t *s = n00b_json_as_string(field);
        return n00b_result_ok(bool,
                              s != nullptr
                                  && n00b_unicode_str_starts_with(s,
                                                                  predicate->text));
    }
    case N00B_PLAN_LEAF_REGEX: {
        if (predicate->regex == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present || !n00b_json_is_string(field)) {
            return n00b_result_ok(bool, false);
        }
        n00b_string_t *s = n00b_json_as_string(field);
        return n00b_result_ok(bool,
                              s != nullptr
                                  && n00b_regex_is_match(predicate->regex, s));
    }
    case N00B_PLAN_LEAF_UNDER: {
        if (predicate->path == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        auto path_r = _rocs_plan_path_resolve(field, predicate->path);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_err(bool, n00b_result_get_err(path_r));
        }
        return n00b_result_ok(bool,
                              n00b_option_is_set(n00b_result_get(path_r)));
    }
    }

    return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(bool)
_rocs_plan_eval_predicate(_rocs_plan_scan_ctx_t *ctx,
                          n00b_plan_predicate_t   *predicate,
                          n00b_json_node_t        *record)
{
    if (ctx == nullptr || predicate == nullptr || record == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
        return _rocs_plan_eval_leaf(ctx, predicate, record);

    case N00B_PLAN_PREDICATE_AND: {
        if (predicate->children == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->children);
        if (len < 2) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        // A conjunction stops at its first false, so a cheap child that
        // rejects the record spares an expensive one from ever running.
        uint16_t        scratch[ROCS_ORDER_MAX];
        const uint16_t *order = _rocs_plan_group_order(ctx, predicate, len,
                                                       scratch);
        for (size_t i = 0; i < len; i++) {
            size_t at      = order != nullptr ? (size_t)order[i] : i;
            auto   child_r = _rocs_plan_eval_predicate(
                ctx,
                n00b_list_get(*predicate->children, at),
                record);
            if (n00b_result_is_err(child_r) || !n00b_result_get(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, true);
    }

    case N00B_PLAN_PREDICATE_OR: {
        if (predicate->children == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->children);
        if (len < 2) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        // A disjunction stops at its first true, so the same argument holds:
        // a cheap child that accepts the record spares an expensive one.
        uint16_t        scratch[ROCS_ORDER_MAX];
        const uint16_t *order = _rocs_plan_group_order(ctx, predicate, len,
                                                       scratch);
        for (size_t i = 0; i < len; i++) {
            size_t at      = order != nullptr ? (size_t)order[i] : i;
            auto   child_r = _rocs_plan_eval_predicate(
                ctx,
                n00b_list_get(*predicate->children, at),
                record);
            if (n00b_result_is_err(child_r) || n00b_result_get(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, false);
    }

    case N00B_PLAN_PREDICATE_NOT: {
        if (predicate->child == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        auto child_r = _rocs_plan_eval_predicate(ctx,
                                                predicate->child,
                                                record);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        return n00b_result_ok(bool, !n00b_result_get(child_r));
    }

    case N00B_PLAN_PREDICATE_FALSE:
        return n00b_result_ok(bool, false);
    }

    return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(n00b_store_record_t *)
_rocs_plan_record_view_for_ordinal(_rocs_plan_scan_ctx_t *ctx,
                                   uint64_t                 ordinal)
{
    if (ctx == nullptr) {
        return n00b_result_err(n00b_store_record_t *, N00B_PLAN_ERR_ARG);
    }

    if (ctx->source == _rocs_plan_scan_src_hot) {
        auto record_r = n00b_store_record_view_hot_at(ctx->hot_shard,
                                                      ordinal,
                                                      .allocator = ctx->allocator);
        if (n00b_result_is_err(record_r)) {
            return n00b_result_err(n00b_store_record_t *,
                                   _rocs_plan_index_err(
                                       n00b_result_get_err(record_r)));
        }
        return record_r;
    }

    auto record_r = n00b_store_record_view_mapped_at(ctx->mapped_shard,
                                                    ordinal,
                                                    .allocator = ctx->allocator);
    if (n00b_result_is_err(record_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               _rocs_plan_index_err(
                                   n00b_result_get_err(record_r)));
    }
    return record_r;
}

// Records materialized and parsed, the dominant cost of a query. Lets a test
// assert an exact amount of work instead of a wall-clock time, which catches a
// plan that answers correctly while reading far more than it needs to.
//
// Counting costs a write on the scan path and a process-global one says little
// while several queries run at once, so it exists only where tests read it.
#ifdef N00B_DEBUG
static _Atomic(uint64_t) rocs_records_scanned = 0;

uint64_t
n00b_plan_records_scanned(void)
{
    return atomic_load_explicit(&rocs_records_scanned, memory_order_relaxed);
}

void
n00b_plan_records_scanned_reset(void)
{
    atomic_store_explicit(&rocs_records_scanned, 0, memory_order_relaxed);
}

void
n00b_plan_records_scanned_set(uint64_t count)
{
    atomic_store_explicit(&rocs_records_scanned, count, memory_order_relaxed);
}
#endif

// Ordinals tested against an index instead of enumerated from it. The
// companion to n00b_plan_postings_walked: the two are the two ways to read an
// index, and a report that showed only one would make choosing the other look
// free.
#ifdef N00B_DEBUG
static _Atomic(uint64_t) rocs_index_probes = 0;
// Posting counts read to decide what to do, as opposed to work avoided by
// deciding. The other three counters all measure what ordering saves, so a
// suite built on them alone passes while wall time regresses: a group that
// reads a df per child and then changes nothing shows as flat.
static _Atomic(uint64_t) rocs_index_df_reads = 0;

uint64_t
n00b_plan_index_df_reads(void)
{
    return atomic_load_explicit(&rocs_index_df_reads, memory_order_relaxed);
}

void
n00b_plan_index_df_reads_reset(void)
{
    atomic_store_explicit(&rocs_index_df_reads, 0, memory_order_relaxed);
}

uint64_t
n00b_plan_index_probes(void)
{
    return atomic_load_explicit(&rocs_index_probes, memory_order_relaxed);
}

void
n00b_plan_index_probes_reset(void)
{
    atomic_store_explicit(&rocs_index_probes, 0, memory_order_relaxed);
}
#endif

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_scan_records(_rocs_plan_scan_ctx_t *ctx,
                             n00b_plan_ordset_t      *candidates,
                             n00b_plan_predicate_t   *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (ctx == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    auto ok = _rocs_plan_ordset_check(candidates);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(ok));
    }
    if (candidates->record_count != ctx->record_count) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               N00B_PLAN_ERR_UNIVERSE);
    }
    if (residual == nullptr) {
        return n00b_result_ok(n00b_plan_ordset_t *, candidates);
    }

    auto out_r = n00b_plan_ordset_empty(ctx->record_count,
                                        .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }
    n00b_plan_ordset_t *out = n00b_result_get(out_r);

    // Per-candidate verification materializes a record view and parses the
    // record's FULL JSON node graph solely to evaluate the residual predicate.
    // None of that escapes: only matching ordinals are recorded into `out`,
    // whose bitset is pre-allocated (in `allocator`) and grows by bit-flip, not
    // allocation. Route the transient per-candidate work through a scratch arena
    // reset each iteration. Otherwise every candidate's JSON accumulated in the
    // long-lived query pool (ctx->allocator) across every boundary, ballooning
    // RSS into the gigabytes on a large residual scan (e.g. crayon search
    // --kind build) — and since that pool is traced but freed only at query end,
    // the GC kept re-scanning it and reclaimed nothing. Swapping ctx->allocator
    // is safe here: within this loop it is used only for the throwaway record
    // view + JSON, and `out` was allocated before the swap.
    n00b_arena_t     *scratch    = n00b_new_arena(.use_gc = false,
                                                  .no_map = true,
                                                  .hidden = false,
                                                  .name   = "rocs_plan_verify");
    n00b_allocator_t *saved_alloc = ctx->allocator;
    ctx->allocator                = (n00b_allocator_t *)scratch;
    n00b_err_t verify_err         = N00B_PLAN_OK;

    uint64_t candidate_count = candidates->count;
    for (uint64_t i = 0; i < candidate_count; i++) {
        // Cooperative cancellation: each candidate costs a record view + a
        // full JSON parse, so an unindexed residual over a large shard runs
        // long. Poll every 1024 candidates (the query.c scan-loop idiom) so a
        // consumer that vanished mid-verify aborts the plan instead of
        // burning CPU to completion as a zombie query.
        if (ctx->cancel_cb != nullptr && (i & 0x3FF) == 0
            && ctx->cancel_cb(ctx->cancel_ctx)) {
            verify_err = N00B_PLAN_ERR_CANCELED;
            break;
        }
        auto ordinal_r = n00b_plan_ordset_at(candidates, i);
        if (n00b_result_is_err(ordinal_r)) {
            verify_err = n00b_result_get_err(ordinal_r);
            break;
        }
        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            verify_err = N00B_PLAN_ERR_STATE;
            break;
        }
        uint64_t ordinal = n00b_option_get(ordinal_opt);

#ifdef N00B_DEBUG
        atomic_fetch_add_explicit(&rocs_records_scanned,
                                  1,
                                  memory_order_relaxed);
#endif

        auto record_r = _rocs_plan_record_view_for_ordinal(ctx, ordinal);
        if (n00b_result_is_err(record_r)) {
            verify_err = n00b_result_get_err(record_r);
            break;
        }

        auto json_r = n00b_store_record_view_json(n00b_result_get(record_r),
                                                  .allocator = ctx->allocator);
        if (n00b_result_is_err(json_r)) {
            verify_err = _rocs_plan_index_err(n00b_result_get_err(json_r));
            break;
        }

        auto match_r = _rocs_plan_eval_predicate(ctx,
                                                residual,
                                                n00b_result_get(json_r));
        if (n00b_result_is_err(match_r)) {
            verify_err = n00b_result_get_err(match_r);
            break;
        }
        if (n00b_result_get(match_r)) {
            auto insert_r = n00b_plan_ordset_insert(out, ordinal);
            if (n00b_result_is_err(insert_r)) {
                verify_err = n00b_result_get_err(insert_r);
                break;
            }
        }

        // Drop this candidate's record view + JSON graph; only `out` survives.
        n00b_arena_reset(scratch);
    }

    ctx->allocator = saved_alloc;
    n00b_allocator_destroy((n00b_allocator_t *)scratch);

    if (verify_err != N00B_PLAN_OK) {
        return n00b_result_err(n00b_plan_ordset_t *, verify_err);
    }

    return n00b_result_ok(n00b_plan_ordset_t *, out);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_record_scan_hot(n00b_store_shard_t    *shard,
                          n00b_plan_ordset_t    *candidates,
                          n00b_plan_predicate_t *residual) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
}
{
    if (shard == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    // A null candidate set means the whole shard, which is what a record scan
    // standing alone wants. This is the one case where the shard's own count is
    // the right universe; when candidates are supplied theirs is authoritative,
    // for the reason below.
    if (candidates == nullptr) {
        auto rc_r = _rocs_plan_hot_record_count(shard);
        if (n00b_result_is_err(rc_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(rc_r));
        }
        auto full_r = n00b_plan_ordset_full(n00b_result_get(rc_r),
                                            .allocator = allocator);
        if (n00b_result_is_err(full_r)) {
            return full_r;
        }
        candidates = n00b_result_get(full_r);
    }

    // The scan universe is the candidate ordset's, which planning froze
    // against the hot shard's record count when the plan ran. Do NOT
    // re-read _rocs_plan_hot_record_count(shard) here: the hot shard is live and
    // grows as events ingest, so on a high-volume class (proc/ai/file/net) the
    // count read now can exceed the count the candidates were sized to, and
    // _rocs_plan_scan_records would then reject the mismatch with
    // N00B_PLAN_ERR_UNIVERSE (surfacing to the caller as a spurious query
    // execution error). Verify only ever tests ordinals already present in
    // `candidates`, so the candidate universe is authoritative; records appended
    // after that read are outside this scan's frozen boundary and are
    // picked up by a later cursor step.
    _rocs_plan_scan_ctx_t ctx = {
        .source       = _rocs_plan_scan_src_hot,
        .hot_shard    = shard,
        .mapped_shard = nullptr,
        .record_count = candidates->record_count,
        .allocator    = allocator,
        .cancel_cb    = cancel_cb,
        .cancel_ctx   = cancel_ctx,
    };

    return _rocs_plan_scan_records(&ctx,
                                   candidates,
                                        residual,
                                        .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_record_scan_mapped(n00b_store_map_shard_t *shard,
                             n00b_plan_ordset_t     *candidates,
                             n00b_plan_predicate_t  *residual) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
}
{
    auto record_count_r = _rocs_plan_mapped_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(record_count_r));
    }

    if (candidates == nullptr) {
        auto full_r = n00b_plan_ordset_full(n00b_result_get(record_count_r),
                                            .allocator = allocator);
        if (n00b_result_is_err(full_r)) {
            return full_r;
        }
        candidates = n00b_result_get(full_r);
    }

    _rocs_plan_scan_ctx_t ctx = {
        .source       = _rocs_plan_scan_src_mapped,
        .hot_shard    = nullptr,
        .mapped_shard = shard,
        .record_count = n00b_result_get(record_count_r),
        .allocator    = allocator,
        .cancel_cb    = cancel_cb,
        .cancel_ctx   = cancel_ctx,
    };

    return _rocs_plan_scan_records(&ctx,
                                   candidates,
                                        residual,
                                        .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Plan execution. This is where every scan happens, index and record alike,
// and where cancellation is polled. The planner decided what to scan; nothing
// here revisits that choice except the broad-set adaptation below, which needs
// a materialized set to make and so cannot be decided ahead of time.
// ---------------------------------------------------------------------------

#define ROCS_DF_CACHE_MAX 64

typedef struct {
    n00b_plan_node_t *node;
    uint64_t          df;
} _rocs_plan_df_entry_t;

typedef struct {
    _rocs_plan_scan_source_t source;
    n00b_store_shard_t        *hot_shard;
    n00b_store_map_shard_t    *mapped_shard;
    uint64_t                   record_count;
    n00b_allocator_t          *allocator;
    n00b_plan_cancel_fn        cancel_cb;
    void                      *cancel_ctx;
    // Seal-time schema watermark; zero disables the trust. See
    // N00B_STORE_SCHEMA_DECLARED_SINCE_NS and _rocs_plan_declared_absent_empty.
    uint64_t                   schema_declared_since_ns;
    // Posting counts read on this shard, kept for as long as the shard is
    // being scanned. A group reads one per child to order them and then every
    // child reads its own again on the way down; a count is fixed for a given
    // node and shard, so it is read once and reused.
    //
    // Bounded, and a miss past the bound just reads again. Groups wider than
    // this are already reading more counts than the postings they could save.
    _rocs_plan_df_entry_t      df_cache[ROCS_DF_CACHE_MAX];
    size_t                     df_cached;
} _rocs_plan_exec_ctx_t;

// Execution carries a restriction: the set a node's answer will be intersected
// with anyway. Handing it down means a record scan reads only what its
// siblings already selected, instead of the whole shard.
//
//   exec(node, R) == answer(node) intersected with R
//
// That distributes through INTERSECT and UNION, since (a | b) & R is
// (a & R) | (b & R), and through COMPLEMENT, since ~(x & R) & R is ~x & R and
// the complement is narrowed again on the way out. A null restriction means
// the whole shard.
static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_node(_rocs_plan_exec_ctx_t *ctx,
                     n00b_plan_node_t      *node,
                     n00b_plan_ordset_t    *restrict_to);

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_verify(_rocs_plan_exec_ctx_t *ctx,
                       n00b_plan_ordset_t    *candidates,
                       n00b_plan_predicate_t *predicate)
{
    if (ctx->source == _rocs_plan_scan_src_hot) {
        return n00b_plan_record_scan_hot(ctx->hot_shard,
                                         candidates,
                                         predicate,
                                         .allocator  = ctx->allocator,
                                         .cancel_cb  = ctx->cancel_cb,
                                         .cancel_ctx = ctx->cancel_ctx);
    }
    return n00b_plan_record_scan_mapped(ctx->mapped_shard,
                                        candidates,
                                        predicate,
                                        .allocator  = ctx->allocator,
                                        .cancel_cb  = ctx->cancel_cb,
                                        .cancel_ctx = ctx->cancel_ctx);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_universe(_rocs_plan_exec_ctx_t *ctx,
                         n00b_plan_ordset_t    *restrict_to)
{
    if (restrict_to != nullptr) {
        return n00b_result_ok(n00b_plan_ordset_t *, restrict_to);
    }
    return n00b_plan_ordset_full(ctx->record_count,
                                 .allocator = ctx->allocator);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_narrow(_rocs_plan_exec_ctx_t *ctx,
                  n00b_plan_ordset_t    *set,
                  n00b_plan_ordset_t    *restrict_to)
{
    if (restrict_to == nullptr) {
        return n00b_result_ok(n00b_plan_ordset_t *, set);
    }
    return n00b_plan_ordset_intersection(set,
                                         restrict_to,
                                         .allocator = ctx->allocator);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_recover(_rocs_plan_exec_ctx_t *ctx,
                        n00b_plan_node_t      *node,
                        n00b_plan_ordset_t    *restrict_to)
{
    if (node->recovery == N00B_PLAN_RECOVER_EMPTY) {
        return n00b_plan_ordset_empty(ctx->record_count,
                                      .allocator = ctx->allocator);
    }

    auto base_r = _rocs_plan_exec_universe(ctx, restrict_to);
    if (n00b_result_is_err(base_r)
        || node->recovery != N00B_PLAN_RECOVER_RECORD_SCAN
        || node->fallback == nullptr) {
        return base_r;
    }
    // An exact scan standing alone has nothing downstream to filter it, so the
    // predicate has to be applied here or the query answers with the shard.
    return _rocs_plan_exec_verify(ctx, n00b_result_get(base_r), node->fallback);
}

// Decide whether a declared-indexed field with NO column on this sealed shard
// can be answered exact-empty, or has to be scanned.
//
// The two states need opposite answers and a sealed image records no schema
// identity to tell them apart (see N00B_STORE_SCHEMA_DECLARED_SINCE_NS for the
// full statement and the derivation of the watermark). What it does carry is
// seal_ts, in CLOCK_REALTIME epoch ns. A shard sealed at or after the moment the
// schema last gained an indexed field was written by a gateway that declared
// this field, so every record populating it was indexed, so no column means
// nothing here populated it -- and exact-empty is the correct answer, which is
// what 0.8.44 gave and what #223 had to give up globally to fix #202.
//
// Below the watermark, nothing changes: #223's residual scan stands, and #202
// stays fixed. Fails SAFE in every ambiguous case -- a zero watermark, an
// unreadable seal_ts, or a hot shard all fall through to the scan.
static bool
_rocs_plan_declared_absent_empty(_rocs_plan_exec_ctx_t *ctx)
{
    if (ctx->schema_declared_since_ns == 0
        || ctx->source != _rocs_plan_scan_src_mapped
        || ctx->mapped_shard == nullptr) {
        return false;
    }
    auto seal_ts_r = n00b_store_map_shard_seal_ts(ctx->mapped_shard);
    if (n00b_result_is_err(seal_ts_r)) {
        return false;
    }
    return n00b_result_get(seal_ts_r) >= ctx->schema_declared_since_ns;
}

// What the index says a scan can match, read from posting headers. The scan
// itself walks every posting, so this is the only way to learn the size before
// paying for it.
static n00b_result_t(uint64_t)
_rocs_plan_index_df(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node)
{
    for (size_t i = 0; i < ctx->df_cached; i++) {
        if (ctx->df_cache[i].node == node) {
            return n00b_result_ok(uint64_t, ctx->df_cache[i].df);
        }
    }

#ifdef N00B_DEBUG
    // Counted on a miss only. A memo hit costs a pointer compare.
    atomic_fetch_add_explicit(&rocs_index_df_reads, 1, memory_order_relaxed);
#endif

    n00b_store_index_keys_t *keys = n00b_plan_node_keys(node);

    n00b_result_t(uint64_t) df_r;
    if (ctx->source == _rocs_plan_scan_src_hot) {
        df_r = n00b_store_index_df_hot(node->index,
                                       ctx->hot_shard,
                                       node->key,
                                       .allocator = ctx->allocator,
                                       .keys      = keys);
    }
    else {
        df_r = n00b_store_index_df_mapped(node->index,
                                          ctx->mapped_shard,
                                          node->key,
                                          .allocator = ctx->allocator,
                                          .keys      = keys);
    }
    if (n00b_result_is_ok(df_r)) {
        uint64_t df = n00b_result_get(df_r);
        // A sealed shard with no column for this field reports zero, the same
        // number a present column reports for a term it does not carry. The
        // two want opposite orderings: the second matches nothing and belongs
        // first, while the first may recover into a record scan and belongs
        // wherever the plan put it. Separating them is only worth a lookup
        // when the scan would not answer empty anyway.
        if (df == 0 && ctx->source == _rocs_plan_scan_src_mapped
            && !_rocs_plan_declared_absent_empty(ctx)) {
            auto present_r = n00b_store_index_present_mapped(node->index,
                                                            ctx->mapped_shard);
            if (n00b_result_is_err(present_r)
                || !n00b_result_get(present_r)) {
                return n00b_result_err(uint64_t, N00B_PLAN_ERR_STATE);
            }
        }
        if (ctx->df_cached < ROCS_DF_CACHE_MAX) {
            ctx->df_cache[ctx->df_cached].node = node;
            ctx->df_cache[ctx->df_cached].df   = df;
            ctx->df_cached++;
        }
    }
    return df_r;
}

static uint64_t
_rocs_plan_candidate_count(_rocs_plan_exec_ctx_t *ctx,
                           n00b_plan_ordset_t    *restrict_to)
{
    if (restrict_to == nullptr) {
        return ctx->record_count;
    }
    auto count_r = n00b_plan_ordset_count(restrict_to);
    return n00b_result_is_ok(count_r) ? n00b_result_get(count_r)
                                      : ctx->record_count;
}

// Resolve the node's term posting lists into something that answers membership.
//
// Separate from running the probe because whether a probe is worth running
// depends on what it resolved to: a list that has to be scanned answers in df
// steps where the cost model priced log2(df).
static n00b_result_t(n00b_store_index_probe_t *)
_rocs_plan_index_probe_new(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node)
{
    n00b_store_index_keys_t *keys = n00b_plan_node_keys(node);

    if (ctx->source == _rocs_plan_scan_src_hot) {
        return n00b_store_index_probe_hot(node->index,
                                          ctx->hot_shard,
                                          node->key,
                                          .allocator = ctx->allocator,
                                          .keys      = keys);
    }
    return n00b_store_index_probe_mapped(node->index,
                                         ctx->mapped_shard,
                                         node->key,
                                         .allocator = ctx->allocator,
                                         .keys      = keys);
}

// Build the answer by asking the index about each candidate, rather than by
// reading the posting list and throwing away everything outside the candidate
// set. Same answer either way: both are the postings intersected with what the
// node was handed.
static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_index_probe(_rocs_plan_exec_ctx_t    *ctx,
                            n00b_store_index_probe_t *probe,
                            n00b_plan_ordset_t       *restrict_to)
{
    auto out_r = n00b_plan_ordset_empty(ctx->record_count,
                                        .allocator = ctx->allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }
    n00b_plan_ordset_t *out = n00b_result_get(out_r);

    auto count_r = n00b_plan_ordset_count(restrict_to);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
    }
    uint64_t candidates = n00b_result_get(count_r);

#ifdef N00B_DEBUG
    atomic_fetch_add_explicit(&rocs_index_probes,
                              candidates,
                              memory_order_relaxed);
#endif

    for (uint64_t i = 0; i < candidates; i++) {
        // Same stride the other unbounded loops poll on.
        if (ctx->cancel_cb != nullptr && (i & 0x3FF) == 0
            && ctx->cancel_cb(ctx->cancel_ctx)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_CANCELED);
        }

        auto at_r = n00b_plan_ordset_at(restrict_to, i);
        if (n00b_result_is_err(at_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(at_r));
        }
        n00b_option_t(uint64_t) opt = n00b_result_get(at_r);
        if (!n00b_option_is_set(opt)) {
            return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
        }
        uint64_t ordinal = n00b_option_get(opt);

        auto has_r = n00b_store_index_probe_contains(probe, ordinal);
        if (n00b_result_is_err(has_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   _rocs_plan_index_err(
                                       n00b_result_get_err(has_r)));
        }
        if (!n00b_result_get(has_r)) {
            continue;
        }

        auto insert_r = n00b_plan_ordset_insert(out, ordinal);
        if (n00b_result_is_err(insert_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(insert_r));
        }
    }

    return n00b_result_ok(n00b_plan_ordset_t *, out);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_index_scan(_rocs_plan_exec_ctx_t *ctx,
                           n00b_plan_node_t      *node,
                           n00b_plan_ordset_t    *restrict_to)
{
    // Resolved once for this node, then reused by the probe and the lookup
    // below. Resolution is lazy, so a leaf the ordering skips never pays.
    n00b_store_index_keys_t *keys = n00b_plan_node_keys(node);

    // Reading a df is not free, so ask only when an answer could change what
    // happens next. What to do with the numbers is plan.c's call; this reads
    // them and applies the verdict.
    uint64_t candidates = _rocs_plan_candidate_count(ctx, restrict_to);
    bool     may_probe  = restrict_to != nullptr
                    && n00b_plan_cost_probe_possible(candidates,
                                                     ctx->record_count);

    if (n00b_plan_cost_enabled() && (node->lossy || may_probe)) {
        auto df_r = _rocs_plan_index_df(ctx, node);
        if (n00b_result_is_ok(df_r)) {
            uint64_t df = n00b_result_get(df_r);

            if (n00b_plan_cost_term_covers_shard(node->lossy,
                                                 df,
                                                 ctx->record_count)) {
                return _rocs_plan_exec_universe(ctx, restrict_to);
            }

            // Every way out of the block below falls through to the walk,
            // which is the answer either choice reaches. A probe that was
            // resolved and then refused, or built and then errored, costs the
            // resolution and nothing else.
            uint64_t terms = keys == nullptr
                               ? 1
                               : n00b_store_index_keys_count(keys);
            uint64_t walk  = n00b_plan_cost_bitmap_walk(
                ctx->record_count,
                restrict_to != nullptr && restrict_to->ord_cache != nullptr);
            if (may_probe) {
                // Resolved before the decision, not after it. Whether a
                // membership test is a binary search or a linear scan is a
                // property of the lists this resolves to, and the arithmetic
                // prices a search; asking afterwards would be asking once the
                // choice had already been made on the wrong number. Resolving
                // costs one dict lookup per term, which the walk below pays
                // anyway.
                auto probe_r = _rocs_plan_index_probe_new(ctx, node);
                if (n00b_result_is_ok(probe_r)) {
                    n00b_store_index_probe_t *probe = n00b_result_get(probe_r);
                    if (n00b_plan_cost_probe_beats_walk(
                            df,
                            candidates,
                            walk,
                            terms,
                            ctx->source == _rocs_plan_scan_src_mapped,
                            n00b_store_index_probe_searchable(probe))) {
                        auto probed_r = _rocs_plan_exec_index_probe(
                            ctx, probe, restrict_to);
                        if (n00b_result_is_ok(probed_r)) {
                            return probed_r;
                        }
                    }
                }
            }
        }
    }

    n00b_result_t(n00b_store_postings_t *) postings_r;
    if (ctx->source == _rocs_plan_scan_src_hot) {
        postings_r = n00b_store_index_lookup(node->index,
                                             ctx->hot_shard,
                                             node->key,
                                             .allocator = ctx->allocator,
                                             .keys      = keys);
    }
    else {
        auto present_r = n00b_store_index_present_mapped(node->index,
                                                        ctx->mapped_shard);
        if (n00b_result_is_err(present_r)) {
            return _rocs_plan_exec_recover(ctx, node, restrict_to);
        }
        if (!n00b_result_get(present_r)) {
            // No column for a field the plan has an index descriptor for. Either
            // nothing here populated it, or this shard predates its declaration.
            if (_rocs_plan_declared_absent_empty(ctx)) {
                return n00b_plan_ordset_empty(ctx->record_count,
                                              .allocator = ctx->allocator);
            }
            return _rocs_plan_exec_recover(ctx, node, restrict_to);
        }
        postings_r = n00b_store_index_lookup_mapped(node->index,
                                                    ctx->mapped_shard,
                                                    node->key,
                                                    .allocator = ctx->allocator,
                                                    .keys      = keys);
    }
    if (n00b_result_is_err(postings_r)) {
        if (n00b_result_get_err(postings_r) == N00B_PLAN_ERR_CANCELED) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_CANCELED);
        }
        return _rocs_plan_exec_recover(ctx, node, restrict_to);
    }

    auto set_r = _rocs_plan_ordset_from_postings(n00b_result_get(postings_r),
                                                 ctx->record_count,
                                                 .allocator  = ctx->allocator,
                                                 .cancel_cb  = ctx->cancel_cb,
                                                 .cancel_ctx = ctx->cancel_ctx,
                                                 .allow_unpublished =
                                                     ctx->source
                                                     == _rocs_plan_scan_src_hot);
    if (n00b_result_is_err(set_r)) {
        // Giving up is not the same as an unusable index: recovering here
        // would answer a cancelled query by doing more work, not less.
        if (n00b_result_get_err(set_r) == N00B_PLAN_ERR_CANCELED) {
            return set_r;
        }
        return _rocs_plan_exec_recover(ctx, node, restrict_to);
    }

    // A lossy scan that kept most of the shard has narrowed nothing worth
    // carrying, so drop to the universe and let the paired record scan work.
    // This needs the set in hand, which is why the planner cannot decide it.
    if (node->lossy
        && _rocs_plan_candidate_set_is_broad(n00b_result_get(set_r))) {
        return _rocs_plan_exec_universe(ctx, restrict_to);
    }
    return _rocs_plan_narrow(ctx, n00b_result_get(set_r), restrict_to);
}

static n00b_result_t(uint64_t)
_rocs_plan_count(n00b_plan_ordset_t *set)
{
    return n00b_plan_ordset_count(set);
}

// Run one INTERSECT child and fold it into the accumulator. The accumulator is
// handed down as the child's restriction, so the child reads only what its
// siblings already selected.
static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_intersect_fold(_rocs_plan_exec_ctx_t *ctx,
                          n00b_plan_node_t      *child,
                          n00b_plan_ordset_t    *acc)
{
    auto child_r = _rocs_plan_exec_node(ctx, child, acc);
    if (n00b_result_is_err(child_r)) {
        return child_r;
    }
    return n00b_plan_ordset_intersection(acc,
                                         n00b_result_get(child_r),
                                         .allocator = ctx->allocator);
}

static bool
_rocs_plan_child_reads_no_records(n00b_plan_node_t *child)
{
    auto exact_r = n00b_plan_reads_no_records(child);
    return n00b_result_is_ok(exact_r) && n00b_result_get(exact_r);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_intersect(_rocs_plan_exec_ctx_t *ctx,
                          n00b_plan_node_t      *node,
                          n00b_plan_ordset_t    *restrict_to)
{
    size_t count = n00b_list_len(*node->children);

    auto acc_r = _rocs_plan_exec_universe(ctx, restrict_to);
    if (n00b_result_is_err(acc_r)) {
        return acc_r;
    }
    n00b_plan_ordset_t *acc = n00b_result_get(acc_r);

    // Plan order. Which operand runs first is the planner's decision, taken
    // from what each matches on this shard (plan.h rule 4); re-deciding it here
    // would be a second implementation of the same rule, free to disagree.
    //
    // The two passes remain: children that read no records go first, so the
    // ones that do inherit everything the indexes ruled out. That is a
    // property of the node kinds, not of the counts, so it belongs here.
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < count; i++) {
            n00b_plan_node_t *child = n00b_list_get(*node->children, i);
            bool              cheap = _rocs_plan_child_reads_no_records(child);
            if ((pass == 0) != cheap) {
                continue;
            }

            auto fold_r = _rocs_plan_intersect_fold(ctx, child, acc);
            if (n00b_result_is_err(fold_r)) {
                return fold_r;
            }
            acc = n00b_result_get(fold_r);

            auto empty_r = _rocs_plan_count(acc);
            if (n00b_result_is_ok(empty_r) && n00b_result_get(empty_r) == 0) {
                return n00b_result_ok(n00b_plan_ordset_t *, acc);
            }
        }
    }
    return n00b_result_ok(n00b_plan_ordset_t *, acc);
}

// Run one UNION branch and fold it in. Every branch gets the same restriction:
// what one branch found does not narrow what another may find, which is the
// difference from the intersect fold above.
static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_union_fold(_rocs_plan_exec_ctx_t *ctx,
                      n00b_plan_node_t      *child,
                      n00b_plan_ordset_t    *acc,
                      n00b_plan_ordset_t    *restrict_to)
{
    auto child_r = _rocs_plan_exec_node(ctx, child, restrict_to);
    if (n00b_result_is_err(child_r) || acc == nullptr) {
        return child_r;
    }
    return n00b_plan_ordset_union(acc,
                                  n00b_result_get(child_r),
                                  .allocator = ctx->allocator);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_union(_rocs_plan_exec_ctx_t *ctx,
                      n00b_plan_node_t      *node,
                      n00b_plan_ordset_t    *restrict_to)
{
    size_t              count   = n00b_list_len(*node->children);
    n00b_plan_ordset_t *acc     = nullptr;
    uint64_t            ceiling = _rocs_plan_candidate_count(ctx, restrict_to);

    // Plan order, which for a union the planner sets widest-first: a union
    // stops once it covers everything still in play, so the branch covering
    // most gets it there soonest and the rest are skipped outright. That
    // decision is taken at build from what each branch matches on this shard.
    for (size_t i = 0; i < count; i++) {
        auto fold_r = _rocs_plan_union_fold(ctx,
                                            n00b_list_get(*node->children, i),
                                            acc,
                                            restrict_to);
        if (n00b_result_is_err(fold_r)) {
            return fold_r;
        }
        acc = n00b_result_get(fold_r);

        auto full_r = _rocs_plan_count(acc);
        if (n00b_result_is_ok(full_r) && n00b_result_get(full_r) >= ceiling) {
            return n00b_result_ok(n00b_plan_ordset_t *, acc);
        }
    }

    if (acc == nullptr) {
        return n00b_plan_ordset_empty(ctx->record_count,
                                      .allocator = ctx->allocator);
    }
    return n00b_result_ok(n00b_plan_ordset_t *, acc);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_node(_rocs_plan_exec_ctx_t *ctx,
                     n00b_plan_node_t      *node,
                     n00b_plan_ordset_t    *restrict_to)
{
    if (ctx == nullptr || node == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    switch (node->kind) {
    case N00B_PLAN_NODE_EMPTY:
        return n00b_plan_ordset_empty(ctx->record_count,
                                      .allocator = ctx->allocator);
    case N00B_PLAN_NODE_INDEX_SCAN:
        return _rocs_plan_exec_index_scan(ctx, node, restrict_to);
    case N00B_PLAN_NODE_RECORD_SCAN: {
        auto base_r = _rocs_plan_exec_universe(ctx, restrict_to);
        if (n00b_result_is_err(base_r)) {
            return base_r;
        }
        return _rocs_plan_exec_verify(ctx,
                                      n00b_result_get(base_r),
                                      node->predicate);
    }
    case N00B_PLAN_NODE_INTERSECT:
        return _rocs_plan_exec_intersect(ctx, node, restrict_to);
    case N00B_PLAN_NODE_UNION:
        return _rocs_plan_exec_union(ctx, node, restrict_to);
    case N00B_PLAN_NODE_COMPLEMENT: {
        // Restricting the child is safe here because the complement is
        // narrowed again afterwards, and ~(x & R) & R is ~x & R. Without it a
        // negated record scan would read the whole shard while a selective
        // sibling sat unapplied.
        auto child_r = _rocs_plan_exec_node(ctx, node->child, restrict_to);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        auto comp_r = n00b_plan_ordset_complement(n00b_result_get(child_r),
                                                  .allocator = ctx->allocator);
        if (n00b_result_is_err(comp_r)) {
            return comp_r;
        }
        return _rocs_plan_narrow(ctx, n00b_result_get(comp_r), restrict_to);
    }
    }
    return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_hot(n00b_plan_node_t   *plan,
                   n00b_store_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator    = nullptr;
    n00b_plan_cancel_fn  cancel_cb    = nullptr;
    void                *cancel_ctx   = nullptr;
    uint64_t             record_limit = UINT64_MAX;
}
{
    if (plan == nullptr || shard == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }
    if (shard->records == nullptr || shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
    }
    uint64_t record_count = record_limit;
    if (record_count == UINT64_MAX) {
        auto rc_r = _rocs_plan_hot_record_count(shard);
        if (n00b_result_is_err(rc_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(rc_r));
        }
        record_count = n00b_result_get(rc_r);
    }
    else if (record_count > (uint64_t)n00b_list_len(*shard->records)) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
    }
    _rocs_plan_exec_ctx_t ctx = {
        .source       = _rocs_plan_scan_src_hot,
        .hot_shard    = shard,
        .record_count = record_count,
        .allocator    = allocator,
        .cancel_cb    = cancel_cb,
        .cancel_ctx   = cancel_ctx,
    };
    return _rocs_plan_exec_node(&ctx, plan, nullptr);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_mapped(n00b_plan_node_t       *plan,
                      n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
    // Defaults to zero, i.e. the trust is OFF unless a caller passes the
    // store's watermark. A caller that forgets gets today's scan, not a
    // silent false negative.
    uint64_t             schema_declared_since_ns = 0;
}
{
    if (plan == nullptr || shard == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }
    auto rc_r = _rocs_plan_mapped_record_count(shard);
    if (n00b_result_is_err(rc_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(rc_r));
    }
    _rocs_plan_exec_ctx_t ctx = {
        .source       = _rocs_plan_scan_src_mapped,
        .mapped_shard = shard,
        .record_count = n00b_result_get(rc_r),
        .allocator    = allocator,
        .cancel_cb    = cancel_cb,
        .cancel_ctx   = cancel_ctx,
        .schema_declared_since_ns = schema_declared_since_ns,
    };
    return _rocs_plan_exec_node(&ctx, plan, nullptr);
}

// ---------------------------------------------------------------------------
// Sealed-store fan-out. Walks the catalog, skips shards the partition filter
// rules out, and runs one plan against each survivor, acquiring and releasing
// a resident mapping per shard.
// ---------------------------------------------------------------------------

struct n00b_plan_shard_result_t {
    uint64_t             shard_id;
    uint64_t             generation;
    uint64_t             schema_generation;
    uint64_t             record_count;
    uint64_t             seal_ts;
    n00b_string_t       *partition_key;
    n00b_plan_ordset_t  *ordinals;
};

static n00b_plan_shard_result_list_t *
_rocs_plan_shard_result_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_shard_result_list_t *results = n00b_alloc_with_opts(
        n00b_plan_shard_result_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *results = n00b_list_new_private(n00b_plan_shard_result_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return results;
}

static n00b_result_t(n00b_string_t *)
_rocs_plan_string_copy(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (s == nullptr || s->data == nullptr
        || s->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(
        n00b_string_t *,
        n00b_string_from_raw(s->data,
                             (int64_t)s->u8_bytes,
                             .allocator = allocator));
}

static n00b_result_t(bool)
_rocs_plan_release_resident(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr) {
        return n00b_result_ok(bool, true);
    }

    auto release_r = n00b_store_resident_shard_release(resident);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(release_r)));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_plan_shard_result_t *)
_rocs_plan_shard_result_new(n00b_store_catalog_entry_t *entry,
                            n00b_plan_ordset_t         *ordinals) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (entry == nullptr || ordinals == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_t *, N00B_PLAN_ERR_ARG);
    }

    auto shard_id_r = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r      = n00b_store_catalog_entry_get_generation(entry);
    auto schema_r   = n00b_store_catalog_entry_get_schema_generation(entry);
    auto records_r  = n00b_store_catalog_entry_get_record_count(entry);
    auto seal_r     = n00b_store_catalog_entry_get_seal_ts(entry);
    auto part_r     = n00b_store_catalog_entry_get_partition_key(entry);

    if (n00b_result_is_err(shard_id_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(schema_r) || n00b_result_is_err(records_r)
        || n00b_result_is_err(seal_r) || n00b_result_is_err(part_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_STATE);
    }

    auto ord_records_r = n00b_plan_ordset_record_count(ordinals);
    if (n00b_result_is_err(ord_records_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               n00b_result_get_err(ord_records_r));
    }
    if (n00b_result_get(ord_records_r) != n00b_result_get(records_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_STATE);
    }

    auto part_copy_r =
        _rocs_plan_string_copy(n00b_result_get(part_r),
                               .allocator = allocator);
    if (n00b_result_is_err(part_copy_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               n00b_result_get_err(part_copy_r));
    }

    n00b_plan_shard_result_t *result = n00b_alloc_with_opts(
        n00b_plan_shard_result_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    result->shard_id          = n00b_result_get(shard_id_r);
    result->generation        = n00b_result_get(gen_r);
    result->schema_generation = n00b_result_get(schema_r);
    result->record_count      = n00b_result_get(records_r);
    result->seal_ts           = n00b_result_get(seal_r);
    result->partition_key     = n00b_result_get(part_copy_r);
    result->ordinals          = ordinals;
    return n00b_result_ok(n00b_plan_shard_result_t *, result);
}

static n00b_result_t(bool)
_rocs_plan_validate_mapped_catalog(n00b_store_map_shard_t      *root,
                                   n00b_store_catalog_entry_t  *entry)
{
    if (root == nullptr || entry == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    auto catalog_id_r = n00b_store_catalog_entry_get_shard_id(entry);
    auto catalog_records_r = n00b_store_catalog_entry_get_record_count(entry);
    auto catalog_seal_r = n00b_store_catalog_entry_get_seal_ts(entry);
    auto root_id_r = n00b_store_map_shard_id(root);
    auto root_records_r = n00b_store_map_shard_records_len(root);
    auto root_seal_r = n00b_store_map_shard_seal_ts(root);

    if (n00b_result_is_err(catalog_id_r)
        || n00b_result_is_err(catalog_records_r)
        || n00b_result_is_err(catalog_seal_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: catalog metadata read failed "
                    "id_err=%d records_err=%d seal_err=%d\n",
                    n00b_result_is_err(catalog_id_r),
                    n00b_result_is_err(catalog_records_r),
                    n00b_result_is_err(catalog_seal_r));
        }
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    if (n00b_result_is_err(root_id_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_map_err(
                                   n00b_result_get_err(root_id_r)));
    }
    if (n00b_result_is_err(root_records_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_map_err(
                                   n00b_result_get_err(root_records_r)));
    }
    if (n00b_result_is_err(root_seal_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_map_err(
                                   n00b_result_get_err(root_seal_r)));
    }

    if (n00b_result_get(catalog_id_r) != n00b_result_get(root_id_r)
        || n00b_result_get(catalog_records_r) != n00b_result_get(root_records_r)
        || n00b_result_get(catalog_seal_r) != n00b_result_get(root_seal_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: mapped catalog mismatch "
                    "catalog=(shard=%llu records=%llu seal=%llu) "
                    "root=(shard=%llu records=%llu seal=%llu)\n",
                    (unsigned long long)n00b_result_get(catalog_id_r),
                    (unsigned long long)n00b_result_get(catalog_records_r),
                    (unsigned long long)n00b_result_get(catalog_seal_r),
                    (unsigned long long)n00b_result_get(root_id_r),
                    (unsigned long long)n00b_result_get(root_records_r),
                    (unsigned long long)n00b_result_get(root_seal_r));
        }
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_plan_shard_result_t *)
n00b_plan_catalog_entry_sealed(n00b_store_t               *store,
                               n00b_store_catalog_entry_t *entry,
                               n00b_plan_predicate_t      *predicate,
                               n00b_plan_index_list_t     *indexes) _kargs
{
    n00b_plan_node_t    *settled      = nullptr;
    bool                 collect_only = false;
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
}
{
    if (store == nullptr || entry == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_ARG);
    }
    n00b_plan_node_t *plan = nullptr;

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_plan_shard_result_t    *result   = nullptr;
    n00b_err_t                   err      = N00B_PLAN_OK;

    auto resident_r = n00b_store_resident_shard_acquire(
        store,
        entry,
        .allocator = allocator);
    if (n00b_result_is_err(resident_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: resident acquire failed store_err=%lld\n",
                    (long long)n00b_result_get_err(resident_r));
        }
        return n00b_result_err(n00b_plan_shard_result_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(resident_r)));
    }
    resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: resident map failed store_err=%lld\n",
                    (long long)n00b_result_get_err(map_r));
        }
        err = _rocs_plan_store_err(n00b_result_get_err(map_r));
        goto release;
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r),
                                      .view_allocator = allocator);
    if (n00b_result_is_err(root_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: map root failed map_err=%lld\n",
                    (long long)n00b_result_get_err(root_r));
        }
        err = _rocs_plan_map_err(n00b_result_get_err(root_r));
        goto release;
    }
    n00b_store_map_shard_t *root = n00b_result_get(root_r);

    auto valid_r = _rocs_plan_validate_mapped_catalog(root, entry);
    if (n00b_result_is_err(valid_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: mapped catalog validation failed plan_err=%lld\n",
                    (long long)n00b_result_get_err(valid_r));
        }
        err = n00b_result_get_err(valid_r);
        goto release;
    }

    // Structure first, counts second, decisions last. Building reads no shard
    // (plan.h rule 1); collecting does, and answers to the cancel hook.
    if (settled != nullptr) {
        // Planned and settled for the whole partition. Fold this shard in on
        // the collect pass; on the execute pass it is already folded.
        if (collect_only) {
            auto c_r = n00b_plan_collect_mapped(settled,
                                                root,
                                                .allocator  = allocator,
                                                .cancel_cb  = cancel_cb,
                                                .cancel_ctx = cancel_ctx);
            if (n00b_result_is_err(c_r)) {
                err = n00b_result_get_err(c_r);
            }
            goto release;
        }
        plan = settled;
        goto execute;
    }

    auto plan_r = n00b_plan_build(predicate,
                                  indexes,
                                  .allocator = allocator);
    if (n00b_result_is_err(plan_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: per-shard build failed plan_err=%lld\n",
                    (long long)n00b_result_get_err(plan_r));
        }
        err = n00b_result_get_err(plan_r);
        goto release;
    }
    plan = n00b_result_get(plan_r);

    // One shard's counts, folded in and settled. This is the plan-per-shard
    // path; a fan-out over a partition folds every shard in before settling
    // once, which is what lets one plan serve them all.
    auto collect_r = n00b_plan_collect_mapped(plan,
                                              root,
                                              .allocator  = allocator,
                                              .cancel_cb  = cancel_cb,
                                              .cancel_ctx = cancel_ctx);
    if (n00b_result_is_err(collect_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: collect failed plan_err=%lld\n",
                    (long long)n00b_result_get_err(collect_r));
        }
        err = n00b_result_get_err(collect_r);
        goto release;
    }

    auto rc_r = _rocs_plan_mapped_record_count(root);
    (void)n00b_plan_settle(plan,
                           n00b_result_is_ok(rc_r) ? n00b_result_get(rc_r) : 0,
                           .allocator = allocator);

execute:
    // The watermark is a property of the store, read here rather than baked
    // into the plan, because the verdict it feeds is per-shard.
    auto watermark_r = n00b_store_schema_declared_since_ns(store);
    auto ordinals_r =
        n00b_plan_exec_mapped(plan,
                              root,
                              .allocator  = allocator,
                              .cancel_cb  = cancel_cb,
                              .cancel_ctx = cancel_ctx,
                              .schema_declared_since_ns =
                                  n00b_result_is_ok(watermark_r)
                                      ? n00b_result_get(watermark_r)
                                      : 0);
    if (n00b_result_is_err(ordinals_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: execute mapped failed plan_err=%lld\n",
                    (long long)n00b_result_get_err(ordinals_r));
        }
        err = n00b_result_get_err(ordinals_r);
        goto release;
    }

    auto result_r =
        _rocs_plan_shard_result_new(entry,
                                    n00b_result_get(ordinals_r),
                                    .allocator = allocator);
    if (n00b_result_is_err(result_r)) {
        if (rocs_plan_debug_enabled()) {
            fprintf(stderr,
                    "rocs plan: shard result build failed plan_err=%lld\n",
                    (long long)n00b_result_get_err(result_r));
        }
        err = n00b_result_get_err(result_r);
        goto release;
    }
    result = n00b_result_get(result_r);

release:
    {
        auto release_r = _rocs_plan_release_resident(resident);
        if (n00b_result_is_err(release_r) && err == N00B_PLAN_OK) {
            err = n00b_result_get_err(release_r);
        }
    }

    if (err != N00B_PLAN_OK) {
        return n00b_result_err(n00b_plan_shard_result_t *, err);
    }
    return n00b_result_ok(n00b_plan_shard_result_t *, result);
}

n00b_result_t(n00b_plan_shard_result_list_t *)
n00b_plan_store_sealed(n00b_store_t           *store,
                       n00b_plan_predicate_t  *predicate,
                       n00b_plan_index_list_t *indexes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               N00B_PLAN_ERR_ARG);
    }

    auto filter_r = n00b_plan_partition_filter(store,
                                              predicate,
                                              .allocator = allocator);
    if (n00b_result_is_err(filter_r)) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               n00b_result_get_err(filter_r));
    }
    n00b_plan_partition_filter_t *filter = n00b_result_get(filter_r);

    n00b_plan_shard_result_list_t *results =
        _rocs_plan_shard_result_list_new(.allocator = allocator);

    // The entries the partition filter kept, and the partition each belongs
    // to. Held because the fan-out walks them twice: once to fold counts in,
    // once to run.
    n00b_list_t(n00b_store_catalog_entry_t *) *kept = n00b_alloc_with_opts(
        n00b_list_t(n00b_store_catalog_entry_t *),
        &(n00b_alloc_opts_t){.allocator = allocator});
    *kept = n00b_list_new_private(n00b_store_catalog_entry_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);

    n00b_list_t(n00b_string_t *) *kept_keys = n00b_alloc_with_opts(
        n00b_list_t(n00b_string_t *),
        &(n00b_alloc_opts_t){.allocator = allocator});
    *kept_keys = n00b_list_new_private(n00b_string_t *,
                                       .allocator = allocator,
                                       .scan_kind = N00B_GC_SCAN_KIND_ALL);

    auto count_r = n00b_store_catalog_visible_entry_count(store);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(count_r)));
    }

    uint64_t entry_count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < entry_count; i++) {
        auto entry_r = n00b_store_catalog_visible_entry_at(store, i);
        if (n00b_result_is_err(entry_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   _rocs_plan_store_err(
                                       n00b_result_get_err(entry_r)));
        }

        n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
            n00b_result_get(entry_r);
        if (!n00b_option_is_set(entry_opt)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
        auto partition_r = n00b_store_catalog_entry_get_partition_key(entry);
        if (n00b_result_is_err(partition_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        auto may_match_r =
            n00b_plan_partition_may_match(filter,
                                          n00b_result_get(partition_r));
        if (n00b_result_is_err(may_match_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   n00b_result_get_err(may_match_r));
        }
        if (!n00b_result_get(may_match_r)) {
            continue;
        }

        n00b_list_push(*kept, entry);
        n00b_list_push(*kept_keys, n00b_result_get(partition_r));
    }

    // One plan per partition, settled from every shard in it.
    //
    // Two passes over the kept entries, because settling is destructive and
    // has to see the whole partition first: a plan settled from one shard and
    // then run against another decides from counts that do not describe it,
    // and an intersection settled to EMPTY on one shard would answer empty for
    // the rest. Building is what the second pass avoids repeating, and that is
    // the cost that scaled with shards rather than with partitions.
    size_t kept_len = n00b_list_len(*kept);

    n00b_list_t(n00b_plan_node_t *) *plans = n00b_alloc_with_opts(
        n00b_list_t(n00b_plan_node_t *),
        &(n00b_alloc_opts_t){.allocator = allocator});
    *plans = n00b_list_new_private(n00b_plan_node_t *,
                                   .allocator = allocator,
                                   .scan_kind = N00B_GC_SCAN_KIND_ALL);

    n00b_list_t(n00b_string_t *) *keys = n00b_alloc_with_opts(
        n00b_list_t(n00b_string_t *),
        &(n00b_alloc_opts_t){.allocator = allocator});
    *keys = n00b_list_new_private(n00b_string_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);

    // Records per partition, summed as its shards are folded in. Settling
    // needs this: the estimator turns a count into a fraction of the whole, so
    // a complement is as wide as the shard minus its child and a union
    // saturates against the shard. Handed zero instead, every complement and
    // every union estimates as the narrowest thing there is and sorts to the
    // front of an intersection, which is the ordering exactly inverted.
    //
    // Grows with the partitions found, in step with `keys` and `plans`. A
    // fixed bound here would settle the partitions past it from zero, which
    // is that inverted ordering, silently and only on the large stores where
    // it costs the most: a store partitioned by day passes any fixed bound
    // worth writing.
    n00b_list_t(uint64_t) *part_records = n00b_alloc_with_opts(
        n00b_list_t(uint64_t),
        &(n00b_alloc_opts_t){.allocator = allocator});
    *part_records = n00b_list_new_private(uint64_t,
                                          .allocator = allocator,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE);

    for (size_t i = 0; i < kept_len; i++) {
        n00b_string_t    *key  = n00b_list_get(*kept_keys, i);
        n00b_plan_node_t *plan = nullptr;

        size_t seen    = n00b_list_len(*keys);
        size_t part_at = seen;
        for (size_t j = 0; j < seen; j++) {
            if (n00b_unicode_str_eq(n00b_list_get(*keys, j), key)) {
                plan    = n00b_list_get(*plans, j);
                part_at = j;
                break;
            }
        }
        if (plan == nullptr) {
            auto plan_r = n00b_plan_build(predicate,
                                          indexes,
                                          .allocator = allocator);
            if (n00b_result_is_err(plan_r)) {
                return n00b_result_err(n00b_plan_shard_result_list_t *,
                                       n00b_result_get_err(plan_r));
            }
            plan    = n00b_result_get(plan_r);
            part_at = n00b_list_len(*keys);
            n00b_list_push(*keys, key);
            n00b_list_push(*plans, plan);
            n00b_list_push(*part_records, UINT64_C(0));
        }

        auto rc_r = n00b_store_catalog_entry_get_record_count(
            n00b_list_get(*kept, i));
        if (n00b_result_is_ok(rc_r)) {
            uint64_t total = n00b_list_get(*part_records, part_at);
            uint64_t add   = n00b_result_get(rc_r);
            // Saturating. A partition whose shards sum past the range is a
            // corrupt catalog, and wrapping would hand settling a tiny
            // universe rather than a huge one.
            n00b_list_set(*part_records,
                          part_at,
                          total > UINT64_MAX - add ? UINT64_MAX : total + add);
        }

        auto c_r = n00b_plan_catalog_entry_sealed(store,
                                                  n00b_list_get(*kept, i),
                                                  predicate,
                                                  indexes,
                                                  .settled      = plan,
                                                  .collect_only = true,
                                                  .allocator    = allocator);
        if (n00b_result_is_err(c_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   n00b_result_get_err(c_r));
        }
    }

    size_t plan_count = n00b_list_len(*plans);
    for (size_t j = 0; j < plan_count; j++) {
        (void)n00b_plan_settle(n00b_list_get(*plans, j),
                               n00b_list_get(*part_records, j),
                               .allocator = allocator);
    }

    for (size_t i = 0; i < kept_len; i++) {
        n00b_string_t    *key  = n00b_list_get(*kept_keys, i);
        n00b_plan_node_t *plan = nullptr;
        size_t            seen = n00b_list_len(*keys);
        for (size_t j = 0; j < seen; j++) {
            if (n00b_unicode_str_eq(n00b_list_get(*keys, j), key)) {
                plan = n00b_list_get(*plans, j);
                break;
            }
        }

        auto result_r = n00b_plan_catalog_entry_sealed(store,
                                                       n00b_list_get(*kept, i),
                                                       predicate,
                                                       indexes,
                                                       .settled   = plan,
                                                       .allocator = allocator);
        if (n00b_result_is_err(result_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   n00b_result_get_err(result_r));
        }

        n00b_list_push(*results, n00b_result_get(result_r));
    }

    return n00b_result_ok(n00b_plan_shard_result_list_t *, results);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_count(n00b_plan_shard_result_list_t *results)
{
    if (results == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*results));
}

n00b_result_t(n00b_option_t(n00b_plan_shard_result_t *))
n00b_plan_shard_result_at(n00b_plan_shard_result_list_t *results,
                          uint64_t                       index)
{
    if (results == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_shard_result_t *),
                               N00B_PLAN_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*results);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_plan_shard_result_t *),
                              n00b_option_none(n00b_plan_shard_result_t *));
    }

    n00b_plan_shard_result_t *result =
        n00b_list_get(*results, (size_t)index);
    if (result == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_shard_result_t *),
                               N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(n00b_option_t(n00b_plan_shard_result_t *),
                          n00b_option_set(n00b_plan_shard_result_t *,
                                          result));
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_shard_id(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->shard_id);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_generation(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->generation);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_schema_generation(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->schema_generation);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_record_count(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->record_count);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_seal_ts(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->seal_ts);
}

n00b_result_t(n00b_string_t *)
n00b_plan_shard_result_partition_key(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_ARG);
    }
    if (result->partition_key == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_string_t *, result->partition_key);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_shard_result_ordinals(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }
    auto ok = _rocs_plan_ordset_check(result->ordinals);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(ok));
    }
    return n00b_result_ok(n00b_plan_ordset_t *, result->ordinals);
}

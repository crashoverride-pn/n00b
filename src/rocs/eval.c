/*
 * The record interpreter. Everything here reads records; nothing here consults
 * an index. That is the distinction between this file and plan.c, and it is
 * why the cancel callback is threaded through these entry points rather than
 * through planning.
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

typedef struct {
    _rocs_plan_scan_source_t source;
    n00b_store_shard_t        *hot_shard;
    n00b_store_map_shard_t    *mapped_shard;
    uint64_t                   record_count;
    n00b_allocator_t          *allocator;
    n00b_plan_cancel_fn        cancel_cb;
    void                      *cancel_ctx;
} _rocs_plan_scan_ctx_t;

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
        for (size_t i = 0; i < len; i++) {
            auto child_r = _rocs_plan_eval_predicate(
                ctx,
                n00b_list_get(*predicate->children, i),
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
        for (size_t i = 0; i < len; i++) {
            auto child_r = _rocs_plan_eval_predicate(
                ctx,
                n00b_list_get(*predicate->children, i),
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

typedef struct {
    _rocs_plan_scan_source_t source;
    n00b_store_shard_t        *hot_shard;
    n00b_store_map_shard_t    *mapped_shard;
    uint64_t                   record_count;
    n00b_allocator_t          *allocator;
    n00b_plan_cancel_fn        cancel_cb;
    void                      *cancel_ctx;
} _rocs_plan_exec_ctx_t;

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_node(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node);

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_record_scan(_rocs_plan_exec_ctx_t *ctx,
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
_rocs_plan_exec_recover(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node)
{
    if (node->recovery == N00B_PLAN_RECOVER_EMPTY) {
        return n00b_plan_ordset_empty(ctx->record_count,
                                      .allocator = ctx->allocator);
    }

    auto full_r = n00b_plan_ordset_full(ctx->record_count,
                                        .allocator = ctx->allocator);
    if (n00b_result_is_err(full_r)
        || node->recovery != N00B_PLAN_RECOVER_RECORD_SCAN
        || node->fallback == nullptr) {
        return full_r;
    }
    // An exact scan standing alone has nothing downstream to filter it, so the
    // universe has to be narrowed here or the query answers with the shard.
    return _rocs_plan_exec_record_scan(ctx, n00b_result_get(full_r),
                                  node->fallback);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_index_scan(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node)
{
    n00b_result_t(n00b_store_postings_t *) postings_r;
    if (ctx->source == _rocs_plan_scan_src_hot) {
        postings_r = n00b_store_index_lookup(node->index,
                                             ctx->hot_shard,
                                             node->key,
                                             .allocator = ctx->allocator);
    }
    else {
        postings_r = n00b_store_index_lookup_mapped(node->index,
                                                    ctx->mapped_shard,
                                                    node->key,
                                                    .allocator = ctx->allocator);
    }
    if (n00b_result_is_err(postings_r)) {
        return _rocs_plan_exec_recover(ctx, node);
    }

    auto set_r = _rocs_plan_ordset_from_postings(n00b_result_get(postings_r),
                                                 ctx->record_count,
                                                 .allocator = ctx->allocator);
    if (n00b_result_is_err(set_r)) {
        return _rocs_plan_exec_recover(ctx, node);
    }

    // A lossy scan that kept most of the shard has narrowed nothing worth
    // carrying, so drop to the full universe and let the paired record scan do
    // the work. This needs the set in hand, which is why it lives here rather
    // than in the planner.
    if (node->lossy
        && _rocs_plan_candidate_set_is_broad(n00b_result_get(set_r))) {
        return n00b_plan_ordset_full(ctx->record_count,
                                     .allocator = ctx->allocator);
    }
    return set_r;
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_intersect(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node)
{
    size_t count = n00b_list_len(*node->children);

    // Index work first, so the record scans that follow run against the
    // narrowed set rather than the whole shard.
    n00b_plan_ordset_t *acc = nullptr;
    for (size_t i = 0; i < count; i++) {
        n00b_plan_node_t *child = n00b_list_get(*node->children, i);
        if (child->kind == N00B_PLAN_NODE_RECORD_SCAN) {
            continue;
        }
        auto child_r = _rocs_plan_exec_node(ctx, child);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        if (acc == nullptr) {
            acc = n00b_result_get(child_r);
        }
        else {
            auto and_r = n00b_plan_ordset_intersection(
                acc, n00b_result_get(child_r), .allocator = ctx->allocator);
            if (n00b_result_is_err(and_r)) {
                return and_r;
            }
            acc = n00b_result_get(and_r);
        }
        auto empty_r = n00b_plan_ordset_count(acc);
        if (n00b_result_is_ok(empty_r) && n00b_result_get(empty_r) == 0) {
            return n00b_result_ok(n00b_plan_ordset_t *, acc);
        }
    }

    if (acc == nullptr) {
        auto full_r = n00b_plan_ordset_full(ctx->record_count,
                                            .allocator = ctx->allocator);
        if (n00b_result_is_err(full_r)) {
            return full_r;
        }
        acc = n00b_result_get(full_r);
    }

    for (size_t i = 0; i < count; i++) {
        n00b_plan_node_t *child = n00b_list_get(*node->children, i);
        if (child->kind != N00B_PLAN_NODE_RECORD_SCAN) {
            continue;
        }
        auto v_r = _rocs_plan_exec_record_scan(ctx, acc, child->predicate);
        if (n00b_result_is_err(v_r)) {
            return v_r;
        }
        acc = n00b_result_get(v_r);
        auto empty_r = n00b_plan_ordset_count(acc);
        if (n00b_result_is_ok(empty_r) && n00b_result_get(empty_r) == 0) {
            break;
        }
    }
    return n00b_result_ok(n00b_plan_ordset_t *, acc);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_exec_node(_rocs_plan_exec_ctx_t *ctx, n00b_plan_node_t *node)
{
    if (ctx == nullptr || node == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    switch (node->kind) {
    case N00B_PLAN_NODE_EMPTY:
        return n00b_plan_ordset_empty(ctx->record_count,
                                      .allocator = ctx->allocator);
    case N00B_PLAN_NODE_INDEX_SCAN:
        return _rocs_plan_exec_index_scan(ctx, node);
    case N00B_PLAN_NODE_RECORD_SCAN: {
        auto full_r = n00b_plan_ordset_full(ctx->record_count,
                                            .allocator = ctx->allocator);
        if (n00b_result_is_err(full_r)) {
            return full_r;
        }
        return _rocs_plan_exec_record_scan(ctx, n00b_result_get(full_r),
                                      node->predicate);
    }
    case N00B_PLAN_NODE_INTERSECT:
        return _rocs_plan_exec_intersect(ctx, node);
    case N00B_PLAN_NODE_UNION: {
        size_t              count = n00b_list_len(*node->children);
        n00b_plan_ordset_t *acc   = nullptr;
        for (size_t i = 0; i < count; i++) {
            auto child_r = _rocs_plan_exec_node(
                ctx, n00b_list_get(*node->children, i));
            if (n00b_result_is_err(child_r)) {
                return child_r;
            }
            if (acc == nullptr) {
                acc = n00b_result_get(child_r);
            }
            else {
                auto or_r = n00b_plan_ordset_union(acc,
                                                   n00b_result_get(child_r),
                                                   .allocator = ctx->allocator);
                if (n00b_result_is_err(or_r)) {
                    return or_r;
                }
                acc = n00b_result_get(or_r);
            }
            // Nothing a later branch adds can widen a full universe.
            auto full_r = n00b_plan_ordset_count(acc);
            if (n00b_result_is_ok(full_r)
                && n00b_result_get(full_r) == ctx->record_count) {
                break;
            }
        }
        if (acc == nullptr) {
            return n00b_plan_ordset_empty(ctx->record_count,
                                          .allocator = ctx->allocator);
        }
        return n00b_result_ok(n00b_plan_ordset_t *, acc);
    }
    case N00B_PLAN_NODE_COMPLEMENT: {
        auto child_r = _rocs_plan_exec_node(ctx, node->child);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        return n00b_plan_ordset_complement(n00b_result_get(child_r),
                                           .allocator = ctx->allocator);
    }
    }
    return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_hot(n00b_plan_node_t   *plan,
                   n00b_store_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
}
{
    if (plan == nullptr || shard == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }
    auto rc_r = _rocs_plan_hot_record_count(shard);
    if (n00b_result_is_err(rc_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(rc_r));
    }
    _rocs_plan_exec_ctx_t ctx = {
        .source       = _rocs_plan_scan_src_hot,
        .hot_shard    = shard,
        .record_count = n00b_result_get(rc_r),
        .allocator    = allocator,
        .cancel_cb    = cancel_cb,
        .cancel_ctx   = cancel_ctx,
    };
    return _rocs_plan_exec_node(&ctx, plan);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_mapped(n00b_plan_node_t       *plan,
                      n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
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
    };
    return _rocs_plan_exec_node(&ctx, plan);
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
                               n00b_plan_node_t           *plan) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
}
{
    if (store == nullptr || entry == nullptr || plan == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_ARG);
    }

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

    auto ordinals_r =
        n00b_plan_exec_mapped(plan,
                              root,
                              .allocator  = allocator,
                              .cancel_cb  = cancel_cb,
                              .cancel_ctx = cancel_ctx);
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

    // One plan serves every shard: building it reads index metadata and the
    // store schema, neither of which varies per shard.
    auto schema_r = n00b_store_get_schema(store);
    auto plan_r   = n00b_plan_build(predicate,
                                  indexes,
                                  .allocator = allocator,
                                  .schema    = n00b_result_is_ok(schema_r)
                                                   ? n00b_result_get(schema_r)
                                                   : nullptr);
    if (n00b_result_is_err(plan_r)) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               n00b_result_get_err(plan_r));
    }
    n00b_plan_node_t *plan = n00b_result_get(plan_r);

    n00b_plan_shard_result_list_t *results =
        _rocs_plan_shard_result_list_new(.allocator = allocator);

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

        auto result_r = n00b_plan_catalog_entry_sealed(store,
                                                       entry,
                                                       plan,
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

/* test/unit/test_rocs_plan_predicate.c - WP-006 Phase 1 predicate tree. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
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

static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

static n00b_plan_target_t *
target_ok(n00b_result_t(n00b_plan_target_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_target_t *target = n00b_result_get(r);
    CHECK(target != nullptr);
    return target;
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_predicate_t *predicate = n00b_result_get(r);
    CHECK(predicate != nullptr);
    return predicate;
}

static n00b_plan_path_t *
path_ok(n00b_result_t(n00b_plan_path_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_path_t *path = n00b_result_get(r);
    CHECK(path != nullptr);
    return path;
}

static n00b_regex_t *
regex_ok(n00b_result_t(n00b_regex_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_regex_t *regex = n00b_result_get(r);
    CHECK(regex != nullptr);
    return regex;
}

static n00b_plan_target_t *
field_target(n00b_string_t *name)
{
    return target_ok(n00b_plan_target_field(name));
}

static n00b_plan_target_t *
any_target(void)
{
    return target_ok(n00b_plan_target_any());
}

static void
check_target_field(n00b_plan_target_t *target, n00b_string_t *name)
{
    auto kind_r = n00b_plan_target_kind(target);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == N00B_PLAN_TARGET_FIELD);

    auto field_r = n00b_plan_target_field_name(target);
    CHECK(n00b_result_is_ok(field_r));
    n00b_option_t(n00b_string_t *) opt = n00b_result_get(field_r);
    CHECK(n00b_option_is_set(opt));
    CHECK(n00b_unicode_str_eq(n00b_option_get(opt), name));
}

static void
check_target_any(n00b_plan_target_t *target)
{
    auto kind_r = n00b_plan_target_kind(target);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == N00B_PLAN_TARGET_ANY);

    auto field_r = n00b_plan_target_field_name(target);
    CHECK(n00b_result_is_ok(field_r));
    CHECK(!n00b_option_is_set(n00b_result_get(field_r)));
}

static void
check_kind(n00b_plan_predicate_t      *predicate,
           n00b_plan_predicate_kind_t  kind)
{
    auto kind_r = n00b_plan_predicate_kind(predicate);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == kind);
}

static void
check_leaf(n00b_plan_predicate_t *predicate, n00b_plan_leaf_op_t op)
{
    check_kind(predicate, N00B_PLAN_PREDICATE_LEAF);
    auto op_r = n00b_plan_predicate_leaf_op(predicate);
    CHECK(n00b_result_is_ok(op_r));
    CHECK(n00b_result_get(op_r) == op);
}

static void
check_leaf_target(n00b_plan_predicate_t *predicate,
                  n00b_plan_target_t    *target)
{
    auto target_r = n00b_plan_predicate_target(predicate);
    CHECK(n00b_result_is_ok(target_r));
    n00b_option_t(n00b_plan_target_t *) opt = n00b_result_get(target_r);
    CHECK(n00b_option_is_set(opt));
    CHECK(n00b_option_get(opt) == target);
}

static void
check_text(n00b_plan_predicate_t *predicate, n00b_string_t *expected)
{
    auto text_r = n00b_plan_predicate_text(predicate);
    CHECK(n00b_result_is_ok(text_r));
    n00b_option_t(n00b_string_t *) opt = n00b_result_get(text_r);
    CHECK(n00b_option_is_set(opt));
    CHECK(n00b_unicode_str_eq(n00b_option_get(opt), expected));
}

static n00b_plan_path_t *
sample_path(void)
{
    n00b_plan_path_component_list_t *components =
        n00b_plan_path_component_list_new();

    auto key_r = n00b_plan_path_component_list_append_key(components,
                                                          r"payload");
    CHECK(n00b_result_is_ok(key_r));
    auto index_r = n00b_plan_path_component_list_append_index(components, 0);
    CHECK(n00b_result_is_ok(index_r));
    auto leaf_r = n00b_plan_path_component_list_append_key(components,
                                                           r"message");
    CHECK(n00b_result_is_ok(leaf_r));

    n00b_plan_path_t *path = path_ok(n00b_plan_path_new(components));

    auto count_r = n00b_plan_path_component_count(path);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 3);

    auto c0_r = n00b_plan_path_component_at(path, 0);
    CHECK(n00b_result_is_ok(c0_r));
    CHECK(n00b_option_is_set(n00b_result_get(c0_r)));
    n00b_plan_path_component_t *c0 = n00b_option_get(n00b_result_get(c0_r));
    auto c0_kind_r = n00b_plan_path_component_kind(c0);
    CHECK(n00b_result_is_ok(c0_kind_r));
    CHECK(n00b_result_get(c0_kind_r) == N00B_PLAN_PATH_KEY);
    auto c0_key_r = n00b_plan_path_component_key(c0);
    CHECK(n00b_result_is_ok(c0_key_r));
    CHECK(n00b_option_is_set(n00b_result_get(c0_key_r)));
    CHECK(n00b_unicode_str_eq(n00b_option_get(n00b_result_get(c0_key_r)),
                              r"payload"));
    auto c0_index_r = n00b_plan_path_component_index(c0);
    CHECK(n00b_result_is_ok(c0_index_r));
    CHECK(!n00b_option_is_set(n00b_result_get(c0_index_r)));

    auto c1_r = n00b_plan_path_component_at(path, 1);
    CHECK(n00b_result_is_ok(c1_r));
    CHECK(n00b_option_is_set(n00b_result_get(c1_r)));
    n00b_plan_path_component_t *c1 = n00b_option_get(n00b_result_get(c1_r));
    auto c1_kind_r = n00b_plan_path_component_kind(c1);
    CHECK(n00b_result_is_ok(c1_kind_r));
    CHECK(n00b_result_get(c1_kind_r) == N00B_PLAN_PATH_INDEX);
    auto c1_key_r = n00b_plan_path_component_key(c1);
    CHECK(n00b_result_is_ok(c1_key_r));
    CHECK(!n00b_option_is_set(n00b_result_get(c1_key_r)));
    auto c1_index_r = n00b_plan_path_component_index(c1);
    CHECK(n00b_result_is_ok(c1_index_r));
    CHECK(n00b_option_is_set(n00b_result_get(c1_index_r)));
    CHECK(n00b_option_get(n00b_result_get(c1_index_r)) == 0);

    auto c_far_r = n00b_plan_path_component_at(path, 9);
    CHECK(n00b_result_is_ok(c_far_r));
    CHECK(!n00b_option_is_set(n00b_result_get(c_far_r)));

    return path;
}

static void
test_targets_and_any_field_contract(void)
{
    CHECK(n00b_plan_err_str(N00B_PLAN_OK) != nullptr);
    CHECK(n00b_plan_err_str(N00B_PLAN_ERR_ANY_UNSUPPORTED) != nullptr);
    CHECK(n00b_plan_err_str(9999) != nullptr);

    n00b_plan_target_t *field = field_target(r"message");
    n00b_plan_target_t *any   = any_target();
    check_target_field(field, r"message");
    check_target_any(any);

    n00b_plan_predicate_t *any_contains =
        predicate_ok(n00b_plan_predicate_contains(any, r"panic"));
    check_leaf(any_contains, N00B_PLAN_LEAF_CONTAINS);
    check_leaf_target(any_contains, any);
    check_text(any_contains, r"panic");

    CHECK_ERR(n00b_plan_target_field(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_target_field(r""), N00B_PLAN_ERR_ARG);

    n00b_plan_value_t one = json_value(n00b_json_int_new(1));
    n00b_plan_value_t two = json_value(n00b_json_int_new(2));
    CHECK_ERR(n00b_plan_predicate_eq(any, one),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);
    CHECK_ERR(n00b_plan_predicate_range(any, one, two),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);
    CHECK_ERR(n00b_plan_predicate_exists(any),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);
    CHECK_ERR(n00b_plan_predicate_prefix(any, r"pan"),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"pan.*"));
    CHECK_ERR(n00b_plan_predicate_regex(any, regex),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);
    CHECK_ERR(n00b_plan_predicate_under(any, sample_path()),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);

    n00b_plan_value_list_t *values = n00b_plan_value_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_value_list_append(values, one)));
    CHECK_ERR(n00b_plan_predicate_in(any, values),
              N00B_PLAN_ERR_ANY_UNSUPPORTED);
}

static void
test_representative_field_leaves(void)
{
    n00b_plan_target_t *level   = field_target(r"level");
    n00b_plan_target_t *message = field_target(r"message");

    n00b_json_node_t *error_node = n00b_json_string_new_from_n00b(r"error");
    n00b_plan_predicate_t *eq =
        predicate_ok(n00b_plan_predicate_eq(level, json_value(error_node)));
    check_leaf(eq, N00B_PLAN_LEAF_EQ);
    check_leaf_target(eq, level);

    auto value_r = n00b_plan_predicate_value(eq);
    CHECK(n00b_result_is_ok(value_r));
    CHECK(n00b_option_is_set(n00b_result_get(value_r)));
    n00b_plan_value_t eq_value = n00b_option_get(n00b_result_get(value_r));
    CHECK(n00b_variant_is_type(eq_value, n00b_json_node_t *));
    CHECK(n00b_variant_get(eq_value, n00b_json_node_t *) == error_node);

    n00b_plan_value_list_t *in_values = n00b_plan_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_value_list_append(in_values,
                                    json_value(n00b_json_int_new(200)))));
    CHECK(n00b_result_is_ok(
        n00b_plan_value_list_append(in_values,
                                    json_value(n00b_json_int_new(500)))));
    n00b_plan_predicate_t *in =
        predicate_ok(n00b_plan_predicate_in(field_target(r"status"),
                                            in_values));
    check_leaf(in, N00B_PLAN_LEAF_IN);
    auto values_r = n00b_plan_predicate_values(in);
    CHECK(n00b_result_is_ok(values_r));
    CHECK(n00b_option_is_set(n00b_result_get(values_r)));
    CHECK(n00b_option_get(n00b_result_get(values_r)) == in_values);
    CHECK(n00b_list_len(*in_values) == 2);

    n00b_plan_predicate_t *range = predicate_ok(
        n00b_plan_predicate_range(field_target(r"latency_ms"),
                                  json_value(n00b_json_int_new(10)),
                                  json_value(n00b_json_int_new(50)),
                                  .include_lower = false));
    check_leaf(range, N00B_PLAN_LEAF_RANGE);
    CHECK(n00b_result_is_ok(n00b_plan_predicate_range_lower(range)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_range_upper(range)));
    auto include_lower_r = n00b_plan_predicate_range_include_lower(range);
    auto include_upper_r = n00b_plan_predicate_range_include_upper(range);
    CHECK(n00b_result_is_ok(include_lower_r));
    CHECK(n00b_result_is_ok(include_upper_r));
    CHECK(!n00b_result_get(include_lower_r));
    CHECK(n00b_result_get(include_upper_r));

    n00b_plan_predicate_t *exists =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"trace_id")));
    check_leaf(exists, N00B_PLAN_LEAF_EXISTS);

    n00b_plan_predicate_t *contains =
        predicate_ok(n00b_plan_predicate_contains(message, r"timeout"));
    check_leaf(contains, N00B_PLAN_LEAF_CONTAINS);
    check_text(contains, r"timeout");

    n00b_plan_predicate_t *prefix =
        predicate_ok(n00b_plan_predicate_prefix(message, r"time"));
    check_leaf(prefix, N00B_PLAN_LEAF_PREFIX);
    check_text(prefix, r"time");

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"time(out)?"));
    n00b_plan_predicate_t *regex_pred =
        predicate_ok(n00b_plan_predicate_regex(message, regex));
    check_leaf(regex_pred, N00B_PLAN_LEAF_REGEX);
    auto regex_r = n00b_plan_predicate_regex_handle(regex_pred);
    CHECK(n00b_result_is_ok(regex_r));
    CHECK(n00b_option_is_set(n00b_result_get(regex_r)));
    CHECK(n00b_option_get(n00b_result_get(regex_r)) == regex);

    n00b_plan_path_t *path = sample_path();
    n00b_plan_predicate_t *under =
        predicate_ok(n00b_plan_predicate_under(field_target(r"payload"),
                                               path));
    check_leaf(under, N00B_PLAN_LEAF_UNDER);
    auto path_r = n00b_plan_predicate_path(under);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_option_is_set(n00b_result_get(path_r)));
    CHECK(n00b_option_get(n00b_result_get(path_r)) == path);
}

static void
test_boolean_child_order_and_not_ownership(void)
{
    n00b_plan_predicate_t *a = predicate_ok(
        n00b_plan_predicate_exists(field_target(r"a")));
    n00b_plan_predicate_t *b = predicate_ok(
        n00b_plan_predicate_contains(field_target(r"b"), r"needle"));
    n00b_plan_predicate_t *c = predicate_ok(
        n00b_plan_predicate_prefix(field_target(r"c"), r"pre"));

    n00b_plan_predicate_list_t *and_children =
        n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children, a)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children, b)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(and_children, c)));

    n00b_plan_predicate_t *and =
        predicate_ok(n00b_plan_predicate_and(and_children));
    check_kind(and, N00B_PLAN_PREDICATE_AND);
    auto and_count_r = n00b_plan_predicate_child_count(and);
    CHECK(n00b_result_is_ok(and_count_r));
    CHECK(n00b_result_get(and_count_r) == 3);

    auto and0 = n00b_plan_predicate_child_at(and, 0);
    auto and1 = n00b_plan_predicate_child_at(and, 1);
    auto and2 = n00b_plan_predicate_child_at(and, 2);
    auto and3 = n00b_plan_predicate_child_at(and, 3);
    CHECK(n00b_result_is_ok(and0));
    CHECK(n00b_result_is_ok(and1));
    CHECK(n00b_result_is_ok(and2));
    CHECK(n00b_result_is_ok(and3));
    CHECK(n00b_option_get(n00b_result_get(and0)) == a);
    CHECK(n00b_option_get(n00b_result_get(and1)) == b);
    CHECK(n00b_option_get(n00b_result_get(and2)) == c);
    CHECK(!n00b_option_is_set(n00b_result_get(and3)));

    n00b_plan_predicate_list_t *or_children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(or_children, c)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(or_children, a)));
    n00b_plan_predicate_t *or =
        predicate_ok(n00b_plan_predicate_or(or_children));
    check_kind(or, N00B_PLAN_PREDICATE_OR);
    auto or0 = n00b_plan_predicate_child_at(or, 0);
    auto or1 = n00b_plan_predicate_child_at(or, 1);
    CHECK(n00b_result_is_ok(or0));
    CHECK(n00b_result_is_ok(or1));
    CHECK(n00b_option_get(n00b_result_get(or0)) == c);
    CHECK(n00b_option_get(n00b_result_get(or1)) == a);

    n00b_plan_predicate_t *not = predicate_ok(n00b_plan_predicate_not(or));
    check_kind(not, N00B_PLAN_PREDICATE_NOT);
    auto not_count_r = n00b_plan_predicate_child_count(not);
    CHECK(n00b_result_is_ok(not_count_r));
    CHECK(n00b_result_get(not_count_r) == 1);
    auto not_child_r = n00b_plan_predicate_child_at(not, 0);
    CHECK(n00b_result_is_ok(not_child_r));
    CHECK(n00b_option_get(n00b_result_get(not_child_r)) == or);
    auto not_far_r = n00b_plan_predicate_child_at(not, 1);
    CHECK(n00b_result_is_ok(not_far_r));
    CHECK(!n00b_option_is_set(n00b_result_get(not_far_r)));

    auto leaf_count_r = n00b_plan_predicate_child_count(a);
    CHECK(n00b_result_is_ok(leaf_count_r));
    CHECK(n00b_result_get(leaf_count_r) == 0);
    auto leaf_child_r = n00b_plan_predicate_child_at(a, 0);
    CHECK(n00b_result_is_ok(leaf_child_r));
    CHECK(!n00b_option_is_set(n00b_result_get(leaf_child_r)));
}

static void
test_false_predicate_shape(void)
{
    n00b_plan_predicate_t *predicate =
        predicate_ok(n00b_plan_predicate_false());

    check_kind(predicate, N00B_PLAN_PREDICATE_FALSE);

    auto child_count_r = n00b_plan_predicate_child_count(predicate);
    CHECK(n00b_result_is_ok(child_count_r));
    CHECK(n00b_result_get(child_count_r) == 0);

    auto child_r = n00b_plan_predicate_child_at(predicate, 0);
    CHECK(n00b_result_is_ok(child_r));
    CHECK(!n00b_option_is_set(n00b_result_get(child_r)));

    auto target_r = n00b_plan_predicate_target(predicate);
    CHECK(n00b_result_is_ok(target_r));
    CHECK(!n00b_option_is_set(n00b_result_get(target_r)));

    auto value_r = n00b_plan_predicate_value(predicate);
    CHECK(n00b_result_is_ok(value_r));
    CHECK(!n00b_option_is_set(n00b_result_get(value_r)));

    CHECK_ERR(n00b_plan_predicate_leaf_op(predicate), N00B_PLAN_ERR_STATE);
    CHECK_ERR(n00b_plan_predicate_range_include_lower(predicate),
              N00B_PLAN_ERR_STATE);
}

static void
test_null_and_invalid_inputs(void)
{
    n00b_plan_target_t *field = field_target(r"field");
    n00b_plan_value_t  one   = json_value(n00b_json_int_new(1));
    n00b_plan_value_t  empty = n00b_variant_empty(n00b_plan_value_t);

    CHECK_ERR(n00b_plan_target_kind(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_target_field_name(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_eq(nullptr, one), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_eq(field, empty), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_range(field, empty, one),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_contains(field, nullptr),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_contains(field, r""), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_prefix(field, nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_regex(field, nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_under(field, nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_not(nullptr), N00B_PLAN_ERR_ARG);

    n00b_plan_value_list_t *values = n00b_plan_value_list_new();
    CHECK_ERR(n00b_plan_value_list_append(nullptr, one), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_value_list_append(values, empty), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_in(field, nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_in(field, values), N00B_PLAN_ERR_EMPTY);

    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    CHECK_ERR(n00b_plan_predicate_list_append(nullptr, nullptr),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_list_append(children, nullptr),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_and(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_and(children), N00B_PLAN_ERR_EMPTY);

    n00b_plan_predicate_t *leaf =
        predicate_ok(n00b_plan_predicate_exists(field));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(children, leaf)));
    CHECK_ERR(n00b_plan_predicate_or(children), N00B_PLAN_ERR_EMPTY);

    CHECK_ERR(n00b_plan_predicate_kind(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_leaf_op(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_child_count(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_child_at(nullptr, 0), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_value(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_predicate_range_include_lower(leaf),
              N00B_PLAN_ERR_STATE);
    CHECK_ERR(n00b_plan_predicate_leaf_op(
                  predicate_ok(n00b_plan_predicate_not(leaf))),
              N00B_PLAN_ERR_STATE);

    n00b_plan_path_component_list_t *components =
        n00b_plan_path_component_list_new();
    CHECK_ERR(n00b_plan_path_component_list_append_key(nullptr, r"x"),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_list_append_key(components, nullptr),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_list_append_index(nullptr, 1),
              N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_new(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_count(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_at(nullptr, 0), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_kind(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_key(nullptr), N00B_PLAN_ERR_ARG);
    CHECK_ERR(n00b_plan_path_component_index(nullptr), N00B_PLAN_ERR_ARG);
}

static void
test_variant_only_value_contract(void)
{
    n00b_plan_target_t *field = field_target(r"scalar");
    n00b_json_node_t   *int_node = n00b_json_int_new(1);
    n00b_json_node_t   *str_node = n00b_json_string_new_from_n00b(r"1");

    n00b_plan_predicate_t *int_eq =
        predicate_ok(n00b_plan_predicate_eq(field, json_value(int_node)));
    n00b_plan_predicate_t *str_eq =
        predicate_ok(n00b_plan_predicate_eq(field, json_value(str_node)));

    check_leaf(int_eq, N00B_PLAN_LEAF_EQ);
    check_leaf(str_eq, N00B_PLAN_LEAF_EQ);

    n00b_plan_value_t int_value =
        n00b_option_get(n00b_result_get(n00b_plan_predicate_value(int_eq)));
    n00b_plan_value_t str_value =
        n00b_option_get(n00b_result_get(n00b_plan_predicate_value(str_eq)));

    CHECK(n00b_variant_is_type(int_value, n00b_json_node_t *));
    CHECK(n00b_variant_is_type(str_value, n00b_json_node_t *));
    CHECK(n00b_variant_get(int_value, n00b_json_node_t *) == int_node);
    CHECK(n00b_variant_get(str_value, n00b_json_node_t *) == str_node);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_targets_and_any_field_contract();
    test_representative_field_leaves();
    test_boolean_child_order_and_not_ownership();
    test_false_predicate_shape();
    test_null_and_invalid_inputs();
    test_variant_only_value_contract();

    n00b_shutdown();
    return 0;
}

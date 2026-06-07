/* test/unit/test_rocs_filter_lowering.c - WP-007 Phase 4 lowering. */

#include <stdint.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include "rocs/filter.h"

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "rocs/filter.h must not include internal planner declarations"
#endif

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "rocs/n00b_rocs.h must not include internal planner declarations"
#endif

#include "internal/rocs/filter.h"

#ifndef N00B_ROCS_INTERNAL_PLAN_H
#error "internal filter lowering must include internal planner declarations"
#endif

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_check_err_result));                       \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));        \
    } while (0)

static n00b_filter_field_t *
field_ok(n00b_result_t(n00b_filter_field_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_field_t *field = n00b_result_get(r);
    CHECK(field != nullptr);
    return field;
}

static n00b_filter_t *
filter_ok(n00b_result_t(n00b_filter_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_t *filter = n00b_result_get(r);
    CHECK(filter != nullptr);
    return filter;
}

static n00b_filter_path_component_t *
component_ok(n00b_result_t(n00b_filter_path_component_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_path_component_t *component = n00b_result_get(r);
    CHECK(component != nullptr);
    return component;
}

static n00b_filter_path_t *
path_ok(n00b_result_t(n00b_filter_path_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_path_t *path = n00b_result_get(r);
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

static n00b_plan_predicate_t *
plan_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_predicate_t *predicate = n00b_result_get(r);
    CHECK(predicate != nullptr);
    return predicate;
}

static n00b_filter_field_t *
field_named(n00b_string_t *name)
{
    return field_ok(n00b_filter_field(name));
}

static n00b_filter_path_t *
sample_filter_path(void)
{
    n00b_filter_path_component_list_t *components =
        n00b_filter_path_component_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_key(r"items")))));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_index(2)))));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_key(r"message")))));
    return path_ok(n00b_filter_path(components));
}

static n00b_plan_predicate_t *
lower_ok(n00b_filter_t *filter)
{
    return plan_ok(n00b_filter_lower_to_plan(filter));
}

static void
check_kind(n00b_plan_predicate_t *predicate,
           n00b_plan_predicate_kind_t kind)
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

static n00b_plan_target_t *
required_target(n00b_plan_predicate_t *predicate)
{
    auto target_r = n00b_plan_predicate_target(predicate);
    CHECK(n00b_result_is_ok(target_r));
    n00b_option_t(n00b_plan_target_t *) target_opt = n00b_result_get(target_r);
    CHECK(n00b_option_is_set(target_opt));
    return n00b_option_get(target_opt);
}

static void
check_target_field(n00b_plan_target_t *target, n00b_string_t *field)
{
    auto kind_r = n00b_plan_target_kind(target);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == N00B_PLAN_TARGET_FIELD);

    auto field_r = n00b_plan_target_field_name(target);
    CHECK(n00b_result_is_ok(field_r));
    n00b_option_t(n00b_string_t *) field_opt = n00b_result_get(field_r);
    CHECK(n00b_option_is_set(field_opt));
    CHECK(n00b_unicode_str_eq(n00b_option_get(field_opt), field));
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

static n00b_json_node_t *
required_json_node(n00b_plan_value_t value)
{
    CHECK(n00b_variant_is_type(value, n00b_json_node_t *));
    n00b_json_node_t *node = n00b_variant_get(value, n00b_json_node_t *);
    CHECK(node != nullptr);
    return node;
}

static n00b_json_node_t *
required_eq_json(n00b_plan_predicate_t *predicate)
{
    auto value_r = n00b_plan_predicate_value(predicate);
    CHECK(n00b_result_is_ok(value_r));
    n00b_option_t(n00b_plan_value_t) value_opt = n00b_result_get(value_r);
    CHECK(n00b_option_is_set(value_opt));
    return required_json_node(n00b_option_get(value_opt));
}

static n00b_plan_predicate_t *
required_child(n00b_plan_predicate_t *predicate, uint64_t ordinal)
{
    auto child_r = n00b_plan_predicate_child_at(predicate, ordinal);
    CHECK(n00b_result_is_ok(child_r));
    n00b_option_t(n00b_plan_predicate_t *) child_opt =
        n00b_result_get(child_r);
    CHECK(n00b_option_is_set(child_opt));
    return n00b_option_get(child_opt);
}

static void
test_scalar_value_lowering(void)
{
    n00b_filter_field_t *field = field_named(r"value");

    n00b_json_node_t *null_node = required_eq_json(
        lower_ok(filter_ok(n00b_filter_eq(field, n00b_fv_null()))));
    CHECK(n00b_json_is_null(null_node));

    n00b_json_node_t *bool_node = required_eq_json(
        lower_ok(filter_ok(n00b_filter_eq(field, n00b_fv_bool(true)))));
    CHECK(n00b_json_is_bool(bool_node));
    CHECK(n00b_json_as_bool(bool_node));

    n00b_json_node_t *i64_node = required_eq_json(
        lower_ok(filter_ok(n00b_filter_eq(field, n00b_fv_i64(-42)))));
    CHECK(n00b_json_is_int(i64_node));
    CHECK(n00b_json_as_i64(i64_node) == -42);

    n00b_json_node_t *u64_node = required_eq_json(
        lower_ok(filter_ok(n00b_filter_eq(field, n00b_fv_u64(42)))));
    CHECK(n00b_json_is_int(u64_node));
    CHECK(n00b_json_as_i64(u64_node) == 42);

    n00b_json_node_t *double_node = required_eq_json(
        lower_ok(filter_ok(n00b_filter_eq(field, n00b_fv_f64(1.5)))));
    CHECK(n00b_json_is_double(double_node));
    CHECK(n00b_json_as_f64(double_node) == 1.5);

    n00b_json_node_t *string_node = required_eq_json(
        lower_ok(filter_ok(n00b_filter_eq(field, n00b_fv_utf8(r"error")))));
    CHECK(n00b_json_is_string(string_node));
    CHECK(n00b_unicode_str_eq(n00b_json_as_string(string_node), r"error"));
}

static void
test_leaf_lowering(void)
{
    n00b_filter_field_t *level = field_named(r"level");
    n00b_plan_predicate_t *eq =
        lower_ok(filter_ok(n00b_filter_eq(level, n00b_fv_utf8(r"error"))));
    check_leaf(eq, N00B_PLAN_LEAF_EQ);
    check_target_field(required_target(eq), r"level");

    n00b_filter_value_list_t *values = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_i64(200))));
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_utf8(r"closed"))));
    n00b_plan_predicate_t *in =
        lower_ok(filter_ok(n00b_filter_in(field_named(r"status"),
                                          n00b_fv_list(values))));
    check_leaf(in, N00B_PLAN_LEAF_IN);
    check_target_field(required_target(in), r"status");
    auto values_r = n00b_plan_predicate_values(in);
    CHECK(n00b_result_is_ok(values_r));
    n00b_option_t(n00b_plan_value_list_t *) values_opt =
        n00b_result_get(values_r);
    CHECK(n00b_option_is_set(values_opt));
    n00b_plan_value_list_t *plan_values = n00b_option_get(values_opt);
    CHECK(n00b_list_len(*plan_values) == 2);
    CHECK(n00b_json_as_i64(required_json_node(n00b_list_get(*plan_values, 0)))
          == 200);
    CHECK(n00b_unicode_str_eq(
        n00b_json_as_string(required_json_node(n00b_list_get(*plan_values,
                                                             1))),
        r"closed"));

    n00b_plan_predicate_t *range = lower_ok(
        filter_ok(n00b_filter_between(field_named(r"latency_ms"),
                                      n00b_fv_i64(10),
                                      n00b_fv_f64(50.0),
                                      .include_lower = false)));
    check_leaf(range, N00B_PLAN_LEAF_RANGE);
    check_target_field(required_target(range), r"latency_ms");
    auto lower_r = n00b_plan_predicate_range_lower(range);
    auto upper_r = n00b_plan_predicate_range_upper(range);
    CHECK(n00b_result_is_ok(lower_r));
    CHECK(n00b_result_is_ok(upper_r));
    CHECK(n00b_json_as_i64(
              required_json_node(n00b_option_get(n00b_result_get(lower_r))))
          == 10);
    CHECK(n00b_json_as_f64(
              required_json_node(n00b_option_get(n00b_result_get(upper_r))))
          == 50.0);
    CHECK(!n00b_result_get(n00b_plan_predicate_range_include_lower(range)));
    CHECK(n00b_result_get(n00b_plan_predicate_range_include_upper(range)));

    n00b_plan_predicate_t *contains =
        lower_ok(filter_ok(n00b_filter_contains(field_named(r"message"),
                                                r"timeout")));
    check_leaf(contains, N00B_PLAN_LEAF_CONTAINS);
    check_target_field(required_target(contains), r"message");
    auto contains_text_r = n00b_plan_predicate_text(contains);
    CHECK(n00b_result_is_ok(contains_text_r));
    CHECK(n00b_unicode_str_eq(
        n00b_option_get(n00b_result_get(contains_text_r)),
        r"timeout"));

    n00b_plan_predicate_t *any_contains =
        lower_ok(filter_ok(n00b_filter_contains(n00b_filter_any(),
                                                r"panic")));
    check_leaf(any_contains, N00B_PLAN_LEAF_CONTAINS);
    check_target_any(required_target(any_contains));

    n00b_plan_predicate_t *prefix =
        lower_ok(filter_ok(n00b_filter_prefix(field_named(r"message"),
                                              r"time")));
    check_leaf(prefix, N00B_PLAN_LEAF_PREFIX);
    check_target_field(required_target(prefix), r"message");
    auto prefix_text_r = n00b_plan_predicate_text(prefix);
    CHECK(n00b_result_is_ok(prefix_text_r));
    CHECK(n00b_unicode_str_eq(n00b_option_get(n00b_result_get(prefix_text_r)),
                              r"time"));

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"time(out)?"));
    n00b_plan_predicate_t *regex_pred =
        lower_ok(filter_ok(n00b_filter_regex(field_named(r"message"),
                                             regex)));
    check_leaf(regex_pred, N00B_PLAN_LEAF_REGEX);
    check_target_field(required_target(regex_pred), r"message");
    auto regex_r = n00b_plan_predicate_regex_handle(regex_pred);
    CHECK(n00b_result_is_ok(regex_r));
    CHECK(n00b_option_get(n00b_result_get(regex_r)) == regex);

    n00b_plan_predicate_t *exists =
        lower_ok(filter_ok(n00b_filter_exists(field_named(r"trace_id"))));
    check_leaf(exists, N00B_PLAN_LEAF_EXISTS);
    check_target_field(required_target(exists), r"trace_id");

    n00b_filter_path_t *path = sample_filter_path();
    n00b_plan_predicate_t *under =
        lower_ok(filter_ok(n00b_filter_under(field_named(r"payload"), path)));
    check_leaf(under, N00B_PLAN_LEAF_UNDER);
    check_target_field(required_target(under), r"payload");
    auto path_r = n00b_plan_predicate_path(under);
    CHECK(n00b_result_is_ok(path_r));
    n00b_plan_path_t *plan_path = n00b_option_get(n00b_result_get(path_r));
    auto count_r = n00b_plan_path_component_count(plan_path);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 3);

    auto c0_r = n00b_plan_path_component_at(plan_path, 0);
    auto c1_r = n00b_plan_path_component_at(plan_path, 1);
    auto c2_r = n00b_plan_path_component_at(plan_path, 2);
    CHECK(n00b_result_is_ok(c0_r));
    CHECK(n00b_result_is_ok(c1_r));
    CHECK(n00b_result_is_ok(c2_r));
    n00b_plan_path_component_t *c0 = n00b_option_get(n00b_result_get(c0_r));
    n00b_plan_path_component_t *c1 = n00b_option_get(n00b_result_get(c1_r));
    n00b_plan_path_component_t *c2 = n00b_option_get(n00b_result_get(c2_r));
    CHECK(n00b_result_get(n00b_plan_path_component_kind(c0))
          == N00B_PLAN_PATH_KEY);
    CHECK(n00b_unicode_str_eq(
        n00b_option_get(n00b_result_get(n00b_plan_path_component_key(c0))),
        r"items"));
    CHECK(n00b_result_get(n00b_plan_path_component_kind(c1))
          == N00B_PLAN_PATH_INDEX);
    CHECK(n00b_option_get(n00b_result_get(n00b_plan_path_component_index(c1)))
          == 2);
    CHECK(n00b_result_get(n00b_plan_path_component_kind(c2))
          == N00B_PLAN_PATH_KEY);
    CHECK(n00b_unicode_str_eq(
        n00b_option_get(n00b_result_get(n00b_plan_path_component_key(c2))),
        r"message"));
}

static void
test_empty_in_lowers_to_false(void)
{
    n00b_filter_value_list_t *empty = n00b_filter_value_list_new();
    n00b_filter_t *filter =
        filter_ok(n00b_filter_in(field_named(r"status"),
                                 n00b_fv_list(empty)));
    n00b_plan_predicate_t *predicate = lower_ok(filter);

    check_kind(predicate, N00B_PLAN_PREDICATE_FALSE);
    auto child_count_r = n00b_plan_predicate_child_count(predicate);
    CHECK(n00b_result_is_ok(child_count_r));
    CHECK(n00b_result_get(child_count_r) == 0);
    CHECK_ERR(n00b_plan_predicate_leaf_op(predicate), N00B_PLAN_ERR_STATE);

    auto target_r = n00b_plan_predicate_target(predicate);
    CHECK(n00b_result_is_ok(target_r));
    CHECK(!n00b_option_is_set(n00b_result_get(target_r)));
}

static void
test_boolean_lowering_preserves_order(void)
{
    n00b_filter_t *a = filter_ok(n00b_filter_exists(field_named(r"a")));
    n00b_filter_t *b = filter_ok(n00b_filter_prefix(field_named(r"b"),
                                                    r"pre"));
    n00b_filter_t *c = filter_ok(n00b_filter_contains(field_named(r"c"),
                                                      r"needle"));
    n00b_filter_t *d =
        filter_ok(n00b_filter_regex(field_named(r"d"),
                                    regex_ok(n00b_regex_new(r"d+"))));

    n00b_filter_t *or = filter_ok(n00b_filter_or(b, c,
                                                 kw_func(n00b_filter_or)));
    n00b_filter_t *not = filter_ok(n00b_filter_not(d));
    n00b_filter_t *root = filter_ok(n00b_filter_and(a,
                                                    or,
                                                    not,
                                                    kw_func(n00b_filter_and)));

    n00b_plan_predicate_t *plan = lower_ok(root);
    check_kind(plan, N00B_PLAN_PREDICATE_AND);
    auto count_r = n00b_plan_predicate_child_count(plan);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 3);

    check_leaf(required_child(plan, 0), N00B_PLAN_LEAF_EXISTS);
    n00b_plan_predicate_t *or_plan = required_child(plan, 1);
    n00b_plan_predicate_t *not_plan = required_child(plan, 2);
    check_kind(or_plan, N00B_PLAN_PREDICATE_OR);
    check_kind(not_plan, N00B_PLAN_PREDICATE_NOT);

    check_leaf(required_child(or_plan, 0), N00B_PLAN_LEAF_PREFIX);
    check_leaf(required_child(or_plan, 1), N00B_PLAN_LEAF_CONTAINS);

    n00b_plan_predicate_t *not_child = required_child(not_plan, 0);
    CHECK(required_child(not_plan, 0) == not_child);
    check_leaf(not_child, N00B_PLAN_LEAF_REGEX);
}

static void
test_lowering_errors(void)
{
    n00b_filter_field_t *field = field_named(r"value");

    CHECK_ERR(n00b_filter_lower_to_plan(nullptr), N00B_FILTER_ERR_ARG);

    n00b_filter_t *bytes =
        filter_ok(n00b_filter_eq(field,
                                 n00b_fv_bytes(n00b_buffer_empty())));
    CHECK_ERR(n00b_filter_lower_to_plan(bytes), N00B_FILTER_ERR_UNSUPPORTED);

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"v+"));
    n00b_filter_t *regex_value =
        filter_ok(n00b_filter_eq(field, n00b_fv_regex(regex)));
    CHECK_ERR(n00b_filter_lower_to_plan(regex_value),
              N00B_FILTER_ERR_UNSUPPORTED);

    n00b_filter_t *large_u64 =
        filter_ok(n00b_filter_eq(field,
                                 n00b_fv_u64((uint64_t)INT64_MAX
                                             + UINT64_C(1))));
    CHECK_ERR(n00b_filter_lower_to_plan(large_u64),
              N00B_FILTER_ERR_UNSUPPORTED);

    n00b_filter_value_list_t *inner = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(inner, n00b_fv_i64(1))));
    n00b_filter_t *list_value =
        filter_ok(n00b_filter_eq(field, n00b_fv_list(inner)));
    CHECK_ERR(n00b_filter_lower_to_plan(list_value),
              N00B_FILTER_ERR_UNSUPPORTED);

    n00b_filter_value_list_t *outer = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(outer, n00b_fv_list(inner))));
    n00b_filter_t *nested_in =
        filter_ok(n00b_filter_in(field, n00b_fv_list(outer)));
    CHECK_ERR(n00b_filter_lower_to_plan(nested_in),
              N00B_FILTER_ERR_UNSUPPORTED);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_scalar_value_lowering();
    test_leaf_lowering();
    test_empty_in_lowers_to_false();
    test_boolean_lowering_preserves_order();
    test_lowering_errors();

    n00b_shutdown();
    return 0;
}

/* test/unit/test_rocs_filter_builder.c - WP-007 Phase 2 filter builders. */

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

static n00b_filter_field_t *
field_named(n00b_string_t *name)
{
    return field_ok(n00b_filter_field(name));
}

static n00b_filter_path_t *
sample_path(void)
{
    n00b_filter_path_component_list_t *components =
        n00b_filter_path_component_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_key(r"payload")))));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_index(0)))));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_key(r"message")))));
    return path_ok(n00b_filter_path(components));
}

static void
check_kind(n00b_filter_t *filter, n00b_filter_predicate_kind_t kind)
{
    auto kind_r = n00b_filter_predicate_kind(filter);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == kind);
}

static void
check_leaf(n00b_filter_t *filter,
           n00b_filter_leaf_op_t op,
           n00b_filter_field_t *field)
{
    check_kind(filter, N00B_FILTER_PREDICATE_LEAF);

    auto op_r = n00b_filter_predicate_leaf_op(filter);
    CHECK(n00b_result_is_ok(op_r));
    CHECK(n00b_result_get(op_r) == op);

    auto field_r = n00b_filter_predicate_field(filter);
    CHECK(n00b_result_is_ok(field_r));
    n00b_option_t(n00b_filter_field_t *) field_opt =
        n00b_result_get(field_r);
    CHECK(n00b_option_is_set(field_opt));
    CHECK(n00b_option_get(field_opt) == field);
}

static void
check_text(n00b_filter_t *filter, n00b_string_t *expected)
{
    auto text_r = n00b_filter_predicate_text(filter);
    CHECK(n00b_result_is_ok(text_r));
    n00b_option_t(n00b_string_t *) text_opt = n00b_result_get(text_r);
    CHECK(n00b_option_is_set(text_opt));
    CHECK(n00b_unicode_str_eq(n00b_option_get(text_opt), expected));
}

static void
test_error_strings(void)
{
    CHECK(n00b_filter_err_str(N00B_FILTER_OK) != nullptr);
    CHECK(n00b_filter_err_str(N00B_FILTER_ERR_UNSUPPORTED) != nullptr);
    CHECK(n00b_filter_err_str(N00B_FILTER_ERR_STATE) != nullptr);
    CHECK(n00b_filter_err_str(9999) != nullptr);
}

static void
test_leaf_constructors_and_inspectors(void)
{
    n00b_filter_field_t *level   = field_named(r"level");
    n00b_filter_field_t *message = field_named(r"message");

    n00b_filter_t *eq =
        filter_ok(n00b_filter_eq(level, n00b_fv_utf8(r"error")));
    check_leaf(eq, N00B_FILTER_LEAF_EQ, level);
    auto eq_value_r = n00b_filter_predicate_value(eq);
    CHECK(n00b_result_is_ok(eq_value_r));
    CHECK(n00b_option_is_set(n00b_result_get(eq_value_r)));
    n00b_filter_value_t eq_value =
        n00b_option_get(n00b_result_get(eq_value_r));
    CHECK(n00b_variant_is_type(eq_value, n00b_string_t *));
    CHECK(n00b_unicode_str_eq(n00b_variant_get(eq_value, n00b_string_t *),
                              r"error"));

    n00b_filter_t *eq_null =
        filter_ok(n00b_filter_eq(level, n00b_fv_null()));
    check_leaf(eq_null, N00B_FILTER_LEAF_EQ, level);

    n00b_filter_value_list_t *values = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_i64(200))));
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_i64(500))));
    n00b_filter_field_t *status = field_named(r"status");
    n00b_filter_t *in =
        filter_ok(n00b_filter_in(status, n00b_fv_list(values)));
    check_leaf(in, N00B_FILTER_LEAF_IN, status);
    auto values_r = n00b_filter_predicate_values(in);
    CHECK(n00b_result_is_ok(values_r));
    CHECK(n00b_option_is_set(n00b_result_get(values_r)));
    CHECK(n00b_option_get(n00b_result_get(values_r)) == values);

    n00b_filter_value_list_t *empty_values = n00b_filter_value_list_new();
    n00b_filter_t *empty_in =
        filter_ok(n00b_filter_in(level, n00b_fv_list(empty_values)));
    check_leaf(empty_in, N00B_FILTER_LEAF_IN, level);
    auto empty_values_r = n00b_filter_predicate_values(empty_in);
    CHECK(n00b_result_is_ok(empty_values_r));
    CHECK(n00b_option_is_set(n00b_result_get(empty_values_r)));
    auto empty_count_r = n00b_filter_value_list_count(
        n00b_option_get(n00b_result_get(empty_values_r)));
    CHECK(n00b_result_is_ok(empty_count_r));
    CHECK(n00b_result_get(empty_count_r) == 0);

    n00b_filter_field_t *latency = field_named(r"latency_ms");
    n00b_filter_t *range =
        filter_ok(n00b_filter_between(latency,
                                      n00b_fv_i64(10),
                                      n00b_fv_f64(50.0),
                                      .include_lower = false));
    check_leaf(range, N00B_FILTER_LEAF_RANGE, latency);
    auto lower_r = n00b_filter_predicate_range_lower(range);
    auto upper_r = n00b_filter_predicate_range_upper(range);
    CHECK(n00b_result_is_ok(lower_r));
    CHECK(n00b_result_is_ok(upper_r));
    CHECK(n00b_option_is_set(n00b_result_get(lower_r)));
    CHECK(n00b_option_is_set(n00b_result_get(upper_r)));
    auto lower_o = n00b_result_get(lower_r);
    auto upper_o = n00b_result_get(upper_r);
    n00b_filter_value_t lower_v = n00b_option_get(lower_o);
    n00b_filter_value_t upper_v = n00b_option_get(upper_o);
    CHECK(n00b_variant_is_type(lower_v, int64_t));
    CHECK(n00b_variant_is_type(upper_v, double));
    auto include_lower_r = n00b_filter_predicate_range_include_lower(range);
    auto include_upper_r = n00b_filter_predicate_range_include_upper(range);
    CHECK(n00b_result_is_ok(include_lower_r));
    CHECK(n00b_result_is_ok(include_upper_r));
    CHECK(!n00b_result_get(include_lower_r));
    CHECK(n00b_result_get(include_upper_r));

    n00b_filter_field_t *name = field_named(r"name");
    n00b_filter_t *string_range =
        filter_ok(n00b_filter_between(name,
                                      n00b_fv_utf8(r"a"),
                                      n00b_fv_utf8(r"z")));
    check_leaf(string_range, N00B_FILTER_LEAF_RANGE, name);

    n00b_filter_t *contains =
        filter_ok(n00b_filter_contains(message, r"timeout"));
    check_leaf(contains, N00B_FILTER_LEAF_CONTAINS, message);
    check_text(contains, r"timeout");

    n00b_filter_t *prefix =
        filter_ok(n00b_filter_prefix(message, r"time"));
    check_leaf(prefix, N00B_FILTER_LEAF_PREFIX, message);
    check_text(prefix, r"time");

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"time(out)?"));
    n00b_filter_t *regex_filter =
        filter_ok(n00b_filter_regex(message, regex));
    check_leaf(regex_filter, N00B_FILTER_LEAF_REGEX, message);
    auto regex_r = n00b_filter_predicate_regex_handle(regex_filter);
    CHECK(n00b_result_is_ok(regex_r));
    CHECK(n00b_option_is_set(n00b_result_get(regex_r)));
    CHECK(n00b_option_get(n00b_result_get(regex_r)) == regex);

    n00b_filter_field_t *trace_id = field_named(r"trace_id");
    n00b_filter_t *exists =
        filter_ok(n00b_filter_exists(trace_id));
    check_leaf(exists, N00B_FILTER_LEAF_EXISTS, trace_id);
    CHECK(!n00b_option_is_set(
        n00b_result_get(n00b_filter_predicate_text(exists))));

    n00b_filter_path_t *path = sample_path();
    n00b_filter_field_t *payload = field_named(r"payload");
    n00b_filter_t *under =
        filter_ok(n00b_filter_under(payload, path));
    check_leaf(under, N00B_FILTER_LEAF_UNDER, payload);
    auto path_r = n00b_filter_predicate_path(under);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_option_is_set(n00b_result_get(path_r)));
    CHECK(n00b_option_get(n00b_result_get(path_r)) == path);
}

static void
test_any_field_validity_matrix(void)
{
    n00b_filter_field_t *any = n00b_filter_any();
    CHECK(any != nullptr);

    n00b_filter_t *contains =
        filter_ok(n00b_filter_contains(any, r"panic"));
    check_leaf(contains, N00B_FILTER_LEAF_CONTAINS, any);

    n00b_filter_value_list_t *values = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_i64(1))));

    CHECK_ERR(n00b_filter_eq(any, n00b_fv_i64(1)),
              N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_in(any, n00b_fv_list(values)),
              N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_between(any, n00b_fv_i64(1), n00b_fv_i64(2)),
              N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_prefix(any, r"pa"),
              N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_regex(any, regex_ok(n00b_regex_new(r"pa.*"))),
              N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_exists(any), N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_under(any, sample_path()),
              N00B_FILTER_ERR_UNSUPPORTED);
}

static void
test_boolean_ordering_and_arity(void)
{
    n00b_filter_t *a = filter_ok(n00b_filter_exists(field_named(r"a")));
    n00b_filter_t *b = filter_ok(n00b_filter_contains(field_named(r"b"),
                                                      r"needle"));
    n00b_filter_t *c = filter_ok(n00b_filter_prefix(field_named(r"c"),
                                                    r"pre"));

    n00b_filter_t *and = filter_ok(n00b_filter_and(a, b, c,
                                                   kw_func(n00b_filter_and)));
    check_kind(and, N00B_FILTER_PREDICATE_AND);
    auto and_count_r = n00b_filter_predicate_child_count(and);
    CHECK(n00b_result_is_ok(and_count_r));
    CHECK(n00b_result_get(and_count_r) == 3);

    auto and0 = n00b_filter_predicate_child_at(and, 0);
    auto and1 = n00b_filter_predicate_child_at(and, 1);
    auto and2 = n00b_filter_predicate_child_at(and, 2);
    auto and3 = n00b_filter_predicate_child_at(and, 3);
    CHECK(n00b_result_is_ok(and0));
    CHECK(n00b_result_is_ok(and1));
    CHECK(n00b_result_is_ok(and2));
    CHECK(n00b_result_is_ok(and3));
    CHECK(n00b_option_get(n00b_result_get(and0)) == a);
    CHECK(n00b_option_get(n00b_result_get(and1)) == b);
    CHECK(n00b_option_get(n00b_result_get(and2)) == c);
    CHECK(!n00b_option_is_set(n00b_result_get(and3)));

    n00b_filter_t *or = filter_ok(n00b_filter_or(c, a,
                                                 kw_func(n00b_filter_or)));
    check_kind(or, N00B_FILTER_PREDICATE_OR);
    auto or_count_r = n00b_filter_predicate_child_count(or);
    CHECK(n00b_result_is_ok(or_count_r));
    CHECK(n00b_result_get(or_count_r) == 2);
    auto or0 = n00b_filter_predicate_child_at(or, 0);
    auto or1 = n00b_filter_predicate_child_at(or, 1);
    CHECK(n00b_result_is_ok(or0));
    CHECK(n00b_result_is_ok(or1));
    CHECK(n00b_option_get(n00b_result_get(or0)) == c);
    CHECK(n00b_option_get(n00b_result_get(or1)) == a);

    n00b_filter_t *not = filter_ok(n00b_filter_not(or));
    check_kind(not, N00B_FILTER_PREDICATE_NOT);
    auto not_count_r = n00b_filter_predicate_child_count(not);
    CHECK(n00b_result_is_ok(not_count_r));
    CHECK(n00b_result_get(not_count_r) == 1);
    auto not_child_r = n00b_filter_predicate_child_at(not, 0);
    CHECK(n00b_result_is_ok(not_child_r));
    CHECK(n00b_option_get(n00b_result_get(not_child_r)) == or);
    auto not_far_r = n00b_filter_predicate_child_at(not, 1);
    CHECK(n00b_result_is_ok(not_far_r));
    CHECK(!n00b_option_is_set(n00b_result_get(not_far_r)));

    auto leaf_count_r = n00b_filter_predicate_child_count(a);
    CHECK(n00b_result_is_ok(leaf_count_r));
    CHECK(n00b_result_get(leaf_count_r) == 0);
    auto leaf_child_r = n00b_filter_predicate_child_at(a, 0);
    CHECK(n00b_result_is_ok(leaf_child_r));
    CHECK(!n00b_option_is_set(n00b_result_get(leaf_child_r)));

    CHECK_ERR(n00b_filter_and(a, kw_func(n00b_filter_and)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_or(a, kw_func(n00b_filter_or)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_and(nullptr, a, kw_func(n00b_filter_and)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_or(a, nullptr, kw_func(n00b_filter_or)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_not(nullptr), N00B_FILTER_ERR_ARG);
}

static void
test_invalid_leaf_inputs(void)
{
    n00b_filter_field_t *field = field_named(r"field");
    n00b_filter_value_t empty = n00b_variant_empty(n00b_filter_value_t);

    CHECK_ERR(n00b_filter_eq(nullptr, n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_eq(field, empty), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_eq(field, n00b_fv_utf8(nullptr)),
              N00B_FILTER_ERR_ARG);

    n00b_filter_value_list_t *values = n00b_filter_value_list_new();
    CHECK_ERR(n00b_filter_in(field, empty), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_in(field, n00b_fv_i64(1)), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_in(field, n00b_fv_list(nullptr)),
              N00B_FILTER_ERR_ARG);
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_utf8(nullptr))));
    CHECK_ERR(n00b_filter_in(field, n00b_fv_list(values)),
              N00B_FILTER_ERR_ARG);

    n00b_buffer_t *bytes = n00b_buffer_empty();
    n00b_regex_t  *regex = regex_ok(n00b_regex_new(r"x.*"));
    CHECK_ERR(n00b_filter_between(field, empty, n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field, n00b_fv_null(), n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field, n00b_fv_bool(true), n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field, n00b_fv_bytes(bytes), n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field, n00b_fv_regex(regex), n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field,
                                  n00b_fv_list(n00b_filter_value_list_new()),
                                  n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field, n00b_fv_i64(1), n00b_fv_utf8(r"z")),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_between(field,
                                  n00b_fv_utf8(nullptr),
                                  n00b_fv_utf8(r"z")),
              N00B_FILTER_ERR_ARG);

    CHECK_ERR(n00b_filter_contains(field, nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_contains(field, r""), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_prefix(field, nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_prefix(field, r""), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_regex(field, nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_under(field, nullptr), N00B_FILTER_ERR_ARG);
}

static void
test_invalid_inspector_inputs(void)
{
    n00b_filter_t *leaf =
        filter_ok(n00b_filter_exists(field_named(r"field")));
    n00b_filter_t *not = filter_ok(n00b_filter_not(leaf));

    CHECK_ERR(n00b_filter_predicate_kind(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_leaf_op(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_field(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_child_count(nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_child_at(nullptr, 0),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_value(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_values(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_range_lower(nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_range_upper(nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_range_include_lower(nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_range_include_upper(nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_text(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_regex_handle(nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_predicate_path(nullptr), N00B_FILTER_ERR_ARG);

    CHECK_ERR(n00b_filter_predicate_leaf_op(not), N00B_FILTER_ERR_STATE);
    CHECK_ERR(n00b_filter_predicate_range_include_lower(leaf),
              N00B_FILTER_ERR_STATE);
    CHECK_ERR(n00b_filter_predicate_range_include_upper(leaf),
              N00B_FILTER_ERR_STATE);

    auto value_r = n00b_filter_predicate_value(leaf);
    CHECK(n00b_result_is_ok(value_r));
    CHECK(!n00b_option_is_set(n00b_result_get(value_r)));

    auto field_r = n00b_filter_predicate_field(not);
    CHECK(n00b_result_is_ok(field_r));
    CHECK(!n00b_option_is_set(n00b_result_get(field_r)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_error_strings();
    test_leaf_constructors_and_inspectors();
    test_any_field_validity_matrix();
    test_boolean_ordering_and_arity();
    test_invalid_leaf_inputs();
    test_invalid_inspector_inputs();

    n00b_shutdown();
    return 0;
}

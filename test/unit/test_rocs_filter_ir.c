/* test/unit/test_rocs_filter_ir.c - WP-007 Phase 3 filter IR round trip. */

#include <stdint.h>

#include "n00b.h"
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

static n00b_filter_ir_t *
ir_ok(n00b_result_t(n00b_filter_ir_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_filter_ir_t *ir = n00b_result_get(r);
    CHECK(ir != nullptr);
    return ir;
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
            component_ok(n00b_filter_path_index(3)))));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(
            components,
            component_ok(n00b_filter_path_key(r"message")))));
    return path_ok(n00b_filter_path(components));
}

static void
check_ir_kind(n00b_filter_ir_t *ir, n00b_filter_predicate_kind_t kind)
{
    auto kind_r = n00b_filter_ir_kind(ir);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == kind);
}

static void
check_filter_kind(n00b_filter_t *filter, n00b_filter_predicate_kind_t kind)
{
    auto kind_r = n00b_filter_predicate_kind(filter);
    CHECK(n00b_result_is_ok(kind_r));
    CHECK(n00b_result_get(kind_r) == kind);
}

static void
check_ir_leaf(n00b_filter_ir_t    *ir,
              n00b_filter_leaf_op_t op,
              n00b_filter_field_t  *field)
{
    check_ir_kind(ir, N00B_FILTER_PREDICATE_LEAF);

    auto op_r = n00b_filter_ir_leaf_op(ir);
    CHECK(n00b_result_is_ok(op_r));
    CHECK(n00b_result_get(op_r) == op);

    auto field_r = n00b_filter_ir_field(ir);
    CHECK(n00b_result_is_ok(field_r));
    n00b_option_t(n00b_filter_field_t *) field_opt =
        n00b_result_get(field_r);
    CHECK(n00b_option_is_set(field_opt));
    CHECK(n00b_option_get(field_opt) == field);
}

static void
check_filter_leaf(n00b_filter_t       *filter,
                  n00b_filter_leaf_op_t op,
                  n00b_filter_field_t  *field)
{
    check_filter_kind(filter, N00B_FILTER_PREDICATE_LEAF);

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

static n00b_filter_value_t
required_ir_value(n00b_filter_ir_t *ir)
{
    auto value_r = n00b_filter_ir_value(ir);
    CHECK(n00b_result_is_ok(value_r));
    n00b_option_t(n00b_filter_value_t) value_opt = n00b_result_get(value_r);
    CHECK(n00b_option_is_set(value_opt));
    return n00b_option_get(value_opt);
}

static n00b_filter_value_t
required_filter_value(n00b_filter_t *filter)
{
    auto value_r = n00b_filter_predicate_value(filter);
    CHECK(n00b_result_is_ok(value_r));
    n00b_option_t(n00b_filter_value_t) value_opt = n00b_result_get(value_r);
    CHECK(n00b_option_is_set(value_opt));
    return n00b_option_get(value_opt);
}

static n00b_filter_ir_t *
required_ir_child(n00b_filter_ir_t *ir, uint64_t ordinal)
{
    auto child_r = n00b_filter_ir_child_at(ir, ordinal);
    CHECK(n00b_result_is_ok(child_r));
    n00b_option_t(n00b_filter_ir_t *) child_opt = n00b_result_get(child_r);
    CHECK(n00b_option_is_set(child_opt));
    return n00b_option_get(child_opt);
}

static n00b_filter_t *
required_filter_child(n00b_filter_t *filter, uint64_t ordinal)
{
    auto child_r = n00b_filter_predicate_child_at(filter, ordinal);
    CHECK(n00b_result_is_ok(child_r));
    n00b_option_t(n00b_filter_t *) child_opt = n00b_result_get(child_r);
    CHECK(n00b_option_is_set(child_opt));
    return n00b_option_get(child_opt);
}

static void
test_leaf_round_trip_preserves_payloads(void)
{
    n00b_filter_field_t *level = field_named(r"level");
    n00b_filter_t *eq =
        filter_ok(n00b_filter_eq(level, n00b_fv_utf8(r"error")));
    n00b_filter_ir_t *eq_ir = ir_ok(n00b_filter_to_ir(eq));
    check_ir_leaf(eq_ir, N00B_FILTER_LEAF_EQ, level);
    n00b_filter_value_t eq_ir_value = required_ir_value(eq_ir);
    CHECK(n00b_variant_is_type(eq_ir_value, n00b_string_t *));
    CHECK(n00b_unicode_str_eq(
        n00b_variant_get(eq_ir_value, n00b_string_t *),
        r"error"));

    n00b_filter_t *eq_imported = filter_ok(n00b_filter_from_ir(eq_ir));
    check_filter_leaf(eq_imported, N00B_FILTER_LEAF_EQ, level);
    n00b_filter_value_t eq_value = required_filter_value(eq_imported);
    CHECK(n00b_variant_is_type(eq_value, n00b_string_t *));
    CHECK(n00b_unicode_str_eq(n00b_variant_get(eq_value, n00b_string_t *),
                              r"error"));

    n00b_filter_value_list_t *empty_values = n00b_filter_value_list_new();
    n00b_filter_t *empty_in =
        filter_ok(n00b_filter_in(level, n00b_fv_list(empty_values)));
    n00b_filter_ir_t *empty_in_ir = ir_ok(n00b_filter_to_ir(empty_in));
    check_ir_leaf(empty_in_ir, N00B_FILTER_LEAF_IN, level);
    n00b_filter_value_t empty_ir_value = required_ir_value(empty_in_ir);
    CHECK(n00b_variant_is_type(empty_ir_value, n00b_filter_value_list_t *));
    CHECK(n00b_variant_get(empty_ir_value, n00b_filter_value_list_t *)
          == empty_values);

    n00b_filter_t *empty_in_imported =
        filter_ok(n00b_filter_from_ir(empty_in_ir));
    check_filter_leaf(empty_in_imported, N00B_FILTER_LEAF_IN, level);
    auto values_r = n00b_filter_predicate_values(empty_in_imported);
    CHECK(n00b_result_is_ok(values_r));
    CHECK(n00b_option_is_set(n00b_result_get(values_r)));
    CHECK(n00b_option_get(n00b_result_get(values_r)) == empty_values);
    auto empty_count_r = n00b_filter_value_list_count(empty_values);
    CHECK(n00b_result_is_ok(empty_count_r));
    CHECK(n00b_result_get(empty_count_r) == 0);

    n00b_filter_field_t *latency = field_named(r"latency");
    n00b_filter_t *range =
        filter_ok(n00b_filter_between(latency,
                                      n00b_fv_i64(10),
                                      n00b_fv_i64(20),
                                      .include_lower = false,
                                      .include_upper = false));
    n00b_filter_ir_t *range_ir = ir_ok(n00b_filter_to_ir(range));
    check_ir_leaf(range_ir, N00B_FILTER_LEAF_RANGE, latency);
    CHECK(n00b_result_is_ok(n00b_filter_ir_range_lower(range_ir)));
    CHECK(n00b_result_is_ok(n00b_filter_ir_range_upper(range_ir)));
    auto lower_incl_r = n00b_filter_ir_range_include_lower(range_ir);
    auto upper_incl_r = n00b_filter_ir_range_include_upper(range_ir);
    CHECK(n00b_result_is_ok(lower_incl_r));
    CHECK(n00b_result_is_ok(upper_incl_r));
    CHECK(!n00b_result_get(lower_incl_r));
    CHECK(!n00b_result_get(upper_incl_r));

    n00b_filter_t *range_imported = filter_ok(n00b_filter_from_ir(range_ir));
    check_filter_leaf(range_imported, N00B_FILTER_LEAF_RANGE, latency);
    auto imported_lower_incl_r =
        n00b_filter_predicate_range_include_lower(range_imported);
    auto imported_upper_incl_r =
        n00b_filter_predicate_range_include_upper(range_imported);
    CHECK(n00b_result_is_ok(imported_lower_incl_r));
    CHECK(n00b_result_is_ok(imported_upper_incl_r));
    CHECK(!n00b_result_get(imported_lower_incl_r));
    CHECK(!n00b_result_get(imported_upper_incl_r));

    n00b_filter_field_t *any = n00b_filter_any();
    n00b_filter_t *contains_any =
        filter_ok(n00b_filter_contains(any, r"panic"));
    n00b_filter_ir_t *contains_any_ir =
        ir_ok(n00b_filter_to_ir(contains_any));
    check_ir_leaf(contains_any_ir, N00B_FILTER_LEAF_CONTAINS, any);
    auto contains_text_r = n00b_filter_ir_text(contains_any_ir);
    CHECK(n00b_result_is_ok(contains_text_r));
    CHECK(n00b_unicode_str_eq(
        n00b_option_get(n00b_result_get(contains_text_r)),
        r"panic"));
    n00b_filter_t *contains_any_imported =
        filter_ok(n00b_filter_from_ir(contains_any_ir));
    check_filter_leaf(contains_any_imported, N00B_FILTER_LEAF_CONTAINS, any);

    n00b_filter_field_t *message = field_named(r"message");
    n00b_filter_t *prefix =
        filter_ok(n00b_filter_prefix(message, r"time"));
    n00b_filter_ir_t *prefix_ir = ir_ok(n00b_filter_to_ir(prefix));
    check_ir_leaf(prefix_ir, N00B_FILTER_LEAF_PREFIX, message);
    n00b_filter_t *prefix_imported = filter_ok(n00b_filter_from_ir(prefix_ir));
    check_filter_leaf(prefix_imported, N00B_FILTER_LEAF_PREFIX, message);

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"time(out)?"));
    n00b_filter_t *regex_filter =
        filter_ok(n00b_filter_regex(message, regex));
    n00b_filter_ir_t *regex_ir = ir_ok(n00b_filter_to_ir(regex_filter));
    check_ir_leaf(regex_ir, N00B_FILTER_LEAF_REGEX, message);
    auto regex_r = n00b_filter_ir_regex_handle(regex_ir);
    CHECK(n00b_result_is_ok(regex_r));
    CHECK(n00b_option_get(n00b_result_get(regex_r)) == regex);
    n00b_filter_t *regex_imported = filter_ok(n00b_filter_from_ir(regex_ir));
    check_filter_leaf(regex_imported, N00B_FILTER_LEAF_REGEX, message);

    n00b_filter_field_t *trace_id = field_named(r"trace_id");
    n00b_filter_t *exists = filter_ok(n00b_filter_exists(trace_id));
    n00b_filter_ir_t *exists_ir = ir_ok(n00b_filter_to_ir(exists));
    check_ir_leaf(exists_ir, N00B_FILTER_LEAF_EXISTS, trace_id);
    CHECK(n00b_result_is_ok(n00b_filter_from_ir(exists_ir)));

    n00b_filter_path_t *path = sample_path();
    n00b_filter_field_t *payload = field_named(r"payload");
    n00b_filter_t *under = filter_ok(n00b_filter_under(payload, path));
    n00b_filter_ir_t *under_ir = ir_ok(n00b_filter_to_ir(under));
    check_ir_leaf(under_ir, N00B_FILTER_LEAF_UNDER, payload);
    auto path_r = n00b_filter_ir_path(under_ir);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_option_get(n00b_result_get(path_r)) == path);
    n00b_filter_t *under_imported = filter_ok(n00b_filter_from_ir(under_ir));
    auto imported_path_r = n00b_filter_predicate_path(under_imported);
    CHECK(n00b_result_is_ok(imported_path_r));
    CHECK(n00b_option_get(n00b_result_get(imported_path_r)) == path);
}

static void
test_nested_boolean_round_trip_preserves_order(void)
{
    n00b_filter_field_t *field_a = field_named(r"a");
    n00b_filter_field_t *field_b = field_named(r"b");
    n00b_filter_field_t *field_c = field_named(r"c");
    n00b_filter_field_t *field_d = field_named(r"d");

    n00b_filter_t *a = filter_ok(n00b_filter_exists(field_a));
    n00b_filter_t *b =
        filter_ok(n00b_filter_contains(field_b, r"needle"));
    n00b_filter_t *c =
        filter_ok(n00b_filter_prefix(field_c, r"pre"));
    n00b_filter_t *d =
        filter_ok(n00b_filter_regex(field_d,
                                    regex_ok(n00b_regex_new(r"d+"))));

    n00b_filter_t *or = filter_ok(n00b_filter_or(b, c,
                                                 kw_func(n00b_filter_or)));
    n00b_filter_t *not = filter_ok(n00b_filter_not(d));
    n00b_filter_t *root = filter_ok(n00b_filter_and(a,
                                                    or,
                                                    not,
                                                    kw_func(n00b_filter_and)));

    n00b_filter_ir_t *ir = ir_ok(n00b_filter_to_ir(root));
    check_ir_kind(ir, N00B_FILTER_PREDICATE_AND);
    auto count_r = n00b_filter_ir_child_count(ir);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 3);

    check_ir_leaf(required_ir_child(ir, 0), N00B_FILTER_LEAF_EXISTS, field_a);
    check_ir_kind(required_ir_child(ir, 1), N00B_FILTER_PREDICATE_OR);
    check_ir_kind(required_ir_child(ir, 2), N00B_FILTER_PREDICATE_NOT);
    CHECK(required_ir_child(required_ir_child(ir, 1), 0) != nullptr);
    CHECK(required_ir_child(required_ir_child(ir, 1), 1) != nullptr);

    n00b_filter_t *imported = filter_ok(n00b_filter_from_ir(ir));
    check_filter_kind(imported, N00B_FILTER_PREDICATE_AND);
    auto imported_count_r = n00b_filter_predicate_child_count(imported);
    CHECK(n00b_result_is_ok(imported_count_r));
    CHECK(n00b_result_get(imported_count_r) == 3);
    check_filter_leaf(required_filter_child(imported, 0),
                      N00B_FILTER_LEAF_EXISTS,
                      field_a);
    check_filter_kind(required_filter_child(imported, 1),
                      N00B_FILTER_PREDICATE_OR);
    check_filter_kind(required_filter_child(imported, 2),
                      N00B_FILTER_PREDICATE_NOT);
}

static void
test_ir_child_list_copy_immutability(void)
{
    n00b_filter_ir_t *a =
        n00b_filter_ir_exists_leaf(field_named(r"a"));
    n00b_filter_ir_t *b =
        n00b_filter_ir_text_leaf(field_named(r"b"),
                                 N00B_FILTER_LEAF_CONTAINS,
                                 r"needle");
    n00b_filter_ir_t *c =
        n00b_filter_ir_exists_leaf(field_named(r"c"));

    n00b_filter_ir_child_list_t *children =
        n00b_filter_ir_child_list_new();
    CHECK(n00b_result_is_ok(n00b_filter_ir_child_list_append(children, a)));
    CHECK(n00b_result_is_ok(n00b_filter_ir_child_list_append(children, b)));

    n00b_filter_ir_t *and_ir = n00b_filter_ir_and(children);
    CHECK(n00b_result_is_ok(n00b_filter_ir_child_list_append(children, c)));

    auto count_r = n00b_filter_ir_child_count(and_ir);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);
    CHECK(required_ir_child(and_ir, 0) == a);
    CHECK(required_ir_child(and_ir, 1) == b);

    n00b_filter_t *imported = filter_ok(n00b_filter_from_ir(and_ir));
    auto imported_count_r = n00b_filter_predicate_child_count(imported);
    CHECK(n00b_result_is_ok(imported_count_r));
    CHECK(n00b_result_get(imported_count_r) == 2);
}

static void
test_malformed_ir_imports_return_ir_errors(void)
{
    n00b_filter_field_t *field = field_named(r"field");
    n00b_filter_path_t  *path  = sample_path();

    CHECK_ERR(n00b_filter_from_ir(nullptr), N00B_FILTER_ERR_ARG);

    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_raw_node(9999)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_raw_leaf(9999, field)),
              N00B_FILTER_ERR_IR);

    n00b_filter_ir_child_list_t *one_child =
        n00b_filter_ir_child_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_ir_child_list_append(one_child,
                                         n00b_filter_ir_exists_leaf(field))));
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_and(one_child)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_and(nullptr)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_not(nullptr)),
              N00B_FILTER_ERR_IR);

    n00b_filter_ir_child_list_t *malformed_children =
        n00b_filter_ir_child_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_ir_child_list_append(malformed_children,
                                         n00b_filter_ir_exists_leaf(field))));
    CHECK(n00b_result_is_ok(
        n00b_filter_ir_child_list_append(malformed_children, nullptr)));
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_or(malformed_children)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_ir_child_list_append(nullptr, nullptr),
              N00B_FILTER_ERR_ARG);

    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_value_leaf(nullptr,
                                            N00B_FILTER_LEAF_EQ,
                                            n00b_fv_i64(1))),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_raw_leaf(N00B_FILTER_LEAF_EQ, field)),
              N00B_FILTER_ERR_IR);

    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_value_leaf(n00b_filter_any(),
                                            N00B_FILTER_LEAF_EQ,
                                            n00b_fv_i64(1))),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_value_leaf(field,
                                            N00B_FILTER_LEAF_IN,
                                            n00b_fv_i64(1))),
              N00B_FILTER_ERR_IR);

    n00b_filter_value_list_t *bad_values = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(bad_values, n00b_fv_utf8(nullptr))));
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_value_leaf(field,
                                            N00B_FILTER_LEAF_IN,
                                            n00b_fv_list(bad_values))),
              N00B_FILTER_ERR_IR);

    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_raw_leaf(N00B_FILTER_LEAF_RANGE, field)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_range_leaf(field,
                                            n00b_fv_bool(true),
                                            n00b_fv_i64(10))),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_range_leaf(field,
                                            n00b_fv_i64(1),
                                            n00b_fv_utf8(r"z"))),
              N00B_FILTER_ERR_IR);

    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_raw_leaf(N00B_FILTER_LEAF_CONTAINS,
                                          field)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_text_leaf(field,
                                           N00B_FILTER_LEAF_CONTAINS,
                                           r"")),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(
                  n00b_filter_ir_text_leaf(n00b_filter_any(),
                                           N00B_FILTER_LEAF_PREFIX,
                                           r"pre")),
              N00B_FILTER_ERR_IR);

    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_regex_leaf(field, nullptr)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_under_leaf(field, nullptr)),
              N00B_FILTER_ERR_IR);
    CHECK_ERR(n00b_filter_from_ir(n00b_filter_ir_under_leaf(n00b_filter_any(),
                                                            path)),
              N00B_FILTER_ERR_IR);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_leaf_round_trip_preserves_payloads();
    test_nested_boolean_round_trip_preserves_order();
    test_ir_child_list_copy_immutability();
    test_malformed_ir_imports_return_ir_errors();

    n00b_shutdown();
    return 0;
}

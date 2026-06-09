/* test/unit/test_rocs_filter_value.c - WP-007 Phase 1 filter foundation. */

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

static void
test_error_strings(void)
{
    CHECK(n00b_filter_err_str(N00B_FILTER_OK) != nullptr);
    CHECK(n00b_filter_err_str(N00B_FILTER_ERR_ARG) != nullptr);
    CHECK(n00b_filter_err_str(N00B_FILTER_ERR_PATH) != nullptr);
    CHECK(n00b_filter_err_str(9999) != nullptr);
}

static void
test_value_constructors_are_variant_only(void)
{
    n00b_filter_value_t null_value = n00b_fv_null();
    CHECK(n00b_variant_is_type(null_value, n00b_filter_null_t));

    n00b_filter_value_t bool_value = n00b_fv_bool(true);
    CHECK(n00b_variant_is_type(bool_value, bool));
    CHECK(n00b_variant_get(bool_value, bool));

    n00b_filter_value_t i64_value = n00b_fv_i64(-42);
    CHECK(n00b_variant_is_type(i64_value, int64_t));
    CHECK(n00b_variant_get(i64_value, int64_t) == -42);

    n00b_filter_value_t u64_value = n00b_fv_u64(42);
    CHECK(n00b_variant_is_type(u64_value, uint64_t));
    CHECK(n00b_variant_get(u64_value, uint64_t) == 42);

    n00b_filter_value_t f64_value = n00b_fv_f64(1.5);
    CHECK(n00b_variant_is_type(f64_value, double));
    CHECK(n00b_variant_get(f64_value, double) == 1.5);

    n00b_string_t *text = r"needle";
    n00b_filter_value_t text_value = n00b_fv_utf8(text);
    CHECK(n00b_variant_is_type(text_value, n00b_string_t *));
    CHECK(n00b_variant_get(text_value, n00b_string_t *) == text);

    n00b_buffer_t *bytes = n00b_buffer_empty();
    n00b_filter_value_t bytes_value = n00b_fv_bytes(bytes);
    CHECK(n00b_variant_is_type(bytes_value, n00b_buffer_t *));
    CHECK(n00b_variant_get(bytes_value, n00b_buffer_t *) == bytes);

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"need.*"));
    n00b_filter_value_t regex_value = n00b_fv_regex(regex);
    CHECK(n00b_variant_is_type(regex_value, n00b_regex_t *));
    CHECK(n00b_variant_get(regex_value, n00b_regex_t *) == regex);

    n00b_filter_value_list_t *values = n00b_filter_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_i64(1))));
    CHECK(n00b_result_is_ok(
        n00b_filter_value_list_append(values, n00b_fv_utf8(r"two"))));

    auto count_r = n00b_filter_value_list_count(values);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    auto first_r = n00b_filter_value_list_at(values, 0);
    CHECK(n00b_result_is_ok(first_r));
    n00b_option_t(n00b_filter_value_t) first = n00b_result_get(first_r);
    CHECK(n00b_option_is_set(first));
    n00b_filter_value_t first_value = n00b_option_get(first);
    CHECK(n00b_variant_is_type(first_value, int64_t));
    CHECK(n00b_variant_get(first_value, int64_t) == 1);

    auto far_r = n00b_filter_value_list_at(values, 9);
    CHECK(n00b_result_is_ok(far_r));
    CHECK(!n00b_option_is_set(n00b_result_get(far_r)));

    n00b_filter_value_t list_value = n00b_fv_list(values);
    CHECK(n00b_variant_is_type(list_value, n00b_filter_value_list_t *));
    CHECK(n00b_variant_get(list_value, n00b_filter_value_list_t *) == values);

    n00b_filter_value_t empty = n00b_variant_empty(n00b_filter_value_t);
    CHECK_ERR(n00b_filter_value_list_append(values, empty),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_value_list_append(nullptr, n00b_fv_i64(1)),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_value_list_count(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_value_list_at(nullptr, 0), N00B_FILTER_ERR_ARG);
}

static void
test_fields_and_any_identity(void)
{
    n00b_filter_field_t *any_a = n00b_filter_any();
    n00b_filter_field_t *any_b = n00b_filter_any();
    CHECK(any_a != nullptr);
    CHECK(any_a == any_b);

    n00b_filter_field_t *named = field_ok(n00b_filter_field(r"*"));
    CHECK(named != any_a);

    auto any_is_any_r = n00b_filter_field_is_any(any_a);
    CHECK(n00b_result_is_ok(any_is_any_r));
    CHECK(n00b_result_get(any_is_any_r));

    auto named_is_any_r = n00b_filter_field_is_any(named);
    CHECK(n00b_result_is_ok(named_is_any_r));
    CHECK(!n00b_result_get(named_is_any_r));

    auto any_name_r = n00b_filter_field_name(any_a);
    CHECK(n00b_result_is_ok(any_name_r));
    CHECK(!n00b_option_is_set(n00b_result_get(any_name_r)));

    auto named_name_r = n00b_filter_field_name(named);
    CHECK(n00b_result_is_ok(named_name_r));
    n00b_option_t(n00b_string_t *) name = n00b_result_get(named_name_r);
    CHECK(n00b_option_is_set(name));
    CHECK(n00b_unicode_str_eq(n00b_option_get(name), r"*"));

    CHECK_ERR(n00b_filter_field(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_field(r""), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_field_is_any(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_field_name(nullptr), N00B_FILTER_ERR_ARG);
}

static void
test_paths_are_typed_and_immutable(void)
{
    n00b_filter_path_component_list_t *components =
        n00b_filter_path_component_list_new();
    n00b_filter_path_component_t *payload =
        component_ok(n00b_filter_path_key(r"payload"));
    n00b_filter_path_component_t *index =
        component_ok(n00b_filter_path_index(2));

    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(components, payload)));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(components, index)));

    n00b_filter_path_t *path = path_ok(n00b_filter_path(components));

    auto count_r = n00b_filter_path_component_count(path);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    n00b_filter_path_component_t *extra =
        component_ok(n00b_filter_path_key(r"ignored"));
    CHECK(n00b_result_is_ok(
        n00b_filter_path_component_list_append(components, extra)));

    count_r = n00b_filter_path_component_count(path);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);

    auto c0_r = n00b_filter_path_component_at(path, 0);
    CHECK(n00b_result_is_ok(c0_r));
    CHECK(n00b_option_is_set(n00b_result_get(c0_r)));
    n00b_filter_path_component_t *c0 = n00b_option_get(n00b_result_get(c0_r));
    CHECK(c0 != payload);

    auto c0_kind_r = n00b_filter_path_component_kind(c0);
    CHECK(n00b_result_is_ok(c0_kind_r));
    CHECK(n00b_result_get(c0_kind_r) == N00B_FILTER_PATH_KEY);

    auto c0_key_r = n00b_filter_path_component_key(c0);
    CHECK(n00b_result_is_ok(c0_key_r));
    CHECK(n00b_option_is_set(n00b_result_get(c0_key_r)));
    CHECK(n00b_unicode_str_eq(n00b_option_get(n00b_result_get(c0_key_r)),
                              r"payload"));

    auto c0_index_r = n00b_filter_path_component_index(c0);
    CHECK(n00b_result_is_ok(c0_index_r));
    CHECK(!n00b_option_is_set(n00b_result_get(c0_index_r)));

    auto c1_r = n00b_filter_path_component_at(path, 1);
    CHECK(n00b_result_is_ok(c1_r));
    CHECK(n00b_option_is_set(n00b_result_get(c1_r)));
    n00b_filter_path_component_t *c1 = n00b_option_get(n00b_result_get(c1_r));
    CHECK(c1 != index);

    auto c1_kind_r = n00b_filter_path_component_kind(c1);
    CHECK(n00b_result_is_ok(c1_kind_r));
    CHECK(n00b_result_get(c1_kind_r) == N00B_FILTER_PATH_INDEX);

    auto c1_key_r = n00b_filter_path_component_key(c1);
    CHECK(n00b_result_is_ok(c1_key_r));
    CHECK(!n00b_option_is_set(n00b_result_get(c1_key_r)));

    auto c1_index_r = n00b_filter_path_component_index(c1);
    CHECK(n00b_result_is_ok(c1_index_r));
    CHECK(n00b_option_is_set(n00b_result_get(c1_index_r)));
    CHECK(n00b_option_get(n00b_result_get(c1_index_r)) == 2);

    auto far_r = n00b_filter_path_component_at(path, 9);
    CHECK(n00b_result_is_ok(far_r));
    CHECK(!n00b_option_is_set(n00b_result_get(far_r)));
}

static void
test_invalid_path_inputs(void)
{
    CHECK_ERR(n00b_filter_path_key(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_list_append(nullptr, nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_list_append(
                  n00b_filter_path_component_list_new(),
                  nullptr),
              N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_count(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_at(nullptr, 0), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_kind(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_key(nullptr), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_path_component_index(nullptr), N00B_FILTER_ERR_ARG);

    n00b_filter_path_component_list_t *bad_components =
        n00b_filter_path_component_list_new();
    n00b_list_push(*bad_components, nullptr);
    CHECK_ERR(n00b_filter_path(bad_components), N00B_FILTER_ERR_PATH);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_error_strings();
    test_value_constructors_are_variant_only();
    test_fields_and_any_identity();
    test_paths_are_typed_and_immutable();
    test_invalid_path_inputs();

    n00b_shutdown();
    return 0;
}

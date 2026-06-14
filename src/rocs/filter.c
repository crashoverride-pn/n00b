#include "internal/rocs/filter.h"

#include "internal/rocs/json_field.h"

typedef enum : int32_t {
    ROCS_FILTER_FIELD_NAMED = 1,
    ROCS_FILTER_FIELD_ANY   = 2,
} rocs_filter_field_kind_t;

typedef enum : int32_t {
    ROCS_FILTER_RANGE_INVALID = 0,
    ROCS_FILTER_RANGE_NUMERIC = 1,
    ROCS_FILTER_RANGE_UTF8    = 2,
} rocs_filter_range_family_t;

typedef n00b_list_t(n00b_filter_t *) rocs_filter_child_list_t;

struct n00b_filter_ir_t {
    int32_t                       kind;
    int32_t                       leaf_op;
    n00b_filter_field_t          *field;
    n00b_filter_ir_child_list_t  *children;
    n00b_filter_ir_t             *child;
    n00b_filter_value_t          *value;
    n00b_filter_value_t          *lower;
    n00b_filter_value_t          *upper;
    n00b_string_t                *text;
    n00b_regex_t                 *regex;
    n00b_filter_path_t           *path;
    bool                          include_lower;
    bool                          include_upper;
};

struct n00b_filter_value_list_t {
    n00b_list_t(n00b_filter_value_t) values;
};

struct n00b_filter_t {
    n00b_filter_predicate_kind_t kind;
    n00b_filter_leaf_op_t        leaf_op;
    n00b_filter_field_t         *field;
    rocs_filter_child_list_t    *children;
    n00b_filter_t               *child;
    n00b_filter_value_t         *value;
    n00b_filter_value_t         *lower;
    n00b_filter_value_t         *upper;
    n00b_filter_value_list_t    *values;
    n00b_string_t               *text;
    n00b_regex_t                *regex;
    n00b_filter_path_t          *path;
    bool                         include_lower;
    bool                         include_upper;
};

struct n00b_filter_field_t {
    rocs_filter_field_kind_t kind;
    n00b_string_t           *name;
};

struct n00b_filter_path_t {
    n00b_filter_path_component_list_t *components;
};

struct n00b_filter_path_component_t {
    n00b_filter_path_component_kind_t kind;
    n00b_string_t                    *key;
    uint64_t                          index;
};

static n00b_filter_field_t rocs_filter_any_field = {
    .kind = ROCS_FILTER_FIELD_ANY,
    .name = nullptr,
};

static bool
rocs_filter_value_is_set(n00b_filter_value_t value)
{
    return n00b_variant_is_set(value);
}

static bool
rocs_filter_value_payload_is_valid(n00b_filter_value_t value)
{
    if (!rocs_filter_value_is_set(value)) {
        return false;
    }

    if (n00b_variant_is_type(value, n00b_filter_null_t)
        || n00b_variant_is_type(value, bool)
        || n00b_variant_is_type(value, int64_t)
        || n00b_variant_is_type(value, uint64_t)
        || n00b_variant_is_type(value, double)) {
        return true;
    }

    if (n00b_variant_is_type(value, n00b_string_t *)) {
        return n00b_variant_get(value, n00b_string_t *) != nullptr;
    }
    if (n00b_variant_is_type(value, n00b_buffer_t *)) {
        return n00b_variant_get(value, n00b_buffer_t *) != nullptr;
    }
    if (n00b_variant_is_type(value, n00b_regex_t *)) {
        return n00b_variant_get(value, n00b_regex_t *) != nullptr;
    }
    if (n00b_variant_is_type(value, n00b_filter_value_list_t *)) {
        return n00b_variant_get(value, n00b_filter_value_list_t *) != nullptr;
    }

    return false;
}

static bool
rocs_filter_value_list_payloads_are_valid(n00b_filter_value_list_t *list)
{
    if (list == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(list->values);
    for (size_t i = 0; i < len; i++) {
        if (!rocs_filter_value_payload_is_valid(
                n00b_list_get(list->values, i))) {
            return false;
        }
    }

    return true;
}

static rocs_filter_range_family_t
rocs_filter_range_family(n00b_filter_value_t value)
{
    if (!rocs_filter_value_is_set(value)) {
        return ROCS_FILTER_RANGE_INVALID;
    }

    if (n00b_variant_is_type(value, int64_t)
        || n00b_variant_is_type(value, uint64_t)
        || n00b_variant_is_type(value, double)) {
        return ROCS_FILTER_RANGE_NUMERIC;
    }

    if (n00b_variant_is_type(value, n00b_string_t *)
        && n00b_variant_get(value, n00b_string_t *) != nullptr) {
        return ROCS_FILTER_RANGE_UTF8;
    }

    return ROCS_FILTER_RANGE_INVALID;
}

static bool
rocs_filter_path_component_is_valid(n00b_filter_path_component_t *component)
{
    if (component == nullptr) {
        return false;
    }

    switch (component->kind) {
    case N00B_FILTER_PATH_KEY:
        return component->key != nullptr;
    case N00B_FILTER_PATH_INDEX:
        return true;
    }

    return false;
}

static bool
rocs_filter_path_is_valid(n00b_filter_path_t *path)
{
    if (path == nullptr || path->components == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*path->components);
    for (size_t i = 0; i < len; i++) {
        if (!rocs_filter_path_component_is_valid(
                n00b_list_get(*path->components, i))) {
            return false;
        }
    }

    return true;
}

static n00b_err_t
rocs_filter_check_field(n00b_filter_field_t *field, n00b_filter_leaf_op_t op)
{
    if (field == nullptr) {
        return N00B_FILTER_ERR_ARG;
    }

    if (field == &rocs_filter_any_field) {
        if (op == N00B_FILTER_LEAF_CONTAINS) {
            return N00B_FILTER_OK;
        }
        return N00B_FILTER_ERR_UNSUPPORTED;
    }

    if (field->kind != ROCS_FILTER_FIELD_NAMED
        || !rocs_json_field_name_valid(field->name)) {
        return N00B_FILTER_ERR_ARG;
    }

    return N00B_FILTER_OK;
}

static n00b_filter_t *
rocs_filter_predicate_new(n00b_filter_predicate_kind_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_t *filter = n00b_alloc_with_opts(
        n00b_filter_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    filter->kind = kind;
    return filter;
}

static n00b_filter_ir_t *
rocs_filter_ir_node_new(int32_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = n00b_alloc_with_opts(
        n00b_filter_ir_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    ir->kind = kind;
    return ir;
}

static n00b_filter_value_t *
rocs_filter_value_copy(n00b_filter_value_t value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_value_t *copy = n00b_alloc_with_opts(
        n00b_filter_value_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    *copy = value;
    return copy;
}

static n00b_filter_ir_child_list_t *
rocs_filter_ir_child_list_copy(n00b_filter_ir_child_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (children == nullptr) {
        return nullptr;
    }

    n00b_filter_ir_child_list_t *copy =
        n00b_filter_ir_child_list_new(.allocator = allocator);

    size_t len = n00b_list_len(*children);
    for (size_t i = 0; i < len; i++) {
        n00b_list_push(*copy, n00b_list_get(*children, i));
    }

    return copy;
}

static n00b_result_t(n00b_filter_t *)
rocs_filter_leaf_new(n00b_filter_field_t *field,
                     n00b_filter_leaf_op_t op) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t field_err = rocs_filter_check_field(field, op);
    if (field_err != N00B_FILTER_OK) {
        return n00b_result_err(n00b_filter_t *, field_err);
    }

    n00b_filter_t *filter =
        rocs_filter_predicate_new(N00B_FILTER_PREDICATE_LEAF,
                                  .allocator = allocator);
    filter->leaf_op = op;
    filter->field   = field;
    return n00b_result_ok(n00b_filter_t *, filter);
}

static rocs_filter_child_list_t *
rocs_filter_child_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_filter_child_list_t *children = n00b_alloc_with_opts(
        rocs_filter_child_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *children = n00b_list_new_private(n00b_filter_t *,
                                      .allocator = allocator,
                                      .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return children;
}

static n00b_result_t(n00b_filter_t *)
rocs_filter_bool_from_child_list(n00b_filter_predicate_kind_t kind,
                                 rocs_filter_child_list_t    *children)
    _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (children == nullptr || n00b_list_len(*children) < 2) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    size_t len = n00b_list_len(*children);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*children, i) == nullptr) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
        }
    }

    n00b_filter_t *filter = rocs_filter_predicate_new(
        kind,
        .allocator = allocator);
    filter->children = children;
    return n00b_result_ok(n00b_filter_t *, filter);
}

static n00b_result_t(n00b_filter_t *)
rocs_filter_bool_from_vargs(n00b_filter_predicate_kind_t kind,
                            n00b_filter_t              *first,
                            n00b_vargs_t               *args,
                            n00b_allocator_t           *allocator)
{
    if (first == nullptr || n00b_remaining_vargs(args) < 1) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    rocs_filter_child_list_t *children =
        rocs_filter_child_list_new(.allocator = allocator);
    n00b_list_push(*children, first);

    unsigned int count = n00b_remaining_vargs(args);
    for (unsigned int i = 0; i < count; i++) {
        n00b_filter_t *child = (n00b_filter_t *)n00b_vargs_next(args);
        if (child == nullptr) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
        }
        n00b_list_push(*children, child);
    }

    n00b_filter_t *filter =
        rocs_filter_predicate_new(kind, .allocator = allocator);
    filter->children = children;
    return n00b_result_ok(n00b_filter_t *, filter);
}

static n00b_filter_path_component_t *
rocs_filter_path_component_copy(n00b_filter_path_component_t *component)
    _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_path_component_t *copy = n00b_alloc_with_opts(
        n00b_filter_path_component_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    copy->kind  = component->kind;
    copy->key   = component->key;
    copy->index = component->index;
    return copy;
}

static n00b_filter_path_component_list_t *
rocs_filter_path_component_list_copy(
    n00b_filter_path_component_list_t *components) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_path_component_list_t *copy =
        n00b_filter_path_component_list_new(.allocator = allocator);

    size_t len = n00b_list_len(*components);
    for (size_t i = 0; i < len; i++) {
        n00b_filter_path_component_t *component =
            n00b_list_get(*components, i);
        n00b_filter_path_component_t *component_copy =
            rocs_filter_path_component_copy(component,
                                           .allocator = allocator);
        n00b_list_push(*copy, component_copy);
    }

    return copy;
}

n00b_string_t *
n00b_filter_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_FILTER_OK:
        return r"N00B_FILTER_OK";
    case N00B_FILTER_ERR_ARG:
        return r"N00B_FILTER_ERR_ARG";
    case N00B_FILTER_ERR_PATH:
        return r"N00B_FILTER_ERR_PATH";
    case N00B_FILTER_ERR_IR:
        return r"N00B_FILTER_ERR_IR";
    case N00B_FILTER_ERR_UNSUPPORTED:
        return r"N00B_FILTER_ERR_UNSUPPORTED";
    case N00B_FILTER_ERR_STATE:
        return r"N00B_FILTER_ERR_STATE";
    }

    return r"N00B_FILTER_ERR_UNKNOWN";
}

n00b_filter_value_t
n00b_fv_null(void)
{
    return n00b_variant_set(n00b_filter_value_t,
                            n00b_filter_null_t,
                            ((n00b_filter_null_t){}));
}

n00b_filter_value_t
n00b_fv_bool(bool value)
{
    return n00b_variant_set(n00b_filter_value_t, bool, value);
}

n00b_filter_value_t
n00b_fv_i64(int64_t value)
{
    return n00b_variant_set(n00b_filter_value_t, int64_t, value);
}

n00b_filter_value_t
n00b_fv_u64(uint64_t value)
{
    return n00b_variant_set(n00b_filter_value_t, uint64_t, value);
}

n00b_filter_value_t
n00b_fv_f64(double value)
{
    return n00b_variant_set(n00b_filter_value_t, double, value);
}

n00b_filter_value_t
n00b_fv_utf8(n00b_string_t *value)
{
    return n00b_variant_set(n00b_filter_value_t, n00b_string_t *, value);
}

n00b_filter_value_t
n00b_fv_bytes(n00b_buffer_t *value)
{
    return n00b_variant_set(n00b_filter_value_t, n00b_buffer_t *, value);
}

n00b_filter_value_t
n00b_fv_regex(n00b_regex_t *value)
{
    return n00b_variant_set(n00b_filter_value_t, n00b_regex_t *, value);
}

n00b_filter_value_t
n00b_fv_list(n00b_filter_value_list_t *values)
{
    return n00b_variant_set(n00b_filter_value_t,
                            n00b_filter_value_list_t *,
                            values);
}

n00b_filter_value_list_t *
n00b_filter_value_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_value_list_t *list = n00b_alloc_with_opts(
        n00b_filter_value_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    list->values = n00b_list_new_private(n00b_filter_value_t,
                                         .allocator = allocator);
    return list;
}

n00b_result_t(bool)
n00b_filter_value_list_append(n00b_filter_value_list_t *list,
                              n00b_filter_value_t      value)
{
    if (list == nullptr || !rocs_filter_value_is_set(value)) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }

    n00b_list_push(list->values, value);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_filter_value_list_count(n00b_filter_value_list_t *list)
{
    if (list == nullptr) {
        return n00b_result_err(uint64_t, N00B_FILTER_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(list->values));
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_value_list_at(n00b_filter_value_list_t *list, uint64_t ordinal)
{
    if (list == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(list->values);
    if (ordinal >= len) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_filter_value_t),
        n00b_option_set(n00b_filter_value_t,
                        n00b_list_get(list->values, (size_t)ordinal)));
}

n00b_result_t(n00b_filter_field_t *)
n00b_filter_field(n00b_string_t *name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_json_field_name_valid(name)) {
        return n00b_result_err(n00b_filter_field_t *, N00B_FILTER_ERR_ARG);
    }

    n00b_filter_field_t *field = n00b_alloc_with_opts(
        n00b_filter_field_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    field->kind = ROCS_FILTER_FIELD_NAMED;
    field->name = name;
    return n00b_result_ok(n00b_filter_field_t *, field);
}

n00b_filter_field_t *
n00b_filter_any(void)
{
    return &rocs_filter_any_field;
}

n00b_result_t(bool)
n00b_filter_field_is_any(n00b_filter_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }

    return n00b_result_ok(bool, field == &rocs_filter_any_field);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_field_name(n00b_filter_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_FILTER_ERR_ARG);
    }

    if (field == &rocs_filter_any_field || field->kind != ROCS_FILTER_FIELD_NAMED) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }

    if (field->name == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_FILTER_ERR_ARG);
    }

    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, field->name));
}

n00b_filter_path_component_list_t *
n00b_filter_path_component_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_path_component_list_t *list = n00b_alloc_with_opts(
        n00b_filter_path_component_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_filter_path_component_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

n00b_result_t(n00b_filter_path_component_t *)
n00b_filter_path_key(n00b_string_t *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (key == nullptr) {
        return n00b_result_err(n00b_filter_path_component_t *,
                               N00B_FILTER_ERR_ARG);
    }

    n00b_filter_path_component_t *component = n00b_alloc_with_opts(
        n00b_filter_path_component_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    component->kind = N00B_FILTER_PATH_KEY;
    component->key  = key;
    return n00b_result_ok(n00b_filter_path_component_t *, component);
}

n00b_result_t(n00b_filter_path_component_t *)
n00b_filter_path_index(uint64_t ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_path_component_t *component = n00b_alloc_with_opts(
        n00b_filter_path_component_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    component->kind  = N00B_FILTER_PATH_INDEX;
    component->index = ordinal;
    return n00b_result_ok(n00b_filter_path_component_t *, component);
}

n00b_result_t(bool)
n00b_filter_path_component_list_append(
    n00b_filter_path_component_list_t *list,
    n00b_filter_path_component_t      *component)
{
    if (list == nullptr || component == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }

    n00b_list_push(*list, component);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_filter_path_t *)
n00b_filter_path(n00b_filter_path_component_list_t *components) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (components == nullptr) {
        return n00b_result_err(n00b_filter_path_t *, N00B_FILTER_ERR_ARG);
    }

    size_t len = n00b_list_len(*components);
    for (size_t i = 0; i < len; i++) {
        if (!rocs_filter_path_component_is_valid(
                n00b_list_get(*components, i))) {
            return n00b_result_err(n00b_filter_path_t *,
                                   N00B_FILTER_ERR_PATH);
        }
    }

    n00b_filter_path_t *path = n00b_alloc_with_opts(
        n00b_filter_path_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    path->components =
        rocs_filter_path_component_list_copy(components,
                                            .allocator = allocator);
    return n00b_result_ok(n00b_filter_path_t *, path);
}

n00b_result_t(uint64_t)
n00b_filter_path_component_count(n00b_filter_path_t *path)
{
    if (path == nullptr || path->components == nullptr) {
        return n00b_result_err(uint64_t, N00B_FILTER_ERR_ARG);
    }

    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*path->components));
}

n00b_result_t(n00b_option_t(n00b_filter_path_component_t *))
n00b_filter_path_component_at(n00b_filter_path_t *path, uint64_t ordinal)
{
    if (path == nullptr || path->components == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_path_component_t *),
                               N00B_FILTER_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*path->components);
    if (ordinal >= len) {
        return n00b_result_ok(n00b_option_t(n00b_filter_path_component_t *),
                              n00b_option_none(n00b_filter_path_component_t *));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_filter_path_component_t *),
        n00b_option_set(n00b_filter_path_component_t *,
                        n00b_list_get(*path->components, (size_t)ordinal)));
}

n00b_result_t(n00b_filter_path_component_kind_t)
n00b_filter_path_component_kind(n00b_filter_path_component_t *component)
{
    if (!rocs_filter_path_component_is_valid(component)) {
        return n00b_result_err(n00b_filter_path_component_kind_t,
                               N00B_FILTER_ERR_ARG);
    }

    return n00b_result_ok(n00b_filter_path_component_kind_t,
                          component->kind);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_path_component_key(n00b_filter_path_component_t *component)
{
    if (!rocs_filter_path_component_is_valid(component)) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_FILTER_ERR_ARG);
    }

    if (component->kind != N00B_FILTER_PATH_KEY) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, component->key));
}

n00b_result_t(n00b_option_t(uint64_t))
n00b_filter_path_component_index(n00b_filter_path_component_t *component)
{
    if (!rocs_filter_path_component_is_valid(component)) {
        return n00b_result_err(n00b_option_t(uint64_t),
                               N00B_FILTER_ERR_ARG);
    }

    if (component->kind != N00B_FILTER_PATH_INDEX) {
        return n00b_result_ok(n00b_option_t(uint64_t),
                              n00b_option_none(uint64_t));
    }

    return n00b_result_ok(n00b_option_t(uint64_t),
                          n00b_option_set(uint64_t, component->index));
}

n00b_result_t(n00b_filter_t *)
n00b_filter_eq(n00b_filter_field_t *field,
               n00b_filter_value_t  value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_filter_value_payload_is_valid(value)) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_EQ,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->value = rocs_filter_value_copy(value, .allocator = allocator);
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_in(n00b_filter_field_t *field,
               n00b_filter_value_t  values) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_filter_value_is_set(values)
        || !n00b_variant_is_type(values, n00b_filter_value_list_t *)) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    n00b_filter_value_list_t *list =
        n00b_variant_get(values, n00b_filter_value_list_t *);
    if (list == nullptr) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    size_t len = n00b_list_len(list->values);
    for (size_t i = 0; i < len; i++) {
        if (!rocs_filter_value_payload_is_valid(
                n00b_list_get(list->values, i))) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
        }
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_IN,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->values = list;
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_between(n00b_filter_field_t *field,
                    n00b_filter_value_t  lower,
                    n00b_filter_value_t  upper) _kargs
{
    bool              include_lower = true;
    bool              include_upper = true;
    n00b_allocator_t *allocator     = nullptr;
}
{
    rocs_filter_range_family_t lower_family =
        rocs_filter_range_family(lower);
    rocs_filter_range_family_t upper_family =
        rocs_filter_range_family(upper);
    if (lower_family == ROCS_FILTER_RANGE_INVALID
        || upper_family == ROCS_FILTER_RANGE_INVALID
        || lower_family != upper_family) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_RANGE,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->lower         = rocs_filter_value_copy(lower,
                                                   .allocator = allocator);
    filter->upper         = rocs_filter_value_copy(upper,
                                                   .allocator = allocator);
    filter->include_lower = include_lower;
    filter->include_upper = include_upper;
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_contains(n00b_filter_field_t *field,
                     n00b_string_t       *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (term == nullptr || term->u8_bytes == 0) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_CONTAINS,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->text = term;
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_prefix(n00b_filter_field_t *field,
                   n00b_string_t       *prefix) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (prefix == nullptr || prefix->u8_bytes == 0) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_PREFIX,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->text = prefix;
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_regex(n00b_filter_field_t *field,
                  n00b_regex_t        *regex) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (regex == nullptr) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_REGEX,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->regex = regex;
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_exists(n00b_filter_field_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return rocs_filter_leaf_new(field,
                                N00B_FILTER_LEAF_EXISTS,
                                .allocator = allocator);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_under(n00b_filter_field_t *field,
                  n00b_filter_path_t  *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_filter_path_is_valid(path)) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    auto leaf_r = rocs_filter_leaf_new(field,
                                      N00B_FILTER_LEAF_UNDER,
                                      .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_filter_t *filter = n00b_result_get(leaf_r);
    filter->path = path;
    return n00b_result_ok(n00b_filter_t *, filter);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_and(n00b_filter_t *first, n00b_filter_t *+) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return rocs_filter_bool_from_vargs(N00B_FILTER_PREDICATE_AND,
                                      first,
                                      vargs,
                                      allocator);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_or(n00b_filter_t *first, n00b_filter_t *+) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return rocs_filter_bool_from_vargs(N00B_FILTER_PREDICATE_OR,
                                      first,
                                      vargs,
                                      allocator);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_not(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    n00b_filter_t *out =
        rocs_filter_predicate_new(N00B_FILTER_PREDICATE_NOT,
                                  .allocator = allocator);
    out->child = filter;
    return n00b_result_ok(n00b_filter_t *, out);
}

n00b_filter_ir_child_list_t *
n00b_filter_ir_child_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_child_list_t *children = n00b_alloc_with_opts(
        n00b_filter_ir_child_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *children = n00b_list_new_private(n00b_filter_ir_t *,
                                      .allocator = allocator,
                                      .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return children;
}

n00b_result_t(bool)
n00b_filter_ir_child_list_append(n00b_filter_ir_child_list_t *list,
                                 n00b_filter_ir_t            *child)
{
    if (list == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }

    n00b_list_push(*list, child);
    return n00b_result_ok(bool, true);
}

n00b_filter_ir_t *
n00b_filter_ir_value_leaf(n00b_filter_field_t *field,
                          n00b_filter_leaf_op_t op,
                          n00b_filter_value_t   value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op = op;
    ir->field   = field;
    ir->value   = rocs_filter_value_copy(value, .allocator = allocator);
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_range_leaf(n00b_filter_field_t *field,
                          n00b_filter_value_t  lower,
                          n00b_filter_value_t  upper) _kargs
{
    bool              include_lower = true;
    bool              include_upper = true;
    n00b_allocator_t *allocator     = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op       = N00B_FILTER_LEAF_RANGE;
    ir->field         = field;
    ir->lower         = rocs_filter_value_copy(lower,
                                               .allocator = allocator);
    ir->upper         = rocs_filter_value_copy(upper,
                                               .allocator = allocator);
    ir->include_lower = include_lower;
    ir->include_upper = include_upper;
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_text_leaf(n00b_filter_field_t *field,
                         n00b_filter_leaf_op_t op,
                         n00b_string_t        *text) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op = op;
    ir->field   = field;
    ir->text    = text;
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_regex_leaf(n00b_filter_field_t *field,
                          n00b_regex_t        *regex) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op = N00B_FILTER_LEAF_REGEX;
    ir->field   = field;
    ir->regex   = regex;
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_under_leaf(n00b_filter_field_t *field,
                          n00b_filter_path_t  *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op = N00B_FILTER_LEAF_UNDER;
    ir->field   = field;
    ir->path    = path;
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_exists_leaf(n00b_filter_field_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op = N00B_FILTER_LEAF_EXISTS;
    ir->field   = field;
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_and(n00b_filter_ir_child_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_AND,
        .allocator = allocator);
    ir->children = rocs_filter_ir_child_list_copy(children,
                                                 .allocator = allocator);
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_or(n00b_filter_ir_child_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_OR,
        .allocator = allocator);
    ir->children = rocs_filter_ir_child_list_copy(children,
                                                 .allocator = allocator);
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_not(n00b_filter_ir_t *child) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_NOT,
        .allocator = allocator);
    ir->child = child;
    return ir;
}

n00b_filter_ir_t *
n00b_filter_ir_raw_node(int32_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return rocs_filter_ir_node_new(kind, .allocator = allocator);
}

n00b_filter_ir_t *
n00b_filter_ir_raw_leaf(int32_t leaf_op,
                        n00b_filter_field_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_filter_ir_t *ir = rocs_filter_ir_node_new(
        N00B_FILTER_PREDICATE_LEAF,
        .allocator = allocator);
    ir->leaf_op = leaf_op;
    ir->field   = field;
    return ir;
}

static n00b_result_t(n00b_filter_ir_t *)
rocs_filter_export_ir(n00b_filter_t *filter,
                      n00b_allocator_t *allocator)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_filter_ir_t *, N00B_FILTER_ERR_STATE);
    }

    switch (filter->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        if (filter->children == nullptr
            || n00b_list_len(*filter->children) < 2) {
            return n00b_result_err(n00b_filter_ir_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        n00b_filter_ir_child_list_t *children =
            n00b_filter_ir_child_list_new(.allocator = allocator);
        size_t len = n00b_list_len(*filter->children);
        for (size_t i = 0; i < len; i++) {
            n00b_filter_t *child = n00b_list_get(*filter->children, i);
            if (child == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }

            auto child_r = rocs_filter_export_ir(child, allocator);
            if (n00b_result_is_err(child_r)) {
                return child_r;
            }

            auto append_r = n00b_filter_ir_child_list_append(
                children,
                n00b_result_get(child_r));
            if (n00b_result_is_err(append_r)) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       n00b_result_get_err(append_r));
            }
        }

        n00b_filter_ir_t *ir =
            filter->kind == N00B_FILTER_PREDICATE_AND
                ? n00b_filter_ir_and(children, .allocator = allocator)
                : n00b_filter_ir_or(children, .allocator = allocator);
        return n00b_result_ok(n00b_filter_ir_t *, ir);
    }

    case N00B_FILTER_PREDICATE_NOT: {
        if (filter->child == nullptr) {
            return n00b_result_err(n00b_filter_ir_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto child_r = rocs_filter_export_ir(filter->child, allocator);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }

        return n00b_result_ok(
            n00b_filter_ir_t *,
            n00b_filter_ir_not(n00b_result_get(child_r),
                               .allocator = allocator));
    }

    case N00B_FILTER_PREDICATE_LEAF:
        if (filter->field == nullptr) {
            return n00b_result_err(n00b_filter_ir_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        switch (filter->leaf_op) {
        case N00B_FILTER_LEAF_EQ:
            if (filter->value == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_value_leaf(filter->field,
                                          N00B_FILTER_LEAF_EQ,
                                          *filter->value,
                                          .allocator = allocator));

        case N00B_FILTER_LEAF_IN:
            if (filter->values == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_value_leaf(filter->field,
                                          N00B_FILTER_LEAF_IN,
                                          n00b_fv_list(filter->values),
                                          .allocator = allocator));

        case N00B_FILTER_LEAF_RANGE:
            if (filter->lower == nullptr || filter->upper == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_range_leaf(
                    filter->field,
                    *filter->lower,
                    *filter->upper,
                    .include_lower = filter->include_lower,
                    .include_upper = filter->include_upper,
                    .allocator = allocator));

        case N00B_FILTER_LEAF_EXISTS:
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_exists_leaf(filter->field,
                                           .allocator = allocator));

        case N00B_FILTER_LEAF_CONTAINS:
        case N00B_FILTER_LEAF_PREFIX:
            if (filter->text == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_text_leaf(filter->field,
                                         filter->leaf_op,
                                         filter->text,
                                         .allocator = allocator));

        case N00B_FILTER_LEAF_REGEX:
            if (filter->regex == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_regex_leaf(filter->field,
                                          filter->regex,
                                          .allocator = allocator));

        case N00B_FILTER_LEAF_UNDER:
            if (filter->path == nullptr) {
                return n00b_result_err(n00b_filter_ir_t *,
                                       N00B_FILTER_ERR_STATE);
            }
            return n00b_result_ok(
                n00b_filter_ir_t *,
                n00b_filter_ir_under_leaf(filter->field,
                                          filter->path,
                                          .allocator = allocator));
        }
        break;
    }

    return n00b_result_err(n00b_filter_ir_t *, N00B_FILTER_ERR_STATE);
}

static n00b_result_t(n00b_filter_t *)
rocs_filter_import_ir(n00b_filter_ir_t *ir,
                      n00b_allocator_t *allocator);

static n00b_result_t(n00b_plan_predicate_t *)
rocs_filter_lower_filter(n00b_filter_t *filter,
                         n00b_allocator_t *allocator);

static n00b_result_t(n00b_filter_t *)
rocs_filter_import_leaf_ir(n00b_filter_ir_t *ir,
                           n00b_allocator_t *allocator)
{
    switch (ir->leaf_op) {
    case N00B_FILTER_LEAF_EQ: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_EQ)
                != N00B_FILTER_OK
            || ir->value == nullptr
            || !rocs_filter_value_payload_is_valid(*ir->value)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_eq(ir->field,
                                *ir->value,
                                .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_IN: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_IN)
                != N00B_FILTER_OK
            || ir->value == nullptr
            || !rocs_filter_value_is_set(*ir->value)
            || !n00b_variant_is_type(*ir->value,
                                     n00b_filter_value_list_t *)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        n00b_filter_value_list_t *values =
            n00b_variant_get(*ir->value, n00b_filter_value_list_t *);
        if (!rocs_filter_value_list_payloads_are_valid(values)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_in(ir->field,
                                *ir->value,
                                .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_RANGE: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_RANGE)
                != N00B_FILTER_OK
            || ir->lower == nullptr
            || ir->upper == nullptr) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        rocs_filter_range_family_t lower_family =
            rocs_filter_range_family(*ir->lower);
        rocs_filter_range_family_t upper_family =
            rocs_filter_range_family(*ir->upper);
        if (lower_family == ROCS_FILTER_RANGE_INVALID
            || upper_family == ROCS_FILTER_RANGE_INVALID
            || lower_family != upper_family) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_between(ir->field,
                                     *ir->lower,
                                     *ir->upper,
                                     .include_lower = ir->include_lower,
                                     .include_upper = ir->include_upper,
                                     .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_EXISTS: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_EXISTS)
            != N00B_FILTER_OK) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_exists(ir->field, .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_CONTAINS: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_CONTAINS)
                != N00B_FILTER_OK
            || ir->text == nullptr
            || ir->text->u8_bytes == 0) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_contains(ir->field,
                                      ir->text,
                                      .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_PREFIX: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_PREFIX)
                != N00B_FILTER_OK
            || ir->text == nullptr
            || ir->text->u8_bytes == 0) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_prefix(ir->field,
                                    ir->text,
                                    .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_REGEX: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_REGEX)
                != N00B_FILTER_OK
            || ir->regex == nullptr) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_regex(ir->field,
                                   ir->regex,
                                   .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_LEAF_UNDER: {
        if (rocs_filter_check_field(ir->field, N00B_FILTER_LEAF_UNDER)
                != N00B_FILTER_OK
            || !rocs_filter_path_is_valid(ir->path)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto r = n00b_filter_under(ir->field,
                                   ir->path,
                                   .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }
    }

    return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
}

static n00b_result_t(n00b_filter_t *)
rocs_filter_import_ir(n00b_filter_ir_t *ir,
                      n00b_allocator_t *allocator)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
    }

    switch (ir->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        if (ir->children == nullptr || n00b_list_len(*ir->children) < 2) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        rocs_filter_child_list_t *children =
            rocs_filter_child_list_new(.allocator = allocator);
        size_t len = n00b_list_len(*ir->children);
        for (size_t i = 0; i < len; i++) {
            n00b_filter_ir_t *child_ir = n00b_list_get(*ir->children, i);
            if (child_ir == nullptr) {
                return n00b_result_err(n00b_filter_t *,
                                       N00B_FILTER_ERR_IR);
            }

            auto child_r = rocs_filter_import_ir(child_ir, allocator);
            if (n00b_result_is_err(child_r)) {
                return child_r;
            }

            n00b_list_push(*children, n00b_result_get(child_r));
        }

        auto r = rocs_filter_bool_from_child_list(
            (n00b_filter_predicate_kind_t)ir->kind,
            children,
            .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_PREDICATE_NOT: {
        if (ir->child == nullptr) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }

        auto child_r = rocs_filter_import_ir(ir->child, allocator);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }

        auto r = n00b_filter_not(n00b_result_get(child_r),
                                 .allocator = allocator);
        if (n00b_result_is_err(r)) {
            return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
        }
        return r;
    }

    case N00B_FILTER_PREDICATE_LEAF:
        return rocs_filter_import_leaf_ir(ir, allocator);
    }

    return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_IR);
}

n00b_result_t(n00b_filter_ir_t *)
n00b_filter_to_ir(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_filter_ir_t *, N00B_FILTER_ERR_ARG);
    }

    return rocs_filter_export_ir(filter, allocator);
}

n00b_result_t(n00b_filter_t *)
n00b_filter_from_ir(n00b_filter_ir_t *ir) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    return rocs_filter_import_ir(ir, allocator);
}

static n00b_err_t
rocs_filter_lower_plan_err(n00b_err_t err)
{
    switch ((n00b_plan_err_t)err) {
    case N00B_PLAN_OK:
        return N00B_FILTER_OK;
    case N00B_PLAN_ERR_ARG:
    case N00B_PLAN_ERR_STATE:
    case N00B_PLAN_ERR_EMPTY:
    case N00B_PLAN_ERR_ANY_UNSUPPORTED:
    case N00B_PLAN_ERR_ORDINAL:
    case N00B_PLAN_ERR_UNIVERSE:
        return N00B_FILTER_ERR_STATE;
    }

    return N00B_FILTER_ERR_STATE;
}

static n00b_plan_value_t
rocs_filter_plan_value_from_json(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

static n00b_result_t(n00b_plan_value_t)
rocs_filter_lower_value(n00b_filter_value_t value,
                        n00b_allocator_t   *allocator)
{
    if (!rocs_filter_value_is_set(value)) {
        return n00b_result_err(n00b_plan_value_t, N00B_FILTER_ERR_STATE);
    }

    n00b_json_node_t *node = nullptr;
    if (n00b_variant_is_type(value, n00b_filter_null_t)) {
        node = n00b_json_null_new(.allocator = allocator);
    }
    else if (n00b_variant_is_type(value, bool)) {
        node = n00b_json_bool_new(n00b_variant_get(value, bool),
                                  .allocator = allocator);
    }
    else if (n00b_variant_is_type(value, int64_t)) {
        node = n00b_json_int_new(n00b_variant_get(value, int64_t),
                                 .allocator = allocator);
    }
    else if (n00b_variant_is_type(value, uint64_t)) {
        uint64_t u = n00b_variant_get(value, uint64_t);
        if (u > (uint64_t)INT64_MAX) {
            return n00b_result_err(n00b_plan_value_t,
                                   N00B_FILTER_ERR_UNSUPPORTED);
        }
        node = n00b_json_int_new((int64_t)u, .allocator = allocator);
    }
    else if (n00b_variant_is_type(value, double)) {
        node = n00b_json_double_new(n00b_variant_get(value, double),
                                    .allocator = allocator);
    }
    else if (n00b_variant_is_type(value, n00b_string_t *)) {
        n00b_string_t *s = n00b_variant_get(value, n00b_string_t *);
        if (s == nullptr) {
            return n00b_result_err(n00b_plan_value_t,
                                   N00B_FILTER_ERR_STATE);
        }
        node = n00b_json_string_new_from_n00b(s, .allocator = allocator);
    }
    else if (n00b_variant_is_type(value, n00b_buffer_t *)
             || n00b_variant_is_type(value, n00b_regex_t *)
             || n00b_variant_is_type(value,
                                     n00b_filter_value_list_t *)) {
        return n00b_result_err(n00b_plan_value_t,
                               N00B_FILTER_ERR_UNSUPPORTED);
    }
    else {
        return n00b_result_err(n00b_plan_value_t, N00B_FILTER_ERR_STATE);
    }

    if (node == nullptr) {
        return n00b_result_err(n00b_plan_value_t, N00B_FILTER_ERR_STATE);
    }

    return n00b_result_ok(n00b_plan_value_t,
                          rocs_filter_plan_value_from_json(node));
}

static n00b_result_t(n00b_plan_value_list_t *)
rocs_filter_lower_value_list(n00b_filter_value_list_t *values,
                             n00b_allocator_t         *allocator)
{
    if (values == nullptr) {
        return n00b_result_err(n00b_plan_value_list_t *,
                               N00B_FILTER_ERR_STATE);
    }

    n00b_plan_value_list_t *out =
        n00b_plan_value_list_new(.allocator = allocator);
    size_t len = n00b_list_len(values->values);
    for (size_t i = 0; i < len; i++) {
        auto value_r =
            rocs_filter_lower_value(n00b_list_get(values->values, i),
                                    allocator);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_err(n00b_plan_value_list_t *,
                                   n00b_result_get_err(value_r));
        }

        auto append_r =
            n00b_plan_value_list_append(out, n00b_result_get(value_r));
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(
                n00b_plan_value_list_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(append_r)));
        }
    }

    return n00b_result_ok(n00b_plan_value_list_t *, out);
}

static n00b_result_t(n00b_plan_target_t *)
rocs_filter_lower_target(n00b_filter_field_t *field,
                         n00b_filter_leaf_op_t op,
                         n00b_allocator_t *allocator)
{
    n00b_err_t field_err = rocs_filter_check_field(field, op);
    if (field_err == N00B_FILTER_ERR_UNSUPPORTED) {
        return n00b_result_err(n00b_plan_target_t *,
                               N00B_FILTER_ERR_UNSUPPORTED);
    }
    if (field_err != N00B_FILTER_OK) {
        return n00b_result_err(n00b_plan_target_t *, N00B_FILTER_ERR_STATE);
    }

    if (field == &rocs_filter_any_field) {
        auto any_r = n00b_plan_target_any(.allocator = allocator);
        if (n00b_result_is_err(any_r)) {
            return n00b_result_err(
                n00b_plan_target_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(any_r)));
        }
        return any_r;
    }

    if (!rocs_json_field_name_valid(field->name)) {
        return n00b_result_err(n00b_plan_target_t *, N00B_FILTER_ERR_STATE);
    }

    auto target_r = n00b_plan_target_field(field->name,
                                           .allocator = allocator);
    if (n00b_result_is_err(target_r)) {
        return n00b_result_err(
            n00b_plan_target_t *,
            rocs_filter_lower_plan_err(n00b_result_get_err(target_r)));
    }
    return target_r;
}

static n00b_result_t(n00b_plan_path_t *)
rocs_filter_lower_path(n00b_filter_path_t *path,
                       n00b_allocator_t   *allocator)
{
    if (!rocs_filter_path_is_valid(path)) {
        return n00b_result_err(n00b_plan_path_t *, N00B_FILTER_ERR_STATE);
    }

    n00b_plan_path_component_list_t *components =
        n00b_plan_path_component_list_new(.allocator = allocator);
    size_t len = n00b_list_len(*path->components);
    for (size_t i = 0; i < len; i++) {
        n00b_filter_path_component_t *component =
            n00b_list_get(*path->components, i);
        if (!rocs_filter_path_component_is_valid(component)) {
            return n00b_result_err(n00b_plan_path_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        n00b_result_t(bool) append_r;
        switch (component->kind) {
        case N00B_FILTER_PATH_KEY:
            append_r = n00b_plan_path_component_list_append_key(
                components,
                component->key,
                .allocator = allocator);
            break;
        case N00B_FILTER_PATH_INDEX:
            append_r = n00b_plan_path_component_list_append_index(
                components,
                component->index,
                .allocator = allocator);
            break;
        default:
            return n00b_result_err(n00b_plan_path_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(
                n00b_plan_path_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(append_r)));
        }
    }

    auto path_r = n00b_plan_path_new(components, .allocator = allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(
            n00b_plan_path_t *,
            rocs_filter_lower_plan_err(n00b_result_get_err(path_r)));
    }
    return path_r;
}

static n00b_result_t(n00b_plan_predicate_t *)
rocs_filter_lower_leaf(n00b_filter_t     *filter,
                       n00b_allocator_t *allocator)
{
    if (filter == nullptr || filter->kind != N00B_FILTER_PREDICATE_LEAF) {
        return n00b_result_err(n00b_plan_predicate_t *,
                               N00B_FILTER_ERR_STATE);
    }

    switch (filter->leaf_op) {
    case N00B_FILTER_LEAF_EQ: {
        if (filter->value == nullptr
            || !rocs_filter_value_payload_is_valid(*filter->value)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_EQ,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto value_r = rocs_filter_lower_value(*filter->value, allocator);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(value_r));
        }

        auto pred_r =
            n00b_plan_predicate_eq(n00b_result_get(target_r),
                                   n00b_result_get(value_r),
                                   .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_IN: {
        if (filter->values == nullptr
            || !rocs_filter_value_list_payloads_are_valid(filter->values)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_IN,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        if (n00b_list_len(filter->values->values) == 0) {
            auto false_r = n00b_plan_predicate_false(
                .allocator = allocator);
            if (n00b_result_is_err(false_r)) {
                return n00b_result_err(
                    n00b_plan_predicate_t *,
                    rocs_filter_lower_plan_err(
                        n00b_result_get_err(false_r)));
            }
            return false_r;
        }

        auto values_r =
            rocs_filter_lower_value_list(filter->values, allocator);
        if (n00b_result_is_err(values_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(values_r));
        }

        auto pred_r =
            n00b_plan_predicate_in(n00b_result_get(target_r),
                                   n00b_result_get(values_r),
                                   .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_RANGE: {
        if (filter->lower == nullptr || filter->upper == nullptr) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        rocs_filter_range_family_t lower_family =
            rocs_filter_range_family(*filter->lower);
        rocs_filter_range_family_t upper_family =
            rocs_filter_range_family(*filter->upper);
        if (lower_family == ROCS_FILTER_RANGE_INVALID
            || upper_family == ROCS_FILTER_RANGE_INVALID
            || lower_family != upper_family) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_RANGE,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto lower_r = rocs_filter_lower_value(*filter->lower, allocator);
        if (n00b_result_is_err(lower_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(lower_r));
        }
        auto upper_r = rocs_filter_lower_value(*filter->upper, allocator);
        if (n00b_result_is_err(upper_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(upper_r));
        }

        auto pred_r =
            n00b_plan_predicate_range(n00b_result_get(target_r),
                                      n00b_result_get(lower_r),
                                      n00b_result_get(upper_r),
                                      .include_lower = filter->include_lower,
                                      .include_upper = filter->include_upper,
                                      .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_EXISTS: {
        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_EXISTS,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto pred_r =
            n00b_plan_predicate_exists(n00b_result_get(target_r),
                                       .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_CONTAINS: {
        if (filter->text == nullptr || filter->text->u8_bytes == 0) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_CONTAINS,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto pred_r =
            n00b_plan_predicate_contains(n00b_result_get(target_r),
                                         filter->text,
                                         .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_PREFIX: {
        if (filter->text == nullptr || filter->text->u8_bytes == 0) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_PREFIX,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto pred_r =
            n00b_plan_predicate_prefix(n00b_result_get(target_r),
                                       filter->text,
                                       .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_REGEX: {
        if (filter->regex == nullptr) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_REGEX,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto pred_r =
            n00b_plan_predicate_regex(n00b_result_get(target_r),
                                      filter->regex,
                                      .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_LEAF_UNDER: {
        if (!rocs_filter_path_is_valid(filter->path)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto target_r = rocs_filter_lower_target(filter->field,
                                                 N00B_FILTER_LEAF_UNDER,
                                                 allocator);
        if (n00b_result_is_err(target_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(target_r));
        }

        auto path_r = rocs_filter_lower_path(filter->path, allocator);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(path_r));
        }

        auto pred_r =
            n00b_plan_predicate_under(n00b_result_get(target_r),
                                      n00b_result_get(path_r),
                                      .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }
    }

    return n00b_result_err(n00b_plan_predicate_t *, N00B_FILTER_ERR_STATE);
}

static n00b_result_t(n00b_plan_predicate_list_t *)
rocs_filter_lower_children(rocs_filter_child_list_t *children,
                           n00b_allocator_t        *allocator)
{
    if (children == nullptr || n00b_list_len(*children) < 2) {
        return n00b_result_err(n00b_plan_predicate_list_t *,
                               N00B_FILTER_ERR_STATE);
    }

    n00b_plan_predicate_list_t *out =
        n00b_plan_predicate_list_new(.allocator = allocator);
    size_t len = n00b_list_len(*children);
    for (size_t i = 0; i < len; i++) {
        n00b_filter_t *child = n00b_list_get(*children, i);
        if (child == nullptr) {
            return n00b_result_err(n00b_plan_predicate_list_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto child_r = rocs_filter_lower_filter(child, allocator);
        if (n00b_result_is_err(child_r)) {
            return n00b_result_err(n00b_plan_predicate_list_t *,
                                   n00b_result_get_err(child_r));
        }

        auto append_r =
            n00b_plan_predicate_list_append(out, n00b_result_get(child_r));
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(
                n00b_plan_predicate_list_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(append_r)));
        }
    }

    return n00b_result_ok(n00b_plan_predicate_list_t *, out);
}

static n00b_result_t(n00b_plan_predicate_t *)
rocs_filter_lower_filter(n00b_filter_t *filter,
                         n00b_allocator_t *allocator)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *,
                               N00B_FILTER_ERR_STATE);
    }

    switch (filter->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        auto children_r =
            rocs_filter_lower_children(filter->children, allocator);
        if (n00b_result_is_err(children_r)) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   n00b_result_get_err(children_r));
        }

        n00b_result_t(n00b_plan_predicate_t *) pred_r;
        if (filter->kind == N00B_FILTER_PREDICATE_AND) {
            pred_r = n00b_plan_predicate_and(n00b_result_get(children_r),
                                             .allocator = allocator);
        }
        else {
            pred_r = n00b_plan_predicate_or(n00b_result_get(children_r),
                                            .allocator = allocator);
        }

        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_PREDICATE_NOT: {
        if (filter->child == nullptr) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_FILTER_ERR_STATE);
        }

        auto child_r = rocs_filter_lower_filter(filter->child, allocator);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }

        auto pred_r =
            n00b_plan_predicate_not(n00b_result_get(child_r),
                                    .allocator = allocator);
        if (n00b_result_is_err(pred_r)) {
            return n00b_result_err(
                n00b_plan_predicate_t *,
                rocs_filter_lower_plan_err(n00b_result_get_err(pred_r)));
        }
        return pred_r;
    }

    case N00B_FILTER_PREDICATE_LEAF:
        return rocs_filter_lower_leaf(filter, allocator);
    }

    return n00b_result_err(n00b_plan_predicate_t *, N00B_FILTER_ERR_STATE);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_filter_lower_to_plan(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *,
                               N00B_FILTER_ERR_ARG);
    }

    return rocs_filter_lower_filter(filter, allocator);
}

n00b_result_t(n00b_filter_predicate_kind_t)
n00b_filter_ir_kind(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_filter_predicate_kind_t,
                               N00B_FILTER_ERR_ARG);
    }

    return n00b_result_ok(n00b_filter_predicate_kind_t,
                          (n00b_filter_predicate_kind_t)ir->kind);
}

n00b_result_t(n00b_filter_leaf_op_t)
n00b_filter_ir_leaf_op(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_filter_leaf_op_t,
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF) {
        return n00b_result_err(n00b_filter_leaf_op_t,
                               N00B_FILTER_ERR_STATE);
    }

    return n00b_result_ok(n00b_filter_leaf_op_t,
                          (n00b_filter_leaf_op_t)ir->leaf_op);
}

n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_filter_ir_field(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_field_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF || ir->field == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_filter_field_t *),
                              n00b_option_none(n00b_filter_field_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_filter_field_t *),
                          n00b_option_set(n00b_filter_field_t *,
                                          ir->field));
}

n00b_result_t(uint64_t)
n00b_filter_ir_child_count(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(uint64_t, N00B_FILTER_ERR_ARG);
    }

    switch (ir->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR:
        if (ir->children == nullptr) {
            return n00b_result_ok(uint64_t, 0);
        }
        return n00b_result_ok(uint64_t,
                              (uint64_t)n00b_list_len(*ir->children));

    case N00B_FILTER_PREDICATE_NOT:
        return n00b_result_ok(uint64_t, ir->child == nullptr ? 0 : 1);

    case N00B_FILTER_PREDICATE_LEAF:
    default:
        return n00b_result_ok(uint64_t, 0);
    }
}

n00b_result_t(n00b_option_t(n00b_filter_ir_t *))
n00b_filter_ir_child_at(n00b_filter_ir_t *ir, uint64_t ordinal)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_ir_t *),
                               N00B_FILTER_ERR_ARG);
    }

    switch (ir->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        if (ir->children == nullptr) {
            return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                                  n00b_option_none(n00b_filter_ir_t *));
        }

        uint64_t len = (uint64_t)n00b_list_len(*ir->children);
        if (ordinal >= len) {
            return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                                  n00b_option_none(n00b_filter_ir_t *));
        }

        n00b_filter_ir_t *child = n00b_list_get(*ir->children,
                                                (size_t)ordinal);
        if (child == nullptr) {
            return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                                  n00b_option_none(n00b_filter_ir_t *));
        }

        return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                              n00b_option_set(n00b_filter_ir_t *,
                                              child));
    }

    case N00B_FILTER_PREDICATE_NOT:
        if (ordinal == 0 && ir->child != nullptr) {
            return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                                  n00b_option_set(n00b_filter_ir_t *,
                                                  ir->child));
        }
        return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                              n00b_option_none(n00b_filter_ir_t *));

    case N00B_FILTER_PREDICATE_LEAF:
    default:
        return n00b_result_ok(n00b_option_t(n00b_filter_ir_t *),
                              n00b_option_none(n00b_filter_ir_t *));
    }
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_ir_value(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF || ir->value == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                          n00b_option_set(n00b_filter_value_t,
                                          *ir->value));
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_ir_range_lower(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || ir->leaf_op != N00B_FILTER_LEAF_RANGE
        || ir->lower == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                          n00b_option_set(n00b_filter_value_t,
                                          *ir->lower));
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_ir_range_upper(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || ir->leaf_op != N00B_FILTER_LEAF_RANGE
        || ir->upper == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                          n00b_option_set(n00b_filter_value_t,
                                          *ir->upper));
}

n00b_result_t(bool)
n00b_filter_ir_range_include_lower(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || ir->leaf_op != N00B_FILTER_LEAF_RANGE) {
        return n00b_result_err(bool, N00B_FILTER_ERR_STATE);
    }

    return n00b_result_ok(bool, ir->include_lower);
}

n00b_result_t(bool)
n00b_filter_ir_range_include_upper(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || ir->leaf_op != N00B_FILTER_LEAF_RANGE) {
        return n00b_result_err(bool, N00B_FILTER_ERR_STATE);
    }

    return n00b_result_ok(bool, ir->include_upper);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_ir_text(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || (ir->leaf_op != N00B_FILTER_LEAF_CONTAINS
            && ir->leaf_op != N00B_FILTER_LEAF_PREFIX)
        || ir->text == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, ir->text));
}

n00b_result_t(n00b_option_t(n00b_regex_t *))
n00b_filter_ir_regex_handle(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_regex_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || ir->leaf_op != N00B_FILTER_LEAF_REGEX
        || ir->regex == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_regex_t *),
                              n00b_option_none(n00b_regex_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_regex_t *),
                          n00b_option_set(n00b_regex_t *, ir->regex));
}

n00b_result_t(n00b_option_t(n00b_filter_path_t *))
n00b_filter_ir_path(n00b_filter_ir_t *ir)
{
    if (ir == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_path_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (ir->kind != N00B_FILTER_PREDICATE_LEAF
        || ir->leaf_op != N00B_FILTER_LEAF_UNDER
        || ir->path == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_filter_path_t *),
                              n00b_option_none(n00b_filter_path_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_filter_path_t *),
                          n00b_option_set(n00b_filter_path_t *, ir->path));
}

n00b_result_t(n00b_filter_predicate_kind_t)
n00b_filter_predicate_kind(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_filter_predicate_kind_t,
                               N00B_FILTER_ERR_ARG);
    }
    return n00b_result_ok(n00b_filter_predicate_kind_t, filter->kind);
}

n00b_result_t(n00b_filter_leaf_op_t)
n00b_filter_predicate_leaf_op(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_filter_leaf_op_t,
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF) {
        return n00b_result_err(n00b_filter_leaf_op_t,
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_filter_leaf_op_t, filter->leaf_op);
}

n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_filter_predicate_field(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_field_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF) {
        return n00b_result_ok(n00b_option_t(n00b_filter_field_t *),
                              n00b_option_none(n00b_filter_field_t *));
    }
    if (filter->field == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_field_t *),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_filter_field_t *),
                          n00b_option_set(n00b_filter_field_t *,
                                          filter->field));
}

n00b_result_t(uint64_t)
n00b_filter_predicate_child_count(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(uint64_t, N00B_FILTER_ERR_ARG);
    }

    switch (filter->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR:
        if (filter->children == nullptr) {
            return n00b_result_err(uint64_t, N00B_FILTER_ERR_STATE);
        }
        return n00b_result_ok(uint64_t,
                              (uint64_t)n00b_list_len(*filter->children));

    case N00B_FILTER_PREDICATE_NOT:
        return n00b_result_ok(uint64_t, filter->child == nullptr ? 0 : 1);

    case N00B_FILTER_PREDICATE_LEAF:
        return n00b_result_ok(uint64_t, 0);
    }

    return n00b_result_err(uint64_t, N00B_FILTER_ERR_STATE);
}

n00b_result_t(n00b_option_t(n00b_filter_t *))
n00b_filter_predicate_child_at(n00b_filter_t *filter, uint64_t ordinal)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_t *),
                               N00B_FILTER_ERR_ARG);
    }

    switch (filter->kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        if (filter->children == nullptr) {
            return n00b_result_err(n00b_option_t(n00b_filter_t *),
                                   N00B_FILTER_ERR_STATE);
        }
        uint64_t len = (uint64_t)n00b_list_len(*filter->children);
        if (ordinal >= len) {
            return n00b_result_ok(n00b_option_t(n00b_filter_t *),
                                  n00b_option_none(n00b_filter_t *));
        }
        return n00b_result_ok(
            n00b_option_t(n00b_filter_t *),
            n00b_option_set(n00b_filter_t *,
                            n00b_list_get(*filter->children,
                                          (size_t)ordinal)));
    }

    case N00B_FILTER_PREDICATE_NOT:
        if (ordinal == 0 && filter->child != nullptr) {
            return n00b_result_ok(n00b_option_t(n00b_filter_t *),
                                  n00b_option_set(n00b_filter_t *,
                                                  filter->child));
        }
        return n00b_result_ok(n00b_option_t(n00b_filter_t *),
                              n00b_option_none(n00b_filter_t *));

    case N00B_FILTER_PREDICATE_LEAF:
        return n00b_result_ok(n00b_option_t(n00b_filter_t *),
                              n00b_option_none(n00b_filter_t *));
    }

    return n00b_result_err(n00b_option_t(n00b_filter_t *),
                           N00B_FILTER_ERR_STATE);
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_predicate_value(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_EQ) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }
    if (filter->value == nullptr
        || !rocs_filter_value_payload_is_valid(*filter->value)) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                          n00b_option_set(n00b_filter_value_t,
                                          *filter->value));
}

n00b_result_t(n00b_option_t(n00b_filter_value_list_t *))
n00b_filter_predicate_values(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_list_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_IN) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_list_t *),
                              n00b_option_none(n00b_filter_value_list_t *));
    }
    if (filter->values == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_list_t *),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_filter_value_list_t *),
                          n00b_option_set(n00b_filter_value_list_t *,
                                          filter->values));
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_predicate_range_lower(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_RANGE) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }
    if (filter->lower == nullptr
        || rocs_filter_range_family(*filter->lower)
               == ROCS_FILTER_RANGE_INVALID) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                          n00b_option_set(n00b_filter_value_t,
                                          *filter->lower));
}

n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_predicate_range_upper(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_RANGE) {
        return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                              n00b_option_none(n00b_filter_value_t));
    }
    if (filter->upper == nullptr
        || rocs_filter_range_family(*filter->upper)
               == ROCS_FILTER_RANGE_INVALID) {
        return n00b_result_err(n00b_option_t(n00b_filter_value_t),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_filter_value_t),
                          n00b_option_set(n00b_filter_value_t,
                                          *filter->upper));
}

n00b_result_t(bool)
n00b_filter_predicate_range_include_lower(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_RANGE) {
        return n00b_result_err(bool, N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(bool, filter->include_lower);
}

n00b_result_t(bool)
n00b_filter_predicate_range_include_upper(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(bool, N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_RANGE) {
        return n00b_result_err(bool, N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(bool, filter->include_upper);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_predicate_text(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || (filter->leaf_op != N00B_FILTER_LEAF_CONTAINS
            && filter->leaf_op != N00B_FILTER_LEAF_PREFIX)) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }
    if (filter->text == nullptr || filter->text->u8_bytes == 0) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *,
                                          filter->text));
}

n00b_result_t(n00b_option_t(n00b_regex_t *))
n00b_filter_predicate_regex_handle(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_regex_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_REGEX) {
        return n00b_result_ok(n00b_option_t(n00b_regex_t *),
                              n00b_option_none(n00b_regex_t *));
    }
    if (filter->regex == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_regex_t *),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_regex_t *),
                          n00b_option_set(n00b_regex_t *,
                                          filter->regex));
}

n00b_result_t(n00b_option_t(n00b_filter_path_t *))
n00b_filter_predicate_path(n00b_filter_t *filter)
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_path_t *),
                               N00B_FILTER_ERR_ARG);
    }
    if (filter->kind != N00B_FILTER_PREDICATE_LEAF
        || filter->leaf_op != N00B_FILTER_LEAF_UNDER) {
        return n00b_result_ok(n00b_option_t(n00b_filter_path_t *),
                              n00b_option_none(n00b_filter_path_t *));
    }
    if (!rocs_filter_path_is_valid(filter->path)) {
        return n00b_result_err(n00b_option_t(n00b_filter_path_t *),
                               N00B_FILTER_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_filter_path_t *),
                          n00b_option_set(n00b_filter_path_t *,
                                          filter->path));
}

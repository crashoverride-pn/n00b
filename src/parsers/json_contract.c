/*
 * json_contract.c — Small JSON request contract helpers.
 */

#include "parsers/json_contract.h"

#include <string.h>

#include "core/alloc.h"
#include "text/strings/format.h"

struct n00b_json_contract {
    n00b_list_t(n00b_string_t *) errors;
    n00b_allocator_t            *allocator;
};

static n00b_string_t *
type_name(n00b_json_contract_type_t type)
{
    switch (type) {
    case N00B_JSON_CONTRACT_ANY:    return r"any";
    case N00B_JSON_CONTRACT_NULL:   return r"null";
    case N00B_JSON_CONTRACT_BOOL:   return r"bool";
    case N00B_JSON_CONTRACT_INT:    return r"int";
    case N00B_JSON_CONTRACT_DOUBLE: return r"double";
    case N00B_JSON_CONTRACT_NUMBER: return r"number";
    case N00B_JSON_CONTRACT_STRING: return r"string";
    case N00B_JSON_CONTRACT_ARRAY:  return r"array";
    case N00B_JSON_CONTRACT_OBJECT: return r"object";
    default:                        return r"unknown";
    }
}

static n00b_string_t *
node_type_name(n00b_json_node_t *node)
{
    if (node == nullptr) {
        return r"missing";
    }
    switch (n00b_json_type(node)) {
    case N00B_JSON_NULL:   return r"null";
    case N00B_JSON_BOOL:   return r"bool";
    case N00B_JSON_INT:    return r"int";
    case N00B_JSON_DOUBLE: return r"double";
    case N00B_JSON_STRING: return r"string";
    case N00B_JSON_ARRAY:  return r"array";
    case N00B_JSON_OBJECT: return r"object";
    default:               return r"unknown";
    }
}

static n00b_string_t *
effective_path(n00b_string_t *field, n00b_string_t *path)
{
    return path != nullptr ? path : field;
}

static bool
json_string_eq(n00b_json_node_t *node, n00b_string_t *s)
{
    if (!n00b_json_is_string(node) || s == nullptr) {
        return false;
    }

    n00b_string_t *node_s = n00b_json_as_string(node);
    if (node_s == nullptr) {
        return false;
    }
    size_t n = node_s->u8_bytes;
    return n == s->u8_bytes && (n == 0 || memcmp(node_s->data, s->data, n) == 0);
}

static n00b_json_node_t *
object_get(n00b_json_node_t *object, n00b_string_t *field, bool *found)
{
    *found = false;
    if (object == nullptr || !n00b_json_is_object(object)
        || field == nullptr) {
        return nullptr;
    }

    n00b_json_node_t *value = n00b_json_object_get(object, field);
    *found = value != nullptr;
    return value;
}

static bool
type_matches(n00b_json_node_t *value, n00b_json_contract_type_t type)
{
    if (value == nullptr) {
        return false;
    }

    switch (type) {
    case N00B_JSON_CONTRACT_ANY:    return true;
    case N00B_JSON_CONTRACT_NULL:   return n00b_json_is_null(value);
    case N00B_JSON_CONTRACT_BOOL:   return n00b_json_is_bool(value);
    case N00B_JSON_CONTRACT_INT:    return n00b_json_is_int(value);
    case N00B_JSON_CONTRACT_DOUBLE: return n00b_json_is_double(value);
    case N00B_JSON_CONTRACT_NUMBER:
        return n00b_json_is_int(value) || n00b_json_is_double(value);
    case N00B_JSON_CONTRACT_STRING: return n00b_json_is_string(value);
    case N00B_JSON_CONTRACT_ARRAY:  return n00b_json_is_array(value);
    case N00B_JSON_CONTRACT_OBJECT: return n00b_json_is_object(value);
    default:                        return false;
    }
}

static n00b_json_node_t *
field_common(n00b_json_contract_t      *contract,
             n00b_json_node_t          *object,
             n00b_string_t             *field,
             n00b_json_contract_type_t  type,
             bool                       required,
             bool                       nullable,
             n00b_json_node_t          *default_value,
             n00b_string_t             *path)
{
    n00b_string_t *diag_path = effective_path(field, path);

    if (object == nullptr || !n00b_json_is_object(object)) {
        n00b_json_contract_add_error(contract,
                                     diag_path,
                                     r"parent value is not an object");
        return nullptr;
    }

    bool found = false;
    n00b_json_node_t *value = object_get(object, field, &found);
    if (!found) {
        if (required) {
            n00b_json_contract_add_error(contract,
                                         diag_path,
                                         r"missing required field");
            return nullptr;
        }
        return default_value;
    }

    if (!n00b_json_contract_validate(contract,
                                     value,
                                     diag_path,
                                     type,
                                     .nullable = nullable)) {
        return nullptr;
    }
    return value;
}

static bool
enum_contains(n00b_json_node_t             *value,
              n00b_list_t(n00b_string_t *) *allowed)
{
    if (allowed == nullptr || value == nullptr
        || !n00b_json_is_string(value)) {
        return false;
    }

    size_t n = n00b_list_len(*allowed);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *candidate = n00b_list_get(*allowed, i);
        if (json_string_eq(value, candidate)) {
            return true;
        }
    }
    return false;
}

n00b_json_contract_t *
n00b_json_contract_new()
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    n00b_json_contract_t *contract = n00b_alloc_with_opts(
        n00b_json_contract_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    contract->errors    = n00b_list_new(n00b_string_t *,
                                        .allocator = allocator);
    contract->allocator = allocator;
    return contract;
}

void
n00b_json_contract_reset(n00b_json_contract_t *contract)
{
    if (contract == nullptr) {
        return;
    }
    contract->errors = n00b_list_new(n00b_string_t *,
                                     .allocator = contract->allocator);
}

bool
n00b_json_contract_ok(n00b_json_contract_t *contract)
{
    return contract != nullptr && n00b_list_len(contract->errors) == 0;
}

size_t
n00b_json_contract_error_count(n00b_json_contract_t *contract)
{
    return contract == nullptr ? 0 : n00b_list_len(contract->errors);
}

n00b_string_t *
n00b_json_contract_error(n00b_json_contract_t *contract, size_t index)
{
    if (contract == nullptr || index >= n00b_list_len(contract->errors)) {
        return nullptr;
    }
    return n00b_list_get(contract->errors, index);
}

n00b_string_t *
n00b_json_contract_summary(n00b_json_contract_t *contract)
{
    size_t n = n00b_json_contract_error_count(contract);
    if (n == 0) {
        return r"";
    }
    n00b_string_t *first = n00b_json_contract_error(contract, 0);
    if (n == 1) {
        return first;
    }
    return n00b_cformat("[|#|] JSON contract errors; first: [|#|]",
                        (int64_t)n,
                        first);
}

void
n00b_json_contract_add_error(n00b_json_contract_t *contract,
                             n00b_string_t        *path,
                             n00b_string_t        *message)
{
    if (contract == nullptr) {
        return;
    }
    n00b_string_t *diag_path = path != nullptr ? path : r"$";
    n00b_string_t *diag_msg  = message != nullptr ? message : r"invalid value";
    n00b_list_push(contract->errors,
                   n00b_cformat("[|#|]: [|#|]", diag_path, diag_msg));
}

bool
n00b_json_contract_validate(n00b_json_contract_t      *contract,
                            n00b_json_node_t          *value,
                            n00b_string_t             *path,
                            n00b_json_contract_type_t  type)
    _kargs { bool nullable = false; }
{
    if (value == nullptr) {
        n00b_json_contract_add_error(contract, path, r"missing value");
        return false;
    }

    if (n00b_json_is_null(value)
        && (nullable || type == N00B_JSON_CONTRACT_NULL
            || type == N00B_JSON_CONTRACT_ANY)) {
        return true;
    }

    if (n00b_json_is_null(value)) {
        n00b_json_contract_add_error(contract,
                                     path,
                                     n00b_cformat("expected [|#|], got null",
                                                  type_name(type)));
        return false;
    }

    if (!type_matches(value, type)) {
        n00b_json_contract_add_error(contract,
                                     path,
                                     n00b_cformat("expected [|#|], got [|#|]",
                                                  type_name(type),
                                                  node_type_name(value)));
        return false;
    }
    return true;
}

n00b_json_node_t *
n00b_json_contract_required(n00b_json_contract_t      *contract,
                            n00b_json_node_t          *object,
                            n00b_string_t             *field,
                            n00b_json_contract_type_t  type)
    _kargs {
        bool           nullable = false;
        n00b_string_t *path     = nullptr;
    }
{
    return field_common(contract,
                        object,
                        field,
                        type,
                        true,
                        nullable,
                        nullptr,
                        path);
}

n00b_json_node_t *
n00b_json_contract_optional(n00b_json_contract_t      *contract,
                            n00b_json_node_t          *object,
                            n00b_string_t             *field,
                            n00b_json_contract_type_t  type,
                            n00b_json_node_t          *default_value)
    _kargs {
        bool           nullable = false;
        n00b_string_t *path     = nullptr;
    }
{
    return field_common(contract,
                        object,
                        field,
                        type,
                        false,
                        nullable,
                        default_value,
                        path);
}

n00b_json_node_t *
n00b_json_contract_required_enum(n00b_json_contract_t        *contract,
                                 n00b_json_node_t            *object,
                                 n00b_string_t               *field,
                                 n00b_list_t(n00b_string_t *) *allowed)
    _kargs {
        bool           nullable = false;
        n00b_string_t *path     = nullptr;
    }
{
    n00b_string_t *diag_path = effective_path(field, path);
    n00b_json_node_t *value = n00b_json_contract_required(contract,
                                                          object,
                                                          field,
                                                          N00B_JSON_CONTRACT_STRING,
                                                          .nullable = nullable,
                                                          .path = diag_path);
    if (value == nullptr || n00b_json_is_null(value)) {
        return value;
    }
    if (!enum_contains(value, allowed)) {
        n00b_json_contract_add_error(contract,
                                     diag_path,
                                     r"value is not in the allowed set");
        return nullptr;
    }
    return value;
}

n00b_json_node_t *
n00b_json_contract_optional_enum(n00b_json_contract_t        *contract,
                                 n00b_json_node_t            *object,
                                 n00b_string_t               *field,
                                 n00b_list_t(n00b_string_t *) *allowed,
                                 n00b_json_node_t            *default_value)
    _kargs {
        bool           nullable = false;
        n00b_string_t *path     = nullptr;
    }
{
    n00b_string_t *diag_path = effective_path(field, path);
    n00b_json_node_t *value = n00b_json_contract_optional(contract,
                                                          object,
                                                          field,
                                                          N00B_JSON_CONTRACT_STRING,
                                                          default_value,
                                                          .nullable = nullable,
                                                          .path = diag_path);
    if (value == nullptr || n00b_json_is_null(value)) {
        return value;
    }
    if (!enum_contains(value, allowed)) {
        n00b_json_contract_add_error(contract,
                                     diag_path,
                                     r"value is not in the allowed set");
        return nullptr;
    }
    return value;
}

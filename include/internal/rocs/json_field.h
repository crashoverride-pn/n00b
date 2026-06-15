/**
 * @file internal/rocs/json_field.h
 * @brief Internal JSON field-name resolution helpers for rocs.
 */
#pragma once

#include "n00b.h"
#include "parsers/json.h"

#ifdef __cplusplus
extern "C" {
#endif

extern bool
rocs_json_field_name_valid(n00b_string_t *field);

extern n00b_json_node_t *
rocs_json_object_get_field(n00b_json_node_t *record, n00b_string_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

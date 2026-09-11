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

/**
 * @brief Outcome of a byte scan for one top-level field.
 *
 * @c ROCS_JSON_SCAN_UNSURE is not an error. It says the scan declined, and the
 * caller answers by parsing the record, which is what it would have done
 * anyway.
 */
typedef enum {
    ROCS_JSON_SCAN_FOUND,
    ROCS_JSON_SCAN_ABSENT,
    ROCS_JSON_SCAN_UNSURE,
} rocs_json_scan_t;

/**
 * @brief Locate one top-level field's value in a compact JSON object, by
 *        scanning the bytes rather than building the object's node graph.
 *
 * On @c ROCS_JSON_SCAN_FOUND, @p out_start and @p out_len bound the value's
 * bytes inside @p data, ready to hand to @ref n00b_json_parse on their own.
 *
 * The whole object is scanned before either answer is given, so a record that
 * is well-formed up to the wanted field and broken after it is declined rather
 * than indexed. What a caller gets never depends on where in the record its
 * field sits.
 *
 * Declines (@c ROCS_JSON_SCAN_UNSURE) for a dotted path, an escaped key, a
 * repeated key, nesting past the parser's own depth limit, trailing bytes, or
 * anything it cannot read as a flat object. Correctness never rests on the
 * scanner agreeing with the parser about a hard case, because it refuses them.
 */
extern rocs_json_scan_t
rocs_json_scan_field_span(const char    *data,
                          size_t         len,
                          n00b_string_t *field,
                          size_t        *out_start,
                          size_t        *out_len);

extern n00b_json_node_t *
rocs_json_object_get_field(n00b_json_node_t *record, n00b_string_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

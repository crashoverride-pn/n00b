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

/**
 * @brief Check that @p data holds one well-formed JSON value and nothing but
 *        whitespace after it, without building a node graph.
 *
 * True means the bytes are JSON a client can parse. False means they are
 * damaged, or the scan declined a shape it does not settle (a surrogate
 * escape, nesting past the parser's depth limit), so a caller that needs a
 * definite answer parses on false.
 */
extern bool
rocs_json_scan_well_formed(const char *data, size_t len);

/** @brief Where one field's value sits in a record's bytes, if it is there. */
typedef struct {
    size_t start;
    size_t len;
    bool   found;
} rocs_json_span_t;

/** @brief Most fields one @ref rocs_json_scan_fields call looks for. */
#define ROCS_JSON_SCAN_FIELDS_MAX 8

/**
 * @brief Locate several fields' values in a compact JSON object in one pass.
 *
 * Each field resolves as @ref rocs_json_object_get_field would on the parsed
 * record: a key spelling the whole name wins, and otherwise a dotted name is
 * walked one segment at a time through nested objects. Top-level keys for
 * every field are found in a single pass over the record; a dotted walk then
 * scans only the nested value it descends into.
 *
 * Returns @c ROCS_JSON_SCAN_FOUND when every field was answered, with
 * @p out[i].found saying whether field @p i is present, or
 * @c ROCS_JSON_SCAN_UNSURE for anything @ref rocs_json_scan_field_span would
 * decline, and for more than @c ROCS_JSON_SCAN_FIELDS_MAX fields. Never
 * returns @c ROCS_JSON_SCAN_ABSENT.
 */
extern rocs_json_scan_t
rocs_json_scan_fields(const char       *data,
                      size_t            len,
                      size_t            count,
                      n00b_string_t   **fields,
                      rocs_json_span_t *out);

extern n00b_json_node_t *
rocs_json_object_get_field(n00b_json_node_t *record, n00b_string_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

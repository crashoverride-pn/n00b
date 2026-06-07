#pragma once

/** @file json_util.h — module-internal JSON helpers for n00b_attest.
 *
 *  Internal-linkage helpers shared between `statement.c` and
 *  `dsse.c`. Not part of the public surface; consumed only via
 *  `#include "internal/attest/json_util.h"` from within the
 *  module's translation units.
 */

#include <n00b.h>

#include "parsers/json.h"

/** Look up a string-keyed entry in a parsed JSON object.
 *
 *  Returns the node whose key matches `key`. Returns `nullptr` if `obj` is
 *  null, `obj` is not a JSON object, the dict store is empty, or the key is
 *  absent.
 *
 *  The returned pointer aliases the parse tree — the caller must
 *  not free it independently. Callers typically pass `r"..."`
 *  rich-string literals for zero-allocation static keys.
 */
n00b_json_node_t *n00b_attest_json_obj_lookup(n00b_json_node_t *obj,
                                              n00b_string_t    *key);

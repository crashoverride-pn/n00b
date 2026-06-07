/* json_util.c — module-internal JSON helpers for n00b_attest.
 *
 * Implementation for the helpers declared in
 * `include/internal/attest/json_util.h`. Shared between
 * `statement.c` and `dsse.c`; not part of the public surface.
 * Doxygen for these symbols lives in the header.
 */

#include "internal/attest/json_util.h"

n00b_json_node_t *
n00b_attest_json_obj_lookup(n00b_json_node_t *obj, n00b_string_t *key)
{
    return n00b_json_object_get(obj, key);
}

/**
 * @file rocs/normalizer.h
 * @brief Shared JSON value normalization and hash declarations for rocs.
 *
 * Ingest and query code must use this surface for indexed term construction.
 * The term-dict index stores hashes of normalized scalar payloads, while
 * composite JSON values are flattened into scalar leaves addressed by stable
 * JSON Pointer-style paths.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "parsers/json.h"
#include "rocs/index.h"

/**
 * @brief Error domain for normalizer operations.
 *
 * @post Codes are stable public result errors for normalization helpers.
 */
typedef enum : int32_t {
    N00B_STORE_NORM_OK          = 0,
    N00B_STORE_NORM_ERR_ARG     = -1,
    N00B_STORE_NORM_ERR_TYPE    = -2,
    N00B_STORE_NORM_ERR_NUMERIC = -3,
    N00B_STORE_NORM_ERR_STATE   = -4,
} n00b_store_norm_err_t;

/**
 * @brief One normalized scalar term.
 *
 * `path` is a JSON Pointer-style path. The root scalar path is the empty
 * string. Object field names are escaped by replacing `~` with `~0` and `/`
 * with `~1`; array positions use unsigned decimal indexes.
 *
 * `value` is the scalar JSON variant. Its selector is the authoritative JSON
 * kind; normalized terms do not carry a parallel type field.
 *
 * `bytes` is the canonical scalar payload derived from `value`. Hash framing
 * adds the index kind, scalar tag derived from the variant selector, path
 * length/path bytes, and payload length/payload bytes so term keys are
 * path-, kind-, and variant-separated.
 */
typedef struct {
    n00b_string_t    *path;
    n00b_json_node_t *value;
    n00b_buffer_t    *bytes;
} n00b_store_normalized_t;

/** @brief List of normalized scalar terms. */
typedef n00b_list_t(n00b_store_normalized_t *) n00b_store_normalized_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for a normalizer error code.
 *
 * @param err A @c N00B_STORE_NORM_* code.
 * @pre `err` is expected to come from a normalizer result.
 * @return A n00b string naming the code, or @c UNKNOWN for an unrecognized
 *         value.
 * @post The returned string is static and remains owned by the runtime.
 */
extern n00b_string_t *n00b_store_normalize_err_str(n00b_err_t err);

/**
 * @brief Normalize one scalar JSON node.
 *
 * @param node Scalar JSON node. Objects and arrays return
 *             @c N00B_STORE_NORM_ERR_TYPE.
 *
 * @kw path      Path assigned to the returned term. Defaults to the root path.
 * @kw allocator Allocator for the term and canonical byte payload.
 * @pre `node` must be non-null and must be a scalar JSON variant for success.
 *
 * Numeric canonical form:
 * - integers are signed int64 values encoded as eight big-endian
 *   two's-complement bytes;
 * - doubles are IEEE-754 binary64 values encoded as eight big-endian bytes;
 * - `-0.0` is normalized to `+0.0`;
 * - non-finite doubles are rejected with @c N00B_STORE_NORM_ERR_NUMERIC.
 *
 * Strings are exact UTF-8 bytes as stored in the JSON node. Term-dict exact
 * matching does not case-fold or Unicode-normalize strings; full-text/token
 * indexes may layer those transforms through their own index kind.
 *
 * @return Ok(normalized term) for scalar JSON nodes. Returns
 *         @c N00B_STORE_NORM_ERR_ARG for null input,
 *         @c N00B_STORE_NORM_ERR_TYPE for objects/arrays, and
 *         @c N00B_STORE_NORM_ERR_NUMERIC for non-finite doubles.
 * @post The returned term carries `{path, value, bytes}`. `value` is the
 *       original JSON node and its variant selector is the only public JSON
 *       kind. `bytes` is newly allocated canonical payload storage.
 */
extern n00b_result_t(n00b_store_normalized_t *)
n00b_store_normalize_scalar(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *path      = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Flatten a JSON tree into normalized scalar leaves.
 *
 * @param node JSON node to normalize. Scalars produce a one-element list.
 *             Objects and arrays recurse through their children.
 *
 * @kw root_path Base path for the tree. Defaults to the root path.
 * @kw allocator Allocator for the result list and terms.
 * @pre `node` must be non-null for success.
 *
 * Object traversal is sorted by key using `n00b_unicode_str_cmp` so the output
 * order is stable independent of dictionary bucket order.
 *
 * @return Ok(list) containing normalized scalar leaves in stable path order.
 *         Returns @c N00B_STORE_NORM_ERR_ARG for null input and forwards
 *         scalar/path construction errors.
 * @post Each returned term follows the scalar normalization contract. Empty
 *       objects and arrays contribute no terms.
 */
extern n00b_result_t(n00b_store_normalized_list_t *)
n00b_store_normalize_json(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *root_path = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Hash one normalized term for an index kind.
 *
 * @param kind  Index kind whose key-space should receive the term.
 * @param value Normalized scalar term returned by this module.
 * @kw allocator Allocator for scratch hash-frame storage.
 * @pre `kind` must name a concrete index kind. `value` must be a well-formed
 *      scalar normalized term.
 *
 * @return Ok(nonzero 128-bit hash) over a byte-stable frame containing the
 *         index kind, scalar tag derived from `value`'s variant selector,
 *         normalized path length/path bytes, payload length, and payload
 *         bytes. Invalid kinds or malformed terms return an error.
 * @post Equal `{kind, path, scalar variant, canonical payload}` inputs produce
 *       equal hashes. Changing any of those fields changes the framed input.
 */
extern n00b_result_t(n00b_uint128_t)
n00b_store_normalize_hash(n00b_store_index_kind_t  kind,
                          n00b_store_normalized_t *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

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

/**
 * @brief Visitor for allocation-light normalized text key generation.
 *
 * @param ctx Caller-owned context pointer.
 * @param key Framed, normalized 128-bit term key.
 * @return `true` to continue visiting keys, `false` to stop with a state
 *         error.
 */
typedef bool (*n00b_store_normalized_key_visitor_t)(void *ctx,
                                                    n00b_uint128_t key);

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
 * @brief Tokenize and normalize one JSON string for full-text indexes.
 *
 * @param node String JSON node to tokenize. Non-string JSON values return
 *             @c N00B_STORE_NORM_ERR_TYPE.
 *
 * @kw path      Path assigned to every returned token term. Defaults to the
 *               root path. Named-field full-text indexes use the root path for
 *               both ingest and query lookup because the descriptor field is
 *               the field discriminator.
 * @kw allocator Allocator for the result list, token JSON nodes, strings, and
 *               canonical byte payloads.
 * @pre `node` must be non-null for success.
 *
 * Tokenization is deliberately conservative in this phase: the input is first
 * Unicode case-folded, then split on ASCII bytes that are not letters, digits,
 * underscores, or non-ASCII UTF-8 bytes. Term-dict exact string normalization
 * is unchanged and does not call this helper.
 *
 * @return Ok(list) containing one normalized string term per token, or an
 *         empty list for empty/no-token strings. Returns
 *         @c N00B_STORE_NORM_ERR_ARG for null input,
 *         @c N00B_STORE_NORM_ERR_TYPE for non-string values, and
 *         @c N00B_STORE_NORM_ERR_STATE for malformed string payloads.
 * @post Each token term carries `{path, value, bytes}`. `value` is a JSON
 *       string node holding the normalized token and remains the only public
 *       value-kind discriminator; `bytes` is the normalized token UTF-8
 *       payload.
 */
extern n00b_result_t(n00b_store_normalized_list_t *)
n00b_store_normalize_text_tokens(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *path      = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Normalize one JSON string into overlapping text n-grams.
 *
 * @param node String JSON node to split into n-grams. Non-string JSON values
 *             return @c N00B_STORE_NORM_ERR_TYPE.
 *
 * @kw path      Path assigned to every returned n-gram term. Defaults to the
 *               root path. Named-field n-gram indexes use the root path for
 *               both ingest and query lookup because the descriptor field is
 *               the field discriminator.
 * @kw ngram_n   Byte width for each gram. Defaults to
 *               @c N00B_STORE_NGRAM_DEFAULT_N. Supported values are
 *               @c N00B_STORE_NGRAM_MIN_N through @c N00B_STORE_NGRAM_MAX_N;
 *               invalid values return @c N00B_STORE_NORM_ERR_ARG.
 * @kw allocator Allocator for the result list, n-gram JSON nodes, strings, and
 *               canonical byte payloads.
 * @pre `node` must be non-null for success.
 *
 * Generation is byte-stable: the input string is Unicode case-folded, then
 * overlapping grams are emitted from the folded UTF-8 byte sequence. Values
 * shorter than @p ngram_n produce an empty list. The helper does not tokenize
 * on punctuation; it is a candidate generator for substring-style predicates.
 *
 * @return Ok(list) containing normalized string terms for each generated
 *         n-gram, or an empty list when the folded string is too short.
 *         Returns @c N00B_STORE_NORM_ERR_ARG for null input or invalid
 *         @p ngram_n, @c N00B_STORE_NORM_ERR_TYPE for non-string values, and
 *         @c N00B_STORE_NORM_ERR_STATE for malformed string payloads.
 * @post Each n-gram term carries `{path, value, bytes}`. `value` is a JSON
 *       string node holding the normalized gram and remains the only public
 *       value-kind discriminator; `bytes` is the normalized gram UTF-8
 *       payload.
 */
extern n00b_result_t(n00b_store_normalized_list_t *)
n00b_store_normalize_text_ngrams(n00b_json_node_t *node) _kargs
{
    n00b_string_t    *path      = nullptr;
    uint8_t           ngram_n   = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Visit full-text token keys without materializing normalized terms.
 *
 * This uses the same case-folding, tokenization, scalar tag, path framing, and
 * hash primitive as @ref n00b_store_normalize_text_tokens followed by
 * @ref n00b_store_normalize_hash.
 */
extern n00b_result_t(uint64_t)
n00b_store_normalize_text_token_keys(
    n00b_json_node_t                     *node,
    n00b_store_normalized_key_visitor_t   visitor,
    void                                *visitor_ctx) _kargs
{
    n00b_string_t    *path      = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Visit n-gram keys without materializing normalized terms.
 *
 * This uses the same folded byte grams, scalar tag, path framing, and hash
 * primitive as @ref n00b_store_normalize_text_ngrams followed by
 * @ref n00b_store_normalize_hash.
 */
extern n00b_result_t(uint64_t)
n00b_store_normalize_text_ngram_keys(
    n00b_json_node_t                     *node,
    n00b_store_normalized_key_visitor_t   visitor,
    void                                *visitor_ctx) _kargs
{
    n00b_string_t    *path      = nullptr;
    uint8_t           ngram_n   = N00B_STORE_NGRAM_DEFAULT_N;
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

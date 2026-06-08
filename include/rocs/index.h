/**
 * @file rocs/index.h
 * @brief Index descriptors and posting-view declarations for rocs.
 *
 * Indexes are query accelerators. They may make a predicate faster, but query
 * correctness must not depend on any index being present or able to serve a
 * predicate. The planner treats advertisements as hints and verifies residual
 * predicates through record views when needed.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/string.h"
#include "rocs/shard.h"

typedef struct n00b_store_index_t    n00b_store_index_t;
typedef struct n00b_store_postings_t n00b_store_postings_t;
typedef struct n00b_store_record_t   n00b_store_record_t;
typedef struct n00b_store_map_shard_t n00b_store_map_shard_t;

/**
 * @brief Stable record identity independent of process pointers.
 */
typedef struct {
    uint64_t shard_id;
    uint64_t ordinal;
    uint64_t generation;
} n00b_store_pos_t;

/**
 * @brief Public index kind tag.
 *
 * Dispatch is by this scalar tag and process-side implementation code. rocs
 * never marshals function pointers into shard images or index tables.
 */
typedef enum : int32_t {
    N00B_STORE_INDEX_NONE     = 0,
    N00B_STORE_INDEX_TERM     = 1,
    N00B_STORE_INDEX_FULLTEXT = 2,
    N00B_STORE_INDEX_NGRAM    = 3,
    N00B_STORE_INDEX_NUMERIC  = 4,
    N00B_STORE_INDEX_BOOL     = 5,
    N00B_STORE_INDEX_VECTOR   = 6,
} n00b_store_index_kind_t;

/** @brief Smallest configurable n-gram byte width accepted by rocs. */
#define N00B_STORE_NGRAM_MIN_N ((uint8_t)2)

/** @brief Default n-gram byte width used by rocs text indexes. */
#define N00B_STORE_NGRAM_DEFAULT_N ((uint8_t)3)

/** @brief Largest configurable n-gram byte width accepted by rocs. */
#define N00B_STORE_NGRAM_MAX_N ((uint8_t)16)

/**
 * @brief Predicate operator codes accepted by index advertisement.
 *
 * These values are the public contract for @ref n00b_store_index_advertise.
 * Planner and filter layers must map their own predicate enums to this enum
 * before asking an index for an acceleration hint.
 *
 * @c N00B_STORE_INDEX_OP_UNSPECIFIED preserves the legacy term-index default:
 * a matching term descriptor may advertise equality acceleration. Full-text
 * descriptors require an explicit @c N00B_STORE_INDEX_OP_CONTAINS because a
 * contains predicate has different correctness rules from exact equality.
 * N-gram descriptors advertise @c N00B_STORE_INDEX_OP_PREFIX as candidate
 * acceleration only. The planner may reuse that candidate contract for regex
 * leaves with compiled literal prefixes, but callers must verify the original
 * residual predicate before treating candidates as hits.
 */
typedef enum : int32_t {
    N00B_STORE_INDEX_OP_UNSPECIFIED = 0,
    N00B_STORE_INDEX_OP_EQ          = 1,
    N00B_STORE_INDEX_OP_CONTAINS    = 5,
    N00B_STORE_INDEX_OP_PREFIX      = 6,
} n00b_store_index_op_t;

/**
 * @brief Error domain for index and posting-view operations.
 */
typedef enum : int32_t {
    N00B_STORE_INDEX_OK          = 0,
    N00B_STORE_INDEX_ERR_ARG     = -1,
    N00B_STORE_INDEX_ERR_STATE   = -2,
    N00B_STORE_INDEX_ERR_KIND    = -3,
    N00B_STORE_INDEX_ERR_UNREADY = -4,
    N00B_STORE_INDEX_ERR_INTERNAL = -5,
} n00b_store_index_err_t;

/**
 * @brief One posting result.
 *
 * The record member is a shard-aware view handle. It is never a raw mapped JSON
 * pointer; public callers may inspect only its durable position in this phase.
 * Internal planner verification resolves it through rocs-private record-view
 * helpers.
 */
typedef struct {
    n00b_store_pos_t     pos;
    n00b_store_record_t *record;
} n00b_store_posting_t;

/**
 * @brief Planner-facing index advertisement.
 *
 * Advertisements are hints only. An incorrect hint may change performance, but
 * it must not change query semantics.
 */
typedef struct {
    bool                    accelerates;
    n00b_store_index_kind_t kind;
    double                  selectivity_hint;
} n00b_store_advert_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for an index error code.
 *
 * @param err A @c N00B_STORE_INDEX_* code, usually from a result error branch.
 * @return A n00b string naming the code, or @c UNKNOWN for an unrecognized
 *         value.
 */
extern n00b_string_t *n00b_store_index_err_str(n00b_err_t err);

/**
 * @brief Construct a process-side index descriptor.
 *
 * @param field Field this index is configured to serve. The pointer is
 *              retained, not copied.
 * @param kind  Scalar index kind tag.
 * @kw ngram_n N-gram byte width for @c N00B_STORE_INDEX_NGRAM descriptors.
 *             Defaults to @c N00B_STORE_NGRAM_DEFAULT_N. Non-NGRAM
 *             descriptors must use the default value.
 * @kw allocator Allocator for the process-side descriptor.
 *
 * @return Ok(index) for recognized non-NONE kinds. Returns
 *         @c N00B_STORE_INDEX_ERR_ARG for null field and
 *         invalid n-gram sizing, and @c N00B_STORE_INDEX_ERR_KIND for unknown
 *         or NONE kinds.
 *
 * The returned descriptor contains no function pointers and is not shard
 * marshal state.
 */
extern n00b_result_t(n00b_store_index_t *)
n00b_store_index_new(n00b_string_t          *field,
                     n00b_store_index_kind_t kind) _kargs
{
    uint8_t           ngram_n   = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Read the scalar kind tag from an index descriptor.
 *
 * @param index Index descriptor returned by @c n00b_store_index_new.
 * @return Ok(kind) on success, or @c N00B_STORE_INDEX_ERR_ARG for a null
 *         descriptor.
 */
extern n00b_result_t(n00b_store_index_kind_t)
n00b_store_index_kind(n00b_store_index_t *index);

/**
 * @brief Read the configured n-gram byte width from an index descriptor.
 *
 * @param index Index descriptor returned by @c n00b_store_index_new.
 * @return Ok(width) for @c N00B_STORE_INDEX_NGRAM descriptors. Returns
 *         @c N00B_STORE_INDEX_ERR_ARG for null descriptors and
 *         @c N00B_STORE_INDEX_ERR_KIND for non-NGRAM descriptors.
 */
extern n00b_result_t(uint8_t)
n00b_store_index_ngram_n(n00b_store_index_t *index);

/**
 * @brief Borrow the field configured on an index descriptor.
 *
 * @param index Index descriptor returned by @c n00b_store_index_new.
 * @return Ok(field) on success. The returned pointer is borrowed from the
 *         descriptor. Returns @c N00B_STORE_INDEX_ERR_ARG for a null descriptor
 *         or malformed descriptor with no field.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_index_field(n00b_store_index_t *index);

/**
 * @brief Ask an index whether it can accelerate a field/operator pair.
 *
 * Term descriptors advertise equality acceleration for their configured field.
 * Full-text descriptors advertise only named-field whole-token contains
 * acceleration. N-gram descriptors advertise named-field prefix candidate
 * acceleration; the planner must retain and verify the original
 * residual predicate. Unsupported operator/kind combinations return a
 * non-accelerating hint so the planner can scan and verify.
 *
 * @param index Index descriptor to inspect.
 * @param field Field being planned.
 * @param op    One of @ref n00b_store_index_op_t. Unknown operator codes return
 *              a non-accelerating hint. @c N00B_STORE_INDEX_OP_UNSPECIFIED is
 *              accepted only for the legacy term equality default.
 * @return Planner hint. Invalid inputs and field mismatches return a
 *         non-accelerating @c N00B_STORE_INDEX_NONE hint. A matching
 *         @c N00B_STORE_INDEX_TERM equality descriptor,
 *         @c N00B_STORE_INDEX_FULLTEXT contains descriptor, or
 *         @c N00B_STORE_INDEX_NGRAM prefix descriptor returns an
 *         accelerating hint with a heuristic selectivity. N-gram hints are
 *         never exact-answer contracts.
 */
extern n00b_store_advert_t
n00b_store_index_advertise(n00b_store_index_t *index,
                           n00b_string_t      *field,
                           int64_t             op);

/**
 * @brief Add one hot shard record to an index.
 *
 * @param index          Index descriptor. Hot shards support
 *                       @c N00B_STORE_INDEX_TERM,
 *                       @c N00B_STORE_INDEX_FULLTEXT, and
 *                       @c N00B_STORE_INDEX_NGRAM.
 * @param shard          Open hot shard containing the record.
 * @param record_ordinal Stable ordinal returned by @c n00b_store_shard_append.
 * @kw allocator         Allocator for normalization and hash scratch. Durable
 *                       column/posting storage remains owned by @p shard.
 *
 * @return Ok(number of normalized terms appended). Records missing the
 *         descriptor's field, non-text values in text indexes, or fields that
 *         normalize to no terms return Ok(0). Unsupported index kinds return
 *         @c N00B_STORE_INDEX_ERR_UNREADY.
 *
 * The index descriptor's field is the single source of truth; this call does
 * not accept a second field argument. Hot insertion mutates only the shard's
 * typed column/posting containers.
 */
extern n00b_result_t(uint64_t)
n00b_store_index_add(n00b_store_index_t *index,
                     n00b_store_shard_t *shard,
                     uint64_t            record_ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Look up a value in an open hot shard index.
 *
 * @param index Index descriptor whose field should be searched.
 * @param shard Open hot shard.
 * @param value Query JSON value. Term indexes accept scalar or composite JSON
 *              values; composites are flattened and matched as a conjunction
 *              of scalar terms under their normalized paths. Full-text indexes
 *              accept only string values that normalize to exactly one text
 *              token. N-gram indexes accept only string values that produce at
 *              least one configured n-gram, and return candidate postings only.
 * @kw allocator Allocator for the returned posting view and record handles.
 *
 * @return Ok(postings). Misses are successful empty posting views. Invalid
 *         inputs, sealed hot shards, malformed index state, unsupported index
 *         kinds, non-text text-index query values, empty/multi-token full-text
 *         query values, or too-short n-gram query values return typed index
 *         errors.
 */
extern n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup(n00b_store_index_t *index,
                        n00b_store_shard_t *shard,
                        n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Look up a value in a sealed shard through mapped views.
 *
 * @param index Index descriptor whose field should be searched.
 * @param shard Borrowed mapped shard view for a sealed shard.
 * @param value Query JSON value. Term indexes accept scalar or composite JSON
 *              values; composites are flattened and matched as a conjunction
 *              of scalar terms under their normalized paths. Full-text and
 *              catch-all full-text descriptors accept exactly one whole-token
 *              string query. N-gram descriptors accept string queries that
 *              produce at least one configured n-gram and return candidates
 *              only.
 * @kw allocator Allocator for the returned posting view and record handles.
 *
 * @pre @p shard must name a sealed shard image opened through rocs map APIs.
 *      Mapped bytes must stay resident for the lifetime of returned record
 *      view handles.
 *
 * @return Ok(postings). Misses are successful empty posting views. Invalid
 *         inputs, non-sealed mapped shards, malformed mapped index state,
 *         unsupported index kinds, non-text text-index query values,
 *         empty/multi-token full-text query values, or too-short n-gram query
 *         values return typed index errors.
 *
 * @post Returned record handles are shard-aware mapped views. They do not
 *       expose raw mapped JSON pointers to callers.
 *
 * This is the sealed-image counterpart to @c n00b_store_index_lookup. It uses
 * resolver-aware mapped dict/list APIs, resolves internal vaddrs, compares the
 * mapped field and term keys, and never unmarshals shard bytes.
 */
extern n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup_mapped(n00b_store_index_t     *index,
                               n00b_store_map_shard_t *shard,
                               n00b_json_node_t       *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a valid empty postings view.
 *
 * Empty views are successful, non-null values. They represent "no candidate
 * postings", not an error and not a missing index.
 *
 * @kw shard_id   Shard identity represented by this posting view.
 * @kw generation Store generation for durable positions.
 * @kw allocator  Allocator for the postings view.
 *
 * @return Ok(postings) containing a non-null empty postings view.
 */
extern n00b_result_t(n00b_store_postings_t *)
n00b_store_postings_empty() _kargs
{
    uint64_t          shard_id   = 0;
    uint64_t          generation = 0;
    n00b_allocator_t *allocator  = nullptr;
};

/**
 * @brief Return the number of postings in a view.
 *
 * @param postings Posting view returned by an index lookup or
 *                 @c n00b_store_postings_empty.
 * @return Ok(length) on success, or @c N00B_STORE_INDEX_ERR_ARG for a null or
 *         malformed view.
 */
extern n00b_result_t(uint64_t)
n00b_store_postings_len(n00b_store_postings_t *postings);

/**
 * @brief Borrow a posting by ordinal within the posting view.
 *
 * Out-of-range ordinals return successful none.
 *
 * @param postings Posting view returned by an index lookup or
 *                 @c n00b_store_postings_empty.
 * @param ordinal  Zero-based ordinal within the posting view.
 * @return Result wrapping some posting for an in-range entry, none for
 *         out-of-range, or @c N00B_STORE_INDEX_ERR_ARG /
 *         @c N00B_STORE_INDEX_ERR_STATE for invalid view state.
 */
extern n00b_result_t(n00b_option_t(n00b_store_posting_t))
n00b_store_postings_get(n00b_store_postings_t *postings, uint64_t ordinal);

/**
 * @brief Read the durable position carried by a record-view handle.
 *
 * @param record Opaque shard-aware record-view handle.
 * @return Ok(position) on success, or @c N00B_STORE_INDEX_ERR_ARG for a null
 *         handle.
 */
extern n00b_result_t(n00b_store_pos_t)
n00b_store_record_pos(n00b_store_record_t *record);

#ifdef __cplusplus
}
#endif

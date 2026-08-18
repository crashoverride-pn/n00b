/**
 * This header is internal to rocs planner implementation and focused tests.
 * It is not part of the public rocs umbrella, is not included by
 * <rocs/n00b_rocs.h>, and may change before the public filter/query APIs land.
 *
 * The planner answers one question: given a query and one shard, which records
 * in that shard match? It answers with ordinals, meaning record positions
 * within the shard, numbered from zero.
 *
 *     filter                 what callers build, via rocs/filter.h
 *       |
 *       |  lowered by filter.c
 *       v
 *     predicate tree         AND / OR / NOT over leaf tests like eq or contains
 *       |
 *       |  DISPATCH: consult the indexes, never read a record
 *       v
 *     candidates             ordinals that might match
 *      + residual            the part of the query no index could answer
 *       |
 *       |  VERIFY: read those records, test the residual on each
 *       v
 *     ordinals               the records that actually match
 *
 * Dispatch is the half that uses indexes and touches no records. Verify is the
 * half that reads records and uses no index. When dispatch can answer a query
 * exactly it returns no residual, and verify has nothing left to do.
 *
 * It is not a cost-based optimizer. There is exactly one plan for a given
 * predicate, and the only choice it makes is which index serves a leaf.
 *
 * Leaf dispatch asks every configured descriptor for an acceleration hint and
 * keeps the accelerating one with the lowest selectivity. Equality and
 * whole-token contains can be exact. Prefix and regex use n-gram postings as a
 * prefilter and always keep their own leaf as residual. IN, RANGE, and UNDER
 * have no index path and always scan with a residual.
 *
 * Booleans compose over ordinal sets. AND intersects candidates and conjoins
 * residuals, OR unions them while retaining which branches came back exact,
 * and NOT complements. Each set carries its shard's @c 0..record_count-1
 * universe, and set operations refuse to mix universes.
 *
 * Falling back never changes answers, only cost. Anything unsupported,
 * unready, or matching too much of a shard degrades to a full-universe
 * candidate set plus residual verification.
 *
 * Sealed stores fan out per shard. Partition routes prune shards that cannot
 * match, then each surviving shard is dispatched and verified on its own and
 * contributes its own ordinal set.
 *
 * A three-term query over a shard with a term index on kind, a full-text index
 * on msg, and nothing on ts:
 *
 *     AND
 *      |-- kind == "build"        term index      -> {2,5,7,9}  exact
 *      |-- ts > 1000              no index path   -> {0..9}     residual
 *      '-- msg contains "error"   full-text index -> {5,9}      exact
 *
 *     candidates = {2,5,7,9} & {0..9} & {5,9} = {5,9}
 *     residual   = ts > 1000
 *     verify     = load records 5 and 9, evaluate ts > 1000 on each
 *     result     = {9}
 *
 * Note that the unindexed term did not force a scan of the shard. It widened
 * nothing, because its siblings had already narrowed the candidates, and it
 * survived as the residual that verify applies to those two records.
 *
 * An ordinal set is a bitset over exactly one shard's records:
 *
 *     ordinal   0  1  2  3  4  5  6  7  8  9
 *     bits      .  .  X  .  .  X  .  X  .  X    count 4, record_count 10
 *
 * record_count is the set's universe. Two sets from different shards can never
 * be combined, and complement is relative to the owning set's record_count, so
 * NOT of the above is {0,1,3,4,6,8} and never reaches another shard.
 *
 * Predicate trees and ordinal sets declared here are process-side planning
 * state only. They are not shard marshal state, are not stored in
 * @c n00b_store_shard_t, and must not be embedded in sealed shard images. Nodes,
 * sets, and helper containers are allocated through the caller-selected
 * allocator and are owned by that allocator/GC lifetime; there is no explicit
 * destroy API.
 *
 * The any-field marker is accepted only for catch-all search-compatible
 * predicates in this phase: @c N00B_PLAN_LEAF_CONTAINS. It is rejected for
 * range, exists, under/path, prefix, regex, equality, and IN leaves.
 */
#pragma once

#define N00B_ROCS_INTERNAL_PLAN_H 1

#include <stdint.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/variant.h"
#include "core/alloc.h"
#include "core/string.h"
#include "parsers/json.h"
#include "rocs/index.h"
#include "rocs/store.h"
#include "text/regex/regex.h"

typedef struct n00b_plan_predicate_t n00b_plan_predicate_t;
typedef struct n00b_plan_target_t    n00b_plan_target_t;
typedef struct n00b_plan_path_t      n00b_plan_path_t;
typedef struct n00b_plan_ordset_t    n00b_plan_ordset_t;
typedef struct n00b_plan_dispatch_t  n00b_plan_dispatch_t;
typedef struct n00b_plan_shard_result_t n00b_plan_shard_result_t;
typedef struct n00b_plan_path_component_t n00b_plan_path_component_t;

/**
 * @brief Variant-only JSON value handle used by internal predicate leaves.
 *
 * Planner predicate/node/operator tags classify predicate structure only. The
 * JSON node's own variant selector is the JSON value-kind discriminator.
 */
typedef n00b_variant_t(n00b_json_node_t *) n00b_plan_value_t;

/** @brief Ordered list of internal predicate children. */
typedef n00b_list_t(n00b_plan_predicate_t *) n00b_plan_predicate_list_t;

/** @brief Ordered list of process-side index descriptors available to a plan. */
typedef n00b_list_t(n00b_store_index_t *) n00b_plan_index_list_t;

/** @brief Ordered list of per-shard planner results for WP-008 fan-out. */
typedef n00b_list_t(n00b_plan_shard_result_t *)
    n00b_plan_shard_result_list_t;

/** @brief Ordered list of variant-only values for IN predicates. */
typedef n00b_list_t(n00b_plan_value_t) n00b_plan_value_list_t;

/** @brief Ordered list of internal path components. */
typedef n00b_list_t(n00b_plan_path_component_t *)
    n00b_plan_path_component_list_t;

/** @brief Error domain for internal planner helpers. */
typedef enum : int32_t {
    N00B_PLAN_OK                  = 0,
    N00B_PLAN_ERR_ARG             = -1,
    N00B_PLAN_ERR_STATE           = -2,
    N00B_PLAN_ERR_EMPTY           = -3,
    N00B_PLAN_ERR_ANY_UNSUPPORTED = -4,
    N00B_PLAN_ERR_ORDINAL         = -5,
    N00B_PLAN_ERR_UNIVERSE        = -6,
    N00B_PLAN_ERR_CANCELED        = -7,
} n00b_plan_err_t;

/**
 * @brief Cooperative-cancellation predicate for residual verification.
 *
 * Residual verification materializes and JSON-parses every candidate record
 * (an unindexed CONTAINS over a large shard verifies the full universe), so a
 * long verify must be abortable when its consumer goes away. Polled
 * periodically (every 1024 candidates) inside the verify loop; returning true
 * aborts the plan with @c N00B_PLAN_ERR_CANCELED. Same shape as the query
 * cursor's cancel hook (query.h) — declared here independently so plan.h does
 * not depend on query.h.
 */
typedef bool (*n00b_plan_cancel_fn)(void *ctx);

/** @brief Predicate shape tag. This classifies structure only. */
typedef enum : int32_t {
    N00B_PLAN_PREDICATE_AND   = 1,
    N00B_PLAN_PREDICATE_OR    = 2,
    N00B_PLAN_PREDICATE_NOT   = 3,
    N00B_PLAN_PREDICATE_LEAF  = 4,
    N00B_PLAN_PREDICATE_FALSE = 5,
} n00b_plan_predicate_kind_t;

/** @brief Leaf operator tag. This classifies predicate structure only. */
typedef enum : int32_t {
    N00B_PLAN_LEAF_EQ       = 1,
    N00B_PLAN_LEAF_IN       = 2,
    N00B_PLAN_LEAF_RANGE    = 3,
    N00B_PLAN_LEAF_EXISTS   = 4,
    N00B_PLAN_LEAF_CONTAINS = 5,
    N00B_PLAN_LEAF_PREFIX   = 6,
    N00B_PLAN_LEAF_REGEX    = 7,
    N00B_PLAN_LEAF_UNDER    = 8,
} n00b_plan_leaf_op_t;

/**
 * @brief Predicate target kind.
 *
 * Field targets name real schema fields. Any targets are catch-all search
 * markers and do not carry a schema field name.
 */
typedef enum : int32_t {
    N00B_PLAN_TARGET_FIELD = 1,
    N00B_PLAN_TARGET_ANY   = 2,
} n00b_plan_target_kind_t;

/**
 * @brief Internal path component syntax tag.
 *
 * This classifies path syntax only: object key versus array index. It is not a
 * predicate payload-kind discriminator, and value-bearing predicate leaves
 * remain variant-only.
 */
typedef enum : int32_t {
    N00B_PLAN_PATH_KEY   = 1,
    N00B_PLAN_PATH_INDEX = 2,
} n00b_plan_path_component_kind_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for an internal planner error.
 *
 * @param err Error code in the internal planner predicate error domain.
 * @return Static rich string naming the error, or an unknown-error string for
 *         codes outside @ref n00b_plan_err_t.
 */
extern n00b_string_t *n00b_plan_err_str(n00b_err_t err);

/**
 * @brief Construct a field target for a real schema field name.
 *
 * @param field Field name. Must be non-null and non-empty.
 * @kw allocator Allocator for the returned process-side target.
 * @return Ok(target) on success, or @c N00B_PLAN_ERR_ARG for invalid input.
 */
extern n00b_result_t(n00b_plan_target_t *)
n00b_plan_target_field(n00b_string_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an internal catch-all target marker.
 *
 * @kw allocator Allocator for the returned process-side target.
 * @return Ok(target) on success.
 *
 * The returned target has kind @c N00B_PLAN_TARGET_ANY and no field name. It is
 * accepted only by catch-all search-compatible leaf constructors documented in
 * this header.
 */
extern n00b_result_t(n00b_plan_target_t *)
n00b_plan_target_any() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Inspect a target's structural kind.
 *
 * @param target Target handle.
 * @return Ok(kind) on success, or @c N00B_PLAN_ERR_ARG for null target.
 */
extern n00b_result_t(n00b_plan_target_kind_t)
n00b_plan_target_kind(n00b_plan_target_t *target);

/**
 * @brief Borrow a field target's field name.
 *
 * @param target Target handle.
 * @return Ok(some(field)) for field targets, Ok(none) for any targets, or
 *         @c N00B_PLAN_ERR_ARG for null target.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_plan_target_field_name(n00b_plan_target_t *target);

/**
 * @brief Allocate an empty child-list helper for AND/OR construction.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned empty child-list helper. The caller mutates it until passing it
 *         to a successful AND/OR constructor.
 */
extern n00b_plan_predicate_list_t *
n00b_plan_predicate_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one non-null child to a predicate child list.
 *
 * @param list Mutable borrowed child list.
 * @param child Predicate handle that the list records by pointer.
 * @return Ok(true) on append, or @c N00B_PLAN_ERR_ARG for null list/child.
 */
extern n00b_result_t(bool)
n00b_plan_predicate_list_append(n00b_plan_predicate_list_t *list,
                                n00b_plan_predicate_t      *child);

/**
 * @brief Allocate an empty process-side index descriptor list.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned empty index-list helper. The caller mutates it until using it
 *         as a borrowed dispatch input.
 *
 * The list records borrowed descriptor pointers only. Descriptors remain
 * process-side configuration and are never marshaled into a shard.
 */
extern n00b_plan_index_list_t *
n00b_plan_index_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one index descriptor to a process-side index list.
 *
 * @param list Mutable borrowed index list.
 * @param index Process-side index descriptor.
 * @return Ok(true) on append, or @c N00B_PLAN_ERR_ARG for null list/index.
 */
extern n00b_result_t(bool)
n00b_plan_index_list_append(n00b_plan_index_list_t *list,
                            n00b_store_index_t     *index);

/**
 * @brief Allocate an empty value-list helper for IN construction.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned empty value-list helper. The caller mutates it until passing it
 *         to a successful IN constructor.
 */
extern n00b_plan_value_list_t *
n00b_plan_value_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one variant-only value to an IN value list.
 *
 * @param list Mutable borrowed value list.
 * @param value Variant-only JSON node handle value. Must be set.
 * @return Ok(true) on append, or @c N00B_PLAN_ERR_ARG for a null list or unset
 *         variant value.
 */
extern n00b_result_t(bool)
n00b_plan_value_list_append(n00b_plan_value_list_t *list,
                            n00b_plan_value_t      value);

/**
 * @brief Allocate an empty internal path-component list.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned empty path-component list helper. The caller mutates it until
 *         passing it to a successful path constructor.
 */
extern n00b_plan_path_component_list_t *
n00b_plan_path_component_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append an object-key component to a path-component list.
 *
 * @param list Mutable borrowed path-component list.
 * @param key Key string. Must be non-null and outlive the resulting
 *            path through the allocator/GC lifetime if the list is copied into
 *            a path.
 * @kw allocator Allocator for the appended component helper.
 * @return Ok(true) on append, or @c N00B_PLAN_ERR_ARG for null list/key.
 */
extern n00b_result_t(bool)
n00b_plan_path_component_list_append_key(
    n00b_plan_path_component_list_t *list,
    n00b_string_t                   *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append an array-ordinal component to a path-component list.
 *
 * @param list Mutable borrowed path-component list.
 * @param index Array ordinal to record in the component.
 * @kw allocator Allocator for the appended component helper.
 * @return Ok(true) on append, or @c N00B_PLAN_ERR_ARG for null list.
 */
extern n00b_result_t(bool)
n00b_plan_path_component_list_append_index(
    n00b_plan_path_component_list_t *list,
    uint64_t                         index) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an immutable internal path handle from path components.
 *
 * @param components Ordered component list. Components are copied into
 *                   an owned immutable list for the returned path handle.
 * @kw allocator Allocator for the path handle and copied list.
 * @return Ok(path) on success, or @c N00B_PLAN_ERR_ARG for null components or
 *         invalid component state.
 */
extern n00b_result_t(n00b_plan_path_t *)
n00b_plan_path_new(n00b_plan_path_component_list_t *components) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the number of components in an internal path handle.
 *
 * @param path Path handle.
 * @return Ok(count) on success, or @c N00B_PLAN_ERR_ARG for null/malformed
 *         path state.
 */
extern n00b_result_t(uint64_t)
n00b_plan_path_component_count(n00b_plan_path_t *path);

/**
 * @brief Borrow one path component by ordinal.
 *
 * @param path Path handle.
 * @param ordinal Zero-based component ordinal.
 * @return Ok(some(component)) when present, Ok(none) when @p ordinal is out of
 *         range, or @c N00B_PLAN_ERR_ARG for null path.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_path_component_t *))
n00b_plan_path_component_at(n00b_plan_path_t *path, uint64_t ordinal);

/**
 * @brief Inspect a path component's path-syntax kind.
 *
 * @param component Path component.
 * @return Ok(kind) on success, or @c N00B_PLAN_ERR_ARG for null/invalid
 *         component state.
 */
extern n00b_result_t(n00b_plan_path_component_kind_t)
n00b_plan_path_component_kind(n00b_plan_path_component_t *component);

/**
 * @brief Borrow a key path component's key string.
 *
 * @param component Path component.
 * @return Ok(some(key)) for key components, Ok(none) for index components, or
 *         @c N00B_PLAN_ERR_ARG for null/invalid component state.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_plan_path_component_key(n00b_plan_path_component_t *component);

/**
 * @brief Inspect an index path component's array ordinal.
 *
 * @param component Path component.
 * @return Ok(some(index)) for index components, Ok(none) for key components,
 *         or @c N00B_PLAN_ERR_ARG for null/invalid component state.
 */
extern n00b_result_t(n00b_option_t(uint64_t))
n00b_plan_path_component_index(n00b_plan_path_component_t *component);

/**
 * @brief Construct an empty per-shard ordinal set.
 *
 * @param record_count Size of the single-shard universe. Valid ordinals are
 *                     exactly @c 0..record_count-1. Zero is valid and creates
 *                     an empty zero-universe set.
 * @kw allocator Allocator for the returned process-side set and its internal
 *               dense bit storage.
 * @return Ok(set) on success, or @c N00B_PLAN_ERR_ARG if @p record_count
 *         cannot be represented by the internal byte storage.
 *
 * The returned set is owned by the caller-selected allocator/GC lifetime and is
 * process-side planner state only. It is not shard marshal state.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_empty(uint64_t record_count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a full per-shard ordinal set.
 *
 * @param record_count Size of the single-shard universe. Valid ordinals are
 *                     exactly @c 0..record_count-1. Zero is valid and creates
 *                     an empty zero-universe set.
 * @kw allocator Allocator for the returned process-side set and its internal
 *               dense bit storage.
 * @return Ok(set) on success, or @c N00B_PLAN_ERR_ARG if @p record_count
 *         cannot be represented by the internal byte storage.
 *
 * @post For every ordinal less than @p record_count,
 *       @ref n00b_plan_ordset_contains returns Ok(true).
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_full(uint64_t record_count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return an ordinal set's explicit shard universe size.
 *
 * @param set Ordinal set.
 * @return Ok(record_count) on success, @c N00B_PLAN_ERR_ARG for null set, or
 *         @c N00B_PLAN_ERR_STATE for malformed internal storage.
 */
extern n00b_result_t(uint64_t)
n00b_plan_ordset_record_count(n00b_plan_ordset_t *set);

/**
 * @brief Return the number of member ordinals.
 *
 * @param set Ordinal set.
 * @return Ok(count) on success, @c N00B_PLAN_ERR_ARG for null set, or
 *         @c N00B_PLAN_ERR_STATE for malformed internal storage.
 */
extern n00b_result_t(uint64_t)
n00b_plan_ordset_count(n00b_plan_ordset_t *set);

/**
 * @brief Insert one ordinal into a mutable ordinal set.
 *
 * @param set Mutable ordinal set.
 * @param ordinal Ordinal to insert. Must be less than the set's
 *                @c record_count.
 * @return Ok(true) when the set changed, Ok(false) when @p ordinal was already
 *         present, @c N00B_PLAN_ERR_ARG for null set,
 *         @c N00B_PLAN_ERR_STATE for malformed storage, or
 *         @c N00B_PLAN_ERR_ORDINAL when @p ordinal is outside the explicit
 *         universe.
 */
extern n00b_result_t(bool)
n00b_plan_ordset_insert(n00b_plan_ordset_t *set, uint64_t ordinal);

/**
 * @brief Free an ordset (its bitset buffer and the struct) back to its
 *        allocator. Null-safe. For pool allocators this returns the slots to
 *        the free-list so a per-boundary streaming scan does not accumulate one
 *        ordset per boundary.
 */
extern void
n00b_plan_ordset_free(n00b_plan_ordset_t *set);

/**
 * @brief Test membership for one ordinal.
 *
 * @param set Ordinal set.
 * @param ordinal Ordinal to test.
 * @return Ok(true) when @p ordinal is present, Ok(false) when absent or when
 *         @p ordinal is outside the set's explicit universe,
 *         @c N00B_PLAN_ERR_ARG for null set, or @c N00B_PLAN_ERR_STATE for
 *         malformed storage.
 */
extern n00b_result_t(bool)
n00b_plan_ordset_contains(n00b_plan_ordset_t *set, uint64_t ordinal);

/**
 * @brief Borrow a member ordinal by deterministic increasing-order index.
 *
 * Observable iteration order is always increasing ordinal order and does not
 * depend on dictionary, set, shard-residency, or storage iteration order.
 *
 * @param set Ordinal set.
 * @param index Zero-based index among present ordinals in increasing order.
 * @return Ok(some(ordinal)) when @p index names a member, Ok(none) when
 *         @p index is out of range, @c N00B_PLAN_ERR_ARG for null set, or
 *         @c N00B_PLAN_ERR_STATE for malformed storage.
 */
extern n00b_result_t(n00b_option_t(uint64_t))
n00b_plan_ordset_at(n00b_plan_ordset_t *set, uint64_t index);

/**
 * @brief Compute the union of two ordinal sets with the same universe.
 *
 * @param left Ordinal set.
 * @param right Ordinal set.
 * @kw allocator Allocator for the returned process-side set.
 * @return Ok(set) with the same @c record_count as the inputs,
 *         @c N00B_PLAN_ERR_ARG for null input, @c N00B_PLAN_ERR_STATE for
 *         malformed storage, or @c N00B_PLAN_ERR_UNIVERSE for mismatched
 *         universes.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_union(n00b_plan_ordset_t *left,
                       n00b_plan_ordset_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Compute the intersection of two ordinal sets with the same universe.
 *
 * @param left Ordinal set.
 * @param right Ordinal set.
 * @kw allocator Allocator for the returned process-side set.
 * @return Ok(set) with the same @c record_count as the inputs,
 *         @c N00B_PLAN_ERR_ARG for null input, @c N00B_PLAN_ERR_STATE for
 *         malformed storage, or @c N00B_PLAN_ERR_UNIVERSE for mismatched
 *         universes.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_intersection(n00b_plan_ordset_t *left,
                              n00b_plan_ordset_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Compute set difference over two ordinal sets with the same universe.
 *
 * @param left Left-hand set.
 * @param right Set whose members are removed from @p left.
 * @kw allocator Allocator for the returned process-side set.
 * @return Ok(set) with the same @c record_count as the inputs,
 *         @c N00B_PLAN_ERR_ARG for null input, @c N00B_PLAN_ERR_STATE for
 *         malformed storage, or @c N00B_PLAN_ERR_UNIVERSE for mismatched
 *         universes.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_difference(n00b_plan_ordset_t *left,
                            n00b_plan_ordset_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Compute complement relative to one set's explicit universe.
 *
 * @param set Ordinal set.
 * @kw allocator Allocator for the returned process-side set.
 * @return Ok(set) with the same @c record_count as @p set,
 *         @c N00B_PLAN_ERR_ARG for null input, or
 *         @c N00B_PLAN_ERR_STATE for malformed storage.
 *
 * Complement is never global and never cross-shard. It flips membership only
 * inside @c 0..record_count-1.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_complement(n00b_plan_ordset_t *set) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf equality predicate.
 *
 * @param target Target. Must be a real field target in this phase.
 * @param value Set variant-only JSON node handle value.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null/unset input,
 *         or @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_eq(n00b_plan_target_t *target,
                       n00b_plan_value_t   value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf IN predicate from a non-empty value list.
 *
 * @param target Target. Must be a real field target in this phase.
 * @param values Non-empty list of set variant-only JSON node values.
 *               A successful predicate logically owns the list; the caller
 *               must not mutate it afterwards.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null/unset input,
 *         @c N00B_PLAN_ERR_EMPTY for an empty value list, or
 *         @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_in(n00b_plan_target_t    *target,
                       n00b_plan_value_list_t *values) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf range predicate with lower and upper bounds.
 *
 * @param target Target. Must be a real field target in this phase.
 * @param lower Set variant-only JSON node handle lower bound.
 * @param upper Set variant-only JSON node handle upper bound.
 * @kw include_lower Whether the lower bound is inclusive. Defaults to true.
 * @kw include_upper Whether the upper bound is inclusive. Defaults to true.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null/unset input,
 *         or @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_range(n00b_plan_target_t *target,
                          n00b_plan_value_t   lower,
                          n00b_plan_value_t   upper) _kargs
{
    bool              include_lower = true;
    bool              include_upper = true;
    n00b_allocator_t *allocator     = nullptr;
};

/**
 * @brief Construct a leaf existence predicate.
 *
 * @param target Target. Must be a real field target in this phase.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null target, or
 *         @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_exists(n00b_plan_target_t *target) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf whole-word contains/search predicate.
 *
 * This is the only current leaf constructor that accepts
 * @c N00B_PLAN_TARGET_ANY.
 *
 * @param target Real field target or internal any-field target.
 * @param term Non-empty search term.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, or @c N00B_PLAN_ERR_ARG for null/empty
 *         input or invalid target state.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_contains(n00b_plan_target_t *target,
                             n00b_string_t      *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf prefix predicate over a real field target.
 *
 * @param target Target. Must be a real field target in this phase.
 * @param prefix Non-empty prefix string.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null/empty input,
 *         or @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_prefix(n00b_plan_target_t *target,
                           n00b_string_t      *prefix) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf regex predicate over a real field target.
 *
 * @param target Target. Must be a real field target in this phase.
 * @param regex Compiled regex handle.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null input, or
 *         @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_regex(n00b_plan_target_t *target,
                          n00b_regex_t       *regex) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a leaf under/path predicate over a real field target.
 *
 * @param target Target. Must be a real field target in this phase.
 * @param path Internal path handle.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null input, or
 *         @c N00B_PLAN_ERR_ANY_UNSUPPORTED for any-field targets.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_under(n00b_plan_target_t *target,
                          n00b_plan_path_t   *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an AND predicate from an ordered child list.
 *
 * @param children List with at least two non-null predicate children.
 *                 A successful predicate logically owns the list; the caller
 *                 must not mutate it afterwards.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null/malformed
 *         input, or @c N00B_PLAN_ERR_EMPTY for fewer than two children.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_and(n00b_plan_predicate_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an OR predicate from an ordered child list.
 *
 * @param children List with at least two non-null predicate children.
 *                 A successful predicate logically owns the list; the caller
 *                 must not mutate it afterwards.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null/malformed
 *         input, or @c N00B_PLAN_ERR_EMPTY for fewer than two children.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_or(n00b_plan_predicate_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a NOT predicate and logically own its child.
 *
 * @param child Non-null predicate child. A successful NOT node
 *              logically owns the child relationship.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, or @c N00B_PLAN_ERR_ARG for null child.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_not(n00b_plan_predicate_t *child) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an internal always-false predicate.
 *
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success.
 *
 * This process-side shape is used by internal bridges such as public empty
 * @c IN lowering. It has no target, value payload, or children; dispatch over a
 * shard produces exact empty candidates and residual verification evaluates it
 * as false.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_false() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Inspect a predicate's shape kind.
 *
 * @param predicate Predicate handle.
 * @return Ok(kind) on success, or @c N00B_PLAN_ERR_ARG for null predicate.
 */
extern n00b_result_t(n00b_plan_predicate_kind_t)
n00b_plan_predicate_kind(n00b_plan_predicate_t *predicate);

/**
 * @brief Inspect a leaf predicate's operator.
 *
 * @param predicate Predicate handle.
 * @return Ok(op) for leaf predicates, @c N00B_PLAN_ERR_STATE for boolean
 *         predicates, or @c N00B_PLAN_ERR_ARG for null.
 */
extern n00b_result_t(n00b_plan_leaf_op_t)
n00b_plan_predicate_leaf_op(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow a leaf predicate target.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(target)) for leaves, Ok(none) for boolean predicates, or
 *         @c N00B_PLAN_ERR_ARG for null.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_target_t *))
n00b_plan_predicate_target(n00b_plan_predicate_t *predicate);

/**
 * @brief Return child count for boolean predicates, or zero for leaves.
 *
 * @param predicate Predicate handle.
 * @return Ok(count) on success, @c N00B_PLAN_ERR_ARG for null predicate, or
 *         @c N00B_PLAN_ERR_STATE for malformed boolean state.
 */
extern n00b_result_t(uint64_t)
n00b_plan_predicate_child_count(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow a child predicate by ordinal.
 *
 * NOT exposes its single child at ordinal zero. Leaves and out-of-range
 * ordinals return Ok(none).
 *
 * @param predicate Predicate handle.
 * @param ordinal Zero-based child ordinal.
 * @return Ok(some(child)) when present, Ok(none) for leaves or out-of-range
 *         ordinals, @c N00B_PLAN_ERR_ARG for null predicate, or
 *         @c N00B_PLAN_ERR_STATE for malformed boolean state.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_predicate_t *))
n00b_plan_predicate_child_at(n00b_plan_predicate_t *predicate,
                             uint64_t               ordinal);

/**
 * @brief Borrow an equality leaf's variant-only value.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(value)) for equality leaves, Ok(none) for other predicates,
 *         @c N00B_PLAN_ERR_ARG for null predicate, or @c N00B_PLAN_ERR_STATE
 *         for malformed equality leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_value_t))
n00b_plan_predicate_value(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow an IN leaf's owned value list.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(values)) for IN leaves, Ok(none) for other predicates,
 *         @c N00B_PLAN_ERR_ARG for null predicate, or @c N00B_PLAN_ERR_STATE
 *         for malformed IN leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_value_list_t *))
n00b_plan_predicate_values(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow a range leaf's lower bound.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(value)) for range leaves, Ok(none) for other predicates,
 *         @c N00B_PLAN_ERR_ARG for null predicate, or @c N00B_PLAN_ERR_STATE
 *         for malformed range leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_value_t))
n00b_plan_predicate_range_lower(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow a range leaf's upper bound.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(value)) for range leaves, Ok(none) for other predicates,
 *         @c N00B_PLAN_ERR_ARG for null predicate, or @c N00B_PLAN_ERR_STATE
 *         for malformed range leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_value_t))
n00b_plan_predicate_range_upper(n00b_plan_predicate_t *predicate);

/**
 * @brief Return whether a range leaf includes its lower bound.
 *
 * @param predicate Predicate handle.
 * @return Ok(flag) for range leaves, @c N00B_PLAN_ERR_ARG for null predicate,
 *         or @c N00B_PLAN_ERR_STATE for non-range predicates.
 */
extern n00b_result_t(bool)
n00b_plan_predicate_range_include_lower(n00b_plan_predicate_t *predicate);

/**
 * @brief Return whether a range leaf includes its upper bound.
 *
 * @param predicate Predicate handle.
 * @return Ok(flag) for range leaves, @c N00B_PLAN_ERR_ARG for null predicate,
 *         or @c N00B_PLAN_ERR_STATE for non-range predicates.
 */
extern n00b_result_t(bool)
n00b_plan_predicate_range_include_upper(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow a contains or prefix leaf's text handle.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(text)) for contains/prefix leaves, Ok(none) for other
 *         predicates, @c N00B_PLAN_ERR_ARG for null predicate, or
 *         @c N00B_PLAN_ERR_STATE for malformed text leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_plan_predicate_text(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow a regex leaf's compiled regex handle.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(regex)) for regex leaves, Ok(none) for other predicates,
 *         @c N00B_PLAN_ERR_ARG for null predicate, or @c N00B_PLAN_ERR_STATE
 *         for malformed regex leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_regex_t *))
n00b_plan_predicate_regex_handle(n00b_plan_predicate_t *predicate);

/**
 * @brief Borrow an under/path leaf's path handle.
 *
 * @param predicate Predicate handle.
 * @return Ok(some(path)) for under/path leaves, Ok(none) for other predicates,
 *         @c N00B_PLAN_ERR_ARG for null predicate, or @c N00B_PLAN_ERR_STATE
 *         for malformed under/path leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_path_t *))
n00b_plan_predicate_path(n00b_plan_predicate_t *predicate);

/**
 * @brief Dispatch one predicate tree over an open hot shard.
 *
 * @param predicate Predicate tree to plan.
 * @param indexes Process-side descriptor list. @c nullptr is treated
 *                as an empty list.
 * @param shard Open hot shard. It must expose a readable record
 *              universe through the hot shard root.
 * @kw allocator Allocator for the dispatch result, owned candidate set, and any
 *               synthesized residual boolean nodes.
 * @return Ok(dispatch) on success. Invalid inputs or unreadable shard state
 *         return @c N00B_PLAN_ERR_ARG or @c N00B_PLAN_ERR_STATE.
 *
 * Dispatch is conservative. Equality leaves over real field targets ask
 * each configured descriptor for @ref n00b_store_index_advertise and greedily
 * choose the accelerating term descriptor with the lowest selectivity hint. The
 * planner then calls @ref n00b_store_index_lookup and converts returned
 * postings to ordinals through @ref n00b_store_postings_len and
 * @ref n00b_store_postings_get. Resulting candidate cost is observable through
 * @ref n00b_plan_ordset_count on the dispatch candidates; no separate planner
 * cost API is provided.
 *
 * Hot full-text contains dispatch can be exact for the documented whole-token
 * shape. Hot n-gram dispatch is candidate-only for eligible named-field prefix
 * leaves and named-field regex leaves with a compiled literal-prefix fact, and
 * always returns the original leaf as residual for verification. Broad
 * candidate sets may drop to full-universe scan/verify without changing
 * answers. Named-field contains without a usable full-text index falls back to
 * scan/verify because its current semantics are whole-token, not substring.
 *
 * Hot any-field contains dispatch can be exact only through the internal
 * schema-derived catch-all descriptor. The descriptor reads whole-token
 * full-text postings for explicitly opted-in real schema fields. If no such
 * descriptor is supplied, the dispatch result is exact empty rather than a
 * broad scan, because raw residual verification has no schema opt-in list and
 * must not match excluded fields.
 *
 * Unsupported, mismatched, unready, partial, or failed index service falls back
 * to a full-universe candidate set plus a residual predicate whenever the shard
 * universe is readable. A fully served exact miss may return empty candidates
 * with no residual.
 */
extern n00b_result_t(n00b_plan_dispatch_t *)
n00b_plan_dispatch_hot(n00b_plan_predicate_t  *predicate,
                       n00b_plan_index_list_t *indexes,
                       n00b_store_shard_t     *shard) _kargs
{
    n00b_allocator_t    *allocator = nullptr;
    n00b_store_schema_t *schema    = nullptr;
};

/**
 * @brief Dispatch one predicate tree over a sealed mapped shard.
 *
 * @param predicate Predicate tree to plan.
 * @param indexes Process-side descriptor list. @c nullptr is treated
 *                as an empty list.
 * @param shard Sealed mapped shard view. It must expose a readable
 *              record-count universe through mapped shard accessors.
 * @kw allocator Allocator for the dispatch result, owned candidate set, and any
 *               synthesized residual boolean nodes.
 * @return Ok(dispatch) on success. Invalid inputs or unreadable mapped-shard
 *         state return @c N00B_PLAN_ERR_ARG or @c N00B_PLAN_ERR_STATE.
 *
 * This mapped entry point never unmarshals sealed shard bytes. Matching exact
 * term, full-text contains, and catch-all contains leaves use
 * @ref n00b_store_index_lookup_mapped and mapped shard accessors only; postings
 * are converted through durable @c n00b_store_pos_t ordinals. N-gram prefix and
 * regex paths may use mapped n-gram postings as candidate prefilters, but the
 * original predicate remains residual and is verified before hits are returned.
 * Broad mapped candidate sets fall back to full-universe scan/verify instead
 * of carrying an index-shaped residual that would be more expensive than the
 * scan.
 */
extern n00b_result_t(n00b_plan_dispatch_t *)
n00b_plan_dispatch_mapped(n00b_plan_predicate_t    *predicate,
                          n00b_plan_index_list_t   *indexes,
                          n00b_store_map_shard_t   *shard) _kargs
{
    n00b_allocator_t    *allocator = nullptr;
    n00b_store_schema_t *schema    = nullptr;
};

/**
 * @brief Borrow the owned candidate ordinal set from a dispatch result.
 *
 * @param dispatch Dispatch result.
 * @return Ok(candidates) on success, or @c N00B_PLAN_ERR_ARG /
 *         @c N00B_PLAN_ERR_STATE for invalid result state.
 *
 * The returned set is owned by the dispatch result's allocator lifetime. Callers
 * may inspect it with ordinal-set accessors but must not mutate it if later
 * verification will consume the same dispatch result.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_dispatch_candidates(n00b_plan_dispatch_t *dispatch);

/**
 * @brief Borrow the residual predicate tree, if verification is needed.
 *
 * @param dispatch Dispatch result.
 * @return Ok(some(predicate)) when residual verification remains, Ok(none) for
 *         exact candidate sets, or @c N00B_PLAN_ERR_ARG for null dispatch.
 *
 * The residual pointer is borrowed. It may point into the original predicate
 * tree or into planner-synthesized residual boolean nodes that share the
 * dispatch allocator lifetime.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_predicate_t *))
n00b_plan_dispatch_residual(n00b_plan_dispatch_t *dispatch);

/**
 * @brief Report whether residual verification is required.
 *
 * @param dispatch Dispatch result.
 * @return Ok(true) when @ref n00b_plan_dispatch_residual returns some, Ok(false)
 *         when candidates are exact, or @c N00B_PLAN_ERR_ARG for null dispatch.
 */
extern n00b_result_t(bool)
n00b_plan_dispatch_residual_needed(n00b_plan_dispatch_t *dispatch);

/**
 * @brief Report whether candidates fully satisfy the predicate.
 *
 * @param dispatch Dispatch result.
 * @return Ok(true) when no residual verification remains, Ok(false) otherwise,
 *         or @c N00B_PLAN_ERR_ARG for null dispatch.
 */
extern n00b_result_t(bool)
n00b_plan_dispatch_is_exact(n00b_plan_dispatch_t *dispatch);

/**
 * @brief Report whether at least one index lookup was used while planning.
 *
 * @param dispatch Dispatch result.
 * @return Ok(flag) on success, or @c N00B_PLAN_ERR_ARG for null dispatch.
 *
 * @note Currently unconsumed. Gating results on it would drop valid rows:
 * @c N00B_PLAN_LEAF_IN, @c N00B_PLAN_LEAF_RANGE, and
 * @c N00B_PLAN_LEAF_UNDER have no index dispatch path.
 */
extern n00b_result_t(bool)
n00b_plan_dispatch_used_index(n00b_plan_dispatch_t *dispatch);

/**
 * @brief Verify candidate ordinals against a residual over an open hot shard.
 *
 * @param shard Open hot shard.
 * @param candidates Per-shard candidate ordinal set.
 * @param residual Residual predicate, or @c nullptr when candidates
 *                 are already exact.
 * @kw allocator Allocator for a newly filtered ordinal set when verification is
 *               required.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(set) with verified ordinals, @c N00B_PLAN_ERR_ARG for invalid
 *         inputs, @c N00B_PLAN_ERR_STATE for unreadable shard/predicate state,
 *         or @c N00B_PLAN_ERR_UNIVERSE if @p candidates does not match the
 *         shard's record universe.
 *
 * Residual predicates are evaluated over shard-aware record access. Missing
 * fields or missing path components evaluate false. Empty IN predicates are
 * rejected by construction; a malformed empty IN residual is treated as
 * planner state error. Range comparisons over incompatible JSON variants
 * evaluate false. Regex verification runs only against JSON string values;
 * non-string and missing values evaluate false.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_verify_hot(n00b_store_shard_t     *shard,
                     n00b_plan_ordset_t    *candidates,
                     n00b_plan_predicate_t *residual) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Verify candidate ordinals against a residual over a sealed mapped shard.
 *
 * @param shard Sealed mapped shard view.
 * @param candidates Per-shard candidate ordinal set.
 * @param residual Residual predicate, or @c nullptr when candidates
 *                 are already exact.
 * @kw allocator Allocator for materialized record JSON and the returned set
 *               when verification is required.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(set) with verified ordinals, @c N00B_PLAN_ERR_ARG for invalid
 *         inputs, @c N00B_PLAN_ERR_STATE for unreadable mapped state, or
 *         @c N00B_PLAN_ERR_UNIVERSE if @p candidates does not match the mapped
 *         shard's record universe.
 *
 * Sealed records are resolved by ordinal through internal rocs map helpers.
 * Verification never unmarshals the sealed shard, never passes mapped
 * container internals to ordinary hot JSON/list/dict APIs, and never exposes
 * raw mapped JSON pointers.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_verify_mapped(n00b_store_map_shard_t *shard,
                        n00b_plan_ordset_t     *candidates,
                        n00b_plan_predicate_t  *residual) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Scan a hot shard's full ordinal universe and verify a residual.
 *
 * @param shard Open hot shard.
 * @param residual Residual predicate, or @c nullptr to return the
 *                 full universe.
 * @kw allocator Allocator for the candidate universe and verified result.
 * @return Ok(set) with verified ordinals or a typed planner error.
 *
 * This is the internal fallback for predicates with no usable index. It must
 * return scan-and-verify results rather than an empty-answer shortcut for
 * ordinary field predicates. It is intentionally not the catch-all execution
 * path: @c N00B_PLAN_TARGET_ANY requires schema opt-in metadata supplied during
 * dispatch and cannot be evaluated correctly from a raw record alone.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_scan_verify_hot(n00b_store_shard_t     *shard,
                          n00b_plan_predicate_t *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Scan a mapped shard's full ordinal universe and verify a residual.
 *
 * @param shard Sealed mapped shard view.
 * @param residual Residual predicate, or @c nullptr to return the
 *                 full universe.
 * @kw allocator Allocator for the candidate universe, mapped record
 *               materializations, and verified result.
 * @return Ok(set) with verified ordinals or a typed planner error.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_scan_verify_mapped(n00b_store_map_shard_t *shard,
                             n00b_plan_predicate_t  *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Verify a hot dispatch result's candidate/residual handoff.
 *
 * @param dispatch Dispatch result.
 * @param shard Open hot shard matching the dispatch universe.
 * @kw allocator Allocator for any filtered verification result.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(exact_set) on success or a typed planner error.
 *
 * Exact dispatch results with no residual pass through their candidate set
 * unchanged. Dispatch fallbacks with residuals are filtered by verification.
 * Mixed OR dispatches may preserve already-exact child candidates internally
 * and union them with the verified residual result.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_dispatch_verify_hot(n00b_plan_dispatch_t *dispatch,
                              n00b_store_shard_t   *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Verify a mapped dispatch result's candidate/residual handoff.
 *
 * @param dispatch Dispatch result.
 * @param shard Sealed mapped shard matching the dispatch universe.
 * @kw allocator Allocator for mapped record materializations and any filtered
 *               verification result.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(exact_set) on success or a typed planner error.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_dispatch_verify_mapped(n00b_plan_dispatch_t   *dispatch,
                                 n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Plan catalog-visible sealed shards for WP-008 snapshot fan-out.
 *
 * @param store Open store whose catalog-visible sealed shards are planned.
 * @param predicate Internal predicate tree.
 * @param indexes Process-side descriptor list. @c nullptr is treated
 *                as an empty list.
 * @kw allocator Allocator for the ordered result list, result objects, copied
 *               route-key strings, dispatch scratch, mapped materializations,
 *               and verified ordinal sets.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(result list) on success or a typed planner/store-derived error.
 *
 * The planner enumerates only the store catalog visibility boundary: retained
 * sealed entries currently present in the catalog. Dropped or stale shards are
 * absent because retention removes them from that boundary. Partition pruning
 * is conservative; false positives may remain, but unsupported, unsafe OR, and
 * NOT cases keep shards instead of risking false negatives. Resident maps are
 * acquired only after a shard survives pruning and are released before this
 * function returns on every success and error path.
 *
 * Result objects are internal handoff state for WP-008. They expose durable
 * identity/metadata and the verified per-shard ordinal set only; they never
 * expose resident handles, mapped shard handles, record-view handles, raw
 * mapped JSON pointers, public cursor types, or public query-hit types.
 */
extern n00b_result_t(n00b_plan_shard_result_list_t *)
n00b_plan_store_sealed(n00b_store_t          *store,
                       n00b_plan_predicate_t *predicate,
                       n00b_plan_index_list_t *indexes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan one catalog-visible sealed shard.
 *
 * This is the per-shard form used by streaming/lazy query cursors. It performs
 * the same mapped-shard validation, dispatch, residual verification, and
 * resident release as @ref n00b_plan_store_sealed, but does not walk or prune
 * the whole catalog.
 */
extern n00b_result_t(n00b_plan_shard_result_t *)
n00b_plan_catalog_entry_sealed(n00b_store_t               *store,
                               n00b_store_catalog_entry_t *entry,
                               n00b_plan_predicate_t      *predicate,
                               n00b_plan_index_list_t     *indexes) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Return the number of per-shard results in an ordered result list.
 *
 * @param results Result list returned by @ref n00b_plan_store_sealed.
 * @return Ok(count), or @c N00B_PLAN_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_count(n00b_plan_shard_result_list_t *results);

/**
 * @brief Borrow one per-shard result by deterministic result-list ordinal.
 *
 * @param results Result list returned by @ref n00b_plan_store_sealed.
 * @param index Zero-based result ordinal.
 * @return Ok(some(result)) when present, Ok(none) when out of range, or
 *         @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_shard_result_t *))
n00b_plan_shard_result_at(n00b_plan_shard_result_list_t *results,
                          uint64_t                       index);

/**
 * @brief Return the durable shard id copied from catalog metadata.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(shard id), or @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_shard_id(n00b_plan_shard_result_t *result);

/**
 * @brief Return the catalog generation copied for stale-result detection.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(store/catalog generation), or @c N00B_PLAN_ERR_ARG for null
 *         input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_generation(n00b_plan_shard_result_t *result);

/**
 * @brief Return the schema generation copied from catalog metadata.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(schema generation), or @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_schema_generation(n00b_plan_shard_result_t *result);

/**
 * @brief Return the shard record-count universe for this result.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(record count), or @c N00B_PLAN_ERR_ARG for null input.
 *
 * The returned count must match the universe carried by
 * @ref n00b_plan_shard_result_ordinals.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_record_count(n00b_plan_shard_result_t *result);

/**
 * @brief Return the sealed shard timestamp copied from catalog metadata.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(seal timestamp), or @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_seal_ts(n00b_plan_shard_result_t *result);

/**
 * @brief Borrow the copied catalog partition route key.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(route key), or @c N00B_PLAN_ERR_ARG / @c N00B_PLAN_ERR_STATE.
 */
extern n00b_result_t(n00b_string_t *)
n00b_plan_shard_result_partition_key(n00b_plan_shard_result_t *result);

/**
 * @brief Borrow the verified per-shard ordinal set.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(ordinals), or @c N00B_PLAN_ERR_ARG / @c N00B_PLAN_ERR_STATE.
 *
 * The returned set is owned by the result object's allocator lifetime. WP-008
 * callers may inspect it with ordinal-set accessors and must not mutate it.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_shard_result_ordinals(n00b_plan_shard_result_t *result);

#ifdef __cplusplus
}
#endif

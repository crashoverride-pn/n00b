/**
 * Query planning: turning a predicate tree into a plan.
 *
 * n00b_plan_build takes a predicate and a shard's index descriptors and
 * returns a plan tree. It reads index metadata only and has no shard
 * parameter, so a plan can be built with no store open and one plan serves
 * every shard in a store.
 *
 *     filter                 callers build this, via rocs/filter.h
 *       |
 *       |  lowered by filter.c
 *       v
 *     predicate tree         AND / OR / NOT over leaves like eq or contains
 *       |
 *       |  n00b_plan_build   pick an index per leaf, then group
 *       v
 *     plan tree              INDEX_SCAN / RECORD_SCAN / INTERSECT / UNION /
 *       |                    COMPLEMENT / EMPTY
 *       |  n00b_plan_exec_*  eval.h: reads shards, cancellable
 *       v
 *     ordinals               positions of the records that match
 *
 * Both tree shapes live in plan_ir.h. Execution lives in eval.h.
 *
 * This is not a cost-based optimizer. There is exactly one plan for a given
 * predicate, and the only choice made is which index serves a leaf: every
 * descriptor is asked whether it accelerates (field, op), and the accelerating
 * one with the lowest selectivity hint wins. That hint does not depend on the
 * literal being searched, so the planner cannot tell a selective value from a
 * common one.
 *
 * What each leaf plans to:
 *
 *   eq                term index when one exists, else a record scan. A field
 *                     the schema declares indexed but which has no built index
 *                     plans to EMPTY, since nothing here populated it.
 *   contains, field   full-text index when one exists, else a record scan.
 *   contains, any     the catch-all index, or EMPTY. A record scan would match
 *                     fields the catch-all deliberately excludes.
 *   prefix, regex     n-gram index paired with the record scan that settles
 *                     it, else a record scan alone. Regex needs a literal
 *                     prefix to use an index at all.
 *   exists, in,
 *   range, under      record scan. No index path exists for these.
 *
 * Grouping. INTERSECT and UNION are associative, so a group nested inside a
 * group of the same kind is spliced into its parent, and the record scans in a
 * group merge into one. Both matter for cost rather than for answers: a flat
 * group lets execution resolve every index scan before any record scan runs,
 * so a scan sees only what its siblings already selected, and merging means a
 * group costs one pass over the records instead of one per unindexed leaf. A
 * group left holding a single operand is replaced by that operand, so building
 * an AND of two unindexed leaves yields a bare RECORD_SCAN.
 *
 * Three rules keep the split honest.
 *
 * 1. Planning touches no shard. n00b_plan_build has no shard parameter, so
 *    this is checkable rather than a convention. Reading records here would
 *    put unbounded work in the one phase with no cancel callback.
 *
 * 2. A plan describes work; it does not perform it. When the planner wants an
 *    operation the plan cannot express, extend the node vocabulary instead of
 *    doing the work. NOT over an indefinite child is the worked example: it
 *    cannot complement a maybe, so it plans COMPLEMENT and execution resolves
 *    it.
 *
 * 3. Cost may change; answers may not. An unusable index, a lossy scan that
 *    narrowed nothing, and a leaf with no index path all fall back to reading
 *    more records. None of them change which records match.
 *
 * This header is internal to the rocs planner and its focused tests. It is not
 * part of the public rocs umbrella and is not included by <rocs/n00b_rocs.h>.
 *
 * Predicate trees and ordinal sets are process-side state. They are never
 * shard marshal state, are not stored in n00b_store_shard_t, and must not be
 * embedded in sealed shard images. Nodes, sets and helper containers are
 * allocated through the caller-selected allocator and owned by that
 * allocator/GC lifetime; there is no explicit destroy API.
 *
 * The any-field target is accepted only for N00B_PLAN_LEAF_CONTAINS. It is
 * rejected for range, exists, under/path, prefix, regex, equality and IN.
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
typedef struct n00b_plan_shard_result_t n00b_plan_shard_result_t;
typedef struct n00b_plan_node_t         n00b_plan_node_t;

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
 * @brief Cooperative-cancellation predicate for plan execution.
 *
 * Both kinds of scan are unbounded. A record scan materializes and JSON-parses
 * every candidate, and an index scan walks a posting list that a common term
 * can make millions long. Either can outlive the consumer that asked for it,
 * so both poll this every 1024 items and abort with
 * @c N00B_PLAN_ERR_CANCELED when it returns true.
 *
 * An index scan that is cancelled reports it rather than falling back: an
 * unusable index is recovered from by reading more, which is the wrong answer
 * to somebody giving up. Same shape as the query cursor's cancel hook
 * (query.h), declared here so plan.h does not depend on query.h.
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
    N00B_PLAN_LEAF_SUBSTRING = 9,
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
 * @brief Construct a leaf unanchored substring predicate.
 *
 * Rides an n-gram index as a candidate generator and is settled against
 * records, since gram containment cannot prove the grams were contiguous.
 *
 * @param target Real field target. The any-field target is rejected.
 * @param text Non-empty substring.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, or @c N00B_PLAN_ERR_ARG for null/empty
 *         input or an any-field target.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_substring(n00b_plan_target_t *target,
                              n00b_string_t      *text) _kargs
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
 * @brief Verify candidate ordinals against a residual over an open hot shard.
 *
 * @param shard Open hot shard.
 * @param candidates Per-shard candidate ordinal set.
 * @param residual Predicate to test, or @c nullptr when candidates are
 *                 already the answer.
 * @kw allocator Allocator for a newly filtered ordinal set when verification is
 *               required.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates; returning true aborts with
 *               @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
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
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Plan and execute. Building a plan touches index metadata only, never a
// shard, so it needs no cancellation. Execution performs both index and record
// scans and takes a cancel callback. The node's shape lives in plan_ir.h, which
// only the planner and the interpreter need.
// ---------------------------------------------------------------------------

// Build a plan. Pure with respect to shard data.
extern n00b_result_t(n00b_plan_node_t *)
n00b_plan_build(n00b_plan_predicate_t  *predicate,
                n00b_plan_index_list_t *indexes) _kargs
{
    n00b_allocator_t    *allocator = nullptr;
    n00b_store_schema_t *schema    = nullptr;
};

// Plan inspection. A plan can be examined without a shard, which is how the
// planner is tested apart from execution.

// Which shards a predicate can possibly match, from catalog metadata alone.
// The executor uses this to skip shards before running the plan against them.
typedef struct n00b_plan_partition_filter_t n00b_plan_partition_filter_t;

extern n00b_result_t(n00b_plan_partition_filter_t *)
n00b_plan_partition_filter(n00b_store_t          *store,
                           n00b_plan_predicate_t *predicate) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_result_t(bool)
n00b_plan_partition_may_match(n00b_plan_partition_filter_t *filter,
                              n00b_string_t                *partition_key);

#ifdef __cplusplus
}
#endif

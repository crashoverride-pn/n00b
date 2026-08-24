/**
 * Query planning: turning a predicate tree into a plan.
 *
 * Three steps, and only the middle one reads a shard. n00b_plan_build is
 * structural: which index serves each leaf, and what nests in what.
 * n00b_plan_collect_* folds one shard's counts onto that plan's own nodes, and
 * is called once per shard. n00b_plan_settle decides what those counts decide,
 * once. Counts live on the nodes rather than in a table beside the plan, so a
 * leaf never has to be matched back to anything. Rule 4 below covers which
 * shards the result is then good for.
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
 * Index selection is by descriptor: every one is asked whether it accelerates
 * (field, op), and the accelerating one with the lowest selectivity hint wins.
 * That hint does not depend on the literal being searched. What does depend on
 * it is the count collected for each leaf, which is how the planner tells a
 * selective value from a common one on the shard at hand.
 *
 * What each leaf plans to:
 *
 *   eq                term index when one exists, else a record scan.
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
 * Four rules keep the split honest.
 *
 * 1. Planning touches no shard. n00b_plan_build has no shard parameter, so
 *    this is checkable rather than a convention. Reading records here would
 *    put unbounded work in the one phase with no cancel callback. The shard
 *    is read by n00b_plan_collect_*, which does take a cancel callback.
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
 * 4. A plan belongs to the shards it was collected from. Running it against
 *    a shard that was not folded in answers correctly and decides wrongly,
 *    which is the worst way to be wrong: nothing fails. A fan-out collects
 *    every shard of a partition, settles once, and runs that plan across all
 *    of them. A plan nothing was collected into decided nothing from counts
 *    and so belongs to no shard in particular.
 *
 * Cost planning.
 *
 * Two phases decide, and they decide different things. Settling picks shapes
 * from counts collected across the shards a plan will run on. Execution picks
 * tactics from what the query has actually accumulated by the time a node
 * runs. Neither changes which records match (rule 3), so the same query with
 * ordering off is the reference answer for one with it on.
 *
 *   n00b_plan_build                           reads no shard (rule 1)
 *          |    . which index serves a leaf
 *          |
 *          |  plan, structural, no counts yet
 *          v
 *   n00b_plan_collect_hot / _mapped           reads a shard, once per shard
 *          |
 *          |  counts, folded onto the plan's nodes
 *          v
 *   n00b_plan_settle
 *          |    . which child of a group runs first
 *          |    . an intersection an operand empties
 *          |
 *          |  plan, valid for the shards collected (rule 4)
 *          v
 *   n00b_plan_exec_hot / _mapped              reads the shard
 *               . probe the index, or walk its postings
 *               . skip a lossy scan whose term covers the shard
 *               . order predicate leaves cheapest-first
 *               . stop a group once its answer cannot change
 *
 * Sizes are bounds, not estimates. An intersection is no larger than its
 * smallest operand, a union no larger than the sum of its operands and no
 * larger than the shard, and a complement holds whatever its child does not.
 * Assuming independence would give a * b / n for an intersection, which is
 * smaller and wrong whenever the operands correlate, and correlated fields
 * are the normal case in event data.
 *
 * The planner sorts a group's operands: an INTERSECT narrowest first, so the
 * accumulator is smallest for everything that follows, and a UNION widest
 * first, so the group saturates soonest. The first operand matters most, but
 * the tail is not free after it, because a probe costs log2(df) per candidate
 * and the order of what remains decides how many candidates each of them sees.
 * Equal sizes break on execution cost, in the same direction, and the sort is
 * stable, so operands a count cannot separate keep the order they were
 * written in. An operand nothing can bound keeps its place, and no operand
 * crosses it.
 *
 * A group holding a COMPLEMENT is the exception: it gets the single hoist
 * instead. A complement's size is the shard minus its child's, so a NOT over a
 * rare term sorts to the end while costing what its cheap child costs, and
 * sorting on that number measurably reads more postings than leaving the tail
 * alone (test_rocs_plan_pathological, the negated shapes). The first operand
 * still moves.
 *
 * Execution costs are abstract units, calibrated against each other rather
 * than against a clock:
 *
 *     walk one posting          hot 10    mapped  7
 *     search one posting        hot 20    mapped 52
 *     read one bitmap word               80
 *
 * A mapped binary search costs more than a hot one because it touches pages
 * scattered through the image that a walk would have read in order.
 *
 * Probe or walk. Enumerating an index scan costs one walk step per posting.
 * Testing the candidates the query already holds costs one binary search per
 * term per candidate, plus enumerating those candidates when they are not
 * already cached:
 *
 *     probe = candidates * terms * ceil(log2(df)) * search_step + bitmap_walk
 *     walk  = df * walk_step
 *
 * On a hot shard of 100000 records, with cached candidate ordinals, where a
 * query has narrowed to 12 candidates and the next leaf matches 60000:
 *
 *     probe = 12 * 1 * 16 * 20  =   3840        <- tested against the index
 *     walk  = 60000 * 10        = 600000
 *
 * and inverted, at 5000 candidates against a term matching 40:
 *
 *     probe = 5000 * 1 * 6 * 20 = 600000
 *     walk  = 40 * 10           =    400        <- postings enumerated
 *
 * A probe is not even considered unless candidates * ceil(log2(n)) < n, which
 * keeps the arithmetic off queries that obviously cannot benefit. Note that
 * df understates the walk for a multi-term lookup, which resolves every term
 * rather than only the smallest; leaving it understated biases toward
 * walking, which is the direction that cannot answer wrongly.
 *
 * Predicate leaves carry their own costs, which order a group cheapest-first
 * so an expensive test never runs on a record a cheap one would reject:
 *
 *     field lookup  1     scalar eq  1     range      2     string eq  3
 *     prefix        5     under      7     substring 11     contains  11
 *     regex        40
 *
 * All of it is off when ROCS_PLAN_NO_COST is set in the environment, or after
 * n00b_plan_cost_set_enabled(false). See docs/rocs_env.md.
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
 * @param target Real field target.
 * @param text Non-empty substring.
 * @kw allocator Allocator for the returned predicate node.
 * @return Ok(predicate) on success, @c N00B_PLAN_ERR_ARG for null or empty
 *         input, or @c N00B_PLAN_ERR_ANY_UNSUPPORTED for an any-field target,
 *         whose catch-all descriptor holds whole-token postings only.
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
    n00b_allocator_t *allocator = nullptr;
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

/**
 * @brief Fold one shard's counts into a plan.
 *
 * Called once per shard, so the shards of a partition accumulate into a single
 * plan and one plan serves them all. Counts land on the plan's own nodes,
 * which is why a leaf never has to be matched back to a separate table.
 *
 * Unknown is contagious and is not zero: a shard that cannot answer for a leaf
 * leaves that leaf unknown for the whole partition, because a total that
 * quietly skipped it would read as "matches nothing" and settle an
 * intersection whose rows are there.
 *
 * A no-op when cost planning is off.
 *
 * @param plan  Plan to fold into, from @ref n00b_plan_build.
 * @param shard Sealed shard to read.
 * @kw allocator  Allocator for normalization scratch.
 * @kw cancel_cb  Polled while reading; a cancelled collect returns the error.
 * @kw cancel_ctx Passed to @p cancel_cb.
 * @return Ok(true), or @c N00B_PLAN_ERR_CANCELED.
 */
extern n00b_result_t(bool)
n00b_plan_collect_mapped(n00b_plan_node_t       *plan,
                         n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief The open-shard counterpart to @ref n00b_plan_collect_mapped.
 *
 * Counts move there as records arrive, so these describe the shard as it was
 * read, which is the guarantee its execution gives anyway.
 *
 * @warning A live shard grows between this and execution, so a caller must
 *          bound both to one ceiling: sample the shard's visible record count
 *          before calling this, pass it to @ref n00b_plan_settle, and pass it
 *          again as @c record_limit to @ref n00b_plan_exec_hot. Settling from
 *          a prefix and executing over more than that prefix is the one way
 *          cost planning can change an answer rather than a cost, because an
 *          intersection settled to EMPTY from counts over the prefix then
 *          answers empty for records appended past it. Counts read after the
 *          ceiling was sampled can only overstate, and an overstated count
 *          never reads as zero.
 */
extern n00b_result_t(bool)
n00b_plan_collect_hot(n00b_plan_node_t   *plan,
                      n00b_store_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Decide what the counts decide, once every shard has been folded in.
 *
 * Orders each group cheapest-first and settles an intersection whose operand
 * matches nothing. Ordering is a performance decision and answers the same
 * from any counts. Emptying is not: it removes work whose result the counts
 * described, so it holds only while those counts still describe the records
 * execution will read. Sealed shards make that automatic; a hot one needs the
 * ceiling discipline on @ref n00b_plan_collect_hot.
 *
 * @param plan         Plan collected into.
 * @param record_count Records across the shards collected, since the estimator
 *                     turns a count into a fraction of the whole. For a hot
 *                     shard this is the ceiling execution will be bounded to,
 *                     not the shard's current length.
 */
extern n00b_result_t(bool)
n00b_plan_settle(n00b_plan_node_t *plan, uint64_t record_count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief The descriptor that serves a leaf, or null when none does.
 *
 * The planner's choice, exposed so nothing has to make it a second time.
 * Every descriptor is asked whether it accelerates (field, op) at the wanted
 * kind, and the accelerating one with the lowest selectivity hint wins. A
 * caller that ranked against a different descriptor than the one the plan will
 * use would be describing a query nobody runs.
 */
extern n00b_store_index_t *
_rocs_plan_choose_index(n00b_plan_index_list_t *indexes,
                        n00b_string_t          *field,
                        n00b_store_index_op_t   op,
                        n00b_store_index_kind_t kind);

/**
 * @name Cost model
 *
 * What the executor should do with the counts it has read. Every function
 * below takes numbers and returns a verdict: none touches a shard, so rule 1
 * stays checkable and the policy can be exercised by a table of inputs rather
 * than by building a store and timing it.
 *
 * The executor owns the matching data questions, since answering those needs a
 * shard: what a term's posting count is, how many candidates a set holds,
 * whether a set has already materialized its ordinals.
 * @{
 */

/**
 * @brief Report whether execution orders group children by estimated size.
 *
 * On by default; off when @c ROCS_PLAN_NO_COST is set in the environment, or
 * after @ref n00b_plan_cost_set_enabled says so. With it off, every group runs
 * its children in plan order and a lossy scan is never skipped ahead of its
 * lookup.
 *
 * Ordering may change how much work a query does and may never change what it
 * answers, so the same query run both ways is the check on that.
 */
extern bool
n00b_plan_cost_enabled(void);

/**
 * @brief Turn cost-based ordering on or off for this process.
 *
 * @param enabled Whether groups order their children by estimated size.
 *
 * Overrides the environment default, including after it has been read.
 */
extern void
n00b_plan_cost_set_enabled(bool enabled);

/**
 * @brief Relative cost of testing a predicate against one record.
 *
 * Structural and shard-independent: the same predicate costs the same
 * everywhere, so this is as usable at plan build as during a scan. Units match
 * the scan-step costs above, and ratios are what carry meaning: a regex over a
 * text field is tens of times an integer compare.
 */
extern uint64_t
n00b_plan_cost_predicate(n00b_plan_predicate_t *predicate);

/**
 * @brief Order a group's children cheapest-first.
 *
 * Fills @p order with child indices. A conjunction stops at its first false and
 * a disjunction at its first true, so testing the cheap children first is what
 * keeps an expensive one from running on records something else would have
 * rejected.
 *
 * Stable: equal-cost children keep the order they were written in.
 *
 * @param predicate Borrowed group predicate.
 * @param order     Caller's buffer for the resulting index order.
 * @param cap       Capacity of @p order. Also bounded internally at 64, which
 *                  is what every caller passes.
 * @return The number of indices written, or zero when the group does not fit,
 *         in which case the caller evaluates in plan order.
 */
extern size_t
n00b_plan_cost_order_children(n00b_plan_predicate_t *predicate,
                              uint16_t              *order,
                              size_t                 cap);

/**
 * @brief Upper bound on an intersection's size, from two operand sizes.
 *
 * The smaller operand, which is a bound rather than an estimate. Treating the
 * operands as independent would give a smaller number and be wrong wherever
 * they correlate, which in event data is the usual case.
 */
extern uint64_t
n00b_plan_cost_intersect_size(uint64_t a, uint64_t b);

/**
 * @brief Upper bound on a union's size, from two operand sizes.
 *
 * Their sum, saturating, and never more than the shard holds.
 */
extern uint64_t
n00b_plan_cost_union_size(uint64_t a, uint64_t b, uint64_t record_count);

/**
 * @brief Size of a complement, given what its child matches.
 *
 * A complement holds every record its child does not, so a selective child
 * makes a broad complement and vice versa. Ordering that treats a negated leaf
 * as unknown can lead an intersect with its widest operand.
 *
 * @param child_df     What the complement's child matches.
 * @param record_count Records the shard publishes.
 */
extern uint64_t
n00b_plan_cost_complement_df(uint64_t child_df, uint64_t record_count);

/**
 * @brief Report whether a term covers the shard, making its walk pointless.
 *
 * @param lossy        Whether the scan only narrows rather than decides.
 * @param df           Postings the term carries on this shard.
 * @param record_count Records the shard publishes.
 * @return True when walking the postings cannot change the answer.
 */
extern bool
n00b_plan_cost_term_covers_shard(bool lossy, uint64_t df, uint64_t record_count);

/**
 * @brief Report whether a candidate set is small enough to be worth probing.
 *
 * Screens out sets so large that no posting count could make membership tests
 * cheaper than a walk, so the caller can skip reading a count it cannot use.
 *
 * @param candidates   Ordinals the restriction holds.
 * @param record_count Records the shard publishes.
 */
extern bool
n00b_plan_cost_probe_possible(uint64_t candidates, uint64_t record_count);

/**
 * @brief Cost of materializing a set's ordinals before probing it.
 *
 * @param record_count    Records the shard publishes.
 * @param ordinals_cached Whether the set already holds its ordinals.
 */
extern uint64_t
n00b_plan_cost_bitmap_walk(uint64_t record_count, bool ordinals_cached);

/**
 * @brief Report whether asking about candidates beats walking the postings.
 *
 * @param df          Postings the smallest term carries.
 * @param candidates  Ordinals the restriction holds.
 * @param bitmap_walk Cost of materializing those ordinals.
 * @param terms       Terms the looked-up value reduces to.
 * @param mapped      Whether the postings live in a sealed image.
 * @param searchable  Whether every term answers membership by binary search,
 *                    from @ref n00b_store_index_probe_searchable. False
 *                    refuses the probe outright: the arithmetic prices a
 *                    search, and a list that has to be scanned costs df per
 *                    candidate rather than log2(df).
 */
extern bool
n00b_plan_cost_probe_beats_walk(uint64_t df,
                                uint64_t candidates,
                                uint64_t bitmap_walk,
                                uint64_t terms,
                                bool     mapped,
                                bool     searchable);

/**
 * @brief Cost of one sequential posting step, by residency.
 *
 * A sealed image is contiguous and walks faster than a locked hot list.
 */
extern uint64_t
n00b_plan_cost_walk_step(bool mapped);

/**
 * @brief Cost of one binary-search step, by residency.
 *
 * The opposite way round from a walk: a search over a mapped image touches
 * scattered pages that can fault, where a hot list is memory already owned.
 */
extern uint64_t
n00b_plan_cost_search_step(bool mapped);

/**
 * @brief Report whether a child should displace the current pick.
 *
 * @param bound     Estimated size of what this child matches.
 * @param cost      What running this child costs, which breaks size ties.
 *                  The two are the same number for a leaf and diverge for a
 *                  complement, which is as wide as its child is narrow but
 *                  costs exactly what its child costs to produce.
 * @param best      The standing pick's estimated size.
 * @param best_cost The standing pick's cost.
 * @param widest    True to prefer the widest child, false for the narrowest.
 * @param have_pick Whether a standing pick exists to compare against.
 */
extern bool
n00b_plan_cost_prefers(uint64_t bound,
                       uint64_t cost,
                       uint64_t best,
                       uint64_t best_cost,
                       bool     widest,
                       bool     have_pick);

// Only in a build with N00B_DEBUG. Key sets built by n00b_plan_node_keys,
// counting real resolutions and not memo hits. Plan build is dominated by
// them, so this is how build cost is gated without asserting on a clock.
#ifdef N00B_DEBUG
extern uint64_t
n00b_plan_keys_resolved(void);

extern void
n00b_plan_keys_resolved_reset(void);

/**
 * @brief Plans built since the last reset. Only under @c N00B_DEBUG.
 *
 * A fan-out should build once per partition, not once per shard. Nothing else
 * reports the difference: a plan built too often is still correct.
 */
extern uint64_t
n00b_plan_plans_built(void);

extern void
n00b_plan_plans_built_reset(void);

/**
 * @brief Shards folded into a plan since the last reset. Only under
 *        @c N00B_DEBUG.
 *
 * Read beside @ref n00b_plan_plans_built: collecting scales with shards and
 * building should not.
 */
extern uint64_t
n00b_plan_shards_collected(void);

extern void
n00b_plan_shards_collected_reset(void);
#endif

/** @} */

#ifdef __cplusplus
}
#endif

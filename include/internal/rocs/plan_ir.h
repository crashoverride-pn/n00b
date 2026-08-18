/*
 * The two trees rocs queries are made of, and the accessors over them.
 *
 * A predicate tree says WHAT to match. A plan tree says HOW to get it. The
 * planner turns the first into the second; the interpreter runs the second.
 *
 *   predicate tree                        plan tree
 *   (what to match)                       (how to get it)
 *
 *   AND                                   INTERSECT
 *    |-- eq(kind,"build")     ------->     |-- INDEX_SCAN(term kind)
 *    '-- prefix(msg,"tim")                 '-- INTERSECT
 *                                              |-- INDEX_SCAN(ngram, lossy)
 *                                              '-- RECORD_SCAN(prefix)
 *
 * The predicate side is produced by filter.c lowering a public n00b_filter_t.
 * Its shapes are n00b_plan_predicate_t, n00b_plan_target_t, n00b_plan_path_t.
 *
 * The plan side is produced by n00b_plan_build (plan.h) and consumed by
 * n00b_plan_exec_* (eval.h). Its shape is n00b_plan_node_t. Every leaf names
 * the access it wants: INDEX_SCAN reads an index, RECORD_SCAN reads records.
 * A lossy index scan narrows without deciding, so the planner pairs it with
 * the RECORD_SCAN that settles it.
 *
 * Both sides answer in n00b_plan_ordset_t: a bitset of record positions within
 * a single shard, carrying that shard's 0..record_count-1 universe. Set
 * operations refuse to mix universes, and complement is relative to the
 * owning set's own record_count.
 *
 * Layouts live here because the planner writes them and the interpreter reads
 * them. Callers that only build and run queries need plan.h and eval.h.
 */
#pragma once

#include "internal/rocs/plan.h"

#ifdef __cplusplus
extern "C" {
#endif

struct n00b_plan_target_t {
    n00b_plan_target_kind_t kind;
    n00b_string_t          *field;
};

struct n00b_plan_path_t {
    n00b_plan_path_component_list_t *components;
};

struct n00b_plan_path_component_t {
    n00b_plan_path_component_kind_t kind;
    n00b_string_t                  *key;
    uint64_t                        index;
};

struct n00b_plan_ordset_t {
    uint64_t          record_count;
    uint64_t          count;
    n00b_buffer_t    *bits;
    // Lazily-built cache of the set's `count` ordinals in ascending order, so
    // n00b_plan_ordset_at() is O(1) instead of an O(record_count) bit rescan.
    // Without it, iterating a set via ordset_at(0..count-1) is O(count *
    // record_count) -- the hot-shard query hot spot. Built on first at(),
    // invalidated on any in-place mutation (bit_insert). `allocator` is the
    // set's own allocator so the cache shares its lifetime.
    n00b_allocator_t *allocator;
    uint64_t         *ord_cache;
};

struct n00b_plan_predicate_t {
    n00b_plan_predicate_kind_t  kind;
    n00b_plan_leaf_op_t         leaf_op;
    n00b_plan_target_t         *target;
    n00b_plan_predicate_list_t *children;
    n00b_plan_predicate_t      *child;
    n00b_plan_value_t           value;
    n00b_plan_value_t           lower;
    n00b_plan_value_t           upper;
    n00b_plan_value_list_t     *values;
    n00b_string_t              *text;
    n00b_regex_t               *regex;
    n00b_plan_path_t           *path;
    bool                        include_lower;
    bool                        include_upper;
};

// Shared between the planner and the interpreter. Not API; these exist because
// both halves of a split implementation need them.
extern n00b_err_t
_rocs_plan_index_err(n00b_err_t err);

extern n00b_err_t
_rocs_plan_store_err(n00b_err_t err);

extern n00b_err_t
_rocs_plan_map_err(n00b_err_t err);

extern bool
rocs_plan_debug_enabled(void);

extern n00b_result_t(bool)
_rocs_plan_ordset_check(n00b_plan_ordset_t *set);

extern bool
_rocs_plan_path_component_is_valid(n00b_plan_path_component_t *component);

extern n00b_result_t(n00b_json_node_t *)
_rocs_plan_value_node(n00b_plan_value_t value);

extern n00b_result_t(uint64_t)
_rocs_plan_hot_record_count(n00b_store_shard_t *shard);

extern n00b_result_t(uint64_t)
_rocs_plan_mapped_record_count(n00b_store_map_shard_t *shard);

extern n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_ordset_from_postings(n00b_store_postings_t *postings,
                                uint64_t               record_count) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

extern bool
_rocs_plan_candidate_set_is_broad(n00b_plan_ordset_t *candidates);

// ---------------------------------------------------------------------------
// The plan tree.
//
// A plan says what access to perform, never performs it. Building one touches
// index metadata (which descriptor accelerates which field) and nothing else:
// no shard, no posting list, no record. That is what makes planning cheap
// enough to need no cancellation.
//
// Every leaf declares its access kind. INDEX_SCAN reads an index, RECORD_SCAN
// reads records. Execution does both, and is cancellable throughout.
//
// A lossy index scan is one whose hits are candidates rather than answers. The
// planner pairs it with the RECORD_SCAN that settles it, under an INTERSECT:
//
//     INTERSECT
//      |-- INDEX_SCAN(ngram, "buil", lossy)
//      '-- RECORD_SCAN(prefix(kind, "buil"))
// ---------------------------------------------------------------------------


typedef struct n00b_plan_node_t n00b_plan_node_t;
typedef n00b_list_t(n00b_plan_node_t *) n00b_plan_node_list_t;

// What a plan node asks for. The node's layout is internal to the planner
// and the interpreter; the kinds are vocabulary any caller may read.
typedef enum : int32_t {
    N00B_PLAN_NODE_INDEX_SCAN  = 1,
    N00B_PLAN_NODE_RECORD_SCAN = 2,
    N00B_PLAN_NODE_INTERSECT   = 3,
    N00B_PLAN_NODE_UNION       = 4,
    N00B_PLAN_NODE_COMPLEMENT  = 5,
    N00B_PLAN_NODE_EMPTY       = 6,
} n00b_plan_node_kind_t;

// What an INDEX_SCAN yields when its index turns out to be unusable at
// execution time. An unusable index must never silently widen an answer, so
// the planner records the recovery up front rather than leaving it to the
// executor to guess.
typedef enum : int32_t {
    // Evaluate `fallback` against records. For an exact scan standing alone,
    // returning the universe unfiltered would return wrong answers.
    N00B_PLAN_RECOVER_RECORD_SCAN = 1,
    // Yield the universe. Safe only when a sibling RECORD_SCAN filters it,
    // which is how lossy scans are always paired.
    N00B_PLAN_RECOVER_ALL         = 2,
    // Yield nothing. The catch-all index has a schema opt-in list that raw
    // record evaluation cannot reproduce, so a miss must not fall back to it.
    N00B_PLAN_RECOVER_EMPTY       = 3,
} n00b_plan_recovery_t;

struct n00b_plan_node_t {
    n00b_plan_node_kind_t  kind;
    // INDEX_SCAN
    n00b_store_index_t    *index;
    n00b_json_node_t      *key;
    bool                   lossy;
    n00b_plan_recovery_t   recovery;
    n00b_plan_predicate_t *fallback;
    // RECORD_SCAN
    n00b_plan_predicate_t *predicate;
    // INTERSECT, UNION
    n00b_plan_node_list_t *children;
    // COMPLEMENT
    n00b_plan_node_t      *child;
};


// Accessors over the structures above, for inspecting a plan or a predicate
// tree without reaching into fields.

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

extern n00b_result_t(n00b_plan_node_kind_t)
n00b_plan_node_kind(n00b_plan_node_t *node);

extern n00b_result_t(uint64_t)
n00b_plan_node_child_count(n00b_plan_node_t *node);

extern n00b_result_t(n00b_option_t(n00b_plan_node_t *))
n00b_plan_node_child_at(n00b_plan_node_t *node, uint64_t index);

// True when any leaf reads an index.
extern n00b_result_t(bool)
n00b_plan_uses_index(n00b_plan_node_t *node);

// True when no leaf reads records, so execution answers from indexes alone.
extern n00b_result_t(bool)
n00b_plan_is_exact(n00b_plan_node_t *node);

// The predicate of the single RECORD_SCAN in the plan, if there is exactly
// one.
extern n00b_result_t(n00b_option_t(n00b_plan_predicate_t *))
n00b_plan_sole_record_scan(n00b_plan_node_t *node);

#ifdef __cplusplus
}
#endif

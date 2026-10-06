#pragma once

/**
 * @file earley_internal.h
 * @internal
 * @brief Internal struct definitions for the Earley parser engine.
 *
 * Defines the Earley item, chart state, parser context, BSR element,
 * and item dedup map — all internal to the Earley implementation.
 */

#include "slay/parse_forest.h"
#include "internal/slay/grammar_internal.h"
#include "adt/list.h"
#include "adt/dict.h"

// ============================================================================
// BSR (Binary Subtree Representation) element
// ============================================================================

/**
 * @brief One entry in the BSR parse forest.
 *
 * Records a grammar slot and the three Earley set positions that
 * locate a derivation step within the chart.
 */
typedef struct {
    int32_t slot;         /**< Grammar slot: lr0_rule_item_base[rule_ix] + dot. */
    int32_t left_extent;  /**< Earley set where this rule/symbol started. */
    int32_t pivot;        /**< Split point between left and right parts. */
    int32_t right_extent; /**< Earley set where this rule/symbol ended. */
} n00b_bsr_element_t;

// ============================================================================
// Earley item
// ============================================================================

/**
 * @brief One item in an Earley chart set.
 *
 * Tracks the current dot position within a rule, links back to the
 * start item and the previous scan step, and carries cost/penalty
 * information for ambiguity resolution.
 */
struct n00b_earley_item_t {
    // Structural pointers
    n00b_earley_item_t *start_item;     /**< Item that started this rule. */
    n00b_earley_item_t *previous_scan;  /**< Previous scan item (token link). */

    // Set management
    n00b_dict_t(n00b_earley_item_t *, bool) *parent_states;  /**< Parent Earley states. */
    n00b_dict_t(n00b_earley_item_t *, bool) *predictions;    /**< Predicted items from this item. */
    n00b_dict_t(n00b_earley_item_t *, bool) *completors;     /**< Items that completed this item. */

    // Grammar references
    n00b_parse_rule_t  *rule;           /**< The production rule. */
    n00b_rule_group_t  *group;          /**< Group if inside repetition group. */
    n00b_earley_item_t *group_top;      /**< Top-level item for the group. */

    // Caching
    n00b_dict_t(n00b_earley_item_t *, void *) *cache; /**< Memoized results for tree build. */

    // Markers
    int64_t             noscan;         /**< Non-scannable marker. */

    // Position tracking
    int32_t             ruleset_id;     /**< NT ID being parsed. */
    int32_t             rule_index;     /**< Index of the production rule. */
    int32_t             cursor;         /**< Dot position within the rule. */
    int32_t             predictor_ruleset_id; /**< Earley set of the predictor. */
    int32_t             predictor_rule_index; /**< Rule index of the predictor. */
    int32_t             predictor_cursor;     /**< Cursor of the predictor. */

    // Group bookkeeping
    int32_t             match_ct;       /**< Number of matches for group items. */

    // State identification
    int32_t             estate_id;      /**< Earley state (set) ID. */
    int32_t             eitem_index;    /**< Index within the Earley state. */

    // Cost/penalty tracking
    uint32_t            penalty;        /**< Total accumulated penalty. */
    uint32_t            sub_penalties;  /**< Penalties from sub-parses. */
    uint32_t            my_penalty;     /**< Penalty from this item's rule. */
    uint32_t            group_penalty;  /**< Penalty from group repetitions. */
    uint32_t            cost;           /**< Rule cost. */

    // Operation code
    n00b_earley_op_t    op;             /**< Next operation for this item. */

    // Flags
    bool                double_dot;        /**< Dot at both NT and rule end. */
    bool                null_prediction;   /**< Predicted from nullable NT. */
    bool                no_reprocessing;   /**< Skip reprocessing. */
    bool                from_completion;   /**< Created by completer — skip FIRST filter. */
    bool                leo_item;          /**< True if Leo-optimized item. */
    n00b_earley_item_t *leo_direct_parent; /**< Direct parent for Leo items. */

    // LR(0) integration
    int32_t             lr0_state_id;   /**< LR(0) state for table-driven prediction. */

    // Subtree boundary tag
    n00b_subtree_info_t subtree_info;   /**< Subtree boundary classification. */
};

// ============================================================================
// Item dedup hash map
// ============================================================================

/**
 * @brief Open-addressing hash map for fast Earley item deduplication.
 */
typedef struct {
    n00b_earley_item_t **buckets;
    int32_t              cap;
    int32_t              len;
} n00b_item_map_t;

// ============================================================================
// Earley state (one column of the chart)
// ============================================================================

typedef n00b_earley_item_t *n00b_earley_item_ptr_t;

struct n00b_earley_state_t {
    n00b_token_info_t                   *token;        /**< Token at this position. */
    void                                *cache;        /**< Memoization cache. */
    n00b_list_t(n00b_earley_item_ptr_t)  items;        /**< Items in this Earley set. */
    n00b_item_map_t                      item_map;     /**< Dedup map for items. */
    n00b_earley_item_t                 **leo_table;    /**< Leo optimization table. */
    int                                  id;           /**< Earley set ID. */
};

// ============================================================================
// Earley parser context
// ============================================================================

typedef n00b_earley_state_t *n00b_earley_state_ptr_t;

/**
 * @brief Full Earley parser state.
 *
 * Replaces slop's `slay_parser_t`.  Uses `n00b_alloc()` throughout
 * (GC-managed) instead of arenas, and consumes tokens lazily from
 * an `n00b_token_stream_t` instead of preloaded arrays.
 */
struct n00b_earley_parser_t {
    n00b_grammar_t                         *grammar;
    n00b_list_t(n00b_earley_state_ptr_t)    states;
    n00b_earley_state_t                    *current_state;
    n00b_earley_state_t                    *next_state;
    n00b_token_stream_t                    *stream;
    void                                   *user_context;
    bool                                    run;
    int32_t                                 start;
    int32_t                                 position;

    // BSR parse forest
    n00b_bsr_element_t *bsr_set;
    int32_t             bsr_count;
    int32_t             bsr_cap;
    n00b_dict_t(uint64_t, bool)  *bsr_dedup;

    // Virtual items from Leo expansion (must be freed)
    void  **virt_items;
    int32_t virt_items_len;
    int32_t virt_items_cap;

    // Tree construction intermediates
    n00b_list_t(void *) tree_nb_infos;
    n00b_list_t(void *) tree_ptrlists;

};

// ============================================================================
// Inline helpers
// ============================================================================

/**
 * @brief Three-way cost comparison for Earley items.
 *
 * Compares first by penalty (lower wins), then by cost (lower wins).
 */
static inline n00b_earley_cmp_t
n00b_earley_cost_cmp(n00b_earley_item_t *left, n00b_earley_item_t *right)
{
    if (left->penalty < right->penalty) {
        return N00B_CMP_LT;
    }

    if (left->penalty > right->penalty) {
        return N00B_CMP_GT;
    }

    if (left->cost < right->cost) {
        return N00B_CMP_LT;
    }

    if (left->cost > right->cost) {
        return N00B_CMP_GT;
    }

    return N00B_CMP_EQ;
}

// ============================================================================
// Item-set helpers (replaces n00b_hashset_t operations)
// ============================================================================

typedef n00b_dict_t(n00b_earley_item_t *, bool) n00b_item_set_t;

/**
 * @brief Allocate a new item set (pointer-identity dict used as a set).
 *
 * The default object hash caches an item's first address hash in its header,
 * which moves with the item, so membership survives a copying collection.
 */
static inline n00b_item_set_t *
n00b_item_set_new(void)
{
    n00b_item_set_t *s = n00b_alloc(n00b_item_set_t);
    n00b_dict_init(s);
    return s;
}

/**
 * @brief A new tree-build cache for an item (`n00b_earley_item_t.cache`).
 */
static inline n00b_dict_t(n00b_earley_item_t *, void *) *
n00b_earley_cache_new(void)
{
    n00b_dict_t(n00b_earley_item_t *, void *) *c
        = n00b_alloc(n00b_dict_t(n00b_earley_item_t *, void *));
    n00b_dict_init(c);
    return c;
}

/**
 * @brief Add an item to the set.  Returns true if it was newly added.
 */
static inline bool
n00b_item_set_add(n00b_item_set_t *s, n00b_earley_item_t *item)
{
    if (!item) {
        return false;
    }
    bool true_val = true;
    return n00b_dict_add(s, item, true_val);
}

/**
 * @brief Unconditionally insert an item into the set.
 */
static inline void
n00b_item_set_put(n00b_item_set_t *s, n00b_earley_item_t *item)
{
    bool true_val = true;
    n00b_dict_put(s, item, true_val);
}

/**
 * @brief Test membership.
 */
static inline bool
n00b_item_set_contains(n00b_item_set_t *s, n00b_earley_item_t *item)
{
    if (!s || !item) {
        return false;
    }
    return n00b_dict_contains(s, item);
}

/**
 * @brief Create a shallow copy (independent set with same contents).
 *        Replaces n00b_hashset_share / n00b_hashset_copy.
 */
static inline n00b_item_set_t *
n00b_item_set_copy(n00b_item_set_t *src)
{
    if (!src) {
        return n00b_item_set_new();
    }

    n00b_item_set_t *dst = n00b_item_set_new();

    n00b_dict_foreach(src, k, v, {
        n00b_dict_put(dst, k, v);
    });

    return dst;
}

/**
 * @brief Union: create a new set containing items from both a and b.
 *        Replaces n00b_hashset_union.
 */
static inline n00b_item_set_t *
n00b_item_set_union(n00b_item_set_t *a, n00b_item_set_t *b)
{
    n00b_item_set_t *result = n00b_item_set_copy(a);

    if (b) {
        n00b_dict_foreach(b, k, v, {
            n00b_dict_put(result, k, v);
        });
    }

    return result;
}

// ============================================================================
// Internal API (shared between earley.c and earley_tree.c)
// ============================================================================

void     n00b_earley_cleanup_intermediates(struct n00b_earley_parser_t *p);
uint64_t n00b_earley_item_hash(n00b_earley_item_t *ei);
uint64_t n00b_earley_bsr_hash(int32_t slot, int32_t left,
                                int32_t pivot, int32_t right);

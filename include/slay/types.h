#pragma once

/**
 * @file types.h
 * @brief Core type definitions for the slay parser system.
 *
 * Match item types, character classes, parse node structure,
 * forward declarations, callback signatures, and constants.
 */

#include "slay/token.h"

// ============================================================================
// Forward declarations
// ============================================================================

typedef int64_t                    n00b_nt_id_t;
typedef struct n00b_nonterm_t      n00b_nonterm_t;
typedef struct n00b_parse_rule_t   n00b_parse_rule_t;
typedef struct n00b_rule_group_t   n00b_rule_group_t;
typedef struct n00b_grammar_t      n00b_grammar_t;
typedef struct n00b_earley_item_t  n00b_earley_item_t;
typedef struct n00b_earley_state_t n00b_earley_state_t;
typedef struct n00b_annotation_t   n00b_annotation_t;
typedef struct n00b_scanner_t      n00b_scanner_t;

/** @brief Tokenizer callback function pointer (also defined in scanner.h). */
typedef bool (*n00b_scan_cb_t)(n00b_scanner_t *s);

/**
 * @brief Parse-backend selection. An immutable property of a grammar, fixed
 * at instantiation (see n00b_grammar_new's `parse_mode` kwarg); n00b_parse()
 * reads it from the grammar rather than taking a per-call argument.
 */
typedef enum {
    N00B_PARSE_MODE_UNSET = -1,   /**< Not specified (treated as DEFAULT). */
    N00B_PARSE_MODE_DEFAULT,      /**< PWZ fast path, Earley fallback. */
    N00B_PARSE_MODE_PWZ_ONLY,     /**< PWZ only, no Earley fallback. */
    N00B_PARSE_MODE_EARLEY_ONLY,  /**< Straight to Earley. */
} n00b_parse_mode_t;

// ============================================================================
// Constants
// ============================================================================

#define N00B_EMPTY_STRING         (-126)
#define N00B_GROUP_ID             (1 << 28)
#define N00B_DEFAULT_MAX_PENALTY  128
#define N00B_ERROR_NODE_ID        (-254)
#define N00B_GID_SHOW_GROUP_LHS  (-255)
#define N00B_IX_START_OF_PROGRAM (-1)

// ============================================================================
// Enums
// ============================================================================

/** @brief Discriminator for grammar match items. */
typedef enum {
    N00B_MATCH_EMPTY,    /**< Epsilon (empty) match. */
    N00B_MATCH_NT,       /**< Non-terminal reference. */
    N00B_MATCH_TERMINAL, /**< Terminal (token or codepoint) match. */
    N00B_MATCH_ANY,      /**< Wildcard: matches any single token. */
    N00B_MATCH_CLASS,    /**< Unicode character class. */
    N00B_MATCH_SET,      /**< Set of alternative match items. */
    N00B_MATCH_GROUP,    /**< Repetition group (?, *, +). */
} n00b_match_kind_t;

/** @brief Unicode character class identifiers. */
typedef enum {
    N00B_CC_ID_START,
    N00B_CC_ID_CONTINUE,
    N00B_CC_ASCII_DIGIT,
    N00B_CC_UNICODE_DIGIT,
    N00B_CC_ASCII_UPPER,
    N00B_CC_ASCII_LOWER,
    N00B_CC_ASCII_ALPHA,
    N00B_CC_WHITESPACE,
    N00B_CC_HEX_DIGIT,
    N00B_CC_NONZERO_DIGIT,
    N00B_CC_PRINTABLE,
    N00B_CC_NON_WS_PRINTABLE,
    N00B_CC_NON_NL_WS,
    N00B_CC_NON_NL_PRINTABLE,
    N00B_CC_JSON_STRING_CHAR,
    N00B_CC_REGEX_BODY_CHAR,
} n00b_char_class_t;

/** @brief Earley algorithm operation codes. */
typedef enum {
    N00B_EO_PREDICT_NT,
    N00B_EO_PREDICT_G,
    N00B_EO_FIRST_GROUP_ITEM,
    N00B_EO_SCAN_TOKEN,
    N00B_EO_SCAN_ANY,
    N00B_EO_SCAN_NULL,
    N00B_EO_SCAN_CLASS,
    N00B_EO_SCAN_SET,
    N00B_EO_COMPLETE_N,
    N00B_EO_ITEM_END,
} n00b_earley_op_t;

/** @brief Subtree boundary tags for parse forest extraction. */
typedef enum {
    N00B_SI_NONE             = 0,
    N00B_SI_NT_RULE_START    = 1,
    N00B_SI_NT_RULE_END      = 2,
    N00B_SI_GROUP_START      = 3,
    N00B_SI_GROUP_END        = 4,
    N00B_SI_GROUP_ITEM_START = 5,
    N00B_SI_GROUP_ITEM_END   = 6,
} n00b_subtree_info_t;

/** @brief Three-way comparison for Earley item cost. */
typedef enum {
    N00B_CMP_EQ = 0,
    N00B_CMP_LT = -1,
    N00B_CMP_GT = 1,
} n00b_earley_cmp_t;

// ============================================================================
// Match item
// ============================================================================

/** @brief A grammar match item (tagged union for rule RHS elements).
 *
 * WP-020 (D-039): the payload is split into TWO anonymous unions — a
 * pointer union (`set_items`/`group`) and a non-pointer union
 * (`nt_id`/`terminal_id`/`char_class`) — instead of one union overlapping
 * ints and pointers. ncc generates a precise GC pointer map per struct by
 * computing which fields are pointers (struct-layout offsets); a single
 * union overlapping an int and a pointer forces that word to be marked a
 * pointer unconditionally, so an int payload holding a pointer-shaped
 * value (e.g. `nt_id`/`terminal_id`, or a packed `{min,max}` like
 * `0x100000000`) is scanned as a pointer — which made `n00b_grammar_t`
 * unmarshalable. Splitting the union gives the pointer payload its own
 * dedicated word, so the generated map marks exactly that word and never
 * the int payloads. Field names are unchanged (kind-dispatched access and
 * designated-initializer construction both work regardless of declaration
 * order); the unused union is zero-filled by designated init.
 */
typedef struct n00b_match_t {
    union [[n00b::raw_union]] {
        void *set_items;
        void *group;
    };
    n00b_match_kind_t kind;
    // Non-pointer payloads (NT / TERMINAL / CLASS). Never a pointer.
    union [[n00b::raw_union]] {
        int64_t           nt_id;
        int64_t           terminal_id;
        n00b_char_class_t char_class;
    };
} n00b_match_t;

// ============================================================================
// Non-terminal node (interior parse tree node)
// ============================================================================

typedef struct n00b_scope_t n00b_scope_t;

/** @brief Contents of an interior (non-terminal) parse tree node. */
typedef struct n00b_nt_node_t {
    n00b_string_t  *name;
    n00b_scope_t   *scope;  /**< Scope opened by this node (if @scope annotation fired). */
    int64_t         noscan;
    int64_t         id;
    int64_t         hv;
    int32_t         start;
    int32_t         end;
    int32_t         rule_index;
    uint32_t        penalty;
    uint32_t        cost;
    uint16_t        penalty_location;
    bool            group_item;
    bool            group_top;
    bool            missing;
    bool            bad_prefix;
} n00b_nt_node_t;

// ============================================================================
// Callbacks
// ============================================================================

/** @brief Walk action callback invoked for each NT during tree walk. */
typedef void *(*n00b_walk_action_t)(n00b_nt_node_t *node,
                                     void *children,
                                     void *thunk);

/** @brief Tree walker callback. */
typedef bool (*n00b_tree_walker_fn)(void *node, int32_t depth, void *thunk);

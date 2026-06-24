#pragma once

/**
 * @file transform.h
 * @brief Tree transform framework: registry, pre/post-order transforms,
 *        tree mutation, node construction, and pattern search.
 *
 * Provides the infrastructure for semantic tree
 * transforms. Transforms are registered by NT name or id, then
 * applied in one or more passes over a parse tree.
 *
 * ### Usage
 *
 * ```c
 * n00b_xform_registry_t reg;
 * n00b_xform_registry_init(&reg, grammar);
 * n00b_xform_register(&reg, "function_definition", my_xform, "my_xform");
 *
 * n00b_xform_ctx_t ctx;
 * n00b_xform_ctx_init(&ctx, grammar, &reg, tree);
 * tree = n00b_xform_apply(&reg, &ctx);
 *
 * n00b_xform_registry_free(&reg);
 * ```
 */

#include "slay/parse_tree.h"
#include "parsers/scanner.h"
#include "adt/result.h"

// ============================================================================
// Forward declarations
// ============================================================================

typedef struct n00b_xform_registry_t n00b_xform_registry_t;
typedef struct n00b_xform_ctx_t      n00b_xform_ctx_t;

// ============================================================================
// Control types
// ============================================================================

/** @brief Control value returned by pre-order transforms. */
typedef enum {
    N00B_XFORM_CONTINUE,      /**< Continue walking child nodes. */
    N00B_XFORM_SKIP_CHILDREN, /**< Skip child traversal for this node. */
} n00b_xform_control_t;

// ============================================================================
// Transform function signatures
// ============================================================================

/**
 * @brief Post-order transform: called after children are processed.
 * @param ctx   Transform context.
 * @param node  Current tree node.
 * @return Replacement node, or NULL for no change.
 */
typedef n00b_parse_tree_t *(*n00b_xform_fn_t)(n00b_xform_ctx_t *ctx, n00b_parse_tree_t *node);

/**
 * @brief Pre-order transform: called before children are processed.
 * @param ctx      Transform context.
 * @param node     Current tree node.
 * @param control  Output: set to SKIP_CHILDREN to skip child walk.
 * @return Replacement node, or NULL for no change.
 */
typedef n00b_parse_tree_t *(*n00b_xform_pre_fn_t)(n00b_xform_ctx_t     *ctx,
                                                  n00b_parse_tree_t    *node,
                                                  n00b_xform_control_t *control);

// ============================================================================
// Transform entry (one registered transform)
// ============================================================================

/** @brief A single registered transform (pre-order or post-order). */
typedef struct {
    union [[n00b::raw_union]] {
        n00b_xform_fn_t     post_fn; /**< Post-order function. */
        n00b_xform_pre_fn_t pre_fn;  /**< Pre-order function. */
    };
    const char *name;                /**< Human-readable name for debugging. */
    bool        is_pre;              /**< True if pre-order. */
} n00b_xform_entry_t;

// ============================================================================
// Registry
// ============================================================================

/** @brief Maximum number of NT slots for direct-indexed dispatch. */
#define N00B_XFORM_MAX_DIRECT_NTS 512

/** @brief Registry of tree transforms indexed by non-terminal. */
struct n00b_xform_registry_t {
    n00b_xform_entry_t **pre_order[N00B_XFORM_MAX_DIRECT_NTS];
    int                  pre_count[N00B_XFORM_MAX_DIRECT_NTS];
    int                  pre_cap[N00B_XFORM_MAX_DIRECT_NTS];

    n00b_xform_entry_t **post_order[N00B_XFORM_MAX_DIRECT_NTS];
    int                  post_count[N00B_XFORM_MAX_DIRECT_NTS];
    int                  post_cap[N00B_XFORM_MAX_DIRECT_NTS];

    n00b_xform_entry_t **wildcard_pre;
    int                  wildcard_pre_count;
    int                  wildcard_pre_cap;

    n00b_xform_entry_t **wildcard_post;
    int                  wildcard_post_count;
    int                  wildcard_post_cap;

    n00b_grammar_t *grammar;
};

// ============================================================================
// Transform context
// ============================================================================

/** @brief Mutable context threaded through a transform pass. */
struct n00b_xform_ctx_t {
    n00b_grammar_t        *grammar;
    n00b_xform_registry_t *registry;
    n00b_parse_tree_t     *root;
    int                    depth;
    int                    pass;
    int                    nodes_visited;
    int                    nodes_replaced;
    void                  *user_data;
};

// ============================================================================
// Registry API
// ============================================================================

/**
 * @brief Initialize a transform registry.
 * @param reg      Registry to initialize.
 * @param grammar  Grammar for NT name resolution.
 */
void n00b_xform_registry_init(n00b_xform_registry_t *reg, n00b_grammar_t *grammar);

/** @brief Free all resources held by a registry. */
void n00b_xform_registry_free(n00b_xform_registry_t *reg);

/**
 * @brief Register a post-order transform for a non-terminal.
 *
 * Pass @p nt_name = NULL to register a wildcard that matches all nodes.
 *
 * @return True on success, false if the NT name was not found.
 */
bool n00b_xform_register(n00b_xform_registry_t *reg,
                         const char            *nt_name,
                         n00b_xform_fn_t        fn,
                         const char            *name);

/**
 * @brief Register a pre-order transform for a non-terminal.
 *
 * Pass @p nt_name = NULL for a wildcard.
 */
bool n00b_xform_register_pre(n00b_xform_registry_t *reg,
                             const char            *nt_name,
                             n00b_xform_pre_fn_t    fn,
                             const char            *name);

/** @brief Register a post-order transform by NT id. */
bool n00b_xform_register_by_id(n00b_xform_registry_t *reg,
                               int64_t                nt_id,
                               n00b_xform_fn_t        fn,
                               const char            *name);

/** @brief Register a pre-order transform by NT id. */
bool n00b_xform_register_pre_by_id(n00b_xform_registry_t *reg,
                                   int64_t                nt_id,
                                   n00b_xform_pre_fn_t    fn,
                                   const char            *name);

// ============================================================================
// Context API
// ============================================================================

/**
 * @brief Initialize a transform context.
 * @param ctx      Context to initialize.
 * @param grammar  Grammar for NT lookups.
 * @param reg      Transform registry.
 * @param root     Root tree node.
 */
void n00b_xform_ctx_init(n00b_xform_ctx_t      *ctx,
                         n00b_grammar_t        *grammar,
                         n00b_xform_registry_t *reg,
                         n00b_parse_tree_t     *root);

// ============================================================================
// Transform application
// ============================================================================

/**
 * @brief Apply one pass of transforms over the tree.
 * @return Transformed root tree (may differ from original).
 */
n00b_parse_tree_t *n00b_xform_apply(n00b_xform_registry_t *reg, n00b_xform_ctx_t *ctx);

/**
 * @brief Apply transforms in multiple passes until fixpoint or limit.
 * @param max_passes  Maximum number of passes (0 defaults to 100).
 * @return Transformed root tree.
 */
n00b_parse_tree_t *
n00b_xform_apply_multi(n00b_xform_registry_t *reg, n00b_xform_ctx_t *ctx, int max_passes);

// ============================================================================
// Tree mutation primitives
// ============================================================================

/**
 * @brief Replace child at index.
 * @return True on success, false if index out of range.
 */
bool
n00b_xform_set_child(n00b_parse_tree_t *parent, size_t index, n00b_parse_tree_t *new_child);

/**
 * @brief Remove child at index, compacting the array.
 * @return The removed child, or NULL if out of range.
 */
n00b_parse_tree_t *n00b_xform_remove_child(n00b_parse_tree_t *parent, size_t index);

/**
 * @brief Insert a child at index, shifting others right.
 * @return True on success, false if out of range.
 */
bool n00b_xform_insert_child(n00b_parse_tree_t *parent, size_t index, n00b_parse_tree_t *child);

/**
 * @brief Deep-copy a subtree.
 * @return A new independent copy.
 */
n00b_parse_tree_t *n00b_xform_clone(n00b_parse_tree_t *tree);

// ============================================================================
// Node construction helpers
// ============================================================================

/**
 * @brief Create a non-terminal node with no children.
 * @param grammar     Grammar for NT id resolution.
 * @param nt_name     Non-terminal name (borrowed, copied into n00b_string_t).
 * @param rule_index  Index of the production rule.
 */
n00b_parse_tree_t *
n00b_xform_make_nt_node(n00b_grammar_t *grammar, const char *nt_name, int32_t rule_index);

/**
 * @brief Create a terminal/token leaf node.
 * @param tid    Terminal ID.
 * @param value  Token text (copied into GC-managed string).
 * @param line   Source line number.
 * @param col    Source column number.
 */
n00b_parse_tree_t *
n00b_xform_make_token_node(int64_t tid, const char *value, uint32_t line, uint32_t col);

/**
 * @brief Create a non-terminal with pre-populated children.
 * @param grammar     Grammar for NT id resolution.
 * @param nt_name     Non-terminal name.
 * @param rule_index  Rule index.
 * @param children    Array of child tree nodes.
 * @param count       Number of children.
 */
n00b_parse_tree_t *n00b_xform_make_node_with_children(n00b_grammar_t     *grammar,
                                                      const char         *nt_name,
                                                      int32_t             rule_index,
                                                      n00b_parse_tree_t **children,
                                                      size_t              count);

// ============================================================================
// Template-based subtree construction
// ============================================================================

/** @brief Error: no tokenizer callback available (not passed and none stored). */
#define N00B_XFORM_ERR_NO_TOKENIZER 1
/** @brief Error: @p nt_name does not name a non-terminal in the grammar. */
#define N00B_XFORM_ERR_UNKNOWN_NT   2
/** @brief Error: tokenization or parsing of the source string failed. */
#define N00B_XFORM_ERR_PARSE_FAILED 3

/**
 * @brief Parse a source string into a subtree using a specific start symbol.
 *
 * Tokenizes @p source and parses the token stream against @p grammar
 * starting from the non-terminal named @p nt_name.
 *
 * The tokenizer callback is stored in the grammar on first use. Pass
 * `.tokenize` to override it; otherwise the previously stored callback
 * is reused.
 *
 * The grammar's default start symbol is temporarily overridden for
 * the parse and restored afterward (not thread-safe).
 *
 * @param grammar  Grammar to parse with (must be finalized).
 * @param nt_name  Non-terminal to use as start symbol.
 * @param source   Null-terminated source text to parse.
 * @return Ok with cloned parse tree rooted at @p nt_name, or err on failure.
 *
 * @kw tokenize  Tokenizer callback (e.g., `n00b_c_tokenize`). Stored in
 *               grammar on first call; subsequent calls reuse it unless
 *               a new one is provided.
 */
n00b_result_t(n00b_parse_tree_t *) n00b_xform_parse_template(n00b_grammar_t *grammar,
                                                             const char     *nt_name,
                                                             const char     *source) _kargs
{
    n00b_scan_cb_t tokenize;
};

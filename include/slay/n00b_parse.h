#pragma once

/**
 * @file n00b_parse.h
 * @brief Backend-independent parse API for the slay parser system.
 *
 * Provides a unified entry point (`n00b_parse`) that dispatches to
 * PWZ (fast path) or Earley (general fallback), with rich result
 * objects carrying trees, error diagnostics, repair information,
 * and ambiguity data.
 */

#include "slay/parse_forest.h"
#include "slay/parse_tree.h"

// ============================================================================
// Forward declarations
// ============================================================================

typedef struct n00b_pwz_parser_t    n00b_pwz_parser_t;
typedef struct n00b_earley_parser_t n00b_earley_parser_t;

// `n00b_parse_mode_t` is defined in slay/types.h (it is an immutable
// property of a grammar, set at n00b_grammar_new time).

// ============================================================================
// Repair diagnostics
// ============================================================================

/** @brief Kind of error repair applied during parsing. */
typedef enum {
    N00B_REPAIR_INSERTED, /**< A missing token was inserted. */
    N00B_REPAIR_DELETED,  /**< Junk tokens were skipped. */
} n00b_repair_kind_t;

/** @brief One repair action applied during error recovery. */
typedef struct {
    n00b_repair_kind_t kind;
    int32_t            position;     /**< Token index where repair occurred. */
    uint32_t           line;         /**< Source line of repair. */
    uint32_t           column;       /**< Source column of repair. */
    n00b_string_t     *description;  /**< Human-readable repair description. */
    int64_t            terminal_id;  /**< Terminal involved in the repair. */
} n00b_repair_t;

// ============================================================================
// Error location
// ============================================================================

/** @brief Location where parsing failed. */
typedef struct {
    int32_t       position; /**< Token index where parsing stopped. */
    uint32_t      line;     /**< Source line of failure. */
    uint32_t      column;   /**< Source column of failure. */
    n00b_string_t *got;      /**< Text of the unexpected token. */
    int64_t       got_id;   /**< Terminal ID of the unexpected token. */
} n00b_error_location_t;

// ============================================================================
// Ambiguity info
// ============================================================================

/** @brief One point of ambiguity in the parse result. */
typedef struct {
    n00b_string_t      *nt_name;      /**< Non-terminal where ambiguity occurs. */
    int32_t             start_pos;    /**< Start token position. */
    int32_t             end_pos;      /**< End token position. */
    int32_t             alt_count;    /**< Number of alternative subtrees. */
    n00b_parse_tree_t **alternatives; /**< The alternative subtrees. */
} n00b_ambiguity_t;

// ============================================================================
// Parse options
// ============================================================================

/** @brief Options controlling parse behavior (currently reserved for future use). */
typedef struct {
    void *_reserved;  /**< Reserved for future use. */
} n00b_parse_opts_t;

// ============================================================================
// Opaque result handle
// ============================================================================

typedef struct n00b_parse_result_t n00b_parse_result_t;

// ============================================================================
// Earley diagnostics (extracted without exposing internals)
// ============================================================================

/** @brief Diagnostic information extracted from the Earley chart. */
typedef struct {
    int64_t              *expected_ids;    /**< Terminal IDs expected at failure. */
    n00b_string_t       **expected_desc;   /**< Human-readable descriptions (parallel to expected_ids). */
    int32_t               expected_count;  /**< Number of expected terminals/descriptions. */
    n00b_string_t       **active_ctx;      /**< Active NT context names. */
    int32_t               active_ctx_count;
    n00b_error_location_t error_loc;       /**< Error location. */
} n00b_earley_diagnostics_t;

// ============================================================================
// Parse entry point
// ============================================================================

/**
 * @brief Parse a token stream against a grammar.
 *
 * Dispatches to PWZ (fast path) and/or Earley according to the grammar's
 * own immutable `parse_mode` (set at n00b_grammar_new time) — there is no
 * per-call mode argument. With `N00B_PARSE_MODE_DEFAULT` (or UNSET), tries
 * PWZ first and falls back to Earley if PWZ fails.
 *
 * @param g     Grammar to parse with (carries the backend selection).
 * @param ts    Token stream to consume.
 * @param opts  Parse options (callbacks, etc.).
 * @return Opaque result handle (caller must free via n00b_parse_result_free).
 */
n00b_parse_result_t *n00b_parse(n00b_grammar_t      *g,
                                 n00b_token_stream_t *ts,
                                 n00b_parse_opts_t    opts);

/**
 * @brief Convenience macro using designated initializers for opts.
 *
 * Example:
 * ```c
 * n00b_parse_result_t *r = n00b_grammar_parse(g, ts);
 * ```
 */
#define n00b_grammar_parse(g, ts, ...) \
    n00b_parse((g), (ts), (n00b_parse_opts_t){__VA_ARGS__})

// ============================================================================
// Outcome queries
// ============================================================================

/** @brief True if parsing succeeded (at least one tree). */
bool    n00b_parse_result_ok(n00b_parse_result_t *r);

/** @brief True if the parse produced multiple trees. */
bool    n00b_parse_result_ambiguous(n00b_parse_result_t *r);

/** @brief True if error recovery was applied. */
bool    n00b_parse_result_repaired(n00b_parse_result_t *r);

/** @brief Number of parse trees in the result. */
int32_t n00b_parse_result_tree_count(n00b_parse_result_t *r);

// ============================================================================
// Tree access
// ============================================================================

/** @brief Get the best (first) parse tree. */
n00b_parse_tree_t  *n00b_parse_result_tree(n00b_parse_result_t *r);

/** @brief Get the array of all parse trees. */
n00b_parse_tree_t **n00b_parse_result_trees(n00b_parse_result_t *r);

// ============================================================================
// Walk
// ============================================================================

/**
 * @brief Walk a parse tree using grammar-registered actions.
 *
 * @param r      Parse result.
 * @param tree   Specific tree to walk (or NULL for best tree).
 * @param thunk  User context.
 * @return Result from root action.
 */
void *n00b_parse_result_walk(n00b_parse_result_t *r,
                              n00b_parse_tree_t   *tree,
                              void                *thunk);

// ============================================================================
// Error diagnostics
// ============================================================================

/** @brief Get the location where parsing failed. */
n00b_error_location_t n00b_parse_result_error_location(n00b_parse_result_t *r);

/**
 * @brief Get the terminal IDs expected at the point of failure.
 *
 * @param r        Parse result.
 * @param out      Output array.
 * @param max_out  Maximum entries to write.
 * @return Number of entries written (may be less than total expected).
 */
int32_t n00b_parse_result_expected_tokens(n00b_parse_result_t *r,
                                           int64_t *out, int32_t max_out);

/** @brief Get a human-readable string of expected tokens. */
n00b_string_t *n00b_parse_result_expected_string(n00b_parse_result_t *r);

/** @brief Get a full human-readable error message. */
n00b_string_t *n00b_parse_result_error_string(n00b_parse_result_t *r);

// ============================================================================
// Repair diagnostics
// ============================================================================

/** @brief Number of repairs applied. */
int32_t        n00b_parse_result_repair_count(n00b_parse_result_t *r);

/** @brief Get the array of repairs (length from repair_count). */
n00b_repair_t *n00b_parse_result_repairs(n00b_parse_result_t *r);

// ============================================================================
// Ambiguity diagnostics
// ============================================================================

/**
 * @brief Extract ambiguity information.
 *
 * @param r        Parse result.
 * @param out      Output array.
 * @param max_out  Maximum entries to write.
 * @return Number of ambiguities written.
 */
int32_t n00b_parse_result_ambiguities(n00b_parse_result_t *r,
                                       n00b_ambiguity_t *out,
                                       int32_t max_out);

// ============================================================================
// Grammar accessor
// ============================================================================

/** @brief Get the grammar used for parsing. */
n00b_grammar_t *n00b_parse_result_grammar(n00b_parse_result_t *r);

// ============================================================================
// Cleanup
// ============================================================================

/** @brief Free a parse result and all associated state. */
void n00b_parse_result_free(n00b_parse_result_t *r);

// ============================================================================
// Earley diagnostic extraction (internal helper)
// ============================================================================

/**
 * @brief Extract error diagnostics from an Earley parser's chart.
 *
 * Walks backward through the Earley chart to find the furthest
 * position with scan-ready items, then extracts expected terminal
 * IDs and active context.
 *
 * @param p    Earley parser (must have completed a parse attempt).
 * @param out  Output diagnostics struct.
 */
void n00b_earley_extract_diagnostics(n00b_earley_parser_t      *p,
                                      n00b_earley_diagnostics_t *out);

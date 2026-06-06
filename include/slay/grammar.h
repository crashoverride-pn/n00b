#pragma once

/**
 * @file grammar.h
 * @brief Grammar construction, match macros, and rule building.
 */

#include "slay/annotation.h"
#include "slay/parse_tree.h"

// ============================================================================
// Grammar lifecycle
// ============================================================================

// Backend selection and error-recovery are IMMUTABLE instantiation
// properties of a grammar. `parse_mode` is read by n00b_parse() (there is
// no per-call mode arg). `error_recovery` controls whether the Earley-only
// error-recovery rules are built at finalize; it is FORCED off when
// parse_mode == N00B_PARSE_MODE_PWZ_ONLY (those rules are never consumed by
// PWZ). Neither can be changed after the grammar exists.
n00b_grammar_t *n00b_grammar_new() _kargs {
    n00b_parse_mode_t parse_mode     = N00B_PARSE_MODE_DEFAULT;
    bool              error_recovery = true;
};
void            n00b_grammar_free(n00b_grammar_t *g);
void            n00b_grammar_set_start_id(n00b_grammar_t *g, n00b_nt_id_t nt_id);

#define n00b_grammar_set_start(g, nt) \
    n00b_grammar_set_start_id((g), n00b_nonterm_id(nt))
void            n00b_grammar_set_max_penalty(n00b_grammar_t *g, uint32_t max);
/**
 * @brief Finalize a grammar: distribute annotations, compute nullability,
 *        build the valid-token set, and compute first-sets / left-corners.
 *
 * Idempotent: a grammar that is already finalized returns immediately.
 *
 * First-sets and left-corners ARE computed here because PWZ uses them to
 * prune. The Earley-only LR0 tables (items / states / predict states) are
 * NOT — they are expensive and useless to PWZ, so they are computed lazily
 * by `n00b_grammar_compute_earley_analysis()` the first time Earley is
 * invoked (`n00b_earley_new`). PWZ-only consumers never pay for the LR0
 * construction.
 *
 * @param g  The grammar to finalize.
 */
void            n00b_grammar_finalize(n00b_grammar_t *g);

/**
 * @brief Compute the Earley-only LR0 tables (items / states / predict
 *        states).
 *
 * Called by `n00b_earley_new` the first time Earley parses a grammar.
 * Idempotent and independent of finalize state; the grammar must already
 * be finalized (the Earley constructor guarantees this — the LR0 build
 * relies on the first-sets finalize computes). PWZ never calls it, so
 * PWZ-only workflows (naudit, the eval JIT, baked grammars) skip the cost.
 */
void            n00b_grammar_compute_earley_analysis(n00b_grammar_t *g);

// ============================================================================
// Registration
// ============================================================================

n00b_nonterm_t *n00b_nonterm(n00b_grammar_t *g, n00b_string_t *name);
int64_t         n00b_nonterm_id(n00b_nonterm_t *nt);
int64_t         n00b_register_terminal(n00b_grammar_t *g, n00b_string_t *name);

/**
 * @brief Register a named literal type (e.g. "IDENTIFIER", "INTEGER").
 *
 * Returns a small sequential ID (starting at 0) for the type name.
 * If the name is already registered, returns the existing ID.
 * These IDs are used by tokenizers via `n00b_scan_emit(.token_type = ...)`.
 */
int64_t         n00b_register_literal_type(n00b_grammar_t *g, n00b_string_t *name);

/**
 * @brief Look up a terminal ID by name.
 *
 * @return The terminal ID, or 0 if not found.
 */
int64_t         n00b_grammar_terminal_id(n00b_grammar_t *g, n00b_string_t *name);

/**
 * @brief Check if a string is a registered terminal/keyword in the grammar.
 *
 * Looks up @p text in the grammar's terminal map. This replaces hardcoded
 * keyword tables in analysis passes — any registered terminal (keywords,
 * operators, etc.) is not a variable reference.
 *
 * @param g     Grammar.
 * @param text  Text to check.
 * @return True if @p text matches a registered terminal name.
 */
bool            n00b_grammar_is_keyword(n00b_grammar_t *g, n00b_string_t *text);

// ============================================================================
// Walk actions / user data
// ============================================================================

void  n00b_nonterm_set_action(n00b_nonterm_t *nt, n00b_walk_action_t action);
void  n00b_nonterm_set_user_data(n00b_nonterm_t *nt, void *data);
void *n00b_nonterm_get_user_data(n00b_nonterm_t *nt);
void  n00b_grammar_set_default_action(n00b_grammar_t *g, n00b_walk_action_t a);
void  n00b_grammar_set_terminal_category(n00b_grammar_t *g, int64_t tid,
                                          n00b_string_t *category);

/**
 * @brief Set a custom disambiguator for the grammar.
 *
 * When the parser produces multiple trees with equal penalty/cost, the
 * disambiguator is called to choose between them. Pass NULL to restore
 * the default structural disambiguator.
 */
void  n00b_grammar_set_disambiguator(n00b_grammar_t         *g,
                                       n00b_tree_disambig_fn_t fn);

// ============================================================================
// Match macros
// ============================================================================

#define N00B_NT(nt)       ((n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = n00b_nonterm_id(nt)})
#define N00B_CHAR(cp)     ((n00b_match_t){.kind = N00B_MATCH_TERMINAL, .terminal_id = (int64_t)(cp)})
#define N00B_TERMINAL(id) ((n00b_match_t){.kind = N00B_MATCH_TERMINAL, .terminal_id = (id)})
#define N00B_ANY()        ((n00b_match_t){.kind = N00B_MATCH_ANY})
#define N00B_EPSILON()    ((n00b_match_t){.kind = N00B_MATCH_EMPTY})
#define N00B_CLASS(cc)    ((n00b_match_t){.kind = N00B_MATCH_CLASS, .char_class = (cc)})

// ============================================================================
// Group constructors (variadic via compound literal)
// ============================================================================

n00b_match_t n00b_group_match_v(n00b_grammar_t *g, int min, int max,
                                 int n, n00b_match_t *items);

#define n00b_optional(g, ...)                                                  \
    n00b_group_match_v((g), 0, 1,                                              \
        sizeof((n00b_match_t[]){__VA_ARGS__}) / sizeof(n00b_match_t),           \
        (n00b_match_t[]){__VA_ARGS__})

#define n00b_star(g, ...)                                                      \
    n00b_group_match_v((g), 0, 0,                                              \
        sizeof((n00b_match_t[]){__VA_ARGS__}) / sizeof(n00b_match_t),           \
        (n00b_match_t[]){__VA_ARGS__})

#define n00b_plus_group(g, ...)                                                \
    n00b_group_match_v((g), 1, 0,                                              \
        sizeof((n00b_match_t[]){__VA_ARGS__}) / sizeof(n00b_match_t),           \
        (n00b_match_t[]){__VA_ARGS__})

#define n00b_repeat(g, min, max, ...)                                          \
    n00b_group_match_v((g), (min), (max),                                      \
        sizeof((n00b_match_t[]){__VA_ARGS__}) / sizeof(n00b_match_t),           \
        (n00b_match_t[]){__VA_ARGS__})

// ============================================================================
// Rule building (variadic via compound literal)
// ============================================================================

n00b_parse_rule_t *n00b_add_rule_v(n00b_grammar_t *g, n00b_nt_id_t nt_id,
                                    int n, n00b_match_t *items);
n00b_parse_rule_t *n00b_add_rule_with_cost_v(n00b_grammar_t *g,
                                              n00b_nt_id_t nt_id,
                                              int cost,
                                              int n, n00b_match_t *items);

#define n00b_add_rule(g, nt, ...)                                              \
    n00b_add_rule_v((g), n00b_nonterm_id(nt),                                  \
        sizeof((n00b_match_t[]){__VA_ARGS__}) / sizeof(n00b_match_t),           \
        (n00b_match_t[]){__VA_ARGS__})

#define n00b_add_rule_with_cost(g, nt, cost, ...)                              \
    n00b_add_rule_with_cost_v((g), n00b_nonterm_id(nt), (cost),                \
        sizeof((n00b_match_t[]){__VA_ARGS__}) / sizeof(n00b_match_t),           \
        (n00b_match_t[]){__VA_ARGS__})

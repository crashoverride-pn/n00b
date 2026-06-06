#pragma once

/**
 * @file grammar_internal.h
 * @internal
 * @brief Internal struct definitions for the slay grammar system.
 */

#include "slay/grammar.h"
#include "slay/parse_tree.h"
#include "adt/list.h"
#include "adt/dict.h"

// ============================================================================
// Internal structures
// ============================================================================

struct n00b_nonterm_t {
    n00b_string_t                   *name;
    n00b_list_t(int32_t)             rule_ids;
    n00b_list_t(n00b_annotation_t *) pending_annotations;
    n00b_walk_action_t               action;
    void                            *user_data;
    n00b_dict_t(int64_t, bool)      *first_set;
    int64_t                          id;
    bool                             group_nt;
    bool                             empty_is_error;
    bool                             error_nulled;
    bool                             start_nt;
    bool                             finalized;
    bool                             nullable;
    bool                             no_error_rule;
    bool                             first_has_any;
};

struct n00b_parse_rule_t {
    n00b_nt_id_t                          nt_id;
    n00b_list_t(n00b_match_t)             contents;
    n00b_list_t(n00b_annotation_t *)      annotations;
    n00b_dict_t(int64_t, bool)           *first_set;
    int32_t                               cost;
    int32_t                               link_ix;
    n00b_string_t                        *doc;
    bool                                  penalty_rule;
    bool                                  first_has_any;
    void                                 *thunk;
    /**
     * @internal
     * Sidecar: rewrite-block metadata (`n00b_rewrite_info_t *` from
     * `src/slay/rewrite.c`), or nullptr if this production has no
     * rewrite. Storage decision DF-L: sidecar-by-pointer keeps the
     * core struct flat and zero-cost for rules without rewrites.
     */
    void                                 *rewrite;
    /**
     * @internal
     * Sidecar: capture-name table (`n00b_capture_table_t *` from
     * `src/slay/rewrite.c`), or nullptr if this production declares
     * no `$name:<nt>` captures.
     */
    void                                 *captures;
};

struct n00b_rule_group_t {
    int64_t contents_id;
    int32_t min;
    int32_t max;
    int32_t gid;
};

// ============================================================================
// LR(0) types
// ============================================================================

typedef struct {
    int32_t rule_ix;
    int16_t dot;
    int16_t rule_len;
} n00b_lr0_item_t;

typedef struct {
    int32_t items_start;
    int32_t items_count;
    int32_t gotos_start;
    int32_t gotos_count;
} n00b_lr0_state_t;

typedef struct {
    int64_t symbol;
    int32_t dest_state;
} n00b_lr0_goto_t;

// ============================================================================
// Grammar struct
// ============================================================================

struct n00b_grammar_t {
    n00b_list_t(n00b_parse_rule_t) rules;
    n00b_list_t(n00b_nonterm_t)    nt_list;
    n00b_dict_t(n00b_string_t *, int64_t)  *nt_map;
    n00b_dict_t(n00b_string_t *, int64_t)  *terminal_map;

    /** Maps literal type name (e.g. "IDENTIFIER") → sequential int64_t ID. */
    n00b_dict_t(n00b_string_t *, int64_t)  *literal_type_map;
    /** Set of all valid token IDs (both hashed and sequential). Built at finalize. */
    n00b_dict_t(int64_t, bool)             *valid_tokens;
    /** Reverse lookup: hashed/sequential ID → name string pointer. */
    n00b_dict_t(int64_t, n00b_string_t *)  *terminal_by_id;
    /** Counter for the next literal type sequential ID (starts at 0). */
    int64_t                        next_literal_type_id;

    int32_t                        default_start;
    uint32_t                       max_penalty;
    // Immutable backend selection, fixed at n00b_grammar_new. n00b_parse()
    // reads this instead of taking a per-call mode argument.
    n00b_parse_mode_t              parse_mode;
    bool                           error_rules;
    bool                           finalized;
    // Earley-only LR0 tables (items/states/predict) are computed lazily
    // by n00b_grammar_compute_earley_analysis() the first time Earley is
    // invoked on this grammar (never by n00b_grammar_finalize, which does
    // compute the first-sets/left-corners PWZ prunes with). This guards
    // that one-time LR0 computation.
    //
    // FOOTGUN: this flag is independent of `finalized` and is NOT reset on
    // grammar mutation. Grammars here are build-then-freeze, so it never
    // matters today; but any future path that mutates a grammar after the
    // LR0 tables exist MUST clear this (and re-run the analysis) or Earley
    // will use stale tables.
    bool                           earley_analysis_done;
    bool                           has_groups;
    bool                           hide_penalty_rewrites;
    bool                           hide_groups;
    int                            suspend_penalty_hiding;
    bool                           suspend_group_hiding;
    n00b_string_t                 *tokenizer_name;
    n00b_scan_cb_t                 tokenize_cb;
    n00b_walk_action_t             default_action;
    n00b_tree_disambig_fn_t        disambiguator;

    uint64_t *left_corner_sets;
    int32_t   lc_words_per_nt;

    n00b_lr0_item_t  *lr0_items;
    int32_t           lr0_item_count;
    int32_t          *lr0_rule_item_base;
    n00b_lr0_state_t *lr0_states;
    int32_t           lr0_state_count;
    int32_t          *lr0_state_items;
    int32_t           lr0_state_items_total;
    n00b_lr0_goto_t  *lr0_gotos;
    int32_t           lr0_goto_count;
    int32_t           lr0_start_state;
    int32_t          *lr0_predict_state;

    n00b_dict_t(int64_t, n00b_string_t *)  *terminal_categories;
    bool                      has_terminal_categories;
};

// ============================================================================
// Inline helpers
// ============================================================================

static inline n00b_nonterm_t *
n00b_get_nonterm(n00b_grammar_t *g, int64_t id)
{
    if (id < 0 || (size_t)id >= n00b_list_len(g->nt_list)) {
        return NULL;
    }
    return &g->nt_list.data[id];
}

static inline n00b_string_t *
n00b_get_terminal_name(n00b_grammar_t *g, int64_t id)
{
    if (!g->terminal_by_id) {
        return NULL;
    }

    bool           found = false;
    n00b_string_t *val   = n00b_dict_get(g->terminal_by_id, id, &found);

    if (!found) {
        return NULL;
    }

    return val;
}

static inline n00b_parse_rule_t *
n00b_get_rule(n00b_grammar_t *g, int32_t ix)
{
    if (ix < 0 || (size_t)ix >= n00b_list_len(g->rules)) {
        return NULL;
    }
    return &g->rules.data[ix];
}

static inline bool
n00b_is_non_terminal(n00b_match_t *m)
{
    return m->kind == N00B_MATCH_NT || m->kind == N00B_MATCH_GROUP;
}

/**
 * @brief Look up the rule for a parse tree node.
 *
 * Parse tree nodes store a **local** rule index (position within the NT's
 * `rule_ids` list).  This helper converts to the global index and returns
 * the `n00b_parse_rule_t *`, or NULL if anything is out of range.
 */
static inline n00b_parse_rule_t *
n00b_get_node_rule(n00b_grammar_t *g, n00b_nt_node_t *pn)
{
    n00b_nonterm_t *nt = n00b_get_nonterm(g, pn->id);

    if (!nt
            || pn->rule_index < 0
            || (size_t)pn->rule_index >= n00b_list_len(nt->rule_ids)) {
        return NULL;
    }

    int32_t global_ix = n00b_list_get(nt->rule_ids, pn->rule_index);

    return n00b_get_rule(g, global_ix);
}

static inline bool
n00b_hide_groups(n00b_grammar_t *g)
{
    return g->hide_groups && !g->suspend_group_hiding;
}

static inline bool
n00b_hide_penalties(n00b_grammar_t *g)
{
    return g->hide_penalty_rewrites && !g->suspend_penalty_hiding;
}

static inline n00b_tree_disambig_fn_t
n00b_get_disambiguator(n00b_grammar_t *g)
{
    return g->disambiguator ? g->disambiguator
                            : n00b_parse_tree_default_disambig;
}

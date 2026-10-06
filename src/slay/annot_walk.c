// annot_walk.c - Post-parse DFS annotation walk (slim dispatcher).
//
// Walks the parse tree depth-first. For each non-terminal node, checks
// the grammar for annotations and dispatches to phase handlers:
//
//   Phase 1: scope open       (annot_scope.c)
//   Phase 2-3: symbol reg     (annot_symtab.c) — two-pass for ordering fix
//   Phase 4: CF labels        (annot_cf.c)
//   Phase 5: child recursion  (here)
//   Phase 6: post-order types (annot_types.c)
//   Phase 7: scope close      (annot_scope.c)

#include "internal/slay/annot_phases.h"
#include "slay/n00b_parse.h"
#include "slay/diagnostic.h"

// ============================================================================
// DFS walk
// ============================================================================

static void
walk_node(n00b_annot_walk_ctx_t *ctx, n00b_parse_tree_t *node)
{
    if (!node) {
        return;
    }

    // Terminals (leaves) have no annotations.
    if (n00b_tree_is_leaf(node)) {
        return;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    // Empty-string nodes and negative IDs have no annotations.
    if (pn->id == N00B_EMPTY_STRING || pn->id < 0) {
        return;
    }

    // Group wrapper nodes are internal BNF artifacts (from ?, *, +
    // quantifiers). They carry no annotations — just recurse through them.
    if (pn->group_top) {
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            walk_node(ctx, n00b_tree_child(node, i));
        }

        return;
    }

    n00b_nonterm_t *nt = n00b_get_nonterm(ctx->grammar, pn->id);

    if (!nt) {
        // Unknown NT — just recurse.
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            walk_node(ctx, n00b_tree_child(node, i));
        }

        return;
    }

    // --- Populate per-node context ---

    n00b_parse_rule_t *rule = n00b_get_node_rule(ctx->grammar, pn);

    n00b_list_t(n00b_annotation_t *) *annot_list = NULL;

    if (rule && rule->annotations.data) {
        annot_list = &rule->annotations;
    }

    size_t annot_count = annot_list ? n00b_list_len(*annot_list) : 0;

    // Build a flat pointer array for the phase handlers so they don't
    // need to know about the n00b_list_t internals.
    n00b_annotation_t *annot_stack[annot_count > 0 ? annot_count : 1];

    for (size_t ai = 0; ai < annot_count; ai++) {
        annot_stack[ai] = n00b_list_get(*annot_list, ai);
    }

    annot_node_ctx_t nc_ctx = {
        .node         = node,
        .pn           = pn,
        .nt           = nt,
        .rule         = rule,
        .annots       = annot_stack,
        .annot_count  = annot_count,
        .last_sym     = NULL,
        .opened_scope = false,
        .scope_ns     = n00b_string_empty(),
    };

    // --- Pre-phase extraction ---
    //
    // For <class-decl-one> or <interface-spec-one>, extract visibility
    // from the <member-visibility> child BEFORE phases fire, because
    // @declares is on this node itself and fires in Phase 2.

    n00b_sym_mutability_t saved_mut = ctx->current_mutability;
    n00b_string_t        *saved_vis = ctx->current_visibility;

    if (nt && (n00b_unicode_str_eq(nt->name, r"class-decl-one")
               || n00b_unicode_str_eq(nt->name, r"interface-spec-one"))) {
        ctx->current_visibility = NULL;

        n00b_parse_tree_t *vis = n00b_tree_find_child_by_nt_name(
            ctx->grammar, node, r"member-visibility");

        if (vis) {
            n00b_token_info_t *tok = n00b_tree_find_first_terminal(vis);

            if (tok && n00b_option_is_set(tok->value)) {
                ctx->current_visibility = n00b_option_get(tok->value);
            }
        }
    }

    // --- Phase 1: scope open ---
    annot_phase_scope_open(ctx, &nc_ctx);

    // --- Phases 2-3: two-pass symbol registration + type binding ---
    annot_phase_symtab(ctx, &nc_ctx);

    // --- Phase 4: CF labels ---
    annot_phase_cf(ctx, &nc_ctx);

    // --- Phase 5: recurse into children ---
    //
    // For <variable-decl>, extract the qualifier keyword from the
    // <decl-qualifiers> subtree and set ctx->current_mutability so
    // that child @declares handlers can stamp the symbol.

    if (nt && n00b_unicode_str_eq(nt->name, r"variable-decl")) {
        // Default: var (mutable).
        ctx->current_mutability = N00B_SYM_MUTABLE;

        // <variable-decl> → <decl-qualifiers> <sym-decl-list>
        // Walk <decl-qualifiers> for the last keyword token.
        n00b_parse_tree_t *quals = n00b_tree_find_child_by_nt_name(
            ctx->grammar, node, r"decl-qualifiers");

        if (quals) {
            n00b_token_info_t *tok = n00b_tree_find_first_terminal(quals);

            if (tok && n00b_option_is_set(tok->value)) {
                n00b_string_t *kw = n00b_option_get(tok->value);

                if (n00b_unicode_str_eq(kw, r"let")) {
                    ctx->current_mutability = N00B_SYM_IMMUTABLE;
                }
                else if (n00b_unicode_str_eq(kw, r"const")) {
                    ctx->current_mutability = N00B_SYM_CONST;
                }
                else if (n00b_unicode_str_eq(kw, r"global")) {
                    ctx->current_mutability = N00B_SYM_GLOBAL;
                }
            }
        }
    }

    size_t num_children = n00b_tree_num_children(node);

    for (size_t i = 0; i < num_children; i++) {
        walk_node(ctx, n00b_tree_child(node, i));
    }

    ctx->current_mutability = saved_mut;
    ctx->current_visibility = saved_vis;

    // --- Phase 6: post-order types ---
    annot_phase_types_post(ctx, &nc_ctx);

    // --- Phase 7: scope close ---
    annot_phase_scope_close(ctx, &nc_ctx);
}

// ============================================================================
// Public API — full result (symtab + control flow labels)
// ============================================================================

n00b_annot_result_t *
n00b_annot_walk_tree_full_ex(n00b_grammar_t             *g,
                             n00b_parse_tree_t          *tree,
                             n00b_translate_type_spec_fn ts_fn)
_kargs {
    n00b_symtab_t          *symtab;
    n00b_tc_ctx_t          *tc_ctx;
    struct n00b_diag_ctx_s *diag;
}
{
    if (!g || !tree) {
        return NULL;
    }

    n00b_cf_labels_t *labels = n00b_cf_labels_new();

    // Canonical idiom: build the list as a fully scan-info-threaded
    // lvalue, then struct-copy into the heap-allocated return shell.
    n00b_list_t(n00b_sym_entry_t *) params_lst =
        n00b_list_new_private(n00b_sym_entry_t *);
    n00b_list_t(n00b_sym_entry_t *) *params =
        n00b_alloc(n00b_list_t(n00b_sym_entry_t *));
    *params = params_lst;

    n00b_node_types_t *node_types = n00b_node_types_new();

    n00b_list_t(n00b_sym_entry_t *) shadowed_lst =
        n00b_list_new_private(n00b_sym_entry_t *);
    n00b_list_t(n00b_sym_entry_t *) *shadowed_entries =
        n00b_alloc(n00b_list_t(n00b_sym_entry_t *));
    *shadowed_entries = shadowed_lst;

    n00b_symtab_t     *st = (kargs->symtab) ? kargs->symtab : n00b_symtab_new();
    n00b_tc_ctx_t     *tc = (kargs->tc_ctx) ? kargs->tc_ctx : n00b_tc_ctx_new();
    n00b_diag_ctx_t   *dg = (kargs->diag) ? kargs->diag : n00b_diag_ctx_new();

    n00b_annot_walk_ctx_t ctx = {
        .symtab              = st,
        .grammar             = g,
        .cf_labels           = labels,
        .tc_ctx              = tc,
        .diag                = dg,
        .params              = params,
        .node_types          = node_types,
        .shadowed_entries    = shadowed_entries,
        .translate_type_spec = ts_fn,
    };

    walk_node(&ctx, tree);

    n00b_annot_result_t *result = n00b_alloc(n00b_annot_result_t);
    result->symtab           = ctx.symtab;
    result->cf_labels        = ctx.cf_labels;
    result->tc_ctx           = ctx.tc_ctx;
    result->diag             = ctx.diag;
    result->params           = ctx.params;
    result->node_types       = ctx.node_types;
    result->shadowed_entries = ctx.shadowed_entries;

    return result;
}

n00b_annot_result_t *
n00b_annot_walk_tree_full(n00b_grammar_t *g, n00b_parse_tree_t *tree)
{
    return n00b_annot_walk_tree_full_ex(g, tree, NULL);
}

n00b_annot_result_t *
n00b_annot_walk_full(n00b_parse_result_t *result)
{
    if (!result || !n00b_parse_result_ok(result)) {
        return NULL;
    }

    n00b_grammar_t    *g    = n00b_parse_result_grammar(result);
    n00b_parse_tree_t *tree = n00b_parse_result_tree(result);

    return n00b_annot_walk_tree_full(g, tree);
}

// ============================================================================
// Public API — symtab only (convenience wrappers)
// ============================================================================

n00b_symtab_t *
n00b_annot_walk_tree(n00b_grammar_t *g, n00b_parse_tree_t *tree)
{
    n00b_annot_result_t *r = n00b_annot_walk_tree_full(g, tree);

    return r ? r->symtab : NULL;
}

n00b_symtab_t *
n00b_annot_walk(n00b_parse_result_t *result)
{
    n00b_annot_result_t *r = n00b_annot_walk_full(result);

    return r ? r->symtab : NULL;
}

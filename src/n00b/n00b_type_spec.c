/**
 * @file infer.c
 * @brief Type-spec translator: slay parse tree → typecheck types.
 *
 * Walks `<type-spec>` parse subtrees and produces `n00b_tc_type_t *` nodes
 * by calling the constructors in typecheck/construct.h.
 */

#include "slay/infer.h"
#include "slay/tree_util.h"
#include "slay/annotation.h"
#include "internal/slay/grammar_internal.h"
#include "core/alloc.h"
#include "adt/list.h"
#include "core/vargs.h"
#include "text/strings/string_ops.h"

#include "typecheck/types.h"
#include "typecheck/context.h"

// Forward-declare construct functions (can't include construct.h because
// it uses typed varargs which produce kargs structs we don't need here).
extern n00b_tc_type_t *n00b_tc_var(n00b_tc_ctx_t *ctx, n00b_string_t *name);
extern n00b_tc_type_t *n00b_tc_fresh_var(n00b_tc_ctx_t *ctx);
extern n00b_tc_type_t *n00b_tc_prim(n00b_tc_ctx_t *ctx, n00b_string_t *name);

// Build param types manually (can't use the typed vargs constructors from here).
extern void n00b_tc_ctx_register(n00b_tc_ctx_t *ctx, n00b_tc_type_t *type);

// ============================================================================
// Helpers
// ============================================================================

// Check if a non-terminal node's name matches a string.
static bool
nt_name_is(n00b_grammar_t *g, n00b_parse_tree_t *node, n00b_string_t *name)
{
    if (!node || n00b_tree_is_leaf(node)) {
        return false;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    if (pn->id < 0) {
        return false;
    }

    n00b_nonterm_t *nt = n00b_get_nonterm(g, pn->id);

    return nt && n00b_unicode_str_eq(nt->name, name);
}

// Forward declaration for recursive translation.
static n00b_tc_type_t *translate(n00b_tc_ctx_t *ctx, n00b_grammar_t *g,
                                   n00b_parse_tree_t *node);

// Process a <where-clause> node: attach constraints to type variables.
static void
translate_where_clause(n00b_tc_ctx_t *ctx, n00b_grammar_t *g,
                       n00b_parse_tree_t *where_node)
{
    if (!where_node) {
        return;
    }

    size_t nc = n00b_tree_num_children(where_node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(where_node, i);

        if (n00b_tree_is_leaf(child)) {
            continue;
        }

        n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

        if (cpn->group_top) {
            // Recurse into groups.
            size_t gnc = n00b_tree_num_children(child);

            for (size_t j = 0; j < gnc; j++) {
                n00b_parse_tree_t *gchild = n00b_tree_child(child, j);

                if (!n00b_tree_is_leaf(gchild)
                    && nt_name_is(g, gchild, r"type-constraint")) {
                    translate_where_clause(ctx, g, gchild);
                }
            }

            continue;
        }

        if (!nt_name_is(g, child, r"type-constraint")) {
            continue;
        }

        // <type-constraint> → ` IDENTIFIER : <constraint-list>
        // Find the type variable name.
        n00b_string_t *var_name = n00b_string_empty();
        size_t cnc = n00b_tree_num_children(child);

        for (size_t j = 0; j < cnc; j++) {
            n00b_parse_tree_t *tcc = n00b_tree_child(child, j);

            if (n00b_tree_is_leaf(tcc)) {
                n00b_string_t *s = n00b_tree_extract_first_identifier(tcc);

                if (s->u8_bytes > 0 && !n00b_unicode_str_eq(s, r"`")
                    && !n00b_unicode_str_eq(s, r":")) {
                    var_name = s;
                    break;
                }
            }
        }

        if (var_name->u8_bytes == 0) {
            continue;
        }

        // Look up or create the type variable.
        n00b_tc_type_t *tv = n00b_tc_var(ctx, var_name);

        // Find the <constraint-list> child.
        n00b_parse_tree_t *clist = n00b_tree_find_child_by_nt_name(g, child, r"constraint-list");

        if (!clist) {
            continue;
        }

        // Walk <one-constraint> children.
        size_t clnc = n00b_tree_num_children(clist);

        for (size_t j = 0; j < clnc; j++) {
            n00b_parse_tree_t *con_node = n00b_tree_child(clist, j);

            if (n00b_tree_is_leaf(con_node)) {
                continue;
            }

            n00b_nt_node_t *con_pn = &n00b_tree_node_value(con_node);

            if (con_pn->group_top) {
                size_t gnc2 = n00b_tree_num_children(con_node);

                for (size_t k = 0; k < gnc2; k++) {
                    n00b_parse_tree_t *gc2 = n00b_tree_child(con_node, k);

                    if (nt_name_is(g, gc2, r"one-constraint")) {
                        con_node = gc2;
                        goto handle_constraint;
                    }
                }

                continue;
            }

            if (!nt_name_is(g, con_node, r"one-constraint")) {
                continue;
            }

handle_constraint:;
            // Determine constraint kind.
            // Check first terminal to see if it's "!=" or an IDENTIFIER.
            n00b_string_t *first = n00b_tree_extract_first_identifier(con_node);

            if (n00b_unicode_str_eq(first, r"!=")) {
                // Exclusion constraint: != <one-tspec>
                n00b_parse_tree_t *excluded_node = n00b_tree_find_child_by_nt_name(g, con_node,
                                                                    r"one-tspec");
                n00b_tc_type_t *excluded = excluded_node
                    ? translate(ctx, g, excluded_node)
                    : nullptr;

                if (excluded) {
                    // Add a "not" constraint.
                    n00b_tc_type_t *resolved = tv;

                    while (resolved->forward) {
                        resolved = resolved->forward;
                    }

                    if (n00b_variant_is_type(resolved->kind, n00b_tc_var_t)) {
                        auto var = n00b_variant_get(resolved->kind, n00b_tc_var_t);

                        if (!var.constraints) {
                            var.constraints = n00b_alloc(
                                n00b_list_t(n00b_tc_constraint_t));
                            *var.constraints = n00b_list_new_private(
                                n00b_tc_constraint_t);
                        }

                        n00b_tc_constraint_t con = n00b_variant_set(
                            n00b_tc_constraint_t, n00b_tc_con_not_t,
                            ((n00b_tc_con_not_t){.excluded = excluded}));

                        n00b_list_push(*var.constraints, con);

                        // Write back the updated var to the variant.
                        _n00b_variant_set_ptr(&resolved->kind,
                                              n00b_tc_var_t, var);
                    }
                }
            }
            else if (first->u8_bytes > 0) {
                // Interface constraint: IDENTIFIER (interface name).
                n00b_tc_type_t *resolved = tv;

                while (resolved->forward) {
                    resolved = resolved->forward;
                }

                if (n00b_variant_is_type(resolved->kind, n00b_tc_var_t)) {
                    auto var = n00b_variant_get(resolved->kind, n00b_tc_var_t);

                    if (!var.constraints) {
                        var.constraints = n00b_alloc(
                            n00b_list_t(n00b_tc_constraint_t));
                        *var.constraints = n00b_list_new_private(
                            n00b_tc_constraint_t);
                    }

                    n00b_tc_constraint_t con = n00b_variant_set(
                        n00b_tc_constraint_t, n00b_tc_con_implements_t,
                        ((n00b_tc_con_implements_t){.iface_name = first}));

                    n00b_list_push(*var.constraints, con);

                    _n00b_variant_set_ptr(&resolved->kind,
                                          n00b_tc_var_t, var);
                }
            }
        }
    }
}

// Build a kargs Record type from a <tspec-kargs> node.
// Walks <tspec-field> children, extracts name + type, builds Record
// with ordered=false.
static n00b_tc_type_t *
build_kargs_record(n00b_tc_ctx_t *ctx, n00b_grammar_t *g,
                   n00b_parse_tree_t *kargs_node)
{
    // Canonical idiom: populate the scan-info-threaded lvalues
    // first, then struct-copy each into its heap shell after
    // population is complete.
    n00b_list_t(n00b_string_t *) names = n00b_list_new_private(n00b_string_t *);
    n00b_list_t(n00b_tc_type_t *) types = n00b_list_new_private(n00b_tc_type_t *);

    // Walk children looking for <tspec-field> nodes.
    size_t nc = n00b_tree_num_children(kargs_node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(kargs_node, i);

        if (n00b_tree_is_leaf(child)) {
            continue;
        }

        n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

        if (cpn->group_top) {
            // Recurse into groups to find tspec-field nodes.
            size_t gnc = n00b_tree_num_children(child);

            for (size_t j = 0; j < gnc; j++) {
                n00b_parse_tree_t *gchild = n00b_tree_child(child, j);

                if (nt_name_is(g, gchild, r"tspec-field")) {
                    n00b_string_t *fname = n00b_tree_extract_first_identifier(gchild);

                    if (fname->u8_bytes > 0) {
                        // Find the type child of the field.
                        n00b_parse_tree_t *ft = n00b_tree_find_child_by_nt_name(g, gchild,
                                                                 r"type-spec-body");

                        if (!ft) {
                            ft = n00b_tree_find_child_by_nt_name(g, gchild, r"one-tspec");
                        }

                        n00b_tc_type_t *ftype = ft ? translate(ctx, g, ft) : nullptr;

                        n00b_list_push(names, fname);
                        n00b_list_push(types, ftype);
                    }
                }
            }

            continue;
        }

        if (nt_name_is(g, child, r"tspec-field")) {
            n00b_string_t *fname = n00b_tree_extract_first_identifier(child);

            if (fname->u8_bytes > 0) {
                n00b_parse_tree_t *ft = n00b_tree_find_child_by_nt_name(g, child,
                                                         r"type-spec-body");

                if (!ft) {
                    ft = n00b_tree_find_child_by_nt_name(g, child, r"one-tspec");
                }

                n00b_tc_type_t *ftype = ft ? translate(ctx, g, ft) : nullptr;

                n00b_list_push(names, fname);
                n00b_list_push(types, ftype);
            }
        }
    }

    // Heap-allocate the list shells now (after population) and
    // struct-copy the fully-initialized lvalues in.
    n00b_list_t(n00b_string_t *) *names_ptr =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *names_ptr = names;
    n00b_list_t(n00b_tc_type_t *) *types_ptr =
        n00b_alloc(n00b_list_t(n00b_tc_type_t *));
    *types_ptr = types;

    // Build Record type with ordered=false.
    n00b_tc_type_t *t = n00b_alloc(n00b_tc_type_t);
    t->forward = nullptr;
    n00b_tc_ctx_register(ctx, t);

    n00b_tc_record_t rec = {
        .name             = n00b_string_empty(),
        .type_params      = nullptr,
        .field_names      = names_ptr,
        .field_types      = types_ptr,
        .field_has_default = nullptr,
        .open             = false,
        .ordered          = false,
    };

    _n00b_variant_set_ptr(&t->kind, n00b_tc_record_t, rec);
    return t;
}

// ============================================================================
// Collect type list from <tspec-list>
// ============================================================================

// Collects types from a <tspec-list> node into a pre-allocated list.
static void
collect_tspec_list(n00b_tc_ctx_t *ctx, n00b_grammar_t *g,
                   n00b_parse_tree_t *node,
                   n00b_list_t(n00b_tc_type_t *) *out)
{
    if (!node) {
        return;
    }

    size_t nc = n00b_tree_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(node, i);

        if (n00b_tree_is_leaf(child)) {
            // Skip punctuation tokens (commas, brackets).
            continue;
        }

        n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

        if (cpn->group_top) {
            // Recurse into groups.
            collect_tspec_list(ctx, g, child, out);
            continue;
        }

        if (cpn->id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(g, cpn->id);

            if (nt && (n00b_unicode_str_eq(nt->name, r"one-tspec")
                    || n00b_unicode_str_eq(nt->name, r"tspec-list")
                    || n00b_unicode_str_eq(nt->name, r"union-tspec"))) {
                if (n00b_unicode_str_eq(nt->name, r"tspec-list")
                    || n00b_unicode_str_eq(nt->name, r"union-tspec")) {
                    collect_tspec_list(ctx, g, child, out);
                } else {
                    n00b_tc_type_t *t = translate(ctx, g, child);

                    if (t) {
                        n00b_list_push(*out, t);
                    }
                }
            }
            // Skip tspec-vargs, tspec-kargs — handled separately.
        }
    }
}

// ============================================================================
// Core translation
// ============================================================================

static n00b_tc_type_t *
translate(n00b_tc_ctx_t *ctx, n00b_grammar_t *g, n00b_parse_tree_t *node)
{
    if (!node) {
        return nullptr;
    }

    // Leaf (terminal) — must be a bare IDENTIFIER used as a type name.
    if (n00b_tree_is_leaf(node)) {
        n00b_string_t *name = n00b_tree_extract_first_identifier(node);

        if (name->u8_bytes == 0) {
            return nullptr;
        }

        // Try built-in first, fall back to creating a new prim.
        n00b_tc_type_t *prim = n00b_tc_lookup_prim(ctx, name);

        return prim ? prim : n00b_tc_prim(ctx, name);
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    // Group nodes: recurse into first child.
    if (pn->group_top || pn->id < 0 || pn->id == N00B_EMPTY_STRING) {
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_tc_type_t *t = translate(ctx, g, n00b_tree_child(node, i));

            if (t) {
                return t;
            }
        }

        return nullptr;
    }

    n00b_nonterm_t *nt = n00b_get_nonterm(g, pn->id);

    if (!nt) {
        return nullptr;
    }

    // <type-spec> → <one-tspec> <where-clause>?
    if (n00b_unicode_str_eq(nt->name, r"type-spec")) {
        // Translate the <one-tspec> child.
        n00b_tc_type_t *body_type = nullptr;
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_tree_child(node, i);

            if (!n00b_tree_is_leaf(child)
                && nt_name_is(g, child, r"where-clause")) {
                continue; // Handle below.
            }

            n00b_tc_type_t *t = translate(ctx, g, child);

            if (t) {
                body_type = t;
                break;
            }
        }

        // Process <where-clause> if present.
        n00b_parse_tree_t *where_node = n00b_tree_find_child_by_nt_name(g, node, r"where-clause");

        if (where_node) {
            translate_where_clause(ctx, g, where_node);
        }

        return body_type;
    }

    // <union-tspec> → union or single type (lower tier, | allowed).
    if (n00b_unicode_str_eq(nt->name, r"union-tspec")) {
        // Collect all <one-tspec> children. If more than one, build a Sum.
        // Canonical idiom: populate the scan-info-threaded lvalue, then
        // struct-copy into the heap shell after population.
        n00b_list_t(n00b_tc_type_t *) variants = n00b_list_new_private(n00b_tc_type_t *);

        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_tree_child(node, i);

            if (n00b_tree_is_leaf(child)) {
                // Skip | punctuation.
                continue;
            }

            n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

            if (cpn->group_top) {
                // Recurse through groups.
                size_t gnc = n00b_tree_num_children(child);

                for (size_t j = 0; j < gnc; j++) {
                    n00b_parse_tree_t *gchild = n00b_tree_child(child, j);

                    if (n00b_tree_is_leaf(gchild)) {
                        continue;
                    }

                    n00b_tc_type_t *t = translate(ctx, g, gchild);

                    if (t) {
                        n00b_list_push(variants, t);
                    }
                }

                continue;
            }

            n00b_tc_type_t *t = translate(ctx, g, child);

            if (t) {
                n00b_list_push(variants, t);
            }
        }

        size_t nv = n00b_list_len(variants);

        if (nv == 0) {
            return nullptr;
        }

        if (nv == 1) {
            return n00b_list_get(variants, 0);
        }

        n00b_list_t(n00b_tc_type_t *) *var_ptr =
            n00b_alloc(n00b_list_t(n00b_tc_type_t *));
        *var_ptr = variants;

        // Build Sum type.
        n00b_tc_type_t *t = n00b_alloc(n00b_tc_type_t);
        t->forward = nullptr;
        n00b_tc_ctx_register(ctx, t);

        n00b_tc_sum_t sum = {
            .variants = var_ptr,
        };

        _n00b_variant_set_ptr(&t->kind, n00b_tc_sum_t, sum);
        return t;
    }

    // <one-tspec> — dispatch to the child.
    if (n00b_unicode_str_eq(nt->name, r"one-tspec")) {
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_tc_type_t *t = translate(ctx, g, n00b_tree_child(node, i));

            if (t) {
                return t;
            }
        }

        return nullptr;
    }

    // <tspec-tvar> — ` IDENTIFIER → type variable.
    if (n00b_unicode_str_eq(nt->name, r"tspec-tvar")) {
        // Children: %"`" %IDENTIFIER
        n00b_string_t *name = n00b_string_empty();
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_tree_child(node, i);

            if (n00b_tree_is_leaf(child)) {
                n00b_string_t *s = n00b_tree_extract_first_identifier(child);

                if (s->u8_bytes > 0 && !n00b_unicode_str_eq(s, r"`")) {
                    name = s;
                    break;
                }
            }
        }

        if (name->u8_bytes > 0) {
            return n00b_tc_var(ctx, name);
        }

        return n00b_tc_fresh_var(ctx);
    }

    // <tspec-parameterized> — name [ tspec-list ] or ref [ tspec-list ]
    if (n00b_unicode_str_eq(nt->name, r"tspec-parameterized")) {
        // Get the constructor name from the first identifier.
        n00b_string_t *name = n00b_string_empty();
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_tree_child(node, i);

            if (n00b_tree_is_leaf(child)) {
                n00b_string_t *s = n00b_tree_extract_first_identifier(child);

                // Skip punctuation.
                if (s->u8_bytes > 0
                    && !n00b_unicode_str_eq(s, r"[")
                    && !n00b_unicode_str_eq(s, r"]")) {
                    if (name->u8_bytes == 0) {
                        name = s;
                    }
                }
            } else if (nt_name_is(g, child, r"member-chain")) {
                name = n00b_tree_extract_first_identifier(child);
            }
        }

        if (name->u8_bytes == 0) {
            return nullptr;
        }

        // Find the <tspec-list> child.
        n00b_parse_tree_t *tspec_list = n00b_tree_find_child_by_nt_name(g, node, r"tspec-list");

        if (!tspec_list) {
            // No parameters: bare identifier (not really parameterized).
            n00b_tc_type_t *prim = n00b_tc_lookup_prim(ctx, name);

            return prim ? prim : n00b_tc_prim(ctx, name);
        }

        // Collect parameters. Canonical idiom: populate the
        // scan-info-threaded lvalue first, then struct-copy into the
        // heap shell after population is complete.
        n00b_list_t(n00b_tc_type_t *) params = n00b_list_new_private(n00b_tc_type_t *);
        collect_tspec_list(ctx, g, tspec_list, &params);

        n00b_list_t(n00b_tc_type_t *) *params_ptr =
            n00b_alloc(n00b_list_t(n00b_tc_type_t *));
        *params_ptr = params;

        // Build the Param type manually (can't use typed vargs from here).
        n00b_tc_type_t *t = n00b_alloc(n00b_tc_type_t);
        t->forward = nullptr;
        n00b_tc_ctx_register(ctx, t);

        // We need to include the variant payload types.
        // Use the _n00b_variant_set_ptr macro directly.
        n00b_tc_param_t param = {
            .name   = name,
            .params = params_ptr,
        };

        _n00b_variant_set_ptr(&t->kind, n00b_tc_param_t, param);
        return t;
    }

    // <tspec-func> — ( params ) -> ret
    if (n00b_unicode_str_eq(nt->name, r"tspec-func")) {
        // Collect positional params from <tspec-func-params>.
        // Canonical idiom: populate the scan-info-threaded lvalue
        // first, then struct-copy into the heap shell after
        // population is complete.
        n00b_list_t(n00b_tc_type_t *) positional = n00b_list_new_private(n00b_tc_type_t *);

        n00b_parse_tree_t *func_params = n00b_tree_find_child_by_nt_name(g, node, r"tspec-func-params");
        n00b_tc_type_t    *vargs_type  = nullptr;
        n00b_tc_type_t    *kargs_type  = nullptr;

        if (func_params) {
            collect_tspec_list(ctx, g, func_params, &positional);

            // Extract vargs: <tspec-vargs> → * <one-tspec>
            n00b_parse_tree_t *vargs_node = n00b_tree_find_child_by_nt_name(g, func_params,
                                                             r"tspec-vargs");

            if (vargs_node) {
                // Find the <one-tspec> or <type-spec-body> child.
                n00b_parse_tree_t *vt = n00b_tree_find_child_by_nt_name(g, vargs_node,
                                                         r"type-spec-body");

                if (!vt) {
                    vt = n00b_tree_find_child_by_nt_name(g, vargs_node, r"one-tspec");
                }

                if (vt) {
                    vargs_type = translate(ctx, g, vt);
                }
                else {
                    // Fallback: translate the vargs node itself.
                    vargs_type = translate(ctx, g, vargs_node);
                }
            }

            // Extract kargs: <tspec-kargs> → ** <tspec-field>+
            n00b_parse_tree_t *kargs_node = n00b_tree_find_child_by_nt_name(g, func_params,
                                                             r"tspec-kargs");

            if (kargs_node) {
                kargs_type = build_kargs_record(ctx, g, kargs_node);
            }
        }

        // Get return type from <return-type>.
        n00b_tc_type_t *ret_type = nullptr;
        n00b_parse_tree_t *ret_node = n00b_tree_find_child_by_nt_name(g, node, r"return-type");

        if (ret_node) {
            n00b_parse_tree_t *type_spec = n00b_tree_find_child_by_nt_name(g, ret_node, r"type-spec");

            if (!type_spec) {
                type_spec = n00b_tree_find_child_by_nt_name(g, ret_node, r"one-tspec");
            }

            if (type_spec) {
                ret_type = translate(ctx, g, type_spec);
            }
        }

        // Heap-allocate the positional list shell now (after
        // population) and struct-copy the lvalue in.
        n00b_list_t(n00b_tc_type_t *) *pos_ptr =
            n00b_alloc(n00b_list_t(n00b_tc_type_t *));
        *pos_ptr = positional;

        // Build function type manually.
        n00b_tc_type_t *t = n00b_alloc(n00b_tc_type_t);
        t->forward = nullptr;
        n00b_tc_ctx_register(ctx, t);

        n00b_tc_fn_t fn = {
            .positional  = pos_ptr,
            .vargs_type  = vargs_type,
            .kargs_type  = kargs_type,
            .return_type = ret_type,
        };

        _n00b_variant_set_ptr(&t->kind, n00b_tc_fn_t, fn);
        return t;
    }

    // <member-chain> — resolve to a type name.
    if (n00b_unicode_str_eq(nt->name, r"member-chain")) {
        n00b_string_t *name = n00b_tree_extract_first_identifier(node);

        if (name->u8_bytes > 0) {
            n00b_tc_type_t *prim = n00b_tc_lookup_prim(ctx, name);

            return prim ? prim : n00b_tc_prim(ctx, name);
        }

        return nullptr;
    }

    // Fallback: try recursing into children.
    {
        size_t nc = n00b_tree_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_tc_type_t *t = translate(ctx, g, n00b_tree_child(node, i));

            if (t) {
                return t;
            }
        }
    }

    return nullptr;
}

// ============================================================================
// Public API
// ============================================================================

n00b_tc_type_t *
n00b_tc_translate_type_spec(n00b_tc_ctx_t     *ctx,
                              n00b_grammar_t    *g,
                              n00b_parse_tree_t *type_node)
{
    if (!ctx || !g || !type_node) {
        return nullptr;
    }

    return translate(ctx, g, type_node);
}

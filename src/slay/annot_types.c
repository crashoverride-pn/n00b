// annot_types.c - Phase 6: post-order type inference.
//
// Handles @infer evaluation, auto-propagation from sole NT children,
// symbol↔node-type unification, and @assigns type unification.

#include "internal/slay/annot_phases.h"
#include "slay/infer_expr.h"
#include "typecheck/unify.h"
#include "typecheck/construct.h"
#include "adt/variant.h"

void
annot_phase_types_post(n00b_annot_walk_ctx_t *ctx, annot_node_ctx_t *nc)
{
    if (!ctx->tc_ctx || !ctx->node_types) {
        return;
    }

    size_t num_children = n00b_tree_num_children(nc->node);

    // ---- @infer evaluation ----

    bool has_infer = false;

    for (size_t ai = 0; ai < nc->annot_count; ai++) {
        n00b_annotation_t *a = nc->annots[ai];

        if (a->kind == N00B_ANNOT_INFER) {
            has_infer = true;


            n00b_tc_type_t *t = n00b_infer_eval_ex(
                ctx->tc_ctx, ctx->symtab, ctx->grammar,
                nc->node, ctx->node_types,
                ctx->translate_type_spec, a->infer_expr);

            if (t) {
                n00b_parse_tree_t *key = nc->node;
                n00b_dict_put(ctx->node_types, key, t);
            }

            break;  // Only one @infer per rule.
        }
    }

    // ---- Auto-propagation ----
    //
    // If no @infer and no @literal already set a type, propagate
    // sole NT child's type upward.

    if (!has_infer) {
        bool already_typed = false;
        {
            bool      found = false;
            n00b_parse_tree_t *key = nc->node;
            (void)n00b_dict_get(ctx->node_types, key, &found);
            already_typed = found;
        }

        if (!already_typed) {
            n00b_tc_type_t *sole_child_type = NULL;
            int             nt_child_count  = 0;

            for (size_t i = 0; i < num_children; i++) {
                n00b_parse_tree_t *child
                    = n00b_tree_child(nc->node, i);

                if (child && !n00b_tree_is_leaf(child)) {
                    n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

                    if (!cpn->group_top) {
                        bool found = false;
                        n00b_tc_type_t *ct
                            = n00b_dict_get(ctx->node_types, child, &found);

                        if (found) {
                            sole_child_type = ct;
                        }

                        nt_child_count++;
                    }
                }
            }

            if (nt_child_count == 1 && sole_child_type) {
                n00b_parse_tree_t *key = nc->node;
                n00b_dict_put(ctx->node_types, key, sole_child_type);
            }
        }
    }

    // ---- Symbol↔node-type unification ----
    //
    // If this node declared a symbol and now has a type (from @infer
    // or auto-propagation), unify with the symbol's type variable.

    if (nc->last_sym && nc->last_sym->type_var) {
        bool      found = false;
        n00b_parse_tree_t *key = nc->node;
        n00b_tc_type_t *node_type
            = n00b_dict_get(ctx->node_types, key, &found);

        if (found && node_type) {
            n00b_tc_type_t *resolved = nc->last_sym->type_var;

            while (resolved->forward) {
                resolved = resolved->forward;
            }

            if (n00b_variant_is_type(resolved->kind, n00b_tc_var_t)) {
                n00b_tc_unify(ctx->tc_ctx, nc->last_sym->type_var, node_type);
            }
        }
    }

    // ---- @assigns type unification ----
    //
    // When @assigns($name, $value) is present, unify the LHS symbol's
    // type_var with the RHS expression's inferred type.

    for (size_t ai = 0; ai < nc->annot_count; ai++) {
        n00b_annotation_t *a = nc->annots[ai];

        if (a->kind == N00B_ANNOT_ASSIGNS) {
            n00b_parse_tree_t *name_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);
            n00b_string_t *sym_name
                = name_node
                    ? n00b_tree_extract_first_identifier(name_node)
                    : n00b_string_empty();

            if (!sym_name || sym_name->u8_bytes == 0) {
                break;
            }

            n00b_sym_entry_t *sym = n00b_symtab_lookup_any(
                ctx->symtab, n00b_string_empty(), sym_name);

            if (!sym || !sym->type_var) {
                break;
            }

            if (!n00b_tc_is_var(sym->type_var)) {
                break;
            }

            n00b_parse_tree_t *val_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->value_ref);

            if (!val_node) {
                break;
            }

            bool           found = false;
            uintptr_t      vk    = (uintptr_t)val_node;
            n00b_tc_type_t *val_type
                = n00b_dict_get(ctx->node_types, vk, &found);

            if (found && val_type) {
                n00b_tc_unify(ctx->tc_ctx, sym->type_var, val_type);
            }

            break;
        }
    }

    // ---- @call argument-to-parameter type unification ----
    //
    // When @call($callee, $args) is present and the callee resolves to
    // a function type, unify each positional argument's inferred type
    // with the corresponding parameter type.  Return-type propagation
    // is already handled by @infer("return_of($0)").

    for (size_t ai = 0; ai < nc->annot_count; ai++) {
        n00b_annotation_t *a = nc->annots[ai];

        if (a->kind != N00B_ANNOT_CALL) {
            continue;
        }

        n00b_parse_tree_t *callee_node
            = n00b_tree_resolve_child_ref(
                ctx->grammar, nc->node, a->name_ref);

        if (!callee_node) {
            break;
        }

        bool           found = false;
        uintptr_t      ck    = (uintptr_t)callee_node;
        n00b_tc_type_t *callee_type
            = n00b_dict_get(ctx->node_types, ck, &found);

        if (!found || !callee_type) {
            break;
        }

        n00b_tc_type_t *resolved = n00b_tc_find(callee_type);

        if (!n00b_variant_is_type(resolved->kind, n00b_tc_fn_t)) {
            break;
        }

        // Instantiate the callee's type so each call site gets fresh
        // type variables. This prevents print(42); print("hello") from
        // over-constraining a shared Var. Direct recursive calls could
        // skip this, but for now we always instantiate.
        n00b_tc_type_t *inst = n00b_tc_instantiate(ctx->tc_ctx, resolved);
        n00b_tc_fn_t fn = n00b_variant_get(inst->kind, n00b_tc_fn_t);

        n00b_parse_tree_t *args_node
            = n00b_tree_resolve_child_ref(
                ctx->grammar, nc->node, a->type_ref);

        if (!args_node || !fn.positional) {
            break;
        }

        size_t n_params = n00b_list_len(*fn.positional);
        size_t arg_ix   = 0;
        size_t n_kids   = n00b_tree_num_children(args_node);

        for (size_t i = 0; i < n_kids; i++) {
            n00b_parse_tree_t *child = n00b_tree_child(args_node, i);

            if (!child || n00b_tree_is_leaf(child)) {
                continue;
            }

            // Skip group_top wrappers — descend into their NT children.
            n00b_nt_node_t *cpn = &n00b_tree_node_value(child);

            if (cpn->group_top) {
                size_t gn = n00b_tree_num_children(child);

                for (size_t gi = 0; gi < gn; gi++) {
                    n00b_parse_tree_t *gc = n00b_tree_child(child, gi);

                    if (!gc || n00b_tree_is_leaf(gc)) {
                        continue;
                    }

                    bool           gfound = false;
                    uintptr_t      gk     = (uintptr_t)gc;
                    n00b_tc_type_t *gtype
                        = n00b_dict_get(ctx->node_types, gk, &gfound);

                    if (gfound && gtype && arg_ix < n_params) {
                        n00b_tc_type_t *param_type
                            = n00b_list_get(*fn.positional, arg_ix);

                        if (param_type) {
                            n00b_tc_unify(ctx->tc_ctx, param_type, gtype);
                        }
                    }
                    else if (gfound && gtype && fn.vargs_type) {
                        n00b_tc_unify(ctx->tc_ctx, fn.vargs_type, gtype);
                    }

                    arg_ix++;
                }

                continue;
            }

            // Regular NT child — an argument expression.
            bool           afound = false;
            n00b_tc_type_t *arg_type
                = n00b_dict_get(ctx->node_types, child, &afound);

            if (afound && arg_type && arg_ix < n_params) {
                n00b_tc_type_t *param_type
                    = n00b_list_get(*fn.positional, arg_ix);

                if (param_type) {
                    n00b_tc_unify(ctx->tc_ctx, param_type, arg_type);
                }
            }
            else if (afound && arg_type && fn.vargs_type) {
                n00b_tc_unify(ctx->tc_ctx, fn.vargs_type, arg_type);
            }

            arg_ix++;
        }

        break;
    }
}

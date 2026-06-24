/**
 * @file unify.c
 * @brief Union-find + structural unification implementation.
 * @ingroup typecheck
 */

#include "typecheck/unify.h"
#include "typecheck/context.h"
#include "typecheck/construct.h"
#include "core/alloc.h"
#include "adt/list.h"
#include "core/string.h"
#include "text/strings/string_ops.h"

// ============================================================================
// Union-find: find with path compression
// ============================================================================

n00b_tc_type_t *
n00b_tc_find(n00b_tc_type_t *t)
{
    if (!t) {
        return t;
    }

    while (t->forward) {
        // Two-step path compression.
        if (t->forward->forward) {
            t->forward = t->forward->forward;
        }
        t = t->forward;
    }

    return t;
}

// ============================================================================
// Predicates
// ============================================================================

bool
n00b_tc_is_var(n00b_tc_type_t *t)
{
    t = n00b_tc_find(t);
    return t && n00b_variant_is_type(t->kind, n00b_tc_var_t);
}

bool
n00b_tc_is_prim(n00b_tc_type_t *t)
{
    t = n00b_tc_find(t);
    return t && n00b_variant_is_type(t->kind, n00b_tc_prim_t);
}

n00b_string_t *
n00b_tc_prim_name(n00b_tc_type_t *t)
{
    t = n00b_tc_find(t);
    auto p = n00b_variant_get(t->kind, n00b_tc_prim_t);
    return p.name;
}

// ============================================================================
// Occurs check
// ============================================================================

// Returns true if `needle` (pointer identity after find) occurs in `haystack`.
static bool
occurs_in(n00b_tc_type_t *needle, n00b_tc_type_t *haystack)
{
    haystack = n00b_tc_find(haystack);

    if (!haystack) {
        return false;
    }

    if (needle == haystack) {
        return true;
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_var_t)) {
        return false; // Unbound var, no recursion.
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_prim_t)) {
        return false;
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_param_t)) {
        auto p = n00b_variant_get(haystack->kind, n00b_tc_param_t);
        size_t len = n00b_list_len(*p.params);

        for (size_t i = 0; i < len; i++) {
            if (occurs_in(needle, n00b_list_get(*p.params, i))) {
                return true;
            }
        }

        return false;
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_fn_t)) {
        auto f = n00b_variant_get(haystack->kind, n00b_tc_fn_t);
        size_t len = n00b_list_len(*f.positional);

        for (size_t i = 0; i < len; i++) {
            if (occurs_in(needle, n00b_list_get(*f.positional, i))) {
                return true;
            }
        }

        if (f.vargs_type && occurs_in(needle, f.vargs_type)) {
            return true;
        }

        if (f.kargs_type && occurs_in(needle, f.kargs_type)) {
            return true;
        }

        if (f.return_type && occurs_in(needle, f.return_type)) {
            return true;
        }

        return false;
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_sum_t)) {
        auto s = n00b_variant_get(haystack->kind, n00b_tc_sum_t);
        size_t len = n00b_list_len(*s.variants);

        for (size_t i = 0; i < len; i++) {
            if (occurs_in(needle, n00b_list_get(*s.variants, i))) {
                return true;
            }
        }

        return false;
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_record_t)) {
        auto r = n00b_variant_get(haystack->kind, n00b_tc_record_t);
        size_t len = n00b_list_len(*r.field_types);

        for (size_t i = 0; i < len; i++) {
            if (occurs_in(needle, n00b_list_get(*r.field_types, i))) {
                return true;
            }
        }

        return false;
    }

    if (n00b_variant_is_type(haystack->kind, n00b_tc_tuple_t)) {
        auto tu = n00b_variant_get(haystack->kind, n00b_tc_tuple_t);
        size_t len = n00b_list_len(*tu.elements);

        for (size_t i = 0; i < len; i++) {
            if (occurs_in(needle, n00b_list_get(*tu.elements, i))) {
                return true;
            }
        }

        return false;
    }

    return false;
}

// ============================================================================
// Error push helpers
// ============================================================================

static void
push_error(n00b_tc_ctx_t *ctx, n00b_tc_err_kind_t kind,
           n00b_tc_type_t *expected, n00b_tc_type_t *got,
           n00b_string_t *message)
{
    n00b_tc_error_t err = {
        .kind     = kind,
        .expected = expected,
        .got      = got,
        .message  = message,
    };

    n00b_list_push(*ctx->errors, err);
}

// ============================================================================
// Constraint checking (when binding a var to a concrete type)
// ============================================================================

static bool
check_constraints(n00b_tc_ctx_t *ctx, n00b_tc_type_t *var_node,
                  n00b_tc_type_t *bound_to)
{
    auto v = n00b_variant_get(var_node->kind, n00b_tc_var_t);

    if (!v.constraints) {
        return true;
    }

    size_t len = n00b_list_len(*v.constraints);

    for (size_t i = 0; i < len; i++) {
        n00b_tc_constraint_t c = n00b_list_get(*v.constraints, i);

        switch (c.selector) {
        case typehash(n00b_tc_con_unifies_t): {
            auto unifies = n00b_variant_get(c, n00b_tc_con_unifies_t);
            if (!n00b_tc_unify(ctx, bound_to, unifies.target)) {
                push_error(ctx, N00B_TC_ERR_CONSTRAINT_FAIL,
                           unifies.target, bound_to,
                           r"Constraint UNIFIES failed");
                return false;
            }
            break;
        }

        case typehash(n00b_tc_con_one_of_t): {
            auto one_of = n00b_variant_get(c, n00b_tc_con_one_of_t);
            bool matched = false;
            size_t nc = n00b_list_len(*one_of.types);

            for (size_t j = 0; j < nc; j++) {
                // Try unification without committing errors.
                // For now, we do a shallow check: if bound_to is a Prim,
                // compare names. Otherwise try structural unification.
                n00b_tc_type_t *candidate = n00b_list_get(*one_of.types, j);
                candidate = n00b_tc_find(candidate);
                n00b_tc_type_t *bt = n00b_tc_find(bound_to);

                if (n00b_tc_is_prim(bt) && n00b_tc_is_prim(candidate)) {
                    if (n00b_unicode_str_eq(n00b_tc_prim_name(bt),
                                             n00b_tc_prim_name(candidate))) {
                        matched = true;
                        break;
                    }
                } else if (bt == candidate) {
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                push_error(ctx, N00B_TC_ERR_CONSTRAINT_FAIL,
                           nullptr, bound_to,
                           r"Constraint ONE_OF: no alternative matched");
                return false;
            }
            break;
        }

        case typehash(n00b_tc_con_promotes_t): {
            auto promotes = n00b_variant_get(c, n00b_tc_con_promotes_t);
            n00b_tc_type_t *target = n00b_tc_find(promotes.target);

            if (!n00b_tc_is_prim(bound_to) || !n00b_tc_is_prim(target)) {
                push_error(ctx, N00B_TC_ERR_CONSTRAINT_FAIL,
                           target, bound_to,
                           r"Constraint PROMOTES: non-primitive types");
                return false;
            }

            if (!n00b_tc_promotes_to(ctx, n00b_tc_prim_name(bound_to),
                                      n00b_tc_prim_name(target))) {
                push_error(ctx, N00B_TC_ERR_CONSTRAINT_FAIL,
                           target, bound_to,
                           r"Constraint PROMOTES: no promotion path");
                return false;
            }
            break;
        }

        case typehash(n00b_tc_con_not_t): {
            auto not_con = n00b_variant_get(c, n00b_tc_con_not_t);
            n00b_tc_type_t *excluded = n00b_tc_find(not_con.excluded);
            n00b_tc_type_t *bt = n00b_tc_find(bound_to);

            if (n00b_tc_is_prim(bt) && n00b_tc_is_prim(excluded)) {
                if (n00b_unicode_str_eq(n00b_tc_prim_name(bt),
                                         n00b_tc_prim_name(excluded))) {
                    push_error(ctx, N00B_TC_ERR_CONSTRAINT_FAIL,
                               excluded, bound_to,
                               r"Constraint NOT: type matched excluded type");
                    return false;
                }
            } else if (bt == excluded) {
                push_error(ctx, N00B_TC_ERR_CONSTRAINT_FAIL,
                           excluded, bound_to,
                           r"Constraint NOT: type matched excluded type");
                return false;
            }
            break;
        }

        // Stubs — always pass for now.
        case typehash(n00b_tc_con_implements_t):
        case typehash(n00b_tc_con_has_field_t):
        case typehash(n00b_tc_con_has_param_t):
            break;
        }
    }

    return true;
}

// ============================================================================
// Core unification
// ============================================================================

bool
n00b_tc_unify(n00b_tc_ctx_t *ctx, n00b_tc_type_t *a, n00b_tc_type_t *b)
{
    a = n00b_tc_find(a);
    b = n00b_tc_find(b);

    if (!a || !b) {
        return false;
    }

    // Same pointer → trivially unified.
    if (a == b) {
        return true;
    }

    // --- Var cases ---

    if (n00b_variant_is_type(a->kind, n00b_tc_var_t)) {
        // Occurs check: a must not appear in b.
        if (occurs_in(a, b)) {
            push_error(ctx, N00B_TC_ERR_OCCURS_CHECK, a, b,
                       r"Infinite type: variable occurs in its own binding");
            return false;
        }

        if (!check_constraints(ctx, a, b)) {
            return false;
        }

        a->forward = b;
        return true;
    }

    if (n00b_variant_is_type(b->kind, n00b_tc_var_t)) {
        if (occurs_in(b, a)) {
            push_error(ctx, N00B_TC_ERR_OCCURS_CHECK, b, a,
                       r"Infinite type: variable occurs in its own binding");
            return false;
        }

        if (!check_constraints(ctx, b, a)) {
            return false;
        }

        b->forward = a;
        return true;
    }

    // --- Both concrete: structural match by kind ---

    // Prim vs Prim
    if (n00b_variant_is_type(a->kind, n00b_tc_prim_t)
        && n00b_variant_is_type(b->kind, n00b_tc_prim_t)) {
        auto ap = n00b_variant_get(a->kind, n00b_tc_prim_t);
        auto bp = n00b_variant_get(b->kind, n00b_tc_prim_t);

        if (n00b_unicode_str_eq(ap.name, bp.name)) {
            b->forward = a; // Merge (arbitrary direction for identical prims).
            return true;
        }

        push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                   r"Cannot unify different primitive types");
        return false;
    }

    // Param vs Param
    if (n00b_variant_is_type(a->kind, n00b_tc_param_t)
        && n00b_variant_is_type(b->kind, n00b_tc_param_t)) {
        auto ap = n00b_variant_get(a->kind, n00b_tc_param_t);
        auto bp = n00b_variant_get(b->kind, n00b_tc_param_t);

        if (!n00b_unicode_str_eq(ap.name, bp.name)) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Cannot unify parameterized types with different constructors");
            return false;
        }

        size_t a_len = n00b_list_len(*ap.params);
        size_t b_len = n00b_list_len(*bp.params);

        if (a_len != b_len) {
            push_error(ctx, N00B_TC_ERR_PARAM_MISMATCH, a, b,
                       r"Parameterized types have different parameter counts");
            return false;
        }

        for (size_t i = 0; i < a_len; i++) {
            if (!n00b_tc_unify(ctx,
                                n00b_list_get(*ap.params, i),
                                n00b_list_get(*bp.params, i))) {
                return false;
            }
        }

        b->forward = a;
        return true;
    }

    // Fn vs Fn
    if (n00b_variant_is_type(a->kind, n00b_tc_fn_t)
        && n00b_variant_is_type(b->kind, n00b_tc_fn_t)) {
        auto af = n00b_variant_get(a->kind, n00b_tc_fn_t);
        auto bf = n00b_variant_get(b->kind, n00b_tc_fn_t);

        size_t a_pos = n00b_list_len(*af.positional);
        size_t b_pos = n00b_list_len(*bf.positional);

        if (a_pos != b_pos) {
            push_error(ctx, N00B_TC_ERR_ARITY_MISMATCH, a, b,
                       r"Function types have different positional parameter counts");
            return false;
        }

        for (size_t i = 0; i < a_pos; i++) {
            if (!n00b_tc_unify(ctx,
                                n00b_list_get(*af.positional, i),
                                n00b_list_get(*bf.positional, i))) {
                return false;
            }
        }

        // Vargs
        if (af.vargs_type && bf.vargs_type) {
            if (!n00b_tc_unify(ctx, af.vargs_type, bf.vargs_type)) {
                return false;
            }
        } else if (af.vargs_type != bf.vargs_type) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Function types disagree on variadic");
            return false;
        }

        // Kargs
        if (af.kargs_type && bf.kargs_type) {
            if (!n00b_tc_unify(ctx, af.kargs_type, bf.kargs_type)) {
                return false;
            }
        } else if (af.kargs_type != bf.kargs_type) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Function types disagree on keyword arguments");
            return false;
        }

        // Return type
        if (af.return_type && bf.return_type) {
            if (!n00b_tc_unify(ctx, af.return_type, bf.return_type)) {
                return false;
            }
        } else if (af.return_type != bf.return_type) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Function types disagree on return type");
            return false;
        }

        b->forward = a;
        return true;
    }

    // Sum vs Sum
    if (n00b_variant_is_type(a->kind, n00b_tc_sum_t)
        && n00b_variant_is_type(b->kind, n00b_tc_sum_t)) {
        auto as = n00b_variant_get(a->kind, n00b_tc_sum_t);
        auto bs = n00b_variant_get(b->kind, n00b_tc_sum_t);

        size_t a_len = n00b_list_len(*as.variants);
        size_t b_len = n00b_list_len(*bs.variants);

        if (a_len != b_len) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Sum types have different variant counts");
            return false;
        }

        for (size_t i = 0; i < a_len; i++) {
            if (!n00b_tc_unify(ctx,
                                n00b_list_get(*as.variants, i),
                                n00b_list_get(*bs.variants, i))) {
                return false;
            }
        }

        b->forward = a;
        return true;
    }

    // Record vs Record
    if (n00b_variant_is_type(a->kind, n00b_tc_record_t)
        && n00b_variant_is_type(b->kind, n00b_tc_record_t)) {
        auto ar = n00b_variant_get(a->kind, n00b_tc_record_t);
        auto br = n00b_variant_get(b->kind, n00b_tc_record_t);

        size_t a_fields = n00b_list_len(*ar.field_names);
        size_t b_fields = n00b_list_len(*br.field_names);

        if (a_fields != b_fields) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Record types have different field counts");
            return false;
        }

        // Match fields by name.
        for (size_t i = 0; i < a_fields; i++) {
            n00b_string_t *a_name = n00b_list_get(*ar.field_names, i);
            bool found = false;

            for (size_t j = 0; j < b_fields; j++) {
                n00b_string_t *b_name = n00b_list_get(*br.field_names, j);

                if (n00b_unicode_str_eq(a_name, b_name)) {
                    if (!n00b_tc_unify(ctx,
                                        n00b_list_get(*ar.field_types, i),
                                        n00b_list_get(*br.field_types, j))) {
                        return false;
                    }
                    found = true;
                    break;
                }
            }

            if (!found) {
                push_error(ctx, N00B_TC_ERR_NO_SUCH_FIELD, a, b,
                           r"Record field not found in other record");
                return false;
            }
        }

        b->forward = a;
        return true;
    }

    // Tuple vs Tuple
    if (n00b_variant_is_type(a->kind, n00b_tc_tuple_t)
        && n00b_variant_is_type(b->kind, n00b_tc_tuple_t)) {
        auto at = n00b_variant_get(a->kind, n00b_tc_tuple_t);
        auto bt = n00b_variant_get(b->kind, n00b_tc_tuple_t);

        size_t a_len = n00b_list_len(*at.elements);
        size_t b_len = n00b_list_len(*bt.elements);

        // For open tuples, unify the common prefix.
        size_t min_len = a_len < b_len ? a_len : b_len;

        if (!at.open && !bt.open && a_len != b_len) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Closed tuples have different lengths");
            return false;
        }

        if (!at.open && b_len > a_len) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Tuple length mismatch");
            return false;
        }

        if (!bt.open && a_len > b_len) {
            push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                       r"Tuple length mismatch");
            return false;
        }

        for (size_t i = 0; i < min_len; i++) {
            if (!n00b_tc_unify(ctx,
                                n00b_list_get(*at.elements, i),
                                n00b_list_get(*bt.elements, i))) {
                return false;
            }
        }

        b->forward = a;
        return true;
    }

    // Kind mismatch.
    push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
               r"Cannot unify types of different kinds");
    return false;
}

// ============================================================================
// Unify or promote
// ============================================================================

bool
n00b_tc_unify_or_promote(n00b_tc_ctx_t *ctx,
                            n00b_tc_type_t *a,
                            n00b_tc_type_t *b)
{
    // Save current error count so we can roll back on promotion fallback.
    size_t err_count = n00b_list_len(*ctx->errors);

    if (n00b_tc_unify(ctx, a, b)) {
        return true;
    }

    // Roll back errors from the failed unification attempt.
    while (n00b_list_len(*ctx->errors) > err_count) {
        ctx->errors->len--;
    }

    // Both must be Prim for promotion.
    a = n00b_tc_find(a);
    b = n00b_tc_find(b);

    if (!n00b_tc_is_prim(a) || !n00b_tc_is_prim(b)) {
        push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
                   r"Cannot unify or promote non-primitive types");
        return false;
    }

    n00b_string_t *a_name = n00b_tc_prim_name(a);
    n00b_string_t *b_name = n00b_tc_prim_name(b);

    // Try a promotes to b.
    if (n00b_tc_promotes_to(ctx, a_name, b_name)) {
        n00b_tc_coercion_t coercion = {
            .kind = N00B_TC_COERCE_PROMOTE,
            .from = a,
            .to   = b,
        };
        n00b_list_push(*ctx->coercions, coercion);
        a->forward = b;
        return true;
    }

    // Try b promotes to a.
    if (n00b_tc_promotes_to(ctx, b_name, a_name)) {
        n00b_tc_coercion_t coercion = {
            .kind = N00B_TC_COERCE_PROMOTE,
            .from = b,
            .to   = a,
        };
        n00b_list_push(*ctx->coercions, coercion);
        b->forward = a;
        return true;
    }

    push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
               r"Cannot unify or promote types");
    return false;
}

// ============================================================================
// Unify with coercion (promotion + ref-deref)
// ============================================================================

bool
n00b_tc_unify_with_coercion(n00b_tc_ctx_t *ctx,
                               n00b_tc_type_t *a,
                               n00b_tc_type_t *b)
{
    // Save error count for rollback.
    size_t err_count = n00b_list_len(*ctx->errors);

    // 1. Try exact unification.
    if (n00b_tc_unify(ctx, a, b)) {
        return true;
    }

    while (n00b_list_len(*ctx->errors) > err_count) {
        ctx->errors->len--;
    }

    // 2. Try promotion.
    a = n00b_tc_find(a);
    b = n00b_tc_find(b);

    if (n00b_tc_is_prim(a) && n00b_tc_is_prim(b)) {
        n00b_string_t *a_name = n00b_tc_prim_name(a);
        n00b_string_t *b_name = n00b_tc_prim_name(b);

        if (n00b_tc_promotes_to(ctx, a_name, b_name)) {
            n00b_tc_coercion_t coercion = {
                .kind = N00B_TC_COERCE_PROMOTE,
                .from = a,
                .to   = b,
            };
            n00b_list_push(*ctx->coercions, coercion);
            a->forward = b;
            return true;
        }

        if (n00b_tc_promotes_to(ctx, b_name, a_name)) {
            n00b_tc_coercion_t coercion = {
                .kind = N00B_TC_COERCE_PROMOTE,
                .from = b,
                .to   = a,
            };
            n00b_list_push(*ctx->coercions, coercion);
            b->forward = a;
            return true;
        }
    }

    // 3. Try ref-deref: if a is ref[T], try unifying T with b.
    a = n00b_tc_find(a);

    if (n00b_variant_is_type(a->kind, n00b_tc_param_t)) {
        auto ap = n00b_variant_get(a->kind, n00b_tc_param_t);

        if (n00b_unicode_str_eq(ap.name, r"ref")
            && n00b_list_len(*ap.params) == 1) {
            n00b_tc_type_t *inner = n00b_list_get(*ap.params, 0);

            if (n00b_tc_unify(ctx, inner, b)) {
                n00b_tc_coercion_t coercion = {
                    .kind = N00B_TC_COERCE_DEREF,
                    .from = a,
                    .to   = b,
                };
                n00b_list_push(*ctx->coercions, coercion);
                return true;
            }
        }
    }

    push_error(ctx, N00B_TC_ERR_UNIFY_FAIL, a, b,
               r"Cannot unify types with any coercion");
    return false;
}

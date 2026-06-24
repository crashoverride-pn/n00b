/**
 * @file print.c
 * @brief Type-to-string rendering implementation.
 *
 * Recursive printer with cycle detection via a visited set on the stack.
 * Uses snprintf + n00b_string_from_cstr for string building, and
 * n00b_unicode_str_cat for concatenation.
 */

#include <stdio.h>
#include <stdarg.h>

#include "typecheck/print.h"
#include "typecheck/context.h"
#include "adt/variant.h"
#include "adt/option.h"
#include "adt/list.h"
#include "core/alloc.h"
#include "text/strings/string_ops.h"

// ============================================================================
// Visited set for cycle detection
// ============================================================================

// Simple stack-allocated visited set (pointer array + count).
// Max nesting depth of 64 should be more than enough for any real type.
#define MAX_VISIT_DEPTH 64

typedef struct {
    n00b_tc_type_t *visited[MAX_VISIT_DEPTH];
    int             count;
} visit_set_t;

static bool
visit_contains(visit_set_t *vs, n00b_tc_type_t *t)
{
    for (int i = 0; i < vs->count; i++) {
        if (vs->visited[i] == t) {
            return true;
        }
    }

    return false;
}

static bool
visit_push(visit_set_t *vs, n00b_tc_type_t *t)
{
    if (vs->count >= MAX_VISIT_DEPTH) {
        return false;
    }

    vs->visited[vs->count++] = t;
    return true;
}

static void
visit_pop(visit_set_t *vs)
{
    if (vs->count > 0) {
        vs->count--;
    }
}

// ============================================================================
// Forward declaration
// ============================================================================

// Follow union-find chain (same as n00b_tc_find but we don't want to
// pull in unify.h just for this).
static n00b_tc_type_t *
tc_find(n00b_tc_type_t *t)
{
    // Guard against self-loops (e.g., in cycle tests).
    int limit = MAX_VISIT_DEPTH;

    while (t->forward && limit-- > 0) {
        if (t->forward == t) {
            // Self-referential — stop here.
            break;
        }

        if (t->forward->forward && t->forward->forward != t->forward) {
            t->forward = t->forward->forward;
        }

        t = t->forward;
    }

    return t;
}

static n00b_string_t *type_to_string_inner(n00b_tc_type_t *type, visit_set_t *vs);

// ============================================================================
// Helper: build string from C format string
// ============================================================================

static n00b_string_t *
str_from_fmt(const char *fmt, ...)
{
    char    buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    return n00b_string_from_cstr(buf);
}

// ============================================================================
// Per-kind printers
// ============================================================================

static n00b_string_t *
print_var(n00b_tc_var_t *var)
{
    if (n00b_option_is_set(var->given_name)) {
        n00b_string_t *name = n00b_option_get(var->given_name);

        return str_from_fmt("`%.*s", (int)name->u8_bytes, name->data);
    }

    return str_from_fmt("`%.*s",
                        (int)var->display_name->u8_bytes,
                        var->display_name->data);
}

static n00b_string_t *
print_prim(n00b_tc_prim_t *prim)
{
    // Return the name directly.
    return prim->name;
}

static n00b_string_t *
print_param(n00b_tc_param_t *param, visit_set_t *vs)
{
    // name[p1, p2, ...]
    n00b_string_t *result = param->name;

    if (param->params && n00b_list_len(*param->params) > 0) {
        result = n00b_unicode_str_cat(result, r"[");

        size_t np = n00b_list_len(*param->params);

        for (size_t i = 0; i < np; i++) {
            if (i > 0) {
                result = n00b_unicode_str_cat(result, r", ");
            }

            n00b_tc_type_t *p = n00b_list_get(*param->params, i);
            n00b_string_t  *ps = type_to_string_inner(p, vs);
            result = n00b_unicode_str_cat(result, ps);
        }

        result = n00b_unicode_str_cat(result, r"]");
    }

    return result;
}

static n00b_string_t *
print_fn(n00b_tc_fn_t *fn, visit_set_t *vs)
{
    n00b_string_t *result = r"(";

    // Positional params.
    if (fn->positional) {
        size_t np = n00b_list_len(*fn->positional);

        for (size_t i = 0; i < np; i++) {
            if (i > 0) {
                result = n00b_unicode_str_cat(result, r", ");
            }

            n00b_tc_type_t *p = n00b_list_get(*fn->positional, i);
            n00b_string_t  *ps = type_to_string_inner(p, vs);
            result = n00b_unicode_str_cat(result, ps);
        }
    }

    // Vargs.
    if (fn->vargs_type) {
        size_t np = fn->positional ? n00b_list_len(*fn->positional) : 0;

        if (np > 0) {
            result = n00b_unicode_str_cat(result, r", ");
        }

        result = n00b_unicode_str_cat(result, r"*");
        n00b_string_t *vs_str = type_to_string_inner(fn->vargs_type, vs);
        result = n00b_unicode_str_cat(result, vs_str);
    }

    // Kargs (Record type, print as **field: type, ...).
    if (fn->kargs_type) {
        n00b_tc_type_t *kt = tc_find(fn->kargs_type);

        if (n00b_variant_is_type(kt->kind, n00b_tc_record_t)) {
            auto rec = n00b_variant_get(kt->kind, n00b_tc_record_t);
            size_t nf = n00b_list_len(*rec.field_names);

            size_t prior = (fn->positional ? n00b_list_len(*fn->positional) : 0)
                         + (fn->vargs_type ? 1 : 0);

            if (prior > 0) {
                result = n00b_unicode_str_cat(result, r", ");
            }

            result = n00b_unicode_str_cat(result, r"**");

            for (size_t i = 0; i < nf; i++) {
                if (i > 0) {
                    result = n00b_unicode_str_cat(result, r", ");
                }

                n00b_string_t *fname = n00b_list_get(*rec.field_names, i);
                n00b_tc_type_t *ft = n00b_list_get(*rec.field_types, i);
                n00b_string_t *fts = type_to_string_inner(ft, vs);

                result = n00b_unicode_str_cat(result, fname);
                result = n00b_unicode_str_cat(result, r": ");
                result = n00b_unicode_str_cat(result, fts);
            }
        }
    }

    result = n00b_unicode_str_cat(result, r") -> ");

    // Return type.
    if (fn->return_type) {
        n00b_string_t *rs = type_to_string_inner(fn->return_type, vs);
        result = n00b_unicode_str_cat(result, rs);
    }
    else {
        result = n00b_unicode_str_cat(result, r"void");
    }

    return result;
}

static n00b_string_t *
print_sum(n00b_tc_sum_t *sum, visit_set_t *vs)
{
    n00b_string_t *result = n00b_string_empty();

    if (sum->variants) {
        size_t nv = n00b_list_len(*sum->variants);

        for (size_t i = 0; i < nv; i++) {
            if (i > 0) {
                result = n00b_unicode_str_cat(result, r" | ");
            }

            n00b_tc_type_t *v = n00b_list_get(*sum->variants, i);
            n00b_string_t  *vs_str = type_to_string_inner(v, vs);
            result = n00b_unicode_str_cat(result, vs_str);
        }
    }

    return result;
}

static n00b_string_t *
print_record(n00b_tc_record_t *rec, visit_set_t *vs)
{
    n00b_string_t *result = n00b_string_empty();

    // Named record: Name{...}
    if (rec->name && rec->name->u8_bytes > 0) {
        result = rec->name;
    }

    result = n00b_unicode_str_cat(result, r"{");

    size_t nf = rec->field_names ? n00b_list_len(*rec->field_names) : 0;

    for (size_t i = 0; i < nf; i++) {
        if (i > 0) {
            result = n00b_unicode_str_cat(result, r", ");
        }

        n00b_string_t *fname = n00b_list_get(*rec->field_names, i);
        result = n00b_unicode_str_cat(result, fname);
        result = n00b_unicode_str_cat(result, r": ");

        n00b_tc_type_t *ft = n00b_list_get(*rec->field_types, i);
        n00b_string_t *fts = type_to_string_inner(ft, vs);
        result = n00b_unicode_str_cat(result, fts);
    }

    if (rec->open) {
        if (nf > 0) {
            result = n00b_unicode_str_cat(result, r", ");
        }

        result = n00b_unicode_str_cat(result, r"...");
    }

    result = n00b_unicode_str_cat(result, r"}");

    return result;
}

static n00b_string_t *
print_tuple(n00b_tc_tuple_t *tup, visit_set_t *vs)
{
    n00b_string_t *result = r"(";

    if (tup->elements) {
        size_t ne = n00b_list_len(*tup->elements);

        for (size_t i = 0; i < ne; i++) {
            if (i > 0) {
                result = n00b_unicode_str_cat(result, r", ");
            }

            n00b_tc_type_t *e = n00b_list_get(*tup->elements, i);
            n00b_string_t  *es = type_to_string_inner(e, vs);
            result = n00b_unicode_str_cat(result, es);
        }
    }

    if (tup->open) {
        size_t ne = tup->elements ? n00b_list_len(*tup->elements) : 0;

        if (ne > 0) {
            result = n00b_unicode_str_cat(result, r", ");
        }

        result = n00b_unicode_str_cat(result, r"...");
    }

    result = n00b_unicode_str_cat(result, r")");

    return result;
}

// ============================================================================
// Core recursive printer
// ============================================================================

static n00b_string_t *
type_to_string_inner(n00b_tc_type_t *type, visit_set_t *vs)
{
    if (!type) {
        return r"<null>";
    }

    // Follow union-find chain.
    type = tc_find(type);

    // Cycle detection.
    if (visit_contains(vs, type)) {
        return r"<cycle>";
    }

    if (!visit_push(vs, type)) {
        return r"<too-deep>";
    }

    n00b_string_t *result;

    if (n00b_variant_is_type(type->kind, n00b_tc_var_t)) {
        auto var = n00b_variant_get(type->kind, n00b_tc_var_t);
        result = print_var(&var);
    }
    else if (n00b_variant_is_type(type->kind, n00b_tc_prim_t)) {
        auto prim = n00b_variant_get(type->kind, n00b_tc_prim_t);
        result = print_prim(&prim);
    }
    else if (n00b_variant_is_type(type->kind, n00b_tc_param_t)) {
        auto param = n00b_variant_get(type->kind, n00b_tc_param_t);
        result = print_param(&param, vs);
    }
    else if (n00b_variant_is_type(type->kind, n00b_tc_fn_t)) {
        auto fn = n00b_variant_get(type->kind, n00b_tc_fn_t);
        result = print_fn(&fn, vs);
    }
    else if (n00b_variant_is_type(type->kind, n00b_tc_sum_t)) {
        auto sum = n00b_variant_get(type->kind, n00b_tc_sum_t);
        result = print_sum(&sum, vs);
    }
    else if (n00b_variant_is_type(type->kind, n00b_tc_record_t)) {
        auto rec = n00b_variant_get(type->kind, n00b_tc_record_t);
        result = print_record(&rec, vs);
    }
    else if (n00b_variant_is_type(type->kind, n00b_tc_tuple_t)) {
        auto tup = n00b_variant_get(type->kind, n00b_tc_tuple_t);
        result = print_tuple(&tup, vs);
    }
    else {
        result = r"<unknown>";
    }

    visit_pop(vs);

    return result;
}

// ============================================================================
// Public API
// ============================================================================

n00b_string_t *
n00b_tc_type_to_string(n00b_tc_type_t *type)
{
    visit_set_t vs = {.count = 0};

    return type_to_string_inner(type, &vs);
}

n00b_string_t *
n00b_tc_constraint_to_string(n00b_tc_constraint_t *con)
{
    if (!con) {
        return r"<null>";
    }

    switch (con->selector) {
    case typehash(n00b_tc_con_implements_t):
        return n00b_variant_get(*con, n00b_tc_con_implements_t).iface_name;

    case typehash(n00b_tc_con_not_t): {
        auto not_con = n00b_variant_get(*con, n00b_tc_con_not_t);
        n00b_string_t *ts = n00b_tc_type_to_string(not_con.excluded);
        return n00b_unicode_str_cat(r"!= ", ts);
    }

    case typehash(n00b_tc_con_unifies_t): {
        auto unifies = n00b_variant_get(*con, n00b_tc_con_unifies_t);
        n00b_string_t *ts = n00b_tc_type_to_string(unifies.target);
        return n00b_unicode_str_cat(r"== ", ts);
    }

    case typehash(n00b_tc_con_one_of_t): {
        auto one_of = n00b_variant_get(*con, n00b_tc_con_one_of_t);
        n00b_string_t *result = r"one_of(";
        size_t        nt     = n00b_list_len(*one_of.types);

        for (size_t i = 0; i < nt; i++) {
            if (i > 0) {
                result = n00b_unicode_str_cat(result, r", ");
            }

            n00b_tc_type_t *t = n00b_list_get(*one_of.types, i);
            result = n00b_unicode_str_cat(result, n00b_tc_type_to_string(t));
        }

        return n00b_unicode_str_cat(result, r")");
    }

    case typehash(n00b_tc_con_has_field_t): {
        auto has_field = n00b_variant_get(*con, n00b_tc_con_has_field_t);
        n00b_string_t *ts = n00b_tc_type_to_string(has_field.field_type);
        n00b_string_t *result = n00b_unicode_str_cat(r"has_field(", has_field.field_name);
        result = n00b_unicode_str_cat(result, r": ");
        result = n00b_unicode_str_cat(result, ts);
        return n00b_unicode_str_cat(result, r")");
    }

    case typehash(n00b_tc_con_has_param_t): {
        auto has_param = n00b_variant_get(*con, n00b_tc_con_has_param_t);
        n00b_string_t *ts = n00b_tc_type_to_string(has_param.param_type);
        return str_from_fmt("has_param(%d, %.*s)",
                            has_param.index,
                            (int)ts->u8_bytes, ts->data);
    }

    case typehash(n00b_tc_con_promotes_t): {
        auto promotes = n00b_variant_get(*con, n00b_tc_con_promotes_t);
        n00b_string_t *ts = n00b_tc_type_to_string(promotes.target);
        return n00b_unicode_str_cat(r"promotes_to ", ts);
    }

    default:
        return r"<unknown-constraint>";
    }
}

n00b_string_t *
n00b_tc_type_to_string_full(n00b_tc_type_t *type)
{
    if (!type) {
        return r"<null>";
    }

    n00b_string_t *base = n00b_tc_type_to_string(type);

    // Follow union-find.
    n00b_tc_type_t *resolved = tc_find(type);

    // Only append where clause for unresolved Vars with constraints.
    if (!n00b_variant_is_type(resolved->kind, n00b_tc_var_t)) {
        return base;
    }

    auto var = n00b_variant_get(resolved->kind, n00b_tc_var_t);

    if (!var.constraints || n00b_list_len(*var.constraints) == 0) {
        return base;
    }

    // Get the var name for the where clause.
    n00b_string_t *var_name;

    if (n00b_option_is_set(var.given_name)) {
        var_name = n00b_option_get(var.given_name);
    }
    else {
        var_name = var.display_name;
    }

    n00b_string_t *result = n00b_unicode_str_cat(base, r" where `");
    result = n00b_unicode_str_cat(result, var_name);
    result = n00b_unicode_str_cat(result, r": ");

    size_t nc = n00b_list_len(*var.constraints);

    for (size_t i = 0; i < nc; i++) {
        if (i > 0) {
            result = n00b_unicode_str_cat(result, r" + ");
        }

        n00b_tc_constraint_t con = n00b_list_get(*var.constraints, i);
        n00b_string_t *cs = n00b_tc_constraint_to_string(&con);
        result = n00b_unicode_str_cat(result, cs);
    }

    return result;
}

/**
 * @file asp_types.h
 * @brief Core types for the Datalog engine.
 *
 * Defines symbol IDs, relation IDs, expression trees, builtin
 * constraints, literals, body goals, and rules — the fundamental
 * building blocks of the Datalog data model.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "adt/variant.h"

// ============================================================================
// Symbol IDs
// ============================================================================

/**
 * @brief Interned symbol identifier.
 *
 * Non-negative values represent constants (atoms, integers).
 * Values at or below @ref N00B_DL_VAR_BASE represent logic variables.
 */
typedef int64_t n00b_dl_sym_t;

/**
 * @brief Relation identifier (index into the engine's relation array).
 */
typedef int32_t n00b_dl_rel_id_t;

/** Sentinel for an invalid or missing symbol. */
#define N00B_DL_SYM_INVALID ((n00b_dl_sym_t)-1)

/**
 * @brief Base value for logic variable IDs.
 *
 * Variable IDs are assigned downward from this value.
 */
#define N00B_DL_VAR_BASE ((n00b_dl_sym_t)(INT64_MIN / 2))

/**
 * @brief Test whether a symbol is a logic variable.
 *
 * @param s Symbol to test.
 * @return `true` if @p s is a variable (ID <= N00B_DL_VAR_BASE).
 */
static inline bool
n00b_dl_is_var(n00b_dl_sym_t s)
{
    return s <= N00B_DL_VAR_BASE;
}

// ============================================================================
// Expression trees (for arithmetic builtins)
// ============================================================================

typedef enum {
    N00B_DL_EXPR_SYM, /**< Leaf: variable or constant. */
    N00B_DL_EXPR_INT, /**< Leaf: literal integer. */
    N00B_DL_EXPR_ADD, /**< Binary: left + right. */
    N00B_DL_EXPR_SUB, /**< Binary: left - right. */
    N00B_DL_EXPR_MUL, /**< Binary: left * right. */
    N00B_DL_EXPR_DIV, /**< Binary: left / right (integer division). */
    N00B_DL_EXPR_MOD, /**< Binary: left % right. */
    N00B_DL_EXPR_NEG, /**< Unary: -operand. */
} n00b_dl_expr_kind_t;

typedef struct n00b_dl_expr n00b_dl_expr_t;
struct n00b_dl_expr {
    n00b_dl_expr_kind_t kind;
    union [[n00b::raw_union]] {
        n00b_dl_sym_t sym;
        int64_t       int_val;
        struct {
            n00b_dl_expr_t *left;
            n00b_dl_expr_t *right;
        } bin;
        n00b_dl_expr_t *operand;
    };
};

// ============================================================================
// Builtin constraints
// ============================================================================

typedef enum {
    N00B_DL_BUILTIN_IS, /**< X is \<expr\> */
    N00B_DL_BUILTIN_LT, /**< \<expr\> < \<expr\> */
    N00B_DL_BUILTIN_GT, /**< \<expr\> > \<expr\> */
    N00B_DL_BUILTIN_LE, /**< \<expr\> <= \<expr\> */
    N00B_DL_BUILTIN_GE, /**< \<expr\> >= \<expr\> */
    N00B_DL_BUILTIN_EQ, /**< \<expr\> = \<expr\> (arithmetic equality) */
    N00B_DL_BUILTIN_NE, /**< \<expr\> != \<expr\> */
} n00b_dl_builtin_kind_t;

typedef struct {
    n00b_dl_builtin_kind_t kind;
    n00b_dl_expr_t        *lhs;
    n00b_dl_expr_t        *rhs;
} n00b_dl_builtin_t;

// ============================================================================
// Literals and rules
// ============================================================================

typedef struct {
    n00b_dl_rel_id_t rel;
    int32_t          arity;
    n00b_dl_sym_t   *args;
    bool             negated;
} n00b_dl_literal_t;

typedef n00b_variant_t(n00b_dl_literal_t,
                       n00b_dl_builtin_t) n00b_dl_body_goal_t;

typedef struct {
    n00b_dl_literal_t    head;
    n00b_dl_body_goal_t *body;
    int32_t              body_len;
    int32_t              stratum;
} n00b_dl_rule_t;

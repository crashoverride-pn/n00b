/**
 * @file clpfd_types.h
 * @brief Core types for the constraint satisfaction solver.
 *
 * Defines variable IDs, domain kinds, constraint kinds, and the
 * fundamental data structures for finite-domain constraint solving.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "adt/variant.h"
#include "core/string.h"

/**
 * @brief Constraint variable identifier.
 */
typedef int32_t n00b_csp_var_id_t;

/**
 * @brief Contiguous domain [lo, hi].
 */
typedef struct {
    int64_t lo;
    int64_t hi;
} n00b_csp_dom_interval_t;

/**
 * @brief Small domain (<=64 values), represented as a bitmap.
 */
typedef struct {
    int64_t  base; /**< Lowest possible value. */
    uint64_t bits; /**< Bitmask: bit i set => base+i is in domain. */
} n00b_csp_dom_bitset_t;

/**
 * @brief Arbitrary sorted int array domain.
 */
typedef struct {
    int64_t *values; /**< Sorted array of values. */
    int32_t  count;  /**< Number of values. */
    int32_t  cap;    /**< Capacity of values array. */
} n00b_csp_dom_sparse_t;

/**
 * @brief Finite domain (tagged union of interval/bitset/sparse).
 *
 * The empty domain (failure) is the unset variant: `selector == 0`,
 * i.e. `n00b_variant_empty(n00b_csp_domain_t)`.
 */
typedef n00b_variant_t(n00b_csp_dom_interval_t,
                       n00b_csp_dom_bitset_t,
                       n00b_csp_dom_sparse_t) n00b_csp_domain_t;

/**
 * @brief Constraint kind.
 */
typedef enum {
    N00B_CSP_CON_EQ,       /**< X = Y */
    N00B_CSP_CON_EQ_CONST, /**< X = c */
    N00B_CSP_CON_NE,       /**< X != Y */
    N00B_CSP_CON_LT,       /**< X < Y */
    N00B_CSP_CON_LE,       /**< X <= Y */
    N00B_CSP_CON_IN,       /**< X in D */
    N00B_CSP_CON_LINEAR,   /**< a1*X1 + a2*X2 + ... = c */
    N00B_CSP_CON_ALLDIFF,  /**< all_different(X1, X2, ...) */
} n00b_csp_con_kind_t;

/**
 * @brief A constraint in the store.
 */
typedef struct {
    n00b_csp_con_kind_t  kind;
    n00b_csp_var_id_t   *vars;      /**< Variables involved. */
    int32_t              var_count;
    int64_t             *coeffs;    /**< LINEAR: coefficients (one per var). */
    int64_t              constant;  /**< LINEAR: RHS constant; EQ_CONST: value. */
    n00b_csp_domain_t    in_domain; /**< IN: target domain. */
    bool                 entailed;  /**< True if constraint permanently satisfied. */
    bool                 failed;    /**< True if constraint cannot be satisfied. */
} n00b_csp_constraint_t;

/**
 * @brief A constraint variable.
 */
typedef struct {
    n00b_csp_var_id_t  id;
    n00b_string_t     *name;   /**< Variable name. */
    n00b_csp_domain_t  domain;
    bool               ground; /**< True if domain is singleton. */
    int64_t            value;  /**< Value if ground. */
} n00b_csp_var_t;


/**
 * @file clpfd_domain.h
 * @brief Domain operations for the constraint satisfaction solver.
 *
 * Provides construction, query, and narrowing operations on finite
 * domains. Supports interval, bitset, and sparse representations
 * with automatic promotion when holes appear.
 */
#pragma once

#include "logic/clpfd_types.h"

// ============================================================================
// Construction
// ============================================================================

/**
 * @brief Create an interval domain [lo, hi].
 * @param lo Lower bound.
 * @param hi Upper bound.
 * @return   Domain representing [lo, hi], or empty if lo > hi.
 */
n00b_csp_domain_t n00b_csp_dom_range(int64_t lo, int64_t hi);

/**
 * @brief Create a singleton domain {val}.
 * @param val The single value.
 */
n00b_csp_domain_t n00b_csp_dom_singleton(int64_t val);

/**
 * @brief Create a domain from an array of values.
 *
 * Values need not be sorted; duplicates are removed. The
 * representation (interval/bitset/sparse) is chosen automatically.
 *
 * @param vals   Array of integer values.
 * @param count  Number of values.
 */
n00b_csp_domain_t n00b_csp_dom_from_values(const int64_t *vals, int32_t count);

/**
 * @brief Create an empty domain.
 */
n00b_csp_domain_t n00b_csp_dom_empty(void);

/**
 * @brief Clone a domain (deep copy).
 * @param d Domain to clone.
 */
n00b_csp_domain_t n00b_csp_dom_clone(const n00b_csp_domain_t *d);

/**
 * @brief Free domain resources (sparse array).
 * @param d Domain to free.
 * @post   Domain is set to the empty variant (selector == 0).
 */
void n00b_csp_dom_free(n00b_csp_domain_t *d);

// ============================================================================
// Queries
// ============================================================================

/**
 * @brief Get the minimum value in the domain.
 * @pre Domain is not empty.
 */
int64_t n00b_csp_dom_min(const n00b_csp_domain_t *d);

/**
 * @brief Get the maximum value in the domain.
 * @pre Domain is not empty.
 */
int64_t n00b_csp_dom_max(const n00b_csp_domain_t *d);

/**
 * @brief Get the number of values in the domain.
 */
int64_t n00b_csp_dom_size(const n00b_csp_domain_t *d);

/**
 * @brief Test whether the domain has exactly one value.
 */
bool n00b_csp_dom_is_singleton(const n00b_csp_domain_t *d);

/**
 * @brief Test whether the domain is empty.
 */
bool n00b_csp_dom_is_empty(const n00b_csp_domain_t *d);

/**
 * @brief Test whether the domain contains a specific value.
 * @param d   Domain to test.
 * @param val Value to look for.
 */
bool n00b_csp_dom_contains(const n00b_csp_domain_t *d, int64_t val);

// ============================================================================
// Narrowing (return true if domain changed)
// ============================================================================

/**
 * @brief Intersect domain d with another domain.
 * @param d     Domain to narrow (modified in place).
 * @param other Domain to intersect with.
 * @return      true if d changed (was narrowed).
 */
bool n00b_csp_dom_intersect(n00b_csp_domain_t *d, const n00b_csp_domain_t *other);

/**
 * @brief Remove a single value from the domain.
 * @param d   Domain to modify.
 * @param val Value to remove.
 * @return    true if d changed.
 */
bool n00b_csp_dom_remove_value(n00b_csp_domain_t *d, int64_t val);

/**
 * @brief Restrict the minimum value of the domain.
 * @param d       Domain to modify.
 * @param new_min New minimum bound.
 * @return        true if d changed.
 */
bool n00b_csp_dom_restrict_min(n00b_csp_domain_t *d, int64_t new_min);

/**
 * @brief Restrict the maximum value of the domain.
 * @param d       Domain to modify.
 * @param new_max New maximum bound.
 * @return        true if d changed.
 */
bool n00b_csp_dom_restrict_max(n00b_csp_domain_t *d, int64_t new_max);

/**
 * @file internal/rocs/filter.h
 * @brief Internal rocs filter-to-planner lowering declarations.
 *
 * This header is internal to rocs. It bridges the public, store-independent
 * filter builder surface to the WP-006 internal planner predicate tree without
 * making <rocs/filter.h> depend on stores, query execution, or planner headers.
 */
#pragma once

#include "adt/result.h"
#include "core/alloc.h"
#include "internal/rocs/plan.h"
#include "rocs/filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Lower a checked public filter predicate into an internal planner tree.
 *
 * @param filter Borrowed checked public filter predicate.
 * @kw allocator Allocator for the returned planner predicate tree and helper
 *               lists/targets/paths.
 * @return Ok(planner predicate) on success, @c N00B_FILTER_ERR_ARG for null
 *         input, @c N00B_FILTER_ERR_STATE for malformed public filter state or
 *         planner-constructor failures, and @c N00B_FILTER_ERR_UNSUPPORTED for
 *         public value payloads that cannot be represented by the current
 *         JSON-node-based planner value contract.
 *
 * Lowering is store-independent. Named fields lower to field targets, the
 * public any-field identity lowers to an internal any target only for
 * @c contains, paths lower component-by-component without parsing strings, and
 * empty public @c IN lowers to an internal always-false predicate rather than
 * calling the planner's non-empty @c IN constructor.
 */
extern n00b_result_t(n00b_plan_predicate_t *)
n00b_filter_lower_to_plan(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

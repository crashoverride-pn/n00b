/**
 * @file layout.h
 * @brief One-dimensional constraint-based layout engine.
 *
 * Provides a reusable 1D layout solver for distributing space among
 * a set of items with min/max/preferred size constraints, priority-based
 * allocation, and flex-proportional growth.
 *
 * ### Algorithm
 *
 * 1. Resolve percentage dimensions to absolute values against `available`.
 * 2. Assign each item its `min` (or `pref` if larger). Compute leftover.
 * 3. If space remains, grow items toward their `max`, smallest-first.
 * 4. Any remaining space is distributed proportionally by `flex_multiple`
 *    among items without a `max` constraint.
 * 5. If total exceeds `available`, shrink flex items first (largest-first
 *    toward `min`), then squeeze rigid items.
 * 6. If still over, force-crop by ascending priority (lowest priority
 *    items lose their allocation first).
 *
 * ### Usage
 *
 * ```c
 * n00b_layout_t items[3] = {
 *     { .min = { .value.i = 10 }, .pref = { .value.i = 20 } },
 *     { .min = { .value.i = 5 },  .flex_multiple = 2 },
 *     { .pref = { .value.i = 15 }, .max = { .value.i = 30 } },
 * };
 * n00b_layout_result_t results[3];
 * n00b_layout_calculate(items, results, 3, 80);
 * // results[i].size now holds the computed size for each item.
 * ```
 *
 * ### Related modules
 *
 * - `render/plane.h` — uses layout for child plane sizing
 * - `render/canvas.h` — orchestrates layout before compositing
 *
 * @note This is a flat-array API (no tree). Hierarchical layout is
 *       achieved by calling `n00b_layout_calculate()` recursively at
 *       each nesting level.
 */
#pragma once

#include "n00b.h"
#include "adt/array.h"

// ====================================================================
// Layout dimension
// ====================================================================

/**
 * @brief A dimension that can be absolute (cells/pixels) or percentage.
 *
 * When `pct` is false, `value.i` holds an absolute cell/pixel count.
 * When `pct` is true, `value.d` holds a fraction (0.0–1.0) of the
 * parent's available space.
 */
typedef struct {
    union [[n00b::raw_union]] {
        int64_t i;
        double  d;
    } value;
    bool pct;
} n00b_layout_dim_t;

// ====================================================================
// Per-item layout constraints
// ====================================================================

/**
 * @brief Constraints for a single item in a 1D layout.
 *
 * @pre `min <= pref <= max` when all three are set (absolute).
 *      Violations are clamped silently.
 */
typedef struct {
    n00b_layout_dim_t min;           /**< Minimum size (0 = unconstrained). */
    n00b_layout_dim_t max;           /**< Maximum size (0 = unconstrained). */
    n00b_layout_dim_t pref;          /**< Preferred size (0 = use min). */
    int64_t           priority;      /**< Higher = allocated first. */
    int64_t           flex_multiple; /**< Relative share of leftover space (0 = rigid). */
    int64_t           child_gap;     /**< Spacing between children (for container items). */
} n00b_layout_t;

// ====================================================================
// Layout result
// ====================================================================

/**
 * @brief Output of layout calculation for one item.
 *
 * After `n00b_layout_calculate()`, `size` holds the final computed
 * allocation.  The `computed_*` fields hold the resolved absolute
 * values of the input constraints.
 */
typedef struct {
    int64_t computed_min;  /**< Resolved absolute minimum. */
    int64_t computed_max;  /**< Resolved absolute maximum. */
    int64_t computed_pref; /**< Resolved absolute preferred. */
    int64_t size;          /**< **Output**: final computed size. */
} n00b_layout_result_t;


// ====================================================================
// API
// ====================================================================

/**
 * @brief Resolve a dimension spec against a total available size.
 *
 * @param dim       Dimension specification.
 * @param available Total available space for percentage resolution.
 * @return          Absolute size in cells/pixels.
 */
static inline int64_t
n00b_layout_resolve_dim(const n00b_layout_dim_t *dim, int64_t available)
{
    if (!dim->pct) {
        return dim->value.i;
    }
    return (int64_t)(dim->value.d * available + 0.5);
}

/**
 * @brief Calculate 1D layout for items within `available` space.
 *
 * @param items     Array of constraint descriptors (read-only).
 * @param results   Array of result slots (written on output).
 *                  Must have the same length as @p items.
 * @param available Total space to distribute among items.
 *
 * @pre  @p items.len == @p results.len.
 * @post `n00b_array_get(results, i).size` holds the final allocation
 *       for each item.  The sum of all sizes equals `available` (or
 *       less if all items hit their maximums).
 */
extern void n00b_layout_calculate(n00b_array_t(n00b_layout_t)        items,
                                   n00b_array_t(n00b_layout_result_t) results,
                                   int64_t                            available);

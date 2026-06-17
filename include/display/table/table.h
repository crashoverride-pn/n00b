/**
 * @file table.h
 * @brief Table construction, layout, rendering, and streaming API.
 *
 * `n00b_table_t` provides a high-level abstraction for building styled
 * tables with automatic column layout, content wrapping, and rendering
 * to an `n00b_plane_t` cell grid.  Tables support column spans, style
 * cascading, named style presets, and optional streaming with automatic
 * row ejection (ring buffer).
 *
 * ### Construction flow
 *
 * ```c
 * n00b_table_t *t = n00b_table_new(.num_cols = 3);
 * n00b_table_col_flex(t, 2);  // Column 0: flex 2
 * n00b_table_col_fit(t);      // Column 1: fit to content
 * n00b_table_col_fixed(t, 20); // Column 2: fixed 20
 *
 * n00b_table_add_cell(t, header_str);
 * n00b_table_add_cell(t, header_str2);
 * n00b_table_add_cell(t, header_str3);
 * n00b_table_end_row(t);
 * // ... more rows ...
 * n00b_table_end(t);
 *
 * n00b_plane_t *p = n00b_table_render(t);
 * ```
 *
 * ### Style cascade
 *
 * Cell style resolved (first non-null wins):
 * 1. `cell->cell_props`
 * 2. `col_spec->col_props`
 * 3. Row-based: `header_props` (row 0), `alt_cell_props` (odd rows)
 * 4. `default_cell_props`
 *
 * ### Streaming
 *
 * Set `max_rows > 0` at construction to enable a ring buffer that
 * automatically ejects the oldest row when full.
 *
 * ### Related modules
 *
 * - `table/types.h` — cell, row, column spec, style preset types
 * - `core/layout.h` — 1D constraint layout solver
 * - `render/plane.h` — output plane
 * - `render/box.h` — box stamping for outer border
 */
#pragma once

#include "n00b.h"
#include "display/table/types.h"
#include "display/render/plane.h"

// ====================================================================
// Table structure
// ====================================================================

typedef struct n00b_table_t {
    // --- Content ---
    n00b_list_t(n00b_table_row_t)      rows;
    n00b_table_row_t                   current_row;  /**< Row being built. */

    // --- Columns ---
    n00b_list_t(n00b_table_col_spec_t) col_specs;
    bool                               cols_locked; /**< After first row finalized. */

    // --- Styling ---
    n00b_box_props_t      *table_props;       /**< Outer box. */
    n00b_box_props_t      *default_cell_props; /**< Default cell style. */
    n00b_box_props_t      *header_props;       /**< Row 0 override. */
    n00b_box_props_t      *alt_cell_props;     /**< Odd-row style. */

    n00b_string_t         *title;   /**< Empty string if unused. */
    n00b_string_t         *caption; /**< Empty string if unused. */
    bool                   wrap;    /**< Table-level wrap default (true). */

    // --- Layout cache ---
    n00b_layout_result_t  *col_results;
    int64_t               *row_heights;
    int64_t                total_width;
    bool                   layout_valid;

    // --- Streaming (ring buffer) ---
    n00b_isize_t           ring_base;   /**< Oldest row index in ring. */
    n00b_isize_t           max_rows;    /**< Max retained rows (0 = unlimited). */
    n00b_isize_t           total_added; /**< Lifetime row count. */

    // --- Output ---
    n00b_plane_t          *plane; /**< Owned, created on render. */

    n00b_rwlock_t         *lock;
    n00b_allocator_t      *allocator;
} n00b_table_t;

// ====================================================================
// Construction / destruction
// ====================================================================

/**
 * @brief Initialize a pre-allocated table.
 *
 * @param table Table to initialize.
 *
 * @kw num_cols    Number of columns (0 = auto-detect from first row).
 * @kw style       Style preset (overrides individual `*_props` kargs
 *                 when set; individual kargs still override the preset).
 *                 When NEITHER `style` NOR any `*_props` karg is given, the
 *                 default theme (`n00b_table_style_default()`) is applied, so
 *                 a bare `n00b_table_new(...)` is themed out of the box.
 * @kw table_props Outer box style (nullptr = no outer border).
 * @kw cell_props  Default cell style (nullptr = no decoration).
 * @kw header_props Row 0 style override.
 * @kw alt_props   Alternating (odd) row style override.
 * @kw title       Table title (nullptr = none).
 * @kw caption     Table caption (nullptr = none).
 * @kw max_rows    Max retained rows (0 = unlimited; >0 = ring buffer).
 * @kw wrap        Table-level wrap default (true = word-wrap cell content).
 * @kw allocator   Allocator for internal allocations (nullptr = runtime default).
 *
 * @post Table is ready for cell insertion.
 */
extern void
n00b_table_init(n00b_table_t *table) _kargs
{
    n00b_isize_t        num_cols    = 0;
    n00b_table_style_t *style       = nullptr;
    n00b_box_props_t   *table_props = nullptr;
    n00b_box_props_t   *cell_props  = nullptr;
    n00b_box_props_t   *header_props = nullptr;
    n00b_box_props_t   *alt_props   = nullptr;
    n00b_string_t      *title       = nullptr;
    n00b_string_t      *caption     = nullptr;
    n00b_isize_t        max_rows    = 0;
    bool                wrap        = true;
    n00b_allocator_t   *allocator   = nullptr;
};

/**
 * @brief Destroy a table and all owned resources.
 * @param table Table to destroy.
 * @pre   Table is not referenced by any canvas.
 */
extern void n00b_table_destroy(n00b_table_t *table);

// ====================================================================
// Cell / row insertion
// ====================================================================

/**
 * @brief Add a cell with content to the current row.
 *
 * @param table   Table to modify.
 * @param content Cell content string.
 *
 * @kw col_span   Columns to span (1 = normal, -1 = span all remaining).
 * @kw row_span   Rows to span (must be 1 for now).
 * @kw cell_props Per-cell style override (nullptr = cascade).
 * @kw wrap       Per-cell wrap override (`N00B_TRI_UNSPECIFIED` = inherit
 *                from table, `N00B_TRI_YES` = force wrap,
 *                `N00B_TRI_NO` = no wrap / truncate).
 *
 * @pre `row_span == 1` (asserted).
 */
extern void
n00b_table_add_cell(n00b_table_t *table, n00b_string_t *content) _kargs
{
    int32_t           col_span   = 1;
    int32_t           row_span   = 1;
    n00b_box_props_t *cell_props = nullptr;
    n00b_tristate_t   wrap       = N00B_TRI_UNSPECIFIED;
};

/**
 * @brief Add an empty (blank) cell to the current row.
 * @param table Table to modify.
 */
extern void n00b_table_empty_cell(n00b_table_t *table);

/**
 * @brief Finalize the current row and add it to the table.
 *
 * If this is the first row, auto-detects the column count
 * (unless it was set at construction).  For subsequent rows,
 * pads with empty cells or truncates to match the column count.
 *
 * @param table Table to modify.
 *
 * @post `current_row` is reset for the next row.
 *       Layout is invalidated.
 */
extern void n00b_table_end_row(n00b_table_t *table);

/**
 * @brief Add a complete row of strings.
 * @param table Table to modify.
 * @param cells Array of content strings.
 */
extern void n00b_table_add_row(n00b_table_t *table,
                                n00b_array_t(n00b_string_t *) cells);

/**
 * @brief Finalize the table (flushes any partially built row).
 * @param table Table to finalize.
 */
extern void n00b_table_end(n00b_table_t *table);

// ====================================================================
// Column specification
// ====================================================================

/**
 * @brief Add a FIT column (sized from content).
 * @param table Table.
 * @return Index of the new column.
 *
 * @pre Must be called before the first row is finalized (i.e., before
 *      the first `n00b_table_end_row()` call).
 */
extern n00b_isize_t n00b_table_col_fit(n00b_table_t *table);

/**
 * @brief Add a FLEX column with the given growth factor.
 * @param table  Table.
 * @param factor Flex multiple (1 = 1 share, 2 = 2 shares, etc.).
 * @return Index of the new column.
 *
 * @pre Must be called before the first row is finalized (i.e., before
 *      the first `n00b_table_end_row()` call).
 */
extern n00b_isize_t n00b_table_col_flex(n00b_table_t *table, int64_t factor);

/**
 * @brief Add a FIT column with absolute min/max constraints.
 * @param table Table.
 * @param min   Minimum width in cells.
 * @param max   Maximum width in cells.
 * @return Index of the new column.
 *
 * @pre Must be called before the first row is finalized (i.e., before
 *      the first `n00b_table_end_row()` call).
 */
extern n00b_isize_t n00b_table_col_range(n00b_table_t *table,
                                           int64_t min, int64_t max);

/**
 * @brief Add a FIT column with percentage min/max constraints.
 * @param table Table.
 * @param min   Minimum as fraction of table width (0.0–1.0).
 * @param max   Maximum as fraction of table width (0.0–1.0).
 * @return Index of the new column.
 *
 * @pre Must be called before the first row is finalized (i.e., before
 *      the first `n00b_table_end_row()` call).
 */
extern n00b_isize_t n00b_table_col_pct(n00b_table_t *table,
                                         double min, double max);

/**
 * @brief Add a FIXED-width column.
 * @param table Table.
 * @param width Exact width in cells.
 * @return Index of the new column.
 *
 * @pre Must be called before the first row is finalized (i.e., before
 *      the first `n00b_table_end_row()` call).
 */
extern n00b_isize_t n00b_table_col_fixed(n00b_table_t *table, int64_t width);

/**
 * @brief Set the shrinking priority for a column.
 * @param table    Table.
 * @param col      Column index.
 * @param priority Higher = kept during shrinking.
 *
 * @pre `col < n00b_list_len(table->col_specs)`.
 * @post Layout is invalidated.
 */
extern void n00b_table_set_col_priority(n00b_table_t *table,
                                          n00b_isize_t col, int64_t priority);

/**
 * @brief Set per-column style properties.
 * @param table     Table.
 * @param col       Column index.
 * @param col_props Style to apply (nullptr to clear).
 *
 * @pre `col < n00b_list_len(table->col_specs)`.
 * @post Layout is invalidated.
 */
extern void n00b_table_set_col_props(n00b_table_t *table,
                                       n00b_isize_t col,
                                       n00b_box_props_t *col_props);

// ====================================================================
// Rendering
// ====================================================================

/**
 * @brief Render the table into a plane.
 *
 * Creates (or reuses) an `n00b_plane_t` containing the fully rendered
 * table: outer border, interior borders, cell content, title, and caption.
 *
 * @param table Table to render.
 *
 * @kw width Available width in cells (default: 0 = auto-detect the current
 *           terminal width, falling back to 80 when stdout is not a tty).
 * @kw force If true, re-render even if layout is cached.
 *
 * @return Plane owned by the table (do not destroy separately).
 *         The same plane is reused across renders — previous return
 *         values become stale after a subsequent call to this function.
 */
extern n00b_plane_t *
n00b_table_render(n00b_table_t *table) _kargs
{
    int64_t width = 0;
    bool    force = false;
};

/**
 * @brief Invalidate the cached layout, forcing re-computation on next render.
 * @param table Table.
 */
extern void n00b_table_invalidate(n00b_table_t *table);

// ====================================================================
// Style presets
// ====================================================================

/**
 * @brief Rounded borders, interior lines, 1-cell padding.
 */
extern n00b_table_style_t n00b_table_style_default(void);

/**
 * @brief Top/bottom borders only, no interior lines.
 */
extern n00b_table_style_t n00b_table_style_simple(void);

/**
 * @brief Double borders, interior lines, alternating row colors.
 */
extern n00b_table_style_t n00b_table_style_ornate(void);

/**
 * @brief No borders, just alignment.
 */
extern n00b_table_style_t n00b_table_style_minimal(void);

/**
 * @brief ASCII-only borders (-, |, +).
 */
extern n00b_table_style_t n00b_table_style_ascii(void);

// ====================================================================
// Convenience constructors
// ====================================================================

/**
 * @brief Build a table by splitting a string on row/column delimiters.
 *
 * Splits @p s on @p row_sep (default `"\n"`), then each row on
 * @p col_sep (default `","`).  Trailing empty rows (e.g. from a
 * trailing newline) are skipped.
 *
 * @param s  The delimited input string.
 *
 * @kw row_sep      Row separator (nullptr → `"\n"`).
 * @kw col_sep      Column separator (nullptr → `","`).
 * @kw table_props  Outer box style (forwarded to `n00b_table_new()`).
 * @kw cell_props   Default cell style.
 * @kw header_props Row 0 style override.
 * @kw alt_props    Alternating row style override.
 * @kw no_stripe    When true, ignore @p alt_props (no alternating rows).
 * @kw allocator    Allocator (nullptr → runtime default).
 *
 * @return A fully populated table, ready for `n00b_table_render()`.
 *
 * @note If @p s is empty, the resulting table has 0 rows and
 *       `n00b_table_render()` will return nullptr.
 *
 * @post The table has been finalized via `n00b_table_end()`.
 */
extern n00b_table_t *
n00b_table_from_string(n00b_string_t *s) _kargs
{
    n00b_string_t    *row_sep      = nullptr;
    n00b_string_t    *col_sep      = nullptr;
    n00b_box_props_t *table_props  = nullptr;
    n00b_box_props_t *cell_props   = nullptr;
    n00b_box_props_t *header_props = nullptr;
    n00b_box_props_t *alt_props    = nullptr;
    bool              no_stripe    = false;
    n00b_allocator_t *allocator    = nullptr;
};

/**
 * @brief Create a single-cell bordered callout box.
 * @param content The callout text.
 * @return A ready-to-render table.
 */
extern n00b_table_t *n00b_table_callout(n00b_string_t *content);

/**
 * @brief Create a single-row horizontal flow of items.
 * @param items  Array of strings.
 * @param n      Number of items.
 * @return A ready-to-render table.
 */
extern n00b_table_t *n00b_table_flow(n00b_array_t(n00b_string_t *) items);

// ====================================================================
// Internal (cross-module) entry points
// ====================================================================

/**
 * @brief Compute column widths and row heights.
 * @param table Table.
 * @param width Available width.
 *
 * @post `table->col_results` and `table->row_heights` are valid.
 *       `table->layout_valid` is set to true.
 */
extern void _n00b_table_compute_layout(n00b_table_t *table, int64_t width);

/**
 * @brief Resolve the effective box properties for a cell.
 * @param table    Table.
 * @param row_idx  Row index (for header/alt detection).
 * @param col_idx  Column index (for column style).
 * @param cell     Cell (for per-cell override).
 * @return Effective box properties (never nullptr; falls back to a default).
 */
extern const n00b_box_props_t *
_n00b_table_resolve_cell_props(const n00b_table_t      *table,
                                n00b_isize_t             row_idx,
                                n00b_isize_t             col_idx,
                                const n00b_table_cell_t *cell);

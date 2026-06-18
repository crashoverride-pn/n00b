/*
 * Table construction, destruction, cell/row insertion, and column spec API.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "core/data_lock.h"
#include "core/arena.h"
#include "text/strings/string_ops.h"
#include "display/table/table.h"

#include <assert.h>

// ====================================================================
// Internal: default box props (fallback for style cascade)
// ====================================================================

static n00b_box_props_t _default_cell_props = {
    .border_theme = nullptr,
    .borders      = N00B_BORDER_NONE,
    .alignment    = N00B_ALIGN_TOP_LEFT,
    .pad_left     = 1,
    .pad_right    = 1,
};

static n00b_isize_t
add_col_spec(n00b_table_t *table, n00b_table_col_spec_t spec)
{
    assert(!table->cols_locked
           && "cannot add column specs after first row");

    n00b_list_push(table->col_specs, spec);

    return (n00b_isize_t)table->col_specs.len - 1;
}

// Count how many logical columns the current row's cells consume.
static n00b_isize_t
current_row_col_count(n00b_table_t *table)
{
    n00b_isize_t count = 0;
    size_t       n     = table->current_row.cells.len;

    for (size_t i = 0; i < n; i++) {
        int32_t span = table->current_row.cells.data[i].col_span;
        count += (span > 0) ? (n00b_isize_t)span : 1;
    }

    return count;
}

// ====================================================================
// Construction / destruction
// ====================================================================

void
n00b_table_init(n00b_table_t *table) _kargs
{
    n00b_isize_t        num_cols     = 0;
    n00b_table_style_t *style        = nullptr;
    n00b_box_props_t   *table_props  = nullptr;
    n00b_box_props_t   *cell_props   = nullptr;
    n00b_box_props_t   *header_props = nullptr;
    n00b_box_props_t   *alt_props    = nullptr;
    n00b_string_t      *title        = nullptr;
    n00b_string_t      *caption      = nullptr;
    n00b_isize_t        max_rows     = 0;
    bool                wrap         = true;
    n00b_allocator_t   *allocator    = nullptr;
}
{
    // When the caller supplies neither a style preset nor any individual box
    // props, fall back to the default theme so a bare n00b_table_new(...) is
    // themed (bordered, styled header/cells) out of the box rather than
    // rendering unstyled and borderless. The props inside the returned style
    // are GC-allocated (n00b_box_props_new), so they outlive this call.
    //
    // This applies REGARDLESS of NO_COLOR: borders are Unicode box-drawing
    // glyphs, not ANSI color, so they must still render under NO_COLOR. Color
    // suppression happens at the SGR-emission layer (see ansi_sgr.c), which
    // drops the escape sequences while the glyphs and layout remain.
    n00b_table_style_t default_style;
    if (!style && !table_props && !cell_props && !header_props && !alt_props) {
        default_style = n00b_table_style_default();
        style         = &default_style;
    }

    // Apply style preset as defaults; explicit kargs override.
    if (style) {
        if (!table_props) {
            table_props = style->table_props;
        }
        if (!cell_props) {
            cell_props = style->cell_props;
        }
        if (!header_props) {
            header_props = style->header_props;
        }
        if (!alt_props) {
            alt_props = style->alt_cell_props;
        }
    }

    table->lock               = n00b_data_lock_new();
    table->allocator          = allocator;
    table->table_props        = table_props;
    table->default_cell_props = cell_props;
    table->header_props       = header_props;
    table->alt_cell_props     = alt_props;
    table->max_rows           = max_rows;
    table->wrap               = wrap;

    if (title) {
        table->title = title;
    }
    else {
        table->title = n00b_string_empty(.allocator = allocator);
    }

    if (caption) {
        table->caption = caption;
    }
    else {
        table->caption = n00b_string_empty(.allocator = allocator);
    }

    // Initialize lists.
    table->rows         = n00b_list_new(n00b_table_row_t, .allocator = allocator);
    table->col_specs    = n00b_list_new(n00b_table_col_spec_t, .allocator = allocator);
    table->current_row.cells = n00b_list_new(n00b_table_cell_t, .allocator = allocator);

    if (num_cols > 0) {
        // Default all columns to FIT mode.
        for (n00b_isize_t i = 0; i < num_cols; i++) {
            n00b_table_col_spec_t spec = {
                .mode          = N00B_COL_FIT,
                .flex_multiple = 1,
            };
            n00b_list_push(table->col_specs, spec);
        }
    }

    if (max_rows > 0) {
        // Pre-allocate capacity for ring buffer (but don't fill yet).
        n00b_list_free(table->rows);
        table->rows = n00b_list_new_cap(n00b_table_row_t, max_rows,
                                         .allocator = allocator);
    }
}

void
n00b_table_destroy(n00b_table_t *table)
{
    if (!table) {
        return;
    }

    // Free each row's cell list.
    for (size_t i = 0; i < table->rows.len; i++) {
        n00b_list_free(table->rows.data[i].cells);
    }

    n00b_list_free(table->rows);
    n00b_list_free(table->col_specs);
    n00b_list_free(table->current_row.cells);

    if (table->col_results) {
        n00b_free(table->col_results);
    }

    if (table->row_heights) {
        n00b_free(table->row_heights);
    }

    n00b_free(table);
}

// ====================================================================
// Cell / row insertion
// ====================================================================

void
n00b_table_add_cell(n00b_table_t *table, n00b_string_t *content) _kargs
{
    int32_t           col_span   = 1;
    int32_t           row_span   = 1;
    n00b_box_props_t *cell_props = nullptr;
    n00b_tristate_t   wrap       = N00B_TRI_UNSPECIFIED;
}
{
    assert(table);
    assert(row_span == 1 && "multi-row spanning not yet supported");

    n00b_table_cell_t cell_val = {
        .content    = content,
        .cell_props = cell_props,
        .col_span   = col_span,
        .row_span   = row_span,
        .wrap       = wrap,
    };

    n00b_list_push(table->current_row.cells, cell_val);
}

void
n00b_table_empty_cell(n00b_table_t *table)
{
    assert(table);
    n00b_string_t *empty = n00b_string_empty(.allocator = table->allocator);

    n00b_table_add_cell(table, empty);
}

void
n00b_table_end_row(n00b_table_t *table)
{
    assert(table);
    n00b_table_row_t *row = &table->current_row;

    if (row->cells.len == 0) {
        return;
    }

    n00b_isize_t num_cols = (n00b_isize_t)table->col_specs.len;

    // First row: auto-detect column count if not set.
    if (!table->cols_locked) {
        n00b_isize_t row_cols = current_row_col_count(table);

        if (num_cols == 0) {
            // Auto-detect: create default FIT specs.
            while ((n00b_isize_t)table->col_specs.len < row_cols) {
                n00b_table_col_spec_t spec = {
                    .mode          = N00B_COL_FIT,
                    .flex_multiple = 1,
                };
                add_col_spec(table, spec);
            }
            num_cols = (n00b_isize_t)table->col_specs.len;
        }

        table->cols_locked = true;
    }

    // Resolve span-all (-1) cells: replace with actual span.
    n00b_isize_t used_cols = 0;

    for (size_t i = 0; i < row->cells.len; i++) {
        if (row->cells.data[i].col_span == -1) {
            int32_t remaining = (int32_t)(num_cols - used_cols);
            row->cells.data[i].col_span = (remaining > 0) ? remaining : 1;
        }
        used_cols += (n00b_isize_t)row->cells.data[i].col_span;
    }

    // Commit the row.
    if (table->max_rows > 0) {
        // Ring buffer mode.
        n00b_isize_t slot   = table->total_added % table->max_rows;
        size_t       n_rows = table->rows.len;

        if ((n00b_isize_t)n_rows < table->max_rows) {
            // Still filling up the ring buffer.
            n00b_list_push(table->rows, *row);
        }
        else {
            // Overwriting oldest row in the ring.
            n00b_list_free(table->rows.data[slot].cells);
            table->rows.data[slot] = *row;
            table->ring_base = (table->total_added + 1) % table->max_rows;
        }
    }
    else {
        // Unlimited mode.
        n00b_list_push(table->rows, *row);
    }

    table->total_added++;
    table->layout_valid = false;

    // Reset current row (cells have been moved to rows[]).
    table->current_row.cells = n00b_list_new(n00b_table_cell_t,
                                              .allocator = table->allocator);
}

void
n00b_table_add_row(n00b_table_t *table, n00b_array_t(n00b_string_t *) cells)
{
    assert(table);

    n00b_isize_t n = n00b_array_len(cells);

    for (n00b_isize_t i = 0; i < n; i++) {
        n00b_table_add_cell(table, cells.data[i]);
    }

    n00b_table_end_row(table);
}

void
n00b_table_end(n00b_table_t *table)
{
    assert(table);

    if (table->current_row.cells.len > 0) {
        n00b_table_end_row(table);
    }
}

// ====================================================================
// Column specification
// ====================================================================

n00b_isize_t
n00b_table_col_fit(n00b_table_t *table)
{
    assert(table);

    n00b_table_col_spec_t spec = {
        .mode          = N00B_COL_FIT,
        .flex_multiple = 1,
    };

    return add_col_spec(table, spec);
}

n00b_isize_t
n00b_table_col_flex(n00b_table_t *table, int64_t factor)
{
    assert(table);

    n00b_table_col_spec_t spec = {
        .mode          = N00B_COL_FLEX,
        .flex_multiple = factor > 0 ? factor : 1,
    };

    return add_col_spec(table, spec);
}

n00b_isize_t
n00b_table_col_range(n00b_table_t *table, int64_t min, int64_t max)
{
    assert(table);

    n00b_table_col_spec_t spec = {
        .mode          = N00B_COL_FIT,
        .min           = { .value.i = min },
        .max           = { .value.i = max },
        .flex_multiple = 1,
    };

    return add_col_spec(table, spec);
}

n00b_isize_t
n00b_table_col_pct(n00b_table_t *table, double min, double max)
{
    assert(table);

    n00b_table_col_spec_t spec = {
        .mode          = N00B_COL_FIT,
        .min           = { .value.d = min, .pct = true },
        .max           = { .value.d = max, .pct = true },
        .flex_multiple = 1,
    };

    return add_col_spec(table, spec);
}

n00b_isize_t
n00b_table_col_fixed(n00b_table_t *table, int64_t width)
{
    assert(table);

    n00b_table_col_spec_t spec = {
        .mode = N00B_COL_FIXED,
        .min  = { .value.i = width },
        .max  = { .value.i = width },
        .pref = { .value.i = width },
    };

    return add_col_spec(table, spec);
}

void
n00b_table_set_col_priority(n00b_table_t *table, n00b_isize_t col,
                              int64_t priority)
{
    assert(table);
    assert((size_t)col < table->col_specs.len);
    table->col_specs.data[col].priority = priority;
    table->layout_valid = false;
}

void
n00b_table_set_col_props(n00b_table_t *table, n00b_isize_t col,
                           n00b_box_props_t *col_props)
{
    assert(table);
    assert((size_t)col < table->col_specs.len);
    table->col_specs.data[col].col_props = col_props;
    table->layout_valid = false;
}

// ====================================================================
// Layout invalidation
// ====================================================================

void
n00b_table_invalidate(n00b_table_t *table)
{
    assert(table);
    table->layout_valid = false;
}

// ====================================================================
// Style cascade resolution
// ====================================================================

const n00b_box_props_t *
_n00b_table_resolve_cell_props(const n00b_table_t      *table,
                                n00b_isize_t             row_idx,
                                n00b_isize_t             col_idx,
                                const n00b_table_cell_t *cell)
{
    // 1. Per-cell override.
    if (cell && cell->cell_props) {
        return cell->cell_props;
    }

    // 2. Per-column style.
    if ((size_t)col_idx < table->col_specs.len
        && table->col_specs.data[col_idx].col_props) {
        return table->col_specs.data[col_idx].col_props;
    }

    // 3. Row-based: header (row 0), alternating odd rows.
    if (row_idx == 0 && table->header_props) {
        return table->header_props;
    }

    if ((row_idx & 1) && table->alt_cell_props) {
        return table->alt_cell_props;
    }

    // 4. Default cell props.
    if (table->default_cell_props) {
        return table->default_cell_props;
    }

    return &_default_cell_props;
}

// ====================================================================
// Convenience: build table from delimited string
// ====================================================================

n00b_table_t *
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
}
{
    if (no_stripe) {
        alt_props = nullptr;
    }

    n00b_string_t *default_row_sep = n00b_string_from_raw("\n", 1,
                                                          .allocator = allocator);
    n00b_string_t *default_col_sep = n00b_string_from_raw(",", 1,
                                                          .allocator = allocator);

    n00b_string_t *rsep = row_sep ? row_sep : default_row_sep;
    n00b_string_t *csep = col_sep ? col_sep : default_col_sep;

    n00b_array_t(n00b_string_t *) rows = n00b_unicode_str_split(s, rsep);

    n00b_table_t *table = n00b_new_kargs(n00b_table_t, table,
        .table_props  = table_props,
        .cell_props   = cell_props,
        .header_props = header_props,
        .alt_props    = alt_props,
        .allocator    = allocator);

    n00b_isize_t num_rows = n00b_array_len(rows);

    for (n00b_isize_t r = 0; r < num_rows; r++) {
        n00b_string_t *row_str = n00b_array_get(rows, r);

        // Skip trailing empty rows (common from trailing newline).
        if ((!row_str || row_str->u8_bytes == 0) && r == num_rows - 1) {
            break;
        }

        n00b_array_t(n00b_string_t *) cols = n00b_unicode_str_split(row_str,
                                                                    csep);
        n00b_isize_t num_cols = n00b_array_len(cols);

        for (n00b_isize_t c = 0; c < num_cols; c++) {
            n00b_table_add_cell(table, n00b_array_get(cols, c));
        }

        n00b_array_free(cols);
        n00b_table_end_row(table);
    }

    n00b_array_free(rows);
    n00b_table_end(table);

    return table;
}

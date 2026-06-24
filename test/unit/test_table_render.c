#include <stdio.h>
#include <assert.h>
#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "display/render/plane.h"
#include "display/render/draw_cmd.h"
#include "display/render/types.h"
#include "display/render/box.h"
#include "display/table/table.h"

// ====================================================================
// Helpers
// ====================================================================

static n00b_string_t *
make_str(const char *s)
{
    return n00b_string_from_raw(s, (int64_t)strlen(s));
}

/*
 * Return true if the plane's draw list contains a DRAW_GLYPH command
 * at pixel position (x, y).
 */
static bool
has_glyph_at(n00b_plane_t *p, int32_t x, int32_t y)
{
    for (n00b_isize_t i = 0; i < p->draw_list.count; i++) {
        n00b_draw_cmd_t *cmd = &p->draw_list.cmds[i];
        if (n00b_variant_is_type(*cmd, n00b_draw_glyph_t)
            && n00b_variant_get(*cmd, n00b_draw_glyph_t).x == x
            && n00b_variant_get(*cmd, n00b_draw_glyph_t).y == y) {
            return true;
        }
    }
    return false;
}

/*
 * Return true if the plane's draw list contains at least one DRAW_TEXT
 * command at pixel position (x, y).
 */
static bool
has_text_at(n00b_plane_t *p, int32_t x, int32_t y)
{
    for (n00b_isize_t i = 0; i < p->draw_list.count; i++) {
        n00b_draw_cmd_t *cmd = &p->draw_list.cmds[i];
        if (n00b_variant_is_type(*cmd, n00b_draw_text_t)
            && n00b_variant_get(*cmd, n00b_draw_text_t).x == x
            && n00b_variant_get(*cmd, n00b_draw_text_t).y == y) {
            return true;
        }
    }
    return false;
}

// ====================================================================
// Tests
// ====================================================================

static void
test_basic_render(void)
{
    n00b_table_t *t = n00b_new_kargs(n00b_table_t, table, .num_cols = 2);

    n00b_table_add_cell(t, make_str("A"));
    n00b_table_add_cell(t, make_str("B"));
    n00b_table_end_row(t);

    n00b_plane_t *p = n00b_table_render(t, .width = 40);

    assert(p != nullptr);
    assert(p->height > 0);
    assert(p->width > 0);

    n00b_table_destroy(t);
    printf("  [PASS] basic render returns plane\n");
}

static void
test_render_with_border(void)
{
    n00b_table_style_t style = n00b_table_style_ascii();
    n00b_table_t      *t     = n00b_new_kargs(n00b_table_t,
                                              table,
                                              .num_cols    = 2,
                                              .table_props = style.table_props,
                                              .cell_props  = style.cell_props);

    n00b_table_add_cell(t, make_str("A"));
    n00b_table_add_cell(t, make_str("B"));
    n00b_table_end_row(t);

    n00b_plane_t *p = n00b_table_render(t, .width = 40);

    assert(p != nullptr);

    // In the new draw-command model, borders are box decorations handled
    // per-backend (not draw commands in the list).  Verify that rendering
    // with an ASCII border style produces a plane with valid dimensions.
    assert(p->height > 0);
    assert(p->width > 0);

    n00b_table_destroy(t);
    printf("  [PASS] render with ASCII border\n");
}

static void
test_render_interior_borders(void)
{
    n00b_box_props_t *tp
        = n00b_box_props_new(.theme = &n00b_border_ascii, .borders = N00B_BORDER_ALL);

    n00b_table_t *t = n00b_new_kargs(
        n00b_table_t,
        table,
        .num_cols    = 2,
        .table_props = tp,
        .cell_props
        = n00b_box_props_new(.borders = N00B_BORDER_NONE, .pad_left = 0, .pad_right = 0));

    n00b_table_add_cell(t, make_str("X"));
    n00b_table_add_cell(t, make_str("Y"));
    n00b_table_end_row(t);

    n00b_table_add_cell(t, make_str("A"));
    n00b_table_add_cell(t, make_str("B"));
    n00b_table_end_row(t);

    n00b_plane_t *p = n00b_table_render(t, .width = 40);

    assert(p != nullptr);

    // Should have at least 4 rows: top border, row0, interior-H, row1, bottom border.
    assert(p->height >= 4);

    n00b_table_destroy(t);
    printf("  [PASS] render with interior borders\n");
}

static void
test_render_multiline(void)
{
    n00b_table_t *t = n00b_new_kargs(n00b_table_t, table, .num_cols = 1);

    n00b_table_add_cell(t, make_str("Line one\nLine two\nLine three"));
    n00b_table_end_row(t);

    n00b_plane_t *p = n00b_table_render(t, .width = 40);

    assert(p != nullptr);
    // Row should be at least 3 lines tall.
    assert(p->height >= 3);

    n00b_table_destroy(t);
    printf("  [PASS] render multiline content\n");
}

static void
test_render_empty_table(void)
{
    n00b_table_t *t = n00b_new_kargs(n00b_table_t, table);

    n00b_plane_t *p = n00b_table_render(t, .width = 40);

    // Empty table should return nullptr.
    assert(p == nullptr);

    n00b_table_destroy(t);
    printf("  [PASS] render empty table returns nullptr\n");
}

static void
test_render_col_span(void)
{
    n00b_box_props_t *tp
        = n00b_box_props_new(.theme = &n00b_border_ascii, .borders = N00B_BORDER_ALL);

    n00b_table_t *t = n00b_new_kargs(
        n00b_table_t,
        table,
        .num_cols    = 3,
        .table_props = tp,
        .cell_props
        = n00b_box_props_new(.borders = N00B_BORDER_NONE, .pad_left = 0, .pad_right = 0));

    n00b_table_add_cell(t, make_str("A"));
    n00b_table_add_cell(t, make_str("B"));
    n00b_table_add_cell(t, make_str("C"));
    n00b_table_end_row(t);

    // Second row: first cell spans 2 columns.
    n00b_table_add_cell(t, make_str("Wide"), .col_span = 2);
    n00b_table_add_cell(t, make_str("Z"));
    n00b_table_end_row(t);

    n00b_plane_t *p = n00b_table_render(t, .width = 40);

    assert(p != nullptr);
    assert(p->height > 0);

    n00b_table_destroy(t);
    printf("  [PASS] render with col_span\n");
}

static void
test_rerender_reuses_plane(void)
{
    n00b_table_t *t = n00b_new_kargs(n00b_table_t, table, .num_cols = 2);

    n00b_table_add_cell(t, make_str("A"));
    n00b_table_add_cell(t, make_str("B"));
    n00b_table_end_row(t);

    n00b_plane_t *p1 = n00b_table_render(t, .width = 40);
    n00b_plane_t *p2 = n00b_table_render(t, .width = 40);

    // Same width, cached: should reuse the same plane.
    assert(p1 == p2);

    n00b_table_destroy(t);
    printf("  [PASS] re-render reuses plane\n");
}

static void
test_render_from_csv(void)
{
    const char *csv
        = "Name,Age,City,State\n"
          "John,52,New York,New York\n"
          "Christine,49,Jersey City,New Jersey\n"
          "Margaret,75,Stephens City,Virginia\n"
          "Emily,27,Montclair,New Jersey\n";

    n00b_string_t *input = n00b_string_from_raw(csv, (int64_t)strlen(csv));

    n00b_table_t *t = n00b_table_from_string(input);
    assert(t != nullptr);

    n00b_plane_t *p = n00b_table_render(t, .width = 80);
    assert(p != nullptr);
    assert(p->height > 0);
    assert(p->width > 0);

    n00b_table_destroy(t);
    printf("  [PASS] render from CSV string\n");
}

static void
test_render_large_table_gc_stress(void)
{
    // Build a large CSV that forces the arena to fill up and trigger
    // garbage collection during layout/render.  500 rows of 4 columns
    // with multi-word city names exercises the GC's ability to correctly
    // relocate live objects (table rows, cell backing stores, string data)
    // while the layout engine holds interior pointers into those stores.

    const char *cities[] = {
        "New York",
        "Los Angeles",
        "San Francisco",
        "Jersey City",
        "Stephens City",
        "Montclair",
        "Philadelphia",
        "Springfield",
    };
    const char *states[] = {
        "New York",
        "California",
        "California",
        "New Jersey",
        "Virginia",
        "New Jersey",
        "Pennsylvania",
        "Illinois",
    };
    int n_cities = (int)(sizeof(cities) / sizeof(cities[0]));

    // Build the CSV dynamically to avoid a fixed-size stack buffer.
    n00b_buffer_t *csv_buf = n00b_buffer_empty();

    // Header row.
    const char    *header     = "Name,Age,City,State\n";
    n00b_buffer_t *header_buf = n00b_buffer_from_bytes((char *)header, (int64_t)strlen(header));
    n00b_buffer_concat(csv_buf, header_buf);
    n00b_buffer_free(header_buf);

    // Data rows.
    for (int i = 0; i < 500; i++) {
        // Build one row into a small temporary stack buffer — bounded by
        // the fixed-length format values (name <= 12, age <= 4, city <= 15,
        // state <= 14 chars), well within 64 bytes.
        char row[64];
        int  row_len = snprintf(row,
                                sizeof(row),
                                "Person_%d,%d,%s,%s\n",
                                i,
                                20 + (i % 60),
                                cities[i % n_cities],
                                states[i % n_cities]);

        n00b_buffer_t *row_buf = n00b_buffer_from_bytes(row, (int64_t)row_len);
        n00b_buffer_concat(csv_buf, row_buf);
        n00b_buffer_free(row_buf);
    }

    n00b_string_t *input = n00b_buffer_to_string(csv_buf);
    n00b_buffer_free(csv_buf);

    n00b_table_t *t = n00b_table_from_string(input);
    assert(t != nullptr);

    n00b_plane_t *p = n00b_table_render(t, .width = 120);
    assert(p != nullptr);
    assert(p->height > 0);
    assert(p->width > 0);

    n00b_table_destroy(t);
    printf("  [PASS] large table GC stress (500 rows)\n");
}

// ====================================================================
// Main
// ====================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running table render tests...\n");

    test_basic_render();
    test_render_with_border();
    test_render_interior_borders();
    test_render_multiline();
    test_render_empty_table();
    test_render_col_span();
    test_rerender_reuses_plane();
    test_render_from_csv();
    test_render_large_table_gc_stress();

    printf("All table render tests passed.\n");
    n00b_shutdown();
    return 0;
}

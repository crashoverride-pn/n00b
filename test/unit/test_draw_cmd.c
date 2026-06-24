/*
 * Unit tests for draw command types and font metrics provider.
 */

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "display/render/draw_cmd.h"
#include "display/render/font_metrics.h"

// -------------------------------------------------------------------
// Test 1: Draw list init / append / clear / destroy
// -------------------------------------------------------------------

static void
test_draw_list_lifecycle(void)
{
    n00b_draw_list_t dl;
    n00b_draw_list_init(&dl);

    assert(dl.cmds == nullptr);
    assert(dl.count == 0);
    assert(dl.capacity == 0);

    // Append a text command.
    n00b_draw_cmd_t cmd = n00b_draw_cmd_text(10, 20,
                                               n00b_string_from_cstr("hi"),
                                               nullptr);
    n00b_draw_list_append(&dl, &cmd);
    assert(dl.count == 1);
    assert(dl.capacity >= 1);
    assert(n00b_variant_is_type(dl.cmds[0], n00b_draw_text_t));
    n00b_draw_text_t t0 = n00b_variant_get(dl.cmds[0], n00b_draw_text_t);
    assert(t0.x == 10);
    assert(t0.y == 20);

    // Clear keeps capacity.
    n00b_isize_t old_cap = dl.capacity;
    n00b_draw_list_clear(&dl);
    assert(dl.count == 0);
    assert(dl.capacity == old_cap);

    // Destroy frees buffer.
    n00b_draw_list_destroy(&dl);
    assert(dl.cmds == nullptr);
    assert(dl.count == 0);
    assert(dl.capacity == 0);
}

// -------------------------------------------------------------------
// Test 2: Draw list grows beyond initial capacity
// -------------------------------------------------------------------

static void
test_draw_list_grow(void)
{
    n00b_draw_list_t dl;
    n00b_draw_list_init(&dl);

    // Append more than initial capacity (16).
    for (int i = 0; i < 50; i++) {
        n00b_draw_cmd_t cmd = n00b_draw_cmd_glyph(i, i * 2, 'A' + (i % 26),
                                                     nullptr);
        n00b_draw_list_append(&dl, &cmd);
    }

    assert(dl.count == 50);
    assert(dl.capacity >= 50);

    // Verify first and last.
    assert(n00b_variant_is_type(dl.cmds[0], n00b_draw_glyph_t));
    n00b_draw_glyph_t g0 = n00b_variant_get(dl.cmds[0], n00b_draw_glyph_t);
    assert(g0.x == 0);
    assert(g0.cp == 'A');

    assert(n00b_variant_is_type(dl.cmds[49], n00b_draw_glyph_t));
    n00b_draw_glyph_t g49 = n00b_variant_get(dl.cmds[49], n00b_draw_glyph_t);
    assert(g49.x == 49);
    assert(g49.cp == 'A' + (49 % 26));

    n00b_draw_list_destroy(&dl);
}

// -------------------------------------------------------------------
// Test 3: Command type builders
// -------------------------------------------------------------------

static void
test_command_builders(void)
{
    // Text command.
    n00b_string_t *s = n00b_string_from_cstr("hello");
    n00b_draw_cmd_t t = n00b_draw_cmd_text(5, 10, s, nullptr);
    assert(n00b_variant_is_type(t, n00b_draw_text_t));
    n00b_draw_text_t ta = n00b_variant_get(t, n00b_draw_text_t);
    assert(ta.x == 5);
    assert(ta.y == 10);
    assert(ta.string == s);
    assert(ta.style == nullptr);

    // Fill rect command.
    n00b_draw_cmd_t f = n00b_draw_cmd_fill_rect(0, 0, 100, 50, '#', nullptr);
    assert(n00b_variant_is_type(f, n00b_draw_fill_rect_t));
    n00b_draw_fill_rect_t fa = n00b_variant_get(f, n00b_draw_fill_rect_t);
    assert(fa.w == 100);
    assert(fa.h == 50);
    assert(fa.cp == '#');

    // Glyph command.
    n00b_draw_cmd_t g = n00b_draw_cmd_glyph(42, 99, 0x2588, nullptr);
    assert(n00b_variant_is_type(g, n00b_draw_glyph_t));
    n00b_draw_glyph_t ga = n00b_variant_get(g, n00b_draw_glyph_t);
    assert(ga.x == 42);
    assert(ga.y == 99);
    assert(ga.cp == 0x2588);
}

// -------------------------------------------------------------------
// Test 4: Fallback font metrics
// -------------------------------------------------------------------

static void
test_fallback_metrics(void)
{
    // Simulate 8x16 cell pixels.
    n00b_font_metrics_provider_t fm = n00b_font_metrics_fallback(8, 16);

    assert(fm.text_width != nullptr);
    assert(fm.line_height != nullptr);
    assert(fm.ascent != nullptr);
    assert(fm.ctx != nullptr);

    // Line height and ascent should be cell_px_h.
    assert(fm.line_height(fm.ctx, nullptr) == 16);
    assert(fm.ascent(fm.ctx, nullptr) == 16);

    // "hi" is 2 display columns → 2 * 8 = 16 pixels.
    n00b_string_t *hi = n00b_string_from_cstr("hi");
    assert(fm.text_width(fm.ctx, hi, nullptr) == 16);

    // nullptr text → 0 width.
    assert(fm.text_width(fm.ctx, nullptr, nullptr) == 0);

    // Empty string → 0 width.
    n00b_string_t *empty = n00b_string_from_cstr("");
    assert(fm.text_width(fm.ctx, empty, nullptr) == 0);
}

// -------------------------------------------------------------------
// Test 5: Fallback metrics with cell_px 1x1 (pure cell mode)
// -------------------------------------------------------------------

static void
test_fallback_metrics_cell_mode(void)
{
    n00b_font_metrics_provider_t fm = n00b_font_metrics_fallback(1, 1);

    assert(fm.line_height(fm.ctx, nullptr) == 1);
    assert(fm.ascent(fm.ctx, nullptr) == 1);

    n00b_string_t *abc = n00b_string_from_cstr("abc");
    assert(fm.text_width(fm.ctx, abc, nullptr) == 3);
}

// -------------------------------------------------------------------
// main
// -------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running draw command tests...\n");

    test_draw_list_lifecycle();
    test_draw_list_grow();
    test_command_builders();
    test_fallback_metrics();
    test_fallback_metrics_cell_mode();

    printf("All draw command tests passed.\n");

    n00b_shutdown();
    return 0;
}

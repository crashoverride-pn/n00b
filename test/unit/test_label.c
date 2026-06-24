/*
 * Unit tests for the label widget.
 */

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "adt/option.h"
#include "display/render/plane.h"
#include "display/render/draw_cmd.h"
#include "display/render/types.h"
#include "display/widget.h"
#include "display/widgets/label.h"
#include "text/strings/text_style.h"
#include "text/strings/string_style.h"
#include "text/strings/string_ops.h"
#include "text/unicode/properties.h"

// -------------------------------------------------------------------
// Test 1: Plain text label
// -------------------------------------------------------------------

static void
test_label_plain_text(void)
{
    n00b_string_t *text = n00b_string_from_cstr("Hello");
    n00b_plane_t  *lbl  = n00b_label_new(text);

    assert(lbl != nullptr);
    assert(lbl->widget_vtable == &n00b_widget_label);

    // Render should have produced a DRAW_TEXT command with the text.
    assert(lbl->draw_list.count >= 1);
    assert(n00b_variant_is_type(lbl->draw_list.cmds[0], n00b_draw_text_t));
    assert(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).string != nullptr);

    // The drawn text should contain "Hello".
    assert(n00b_unicode_str_contains(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).string, r"Hello"));

    printf("  [PASS] plain text label\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Test 2: Styled text label
// -------------------------------------------------------------------

static void
test_label_styled_text(void)
{
    n00b_string_t *text = n00b_string_from_cstr("Bold");

    n00b_text_style_t bold_style = {
        .bold = N00B_TRI_YES,
        .fg_rgb = n00b_color_make(0xFF0000),
    };

    // Allocate a persistent copy of the style for the string.
    n00b_text_style_t *style_ptr = n00b_alloc(n00b_text_style_t);
    *style_ptr = bold_style;

    text = n00b_str_set_base_style(text, style_ptr);

    n00b_plane_t *lbl = n00b_label_new(text);
    assert(lbl != nullptr);

    // Render should have produced a DRAW_TEXT command.
    assert(lbl->draw_list.count >= 1);
    assert(n00b_variant_is_type(lbl->draw_list.cmds[0], n00b_draw_text_t));

    // Verify the text content is correct.
    assert(n00b_unicode_str_contains(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).string, r"Bold"));

    printf("  [PASS] styled text label\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Test 3: CENTER alignment
// -------------------------------------------------------------------

static void
test_label_center_align(void)
{
    n00b_string_t *text = n00b_string_from_cstr("Hi");
    n00b_plane_t  *lbl  = n00b_label_new(text,
                                          .width     = 10,
                                          .alignment = N00B_ALIGN_CENTER);

    assert(lbl != nullptr);

    // Render should produce a DRAW_TEXT command with x offset > 0
    // (centered in 10 columns with a 2-char string).
    assert(lbl->draw_list.count >= 1);
    assert(n00b_variant_is_type(lbl->draw_list.cmds[0], n00b_draw_text_t));
    // "Hi" is 2 wide, content is 10 wide, offset should be 4.
    assert(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).x == 4);

    printf("  [PASS] center alignment\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Test 4: RIGHT alignment
// -------------------------------------------------------------------

static void
test_label_right_align(void)
{
    n00b_string_t *text = n00b_string_from_cstr("Hi");
    n00b_plane_t  *lbl  = n00b_label_new(text,
                                          .width     = 10,
                                          .alignment = N00B_ALIGN_RIGHT);

    assert(lbl != nullptr);

    // Render should produce a DRAW_TEXT command with x at right edge.
    // "Hi" is 2 wide in 10 columns: offset = 10 - 2 = 8.
    assert(lbl->draw_list.count >= 1);
    assert(n00b_variant_is_type(lbl->draw_list.cmds[0], n00b_draw_text_t));
    assert(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).x == 8);

    printf("  [PASS] right alignment\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Test 5: Wrap mode
// -------------------------------------------------------------------

static void
test_label_wrap(void)
{
    // 10 chars into 5 columns should produce 2 lines of draw commands.
    n00b_string_t *text = n00b_string_from_cstr("ABCDEFGHIJ");
    n00b_plane_t  *lbl  = n00b_label_new(text,
                                          .width = 5,
                                          .wrap  = true);

    assert(lbl != nullptr);

    // Should have at least 2 DRAW_TEXT commands (one per wrapped line).
    assert(lbl->draw_list.count >= 2);
    assert(n00b_variant_is_type(lbl->draw_list.cmds[0], n00b_draw_text_t));
    assert(n00b_variant_is_type(lbl->draw_list.cmds[1], n00b_draw_text_t));

    // Second line should have y > 0.
    assert(n00b_variant_get(lbl->draw_list.cmds[1], n00b_draw_text_t).y > n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).y);

    printf("  [PASS] wrap mode\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Test 6: set_text updates content
// -------------------------------------------------------------------

static void
test_label_set_text(void)
{
    n00b_string_t *text1 = n00b_string_from_cstr("AAAA");
    n00b_plane_t  *lbl   = n00b_label_new(text1, .width = 10);

    assert(lbl->draw_list.count >= 1);
    assert(n00b_unicode_str_contains(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).string, r"AAAA"));

    n00b_string_t *text2 = n00b_string_from_cstr("BBBB");
    n00b_label_set_text(lbl, text2);

    // Should now show B's.
    assert(lbl->draw_list.count >= 1);
    assert(n00b_variant_is_type(lbl->draw_list.cmds[0], n00b_draw_text_t));
    assert(n00b_unicode_str_contains(n00b_variant_get(lbl->draw_list.cmds[0], n00b_draw_text_t).string, r"BBBB"));

    // get_text should return the new string.
    assert(n00b_label_get_text(lbl) == text2);

    printf("  [PASS] set_text\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Test 7: Widget measure
// -------------------------------------------------------------------

static void
test_label_measure(void)
{
    n00b_string_t *text = n00b_string_from_cstr("Hello World");
    n00b_plane_t  *lbl  = n00b_label_new(text);

    int32_t pref_w, pref_h, min_w, min_h;
    n00b_widget_measure(lbl, &pref_w, &pref_h, &min_w, &min_h);

    assert(pref_w == 11); // "Hello World" = 11 display columns
    assert(pref_h == 1);
    assert(min_w == 1);
    assert(min_h == 1);

    printf("  [PASS] widget measure\n");
    n00b_plane_destroy(lbl);
}

// -------------------------------------------------------------------
// Main
// -------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running label widget tests...\n");

    test_label_plain_text();
    test_label_styled_text();
    test_label_center_align();
    test_label_right_align();
    test_label_wrap();
    test_label_set_text();
    test_label_measure();

    printf("All label tests passed.\n");

    n00b_shutdown();
    return 0;
}

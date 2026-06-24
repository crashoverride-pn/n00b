/*
 * Unit tests for the divider widget.
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
#include "display/widgets/divider.h"

// -------------------------------------------------------------------
// Test 1: Horizontal divider fills with line character
// -------------------------------------------------------------------

static void
test_divider_horizontal(void)
{
    n00b_plane_t *div = n00b_divider_new(.width = 20);

    assert(div != nullptr);
    assert(div->widget_vtable == &n00b_widget_divider);

    // Render should have produced draw commands (fill rect for the line).
    assert(div->draw_list.count > 0);
    assert(n00b_variant_is_type(div->draw_list.cmds[0], n00b_draw_fill_rect_t));

    printf("  [PASS] horizontal divider\n");
    n00b_plane_destroy(div);
}

// -------------------------------------------------------------------
// Test 2: Vertical divider
// -------------------------------------------------------------------

static void
test_divider_vertical(void)
{
    n00b_plane_t *div = n00b_divider_new(.vertical = true,
                                           .height = 5, .width = 1);

    assert(div != nullptr);

    // Should have draw commands for the vertical line.
    assert(div->draw_list.count > 0);
    assert(n00b_variant_is_type(div->draw_list.cmds[0], n00b_draw_fill_rect_t));

    printf("  [PASS] vertical divider\n");
    n00b_plane_destroy(div);
}

// -------------------------------------------------------------------
// Test 3: Divider with label
// -------------------------------------------------------------------

static void
test_divider_label(void)
{
    n00b_string_t *label = n00b_string_from_cstr("Title");
    n00b_plane_t  *div   = n00b_divider_new(.width = 30, .label = label);

    assert(div != nullptr);

    // Should have draw commands including text for the label.
    assert(div->draw_list.count > 0);

    // Check that at least one draw command is a text command
    // containing the label.
    bool found_text = false;
    for (n00b_isize_t i = 0; i < div->draw_list.count; i++) {
        if (n00b_variant_is_type(div->draw_list.cmds[i], n00b_draw_text_t)) {
            found_text = true;
            break;
        }
    }
    assert(found_text);

    printf("  [PASS] divider with label\n");
    n00b_plane_destroy(div);
}

// -------------------------------------------------------------------
// Test 4: Measure
// -------------------------------------------------------------------

static void
test_divider_measure(void)
{
    n00b_plane_t *div = n00b_divider_new(.width = 20);

    int32_t pref_w, pref_h, min_w, min_h;
    n00b_widget_measure(div, &pref_w, &pref_h, &min_w, &min_h);

    assert(pref_h == 1);
    assert(min_w >= 1);
    assert(min_h == 1);

    printf("  [PASS] divider measure\n");
    n00b_plane_destroy(div);
}

// -------------------------------------------------------------------
// Main
// -------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running divider widget tests...\n");

    test_divider_horizontal();
    test_divider_vertical();
    test_divider_label();
    test_divider_measure();

    printf("All divider tests passed.\n");

    n00b_shutdown();
    return 0;
}

/*
 * Unit tests for the progress bar widget.
 */

#include <stdio.h>
#include <assert.h>
#include <math.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "display/render/plane.h"
#include "display/render/draw_cmd.h"
#include "display/widget.h"
#include "display/widgets/progress.h"

// -------------------------------------------------------------------
// Test 1: Default progress bar at 0%
// -------------------------------------------------------------------

static void
test_progress_zero(void)
{
    n00b_plane_t *bar = n00b_progress_new(.width = 20);

    assert(bar != nullptr);
    assert(bar->widget_vtable == &n00b_widget_progress);

    double val = n00b_progress_get_value(bar);
    assert(fabs(val - 0.0) < 0.001);

    // At 0%, render should have issued draw commands (fill rects for
    // the empty portion).
    assert(bar->draw_list.count > 0);

    printf("  [PASS] progress at 0%%\n");
    n00b_plane_destroy(bar);
}

// -------------------------------------------------------------------
// Test 2: Progress at 100%
// -------------------------------------------------------------------

static void
test_progress_full(void)
{
    n00b_plane_t *bar = n00b_progress_new(.width = 10, .value = 1.0);

    double val = n00b_progress_get_value(bar);
    assert(fabs(val - 1.0) < 0.001);

    // At 100%, render should have issued draw commands (fill rects for
    // the filled portion).
    assert(bar->draw_list.count > 0);

    // The first command should be a fill rect for the full bar.
    assert(n00b_variant_is_type(bar->draw_list.cmds[0], n00b_draw_fill_rect_t));

    printf("  [PASS] progress at 100%%\n");
    n00b_plane_destroy(bar);
}

// -------------------------------------------------------------------
// Test 3: Set value
// -------------------------------------------------------------------

static void
test_progress_set_value(void)
{
    n00b_plane_t *bar = n00b_progress_new(.width = 10);

    assert(fabs(n00b_progress_get_value(bar)) < 0.001);

    n00b_progress_set_value(bar, 0.5);
    assert(fabs(n00b_progress_get_value(bar) - 0.5) < 0.001);

    // Clamp above 1.0.
    n00b_progress_set_value(bar, 1.5);
    assert(fabs(n00b_progress_get_value(bar) - 1.0) < 0.001);

    // Clamp below 0.0.
    n00b_progress_set_value(bar, -0.5);
    assert(fabs(n00b_progress_get_value(bar)) < 0.001);

    printf("  [PASS] progress set_value\n");
    n00b_plane_destroy(bar);
}

// -------------------------------------------------------------------
// Test 4: Measure
// -------------------------------------------------------------------

static void
test_progress_measure(void)
{
    n00b_plane_t *bar = n00b_progress_new(.width = 20);

    int32_t pref_w, pref_h, min_w, min_h;
    n00b_widget_measure(bar, &pref_w, &pref_h, &min_w, &min_h);

    assert(pref_w == 20);
    assert(pref_h == 1);
    assert(min_w >= 3);
    assert(min_h == 1);

    printf("  [PASS] progress measure\n");
    n00b_plane_destroy(bar);
}

// -------------------------------------------------------------------
// Test 5: Render produces draw commands
// -------------------------------------------------------------------

static void
test_progress_render(void)
{
    n00b_plane_t *bar = n00b_progress_new(.width = 20, .value = 0.5);

    // Render should have been called by constructor; re-render to verify.
    n00b_widget_render(bar);

    // Should have draw commands for the filled and empty portions.
    assert(bar->draw_list.count > 0);

    // Check that we have at least one fill rect command.
    bool found_fill = false;
    for (n00b_isize_t i = 0; i < bar->draw_list.count; i++) {
        if (n00b_variant_is_type(bar->draw_list.cmds[i], n00b_draw_fill_rect_t)) {
            found_fill = true;
            break;
        }
    }
    assert(found_fill);

    printf("  [PASS] progress render\n");
    n00b_plane_destroy(bar);
}

// -------------------------------------------------------------------
// Main
// -------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running progress widget tests...\n");

    test_progress_zero();
    test_progress_full();
    test_progress_set_value();
    test_progress_measure();
    test_progress_render();

    printf("All progress tests passed.\n");

    n00b_shutdown();
    return 0;
}

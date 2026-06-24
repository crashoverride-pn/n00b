#include <stdio.h>
#include <assert.h>
#include "n00b.h"
#include "core/alloc.h"
#include "adt/option.h"
#include "core/runtime.h"
#include "core/string.h"
#include "display/render/backend.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "display/render/draw_cmd.h"
#include "display/render/box.h"
#include "text/strings/string_ops.h"

// ====================================================================
// Tests
// ====================================================================

static void
test_plane_new_and_destroy(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);
    assert(p != nullptr);
    assert(p->flags & N00B_PLANE_VISIBLE);
    assert(p->draw_list.count == 0);

    n00b_plane_destroy(p);
    printf("  [PASS] plane new and destroy\n");
}

static void
test_plane_new_with_kwargs(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane,
                                      .name    = n00b_option_set(n00b_string_t *, r"test-plane"),
                                      .z       = 5);
    assert(p->z == 5);
    assert(n00b_unicode_str_eq(p->name, r"test-plane"));

    n00b_plane_destroy(p);
    printf("  [PASS] plane new with kwargs\n");
}

static void
test_plane_draw_glyph(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_draw_glyph(p, 0, 0, 'H');
    n00b_plane_draw_glyph(p, 1, 0, 'i');

    assert(p->draw_list.count == 2);
    assert(n00b_variant_is_type(p->draw_list.cmds[0], n00b_draw_glyph_t));
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_glyph_t).cp == 'H');
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_glyph_t).x == 0);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_glyph_t).y == 0);
    assert(n00b_variant_is_type(p->draw_list.cmds[1], n00b_draw_glyph_t));
    assert(n00b_variant_get(p->draw_list.cmds[1], n00b_draw_glyph_t).cp == 'i');
    assert(n00b_variant_get(p->draw_list.cmds[1], n00b_draw_glyph_t).x == 1);
    assert(n00b_variant_get(p->draw_list.cmds[1], n00b_draw_glyph_t).y == 0);

    n00b_plane_destroy(p);
    printf("  [PASS] plane draw_glyph\n");
}

static void
test_plane_draw_text(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_string_t *hello = n00b_string_from_cstr("Hello");
    n00b_plane_draw_text(p, 5, 10, hello);

    assert(p->draw_list.count == 1);
    assert(n00b_variant_is_type(p->draw_list.cmds[0], n00b_draw_text_t));
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_text_t).x == 5);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_text_t).y == 10);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_text_t).string == hello);

    n00b_plane_destroy(p);
    printf("  [PASS] plane draw_text\n");
}

static void
test_plane_clear(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_draw_glyph(p, 0, 0, 'X');
    n00b_plane_draw_glyph(p, 1, 0, 'Y');
    assert(p->draw_list.count == 2);

    n00b_plane_clear(p);
    assert(p->draw_list.count == 0);

    n00b_plane_destroy(p);
    printf("  [PASS] plane clear\n");
}

static void
test_plane_fill_rect(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_fill_rect(p, 2, 1, 3, 2, .cp = '#');

    assert(p->draw_list.count == 1);
    assert(n00b_variant_is_type(p->draw_list.cmds[0], n00b_draw_fill_rect_t));
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_fill_rect_t).x == 2);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_fill_rect_t).y == 1);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_fill_rect_t).w == 3);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_fill_rect_t).h == 2);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_fill_rect_t).cp == '#');

    n00b_plane_destroy(p);
    printf("  [PASS] plane fill_rect\n");
}

static void
test_plane_visibility(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    assert(p->flags & N00B_PLANE_VISIBLE);

    n00b_plane_set_visible(p, false);
    assert(!(p->flags & N00B_PLANE_VISIBLE));

    n00b_plane_set_visible(p, true);
    assert(p->flags & N00B_PLANE_VISIBLE);

    n00b_plane_destroy(p);
    printf("  [PASS] plane visibility\n");
}

static void
test_plane_move_and_z(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_move(p, 5, 10);
    assert(p->x == 5);
    assert(p->y == 10);

    n00b_plane_set_z(p, 3);
    assert(p->z == 3);

    n00b_plane_destroy(p);
    printf("  [PASS] plane move and z-order\n");
}

static void
test_plane_widget_state(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    assert(n00b_plane_get_state(p) == N00B_WSTATE_NORMAL);

    n00b_plane_set_state(p, N00B_WSTATE_FOCUSED);
    assert(n00b_plane_get_state(p) == N00B_WSTATE_FOCUSED);

    n00b_plane_set_state(p, N00B_WSTATE_DISABLED);
    assert(n00b_plane_get_state(p) == N00B_WSTATE_DISABLED);

    n00b_plane_destroy(p);
    printf("  [PASS] plane widget state\n");
}

static void
test_plane_content_size(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    // Set viewport size to known values.
    p->width = 20;
    p->height = 10;

    n00b_box_props_t *box = n00b_box_props_new(
        .theme     = &n00b_border_plain,
        .pad_left  = 1,
        .pad_right = 1,
        .pad_top   = 1,
        .pad_bottom = 1
    );
    n00b_plane_set_box(p, box);

    int32_t w, h;
    n00b_plane_content_size(p, &w, &h);

    // Content size should reflect viewport dimensions.
    assert(w > 0);
    assert(h > 0);

    n00b_plane_destroy(p);
    printf("  [PASS] plane content_size with box\n");
}

static void
test_plane_scroll(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_scroll(p, 5, 3);
    assert(p->scroll_x == 5);
    assert(p->scroll_y == 3);

    // Accumulate.
    n00b_plane_scroll(p, 2, 1);
    assert(p->scroll_x == 7);
    assert(p->scroll_y == 4);

    n00b_plane_destroy(p);
    printf("  [PASS] plane scroll\n");
}

static void
test_plane_scroll_to(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_scroll_to(p, 15, 30);
    assert(p->scroll_x == 15);
    assert(p->scroll_y == 30);

    // Scroll to 0.
    n00b_plane_scroll_to(p, 0, 0);
    assert(p->scroll_x == 0);
    assert(p->scroll_y == 0);

    n00b_plane_destroy(p);
    printf("  [PASS] plane scroll_to\n");
}

static void
test_plane_draw_glyph_with_style(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_text_style_t style = { .bold = N00B_TRI_YES };
    n00b_plane_draw_glyph(p, 0, 0, 'S', .style = &style);

    assert(p->draw_list.count == 1);
    assert(n00b_variant_is_type(p->draw_list.cmds[0], n00b_draw_glyph_t));
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_glyph_t).cp == 'S');
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_glyph_t).style != nullptr);
    assert(n00b_variant_get(p->draw_list.cmds[0], n00b_draw_glyph_t).style->bold == N00B_TRI_YES);

    n00b_plane_destroy(p);
    printf("  [PASS] plane draw_glyph with style\n");
}

static void
test_plane_multiple_draw_commands(void)
{
    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane);

    n00b_string_t *text = n00b_string_from_cstr("Hello");
    n00b_plane_draw_text(p, 0, 0, text);
    n00b_plane_draw_glyph(p, 10, 0, '!');
    n00b_plane_fill_rect(p, 0, 1, 20, 1, .cp = '-');

    assert(p->draw_list.count == 3);
    assert(n00b_variant_is_type(p->draw_list.cmds[0], n00b_draw_text_t));
    assert(n00b_variant_is_type(p->draw_list.cmds[1], n00b_draw_glyph_t));
    assert(n00b_variant_is_type(p->draw_list.cmds[2], n00b_draw_fill_rect_t));

    n00b_plane_destroy(p);
    printf("  [PASS] plane multiple draw commands\n");
}

static void
test_plane_add_remove_child(void)
{
    n00b_plane_t *parent = n00b_new_kargs(n00b_plane_t, plane);
    n00b_plane_t *child1 = n00b_new_kargs(n00b_plane_t, plane);
    n00b_plane_t *child2 = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_add_child(parent, child1, 2, 3);
    n00b_plane_add_child(parent, child2, 15, 10);

    assert(n00b_list_len(parent->children) == 2);
    assert(child1->parent == parent);
    assert(child2->parent == parent);
    assert(child1->x == 2);
    assert(child1->y == 3);

    // Remove child1.
    bool removed = n00b_plane_remove_child(parent, child1);
    assert(removed);
    assert(n00b_list_len(parent->children) == 1);
    assert(child1->parent == nullptr);
    assert(n00b_list_get(parent->children, 0) == child2);

    // Remove non-existent.
    removed = n00b_plane_remove_child(parent, child1);
    assert(!removed);

    n00b_plane_destroy(child1);
    n00b_plane_destroy(child2);
    n00b_plane_destroy(parent);
    printf("  [PASS] plane add/remove child\n");
}

static void
test_plane_canvas_propagates_to_subtree(void)
{
    n00b_canvas_t *canvas = n00b_new_kargs(n00b_canvas_t, canvas,
                                            .vtable = &n00b_renderer_stream);
    n00b_plane_t *root       = n00b_new_kargs(n00b_plane_t, plane);
    n00b_plane_t *child      = n00b_new_kargs(n00b_plane_t, plane);
    n00b_plane_t *grandchild = n00b_new_kargs(n00b_plane_t, plane);

    n00b_plane_add_child(child, grandchild, 0, 0);
    assert(child->canvas == nullptr);
    assert(grandchild->canvas == nullptr);

    n00b_canvas_add_plane(canvas, root);
    assert(root->canvas == canvas);

    n00b_plane_add_child(root, child, 1, 1);
    assert(child->canvas == canvas);
    assert(grandchild->canvas == canvas);

    assert(n00b_plane_remove_child(root, child));
    assert(child->parent == nullptr);
    assert(child->canvas == nullptr);
    assert(grandchild->canvas == nullptr);

    assert(n00b_canvas_remove_plane(canvas, root));
    assert(root->canvas == nullptr);

    n00b_plane_destroy(grandchild);
    n00b_plane_destroy(child);
    n00b_plane_destroy(root);
    n00b_canvas_destroy(canvas);
    printf("  [PASS] plane subtree canvas propagation\n");
}

// ====================================================================
// Main
// ====================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running render plane tests...\n");

    test_plane_new_and_destroy();
    test_plane_new_with_kwargs();
    test_plane_draw_glyph();
    test_plane_draw_text();
    test_plane_clear();
    test_plane_fill_rect();
    test_plane_visibility();
    test_plane_move_and_z();
    test_plane_widget_state();
    test_plane_content_size();
    test_plane_scroll();
    test_plane_scroll_to();
    test_plane_draw_glyph_with_style();
    test_plane_multiple_draw_commands();
    test_plane_add_remove_child();
    test_plane_canvas_propagates_to_subtree();

    printf("All render plane tests passed.\n");
    n00b_shutdown();
    return 0;
}

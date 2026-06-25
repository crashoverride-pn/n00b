/*
 * Render plane: draw command list, text measurement, and state management.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/data_lock.h"
#include "core/arena.h"
#include "core/string.h"
#include "adt/list.h"
#include "display/mouse.h"
#include "display/render/plane.h"
#include "display/render/canvas.h"
#include "display/render/font_metrics.h"
#include "internal/display/plane_geometry.h"
#include "internal/display/plane_tree.h"
#include "text/unicode/properties.h"

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

static inline void
plane_lock(n00b_plane_t *p)
{
    n00b_data_write_lock(p->lock);
}

static inline void
plane_unlock(n00b_plane_t *p)
{
    n00b_data_unlock(p->lock);
}

static inline void
plane_mark_dirty(n00b_plane_t *p)
{
    p->flags |= N00B_PLANE_DIRTY;
}

static void
plane_assign_canvas_recursive(n00b_plane_t *plane, n00b_canvas_t *canvas)
{
    if (!plane) {
        return;
    }

    plane->canvas = canvas;
    plane_mark_dirty(plane);

    if (plane->children.data) {
        for (size_t i = 0; i < plane->children.len; i++) {
            n00b_plane_t *child = plane->children.data[i];
            if (child) {
                plane_assign_canvas_recursive(child, canvas);
            }
        }
    }
}

static void
plane_clear_canvas_recursive(n00b_plane_t *plane)
{
    if (!plane) {
        return;
    }

    plane->canvas = nullptr;
    plane_mark_dirty(plane);

    if (plane->children.data) {
        for (size_t i = 0; i < plane->children.len; i++) {
            n00b_plane_t *child = plane->children.data[i];
            if (child) {
                plane_clear_canvas_recursive(child);
            }
        }
    }
}

static void
plane_translate_layout_subtree(n00b_plane_t *plane, int32_t dx, int32_t dy)
{
    if (!plane || (dx == 0 && dy == 0)) {
        return;
    }

    if (n00b_plane_has_layout_bounds(plane)) {
        plane->bounds.x += dx;
        plane->bounds.y += dy;
    }

    plane_mark_dirty(plane);

    if (plane->children.data) {
        for (size_t i = 0; i < plane->children.len; i++) {
            n00b_plane_t *child = plane->children.data[i];
            if (child) {
                plane_translate_layout_subtree(child, dx, dy);
            }
        }
    }
}

bool
n00b_plane_tree_contains(const n00b_plane_t *root, const n00b_plane_t *target)
{
    if (!root || !target) {
        return false;
    }

    if (root == target) {
        return true;
    }

    if (!root->children.data) {
        return false;
    }

    for (size_t i = 0; i < root->children.len; i++) {
        if (n00b_plane_tree_contains(root->children.data[i], target)) {
            return true;
        }
    }

    return false;
}

// -------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------

void
n00b_plane_init(n00b_plane_t *p) _kargs
{
    n00b_option_t(n00b_string_t *) name = n00b_option_none(n00b_string_t *);
    n00b_scroll_mode_t scroll    = N00B_SCROLL_NONE;
    int32_t            z         = 0;
    n00b_box_props_t  *box       = nullptr;
    n00b_text_style_t *style     = nullptr;
    n00b_allocator_t  *allocator = nullptr;
    n00b_canvas_t     *canvas    = nullptr;
}
{
    p->lock          = n00b_data_lock_new();
    if (n00b_option_is_set(name)) {
        p->name = n00b_option_get(name);
    }
    p->z             = z;
    p->box           = box;
    p->default_style = style;
    p->scroll_mode   = scroll;
    p->flags         = N00B_PLANE_VISIBLE | N00B_PLANE_DIRTY;
    p->allocator     = allocator;
    p->widget_state  = N00B_WSTATE_NORMAL;
    p->widget_vtable = nullptr;
    p->widget_data   = nullptr;
    p->canvas        = canvas;
    p->scroll_x      = 0;
    p->scroll_y      = 0;

    n00b_draw_list_init(&p->draw_list);
}

void
n00b_plane_destroy(n00b_plane_t *p)
{
    if (!p) {
        return;
    }

    n00b_draw_list_destroy(&p->draw_list);

    if (p->children.data) {
        n00b_list_free(p->children);
    }

    n00b_free(p);
}

// -------------------------------------------------------------------
// Hierarchy
// -------------------------------------------------------------------

void
n00b_plane_add_child(n00b_plane_t *parent, n00b_plane_t *child,
                      int32_t x, int32_t y)
{
    assert(child->parent == nullptr);

    child->parent = parent;
    child->x      = x;
    child->y      = y;

    plane_assign_canvas_recursive(child, parent->canvas);

    plane_lock(parent);

    if (!parent->children.data) {
        parent->children = n00b_list_new(n00b_plane_ptr_t);
    }

    n00b_list_push(parent->children, child);

    plane_unlock(parent);
    plane_mark_dirty(parent);
}

bool
n00b_plane_remove_child(n00b_plane_t *parent, n00b_plane_t *child)
{
    n00b_canvas_t *canvas;

    if (!parent || !child || child->parent != parent) {
        return false;
    }

    plane_lock(parent);
    canvas = parent->canvas;

    size_t n = parent->children.len;
    for (size_t i = 0; i < n; i++) {
        if (n00b_list_get(parent->children, i) == child) {
            if (canvas && n00b_plane_tree_contains(child, canvas->mouse_capture)) {
                n00b_canvas_cancel_mouse_capture(canvas);
            }
            (void)n00b_list_delete(parent->children, i);
            child->parent = nullptr;
            plane_clear_canvas_recursive(child);
            plane_unlock(parent);
            plane_mark_dirty(parent);
            return true;
        }
    }

    plane_unlock(parent);
    return false;
}

// -------------------------------------------------------------------
// Draw commands
// -------------------------------------------------------------------

void
n00b_plane_clear(n00b_plane_t *p)
{
    plane_lock(p);
    n00b_draw_list_clear(&p->draw_list);
    plane_mark_dirty(p);
    plane_unlock(p);
}

void
n00b_plane_content_size(n00b_plane_t *p, int32_t *out_w, int32_t *out_h)
{
    // The content area is the plane's width/height in pixels.
    *out_w = p->width;
    *out_h = p->height;
}

void
n00b_plane_draw_text(n00b_plane_t *p, int32_t x, int32_t y,
                      n00b_string_t *text) _kargs
{
    n00b_text_style_t *style = nullptr;
}
{
    if (!text) {
        return;
    }

    n00b_text_style_t *effective = style ? style : p->default_style;
    n00b_draw_cmd_t    cmd       = n00b_draw_cmd_text(x, y, text, effective);

    plane_lock(p);
    n00b_draw_list_append(&p->draw_list, &cmd);
    plane_mark_dirty(p);
    plane_unlock(p);
}

void
n00b_plane_draw_glyph(n00b_plane_t *p, int32_t x, int32_t y,
                       n00b_codepoint_t cp) _kargs
{
    n00b_text_style_t *style = nullptr;
}
{
    n00b_text_style_t *effective = style ? style : p->default_style;
    n00b_draw_cmd_t    cmd       = n00b_draw_cmd_glyph(x, y, cp, effective);

    plane_lock(p);
    n00b_draw_list_append(&p->draw_list, &cmd);
    plane_mark_dirty(p);
    plane_unlock(p);
}

void
n00b_plane_fill_rect(n00b_plane_t *p, int32_t x, int32_t y,
                      int32_t w, int32_t h) _kargs
{
    n00b_codepoint_t   cp    = ' ';
    n00b_text_style_t *style = nullptr;
}
{
    n00b_text_style_t *effective = style ? style : p->default_style;
    n00b_draw_cmd_t    cmd       = n00b_draw_cmd_fill_rect(x, y, w, h,
                                                            cp, effective);

    plane_lock(p);
    n00b_draw_list_append(&p->draw_list, &cmd);
    plane_mark_dirty(p);
    plane_unlock(p);
}

// -------------------------------------------------------------------
// Text measurement (convenience wrappers)
// -------------------------------------------------------------------

int32_t
n00b_plane_text_width(n00b_plane_t *p, n00b_string_t *text,
                       n00b_text_style_t *style)
{
    if (!p || !text) {
        return 0;
    }

    if (p->canvas) {
        n00b_font_metrics_provider_t *fm = &p->canvas->metrics;
        return fm->text_width(fm->ctx, text, style);
    }

    // Fallback: Unicode display width (1 cell = 1 pixel).
    return n00b_unicode_display_width(text);
}

int32_t
n00b_plane_line_height(n00b_plane_t *p, n00b_text_style_t *style)
{
    if (!p || !p->canvas) {
        // Fallback: 1 pixel per cell row.
        return 1;
    }

    n00b_font_metrics_provider_t *fm = &p->canvas->metrics;
    return fm->line_height(fm->ctx, style);
}

int32_t
n00b_plane_text_columns(n00b_plane_t *p, int32_t px_w,
                         n00b_text_style_t *style)
{
    if (!p || px_w <= 0) {
        return 0;
    }

    // Measure a single "M" to get the average character cell width.
    // For fallback metrics this is exactly cell_px_w.
    int32_t cell_w = n00b_plane_text_width(p,
                         r"M", style);

    if (cell_w <= 0) {
        cell_w = 1;
    }

    int32_t cols = px_w / cell_w;
    return cols > 0 ? cols : 1;
}

// -------------------------------------------------------------------
// Viewport / scrolling
// -------------------------------------------------------------------

void
n00b_plane_scroll(n00b_plane_t *p, int32_t dx, int32_t dy)
{
    int64_t new_x = (int64_t)p->scroll_x + dx;
    int64_t new_y = (int64_t)p->scroll_y + dy;

    if (new_x < 0) new_x = 0;
    if (new_y < 0) new_y = 0;

    p->scroll_x = (int32_t)new_x;
    p->scroll_y = (int32_t)new_y;
    plane_mark_dirty(p);
}

void
n00b_plane_scroll_to(n00b_plane_t *p, int32_t x, int32_t y)
{
    p->scroll_x = x < 0 ? 0 : x;
    p->scroll_y = y < 0 ? 0 : y;
    plane_mark_dirty(p);
}

// -------------------------------------------------------------------
// Geometry
// -------------------------------------------------------------------

void
n00b_plane_move(n00b_plane_t *p, int32_t x, int32_t y)
{
    int32_t old_x = p->x;
    int32_t old_y = p->y;
    int32_t dx = 0;
    int32_t dy = 0;

    if (n00b_plane_has_layout_bounds(p)) {
        old_x = p->bounds.x;
        old_y = p->bounds.y;
    }

    dx = x - old_x;
    dy = y - old_y;

    p->x = x;
    p->y = y;

    plane_translate_layout_subtree(p, dx, dy);
    plane_mark_dirty(p);
}

void
n00b_plane_set_z(n00b_plane_t *p, int32_t z)
{
    p->z = z;
    plane_mark_dirty(p);
}

void
n00b_plane_set_visible(n00b_plane_t *p, bool visible)
{
    if (visible) {
        p->flags |= N00B_PLANE_VISIBLE;
    }
    else {
        p->flags &= (uint16_t)~N00B_PLANE_VISIBLE;
    }
    plane_mark_dirty(p);
}

// -------------------------------------------------------------------
// Box decoration
// -------------------------------------------------------------------

void
n00b_plane_set_box(n00b_plane_t *p, n00b_box_props_t *box)
{
    p->box = box;
    plane_mark_dirty(p);
}

// -------------------------------------------------------------------
// Widget state
// -------------------------------------------------------------------

void
n00b_plane_set_state(n00b_plane_t *p, n00b_widget_state_t state)
{
    p->widget_state = state;
    plane_mark_dirty(p);
}

n00b_widget_state_t
n00b_plane_get_state(n00b_plane_t *p)
{
    return p->widget_state;
}

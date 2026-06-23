/*
 * Breadcrumb widget: navigation path with clickable segments.
 *
 * Visual: "Home > Products > Current"
 * Last segment = current (not clickable, primary color).
 * Other segments: secondary color, underline on focus.
 * Separator: dim.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "display/render/plane.h"
#include "display/render/types.h"
#include "display/widget.h"
#include "display/widgets/breadcrumb.h"
#include "display/event.h"
#include "internal/display/widget_primitives.h"
#include "text/unicode/properties.h"
#include "text/strings/text_style.h"
#include "text/strings/string_style.h"
#include "text/strings/theme.h"

#define BC_INIT_CAP 8

static n00b_string_t *bc_default_separator = nullptr;

static n00b_string_t *
bc_get_separator(n00b_breadcrumb_t *bc)
{
    if (bc->separator) {
        return bc->separator;
    }
    if (!bc_default_separator) {
        bc_default_separator = r" > ";
    }
    return bc_default_separator;
}

// -------------------------------------------------------------------
// Internal: recompute segment positions (pixel offsets)
// -------------------------------------------------------------------

static void
bc_recompute_positions(n00b_plane_t *plane, n00b_breadcrumb_t *bc)
{
    if (bc->count == 0) {
        return;
    }

    if (!bc->seg_positions || bc->capacity == 0) {
        bc->seg_positions = n00b_alloc_array(int32_t, bc->capacity);
    }

    n00b_string_t *sep = bc_get_separator(bc);
    int32_t sep_w = n00b_plane_text_width(plane, sep, nullptr);

    int32_t col = 0;
    for (n00b_isize_t i = 0; i < bc->count; i++) {
        bc->seg_positions[i] = col;
        int32_t label_w = 0;
        if (bc->segments[i].label) {
            label_w = n00b_plane_text_width(plane,
                                            bc->segments[i].label,
                                            nullptr);
        }
        col += label_w;
        if (i < bc->count - 1) {
            col += sep_w;
        }
    }
}

// -------------------------------------------------------------------
// Internal: clamp focused_index to valid clickable range
// -------------------------------------------------------------------

static void
bc_clamp_focus(n00b_breadcrumb_t *bc)
{
    // Only segments before the last are clickable.
    n00b_isize_t max_focus = bc->count > 1 ? bc->count - 2 : 0;
    if (bc->focused_index > max_focus) {
        bc->focused_index = max_focus;
    }
    if (bc->focused_index < 0) {
        bc->focused_index = 0;
    }
}

// -------------------------------------------------------------------
// Vtable callbacks
// -------------------------------------------------------------------

static void
breadcrumb_destroy(n00b_plane_t *plane, void *data)
{
    (void)plane;
    (void)data;
}

static void
breadcrumb_render(n00b_plane_t *plane, void *data)
{
    n00b_breadcrumb_t *bc = (n00b_breadcrumb_t *)data;
    if (!bc) {
        return;
    }

    n00b_plane_clear(plane);

    int32_t content_w;
    int32_t content_h;
    n00b_plane_content_size(plane, &content_w, &content_h);

    if (content_w == 0 || content_h == 0 || bc->count == 0) {
        return;
    }

    bool widget_focused = n00b_widget_state_is_focused_or_active(plane);

    bc_recompute_positions(plane, bc);
    bc_clamp_focus(bc);

    n00b_string_t *sep = bc_get_separator(bc);

    // Separator style: dim.
    n00b_text_style_t *sep_style = n00b_alloc(n00b_text_style_t);
    sep_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_TEXT_DISABLED);

    n00b_string_t *sep_styled = n00b_str_set_base_style(sep, sep_style);

    int32_t col = 0;

    for (n00b_isize_t i = 0; i < bc->count; i++) {
        n00b_string_t *label = bc->segments[i].label;
        if (!label) {
            continue;
        }

        bool is_last    = (i == bc->count - 1);
        bool is_focused = (widget_focused && !is_last
                           && i == bc->focused_index);

        n00b_text_style_t *seg_style = n00b_alloc(n00b_text_style_t);

        if (is_last) {
            // Current location: primary, bold.
            seg_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_TEXT_PRIMARY);
            seg_style->bold   = N00B_TRI_YES;
        }
        else if (is_focused) {
            // Focused clickable: focus color + underline.
            seg_style->fg_rgb    = n00b_theme_resolve_color(N00B_PAL_FOCUS);
            seg_style->bold      = N00B_TRI_YES;
            seg_style->underline = N00B_TRI_YES;
        }
        else {
            // Normal clickable: secondary.
            seg_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_TEXT_SECONDARY);
        }

        n00b_string_t *styled = n00b_str_set_base_style(label, seg_style);

        if (col < content_w) {
            n00b_plane_draw_text(plane, col, 0, styled);
        }
        col += n00b_plane_text_width(plane, label, seg_style);

        // Separator (not after last).
        if (!is_last && col < content_w) {
            n00b_plane_draw_text(plane, col, 0, sep_styled);
            col += n00b_plane_text_width(plane, sep, sep_style);
        }
    }
}

static bool
breadcrumb_handle_event(n00b_plane_t *plane, void *data,
                        const n00b_event_t *event)
{
    n00b_breadcrumb_t *bc = (n00b_breadcrumb_t *)data;
    if (!bc || bc->count == 0) {
        return false;
    }

    // Mouse click: hit-test segments.
    if (event->type == N00B_EVENT_MOUSE) {
        if (n00b_widget_event_is_left_press(event)) {
            bc_recompute_positions(plane, bc);
            int32_t click_col = event->mouse.x;

            for (n00b_isize_t i = 0; i < bc->count - 1; i++) {
                int32_t start = bc->seg_positions[i];
                int32_t label_w = 0;
                if (bc->segments[i].label) {
                    label_w = n00b_plane_text_width(plane,
                                                    bc->segments[i].label,
                                                    nullptr);
                }
                int32_t end = start + label_w;

                if (click_col >= start && click_col < end) {
                    bc->focused_index = i;
                    n00b_plane_mark_dirty(plane);
                    if (bc->on_click) {
                        bc->on_click(plane, i, bc->on_click_data);
                    }
                    return true;
                }
            }
            return true; // consumed even if not on a segment
        }
        return false;
    }

    if (event->type != N00B_EVENT_KEY) {
        return false;
    }

    uint32_t key = event->key.key;
    n00b_isize_t max_focus = bc->count > 1 ? bc->count - 2 : 0;

    if (key == N00B_KEY_RIGHT) {
        if (bc->focused_index < max_focus) {
            bc->focused_index++;
        }
        n00b_plane_mark_dirty(plane);
        return true;
    }

    if (key == N00B_KEY_LEFT) {
        if (bc->focused_index > 0) {
            bc->focused_index--;
        }
        n00b_plane_mark_dirty(plane);
        return true;
    }

    // Enter/Space activates focused segment (not last).
    if (n00b_widget_event_is_keyboard_activate(event)) {
        if (bc->count > 1 && bc->focused_index < bc->count - 1) {
            if (bc->on_click) {
                bc->on_click(plane, bc->focused_index, bc->on_click_data);
            }
        }
        return true;
    }

    return false;
}

static bool
breadcrumb_can_focus(n00b_plane_t *plane, void *data)
{
    (void)plane;
    (void)data;
    return true;
}

static void
breadcrumb_measure(n00b_plane_t *plane, void *data,
                   int32_t *pref_w, int32_t *pref_h,
                   int32_t *min_w,  int32_t *min_h)
{
    n00b_breadcrumb_t *bc = (n00b_breadcrumb_t *)data;

    int32_t lh = n00b_widget_line_px_height(plane);

    int32_t total_w = 0;
    if (bc && bc->count > 0) {
        n00b_string_t *sep = bc_get_separator(bc);
        int32_t sep_w = n00b_plane_text_width(plane, sep, nullptr);

        for (n00b_isize_t i = 0; i < bc->count; i++) {
            if (bc->segments[i].label) {
                total_w += n00b_plane_text_width(plane,
                                                 bc->segments[i].label,
                                                 nullptr);
            }
            if (i < bc->count - 1) {
                total_w += sep_w;
            }
        }
    }

    *pref_w = total_w > 0 ? total_w : 1;
    *pref_h = lh;
    *min_w  = 1;
    *min_h  = lh;
}

// -------------------------------------------------------------------
// Vtable instance
// -------------------------------------------------------------------

const n00b_widget_vtable_t n00b_widget_breadcrumb = {
    .kind         = "breadcrumb",
    .destroy      = breadcrumb_destroy,
    .render       = breadcrumb_render,
    .measure      = breadcrumb_measure,
    .handle_event = breadcrumb_handle_event,
    .can_focus    = breadcrumb_can_focus,
};

// -------------------------------------------------------------------
// Internal: ensure capacity
// -------------------------------------------------------------------

static void
bc_ensure_capacity(n00b_breadcrumb_t *bc, n00b_isize_t needed)
{
    if (needed <= bc->capacity) {
        return;
    }

    n00b_isize_t new_cap = bc->capacity * 2;
    if (new_cap < needed) {
        new_cap = needed;
    }

    n00b_breadcrumb_seg_t *new_segs = n00b_alloc_array(n00b_breadcrumb_seg_t,
                                                         new_cap);
    int32_t *new_pos = n00b_alloc_array(int32_t, new_cap);

    for (n00b_isize_t i = 0; i < bc->count; i++) {
        new_segs[i] = bc->segments[i];
    }

    bc->segments      = new_segs;
    bc->seg_positions = new_pos;
    bc->capacity      = new_cap;
}

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

n00b_plane_t *
n00b_breadcrumb_new() _kargs {
    n00b_string_t        *separator      = nullptr;
    n00b_breadcrumb_cb_t  on_click       = nullptr;
    void                 *on_click_data  = nullptr;
    int32_t               width          = 40;
    int32_t               height         = 1;
    n00b_text_style_t    *style          = nullptr;
    n00b_canvas_t        *canvas         = nullptr;
    n00b_allocator_t     *allocator      = nullptr;
}
{
    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t, plane,
                                           .style     = style,
                                           .canvas    = canvas,
                                           .allocator = allocator);

    if (height <= 1) {
        height = n00b_plane_line_height(plane, nullptr);
    }
    if (height <= 0) {
        height = 1;
    }

    plane->width = width;
    plane->height = height;

    plane->flex.align_self = N00B_ALIGN_START_CROSS;

    n00b_breadcrumb_t *bc = n00b_alloc(n00b_breadcrumb_t);
    bc->segments      = n00b_alloc_array(n00b_breadcrumb_seg_t, BC_INIT_CAP);
    bc->seg_positions = n00b_alloc_array(int32_t, BC_INIT_CAP);
    bc->count         = 0;
    bc->capacity      = BC_INIT_CAP;
    bc->separator     = separator;
    bc->focused_index = 0;
    bc->on_click      = on_click;
    bc->on_click_data = on_click_data;

    n00b_widget_attach(plane, &n00b_widget_breadcrumb, bc);
    n00b_plane_mark_dirty(plane);

    return plane;
}

void
n00b_breadcrumb_push(n00b_plane_t  *plane,
                      n00b_string_t *label,
                      void          *data)
{
    n00b_breadcrumb_t *bc =
        n00b_widget_data_if_kind(plane, &n00b_widget_breadcrumb);
    if (!bc) {
        return;
    }

    bc_ensure_capacity(bc, bc->count + 1);

    bc->segments[bc->count].label = label;
    bc->segments[bc->count].data  = data;
    bc->count++;

    bc_clamp_focus(bc);
    n00b_plane_mark_dirty(plane);
}

void
n00b_breadcrumb_pop(n00b_plane_t *plane)
{
    n00b_breadcrumb_t *bc =
        n00b_widget_data_if_kind(plane, &n00b_widget_breadcrumb);
    if (!bc) {
        return;
    }

    if (bc->count > 0) {
        bc->count--;
        bc_clamp_focus(bc);
        n00b_plane_mark_dirty(plane);
    }
}

void
n00b_breadcrumb_clear(n00b_plane_t *plane)
{
    n00b_breadcrumb_t *bc =
        n00b_widget_data_if_kind(plane, &n00b_widget_breadcrumb);
    if (!bc) {
        return;
    }

    bc->count         = 0;
    bc->focused_index = 0;
    n00b_plane_mark_dirty(plane);
}

n00b_isize_t
n00b_breadcrumb_count(n00b_plane_t *plane)
{
    n00b_breadcrumb_t *bc =
        n00b_widget_data_if_kind(plane, &n00b_widget_breadcrumb);
    if (!bc) {
        return 0;
    }

    return bc->count;
}

void
n00b_breadcrumb_set_path(n00b_plane_t   *plane,
                          n00b_string_t **labels,
                          n00b_isize_t    count)
{
    n00b_breadcrumb_t *bc =
        n00b_widget_data_if_kind(plane, &n00b_widget_breadcrumb);
    if (!bc) {
        return;
    }

    bc_ensure_capacity(bc, count);

    bc->count = count;
    for (n00b_isize_t i = 0; i < count; i++) {
        bc->segments[i].label = labels[i];
        bc->segments[i].data  = nullptr;
    }

    bc->focused_index = 0;
    bc_clamp_focus(bc);
    n00b_plane_mark_dirty(plane);
}

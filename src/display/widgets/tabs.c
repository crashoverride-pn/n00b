/*
 * Tabs widget: focusable multi-page container with a one-line header.
 */

#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "display/event.h"
#include "display/focus.h"
#include "display/mouse.h"
#include "display/render/plane.h"
#include "display/widget.h"
#include "display/widgets/tabs.h"
#include "internal/display/plane_tree.h"
#include "internal/display/widget_primitives.h"
#include "text/strings/style_ops.h"
#include "text/strings/theme.h"

#define TABS_INIT_CAPACITY 4

static n00b_string_t *tabs_default_separator = nullptr;

static n00b_tabs_t *
tabs_data(n00b_plane_t *plane)
{
    return (n00b_tabs_t *)n00b_widget_data_if_kind(plane, &n00b_widget_tabs);
}

static bool
tabs_has_valid_bounds(const n00b_plane_t *plane)
{
    return plane && plane->bounds.width > 0 && plane->bounds.height > 0;
}

static n00b_string_t *
tabs_separator(const n00b_tabs_t *tabs)
{
    if (tabs && tabs->separator) {
        return tabs->separator;
    }

    if (!tabs_default_separator) {
        tabs_default_separator = r" | ";
    }

    return tabs_default_separator;
}

static void
tabs_measure_content(n00b_plane_t *content,
                     int32_t      *pref_w,
                     int32_t      *pref_h,
                     int32_t      *min_w,
                     int32_t      *min_h)
{
    if (!content) {
        *pref_w = 0;
        *pref_h = 0;
        *min_w = 0;
        *min_h = 0;
        return;
    }

    if (content->widget_vtable) {
        n00b_widget_measure(content, pref_w, pref_h, min_w, min_h);
        return;
    }

    n00b_widget_measure_plain_plane(content, pref_w, pref_h, min_w, min_h);
}

static void
tabs_ensure_capacity(n00b_tabs_t *tabs, n00b_isize_t needed)
{
    n00b_isize_t     new_capacity;
    n00b_tab_entry_t *new_entries;
    n00b_rect_t      *new_rects;

    if (!tabs || needed <= tabs->capacity) {
        return;
    }

    new_capacity = tabs->capacity ? tabs->capacity : TABS_INIT_CAPACITY;
    while (new_capacity < needed) {
        new_capacity *= 2;
    }

    new_entries = n00b_alloc_array(n00b_tab_entry_t, new_capacity);
    new_rects   = n00b_alloc_array(n00b_rect_t, new_capacity);

    if (tabs->entries && tabs->count > 0) {
        memcpy(new_entries,
               tabs->entries,
               (size_t)tabs->count * sizeof(n00b_tab_entry_t));
    }
    if (tabs->header_rects && tabs->count > 0) {
        memcpy(new_rects,
               tabs->header_rects,
               (size_t)tabs->count * sizeof(n00b_rect_t));
    }

    if (tabs->entries) {
        n00b_free(tabs->entries);
    }
    if (tabs->header_rects) {
        n00b_free(tabs->header_rects);
    }

    tabs->entries      = new_entries;
    tabs->header_rects = new_rects;
    tabs->capacity     = new_capacity;
}

static void
tabs_recompute_header_rects(n00b_plane_t *plane, n00b_tabs_t *tabs)
{
    int32_t        x;
    int32_t        y;
    int32_t        header_h;
    int32_t        sep_w;
    n00b_string_t *separator;

    if (!plane || !tabs) {
        return;
    }

    header_h = tabs->header_height_px > 0
             ? tabs->header_height_px
             : n00b_widget_line_px_height(plane);
    tabs->header_height_px = header_h > 0 ? header_h : 1;

    y = 0;
    if (tabs->position == N00B_TABS_BOTTOM && plane->height > tabs->header_height_px) {
        y = plane->height - tabs->header_height_px;
    }

    separator = tabs_separator(tabs);
    sep_w     = n00b_plane_text_width(plane, separator, nullptr);
    x         = 0;

    for (n00b_isize_t i = 0; i < tabs->count; i++) {
        int32_t label_w = n00b_plane_text_width(plane, tabs->entries[i].name, nullptr);

        tabs->header_rects[i] = (n00b_rect_t){
            .x      = x,
            .y      = y,
            .width  = label_w > 0 ? label_w : 0,
            .height = tabs->header_height_px,
        };

        x += label_w;
        if (i + 1 < tabs->count) {
            x += sep_w;
        }
    }
}

static void
tabs_apply_visibility(n00b_tabs_t *tabs)
{
    if (!tabs) {
        return;
    }

    for (n00b_isize_t i = 0; i < tabs->count; i++) {
        n00b_plane_t *content = tabs->entries[i].content;
        if (!content) {
            continue;
        }

        n00b_plane_set_visible(content, tabs->selected_index >= 0
                                         && (n00b_isize_t)tabs->selected_index == i);
    }
}

static bool
tabs_cancel_capture_if_hidden(n00b_plane_t *tabs_plane, n00b_plane_t *content)
{
    n00b_plane_t *captured;

    if (!tabs_plane || !content || !tabs_plane->canvas) {
        return false;
    }

    captured = n00b_canvas_get_mouse_capture_plane(tabs_plane->canvas);
    if (!captured || !n00b_plane_tree_contains(content, captured)) {
        return false;
    }

    n00b_canvas_cancel_mouse_capture(tabs_plane->canvas);
    return true;
}

static bool
tabs_plane_is_descendant_of(n00b_plane_t *plane, n00b_plane_t *ancestor)
{
    while (plane) {
        if (plane == ancestor) {
            return true;
        }
        plane = plane->parent;
    }

    return false;
}

static void
tabs_relayout_if_needed(n00b_plane_t *plane)
{
    if (!plane) {
        return;
    }

    if (tabs_has_valid_bounds(plane)) {
        n00b_widget_layout(plane, plane->bounds);
        return;
    }

    n00b_plane_mark_dirty(plane);
}

static void
tabs_rebuild_focus_after_visibility_change(n00b_plane_t *plane,
                                           n00b_plane_t *old_focus,
                                           n00b_plane_t *old_content,
                                           bool          force_tabs_focus)
{
    n00b_focus_mgr_t *fm;
    bool              old_focus_hidden;

    if (!plane || !plane->canvas || !plane->canvas->focus) {
        return;
    }

    fm = plane->canvas->focus;
    old_focus_hidden = old_focus && old_content
                    && tabs_plane_is_descendant_of(old_focus, old_content);

    n00b_focus_mgr_rebuild(fm);

    if (force_tabs_focus || old_focus_hidden) {
        (void)n00b_focus_mgr_set(fm, plane);
    }
}

static void
tabs_destroy(n00b_plane_t *plane, void *data)
{
    n00b_tabs_t *tabs = (n00b_tabs_t *)data;

    (void)plane;

    if (!tabs) {
        return;
    }

    if (tabs->entries) {
        n00b_free(tabs->entries);
    }
    if (tabs->header_rects) {
        n00b_free(tabs->header_rects);
    }

    n00b_free(tabs);
}

static void
tabs_render(n00b_plane_t *plane, void *data)
{
    n00b_tabs_t        *tabs = (n00b_tabs_t *)data;
    n00b_text_style_t  *selected_style;
    n00b_text_style_t  *focused_selected_style;
    n00b_text_style_t  *unselected_style;
    n00b_text_style_t  *separator_style;
    n00b_string_t      *separator;
    bool                focused;
    int32_t             x;
    int32_t             y;
    int32_t             sep_w;

    if (!tabs) {
        return;
    }

    n00b_plane_clear(plane);

    focused = n00b_widget_state_is_focused_or_active(plane);

    selected_style = n00b_str_style_new();
    selected_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_TEXT_PRIMARY);
    selected_style->bold   = N00B_TRI_YES;

    focused_selected_style = n00b_str_style_new();
    focused_selected_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_FOCUS);
    focused_selected_style->bold   = N00B_TRI_YES;
    focused_selected_style->underline = N00B_TRI_YES;

    unselected_style = n00b_str_style_new();
    unselected_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_TEXT_SECONDARY);

    separator_style = n00b_str_style_new();
    separator_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_TEXT_DISABLED);
    separator_style->dim    = N00B_TRI_YES;

    tabs_recompute_header_rects(plane, tabs);

    separator = tabs_separator(tabs);
    sep_w     = n00b_plane_text_width(plane, separator, nullptr);
    x         = 0;
    y         = tabs->position == N00B_TABS_BOTTOM && plane->height > tabs->header_height_px
              ? plane->height - tabs->header_height_px
              : 0;

    for (n00b_isize_t i = 0; i < tabs->count; i++) {
        n00b_text_style_t *label_style = ((int32_t)i == tabs->selected_index)
                                       ? (focused ? focused_selected_style : selected_style)
                                       : unselected_style;

        n00b_plane_draw_text(plane,
                             x,
                             y,
                             tabs->entries[i].name,
                             .style = label_style);
        x += tabs->header_rects[i].width;

        if (i + 1 < tabs->count) {
            n00b_plane_draw_text(plane,
                                 x,
                                 y,
                                 separator,
                                 .style = separator_style);
            x += sep_w;
        }
    }
}

static void
tabs_measure(n00b_plane_t *plane, void *data,
             int32_t *pref_w, int32_t *pref_h,
             int32_t *min_w, int32_t *min_h)
{
    n00b_tabs_t   *tabs = (n00b_tabs_t *)data;
    int32_t        header_h;
    int32_t        header_total_w = 0;
    int32_t        max_content_pref_w = 0;
    int32_t        max_content_pref_h = 0;
    int32_t        max_content_min_w = 0;
    int32_t        max_content_min_h = 0;
    n00b_string_t *separator;
    int32_t        sep_w = 0;

    header_h = n00b_widget_line_px_height(plane);
    if (header_h <= 0) {
        header_h = 1;
    }

    if (!tabs || tabs->count == 0) {
        *pref_w = 1;
        *pref_h = header_h;
        *min_w  = 1;
        *min_h  = header_h;
        return;
    }

    separator = tabs_separator(tabs);
    sep_w     = n00b_plane_text_width(plane, separator, nullptr);

    for (n00b_isize_t i = 0; i < tabs->count; i++) {
        int32_t label_w = n00b_plane_text_width(plane, tabs->entries[i].name, nullptr);

        header_total_w += label_w;
        if (i + 1 < tabs->count) {
            header_total_w += sep_w;
        }

        if (tabs->entries[i].content) {
            int32_t child_pref_w = 0;
            int32_t child_pref_h = 0;
            int32_t child_min_w  = 0;
            int32_t child_min_h  = 0;

            tabs_measure_content(tabs->entries[i].content,
                                 &child_pref_w,
                                 &child_pref_h,
                                 &child_min_w,
                                 &child_min_h);

            max_content_pref_w = n00b_max(max_content_pref_w, child_pref_w);
            max_content_pref_h = n00b_max(max_content_pref_h, child_pref_h);
            max_content_min_w  = n00b_max(max_content_min_w, child_min_w);
            max_content_min_h  = n00b_max(max_content_min_h, child_min_h);
        }
    }

    *pref_w = n00b_max(n00b_max(header_total_w, max_content_pref_w), 1);
    *pref_h = header_h + n00b_max(max_content_pref_h, 1);
    *min_w  = n00b_max(max_content_min_w, 1);
    *min_h  = header_h + n00b_max(max_content_min_h, 1);
}

static bool
tabs_handle_event(n00b_plane_t *plane, void *data, const n00b_event_t *event)
{
    n00b_tabs_t *tabs = (n00b_tabs_t *)data;
    int32_t      header_h;
    int32_t      header_y;

    if (!tabs || !event) {
        return false;
    }

    if (event->type == N00B_EVENT_KEY) {
        if (event->key.key == N00B_KEY_LEFT) {
            return n00b_tabs_prev(plane);
        }
        if (event->key.key == N00B_KEY_RIGHT) {
            return n00b_tabs_next(plane);
        }
        return false;
    }

    if (!n00b_widget_event_is_left_press(event)) {
        return false;
    }

    header_h = tabs->header_height_px > 0
             ? tabs->header_height_px
             : n00b_widget_line_px_height(plane);
    if (header_h <= 0) {
        header_h = 1;
    }

    header_y = tabs->position == N00B_TABS_BOTTOM && plane->height > header_h
             ? plane->height - header_h
             : 0;

    if (event->mouse.y < header_y || event->mouse.y >= header_y + header_h) {
        return false;
    }

    for (n00b_isize_t i = 0; i < tabs->count; i++) {
        n00b_rect_t rect = tabs->header_rects ? tabs->header_rects[i] : (n00b_rect_t){};

        if (event->mouse.x >= rect.x
            && event->mouse.x < rect.x + rect.width
            && event->mouse.y >= rect.y
            && event->mouse.y < rect.y + rect.height) {
            if ((int32_t)i == tabs->selected_index) {
                return true;
            }

            return n00b_tabs_select_index(plane, (int)i);
        }
    }

    return false;
}

static bool
tabs_can_focus(n00b_plane_t *plane, void *data)
{
    (void)plane;
    (void)data;

    return true;
}

static void
tabs_layout(n00b_plane_t *plane, void *data, n00b_rect_t bounds)
{
    n00b_tabs_t *tabs = (n00b_tabs_t *)data;
    n00b_rect_t  content_bounds;
    int32_t      header_h;
    int32_t      header_y;

    if (!plane || !tabs) {
        return;
    }

    header_h = n00b_widget_line_px_height(plane);
    if (header_h <= 0) {
        header_h = 1;
    }

    tabs->header_height_px = header_h;
    header_y = tabs->position == N00B_TABS_BOTTOM && bounds.height > header_h
             ? bounds.height - header_h
             : 0;
    (void)header_y;

    if (tabs->position == N00B_TABS_TOP) {
        content_bounds = (n00b_rect_t){
            .x      = bounds.x,
            .y      = bounds.y + header_h,
            .width  = bounds.width,
            .height = bounds.height > header_h ? bounds.height - header_h : 0,
        };
    }
    else {
        content_bounds = (n00b_rect_t){
            .x      = bounds.x,
            .y      = bounds.y,
            .width  = bounds.width,
            .height = bounds.height > header_h ? bounds.height - header_h : 0,
        };
    }

    tabs_recompute_header_rects(plane, tabs);
    tabs_apply_visibility(tabs);

    for (n00b_isize_t i = 0; i < tabs->count; i++) {
        if (tabs->entries[i].content) {
            n00b_widget_layout(tabs->entries[i].content, content_bounds);
        }
    }
}

const n00b_widget_vtable_t n00b_widget_tabs = {
    .kind         = "tabs",
    .destroy      = tabs_destroy,
    .render       = tabs_render,
    .measure      = tabs_measure,
    .handle_event = tabs_handle_event,
    .can_focus    = tabs_can_focus,
    .layout       = tabs_layout,
};

n00b_plane_t *
n00b_tabs_new() _kargs {
    n00b_tabs_position_t  position       = N00B_TABS_TOP;
    n00b_string_t        *separator      = nullptr;
    n00b_tabs_select_cb_t on_select      = nullptr;
    void                 *on_select_data = nullptr;
    n00b_canvas_t        *canvas         = nullptr;
    n00b_allocator_t     *allocator      = nullptr;
}
{
    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t, plane,
                                         .canvas    = canvas,
                                         .allocator = allocator);
    n00b_tabs_t  *tabs  = n00b_alloc(n00b_tabs_t);

    memset(tabs, 0, sizeof(*tabs));
    tabs->position       = position;
    tabs->separator      = separator;
    tabs->on_select      = on_select;
    tabs->on_select_data = on_select_data;
    tabs->selected_index = -1;

    n00b_widget_attach(plane, &n00b_widget_tabs, tabs);
    n00b_plane_mark_dirty(plane);

    return plane;
}

int
n00b_tabs_add(n00b_plane_t *plane, n00b_string_t *name, n00b_plane_t *content)
{
    n00b_tabs_t        *tabs;
    n00b_focus_mgr_t   *fm;
    n00b_isize_t        new_index;

    tabs = tabs_data(plane);
    if (!tabs || !name || (content && content->parent != nullptr)) {
        return -1;
    }

    tabs_ensure_capacity(tabs, tabs->count + 1);

    new_index = tabs->count;
    tabs->entries[new_index] = (n00b_tab_entry_t){
        .name    = name,
        .content = content,
    };
    tabs->header_rects[new_index] = (n00b_rect_t){};
    tabs->count++;

    if (content) {
        n00b_plane_add_child(plane, content, 0, 0);
    }

    if (tabs->selected_index < 0) {
        tabs->selected_index = (int32_t)new_index;
    }

    tabs_apply_visibility(tabs);
    tabs_relayout_if_needed(plane);

    fm = plane && plane->canvas ? plane->canvas->focus : nullptr;
    if (fm) {
        n00b_focus_mgr_rebuild(fm);
    }

    return (int)new_index;
}

bool
n00b_tabs_remove(n00b_plane_t *plane, int index)
{
    n00b_tabs_t      *tabs;
    n00b_plane_t     *removed_content;
    n00b_plane_t     *old_focus;
    int32_t           old_selected;
    bool              force_tabs_focus;

    tabs = tabs_data(plane);
    if (!tabs || index < 0 || (n00b_isize_t)index >= tabs->count) {
        return false;
    }

    removed_content  = tabs->entries[index].content;
    old_selected     = tabs->selected_index;
    old_focus        = plane && plane->canvas && plane->canvas->focus
                     ? n00b_focus_mgr_current_plane(plane->canvas->focus)
                     : nullptr;
    force_tabs_focus = old_focus && removed_content
                    && tabs_plane_is_descendant_of(old_focus, removed_content);

    (void)tabs_cancel_capture_if_hidden(plane, removed_content);

    if (removed_content && removed_content->parent == plane) {
        (void)n00b_plane_remove_child(plane, removed_content);
        n00b_plane_set_visible(removed_content, true);
    }

    if ((n00b_isize_t)(index + 1) < tabs->count) {
        memmove(&tabs->entries[index],
                &tabs->entries[index + 1],
                (size_t)(tabs->count - (n00b_isize_t)index - 1)
                * sizeof(n00b_tab_entry_t));
        memmove(&tabs->header_rects[index],
                &tabs->header_rects[index + 1],
                (size_t)(tabs->count - (n00b_isize_t)index - 1)
                * sizeof(n00b_rect_t));
    }

    tabs->count--;

    if (tabs->count == 0) {
        tabs->selected_index = -1;
    }
    else if (old_selected == index) {
        if ((n00b_isize_t)index < tabs->count) {
            tabs->selected_index = index;
        }
        else {
            tabs->selected_index = (int32_t)tabs->count - 1;
        }
    }
    else if (index < old_selected) {
        tabs->selected_index = old_selected - 1;
    }

    tabs_apply_visibility(tabs);
    tabs_relayout_if_needed(plane);
    tabs_rebuild_focus_after_visibility_change(plane,
                                               old_focus,
                                               removed_content,
                                               force_tabs_focus);

    return true;
}

bool
n00b_tabs_select_index(n00b_plane_t *plane, int index)
{
    n00b_tabs_t *tabs;
    n00b_plane_t *old_focus;
    n00b_plane_t *old_content;
    int32_t       old_index;

    tabs = tabs_data(plane);
    if (!tabs || index < 0 || (n00b_isize_t)index >= tabs->count) {
        return false;
    }

    if (tabs->selected_index == index) {
        return false;
    }

    old_index   = tabs->selected_index;
    old_content = old_index >= 0 && (n00b_isize_t)old_index < tabs->count
                ? tabs->entries[old_index].content
                : nullptr;
    old_focus   = plane && plane->canvas && plane->canvas->focus
                ? n00b_focus_mgr_current_plane(plane->canvas->focus)
                : nullptr;

    (void)tabs_cancel_capture_if_hidden(plane, old_content);

    tabs->selected_index = index;
    tabs_apply_visibility(tabs);
    tabs_relayout_if_needed(plane);

    if (tabs->on_select) {
        tabs->on_select(plane, index, old_index, tabs->on_select_data);
    }

    tabs_rebuild_focus_after_visibility_change(plane,
                                               old_focus,
                                               old_content,
                                               false);

    return true;
}

int
n00b_tabs_selected_index(n00b_plane_t *plane)
{
    n00b_tabs_t *tabs = tabs_data(plane);
    return tabs ? tabs->selected_index : -1;
}

int
n00b_tabs_count(n00b_plane_t *plane)
{
    n00b_tabs_t *tabs = tabs_data(plane);
    return tabs ? (int)tabs->count : 0;
}

n00b_tab_entry_t *
n00b_tabs_get(n00b_plane_t *plane, int index)
{
    n00b_tabs_t *tabs = tabs_data(plane);

    if (!tabs || index < 0 || (n00b_isize_t)index >= tabs->count) {
        return nullptr;
    }

    return &tabs->entries[index];
}

bool
n00b_tabs_next(n00b_plane_t *plane)
{
    n00b_tabs_t *tabs = tabs_data(plane);
    int          next;

    if (!tabs || tabs->count == 0) {
        return false;
    }

    next = tabs->selected_index >= 0
         ? (tabs->selected_index + 1) % (int32_t)tabs->count
         : 0;

    return n00b_tabs_select_index(plane, next);
}

bool
n00b_tabs_prev(n00b_plane_t *plane)
{
    n00b_tabs_t *tabs = tabs_data(plane);
    int          prev;

    if (!tabs || tabs->count == 0) {
        return false;
    }

    if (tabs->selected_index < 0) {
        prev = (int)tabs->count - 1;
    }
    else if (tabs->selected_index == 0) {
        prev = (int)tabs->count - 1;
    }
    else {
        prev = tabs->selected_index - 1;
    }

    return n00b_tabs_select_index(plane, prev);
}

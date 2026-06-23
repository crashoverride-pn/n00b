/*
 * Divider widget: horizontal or vertical separator line with optional label.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "display/render/plane.h"
#include "display/render/types.h"
#include "display/widget.h"
#include "display/widgets/divider.h"
#include "text/unicode/properties.h"

// Default border theme if none specified.
extern const n00b_border_theme_t n00b_border_plain;

// -------------------------------------------------------------------
// Vtable callbacks
// -------------------------------------------------------------------

static void
divider_destroy(n00b_plane_t *plane, void *data)
{
    (void)plane;
    (void)data;
}

static void
divider_render(n00b_plane_t *plane, void *data)
{
    n00b_divider_t *div = (n00b_divider_t *)data;
    if (!div) {
        return;
    }

    n00b_plane_clear(plane);

    int32_t content_w;
    int32_t content_h;
    n00b_plane_content_size(plane, &content_w, &content_h);

    if (content_w == 0 || content_h == 0) {
        return;
    }

    int32_t cpw = n00b_plane_text_width(plane, r"M", nullptr);
    if (cpw <= 0) {
        cpw = 1;
    }
    int32_t lh = n00b_plane_line_height(plane, nullptr);
    if (lh <= 0) {
        lh = 1;
    }

    const n00b_border_theme_t *theme = div->theme;
    if (!theme) {
        theme = &n00b_border_plain;
    }

    n00b_codepoint_t line_cp = div->line_char;

    if (div->vertical) {
        if (line_cp == 0) {
            line_cp = theme->vertical;
        }
        // Draw a vertical line: one glyph wide (cpw px), full content height.
        n00b_plane_fill_rect(plane, 0, 0, cpw, content_h, .cp = line_cp);
    }
    else {
        if (line_cp == 0) {
            line_cp = theme->horizontal;
        }

        if (!div->label || div->label->u8_bytes == 0) {
            // No label: fill the entire row with one line-height of glyphs.
            n00b_plane_fill_rect(plane, 0, 0, content_w, lh, .cp = line_cp);
        }
        else {
            // Label centered with gaps: "──── Label ────"
            // Reserve one character-cell gap on each side of the label.
            int32_t label_width = n00b_plane_text_width(plane, div->label, nullptr);
            int32_t total_line  = content_w - label_width - 2 * cpw;
            int32_t left_len;
            int32_t right_len;

            if (total_line < 2 * cpw) {
                // Not enough room — just render the label.
                n00b_plane_draw_text(plane, 0, 0, div->label);
                return;
            }

            left_len  = total_line / 2;
            right_len = total_line - left_len;

            // Left line segment.
            n00b_plane_fill_rect(plane, 0, 0, left_len, lh, .cp = line_cp);

            // Space + label + space (one character-cell gap each side).
            int32_t label_x = left_len + cpw;
            n00b_plane_draw_text(plane, label_x, 0, div->label);

            // Right line segment.
            int32_t right_start = label_x + label_width + cpw;
            if (right_start < content_w) {
                n00b_plane_fill_rect(plane, right_start, 0,
                                      content_w - right_start, lh, .cp = line_cp);
            }
        }
    }
}

static void
divider_measure(n00b_plane_t *plane, void *data,
                int32_t *pref_w, int32_t *pref_h,
                int32_t *min_w,  int32_t *min_h)
{
    n00b_divider_t *div = (n00b_divider_t *)data;

    int32_t cpw = n00b_plane_text_width(plane, r"M", nullptr);
    if (cpw <= 0) {
        cpw = 1;
    }
    int32_t lh = n00b_plane_line_height(plane, nullptr);
    if (lh <= 0) {
        lh = 1;
    }

    if (div && div->vertical) {
        *pref_w = cpw;
        *pref_h = 3 * lh;
        *min_w  = cpw;
        *min_h  = lh;
    }
    else {
        *pref_w = 20 * cpw;
        *pref_h = lh;
        *min_w  = cpw;
        *min_h  = lh;
    }
}

// -------------------------------------------------------------------
// Vtable instance
// -------------------------------------------------------------------

const n00b_widget_vtable_t n00b_widget_divider = {
    .kind    = "divider",
    .destroy = divider_destroy,
    .render  = divider_render,
    .measure = divider_measure,
};

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

n00b_plane_t *
n00b_divider_new() _kargs {
    bool                       vertical   = false;
    n00b_string_t             *label      = nullptr;
    const n00b_border_theme_t *theme      = nullptr;
    n00b_codepoint_t           line_char  = 0;
    int32_t                    width      = 0;
    int32_t                    height     = 0;
    n00b_text_style_t         *style      = nullptr;
    n00b_canvas_t             *canvas     = nullptr;
    n00b_allocator_t          *allocator  = nullptr;
}
{
    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t, plane,
                                           .style     = style,
                                           .canvas    = canvas,
                                           .allocator = allocator);

    int32_t cpw = n00b_plane_text_width(plane, r"M", nullptr);
    if (cpw <= 0) {
        cpw = 1;
    }

    if (width == 0) {
        width = vertical ? cpw : 20 * cpw;
    }
    if (height == 0) {
        if (vertical) {
            int32_t lh = n00b_plane_line_height(plane, nullptr);
            if (lh <= 0) {
                lh = 1;
            }
            height = 10 * lh;
        }
        else {
            height = n00b_plane_line_height(plane, nullptr);
            if (height <= 0) {
                height = 1;
            }
        }
    }

    plane->width = width;
    plane->height = height;

    n00b_divider_t *div = n00b_alloc(n00b_divider_t);
    div->label     = label;
    div->theme     = theme ? theme : &n00b_border_plain;
    div->line_char = line_char;
    div->vertical  = vertical;

    n00b_widget_attach(plane, &n00b_widget_divider, div);
    n00b_plane_mark_dirty(plane);
    n00b_widget_render(plane);

    return plane;
}

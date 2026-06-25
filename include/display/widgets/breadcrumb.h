/**
 * @file breadcrumb.h
 * @brief Navigation breadcrumb widget with clickable segments.
 *
 * Displays a path like `Home > Products > Current` where each segment
 * except the last is clickable.  Left/Right keys navigate focus between
 * segments; Enter/Space activates the focused segment.
 *
 * ### Usage
 *
 * ```c
 * n00b_plane_t *bc = n00b_breadcrumb_new(.on_click = my_handler);
 * n00b_breadcrumb_push(bc, r"Home", nullptr);
 * n00b_breadcrumb_push(bc, r"Products", nullptr);
 * n00b_breadcrumb_push(bc, r"Current", nullptr);
 * ```
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "display/render/plane.h"
#include "display/widget.h"
#include "display/event.h"

// ====================================================================
// Callback type
// ====================================================================

typedef void (*n00b_breadcrumb_cb_t)(n00b_plane_t  *plane,
                                     n00b_isize_t   index,
                                     void          *data);

// ====================================================================
// Segment struct
// ====================================================================

typedef struct n00b_breadcrumb_seg_t {
    n00b_string_t *label;
    void          *data;
} n00b_breadcrumb_seg_t;

// ====================================================================
// Breadcrumb data
// ====================================================================

typedef struct n00b_breadcrumb_t {
    n00b_breadcrumb_seg_t *segments;
    n00b_isize_t           count;
    n00b_isize_t           capacity;
    n00b_string_t         *separator;     /**< Default " > ". */
    n00b_isize_t           focused_index; /**< Keyboard focus within segments. */
    n00b_breadcrumb_cb_t   on_click;
    void                  *on_click_data;
    int32_t               *seg_positions; /**< Cached column offsets for hit-testing. */
} n00b_breadcrumb_t;

// ====================================================================
// Vtable
// ====================================================================

extern const n00b_widget_vtable_t n00b_widget_breadcrumb;

// ====================================================================
// Public API
// ====================================================================

/**
 * @brief Create a new breadcrumb widget.
 *
 * @kw separator      Separator string (default " > ").
 * @kw on_click       Segment click callback.
 * @kw on_click_data  User data for callback.
 * @kw width          Width (0 = auto from segments).
 * @kw height         Height (default 1, scaled by line height).
 * @kw style          Text style.
 * @kw canvas         Canvas to attach for font metrics (nullptr = none).
 * @kw allocator      Allocator.
 */
extern n00b_plane_t *
n00b_breadcrumb_new() _kargs {
    n00b_string_t        *separator      = nullptr;
    n00b_breadcrumb_cb_t  on_click       = nullptr;
    void                 *on_click_data  = nullptr;
    int32_t               width          = 40;
    int32_t               height         = 1;
    n00b_text_style_t    *style          = nullptr;
    n00b_canvas_t        *canvas         = nullptr;
    n00b_allocator_t     *allocator      = nullptr;
};

/**
 * @brief Push a segment onto the end of the breadcrumb.
 */
extern void n00b_breadcrumb_push(n00b_plane_t  *plane,
                                  n00b_string_t *label,
                                  void          *data);

/**
 * @brief Pop the last segment.
 */
extern void n00b_breadcrumb_pop(n00b_plane_t *plane);

/**
 * @brief Remove all segments.
 */
extern void n00b_breadcrumb_clear(n00b_plane_t *plane);

/**
 * @brief Get the number of segments.
 */
extern n00b_isize_t n00b_breadcrumb_count(n00b_plane_t *plane);

/**
 * @brief Set the full path at once from an array of labels.
 */
extern void n00b_breadcrumb_set_path(n00b_plane_t   *plane,
                                      n00b_string_t **labels,
                                      n00b_isize_t    count);

/**
 * @file link.h
 * @brief Clickable text link widget with optional URL and visited state.
 *
 * Renders underlined text that changes color based on focus and
 * visited state.  Activation fires the callback and optionally
 * opens the URL via the platform's default handler.
 *
 * ### Usage
 *
 * ```c
 * n00b_plane_t *lk = n00b_link_new(r"Docs",
 *                                    .url = r"https://n00b.dev",
 *                                    .on_click = my_handler);
 * n00b_link_activate(lk);
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

typedef void (*n00b_link_cb_t)(n00b_plane_t *plane, void *data);

// ====================================================================
// Link data
// ====================================================================

typedef struct n00b_link_t {
    n00b_string_t   *text;
    n00b_string_t   *url;          /**< nullptr = internal link only. */
    n00b_link_cb_t   on_click;
    void            *on_click_data;
    bool             visited;
    bool             underline;    /**< Default true. */
} n00b_link_t;

// ====================================================================
// Vtable
// ====================================================================

extern const n00b_widget_vtable_t n00b_widget_link;

// ====================================================================
// Public API
// ====================================================================

/**
 * @brief Create a new link widget.
 *
 * @param text Display text for the link.
 *
 * @kw url            URL to open on activation (nullptr = no URL).
 * @kw on_click       Click callback.
 * @kw on_click_data  User data for callback.
 * @kw underline      Show underline (default true).
 * @kw width          Width (0 = auto from text).
 * @kw height         Height (0 = auto from line height).
 * @kw style          Text style override.
 * @kw canvas         Canvas for font metrics (nullptr = cell mode).
 * @kw allocator      Allocator.
 */
extern n00b_plane_t *
n00b_link_new(n00b_string_t *text) _kargs {
    n00b_string_t    *url            = nullptr;
    n00b_link_cb_t    on_click       = nullptr;
    void             *on_click_data  = nullptr;
    bool              underline      = true;
    int32_t           width          = 0;
    int32_t           height         = 0;
    n00b_text_style_t *style         = nullptr;
    n00b_canvas_t     *canvas        = nullptr;
    n00b_allocator_t  *allocator     = nullptr;
};

/**
 * @brief Activate the link: fire callback, open URL if set.
 */
extern void n00b_link_activate(n00b_plane_t *plane);

/**
 * @brief Set the display text.
 */
extern void n00b_link_set_text(n00b_plane_t *plane, n00b_string_t *text);

/**
 * @brief Set the URL.
 */
extern void n00b_link_set_url(n00b_plane_t *plane, n00b_string_t *url);

/**
 * @brief Reset the visited state to false.
 */
extern void n00b_link_reset_visited(n00b_plane_t *plane);

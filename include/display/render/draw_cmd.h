/**
 * @file draw_cmd.h
 * @brief Draw command types for pixel-native rendering.
 *
 * Instead of a cell grid, planes store a flat list of draw commands.
 * Each command carries pixel coordinates relative to the plane's
 * content origin (0,0 = top-left inside box insets).
 *
 * Pixel backends (Notcurses, Cocoa) render commands natively.
 * Cell backends (ANSI) convert commands to a cell grid via the
 * compositor's `n00b_composite_commands_to_grid()`.
 *
 * ### Related modules
 *
 * - `render/plane.h` — plane owns a draw list
 * - `render/composite.h` — commands_to_grid for cell backends
 * - `render/font_metrics.h` — text measurement for positioning
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "text/strings/text_style.h"

// ====================================================================
// Draw command types
// ====================================================================

/**
 * @brief Discriminator for draw commands.
 */
typedef enum : uint8_t {
    N00B_DRAW_TEXT,       /**< Styled text at pixel position. */
    N00B_DRAW_FILL_RECT,  /**< Filled rectangle with a codepoint. */
    N00B_DRAW_GLYPH,      /**< Single codepoint at pixel position. */
} n00b_draw_cmd_type_t;

/**
 * @brief A single draw command in pixel coordinates.
 *
 * All coordinates are relative to the plane's content origin
 * (top-left inside border+padding insets).
 */
typedef struct n00b_draw_cmd_t {
    n00b_draw_cmd_type_t type;

    // Pointer fields live OUTSIDE the union, at fixed offsets, so the GC scans
    // and forwards them normally. (They used to live inside the per-variant
    // union, which forced the whole draw-command buffer to be allocated
    // no_scan — hiding these GC pointers from the collector. When a collection
    // moved the referenced string/style, the stale pointer here was left
    // dangling and the compositor faulted dereferencing it.)
    n00b_string_t     *string; // text payload; NULL for non-text commands
    n00b_text_style_t *style;  // every command variant carries a style

    union {
        struct {
            int32_t x;
            int32_t y;
        } text;

        struct {
            int32_t          x;
            int32_t          y;
            int32_t          w;
            int32_t          h;
            n00b_codepoint_t cp;
        } fill_rect;

        struct {
            int32_t          x;
            int32_t          y;
            n00b_codepoint_t cp;
        } glyph;
    };
} n00b_draw_cmd_t;

/**
 * @brief Dynamic array of draw commands.
 *
 * Owned by an `n00b_plane_t`.  Grows geometrically.
 */
typedef struct n00b_draw_list_t {
    n00b_draw_cmd_t *cmds;
    n00b_isize_t     count;
    n00b_isize_t     capacity;
} n00b_draw_list_t;

// ====================================================================
// Draw list operations
// ====================================================================

/**
 * @brief Initialize a draw list (zero state).
 * @param dl Draw list to initialize.
 */
extern void n00b_draw_list_init(n00b_draw_list_t *dl);

/**
 * @brief Append a draw command to the list.
 * @param dl  Draw list.
 * @param cmd Command to append (copied by value).
 */
extern void n00b_draw_list_append(n00b_draw_list_t *dl,
                                   const n00b_draw_cmd_t *cmd);

/**
 * @brief Clear all commands from the list (count = 0, keeps capacity).
 * @param dl Draw list.
 */
extern void n00b_draw_list_clear(n00b_draw_list_t *dl);

/**
 * @brief Free the command buffer.
 * @param dl Draw list.
 * @post `dl->cmds` is nullptr, count and capacity are 0.
 */
extern void n00b_draw_list_destroy(n00b_draw_list_t *dl);

// ====================================================================
// Convenience builders
// ====================================================================

/**
 * @brief Build a DRAW_TEXT command.
 */
static inline n00b_draw_cmd_t
n00b_draw_cmd_text(int32_t x, int32_t y,
                    n00b_string_t *text, n00b_text_style_t *style)
{
    return (n00b_draw_cmd_t){
        .type   = N00B_DRAW_TEXT,
        .string = text,
        .style  = style,
        .text   = { .x = x, .y = y },
    };
}

/**
 * @brief Build a DRAW_FILL_RECT command.
 */
static inline n00b_draw_cmd_t
n00b_draw_cmd_fill_rect(int32_t x, int32_t y, int32_t w, int32_t h,
                         n00b_codepoint_t cp, n00b_text_style_t *style)
{
    return (n00b_draw_cmd_t){
        .type      = N00B_DRAW_FILL_RECT,
        .style     = style,
        .fill_rect = { .x = x, .y = y, .w = w, .h = h, .cp = cp },
    };
}

/**
 * @brief Build a DRAW_GLYPH command.
 */
static inline n00b_draw_cmd_t
n00b_draw_cmd_glyph(int32_t x, int32_t y,
                     n00b_codepoint_t cp, n00b_text_style_t *style)
{
    return (n00b_draw_cmd_t){
        .type  = N00B_DRAW_GLYPH,
        .style = style,
        .glyph = { .x = x, .y = y, .cp = cp },
    };
}

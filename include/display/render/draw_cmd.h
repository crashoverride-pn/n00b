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
#include "adt/variant.h"

// ====================================================================
// Draw command types
// ====================================================================
//
// A draw command is a tagged union over the three command shapes below,
// expressed as an `n00b_variant_t`. The variant's `selector` is the
// discriminator: dispatch with `n00b_variant_is_type` / `n00b_variant_get`, or
// `switch (cmd->selector) { case typehash(n00b_draw_text_t): ... }` since
// `typehash(T)` is a compile-time integer constant. There is no separate
// `type` enum.
//
// GC: each arm carries its own pointers (string/style). ncc's gc-typemap is
// variant-aware — it reads the selector and scans only the live arm's pointers
// — so the draw-command buffer is scanned precisely and the pointers are
// forwarded across collections. (This replaces the earlier workaround that
// hoisted the pointers to fixed offsets outside a bare union: a bare union has
// no discriminator the collector can read, which had forced the whole buffer
// to be allocated no_scan and left those pointers dangling after a collection.)
//
// All coordinates are pixels relative to the plane's content origin
// (top-left inside border+padding insets).

/** @brief Styled text at a pixel position. */
typedef struct {
    n00b_string_t     *string;
    n00b_text_style_t *style;
    int32_t            x;
    int32_t            y;
} n00b_draw_text_t;

/** @brief Filled rectangle drawn with a repeated codepoint. */
typedef struct {
    n00b_text_style_t *style;
    int32_t            x;
    int32_t            y;
    int32_t            w;
    int32_t            h;
    n00b_codepoint_t   cp;
} n00b_draw_fill_rect_t;

/** @brief A single codepoint at a pixel position. */
typedef struct {
    n00b_text_style_t *style;
    int32_t            x;
    int32_t            y;
    n00b_codepoint_t   cp;
} n00b_draw_glyph_t;

/**
 * @brief A single draw command: a tagged union of the three command shapes.
 */
typedef n00b_variant_t(n00b_draw_text_t,
                       n00b_draw_fill_rect_t,
                       n00b_draw_glyph_t) n00b_draw_cmd_t;

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
 * @brief Build a text draw command.
 */
static inline n00b_draw_cmd_t
n00b_draw_cmd_text(int32_t x, int32_t y,
                    n00b_string_t *text, n00b_text_style_t *style)
{
    return n00b_variant_set(n00b_draw_cmd_t, n00b_draw_text_t,
                            ((n00b_draw_text_t){
                                .string = text,
                                .style  = style,
                                .x      = x,
                                .y      = y,
                            }));
}

/**
 * @brief Build a fill-rect draw command.
 */
static inline n00b_draw_cmd_t
n00b_draw_cmd_fill_rect(int32_t x, int32_t y, int32_t w, int32_t h,
                         n00b_codepoint_t cp, n00b_text_style_t *style)
{
    return n00b_variant_set(n00b_draw_cmd_t, n00b_draw_fill_rect_t,
                            ((n00b_draw_fill_rect_t){
                                .style = style,
                                .x     = x,
                                .y     = y,
                                .w     = w,
                                .h     = h,
                                .cp    = cp,
                            }));
}

/**
 * @brief Build a glyph draw command.
 */
static inline n00b_draw_cmd_t
n00b_draw_cmd_glyph(int32_t x, int32_t y,
                     n00b_codepoint_t cp, n00b_text_style_t *style)
{
    return n00b_variant_set(n00b_draw_cmd_t, n00b_draw_glyph_t,
                            ((n00b_draw_glyph_t){
                                .style = style,
                                .x     = x,
                                .y     = y,
                                .cp    = cp,
                            }));
}

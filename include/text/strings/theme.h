#pragma once
/** @file theme.h
 *  @brief Unified palette theme system.
 *
 *  Provides a 31-slot palette with semantic roles (background, surface,
 *  text, accent, borders, states, etc.).  18 built-in themes are
 *  registered at startup.  The active theme drives palette resolution
 *  in the ANSI backends and updates named styles in the style registry.
 *
 *  ### Palette layout
 *
 *  Slots 0-30 map to `n00b_palette_ix_t`.  Styles reference slots via
 *  `n00b_text_style_t::fg_palette_ix` / `bg_palette_ix`; the backends
 *  resolve them to 24-bit RGB at render time via the current theme.
 *
 *  ### Related modules
 *
 *  - `strings/text_style.h` -- `fg_palette_ix` / `bg_palette_ix`
 *  - `strings/style_registry.h` -- named styles updated by theme
 *  - `render/backend_ansi.c` / `render/backend_ansi_inline.c` -- palette resolution
 */

#include "n00b.h"
#include "text/strings/text_style.h"
#include "adt/option.h"

// ====================================================================
// Palette indices
// ====================================================================

/** @brief Semantic palette slot indices.
 *
 *  Each slot has a fixed meaning.  Themes supply concrete 24-bit RGB
 *  values for every slot.  `N00B_PAL_UNSET` (-1) means "no palette
 *  reference" and is the default for `fg_palette_ix` / `bg_palette_ix`.
 */
typedef enum : int8_t {
    N00B_PAL_BACKGROUND = 0,
    N00B_PAL_SURFACE,
    N00B_PAL_SURFACE_LIGHT,
    N00B_PAL_SURFACE_DARK,
    N00B_PAL_TEXT_PRIMARY,
    N00B_PAL_TEXT_SECONDARY,
    N00B_PAL_TEXT_DISABLED,
    N00B_PAL_TEXT_INVERSE,
    N00B_PAL_PRIMARY,
    N00B_PAL_PRIMARY_LIGHT,
    N00B_PAL_PRIMARY_DARK,
    N00B_PAL_SECONDARY,
    N00B_PAL_ACCENT,
    N00B_PAL_SUCCESS,
    N00B_PAL_WARNING,
    N00B_PAL_ERROR,
    N00B_PAL_INFO,
    N00B_PAL_FOCUS,
    N00B_PAL_HOVER,
    N00B_PAL_ACTIVE,
    N00B_PAL_SELECTED,
    N00B_PAL_BORDER,
    N00B_PAL_BORDER_LIGHT,
    N00B_PAL_BORDER_DARK,
    N00B_PAL_SELECTION_BG,
    N00B_PAL_SELECTION_FG,
    N00B_PAL_CURSOR,
    N00B_PAL_SCROLLBAR_TRACK,
    N00B_PAL_SCROLLBAR_THUMB,
    N00B_PAL_SCROLLBAR_THUMB_HOVER,
    N00B_PAL_PLACEHOLDER,
    N00B_PAL_SIZE,          /**< Number of palette slots (31). */
    N00B_PAL_UNSET = -1,    /**< No palette reference. */
} n00b_palette_ix_t;

// ====================================================================
// Theme structure
// ====================================================================

/** @brief A named color theme with a 31-slot palette. */
typedef struct n00b_theme_t {
    const char   *name;
    const char   *description;
    n00b_color_t  palette[N00B_PAL_SIZE];
} n00b_theme_t;

// ====================================================================
// API
// ====================================================================

/** @brief Initialize the theme subsystem and register all built-in themes.
 *
 *  Sets the default theme (`n00b-dark`) as current and updates the
 *  style registry with themed named styles.
 *
 *  @pre  `n00b_str_registry_init()` has been called.
 *  @post `n00b_theme_lookup()` and `n00b_theme_get_current()` are functional.
 */
extern void n00b_theme_init(void);

/** @brief Register a theme (built-in or user-defined).
 *  @param theme  Theme to register (pointer must remain valid).
 */
extern void n00b_theme_register(const n00b_theme_t *theme);

/** @brief Look up a registered theme by name.
 *  @param name  NUL-terminated theme name.
 *  @return The theme, or none if not found.
 */
extern n00b_option_t(const n00b_theme_t *) n00b_theme_lookup(const char *name);

/** @brief Set the current theme and update the style registry.
 *  @param name  Theme name (must be registered).
 *  @return `true` if the theme was found and set.
 */
extern bool n00b_theme_set_current(const char *name);

/** @brief Get the currently active theme.
 *  @return Current theme (never nullptr after `n00b_theme_init()`).
 */
extern const n00b_theme_t *n00b_theme_get_current(void);

/** @brief Resolve a palette index to a concrete color via the current theme.
 *  @param ix  Palette slot index.
 *  @return Resolved color with `N00B_COLOR_VALID_BIT` set, or 0 (without
 *          the valid bit) if @p ix is out of range.  Use `n00b_color_is_set()`
 *          to distinguish from valid black.
 */
extern n00b_color_t n00b_theme_resolve_color(n00b_palette_ix_t ix);

/** @brief List all registered theme names.
 *  @param[out] out_count  Receives the number of names.
 *  @return Array of NUL-terminated name strings (static storage).
 */
extern const char **n00b_theme_list(int *out_count);

/** @brief Whether ANSI color/style output to the terminal is enabled.
 *
 *  Honors the `NO_COLOR` convention (https://no-color.org): returns false when
 *  the `NO_COLOR` environment variable is present and non-empty, true
 *  otherwise. The result is resolved once and cached. Renderers consult this to
 *  suppress SGR style emission, and the table constructor consults it to skip
 *  the auto-applied default theme, so `NO_COLOR` yields plain, unstyled output.
 */
extern bool n00b_terminal_color_enabled(void);

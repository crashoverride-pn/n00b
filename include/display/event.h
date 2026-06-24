/**
 * @file event.h
 * @brief Event types for the widget system.
 *
 * Defines the tagged-union `n00b_event_t` that backends produce and
 * the event loop dispatches to widgets.  Key events carry a Unicode
 * codepoint for printable characters or a `n00b_key_t` constant for
 * special keys (arrows, function keys, etc.).
 *
 * ### Key encoding
 *
 * Values 0–0x10FFFF are Unicode codepoints.  Special keys live above
 * that range to avoid collision.
 *
 * ### Modifier flags
 *
 * SHIFT, CTRL, ALT are independent bits that can be OR'd together.
 */
#pragma once

#include "n00b.h"

// ====================================================================
// Event type
// ====================================================================

typedef enum : uint8_t {
    N00B_EVENT_NONE    = 0,
    N00B_EVENT_KEY     = 1, /**< Keyboard input. */
    N00B_EVENT_RESIZE  = 2, /**< Terminal resized. */
    N00B_EVENT_MOUSE   = 3, /**< Mouse input. */
} n00b_event_type_t;

// ====================================================================
// Key constants (above Unicode range)
// ====================================================================

typedef enum : uint32_t {
    N00B_KEY_NONE       = 0,

    // Special keys start above the Unicode max codepoint.
    N00B_KEY_UP         = 0x110000,
    N00B_KEY_DOWN       = 0x110001,
    N00B_KEY_LEFT       = 0x110002,
    N00B_KEY_RIGHT      = 0x110003,
    N00B_KEY_HOME       = 0x110004,
    N00B_KEY_END        = 0x110005,
    N00B_KEY_PAGE_UP    = 0x110006,
    N00B_KEY_PAGE_DOWN  = 0x110007,
    N00B_KEY_INSERT     = 0x110008,
    N00B_KEY_DELETE     = 0x110009,
    N00B_KEY_BACKSPACE  = 0x11000A,
    N00B_KEY_TAB        = 0x11000B,
    N00B_KEY_ENTER      = 0x11000C,
    N00B_KEY_ESCAPE     = 0x11000D,

    N00B_KEY_F1         = 0x110010,
    N00B_KEY_F2         = 0x110011,
    N00B_KEY_F3         = 0x110012,
    N00B_KEY_F4         = 0x110013,
    N00B_KEY_F5         = 0x110014,
    N00B_KEY_F6         = 0x110015,
    N00B_KEY_F7         = 0x110016,
    N00B_KEY_F8         = 0x110017,
    N00B_KEY_F9         = 0x110018,
    N00B_KEY_F10        = 0x110019,
    N00B_KEY_F11        = 0x11001A,
    N00B_KEY_F12        = 0x11001B,
} n00b_key_t;

// ====================================================================
// Mouse button constants
// ====================================================================

typedef enum : uint8_t {
    N00B_MOUSE_NONE       = 0, /**< No button (motion only). */
    N00B_MOUSE_LEFT       = 1, /**< Left button. */
    N00B_MOUSE_MIDDLE     = 2, /**< Middle button. */
    N00B_MOUSE_RIGHT      = 3, /**< Right button. */
    N00B_MOUSE_SCROLL_UP  = 4, /**< Scroll wheel up. */
    N00B_MOUSE_SCROLL_DOWN= 5, /**< Scroll wheel down. */
} n00b_mouse_button_t;

// ====================================================================
// Mouse action constants
// ====================================================================

typedef enum : uint8_t {
    N00B_MOUSE_PRESS   = 0, /**< Button pressed. */
    N00B_MOUSE_RELEASE = 1, /**< Button released. */
    N00B_MOUSE_MOVE    = 2, /**< Mouse moved (no button held). */
    N00B_MOUSE_DRAG    = 3, /**< Mouse moved with button held. */
} n00b_mouse_action_t;

// ====================================================================
// Modifier flags
// ====================================================================

typedef enum : uint8_t {
    N00B_MOD_NONE  = 0,
    N00B_MOD_SHIFT = 0x01,
    N00B_MOD_CTRL  = 0x02,
    N00B_MOD_ALT   = 0x04,
} n00b_key_mod_t;

// ====================================================================
// Event struct (tagged union)
// ====================================================================

typedef struct n00b_event_t {
    n00b_event_type_t type;

    union [[n00b::raw_union]] {
        /** Key event payload. */
        struct {
            uint32_t       key;   /**< Codepoint or n00b_key_t constant. */
            n00b_key_mod_t mods;  /**< Modifier bitmask. */
        } key;

        /** Resize event payload. */
        struct {
            n00b_isize_t rows;
            n00b_isize_t cols;
        } resize;

        /** Mouse event payload. */
        struct {
            int32_t              x;      /**< Pixel x position (0-based). */
            int32_t              y;      /**< Pixel y position (0-based). */
            n00b_mouse_button_t  button; /**< Which button (if any). */
            n00b_mouse_action_t  action; /**< Press, release, move, or drag. */
            n00b_key_mod_t       mods;   /**< Active modifier keys. */
        } mouse;
    };
} n00b_event_t;

// ====================================================================
// Helpers
// ====================================================================

/**
 * @brief Check if a key value is a printable Unicode codepoint.
 */
static inline bool
n00b_key_is_printable(uint32_t key)
{
    return key > 0x1F && key < 0x110000 && key != 0x7F;
}

/**
 * @brief Normalize a backend event into a canonical representation.
 *
 * Backends produce different `n00b_event_t` values for the same
 * logical input (e.g. ANSI maps byte 3 to `key='c', mods=CTRL`
 * while notcurses returns `key='C', mods=CTRL`).  This function
 * canonicalizes key events so the event loop and widgets never
 * need backend-specific workarounds.
 *
 * ### Rules (applied in order)
 *
 * 1. **Raw CR/LF/TAB/ESC/BS/DEL → symbolic keys.**
 *    Strips any CTRL modifier these raw bytes might carry.
 * 2. **Raw control bytes 1–26 → Ctrl+lowercase letter.**
 *    Maps byte *N* to `key = N + 'a' - 1`, `mods |= CTRL`.
 * 3. **Ctrl+uppercase → Ctrl+lowercase.**
 *    If CTRL is set and key is `'A'`–`'Z'`, lowercases it.
 *
 * Non-key events pass through unchanged.
 */
static inline void
n00b_event_normalize(n00b_event_t *ev)
{
    if (ev->type != N00B_EVENT_KEY) {
        return;
    }

    uint32_t       key  = ev->key.key;
    n00b_key_mod_t mods = ev->key.mods;

    // Rule 1: Raw CR/LF/TAB/ESC/BS/DEL → symbolic keys.
    switch (key) {
    case '\r':  // 13
    case '\n':  // 10
        ev->key.key  = N00B_KEY_ENTER;
        ev->key.mods = (n00b_key_mod_t)(mods & ~N00B_MOD_CTRL);
        return;
    case '\t':  // 9
        ev->key.key  = N00B_KEY_TAB;
        ev->key.mods = (n00b_key_mod_t)(mods & ~N00B_MOD_CTRL);
        return;
    case 0x1B:  // ESC
        ev->key.key  = N00B_KEY_ESCAPE;
        ev->key.mods = (n00b_key_mod_t)(mods & ~N00B_MOD_CTRL);
        return;
    case 0x08:  // BS
    case 0x7F:  // DEL
        ev->key.key  = N00B_KEY_BACKSPACE;
        ev->key.mods = (n00b_key_mod_t)(mods & ~N00B_MOD_CTRL);
        return;
    default:
        break;
    }

    // Rule 2: Raw control bytes 1–26 → Ctrl+lowercase letter.
    // (Rule 1 already handled 8, 9, 10, 13, 27 — only other
    //  values in 1–26 reach here.)
    if (key >= 1 && key <= 26) {
        ev->key.key  = key + 'a' - 1;
        ev->key.mods = (n00b_key_mod_t)(mods | N00B_MOD_CTRL);
        return;
    }

    // Rule 3: Ctrl+uppercase → Ctrl+lowercase.
    if ((mods & N00B_MOD_CTRL) && key >= 'A' && key <= 'Z') {
        ev->key.key = key + ('a' - 'A');
    }
}

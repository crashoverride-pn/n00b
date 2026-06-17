/*
 * Unified palette theme system: 18 built-in themes, registry, and
 * palette resolution.
 *
 * 16 themes ported from slop/ctui, 2 from n00b-old.
 */

#include <string.h>
#include "n00b.h"
#include "core/alloc.h"
#include "core/env.h"
#include "text/strings/theme.h"
#include "text/strings/style_registry.h"
#include "text/strings/style_ops.h"

// ====================================================================
// Registry (simple fixed-size array for built-in + a few user themes)
// ====================================================================

#define MAX_THEMES 32

static const n00b_theme_t *theme_registry[MAX_THEMES];
static int                  theme_count   = 0;
static const n00b_theme_t *current_theme  = nullptr;

// ====================================================================
// Helper: shorthand for palette entries
// ====================================================================

#define C(rgb) n00b_color_make(rgb)

// ====================================================================
// Built-in themes — slop/ctui ports (16)
// ====================================================================

static const n00b_theme_t theme_n00b_dark = {
    .name        = "n00b-dark",
    .description = "Default dark theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x1a1b26),
        [N00B_PAL_SURFACE]               = C(0x24283b),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x3b4261),
        [N00B_PAL_SURFACE_DARK]          = C(0x16161e),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xc0caf5),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xa9b1d6),
        [N00B_PAL_TEXT_DISABLED]         = C(0x565f89),
        [N00B_PAL_TEXT_INVERSE]          = C(0x1a1b26),
        [N00B_PAL_PRIMARY]              = C(0x7aa2f7),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xb4d0ff),
        [N00B_PAL_PRIMARY_DARK]         = C(0x5277c3),
        [N00B_PAL_SECONDARY]            = C(0xbb9af7),
        [N00B_PAL_ACCENT]               = C(0xff9e64),
        [N00B_PAL_SUCCESS]              = C(0x9ece6a),
        [N00B_PAL_WARNING]              = C(0xe0af68),
        [N00B_PAL_ERROR]                = C(0xf7768e),
        [N00B_PAL_INFO]                 = C(0x7dcfff),
        [N00B_PAL_FOCUS]                = C(0x7aa2f7),
        [N00B_PAL_HOVER]                = C(0x3b4261),
        [N00B_PAL_ACTIVE]               = C(0x24283b),
        [N00B_PAL_SELECTED]             = C(0x24283b),
        [N00B_PAL_BORDER]               = C(0x3b4261),
        [N00B_PAL_BORDER_LIGHT]         = C(0x7aa2f7),
        [N00B_PAL_BORDER_DARK]          = C(0x16161e),
        [N00B_PAL_SELECTION_BG]         = C(0x3b4261),
        [N00B_PAL_SELECTION_FG]         = C(0xc0caf5),
        [N00B_PAL_CURSOR]               = C(0xc0caf5),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x24283b),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x3b4261),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x7aa2f7),
        [N00B_PAL_PLACEHOLDER]          = C(0x565f89),
    },
};

static const n00b_theme_t theme_n00b_light = {
    .name        = "n00b-light",
    .description = "Light theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0xf5f5f5),
        [N00B_PAL_SURFACE]               = C(0xffffff),
        [N00B_PAL_SURFACE_LIGHT]         = C(0xfafafa),
        [N00B_PAL_SURFACE_DARK]          = C(0xeeeeee),
        [N00B_PAL_TEXT_PRIMARY]          = C(0x1a1a2e),
        [N00B_PAL_TEXT_SECONDARY]        = C(0x4a4a5a),
        [N00B_PAL_TEXT_DISABLED]         = C(0x9e9e9e),
        [N00B_PAL_TEXT_INVERSE]          = C(0xffffff),
        [N00B_PAL_PRIMARY]              = C(0x2563eb),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0x60a5fa),
        [N00B_PAL_PRIMARY_DARK]         = C(0x1d4ed8),
        [N00B_PAL_SECONDARY]            = C(0x7c3aed),
        [N00B_PAL_ACCENT]               = C(0xea580c),
        [N00B_PAL_SUCCESS]              = C(0x16a34a),
        [N00B_PAL_WARNING]              = C(0xca8a04),
        [N00B_PAL_ERROR]                = C(0xdc2626),
        [N00B_PAL_INFO]                 = C(0x0284c7),
        [N00B_PAL_FOCUS]                = C(0x2563eb),
        [N00B_PAL_HOVER]                = C(0xf0f0f0),
        [N00B_PAL_ACTIVE]               = C(0xe5e5e5),
        [N00B_PAL_SELECTED]             = C(0xe0e7ff),
        [N00B_PAL_BORDER]               = C(0xd4d4d4),
        [N00B_PAL_BORDER_LIGHT]         = C(0xe5e5e5),
        [N00B_PAL_BORDER_DARK]          = C(0xa3a3a3),
        [N00B_PAL_SELECTION_BG]         = C(0xdbeafe),
        [N00B_PAL_SELECTION_FG]         = C(0x1a1a2e),
        [N00B_PAL_CURSOR]               = C(0x1a1a2e),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0xf0f0f0),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0xc0c0c0),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x2563eb),
        [N00B_PAL_PLACEHOLDER]          = C(0x9e9e9e),
    },
};

static const n00b_theme_t theme_catppuccin_mocha = {
    .name        = "catppuccin-mocha",
    .description = "Catppuccin Mocha - warm dark theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x1e1e2e),
        [N00B_PAL_SURFACE]               = C(0x313244),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x45475a),
        [N00B_PAL_SURFACE_DARK]          = C(0x181825),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xcdd6f4),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xbac2de),
        [N00B_PAL_TEXT_DISABLED]         = C(0x6c7086),
        [N00B_PAL_TEXT_INVERSE]          = C(0x1e1e2e),
        [N00B_PAL_PRIMARY]              = C(0x89b4fa),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xb4d0ff),
        [N00B_PAL_PRIMARY_DARK]         = C(0x5e81ac),
        [N00B_PAL_SECONDARY]            = C(0xcba6f7),
        [N00B_PAL_ACCENT]               = C(0xfab387),
        [N00B_PAL_SUCCESS]              = C(0xa6e3a1),
        [N00B_PAL_WARNING]              = C(0xf9e2af),
        [N00B_PAL_ERROR]                = C(0xf38ba8),
        [N00B_PAL_INFO]                 = C(0x89dceb),
        [N00B_PAL_FOCUS]                = C(0x89b4fa),
        [N00B_PAL_HOVER]                = C(0x45475a),
        [N00B_PAL_ACTIVE]               = C(0x313244),
        [N00B_PAL_SELECTED]             = C(0x313244),
        [N00B_PAL_BORDER]               = C(0x45475a),
        [N00B_PAL_BORDER_LIGHT]         = C(0x89b4fa),
        [N00B_PAL_BORDER_DARK]          = C(0x181825),
        [N00B_PAL_SELECTION_BG]         = C(0x45475a),
        [N00B_PAL_SELECTION_FG]         = C(0xcdd6f4),
        [N00B_PAL_CURSOR]               = C(0xf5e0dc),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x313244),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x45475a),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x89b4fa),
        [N00B_PAL_PLACEHOLDER]          = C(0x6c7086),
    },
};

static const n00b_theme_t theme_dracula = {
    .name        = "dracula",
    .description = "Dracula - dark purple theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x282a36),
        [N00B_PAL_SURFACE]               = C(0x44475a),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x6272a4),
        [N00B_PAL_SURFACE_DARK]          = C(0x21222c),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xf8f8f2),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xbfbfbf),
        [N00B_PAL_TEXT_DISABLED]         = C(0x6272a4),
        [N00B_PAL_TEXT_INVERSE]          = C(0x282a36),
        [N00B_PAL_PRIMARY]              = C(0xbd93f9),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xd6bcfa),
        [N00B_PAL_PRIMARY_DARK]         = C(0x9a6dd7),
        [N00B_PAL_SECONDARY]            = C(0xff79c6),
        [N00B_PAL_ACCENT]               = C(0xffb86c),
        [N00B_PAL_SUCCESS]              = C(0x50fa7b),
        [N00B_PAL_WARNING]              = C(0xf1fa8c),
        [N00B_PAL_ERROR]                = C(0xff5555),
        [N00B_PAL_INFO]                 = C(0x8be9fd),
        [N00B_PAL_FOCUS]                = C(0xbd93f9),
        [N00B_PAL_HOVER]                = C(0x6272a4),
        [N00B_PAL_ACTIVE]               = C(0x44475a),
        [N00B_PAL_SELECTED]             = C(0x44475a),
        [N00B_PAL_BORDER]               = C(0x6272a4),
        [N00B_PAL_BORDER_LIGHT]         = C(0xbd93f9),
        [N00B_PAL_BORDER_DARK]          = C(0x21222c),
        [N00B_PAL_SELECTION_BG]         = C(0x44475a),
        [N00B_PAL_SELECTION_FG]         = C(0xf8f8f2),
        [N00B_PAL_CURSOR]               = C(0xf8f8f2),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x44475a),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x6272a4),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xbd93f9),
        [N00B_PAL_PLACEHOLDER]          = C(0x6272a4),
    },
};

static const n00b_theme_t theme_nord = {
    .name        = "nord",
    .description = "Nord - arctic blue theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x2e3440),
        [N00B_PAL_SURFACE]               = C(0x3b4252),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x434c5e),
        [N00B_PAL_SURFACE_DARK]          = C(0x242933),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xeceff4),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xd8dee9),
        [N00B_PAL_TEXT_DISABLED]         = C(0x4c566a),
        [N00B_PAL_TEXT_INVERSE]          = C(0x2e3440),
        [N00B_PAL_PRIMARY]              = C(0x88c0d0),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0x8fbcbb),
        [N00B_PAL_PRIMARY_DARK]         = C(0x5e81ac),
        [N00B_PAL_SECONDARY]            = C(0x81a1c1),
        [N00B_PAL_ACCENT]               = C(0xd08770),
        [N00B_PAL_SUCCESS]              = C(0xa3be8c),
        [N00B_PAL_WARNING]              = C(0xebcb8b),
        [N00B_PAL_ERROR]                = C(0xbf616a),
        [N00B_PAL_INFO]                 = C(0x88c0d0),
        [N00B_PAL_FOCUS]                = C(0x88c0d0),
        [N00B_PAL_HOVER]                = C(0x434c5e),
        [N00B_PAL_ACTIVE]               = C(0x3b4252),
        [N00B_PAL_SELECTED]             = C(0x3b4252),
        [N00B_PAL_BORDER]               = C(0x434c5e),
        [N00B_PAL_BORDER_LIGHT]         = C(0x88c0d0),
        [N00B_PAL_BORDER_DARK]          = C(0x242933),
        [N00B_PAL_SELECTION_BG]         = C(0x434c5e),
        [N00B_PAL_SELECTION_FG]         = C(0xeceff4),
        [N00B_PAL_CURSOR]               = C(0xeceff4),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x3b4252),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x434c5e),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x88c0d0),
        [N00B_PAL_PLACEHOLDER]          = C(0x4c566a),
    },
};

static const n00b_theme_t theme_gruvbox_dark = {
    .name        = "gruvbox-dark",
    .description = "Gruvbox Dark - retro earthy theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x282828),
        [N00B_PAL_SURFACE]               = C(0x3c3836),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x504945),
        [N00B_PAL_SURFACE_DARK]          = C(0x1d2021),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xebdbb2),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xd5c4a1),
        [N00B_PAL_TEXT_DISABLED]         = C(0x665c54),
        [N00B_PAL_TEXT_INVERSE]          = C(0x282828),
        [N00B_PAL_PRIMARY]              = C(0xfe8019),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xfabd2f),
        [N00B_PAL_PRIMARY_DARK]         = C(0xd65d0e),
        [N00B_PAL_SECONDARY]            = C(0xb8bb26),
        [N00B_PAL_ACCENT]               = C(0x83a598),
        [N00B_PAL_SUCCESS]              = C(0xb8bb26),
        [N00B_PAL_WARNING]              = C(0xfabd2f),
        [N00B_PAL_ERROR]                = C(0xfb4934),
        [N00B_PAL_INFO]                 = C(0x83a598),
        [N00B_PAL_FOCUS]                = C(0xfe8019),
        [N00B_PAL_HOVER]                = C(0x504945),
        [N00B_PAL_ACTIVE]               = C(0x3c3836),
        [N00B_PAL_SELECTED]             = C(0x3c3836),
        [N00B_PAL_BORDER]               = C(0x504945),
        [N00B_PAL_BORDER_LIGHT]         = C(0xfe8019),
        [N00B_PAL_BORDER_DARK]          = C(0x1d2021),
        [N00B_PAL_SELECTION_BG]         = C(0x504945),
        [N00B_PAL_SELECTION_FG]         = C(0xebdbb2),
        [N00B_PAL_CURSOR]               = C(0xebdbb2),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x3c3836),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x504945),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xfe8019),
        [N00B_PAL_PLACEHOLDER]          = C(0x665c54),
    },
};

static const n00b_theme_t theme_tokyo_night = {
    .name        = "tokyo-night",
    .description = "Tokyo Night - neon city theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x1a1b26),
        [N00B_PAL_SURFACE]               = C(0x24283b),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x414868),
        [N00B_PAL_SURFACE_DARK]          = C(0x16161e),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xc0caf5),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xa9b1d6),
        [N00B_PAL_TEXT_DISABLED]         = C(0x565f89),
        [N00B_PAL_TEXT_INVERSE]          = C(0x1a1b26),
        [N00B_PAL_PRIMARY]              = C(0x7aa2f7),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xb4d0ff),
        [N00B_PAL_PRIMARY_DARK]         = C(0x3d59a1),
        [N00B_PAL_SECONDARY]            = C(0xbb9af7),
        [N00B_PAL_ACCENT]               = C(0xff9e64),
        [N00B_PAL_SUCCESS]              = C(0x9ece6a),
        [N00B_PAL_WARNING]              = C(0xe0af68),
        [N00B_PAL_ERROR]                = C(0xf7768e),
        [N00B_PAL_INFO]                 = C(0x7dcfff),
        [N00B_PAL_FOCUS]                = C(0x7aa2f7),
        [N00B_PAL_HOVER]                = C(0x414868),
        [N00B_PAL_ACTIVE]               = C(0x24283b),
        [N00B_PAL_SELECTED]             = C(0x24283b),
        [N00B_PAL_BORDER]               = C(0x414868),
        [N00B_PAL_BORDER_LIGHT]         = C(0x7aa2f7),
        [N00B_PAL_BORDER_DARK]          = C(0x16161e),
        [N00B_PAL_SELECTION_BG]         = C(0x414868),
        [N00B_PAL_SELECTION_FG]         = C(0xc0caf5),
        [N00B_PAL_CURSOR]               = C(0xc0caf5),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x24283b),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x414868),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x7aa2f7),
        [N00B_PAL_PLACEHOLDER]          = C(0x565f89),
    },
};

static const n00b_theme_t theme_cyberpunk = {
    .name        = "cyberpunk",
    .description = "Cyberpunk - neon electric theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x0d0221),
        [N00B_PAL_SURFACE]               = C(0x150535),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x1f0a4a),
        [N00B_PAL_SURFACE_DARK]          = C(0x080116),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xf0e6ff),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xb8a9d1),
        [N00B_PAL_TEXT_DISABLED]         = C(0x5c4d76),
        [N00B_PAL_TEXT_INVERSE]          = C(0x0d0221),
        [N00B_PAL_PRIMARY]              = C(0xff2a6d),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xff6b9d),
        [N00B_PAL_PRIMARY_DARK]         = C(0xd4004c),
        [N00B_PAL_SECONDARY]            = C(0x05d9e8),
        [N00B_PAL_ACCENT]               = C(0xd300c5),
        [N00B_PAL_SUCCESS]              = C(0x01ff70),
        [N00B_PAL_WARNING]              = C(0xff851b),
        [N00B_PAL_ERROR]                = C(0xff2a6d),
        [N00B_PAL_INFO]                 = C(0x05d9e8),
        [N00B_PAL_FOCUS]                = C(0xff2a6d),
        [N00B_PAL_HOVER]                = C(0x1f0a4a),
        [N00B_PAL_ACTIVE]               = C(0x150535),
        [N00B_PAL_SELECTED]             = C(0x150535),
        [N00B_PAL_BORDER]               = C(0x1f0a4a),
        [N00B_PAL_BORDER_LIGHT]         = C(0xff2a6d),
        [N00B_PAL_BORDER_DARK]          = C(0x080116),
        [N00B_PAL_SELECTION_BG]         = C(0x1f0a4a),
        [N00B_PAL_SELECTION_FG]         = C(0xf0e6ff),
        [N00B_PAL_CURSOR]               = C(0x05d9e8),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x150535),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x1f0a4a),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xff2a6d),
        [N00B_PAL_PLACEHOLDER]          = C(0x5c4d76),
    },
};

static const n00b_theme_t theme_synthwave = {
    .name        = "synthwave",
    .description = "Synthwave - retro 80s neon theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x2b213a),
        [N00B_PAL_SURFACE]               = C(0x382c4f),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x4a3f65),
        [N00B_PAL_SURFACE_DARK]          = C(0x1f1830),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xf0e6ff),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xc8b8e0),
        [N00B_PAL_TEXT_DISABLED]         = C(0x6e5f8a),
        [N00B_PAL_TEXT_INVERSE]          = C(0x2b213a),
        [N00B_PAL_PRIMARY]              = C(0xff7edb),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xffb2ec),
        [N00B_PAL_PRIMARY_DARK]         = C(0xd44eb3),
        [N00B_PAL_SECONDARY]            = C(0x72f1b8),
        [N00B_PAL_ACCENT]               = C(0xfede5d),
        [N00B_PAL_SUCCESS]              = C(0x72f1b8),
        [N00B_PAL_WARNING]              = C(0xfede5d),
        [N00B_PAL_ERROR]                = C(0xfe4450),
        [N00B_PAL_INFO]                 = C(0x36f9f6),
        [N00B_PAL_FOCUS]                = C(0xff7edb),
        [N00B_PAL_HOVER]                = C(0x4a3f65),
        [N00B_PAL_ACTIVE]               = C(0x382c4f),
        [N00B_PAL_SELECTED]             = C(0x382c4f),
        [N00B_PAL_BORDER]               = C(0x4a3f65),
        [N00B_PAL_BORDER_LIGHT]         = C(0xff7edb),
        [N00B_PAL_BORDER_DARK]          = C(0x1f1830),
        [N00B_PAL_SELECTION_BG]         = C(0x4a3f65),
        [N00B_PAL_SELECTION_FG]         = C(0xf0e6ff),
        [N00B_PAL_CURSOR]               = C(0x36f9f6),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x382c4f),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x4a3f65),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xff7edb),
        [N00B_PAL_PLACEHOLDER]          = C(0x6e5f8a),
    },
};

static const n00b_theme_t theme_rose_pine = {
    .name        = "rose-pine",
    .description = "Rose Pine - elegant dark theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x191724),
        [N00B_PAL_SURFACE]               = C(0x1f1d2e),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x26233a),
        [N00B_PAL_SURFACE_DARK]          = C(0x13111e),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xe0def4),
        [N00B_PAL_TEXT_SECONDARY]        = C(0x908caa),
        [N00B_PAL_TEXT_DISABLED]         = C(0x6e6a86),
        [N00B_PAL_TEXT_INVERSE]          = C(0x191724),
        [N00B_PAL_PRIMARY]              = C(0xc4a7e7),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xd6c4f0),
        [N00B_PAL_PRIMARY_DARK]         = C(0x9a7ec5),
        [N00B_PAL_SECONDARY]            = C(0xebbcba),
        [N00B_PAL_ACCENT]               = C(0xf6c177),
        [N00B_PAL_SUCCESS]              = C(0x9ccfd8),
        [N00B_PAL_WARNING]              = C(0xf6c177),
        [N00B_PAL_ERROR]                = C(0xeb6f92),
        [N00B_PAL_INFO]                 = C(0x9ccfd8),
        [N00B_PAL_FOCUS]                = C(0xc4a7e7),
        [N00B_PAL_HOVER]                = C(0x26233a),
        [N00B_PAL_ACTIVE]               = C(0x1f1d2e),
        [N00B_PAL_SELECTED]             = C(0x1f1d2e),
        [N00B_PAL_BORDER]               = C(0x26233a),
        [N00B_PAL_BORDER_LIGHT]         = C(0xc4a7e7),
        [N00B_PAL_BORDER_DARK]          = C(0x13111e),
        [N00B_PAL_SELECTION_BG]         = C(0x26233a),
        [N00B_PAL_SELECTION_FG]         = C(0xe0def4),
        [N00B_PAL_CURSOR]               = C(0xe0def4),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x1f1d2e),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x26233a),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xc4a7e7),
        [N00B_PAL_PLACEHOLDER]          = C(0x6e6a86),
    },
};

static const n00b_theme_t theme_monokai = {
    .name        = "monokai",
    .description = "Monokai - classic editor theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x272822),
        [N00B_PAL_SURFACE]               = C(0x3e3d32),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x49483e),
        [N00B_PAL_SURFACE_DARK]          = C(0x1e1f1c),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xf8f8f2),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xd6d6d6),
        [N00B_PAL_TEXT_DISABLED]         = C(0x75715e),
        [N00B_PAL_TEXT_INVERSE]          = C(0x272822),
        [N00B_PAL_PRIMARY]              = C(0xa6e22e),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xc8f06e),
        [N00B_PAL_PRIMARY_DARK]         = C(0x86b21e),
        [N00B_PAL_SECONDARY]            = C(0xf92672),
        [N00B_PAL_ACCENT]               = C(0x66d9ef),
        [N00B_PAL_SUCCESS]              = C(0xa6e22e),
        [N00B_PAL_WARNING]              = C(0xe6db74),
        [N00B_PAL_ERROR]                = C(0xf92672),
        [N00B_PAL_INFO]                 = C(0x66d9ef),
        [N00B_PAL_FOCUS]                = C(0xa6e22e),
        [N00B_PAL_HOVER]                = C(0x49483e),
        [N00B_PAL_ACTIVE]               = C(0x3e3d32),
        [N00B_PAL_SELECTED]             = C(0x3e3d32),
        [N00B_PAL_BORDER]               = C(0x49483e),
        [N00B_PAL_BORDER_LIGHT]         = C(0xa6e22e),
        [N00B_PAL_BORDER_DARK]          = C(0x1e1f1c),
        [N00B_PAL_SELECTION_BG]         = C(0x49483e),
        [N00B_PAL_SELECTION_FG]         = C(0xf8f8f2),
        [N00B_PAL_CURSOR]               = C(0xf8f8f2),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x3e3d32),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x49483e),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xa6e22e),
        [N00B_PAL_PLACEHOLDER]          = C(0x75715e),
    },
};

static const n00b_theme_t theme_solarized_dark = {
    .name        = "solarized-dark",
    .description = "Solarized Dark - precision colors theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x002b36),
        [N00B_PAL_SURFACE]               = C(0x073642),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x586e75),
        [N00B_PAL_SURFACE_DARK]          = C(0x00212b),
        [N00B_PAL_TEXT_PRIMARY]          = C(0x839496),
        [N00B_PAL_TEXT_SECONDARY]        = C(0x93a1a1),
        [N00B_PAL_TEXT_DISABLED]         = C(0x586e75),
        [N00B_PAL_TEXT_INVERSE]          = C(0x002b36),
        [N00B_PAL_PRIMARY]              = C(0x268bd2),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0x6aaee0),
        [N00B_PAL_PRIMARY_DARK]         = C(0x1a6fa8),
        [N00B_PAL_SECONDARY]            = C(0x2aa198),
        [N00B_PAL_ACCENT]               = C(0xcb4b16),
        [N00B_PAL_SUCCESS]              = C(0x859900),
        [N00B_PAL_WARNING]              = C(0xb58900),
        [N00B_PAL_ERROR]                = C(0xdc322f),
        [N00B_PAL_INFO]                 = C(0x268bd2),
        [N00B_PAL_FOCUS]                = C(0x268bd2),
        [N00B_PAL_HOVER]                = C(0x586e75),
        [N00B_PAL_ACTIVE]               = C(0x073642),
        [N00B_PAL_SELECTED]             = C(0x073642),
        [N00B_PAL_BORDER]               = C(0x586e75),
        [N00B_PAL_BORDER_LIGHT]         = C(0x268bd2),
        [N00B_PAL_BORDER_DARK]          = C(0x00212b),
        [N00B_PAL_SELECTION_BG]         = C(0x073642),
        [N00B_PAL_SELECTION_FG]         = C(0x93a1a1),
        [N00B_PAL_CURSOR]               = C(0x93a1a1),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x073642),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x586e75),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x268bd2),
        [N00B_PAL_PLACEHOLDER]          = C(0x586e75),
    },
};

static const n00b_theme_t theme_midnight = {
    .name        = "midnight",
    .description = "Midnight - deep blue dark theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x0f0f1a),
        [N00B_PAL_SURFACE]               = C(0x1a1a2e),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x25254a),
        [N00B_PAL_SURFACE_DARK]          = C(0x0a0a12),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xe0e0f0),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xb0b0c8),
        [N00B_PAL_TEXT_DISABLED]         = C(0x505070),
        [N00B_PAL_TEXT_INVERSE]          = C(0x0f0f1a),
        [N00B_PAL_PRIMARY]              = C(0x6366f1),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0x818cf8),
        [N00B_PAL_PRIMARY_DARK]         = C(0x4f46e5),
        [N00B_PAL_SECONDARY]            = C(0xa78bfa),
        [N00B_PAL_ACCENT]               = C(0xf472b6),
        [N00B_PAL_SUCCESS]              = C(0x34d399),
        [N00B_PAL_WARNING]              = C(0xfbbf24),
        [N00B_PAL_ERROR]                = C(0xf87171),
        [N00B_PAL_INFO]                 = C(0x38bdf8),
        [N00B_PAL_FOCUS]                = C(0x6366f1),
        [N00B_PAL_HOVER]                = C(0x25254a),
        [N00B_PAL_ACTIVE]               = C(0x1a1a2e),
        [N00B_PAL_SELECTED]             = C(0x1a1a2e),
        [N00B_PAL_BORDER]               = C(0x25254a),
        [N00B_PAL_BORDER_LIGHT]         = C(0x6366f1),
        [N00B_PAL_BORDER_DARK]          = C(0x0a0a12),
        [N00B_PAL_SELECTION_BG]         = C(0x25254a),
        [N00B_PAL_SELECTION_FG]         = C(0xe0e0f0),
        [N00B_PAL_CURSOR]               = C(0xe0e0f0),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x1a1a2e),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x25254a),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x6366f1),
        [N00B_PAL_PLACEHOLDER]          = C(0x505070),
    },
};

static const n00b_theme_t theme_ocean = {
    .name        = "ocean",
    .description = "Ocean - deep sea blue-green theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x0b2337),
        [N00B_PAL_SURFACE]               = C(0x122d42),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x1b3a51),
        [N00B_PAL_SURFACE_DARK]          = C(0x071a2b),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xd4e5f7),
        [N00B_PAL_TEXT_SECONDARY]        = C(0x9ab8d0),
        [N00B_PAL_TEXT_DISABLED]         = C(0x4a6a82),
        [N00B_PAL_TEXT_INVERSE]          = C(0x0b2337),
        [N00B_PAL_PRIMARY]              = C(0x0ea5e9),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0x38bdf8),
        [N00B_PAL_PRIMARY_DARK]         = C(0x0284c7),
        [N00B_PAL_SECONDARY]            = C(0x14b8a6),
        [N00B_PAL_ACCENT]               = C(0xf97316),
        [N00B_PAL_SUCCESS]              = C(0x22c55e),
        [N00B_PAL_WARNING]              = C(0xeab308),
        [N00B_PAL_ERROR]                = C(0xef4444),
        [N00B_PAL_INFO]                 = C(0x06b6d4),
        [N00B_PAL_FOCUS]                = C(0x0ea5e9),
        [N00B_PAL_HOVER]                = C(0x1b3a51),
        [N00B_PAL_ACTIVE]               = C(0x122d42),
        [N00B_PAL_SELECTED]             = C(0x122d42),
        [N00B_PAL_BORDER]               = C(0x1b3a51),
        [N00B_PAL_BORDER_LIGHT]         = C(0x0ea5e9),
        [N00B_PAL_BORDER_DARK]          = C(0x071a2b),
        [N00B_PAL_SELECTION_BG]         = C(0x1b3a51),
        [N00B_PAL_SELECTION_FG]         = C(0xd4e5f7),
        [N00B_PAL_CURSOR]               = C(0xd4e5f7),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x122d42),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x1b3a51),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x0ea5e9),
        [N00B_PAL_PLACEHOLDER]          = C(0x4a6a82),
    },
};

static const n00b_theme_t theme_forest = {
    .name        = "forest",
    .description = "Forest - deep green nature theme",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x1a2e1a),
        [N00B_PAL_SURFACE]               = C(0x243a24),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x2f4f2f),
        [N00B_PAL_SURFACE_DARK]          = C(0x122112),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xd4e8d4),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xa8c8a8),
        [N00B_PAL_TEXT_DISABLED]         = C(0x5a7a5a),
        [N00B_PAL_TEXT_INVERSE]          = C(0x1a2e1a),
        [N00B_PAL_PRIMARY]              = C(0x4ade80),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0x86efac),
        [N00B_PAL_PRIMARY_DARK]         = C(0x22c55e),
        [N00B_PAL_SECONDARY]            = C(0xa3e635),
        [N00B_PAL_ACCENT]               = C(0xfbbf24),
        [N00B_PAL_SUCCESS]              = C(0x4ade80),
        [N00B_PAL_WARNING]              = C(0xfbbf24),
        [N00B_PAL_ERROR]                = C(0xef4444),
        [N00B_PAL_INFO]                 = C(0x67e8f9),
        [N00B_PAL_FOCUS]                = C(0x4ade80),
        [N00B_PAL_HOVER]                = C(0x2f4f2f),
        [N00B_PAL_ACTIVE]               = C(0x243a24),
        [N00B_PAL_SELECTED]             = C(0x243a24),
        [N00B_PAL_BORDER]               = C(0x2f4f2f),
        [N00B_PAL_BORDER_LIGHT]         = C(0x4ade80),
        [N00B_PAL_BORDER_DARK]          = C(0x122112),
        [N00B_PAL_SELECTION_BG]         = C(0x2f4f2f),
        [N00B_PAL_SELECTION_FG]         = C(0xd4e8d4),
        [N00B_PAL_CURSOR]               = C(0xd4e8d4),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x243a24),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x2f4f2f),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0x4ade80),
        [N00B_PAL_PLACEHOLDER]          = C(0x5a7a5a),
    },
};

static const n00b_theme_t theme_high_contrast = {
    .name        = "high-contrast",
    .description = "High Contrast - maximum readability",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x000000),
        [N00B_PAL_SURFACE]               = C(0x1a1a1a),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x333333),
        [N00B_PAL_SURFACE_DARK]          = C(0x000000),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xffffff),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xe0e0e0),
        [N00B_PAL_TEXT_DISABLED]         = C(0x808080),
        [N00B_PAL_TEXT_INVERSE]          = C(0x000000),
        [N00B_PAL_PRIMARY]              = C(0xffff00),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xffff80),
        [N00B_PAL_PRIMARY_DARK]         = C(0xcccc00),
        [N00B_PAL_SECONDARY]            = C(0x00ffff),
        [N00B_PAL_ACCENT]               = C(0xff00ff),
        [N00B_PAL_SUCCESS]              = C(0x00ff00),
        [N00B_PAL_WARNING]              = C(0xffff00),
        [N00B_PAL_ERROR]                = C(0xff0000),
        [N00B_PAL_INFO]                 = C(0x00ffff),
        [N00B_PAL_FOCUS]                = C(0xffff00),
        [N00B_PAL_HOVER]                = C(0x333333),
        [N00B_PAL_ACTIVE]               = C(0x1a1a1a),
        [N00B_PAL_SELECTED]             = C(0x1a1a1a),
        [N00B_PAL_BORDER]               = C(0xffffff),
        [N00B_PAL_BORDER_LIGHT]         = C(0xffff00),
        [N00B_PAL_BORDER_DARK]          = C(0x808080),
        [N00B_PAL_SELECTION_BG]         = C(0x333333),
        [N00B_PAL_SELECTION_FG]         = C(0xffffff),
        [N00B_PAL_CURSOR]               = C(0xffffff),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x1a1a1a),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x808080),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xffffff),
        [N00B_PAL_PLACEHOLDER]          = C(0x808080),
    },
};

// ====================================================================
// Built-in themes — n00b-old ports (2)
// ====================================================================

static const n00b_theme_t theme_n00b_bright = {
    .name        = "n00b-bright",
    .description = "N00b flashy bright accents",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x0b1221),
        [N00B_PAL_SURFACE]               = C(0x232937),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x3c414d),
        [N00B_PAL_SURFACE_DARK]          = C(0x050610),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xe6e2dc),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xeeebe8),
        [N00B_PAL_TEXT_DISABLED]         = C(0x6d717a),
        [N00B_PAL_TEXT_INVERSE]          = C(0x0b1221),
        [N00B_PAL_PRIMARY]              = C(0xbfff33),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xcfff66),
        [N00B_PAL_PRIMARY_DARK]         = C(0xb3ff00),
        [N00B_PAL_SECONDARY]            = C(0xff59a1),
        [N00B_PAL_ACCENT]               = C(0x7561b3),
        [N00B_PAL_SUCCESS]              = C(0xc7ff4c),
        [N00B_PAL_WARNING]              = C(0xffbf00),
        [N00B_PAL_ERROR]                = C(0xff0800),
        [N00B_PAL_INFO]                 = C(0x00bfff),
        [N00B_PAL_FOCUS]                = C(0xbfff33),
        [N00B_PAL_HOVER]                = C(0x3c414d),
        [N00B_PAL_ACTIVE]               = C(0x232937),
        [N00B_PAL_SELECTED]             = C(0x232937),
        [N00B_PAL_BORDER]               = C(0x3c414d),
        [N00B_PAL_BORDER_LIGHT]         = C(0xbfff33),
        [N00B_PAL_BORDER_DARK]          = C(0x050610),
        [N00B_PAL_SELECTION_BG]         = C(0x3c414d),
        [N00B_PAL_SELECTION_FG]         = C(0xe6e2dc),
        [N00B_PAL_CURSOR]               = C(0xfcfcfb),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x232937),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x3c414d),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xbfff33),
        [N00B_PAL_PLACEHOLDER]          = C(0x6d717a),
    },
};

static const n00b_theme_t theme_n00b_classic = {
    .name        = "n00b-classic",
    .description = "N00b classic dark (less flashy)",
    .palette     = {
        [N00B_PAL_BACKGROUND]            = C(0x0b1221),
        [N00B_PAL_SURFACE]               = C(0x232937),
        [N00B_PAL_SURFACE_LIGHT]         = C(0x3c414d),
        [N00B_PAL_SURFACE_DARK]          = C(0x050610),
        [N00B_PAL_TEXT_PRIMARY]          = C(0xe6e2dc),
        [N00B_PAL_TEXT_SECONDARY]        = C(0xeeebe8),
        [N00B_PAL_TEXT_DISABLED]         = C(0x6d717a),
        [N00B_PAL_TEXT_INVERSE]          = C(0x0b1221),
        [N00B_PAL_PRIMARY]              = C(0xbfff33),
        [N00B_PAL_PRIMARY_LIGHT]        = C(0xcfff66),
        [N00B_PAL_PRIMARY_DARK]         = C(0xb3ff00),
        [N00B_PAL_SECONDARY]            = C(0x7561b3),
        [N00B_PAL_ACCENT]               = C(0xff59a1),
        [N00B_PAL_SUCCESS]              = C(0xc7ff4c),
        [N00B_PAL_WARNING]              = C(0xffbf00),
        [N00B_PAL_ERROR]                = C(0xff0800),
        [N00B_PAL_INFO]                 = C(0x00bfff),
        [N00B_PAL_FOCUS]                = C(0xbfff33),
        [N00B_PAL_HOVER]                = C(0x3c414d),
        [N00B_PAL_ACTIVE]               = C(0x232937),
        [N00B_PAL_SELECTED]             = C(0x232937),
        [N00B_PAL_BORDER]               = C(0x3c414d),
        [N00B_PAL_BORDER_LIGHT]         = C(0xbfff33),
        [N00B_PAL_BORDER_DARK]          = C(0x050610),
        [N00B_PAL_SELECTION_BG]         = C(0x3c414d),
        [N00B_PAL_SELECTION_FG]         = C(0xe6e2dc),
        [N00B_PAL_CURSOR]               = C(0xfcfcfb),
        [N00B_PAL_SCROLLBAR_TRACK]      = C(0x232937),
        [N00B_PAL_SCROLLBAR_THUMB]      = C(0x3c414d),
        [N00B_PAL_SCROLLBAR_THUMB_HOVER]= C(0xbfff33),
        [N00B_PAL_PLACEHOLDER]          = C(0x6d717a),
    },
};

#undef C

// ====================================================================
// Style registry integration
// ====================================================================

static void
update_named_styles(const n00b_theme_t *theme)
{
    // h1: bold + uppercase + fg from PRIMARY
    n00b_text_style_t h1 = {
        .bold         = N00B_TRI_YES,
        .text_case    = N00B_TEXT_CASE_UPPER,
        .fg_palette_ix = N00B_PAL_PRIMARY,
        .bg_palette_ix = N00B_PAL_UNSET,
        .font_index    = -1,
    };
    n00b_str_style_register("h1", &h1);

    // h2: bold + uppercase + fg from SECONDARY
    n00b_text_style_t h2 = {
        .bold         = N00B_TRI_YES,
        .text_case    = N00B_TEXT_CASE_UPPER,
        .fg_palette_ix = N00B_PAL_SECONDARY,
        .bg_palette_ix = N00B_PAL_UNSET,
        .font_index    = -1,
    };
    n00b_str_style_register("h2", &h2);

    // h3: bold + uppercase + fg from ACCENT
    n00b_text_style_t h3 = {
        .bold         = N00B_TRI_YES,
        .text_case    = N00B_TEXT_CASE_UPPER,
        .fg_palette_ix = N00B_PAL_ACCENT,
        .bg_palette_ix = N00B_PAL_UNSET,
        .font_index    = -1,
    };
    n00b_str_style_register("h3", &h3);

    // em: italic + fg from PRIMARY
    n00b_text_style_t em = {
        .italic       = N00B_TRI_YES,
        .fg_palette_ix = N00B_PAL_PRIMARY,
        .bg_palette_ix = N00B_PAL_UNSET,
        .font_index    = -1,
    };
    n00b_str_style_register("em", &em);

    // em2: bold + fg from SECONDARY
    n00b_text_style_t em2 = {
        .bold         = N00B_TRI_YES,
        .fg_palette_ix = N00B_PAL_SECONDARY,
        .bg_palette_ix = N00B_PAL_UNSET,
        .font_index    = -1,
    };
    n00b_str_style_register("em2", &em2);

    // em3: bold + italic + fg from ACCENT
    n00b_text_style_t em3 = {
        .bold         = N00B_TRI_YES,
        .italic       = N00B_TRI_YES,
        .fg_palette_ix = N00B_PAL_ACCENT,
        .bg_palette_ix = N00B_PAL_UNSET,
        .font_index    = -1,
    };
    n00b_str_style_register("em3", &em3);
}

// ====================================================================
// Public API
// ====================================================================

void
n00b_theme_register(const n00b_theme_t *theme)
{
    if (theme_count >= MAX_THEMES) {
        return;
    }

    // Replace existing theme with same name.
    for (int i = 0; i < theme_count; i++) {
        if (strcmp(theme_registry[i]->name, theme->name) == 0) {
            theme_registry[i] = theme;
            return;
        }
    }

    theme_registry[theme_count++] = theme;
}

n00b_option_t(const n00b_theme_t *)
n00b_theme_lookup(const char *name)
{
    if (!name) {
        return n00b_option_none(const n00b_theme_t *);
    }

    for (int i = 0; i < theme_count; i++) {
        if (strcmp(theme_registry[i]->name, name) == 0) {
            return n00b_option_set(const n00b_theme_t *, theme_registry[i]);
        }
    }

    return n00b_option_none(const n00b_theme_t *);
}

bool
n00b_theme_set_current(const char *name)
{
    auto t_opt = n00b_theme_lookup(name);

    if (!n00b_option_is_set(t_opt)) {
        return false;
    }

    const n00b_theme_t *t = n00b_option_get(t_opt);
    current_theme = t;
    update_named_styles(t);
    return true;
}

const n00b_theme_t *
n00b_theme_get_current(void)
{
    return current_theme;
}

n00b_color_t
n00b_theme_resolve_color(n00b_palette_ix_t ix)
{
    if (!current_theme || ix < 0 || ix >= N00B_PAL_SIZE) {
        return 0;
    }

    return current_theme->palette[ix];
}

bool
n00b_terminal_color_enabled(void)
{
    /* NO_COLOR (https://no-color.org): when the env var is present and
     * non-empty, suppress ANSI color/style output to the terminal. Resolved
     * once and cached — color policy does not change mid-process. Races on the
     * first resolution are benign (all racers compute the same value). */
    static int cached = -1; /* -1 unresolved, 0 disabled, 1 enabled */
    if (cached < 0) {
        n00b_string_t *v = n00b_getenv(r"NO_COLOR");
        cached           = (v != nullptr && v->u8_bytes > 0) ? 0 : 1;
    }
    return cached == 1;
}

const char **
n00b_theme_list(int *out_count)
{
    static const char *names[MAX_THEMES];

    for (int i = 0; i < theme_count; i++) {
        names[i] = theme_registry[i]->name;
    }

    if (out_count) {
        *out_count = theme_count;
    }

    return names;
}

void
n00b_theme_init(void)
{
    // Register all 18 built-in themes.
    n00b_theme_register(&theme_n00b_dark);
    n00b_theme_register(&theme_n00b_light);
    n00b_theme_register(&theme_catppuccin_mocha);
    n00b_theme_register(&theme_dracula);
    n00b_theme_register(&theme_nord);
    n00b_theme_register(&theme_gruvbox_dark);
    n00b_theme_register(&theme_tokyo_night);
    n00b_theme_register(&theme_cyberpunk);
    n00b_theme_register(&theme_synthwave);
    n00b_theme_register(&theme_rose_pine);
    n00b_theme_register(&theme_monokai);
    n00b_theme_register(&theme_solarized_dark);
    n00b_theme_register(&theme_midnight);
    n00b_theme_register(&theme_ocean);
    n00b_theme_register(&theme_forest);
    n00b_theme_register(&theme_high_contrast);
    n00b_theme_register(&theme_n00b_bright);
    n00b_theme_register(&theme_n00b_classic);

    // Set default theme and update named styles.
    n00b_theme_set_current("n00b-classic");
}

/*
 * Native Cocoa/macOS renderer backend.
 *
 * Draws into an NSWindow using Core Text + Core Graphics.  The backend
 * auto-detects whether NSApp is already running (embedded mode) or
 * starts a background event loop (standalone mode).
 *
 * All UI mutations are dispatched to the main thread via
 * dispatch_sync/dispatch_async.  A double-buffer staging cell array
 * ensures thread safety between render_frame() callers and drawRect:.
 */

#import <Cocoa/Cocoa.h>
#import <CoreText/CoreText.h>
#import <QuartzCore/QuartzCore.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// The canonical n00b headers use ncc extensions that Apple's ObjC
// compiler can't parse.  cocoa_bridge.h provides standalone
// redeclarations of the types we need.
#include "display/render/cocoa_bridge.h"
#include "internal/display/cocoa_bridge_contracts.h"
#include "internal/display/cocoa_input.h"
// Backend handles + per-plane caches are n00b-managed via the user pool: it is
// non-moving (these are held as opaque void* / box->gui_ext across GC) and
// free-by-pointer. No libc malloc in our code.
#include "core/alloc_interpose.h"

// ====================================================================
// Constants
// ====================================================================

#define COCOA_DEFAULT_COLS        80
#define COCOA_DEFAULT_ROWS        25
#define COCOA_DEFAULT_FONT_PT     14.0
#define COCOA_CURSOR_BLINK_SEC    0.5
#define COCOA_NUM_FONT_HINTS      4
#define COCOA_EVENT_QUEUE_CAP     64

// ====================================================================
// Internal context
// ====================================================================

typedef struct cocoa_plane_cache_t {
    cocoa_gui_ext_t *ext;           // Borrowed pointer from box->gui_ext.
    CGGradientRef    gradient;      // Pre-built gradient (nullable).
    CGBlendMode      cg_blend;
} cocoa_plane_cache_t;

typedef struct {
    // Window / view (stored as void* to avoid ObjC in struct decl).
    void                *window;    // NSWindow *
    void                *view;      // N00bRenderView *

    // Fonts (one per font hint).
    CTFontRef            ct_fonts[COCOA_NUM_FONT_HINTS];

    // Cell metrics (from monospace font).
    CGFloat              cell_w;
    CGFloat              cell_h;
    CGFloat              ascent;
    CGFloat              descent;
    CGFloat              leading;

    // Grid dimensions (in cells).
    n00b_isize_t         rows;
    n00b_isize_t         cols;

    // Pixel dimensions (backing-store pixels).
    n00b_isize_t         pixel_w;
    n00b_isize_t         pixel_h;

    // Staging cell buffer for thread-safe double-buffering.
    n00b_rcell_t        *staging;
    n00b_isize_t         staging_rows;
    n00b_isize_t         staging_cols;
    n00b_composite_style_pool_t style_pool;

    // Cursor state.
    n00b_isize_t         cursor_row;
    n00b_isize_t         cursor_col;
    bool                 cursor_visible;
    bool                 cursor_blink_on;
    void                *blink_timer;   // NSTimer *

    // Resize callback.
    void               (*resize_cb)(n00b_isize_t, n00b_isize_t, void *);
    void                *resize_user_ctx;

    // GUI extension cache.
    cocoa_plane_cache_t *gui_cache;
    n00b_isize_t         gui_cache_count;

    // Event queue (ring buffer).
    n00b_event_t         event_queue[COCOA_EVENT_QUEUE_CAP];
    uint32_t             eq_head;           // next write index
    uint32_t             eq_tail;           // next read index
    bool                 has_pending_resize;
    n00b_isize_t         pending_resize_rows;
    n00b_isize_t         pending_resize_cols;

    // Event loop ownership.
    bool                 owns_nsapp;
    bool                 needs_finish_launch;
    pthread_t            bg_thread;

    // Output topic (unused for GUI but stored for vtable compat).
    void                *output;
} cocoa_ctx_t;

// ====================================================================
// Forward declarations for ObjC classes
// ====================================================================

@class N00bRenderView;
@class N00bAppDelegate;

// ====================================================================
// Forward declarations for event helpers (used by N00bRenderView)
// ====================================================================

static void           cocoa_enqueue_event(cocoa_ctx_t *ctx, const n00b_event_t *ev);
static bool           cocoa_dequeue_event(cocoa_ctx_t *ctx, n00b_event_t *out);
static uint32_t       cocoa_modifier_mask(NSEventModifierFlags flags);
static void           cocoa_enqueue_mouse_event(cocoa_ctx_t          *ctx,
                                                NSView               *view,
                                                NSEvent              *event,
                                                n00b_mouse_button_t   button,
                                                n00b_mouse_action_t   action);
static bool           cocoa_validate_bridge_layout(void);

// ====================================================================
// CG border drawing for N00B_CELL_BORDER cells
// ====================================================================

// Decode the first UTF-8 codepoint from a grapheme buffer.
static uint32_t
decode_first_codepoint(const char *g, uint8_t len)
{
    if (len == 0) return 0;
    const uint8_t *u = (const uint8_t *)g;
    if (u[0] < 0x80) return u[0];
    if ((u[0] & 0xE0) == 0xC0 && len >= 2)
        return ((u[0] & 0x1F) << 6) | (u[1] & 0x3F);
    if ((u[0] & 0xF0) == 0xE0 && len >= 3)
        return ((u[0] & 0x0F) << 12) | ((u[1] & 0x3F) << 6) | (u[2] & 0x3F);
    if ((u[0] & 0xF8) == 0xF0 && len >= 4)
        return ((u[0] & 0x07) << 18) | ((u[1] & 0x3F) << 12)
             | ((u[2] & 0x3F) << 6) | (u[3] & 0x3F);
    return 0;
}

// Determine which edges a box-drawing codepoint connects through.
// Returns a bitmask: bit 0=top, 1=right, 2=bottom, 3=left.
#define EDGE_TOP    (1 << 0)
#define EDGE_RIGHT  (1 << 1)
#define EDGE_BOTTOM (1 << 2)
#define EDGE_LEFT   (1 << 3)

static uint8_t
border_edges(uint32_t cp)
{
    // Unicode box-drawing: U+2500–U+257F.
    // Also handle rounded corners: U+256D–U+2570.
    // And ASCII fallbacks.
    switch (cp) {
    // Horizontal lines.
    case 0x2500: case 0x2501: // ─ ━
    case 0x2504: case 0x2505: // ┄ ┅
    case 0x2508: case 0x2509: // ┈ ┉
    case 0x254C: case 0x254D: // ╌ ╍
    case 0x2550:              // ═
    case '-': case '=':
        return EDGE_LEFT | EDGE_RIGHT;

    // Vertical lines.
    case 0x2502: case 0x2503: // │ ┃
    case 0x2506: case 0x2507: // ┆ ┇
    case 0x250A: case 0x250B: // ┊ ┋
    case 0x254E: case 0x254F: // ╎ ╏
    case 0x2551:              // ║
    case '|':
        return EDGE_TOP | EDGE_BOTTOM;

    // Upper-left corners (rounded and square).
    case 0x250C: case 0x250D: case 0x250E: case 0x250F: // ┌ ┍ ┎ ┏
    case 0x256D:              // ╭
    case 0x2552: case 0x2553: case 0x2554: // ╒ ╓ ╔
        return EDGE_RIGHT | EDGE_BOTTOM;

    // Upper-right corners.
    case 0x2510: case 0x2511: case 0x2512: case 0x2513: // ┐ ┑ ┒ ┓
    case 0x256E:              // ╮
    case 0x2555: case 0x2556: case 0x2557: // ╕ ╖ ╗
        return EDGE_LEFT | EDGE_BOTTOM;

    // Lower-left corners.
    case 0x2514: case 0x2515: case 0x2516: case 0x2517: // └ ┕ ┖ ┗
    case 0x2570:              // ╰
    case 0x2558: case 0x2559: case 0x255A: // ╘ ╙ ╚
        return EDGE_RIGHT | EDGE_TOP;

    // Lower-right corners.
    case 0x2518: case 0x2519: case 0x251A: case 0x251B: // ┘ ┙ ┚ ┛
    case 0x256F:              // ╯
    case 0x255B: case 0x255C: case 0x255D: // ╛ ╜ ╝
        return EDGE_LEFT | EDGE_TOP;

    // T-junctions.
    case 0x251C: case 0x251D: case 0x251E: case 0x251F: // ├ variants
    case 0x2520: case 0x2521: case 0x2522: case 0x2523:
    case 0x255E: case 0x255F: case 0x2560:
        return EDGE_TOP | EDGE_RIGHT | EDGE_BOTTOM;

    case 0x2524: case 0x2525: case 0x2526: case 0x2527: // ┤ variants
    case 0x2528: case 0x2529: case 0x252A: case 0x252B:
    case 0x2561: case 0x2562: case 0x2563:
        return EDGE_TOP | EDGE_LEFT | EDGE_BOTTOM;

    case 0x252C: case 0x252D: case 0x252E: case 0x252F: // ┬ variants
    case 0x2530: case 0x2531: case 0x2532: case 0x2533:
    case 0x2564: case 0x2565: case 0x2566:
        return EDGE_LEFT | EDGE_RIGHT | EDGE_BOTTOM;

    case 0x2534: case 0x2535: case 0x2536: case 0x2537: // ┴ variants
    case 0x2538: case 0x2539: case 0x253A: case 0x253B:
    case 0x2567: case 0x2568: case 0x2569:
        return EDGE_LEFT | EDGE_RIGHT | EDGE_TOP;

    // Cross.
    case 0x253C: case 0x253D: case 0x253E: case 0x253F: // ┼ variants
    case 0x2540: case 0x2541: case 0x2542: case 0x2543:
    case 0x2544: case 0x2545: case 0x2546: case 0x2547:
    case 0x256A: case 0x256B: case 0x256C:
    case '+':
        return EDGE_TOP | EDGE_RIGHT | EDGE_BOTTOM | EDGE_LEFT;

    default:
        return 0;
    }
}

// Is a codepoint a rounded corner?
static bool
border_is_rounded(uint32_t cp)
{
    return cp >= 0x256D && cp <= 0x2570;
}

// Draw a border cell as CG lines/arcs instead of text glyphs.
static void
draw_border_cell(CGContextRef cg,
                 CGFloat x, CGFloat y, CGFloat w, CGFloat h,
                 CGFloat fg_r, CGFloat fg_g, CGFloat fg_b, CGFloat fg_alpha,
                 uint32_t codepoint)
{
    uint8_t edges = border_edges(codepoint);
    if (edges == 0) return;

    CGFloat cx = x + w / 2.0;
    CGFloat cy = y + h / 2.0;
    CGFloat line_width = 1.0;

    CGContextSetRGBStrokeColor(cg, fg_r, fg_g, fg_b, fg_alpha);
    CGContextSetLineWidth(cg, line_width);
    CGContextSetLineCap(cg, kCGLineCapButt);

    if (border_is_rounded(codepoint)) {
        // Rounded corners: draw a quarter-circle arc from the center
        // to the two connected edges.
        CGFloat radius = fmin(w, h) / 2.0;
        CGFloat sa, ea;

        switch (codepoint) {
        case 0x256D: // ╭ upper-left: connects right + bottom
            sa = -M_PI;     ea = -M_PI_2;
            // Arc center is at bottom-right of the arc.
            CGContextAddArc(cg, x + w, y + h, radius, sa, ea, 0);
            break;
        case 0x256E: // ╮ upper-right: connects left + bottom
            sa = -M_PI_2;  ea = 0;
            CGContextAddArc(cg, x, y + h, radius, sa, ea, 0);
            break;
        case 0x256F: // ╯ lower-right: connects left + top
            sa = 0;         ea = M_PI_2;
            CGContextAddArc(cg, x, y, radius, sa, ea, 0);
            break;
        case 0x2570: // ╰ lower-left: connects right + top
            sa = M_PI_2;   ea = M_PI;
            CGContextAddArc(cg, x + w, y, radius, sa, ea, 0);
            break;
        }
        CGContextStrokePath(cg);

        // Extend straight lines from arc endpoints to cell edges.
        if (edges & EDGE_RIGHT) {
            CGContextMoveToPoint(cg, cx, cy);
            CGContextAddLineToPoint(cg, x + w, cy);
            CGContextStrokePath(cg);
        }
        if (edges & EDGE_LEFT) {
            CGContextMoveToPoint(cg, x, cy);
            CGContextAddLineToPoint(cg, cx, cy);
            CGContextStrokePath(cg);
        }
        if (edges & EDGE_BOTTOM) {
            CGContextMoveToPoint(cg, cx, cy);
            CGContextAddLineToPoint(cg, cx, y + h);
            CGContextStrokePath(cg);
        }
        if (edges & EDGE_TOP) {
            CGContextMoveToPoint(cg, cx, cy);
            CGContextAddLineToPoint(cg, cx, y);
            CGContextStrokePath(cg);
        }
    }
    else {
        // Straight lines from center to each connected edge.
        if (edges & EDGE_TOP) {
            CGContextMoveToPoint(cg, cx, y);
            CGContextAddLineToPoint(cg, cx, cy);
            CGContextStrokePath(cg);
        }
        if (edges & EDGE_BOTTOM) {
            CGContextMoveToPoint(cg, cx, cy);
            CGContextAddLineToPoint(cg, cx, y + h);
            CGContextStrokePath(cg);
        }
        if (edges & EDGE_LEFT) {
            CGContextMoveToPoint(cg, x, cy);
            CGContextAddLineToPoint(cg, cx, cy);
            CGContextStrokePath(cg);
        }
        if (edges & EDGE_RIGHT) {
            CGContextMoveToPoint(cg, cx, cy);
            CGContextAddLineToPoint(cg, x + w, cy);
            CGContextStrokePath(cg);
        }
    }
}

// ====================================================================
// N00bRenderView — custom NSView
// ====================================================================

@interface N00bRenderView : NSView
@property (nonatomic, assign) cocoa_ctx_t *ctx;
@end

@implementation N00bRenderView

- (BOOL)isFlipped
{
    return YES;
}

- (BOOL)isOpaque
{
    return YES;
}

- (void)drawRect:(NSRect)dirtyRect
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx || !ctx->staging) {
        // Fill with black if no data yet.
        [[NSColor blackColor] setFill];
        NSRectFill(dirtyRect);
        return;
    }

    CGContextRef cg = [[NSGraphicsContext currentContext] CGContext];

    n00b_isize_t rows = ctx->staging_rows;
    n00b_isize_t cols = ctx->staging_cols;

    // Determine cell range that intersects dirtyRect.
    n00b_isize_t min_row = (n00b_isize_t)(dirtyRect.origin.y / ctx->cell_h);
    n00b_isize_t max_row = (n00b_isize_t)((dirtyRect.origin.y + dirtyRect.size.height) / ctx->cell_h) + 1;
    n00b_isize_t min_col = (n00b_isize_t)(dirtyRect.origin.x / ctx->cell_w);
    n00b_isize_t max_col = (n00b_isize_t)((dirtyRect.origin.x + dirtyRect.size.width) / ctx->cell_w) + 1;

    if (min_row < 0) min_row = 0;
    if (min_col < 0) min_col = 0;
    if (max_row > rows) max_row = rows;
    if (max_col > cols) max_col = cols;

    // Default colors.
    CGFloat default_bg_r = 0.0, default_bg_g = 0.0, default_bg_b = 0.0;
    CGFloat default_fg_r = 1.0, default_fg_g = 1.0, default_fg_b = 1.0;

    for (n00b_isize_t r = min_row; r < max_row; r++) {
        for (n00b_isize_t c = min_col; c < max_col; c++) {
            n00b_rcell_t *cell = &ctx->staging[r * cols + c];

            // Skip continuation cells of wide chars.
            if (cell->flags & N00B_CELL_WIDE_CONT) {
                continue;
            }

            CGFloat x = c * ctx->cell_w;
            CGFloat y = r * ctx->cell_h;
            CGFloat w = cell->display_width > 1
                ? cell->display_width * ctx->cell_w
                : ctx->cell_w;

            // --- Extract colors ---
            CGFloat bg_r = default_bg_r, bg_g = default_bg_g, bg_b = default_bg_b;
            CGFloat fg_r = default_fg_r, fg_g = default_fg_g, fg_b = default_fg_b;
            CGFloat fg_alpha = 1.0;
            bool    is_bold      = false;
            bool    is_italic    = false;
            bool    is_underline = false;
            bool    is_dbl_underline = false;
            bool    is_strike    = false;
            bool    is_reverse   = false;
            bool    is_dim       = false;
            int     font_hint    = N00B_FONT_DEFAULT;

            const n00b_text_style_t *style = cell->style;
            if (style) {
                // Foreground color.
                if (n00b_color_is_set(style->fg_rgb)) {
                    int rgb = n00b_color_rgb(style->fg_rgb);
                    fg_r = ((rgb >> 16) & 0xFF) / 255.0;
                    fg_g = ((rgb >>  8) & 0xFF) / 255.0;
                    fg_b = ( rgb        & 0xFF) / 255.0;
                }
                else if (style->fg_palette_ix >= 0 && style->fg_palette_ix < N00B_PAL_SIZE) {
                    n00b_color_t resolved = n00b_theme_resolve_color(style->fg_palette_ix);
                    if (n00b_color_is_set(resolved)) {
                        int rgb = n00b_color_rgb(resolved);
                        fg_r = ((rgb >> 16) & 0xFF) / 255.0;
                        fg_g = ((rgb >>  8) & 0xFF) / 255.0;
                        fg_b = ( rgb        & 0xFF) / 255.0;
                    }
                }

                // Background color.
                if (n00b_color_is_set(style->bg_rgb)) {
                    int rgb = n00b_color_rgb(style->bg_rgb);
                    bg_r = ((rgb >> 16) & 0xFF) / 255.0;
                    bg_g = ((rgb >>  8) & 0xFF) / 255.0;
                    bg_b = ( rgb        & 0xFF) / 255.0;
                }
                else if (style->bg_palette_ix >= 0 && style->bg_palette_ix < N00B_PAL_SIZE) {
                    n00b_color_t resolved = n00b_theme_resolve_color(style->bg_palette_ix);
                    if (n00b_color_is_set(resolved)) {
                        int rgb = n00b_color_rgb(resolved);
                        bg_r = ((rgb >> 16) & 0xFF) / 255.0;
                        bg_g = ((rgb >>  8) & 0xFF) / 255.0;
                        bg_b = ( rgb        & 0xFF) / 255.0;
                    }
                }

                is_bold          = (style->bold == N00B_TRI_YES);
                is_italic        = (style->italic == N00B_TRI_YES);
                is_underline     = (style->underline == N00B_TRI_YES);
                is_dbl_underline = (style->double_underline == N00B_TRI_YES);
                is_strike        = (style->strikethrough == N00B_TRI_YES);
                is_reverse       = (style->reverse == N00B_TRI_YES);
                is_dim           = (style->dim == N00B_TRI_YES);
                font_hint        = style->font_hint;
            }

            // Handle reverse.
            if (is_reverse) {
                CGFloat tmp;
                tmp = fg_r; fg_r = bg_r; bg_r = tmp;
                tmp = fg_g; fg_g = bg_g; bg_g = tmp;
                tmp = fg_b; fg_b = bg_b; bg_b = tmp;
            }

            // Handle dim.
            if (is_dim) {
                fg_alpha = 0.5;
            }

            // --- Background fill ---
            CGContextSetRGBFillColor(cg, bg_r, bg_g, bg_b, 1.0);
            CGContextFillRect(cg, CGRectMake(x, y, w, ctx->cell_h));

            // --- Border cells: draw with CG lines instead of glyphs ---
            if ((cell->flags & N00B_CELL_BORDER) && cell->grapheme_len > 0) {
                uint32_t cp = decode_first_codepoint(cell->grapheme,
                                                     cell->grapheme_len);
                draw_border_cell(cg, x, y, w, ctx->cell_h,
                                 fg_r, fg_g, fg_b, fg_alpha, cp);
            }
            // --- Foreground text ---
            else if ((cell->flags & N00B_CELL_OCCUPIED) && cell->grapheme_len > 0) {
                // Select font, honoring per-cell font_size.
                CTFontRef base_font = ctx->ct_fonts[font_hint < COCOA_NUM_FONT_HINTS ? font_hint : 0];
                CTFontRef font = base_font;
                bool font_size_override = false;

                if (style && style->font_size > 0) {
                    CGFloat pt = (CGFloat)style->font_size;
                    CTFontRef sized = CTFontCreateCopyWithAttributes(base_font, pt, NULL, NULL);
                    if (sized) {
                        font = sized;
                        font_size_override = true;
                    }
                }

                // Apply bold/italic traits.
                if (is_bold || is_italic) {
                    CTFontSymbolicTraits traits = 0;
                    if (is_bold)   traits |= kCTFontBoldTrait;
                    if (is_italic) traits |= kCTFontItalicTrait;

                    CTFontRef styled = CTFontCreateCopyWithSymbolicTraits(
                        font, 0.0, NULL, traits, traits);
                    if (styled) {
                        if (font_size_override) {
                            CFRelease(font);  // Release sized intermediate.
                        }
                        font = styled;
                    }
                    else {
                        // Fallback: keep current font.  If font_size_override
                        // is set, font is already owned; otherwise retain.
                        if (!font_size_override) {
                            font = CFRetain(font);
                        }
                    }
                }
                else {
                    if (!font_size_override) {
                        font = CFRetain(font);
                    }
                }

                // Build attributed string.
                CFStringRef str = CFStringCreateWithBytes(
                    kCFAllocatorDefault,
                    (const UInt8 *)cell->grapheme,
                    cell->grapheme_len,
                    kCFStringEncodingUTF8,
                    false);

                if (str) {
                    CGColorRef fg_color = CGColorCreateSRGB(fg_r, fg_g, fg_b, fg_alpha);

                    CFStringRef keys[] = {
                        kCTFontAttributeName,
                        kCTForegroundColorAttributeName,
                    };
                    CFTypeRef vals[] = {
                        font,
                        fg_color,
                    };

                    CFDictionaryRef attrs = CFDictionaryCreate(
                        kCFAllocatorDefault,
                        (const void **)keys,
                        (const void **)vals,
                        2,
                        &kCFTypeDictionaryKeyCallBacks,
                        &kCFTypeDictionaryValueCallBacks);

                    CFAttributedStringRef astr = CFAttributedStringCreate(
                        kCFAllocatorDefault, str, attrs);
                    CTLineRef line = CTLineCreateWithAttributedString(astr);

                    // Draw at baseline.  The view is flipped (y=0 at top)
                    // but Core Text draws upward from the baseline, so we
                    // must flip the CG context locally for text rendering.
                    CGContextSaveGState(cg);
                    CGContextTranslateCTM(cg, x, y + ctx->cell_h);
                    CGContextScaleCTM(cg, 1.0, -1.0);
                    CGContextSetTextPosition(cg, 0, ctx->descent + ctx->leading);
                    CTLineDraw(line, cg);
                    CGContextRestoreGState(cg);

                    CFRelease(line);
                    CFRelease(astr);
                    CFRelease(attrs);
                    CGColorRelease(fg_color);
                    CFRelease(str);
                }

                CFRelease(font);
            }

            // --- Decorations ---
            CGContextSetRGBStrokeColor(cg, fg_r, fg_g, fg_b, fg_alpha);
            CGContextSetLineWidth(cg, 1.0);

            if (is_underline) {
                CGFloat uy = y + ctx->ascent + 2.0;
                CGContextMoveToPoint(cg, x, uy);
                CGContextAddLineToPoint(cg, x + w, uy);
                CGContextStrokePath(cg);
            }
            if (is_dbl_underline) {
                CGFloat uy1 = y + ctx->ascent + 2.0;
                CGFloat uy2 = y + ctx->ascent + 4.0;
                CGContextMoveToPoint(cg, x, uy1);
                CGContextAddLineToPoint(cg, x + w, uy1);
                CGContextStrokePath(cg);
                CGContextMoveToPoint(cg, x, uy2);
                CGContextAddLineToPoint(cg, x + w, uy2);
                CGContextStrokePath(cg);
            }
            if (is_strike) {
                CGFloat sy = y + ctx->cell_h / 2.0;
                CGContextMoveToPoint(cg, x, sy);
                CGContextAddLineToPoint(cg, x + w, sy);
                CGContextStrokePath(cg);
            }
        }
    }

    // --- Cursor ---
    if (ctx->cursor_visible && ctx->cursor_blink_on) {
        if (ctx->cursor_row < rows && ctx->cursor_col < cols) {
            CGFloat cx = ctx->cursor_col * ctx->cell_w;
            CGFloat cy = ctx->cursor_row * ctx->cell_h;
            CGContextSetRGBFillColor(cg, default_fg_r, default_fg_g, default_fg_b, 0.5);
            CGContextFillRect(cg, CGRectMake(cx, cy, ctx->cell_w, ctx->cell_h));
        }
    }
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

- (void)keyDown:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    NSString *chars = [event charactersIgnoringModifiers];
    if (!chars || [chars length] == 0) {
        return;
    }

    n00b_event_t ev = {};
    if (!n00b_cocoa_input_translate_key((uint32_t)[chars characterAtIndex:0],
                                         cocoa_modifier_mask([event modifierFlags]),
                                         &ev)) {
        return;
    }
    cocoa_enqueue_event(ctx, &ev);
}

// -------------------------------------------------------------------
// Mouse event handlers
// -------------------------------------------------------------------

- (void)mouseDown:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_LEFT, N00B_MOUSE_PRESS);
}

- (void)mouseUp:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_LEFT, N00B_MOUSE_RELEASE);
}

- (void)rightMouseDown:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_RIGHT, N00B_MOUSE_PRESS);
}

- (void)rightMouseUp:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_RIGHT, N00B_MOUSE_RELEASE);
}

- (void)otherMouseDown:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_MIDDLE, N00B_MOUSE_PRESS);
}

- (void)otherMouseUp:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_MIDDLE, N00B_MOUSE_RELEASE);
}

- (void)mouseMoved:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_NONE, N00B_MOUSE_MOVE);
}

- (void)mouseDragged:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_LEFT, N00B_MOUSE_DRAG);
}

- (void)rightMouseDragged:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    cocoa_enqueue_mouse_event(ctx, self, event, N00B_MOUSE_RIGHT, N00B_MOUSE_DRAG);
}

- (void)scrollWheel:(NSEvent *)event
{
    cocoa_ctx_t *ctx = self.ctx;
    if (!ctx) return;

    CGFloat dy = [event scrollingDeltaY];
    if (dy == 0.0) return;

    n00b_mouse_button_t button = dy > 0.0 ? N00B_MOUSE_SCROLL_UP : N00B_MOUSE_SCROLL_DOWN;
    cocoa_enqueue_mouse_event(ctx, self, event, button, N00B_MOUSE_PRESS);
}

@end

// ====================================================================
// N00bAppDelegate — for standalone event loop
// ====================================================================

@interface N00bAppDelegate : NSObject <NSApplicationDelegate>
@property (nonatomic, assign) dispatch_semaphore_t readySem;
@end

@implementation N00bAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    if (self.readySem) {
        dispatch_semaphore_signal(self.readySem);
    }
}

@end

// ====================================================================
// Helper: dispatch to main thread synchronously
// ====================================================================

static void
dispatch_to_main_sync(dispatch_block_t block)
{
    if ([NSThread isMainThread]) {
        block();
    }
    else {
        dispatch_sync(dispatch_get_main_queue(), block);
    }
}

static bool
cocoa_clipboard_copy(void *vctx, const char *utf8, size_t len)
{
    __block bool ok = false;

    (void)vctx;

    if (!utf8) {
        return false;
    }

    dispatch_to_main_sync(^{
        @autoreleasepool {
            NSString *string = [[NSString alloc] initWithBytes:utf8
                                                        length:len
                                                      encoding:NSUTF8StringEncoding];
            NSPasteboard *pasteboard;

            if (!string) {
                return;
            }

            pasteboard = [NSPasteboard generalPasteboard];
            if (!pasteboard) {
                return;
            }

            [pasteboard clearContents];
            ok = [pasteboard setString:string forType:NSPasteboardTypeString];
        }
    });

    return ok;
}

// ====================================================================
// Event queue helpers
// ====================================================================

static void
cocoa_enqueue_event(cocoa_ctx_t *ctx, const n00b_event_t *ev)
{
    uint32_t next = (ctx->eq_head + 1) % COCOA_EVENT_QUEUE_CAP;
    if (next == ctx->eq_tail) {
        // Queue full — drop oldest.
        ctx->eq_tail = (ctx->eq_tail + 1) % COCOA_EVENT_QUEUE_CAP;
    }
    ctx->event_queue[ctx->eq_head] = *ev;
    ctx->eq_head = next;
}

static bool
cocoa_dequeue_event(cocoa_ctx_t *ctx, n00b_event_t *out)
{
    if (ctx->eq_tail == ctx->eq_head) {
        return false;
    }
    *out = ctx->event_queue[ctx->eq_tail];
    ctx->eq_tail = (ctx->eq_tail + 1) % COCOA_EVENT_QUEUE_CAP;
    return true;
}

static uint32_t
cocoa_modifier_mask(NSEventModifierFlags flags)
{
    uint32_t mods = 0;
    if (flags & NSEventModifierFlagShift) {
        mods |= N00B_COCOA_MOD_SHIFT;
    }
    if (flags & NSEventModifierFlagControl) {
        mods |= N00B_COCOA_MOD_CTRL;
    }
    if (flags & NSEventModifierFlagOption) {
        mods |= N00B_COCOA_MOD_ALT;
    }
    if (flags & NSEventModifierFlagCommand) {
        mods |= N00B_COCOA_MOD_CMD;
    }
    return mods;
}

static void
cocoa_enqueue_mouse_event(cocoa_ctx_t        *ctx,
                          NSView             *view,
                          NSEvent            *event,
                          n00b_mouse_button_t button,
                          n00b_mouse_action_t action)
{
    if (!ctx || !view || !event) {
        return;
    }

    NSPoint loc = [view convertPoint:[event locationInWindow] fromView:nil];
    n00b_event_t ev = {};
    n00b_cocoa_input_translate_mouse_point(loc.x,
                                           loc.y,
                                           (n00b_isize_t)ctx->cell_w,
                                           (n00b_isize_t)ctx->cell_h,
                                           button,
                                           action,
                                           cocoa_modifier_mask([event modifierFlags]),
                                           &ev);
    cocoa_enqueue_event(ctx, &ev);
}

static bool
cocoa_validate_bridge_layout(void)
{
    n00b_cocoa_bridge_layout_t canonical = n00b_cocoa_bridge_layout_canonical();
    n00b_cocoa_bridge_layout_t bridge    = n00b_cocoa_bridge_layout_bridge();
    const char                *mismatch  = NULL;

    if (n00b_cocoa_bridge_layout_match(&canonical, &bridge, &mismatch)) {
        return true;
    }

    fprintf(stderr,
            "cocoa backend bridge layout mismatch at '%s'; "
            "update include/display/render/cocoa_bridge.h to match canonical headers.\n",
            mismatch ? mismatch : "unknown");
    return false;
}

// ====================================================================
// Font management
// ====================================================================

static CTFontRef
create_font_with_fallbacks(NSArray<NSString *> *names, CGFloat size)
{
    for (NSString *name in names) {
        CTFontRef font = CTFontCreateWithName((__bridge CFStringRef)name, size, NULL);
        if (font) {
            // Verify the font was actually found (CT returns a fallback
            // if the name doesn't match).
            CFStringRef actual = CTFontCopyPostScriptName(font);
            if (actual) {
                CFRelease(actual);
                return font;
            }
            CFRelease(font);
        }
    }
    // Ultimate fallback.
    return CTFontCreateWithName(CFSTR("Courier"), size, NULL);
}

static void
setup_fonts(cocoa_ctx_t *ctx)
{
    CGFloat pt = COCOA_DEFAULT_FONT_PT;

    // MONO / DEFAULT — share the same font.
    CTFontRef mono = create_font_with_fallbacks(
        @[@"Menlo", @"Monaco", @"Courier"], pt);
    ctx->ct_fonts[N00B_FONT_DEFAULT] = CFRetain(mono);
    ctx->ct_fonts[N00B_FONT_MONO]    = mono;

    // SERIF
    ctx->ct_fonts[N00B_FONT_SERIF] = create_font_with_fallbacks(
        @[@"Times New Roman", @"Georgia", @"Palatino"], pt);

    // SANS
    ctx->ct_fonts[N00B_FONT_SANS] = create_font_with_fallbacks(
        @[@"Helvetica Neue", @"Helvetica", @"Arial"], pt);

    // Compute cell metrics from the monospace font.
    ctx->ascent  = CTFontGetAscent(mono);
    ctx->descent = CTFontGetDescent(mono);
    ctx->leading = CTFontGetLeading(mono);
    ctx->cell_h  = ceil(ctx->ascent + ctx->descent + ctx->leading);

    // Measure 'M' glyph advance for cell width.
    UniChar ch = 'M';
    CGGlyph glyph;
    CTFontGetGlyphsForCharacters(mono, &ch, &glyph, 1);
    CGSize advance;
    CTFontGetAdvancesForGlyphs(mono, kCTFontOrientationHorizontal,
                               &glyph, &advance, 1);
    ctx->cell_w = ceil(advance.width);
}

// ====================================================================
// Cursor blink timer
// ====================================================================

static void
start_blink_timer(cocoa_ctx_t *ctx);

static void
stop_blink_timer(cocoa_ctx_t *ctx)
{
    if (ctx->blink_timer) {
        NSTimer *timer = (__bridge_transfer NSTimer *)ctx->blink_timer;
        [timer invalidate];
        ctx->blink_timer = NULL;
    }
}

static void
blink_tick(NSTimer *timer)
{
    cocoa_ctx_t *ctx = (__bridge cocoa_ctx_t *)timer.userInfo;
    if (!ctx) return;

    ctx->cursor_blink_on = !ctx->cursor_blink_on;

    N00bRenderView *view = (__bridge N00bRenderView *)ctx->view;
    if (view && ctx->cursor_row < ctx->staging_rows && ctx->cursor_col < ctx->staging_cols) {
        CGFloat x = ctx->cursor_col * ctx->cell_w;
        CGFloat y = ctx->cursor_row * ctx->cell_h;
        [view setNeedsDisplayInRect:NSMakeRect(x, y, ctx->cell_w, ctx->cell_h)];
    }
}

static void
start_blink_timer(cocoa_ctx_t *ctx)
{
    stop_blink_timer(ctx);

    dispatch_to_main_sync(^{
        NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:COCOA_CURSOR_BLINK_SEC
                                                         target:[NSBlockOperation blockOperationWithBlock:^{}]
                                                       selector:@selector(main)
                                                       userInfo:nil
                                                        repeats:YES];
        // Replace with a proper callback timer.
        [timer invalidate];

        timer = [NSTimer timerWithTimeInterval:COCOA_CURSOR_BLINK_SEC
                                       repeats:YES
                                         block:^(NSTimer *t) {
            blink_tick(t);
        }];
        // Store the context reference for the tick.
        // We use a small wrapper since timerWithTimeInterval:block: doesn't
        // take userInfo.  Store ctx in the view property instead.
        [[NSRunLoop mainRunLoop] addTimer:timer forMode:NSRunLoopCommonModes];
        ctx->blink_timer = (__bridge_retained void *)timer;
    });
}

// ====================================================================
// Resize notification handler
// ====================================================================

static void
handle_resize(NSNotification *note, cocoa_ctx_t *ctx)
{
    NSWindow *win = (__bridge NSWindow *)ctx->window;
    if (!win) return;

    NSRect bounds = [win.contentView bounds];
    n00b_isize_t new_cols = (n00b_isize_t)(bounds.size.width / ctx->cell_w);
    n00b_isize_t new_rows = (n00b_isize_t)(bounds.size.height / ctx->cell_h);

    if (new_cols < 1) new_cols = 1;
    if (new_rows < 1) new_rows = 1;

    // Update backing pixel dimensions.
    NSRect backing = [win.contentView convertRectToBacking:bounds];
    ctx->pixel_w = (n00b_isize_t)backing.size.width;
    ctx->pixel_h = (n00b_isize_t)backing.size.height;

    if (new_cols != ctx->cols || new_rows != ctx->rows) {
        ctx->cols = new_cols;
        ctx->rows = new_rows;

        // Store pending resize for the event loop to pick up.
        ctx->has_pending_resize   = true;
        ctx->pending_resize_rows  = new_rows;
        ctx->pending_resize_cols  = new_cols;

        if (ctx->resize_cb) {
            ctx->resize_cb(new_rows, new_cols, ctx->resize_user_ctx);
        }
    }
}

// ====================================================================
// Vtable implementation: init
// ====================================================================

static void *
cocoa_init(void *output)
{
    cocoa_ctx_t *ctx = n00b_interposed_calloc(1, sizeof(cocoa_ctx_t));
    if (!ctx) return NULL;

    ctx->output = output;
    ctx->cursor_blink_on = true;

    if (!cocoa_validate_bridge_layout()) {
        n00b_interposed_free(ctx);
        return NULL;
    }

    // --- NSApplication setup ---
    // We always initialize NSApp but never call [NSApp run] ourselves.
    // The caller is responsible for pumping the run loop (e.g. via
    // [[NSRunLoop mainRunLoop] runUntilDate:] or their own [NSApp run]).
    // This avoids the NSUpdateCycleInitialize crash that occurs when
    // [NSApp run] is called on a background thread.
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];

        if (![app isRunning]) {
            ctx->owns_nsapp = true;
            ctx->needs_finish_launch = true;
            [app setActivationPolicy:NSApplicationActivationPolicyRegular];

            N00bAppDelegate *delegate = [[N00bAppDelegate alloc] init];
            [app setDelegate:delegate];

            // NOTE: We defer [app finishLaunching] to the first
            // cocoa_poll_event() call.  Calling it here (during
            // cocoa_init → n00b_canvas_init) triggers AppKit menu
            // setup which dlopen's WritingTools, firing dyld load
            // notifications into n00b_on_lib_load before the runtime
            // mmap tracking is fully initialized → assertion failure.
        }
        else {
            ctx->owns_nsapp = false;
        }

        // --- Font setup ---
        setup_fonts(ctx);

        ctx->cols = COCOA_DEFAULT_COLS;
        ctx->rows = COCOA_DEFAULT_ROWS;

        // --- Window + view creation ---
        // Must be on main thread.  If we're already on main (the
        // normal case for a GUI app), just do it directly.
        void (^create_window)(void) = ^{
            CGFloat win_w = ctx->cols * ctx->cell_w;
            CGFloat win_h = ctx->rows * ctx->cell_h;

            NSRect frame = NSMakeRect(100, 100, win_w, win_h);

            NSWindow *window = [[NSWindow alloc]
                initWithContentRect:frame
                          styleMask:(NSWindowStyleMaskTitled
                                   | NSWindowStyleMaskClosable
                                   | NSWindowStyleMaskResizable
                                   | NSWindowStyleMaskMiniaturizable)
                            backing:NSBackingStoreBuffered
                              defer:NO];

            [window setTitle:@"n00b"];
            [window setMinSize:NSMakeSize(ctx->cell_w * 10, ctx->cell_h * 5)];

            N00bRenderView *view = [[N00bRenderView alloc] initWithFrame:frame];
            view.ctx = ctx;
            [window setContentView:view];
            [window makeFirstResponder:view];

            ctx->window = (__bridge_retained void *)window;
            ctx->view   = (__bridge_retained void *)view;

            // Compute initial pixel dimensions.
            NSRect backing = [view convertRectToBacking:[view bounds]];
            ctx->pixel_w = (n00b_isize_t)backing.size.width;
            ctx->pixel_h = (n00b_isize_t)backing.size.height;

            // Register resize observer.
            [[NSNotificationCenter defaultCenter]
                addObserverForName:NSWindowDidResizeNotification
                            object:window
                             queue:[NSOperationQueue mainQueue]
                        usingBlock:^(NSNotification *note) {
                            handle_resize(note, ctx);
                        }];

            [window makeKeyAndOrderFront:nil];
            [NSApp activateIgnoringOtherApps:YES];
        };

        if ([NSThread isMainThread]) {
            create_window();
        }
        else {
            dispatch_sync(dispatch_get_main_queue(), create_window);
        }
    }

    return ctx;
}

// ====================================================================
// Vtable implementation: destroy
// ====================================================================

static void
cocoa_destroy(void *vctx)
{
    cocoa_ctx_t *ctx = vctx;
    if (!ctx) return;

    // Stop blink timer.
    if (ctx->blink_timer) {
        dispatch_to_main_sync(^{
            stop_blink_timer(ctx);
        });
    }

    // Remove resize observer and close window.
    dispatch_to_main_sync(^{
        NSWindow *window = (__bridge NSWindow *)ctx->window;
        if (window) {
            [[NSNotificationCenter defaultCenter] removeObserver:window];
            [window close];
        }
    });

    // Release ObjC objects.
    if (ctx->window) {
        CFRelease(ctx->window);
        ctx->window = NULL;
    }
    if (ctx->view) {
        CFRelease(ctx->view);
        ctx->view = NULL;
    }

    // Release fonts.
    for (int i = 0; i < COCOA_NUM_FONT_HINTS; i++) {
        if (ctx->ct_fonts[i]) {
            CFRelease(ctx->ct_fonts[i]);
            ctx->ct_fonts[i] = NULL;
        }
    }

    // Free staging buffer.
    if (ctx->staging) {
        n00b_free(ctx->staging);
        ctx->staging = NULL;
    }
    n00b_composite_style_pool_destroy(&ctx->style_pool);

    // Free GUI cache.
    if (ctx->gui_cache) {
        for (n00b_isize_t i = 0; i < ctx->gui_cache_count; i++) {
            if (ctx->gui_cache[i].gradient) {
                CGGradientRelease(ctx->gui_cache[i].gradient);
            }
        }
        n00b_interposed_free(ctx->gui_cache);
        ctx->gui_cache = NULL;
    }

    n00b_interposed_free(ctx);
}

// ====================================================================
// Vtable implementation: capabilities
// ====================================================================

static n00b_render_cap_t
cocoa_capabilities(void *vctx)
{
    (void)vctx;

    return N00B_RCAP_COLOR_24BIT
         | N00B_RCAP_BOLD
         | N00B_RCAP_ITALIC
         | N00B_RCAP_UNDERLINE
         | N00B_RCAP_STRIKETHROUGH
         | N00B_RCAP_DIM
         | N00B_RCAP_UNICODE
         | N00B_RCAP_WIDE_CHARS
         | N00B_RCAP_CURSOR_MOVE
         | N00B_RCAP_PIXEL_COORDS
         | N00B_RCAP_FONT_METRICS
         | N00B_RCAP_DIFF_RENDER
         | N00B_RCAP_GUI_EXT
         | N00B_RCAP_MANAGES_TTY
         | N00B_RCAP_MOUSE;
}

// ====================================================================
// Vtable implementation: get_size
// ====================================================================

static n00b_render_size_t
cocoa_get_size(void *vctx)
{
    cocoa_ctx_t *ctx = vctx;

    return (n00b_render_size_t){
        .cols        = ctx->cols,
        .rows        = ctx->rows,
        .pixel_w     = ctx->pixel_w,
        .pixel_h     = ctx->pixel_h,
        .cell_pixel_w = (n00b_isize_t)ctx->cell_w,
        .cell_pixel_h = (n00b_isize_t)ctx->cell_h,
    };
}

// ====================================================================
// Vtable implementation: render_frame
// ====================================================================

static void
cocoa_render_frame(void         *vctx,
                   n00b_rcell_t *cells,
                   n00b_isize_t  rows,
                   n00b_isize_t  cols,
                   n00b_rcell_t *prev_cells)
{
    cocoa_ctx_t *ctx = vctx;
    size_t total = (size_t)rows * cols;
    size_t bytes = total * sizeof(n00b_rcell_t);

    // Reallocate staging if dimensions changed.
    if (ctx->staging_rows != rows || ctx->staging_cols != cols) {
        if (ctx->staging) {
            n00b_free(ctx->staging);
        }
        ctx->staging = n00b_cocoa_bridge_alloc_rcells(total);
        ctx->staging_rows = rows;
        ctx->staging_cols = cols;
    }

    // Compute dirty rect for diff rendering.
    n00b_isize_t dirty_min_row = rows;
    n00b_isize_t dirty_max_row = 0;
    n00b_isize_t dirty_min_col = cols;
    n00b_isize_t dirty_max_col = 0;

    if (prev_cells) {
        for (n00b_isize_t r = 0; r < rows; r++) {
            for (n00b_isize_t c = 0; c < cols; c++) {
                n00b_isize_t idx = r * cols + c;
                if (!n00b_rcell_equal(&cells[idx], &prev_cells[idx])) {
                    if (r < dirty_min_row) dirty_min_row = r;
                    if (r >= dirty_max_row) dirty_max_row = r + 1;
                    if (c < dirty_min_col) dirty_min_col = c;
                    if (c >= dirty_max_col) dirty_max_col = c + 1;
                }
            }
        }
    }
    else {
        dirty_min_row = 0;
        dirty_max_row = rows;
        dirty_min_col = 0;
        dirty_max_col = cols;
    }

    // Copy cells to staging buffer.
    memcpy(ctx->staging, cells, bytes);

    // Invalidate the dirty region on the main thread.
    if (dirty_max_row > dirty_min_row && dirty_max_col > dirty_min_col) {
        CGFloat px = dirty_min_col * ctx->cell_w;
        CGFloat py = dirty_min_row * ctx->cell_h;
        CGFloat pw = (dirty_max_col - dirty_min_col) * ctx->cell_w;
        CGFloat ph = (dirty_max_row - dirty_min_row) * ctx->cell_h;

        dispatch_to_main_sync(^{
            N00bRenderView *view = (__bridge N00bRenderView *)ctx->view;
            if (view) {
                [view setNeedsDisplayInRect:NSMakeRect(px, py, pw, ph)];
            }
        });
    }
}

// ====================================================================
// Vtable implementation: flush
// ====================================================================

static void
cocoa_flush(void *vctx)
{
    cocoa_ctx_t *ctx = vctx;

    dispatch_to_main_sync(^{
        N00bRenderView *view = (__bridge N00bRenderView *)ctx->view;
        if (view) {
            [view displayIfNeeded];
        }
    });
}

// ====================================================================
// Vtable implementation: cursor_set_visible
// ====================================================================

static void
cocoa_cursor_set_visible(void *vctx, bool visible)
{
    cocoa_ctx_t *ctx = vctx;

    ctx->cursor_visible = visible;
    ctx->cursor_blink_on = true;

    if (visible) {
        start_blink_timer(ctx);
    }
    else {
        dispatch_to_main_sync(^{
            stop_blink_timer(ctx);
        });
    }

    // Invalidate cursor cell.
    dispatch_to_main_sync(^{
        N00bRenderView *view = (__bridge N00bRenderView *)ctx->view;
        if (view && ctx->cursor_row < ctx->staging_rows && ctx->cursor_col < ctx->staging_cols) {
            CGFloat x = ctx->cursor_col * ctx->cell_w;
            CGFloat y = ctx->cursor_row * ctx->cell_h;
            [view setNeedsDisplayInRect:NSMakeRect(x, y, ctx->cell_w, ctx->cell_h)];
        }
    });
}

// ====================================================================
// Vtable implementation: cursor_move
// ====================================================================

static void
cocoa_cursor_move(void *vctx, n00b_isize_t row, n00b_isize_t col)
{
    cocoa_ctx_t *ctx = vctx;

    n00b_isize_t old_row = ctx->cursor_row;
    n00b_isize_t old_col = ctx->cursor_col;

    ctx->cursor_row = row;
    ctx->cursor_col = col;
    ctx->cursor_blink_on = true;

    dispatch_to_main_sync(^{
        N00bRenderView *view = (__bridge N00bRenderView *)ctx->view;
        if (!view) return;

        // Invalidate old cursor position.
        if (old_row < ctx->staging_rows && old_col < ctx->staging_cols) {
            [view setNeedsDisplayInRect:NSMakeRect(
                old_col * ctx->cell_w, old_row * ctx->cell_h,
                ctx->cell_w, ctx->cell_h)];
        }

        // Invalidate new cursor position.
        if (row < ctx->staging_rows && col < ctx->staging_cols) {
            [view setNeedsDisplayInRect:NSMakeRect(
                col * ctx->cell_w, row * ctx->cell_h,
                ctx->cell_w, ctx->cell_h)];
        }
    });
}

// ====================================================================
// Vtable implementation: on_resize
// ====================================================================

static void
cocoa_on_resize(void *vctx,
                void (*cb)(n00b_isize_t, n00b_isize_t, void *),
                void *user_ctx)
{
    cocoa_ctx_t *ctx = vctx;
    ctx->resize_cb       = cb;
    ctx->resize_user_ctx = user_ctx;
}

// ====================================================================
// Vtable implementation: prepare_gui
// ====================================================================

static CGBlendMode
map_blend_mode(n00b_cocoa_blend_mode_t mode)
{
    switch (mode) {
    case N00B_BLEND_MULTIPLY:   return kCGBlendModeMultiply;
    case N00B_BLEND_SCREEN:     return kCGBlendModeScreen;
    case N00B_BLEND_OVERLAY:    return kCGBlendModeOverlay;
    case N00B_BLEND_SOFT_LIGHT: return kCGBlendModeSoftLight;
    default:                    return kCGBlendModeNormal;
    }
}

static void
cocoa_prepare_gui(void *vctx, n00b_plane_t **planes, n00b_isize_t n)
{
    cocoa_ctx_t *ctx = vctx;

    // Free old cache.
    if (ctx->gui_cache) {
        for (n00b_isize_t i = 0; i < ctx->gui_cache_count; i++) {
            if (ctx->gui_cache[i].gradient) {
                CGGradientRelease(ctx->gui_cache[i].gradient);
            }
        }
        n00b_interposed_free(ctx->gui_cache);
        ctx->gui_cache = NULL;
        ctx->gui_cache_count = 0;
    }

    if (n == 0 || !planes) return;

    ctx->gui_cache = n00b_interposed_calloc(n, sizeof(cocoa_plane_cache_t));
    ctx->gui_cache_count = n;

    for (n00b_isize_t i = 0; i < n; i++) {
        if (!planes[i] || !planes[i]->box || !planes[i]->box->gui_ext) {
            continue;
        }

        cocoa_gui_ext_t *ext = (cocoa_gui_ext_t *)planes[i]->box->gui_ext;
        ctx->gui_cache[i].ext = ext;
        ctx->gui_cache[i].cg_blend = map_blend_mode(ext->blend_mode);

        // Build gradient if specified.
        if (ext->gradient_dir != N00B_GRADIENT_NONE
            && n00b_color_is_set(ext->gradient_start)
            && n00b_color_is_set(ext->gradient_end)) {

            int rgb_start = n00b_color_rgb(ext->gradient_start);
            int rgb_end   = n00b_color_rgb(ext->gradient_end);

            CGFloat components[8] = {
                ((rgb_start >> 16) & 0xFF) / 255.0,
                ((rgb_start >>  8) & 0xFF) / 255.0,
                ( rgb_start        & 0xFF) / 255.0,
                1.0,
                ((rgb_end >> 16) & 0xFF) / 255.0,
                ((rgb_end >>  8) & 0xFF) / 255.0,
                ( rgb_end        & 0xFF) / 255.0,
                1.0,
            };
            CGFloat locations[2] = {0.0, 1.0};

            CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
            ctx->gui_cache[i].gradient = CGGradientCreateWithColorComponents(
                cs, components, locations, 2);
            CGColorSpaceRelease(cs);
        }
    }
}

// ====================================================================
// Vtable implementation: poll_event
// ====================================================================

static bool
cocoa_poll_event(void *vctx, int32_t timeout_ms, n00b_event_t *out)
{
    cocoa_ctx_t *ctx = vctx;
    out->type = N00B_EVENT_NONE;

    // Deferred finishLaunching — must happen after the runtime is
    // fully initialized (not during cocoa_init) because AppKit's
    // menu setup dlopen's frameworks that trigger n00b_on_lib_load.
    if (ctx->needs_finish_launch) {
        ctx->needs_finish_launch = false;
        @autoreleasepool {
            [NSApp finishLaunching];
        }
    }

    // Check for pending resize first.
    if (ctx->has_pending_resize) {
        ctx->has_pending_resize = false;
        out->type        = N00B_EVENT_RESIZE;
        out->resize.rows = ctx->pending_resize_rows;
        out->resize.cols = ctx->pending_resize_cols;
        return true;
    }

    // Pump NSApplication events.  NSRunLoop's runUntilDate: only
    // processes timers and input sources — it does NOT deliver
    // NSApplication events (keyboard, mouse) to views.  We must
    // use nextEventMatchingMask: + sendEvent: explicitly.
    @autoreleasepool {
        NSDate *limit;
        if (timeout_ms < 0) {
            limit = [NSDate dateWithTimeIntervalSinceNow:0.1];
        }
        else if (timeout_ms == 0) {
            limit = [NSDate distantPast];
        }
        else {
            limit = [NSDate dateWithTimeIntervalSinceNow:timeout_ms / 1000.0];
        }

        NSEvent *event;
        while ((event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                           untilDate:limit
                                              inMode:NSDefaultRunLoopMode
                                             dequeue:YES]) != nil) {
            [NSApp sendEvent:event];
            // After the first event, switch to non-blocking drain
            // so we don't wait the full timeout when events are queued.
            limit = [NSDate distantPast];
        }
    }

    // Dequeue from ring buffer.
    return cocoa_dequeue_event(ctx, out);
}

// ====================================================================
// cocoa_gui_ext_t constructor
// ====================================================================

cocoa_gui_ext_t *
n00b_cocoa_gui_ext_new(void)
{
    cocoa_gui_ext_t *ext = n00b_interposed_calloc(1, sizeof(cocoa_gui_ext_t));
    if (ext) {
        ext->opacity = 1.0f;
    }
    return ext;
}

// ====================================================================
// Run loop pump (C-callable)
// ====================================================================

void
n00b_cocoa_run_loop_pump(double seconds)
{
    @autoreleasepool {
        NSDate *limit = [NSDate dateWithTimeIntervalSinceNow:seconds];
        NSEvent *event;
        while ((event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                           untilDate:limit
                                              inMode:NSDefaultRunLoopMode
                                             dequeue:YES]) != nil) {
            [NSApp sendEvent:event];
        }
    }
}

// ====================================================================
// Plane-based rendering
// ====================================================================

static void
cocoa_render_planes(void                         *vctx,
                    const n00b_composite_entry_t *entries,
                    n00b_isize_t                  count,
                    n00b_isize_t                  total_rows,
                    n00b_isize_t                  total_cols,
                    n00b_text_style_t            *default_style,
                    n00b_render_cap_t             caps)
{
    cocoa_ctx_t *ctx = vctx;

    // total_rows/total_cols are now in pixels; convert to cells for the grid.
    int32_t cpw = ctx->cell_w > 0 ? (int32_t)ctx->cell_w : 1;
    int32_t cph = ctx->cell_h > 0 ? (int32_t)ctx->cell_h : 1;
    n00b_isize_t cell_rows = total_rows / cph;
    n00b_isize_t cell_cols = total_cols / cpw;
    if (cell_rows < 1) cell_rows = 1;
    if (cell_cols < 1) cell_cols = 1;

    // Reuse staging buffer dimensions for grid caching.
    size_t total = (size_t)cell_rows * cell_cols;

    // Use the staging buffer directly as our compositing target.
    // Reallocate if size changed.
    if (ctx->staging_rows != cell_rows || ctx->staging_cols != cell_cols) {
        if (ctx->staging) {
            n00b_free(ctx->staging);
        }
        ctx->staging      = n00b_cocoa_bridge_alloc_rcells(total);
        ctx->staging_rows = cell_rows;
        ctx->staging_cols = cell_cols;
    }

    n00b_composite_style_pool_clear(&ctx->style_pool);
    n00b_composite_commands_to_grid(entries, count, ctx->staging,
                                     cell_rows, cell_cols,
                                     cpw, cph,
                                     default_style, caps,
                                     &ctx->style_pool);

    // Route through existing render_frame (which copies staging and
    // invalidates the dirty region for drawRect:).
    cocoa_render_frame(vctx, ctx->staging, cell_rows, cell_cols, NULL);
}

// ====================================================================
// Public vtable
// ====================================================================

const n00b_renderer_vtable_t n00b_renderer_cocoa = {
    .name               = "cocoa",
    .version            = N00B_RENDERER_ABI_VERSION,
    .init               = cocoa_init,
    .destroy            = cocoa_destroy,
    .capabilities       = cocoa_capabilities,
    .get_size           = cocoa_get_size,
    .render_frame       = cocoa_render_frame,
    .flush              = cocoa_flush,
    .render_planes      = cocoa_render_planes,
    .clipboard_copy     = cocoa_clipboard_copy,
    .cursor_set_visible = cocoa_cursor_set_visible,
    .cursor_move        = cocoa_cursor_move,
    .on_resize          = cocoa_on_resize,
    .prepare_gui        = cocoa_prepare_gui,
    .get_font_metrics   = NULL,
    .poll_event         = cocoa_poll_event,
};

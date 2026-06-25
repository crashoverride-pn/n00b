/*
 * Input widget: single-line text input with cursor, scroll, editing.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "display/render/plane.h"
#include "display/render/types.h"
#include "display/widget.h"
#include "display/widgets/input.h"
#include "display/event.h"
#include "display/render/box.h"
#include "internal/display/widget_primitives.h"
#include "text/unicode/properties.h"
#include "text/strings/text_style.h"
#include "text/strings/string_style.h"
#include "text/strings/string_ops.h"
#include "text/strings/theme.h"

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

static n00b_isize_t
input_text_len(n00b_input_t *inp)
{
    if (!inp->text) {
        return 0;
    }
    return (n00b_isize_t)inp->text->codepoints;
}

/*
 * Ensure scroll_offset (in codepoints) is valid so the cursor pixel
 * position remains within [0, content_w) when rendered.
 *
 * We compare pixel widths of the text segments to content_w so the
 * decision is made in pixel units, but scroll_offset is still stored
 * as a codepoint index because editing logic (insert/delete) needs it
 * that way.
 */
static void
input_adjust_scroll(n00b_input_t  *inp,
                    n00b_plane_t  *plane,
                    n00b_string_t *display_text,
                    int32_t        content_w)
{
    if (content_w <= 0) {
        return;
    }

    // Cursor is before the scroll window: snap window left.
    if (inp->cursor_pos < inp->scroll_offset) {
        inp->scroll_offset = inp->cursor_pos;
    }

    // Cursor pixel position relative to scroll_offset.
    // cursor_px is the width of text[scroll_offset .. cursor_pos].
    n00b_isize_t visible_cps = inp->cursor_pos - inp->scroll_offset;

    // Measure the substring from scroll_offset to cursor_pos.
    int32_t cursor_px = 0;
    if (visible_cps > 0 && display_text) {
        // Build a substring starting at scroll_offset, length = visible_cps.
        const char  *p     = display_text->data;
        n00b_isize_t bytes = (n00b_isize_t)display_text->u8_bytes;
        n00b_isize_t b0    = 0;

        // Advance to scroll_offset.
        for (n00b_isize_t i = 0; i < inp->scroll_offset && b0 < bytes; i++) {
            unsigned char c = (unsigned char)p[b0];
            if (c < 0x80)
                b0 += 1;
            else if (c < 0xE0)
                b0 += 2;
            else if (c < 0xF0)
                b0 += 3;
            else
                b0 += 4;
        }

        n00b_isize_t b1 = b0;
        for (n00b_isize_t i = 0; i < visible_cps && b1 < bytes; i++) {
            unsigned char c = (unsigned char)p[b1];
            if (c < 0x80)
                b1 += 1;
            else if (c < 0xE0)
                b1 += 2;
            else if (c < 0xF0)
                b1 += 3;
            else
                b1 += 4;
        }

        if (b1 > b0) {
            n00b_string_t *seg
                = n00b_unicode_str_slice_bytes(display_text, (uint32_t)b0, (uint32_t)b1);
            cursor_px = n00b_plane_text_width(plane, seg, nullptr);
        }
    }

    // If cursor pixel position is at or beyond content_w, scroll right
    // until the cursor fits.  We advance scroll_offset one codepoint at
    // a time — infrequent operation so simplicity beats speed here.
    while (cursor_px >= content_w && inp->scroll_offset < inp->cursor_pos) {
        inp->scroll_offset++;
        visible_cps--;
        if (visible_cps <= 0) {
            cursor_px = 0;
            break;
        }
        // Recompute cursor_px after the bump.
        const char  *p     = display_text->data;
        n00b_isize_t bytes = (n00b_isize_t)display_text->u8_bytes;
        n00b_isize_t b0    = 0;
        for (n00b_isize_t i = 0; i < inp->scroll_offset && b0 < bytes; i++) {
            unsigned char c = (unsigned char)p[b0];
            if (c < 0x80)
                b0 += 1;
            else if (c < 0xE0)
                b0 += 2;
            else if (c < 0xF0)
                b0 += 3;
            else
                b0 += 4;
        }
        n00b_isize_t b1 = b0;
        for (n00b_isize_t i = 0; i < visible_cps && b1 < bytes; i++) {
            unsigned char c = (unsigned char)p[b1];
            if (c < 0x80)
                b1 += 1;
            else if (c < 0xE0)
                b1 += 2;
            else if (c < 0xF0)
                b1 += 3;
            else
                b1 += 4;
        }
        if (b1 > b0) {
            n00b_string_t *seg
                = n00b_unicode_str_slice_bytes(display_text, (uint32_t)b0, (uint32_t)b1);
            cursor_px = n00b_plane_text_width(plane, seg, nullptr);
        }
        else {
            cursor_px = 0;
        }
    }

    if (inp->scroll_offset < 0) {
        inp->scroll_offset = 0;
    }
}

/*
 * Insert a codepoint at cursor_pos.  Strings are immutable, so we
 * build a new one: text[..cursor] + ch + text[cursor..].
 */
static void
input_insert_char(n00b_input_t *inp, uint32_t ch)
{
    n00b_isize_t len = input_text_len(inp);

    if (inp->max_length > 0 && len >= inp->max_length) {
        return;
    }

    // Encode the codepoint as UTF-8.
    char utf8[5];
    int  utf8_len = 0;

    if (ch < 0x80) {
        utf8[0]  = (char)ch;
        utf8_len = 1;
    }
    else if (ch < 0x800) {
        utf8[0]  = (char)(0xC0 | (ch >> 6));
        utf8[1]  = (char)(0x80 | (ch & 0x3F));
        utf8_len = 2;
    }
    else if (ch < 0x10000) {
        utf8[0]  = (char)(0xE0 | (ch >> 12));
        utf8[1]  = (char)(0x80 | ((ch >> 6) & 0x3F));
        utf8[2]  = (char)(0x80 | (ch & 0x3F));
        utf8_len = 3;
    }
    else {
        utf8[0]  = (char)(0xF0 | (ch >> 18));
        utf8[1]  = (char)(0x80 | ((ch >> 12) & 0x3F));
        utf8[2]  = (char)(0x80 | ((ch >> 6) & 0x3F));
        utf8[3]  = (char)(0x80 | (ch & 0x3F));
        utf8_len = 4;
    }
    utf8[utf8_len] = '\0';

    n00b_string_t *ch_str = n00b_string_from_cstr(utf8);

    if (!inp->text || len == 0) {
        inp->text = ch_str;
    }
    else if (inp->cursor_pos == 0) {
        inp->text = n00b_unicode_str_cat(ch_str, inp->text);
    }
    else if (inp->cursor_pos >= len) {
        inp->text = n00b_unicode_str_cat(inp->text, ch_str);
    }
    else {
        // Find the byte offset for cursor_pos codepoints.
        n00b_isize_t byte_offset = 0;
        const char  *p           = inp->text->data;
        for (n00b_isize_t i = 0;
             i < inp->cursor_pos && byte_offset < (n00b_isize_t)inp->text->u8_bytes;
             i++) {
            unsigned char c = (unsigned char)p[byte_offset];
            if (c < 0x80)
                byte_offset += 1;
            else if (c < 0xE0)
                byte_offset += 2;
            else if (c < 0xF0)
                byte_offset += 3;
            else
                byte_offset += 4;
        }

        n00b_string_t *before
            = n00b_unicode_str_slice_bytes(inp->text, 0, (uint32_t)byte_offset);
        n00b_string_t *after = n00b_unicode_str_slice_bytes(inp->text,
                                                            (uint32_t)byte_offset,
                                                            (uint32_t)inp->text->u8_bytes);
        inp->text = n00b_unicode_str_cat(n00b_unicode_str_cat(before, ch_str), after);
    }

    inp->cursor_pos++;
}

/*
 * Delete the codepoint before cursor_pos (backspace).
 */
static void
input_delete_before(n00b_input_t *inp)
{
    if (inp->cursor_pos <= 0 || !inp->text) {
        return;
    }

    n00b_isize_t len = input_text_len(inp);

    if (len == 1) {
        inp->text       = r"";
        inp->cursor_pos = 0;
        return;
    }

    // Find byte offsets for cursor_pos-1 and cursor_pos.
    n00b_isize_t byte_start = 0;
    n00b_isize_t byte_end   = 0;
    const char  *p          = inp->text->data;

    for (n00b_isize_t i = 0;
         i < inp->cursor_pos && byte_end < (n00b_isize_t)inp->text->u8_bytes;
         i++) {
        byte_start      = byte_end;
        unsigned char c = (unsigned char)p[byte_end];
        if (c < 0x80)
            byte_end += 1;
        else if (c < 0xE0)
            byte_end += 2;
        else if (c < 0xF0)
            byte_end += 3;
        else
            byte_end += 4;
    }

    // Rebuild: text[..byte_start] + text[byte_end..].
    n00b_string_t *before = nullptr;
    n00b_string_t *after  = nullptr;

    if (byte_start > 0) {
        before = n00b_unicode_str_slice_bytes(inp->text, 0, (uint32_t)byte_start);
    }
    if (byte_end < (n00b_isize_t)inp->text->u8_bytes) {
        after = n00b_unicode_str_slice_bytes(inp->text,
                                             (uint32_t)byte_end,
                                             (uint32_t)inp->text->u8_bytes);
    }

    if (before && after) {
        inp->text = n00b_unicode_str_cat(before, after);
    }
    else if (before) {
        inp->text = before;
    }
    else if (after) {
        inp->text = after;
    }
    else {
        inp->text = r"";
    }

    inp->cursor_pos--;
}

/*
 * Delete the codepoint at cursor_pos (delete key).
 */
static void
input_delete_at(n00b_input_t *inp)
{
    n00b_isize_t len = input_text_len(inp);
    if (inp->cursor_pos >= len || !inp->text) {
        return;
    }

    // Temporarily move cursor forward and delete behind it.
    inp->cursor_pos++;
    input_delete_before(inp);
}

// -------------------------------------------------------------------
// Vtable callbacks
// -------------------------------------------------------------------

static void
input_destroy(n00b_plane_t *plane, void *data)
{
    (void)plane;
    (void)data;
}

static void
input_render(n00b_plane_t *plane, void *data)
{
    n00b_input_t *inp = (n00b_input_t *)data;
    if (!inp) {
        return;
    }

    n00b_plane_clear(plane);

    int32_t content_w;
    int32_t content_h;
    n00b_plane_content_size(plane, &content_w, &content_h);

    if (content_w == 0 || content_h == 0) {
        return;
    }

    // Character pixel width — used for cursor positioning and single-char
    // width fallback when n00b_plane_text_width returns 0.
    int32_t cpw = n00b_widget_cell_px_width(plane);

    n00b_isize_t text_len = input_text_len(inp);
    bool         focused  = (plane->widget_state == N00B_WSTATE_FOCUSED);

    // Fill the content area with a background colour so the field is
    // visible even when empty.  Note: fill_rect takes (x, y, w, h).
    n00b_text_style_t *bg_style = n00b_alloc(n00b_text_style_t);
    bg_style->bg_rgb
        = n00b_theme_resolve_color(focused ? N00B_PAL_SURFACE : N00B_PAL_SURFACE_DARK);
    n00b_plane_fill_rect(plane, 0, 0, content_w, content_h, .style = bg_style);

    // Empty + unfocused: show placeholder over the fill.
    if (text_len == 0 && !focused && inp->placeholder && inp->placeholder->u8_bytes > 0) {
        n00b_text_style_t *dim_style = n00b_alloc(n00b_text_style_t);
        dim_style->fg_rgb            = n00b_theme_resolve_color(N00B_PAL_PLACEHOLDER);
        dim_style->bg_rgb            = n00b_theme_resolve_color(N00B_PAL_SURFACE_DARK);
        n00b_string_t *ph            = n00b_str_set_base_style(inp->placeholder, dim_style);
        n00b_plane_draw_text(plane, 0, 0, ph);
        return;
    }

    // Build display_text first (password masking) so that
    // input_adjust_scroll measures the actual rendered glyphs.
    n00b_string_t *display_text = inp->text ? inp->text : r"";
    if (inp->password && text_len > 0) {
        char *mask = n00b_alloc_array(char, (size_t)(text_len + 1));
        for (n00b_isize_t i = 0; i < text_len; i++) {
            mask[i] = '*';
        }
        mask[text_len] = '\0';
        display_text   = n00b_string_from_cstr(mask);
    }

    // Adjust scroll so the cursor stays within [0, content_w) in pixels.
    input_adjust_scroll(inp, plane, display_text, content_w);

    // Walk to the byte start of the scroll window.
    const char  *p           = display_text->data;
    n00b_isize_t total_bytes = (n00b_isize_t)display_text->u8_bytes;
    n00b_isize_t byte_offset = 0;

    for (n00b_isize_t i = 0; i < inp->scroll_offset && byte_offset < total_bytes; i++) {
        unsigned char c = (unsigned char)p[byte_offset];
        if (c < 0x80)
            byte_offset += 1;
        else if (c < 0xE0)
            byte_offset += 2;
        else if (c < 0xF0)
            byte_offset += 3;
        else
            byte_offset += 4;
    }

    n00b_isize_t visible_start = byte_offset;

    // Consume codepoints while their cumulative pixel width fits in content_w.
    int32_t      accumulated_px = 0;
    n00b_isize_t end_offset     = byte_offset;

    while (end_offset < total_bytes) {
        unsigned char c    = (unsigned char)p[end_offset];
        n00b_isize_t  clen = (c < 0x80) ? 1 : (c < 0xE0) ? 2 : (c < 0xF0) ? 3 : 4;

        n00b_string_t *one_cp = n00b_unicode_str_slice_bytes(display_text,
                                                             (uint32_t)end_offset,
                                                             (uint32_t)(end_offset + clen));
        int32_t        cp_w   = n00b_plane_text_width(plane, one_cp, nullptr);
        if (cp_w <= 0) {
            cp_w = cpw;
        }

        if (accumulated_px + cp_w > content_w) {
            break;
        }

        accumulated_px += cp_w;
        end_offset += clen;
    }

    // Style and draw the visible slice.
    if (end_offset > visible_start) {
        n00b_text_style_t *text_style = n00b_alloc(n00b_text_style_t);
        text_style->fg_rgb            = n00b_theme_resolve_color(N00B_PAL_TEXT_PRIMARY);
        text_style->bg_rgb
            = n00b_theme_resolve_color(focused ? N00B_PAL_SURFACE : N00B_PAL_SURFACE_DARK);
        n00b_string_t *visible = n00b_unicode_str_slice_bytes(display_text,
                                                              (uint32_t)visible_start,
                                                              (uint32_t)end_offset);
        visible                = n00b_str_set_base_style(visible, text_style);
        n00b_plane_draw_text(plane, 0, 0, visible);
    }

    // Cursor: reverse-video glyph at the pixel x position when focused.
    if (focused) {
        // Pixel x = width of display_text[visible_start .. cursor byte pos].
        n00b_isize_t cps_before_cursor = inp->cursor_pos - inp->scroll_offset;
        int32_t      cursor_px         = 0;

        if (cps_before_cursor > 0) {
            n00b_isize_t bo = visible_start;
            for (n00b_isize_t i = 0; i < cps_before_cursor && bo < total_bytes; i++) {
                unsigned char c = (unsigned char)p[bo];
                if (c < 0x80)
                    bo += 1;
                else if (c < 0xE0)
                    bo += 2;
                else if (c < 0xF0)
                    bo += 3;
                else
                    bo += 4;
            }
            if (bo > visible_start) {
                n00b_string_t *pre = n00b_unicode_str_slice_bytes(display_text,
                                                                  (uint32_t)visible_start,
                                                                  (uint32_t)bo);
                cursor_px          = n00b_plane_text_width(plane, pre, nullptr);
            }
        }

        if (cursor_px >= 0 && cursor_px < content_w) {
            n00b_text_style_t *cursor_style = n00b_alloc(n00b_text_style_t);
            cursor_style->fg_rgb            = n00b_theme_resolve_color(N00B_PAL_TEXT_PRIMARY);
            cursor_style->reverse           = N00B_TRI_YES;
            cursor_style->bg_rgb            = n00b_theme_resolve_color(N00B_PAL_SURFACE);

            if (inp->cursor_pos < text_len) {
                // Walk to the cursor codepoint in the source string and
                // decode it for display (password mode uses '*').
                const char  *cp = display_text->data;
                n00b_isize_t bo = 0;
                for (n00b_isize_t i = 0; i < inp->cursor_pos && bo < total_bytes; i++) {
                    unsigned char ch = (unsigned char)cp[bo];
                    if (ch < 0x80)
                        bo += 1;
                    else if (ch < 0xE0)
                        bo += 2;
                    else if (ch < 0xF0)
                        bo += 3;
                    else
                        bo += 4;
                }

                uint32_t codepoint = ' ';
                if (bo < total_bytes) {
                    unsigned char ch = (unsigned char)cp[bo];
                    if (ch < 0x80) {
                        codepoint = ch;
                    }
                    else if (ch < 0xE0) {
                        codepoint = (ch & 0x1F) << 6;
                        if (bo + 1 < total_bytes)
                            codepoint |= ((unsigned char)cp[bo + 1]) & 0x3F;
                    }
                    else if (ch < 0xF0) {
                        codepoint = (ch & 0x0F) << 12;
                        if (bo + 1 < total_bytes)
                            codepoint |= (((unsigned char)cp[bo + 1]) & 0x3F) << 6;
                        if (bo + 2 < total_bytes)
                            codepoint |= ((unsigned char)cp[bo + 2]) & 0x3F;
                    }
                    else {
                        codepoint = (ch & 0x07) << 18;
                        if (bo + 1 < total_bytes)
                            codepoint |= (((unsigned char)cp[bo + 1]) & 0x3F) << 12;
                        if (bo + 2 < total_bytes)
                            codepoint |= (((unsigned char)cp[bo + 2]) & 0x3F) << 6;
                        if (bo + 3 < total_bytes)
                            codepoint |= ((unsigned char)cp[bo + 3]) & 0x3F;
                    }
                }
                if (inp->password) {
                    codepoint = '*';
                }
                n00b_plane_draw_glyph(plane,
                                      cursor_px,
                                      0,
                                      (n00b_codepoint_t)codepoint,
                                      .style = cursor_style);
            }
            else {
                // Cursor past end of text: show a reverse space.
                n00b_plane_draw_glyph(plane, cursor_px, 0, ' ', .style = cursor_style);
            }
        }
    }
}

static bool
input_handle_event(n00b_plane_t *plane, void *data, const n00b_event_t *event)
{
    n00b_input_t *inp = (n00b_input_t *)data;
    if (!inp) {
        return false;
    }

    // Mouse click: convert clicked pixel x to a codepoint index.
    if (event->type == N00B_EVENT_MOUSE) {
        if (n00b_widget_event_is_left_press(event)) {
            int32_t content_w;
            int32_t content_h;
            n00b_plane_content_size(plane, &content_w, &content_h);
            (void)content_h;

            int32_t click_px = event->mouse.x;
            if (click_px < 0) {
                click_px = 0;
            }

            // Walk codepoints from scroll_offset, accumulating pixel widths,
            // until we reach or pass the click pixel position.
            n00b_string_t *display_text = inp->text ? inp->text : r"";
            if (inp->password && display_text->codepoints > 0) {
                n00b_isize_t plen = (n00b_isize_t)display_text->codepoints;
                char        *mask = n00b_alloc_array(char, (size_t)(plen + 1));
                for (n00b_isize_t i = 0; i < plen; i++) {
                    mask[i] = '*';
                }
                mask[plen]   = '\0';
                display_text = n00b_string_from_cstr(mask);
            }

            int32_t cpw = n00b_widget_cell_px_width(plane);

            const char  *p           = display_text->data;
            n00b_isize_t total_bytes = (n00b_isize_t)display_text->u8_bytes;
            n00b_isize_t byte_pos    = 0;
            n00b_isize_t cp_idx      = 0;

            // Advance to scroll_offset.
            for (n00b_isize_t i = 0; i < inp->scroll_offset && byte_pos < total_bytes; i++) {
                unsigned char c = (unsigned char)p[byte_pos];
                if (c < 0x80)
                    byte_pos += 1;
                else if (c < 0xE0)
                    byte_pos += 2;
                else if (c < 0xF0)
                    byte_pos += 3;
                else
                    byte_pos += 4;
                cp_idx++;
            }

            // Walk codepoints, accumulating pixel widths.
            int32_t accumulated_px = 0;
            while (byte_pos < total_bytes) {
                unsigned char c    = (unsigned char)p[byte_pos];
                n00b_isize_t  clen = (c < 0x80) ? 1 : (c < 0xE0) ? 2 : (c < 0xF0) ? 3 : 4;

                n00b_string_t *one_cp
                    = n00b_unicode_str_slice_bytes(display_text,
                                                   (uint32_t)byte_pos,
                                                   (uint32_t)(byte_pos + clen));
                int32_t cp_w = n00b_plane_text_width(plane, one_cp, nullptr);
                if (cp_w <= 0) {
                    cp_w = cpw;
                }

                // Stop when the midpoint of this glyph is past the click.
                if (accumulated_px + cp_w / 2 >= click_px) {
                    break;
                }

                accumulated_px += cp_w;
                byte_pos += clen;
                cp_idx++;
            }

            n00b_isize_t text_len = input_text_len(inp);
            if (cp_idx > text_len) {
                cp_idx = text_len;
            }
            inp->cursor_pos = cp_idx;
            n00b_plane_mark_dirty(plane);
            return true;
        }
        return false;
    }

    if (event->type != N00B_EVENT_KEY) {
        return false;
    }

    uint32_t key     = event->key.key;
    bool     changed = false;

    // Printable character → insert.
    if (n00b_key_is_printable(key) && !(event->key.mods & N00B_MOD_CTRL)
        && !(event->key.mods & N00B_MOD_ALT)) {
        input_insert_char(inp, key);
        changed = true;
    }
    else if (key == N00B_KEY_BACKSPACE) {
        if (inp->cursor_pos > 0) {
            input_delete_before(inp);
            changed = true;
        }
    }
    else if (key == N00B_KEY_DELETE) {
        if (inp->cursor_pos < input_text_len(inp)) {
            input_delete_at(inp);
            changed = true;
        }
    }
    else if (key == N00B_KEY_LEFT) {
        if (inp->cursor_pos > 0) {
            inp->cursor_pos--;
            n00b_plane_mark_dirty(plane);
            return true;
        }
    }
    else if (key == N00B_KEY_RIGHT) {
        if (inp->cursor_pos < input_text_len(inp)) {
            inp->cursor_pos++;
            n00b_plane_mark_dirty(plane);
            return true;
        }
    }
    else if (key == N00B_KEY_HOME) {
        inp->cursor_pos = 0;
        n00b_plane_mark_dirty(plane);
        return true;
    }
    else if (key == N00B_KEY_END) {
        inp->cursor_pos = input_text_len(inp);
        n00b_plane_mark_dirty(plane);
        return true;
    }
    else if (key == N00B_KEY_ENTER) {
        if (inp->on_submit) {
            inp->on_submit(plane, inp->text, inp->on_submit_data);
        }
        return true;
    }
    else {
        return false;
    }

    if (changed) {
        n00b_plane_mark_dirty(plane);
        if (inp->on_change) {
            inp->on_change(plane, inp->text, inp->on_change_data);
        }
        return true;
    }

    return false;
}

static bool
input_can_focus(n00b_plane_t *plane, void *data)
{
    (void)plane;
    (void)data;
    return true;
}

static void
input_measure(n00b_plane_t *plane,
              void         *data,
              int32_t      *pref_w,
              int32_t      *pref_h,
              int32_t      *min_w,
              int32_t      *min_h)
{
    (void)data;

    int32_t lh = n00b_widget_line_px_height(plane);

    int32_t cpw = n00b_widget_cell_px_width(plane);

    *pref_w = 20 * cpw;
    *pref_h = lh;
    *min_w  = 3 * cpw;
    *min_h  = lh;
}

// -------------------------------------------------------------------
// Vtable instance
// -------------------------------------------------------------------

const n00b_widget_vtable_t n00b_widget_input = {
    .kind         = "input",
    .destroy      = input_destroy,
    .render       = input_render,
    .measure      = input_measure,
    .handle_event = input_handle_event,
    .can_focus    = input_can_focus,
};

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

n00b_plane_t *
n00b_input_new() _kargs
{
    n00b_string_t     *text           = nullptr;
    n00b_string_t     *placeholder    = nullptr;
    n00b_isize_t       max_length     = 0;
    bool               password       = false;
    n00b_input_cb_t    on_change      = nullptr;
    void              *on_change_data = nullptr;
    n00b_input_cb_t    on_submit      = nullptr;
    void              *on_submit_data = nullptr;
    int32_t            width          = 0;
    int32_t            height         = 0;
    n00b_text_style_t *style          = nullptr;
    n00b_canvas_t     *canvas         = nullptr;
    n00b_allocator_t  *allocator      = nullptr;
}
{
    // Bottom-border box with focus-color change.
    n00b_box_props_t *box     = n00b_alloc(n00b_box_props_t);
    box->border_theme         = &n00b_border_plain;
    box->borders              = N00B_BORDER_BOTTOM;
    box->border_style         = n00b_alloc(n00b_text_style_t);
    box->border_style->fg_rgb = n00b_theme_resolve_color(N00B_PAL_BORDER);

    n00b_state_style_t *ss_focus           = n00b_alloc(n00b_state_style_t);
    ss_focus->border_style                 = n00b_alloc(n00b_text_style_t);
    ss_focus->border_style->fg_rgb         = n00b_theme_resolve_color(N00B_PAL_FOCUS);
    ss_focus->border_style->bold           = N00B_TRI_YES;
    box->state_styles[N00B_WSTATE_FOCUSED] = ss_focus;

    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t,
                                         plane,
                                         .box       = box,
                                         .style     = style,
                                         .canvas    = canvas,
                                         .allocator = allocator);

    // Default width: 20 character columns scaled by char pixel width.
    if (width <= 0) {
        int32_t char_w = n00b_widget_cell_px_width(plane);
        width = 20 * char_w;
    }

    // Default height: one line.
    if (height <= 0) {
        height = n00b_widget_line_px_height(plane);
    }

    plane->width  = width;
    plane->height = height;

    n00b_input_t *inp   = n00b_alloc(n00b_input_t);
    inp->text           = text ? text : r"";
    inp->placeholder    = placeholder;
    inp->cursor_pos     = text ? (n00b_isize_t)text->codepoints : 0;
    inp->scroll_offset  = 0;
    inp->max_length     = max_length;
    inp->password       = password;
    inp->on_change      = on_change;
    inp->on_change_data = on_change_data;
    inp->on_submit      = on_submit;
    inp->on_submit_data = on_submit_data;

    n00b_widget_attach(plane, &n00b_widget_input, inp);
    n00b_plane_mark_dirty(plane);

    return plane;
}

void
n00b_input_set_text(n00b_plane_t *plane, n00b_string_t *text)
{
    n00b_input_t *inp = n00b_widget_data_if_kind(plane, &n00b_widget_input);
    if (!inp) {
        return;
    }

    inp->text          = text ? text : r"";
    inp->cursor_pos    = (n00b_isize_t)(inp->text->codepoints);
    inp->scroll_offset = 0;
    n00b_plane_mark_dirty(plane);
}

n00b_string_t *
n00b_input_get_text(n00b_plane_t *plane)
{
    n00b_input_t *inp = n00b_widget_data_if_kind(plane, &n00b_widget_input);
    if (!inp) {
        return nullptr;
    }

    return inp->text;
}

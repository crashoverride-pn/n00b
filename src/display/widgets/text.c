/*
 * Text widget: wrapped rich text with visual selection and clipboard copy.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "display/focus.h"
#include "display/mouse.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "display/widget.h"
#include "display/widgets/text.h"
#include "internal/display/scene_contracts.h"
#include "internal/display/widget_primitives.h"
#include "text/strings/string_ops.h"
#include "text/strings/string_style.h"
#include "text/strings/theme.h"
#include "text/unicode/properties.h"
#include "text/unicode/linebreak.h"
#include "text/unicode/segmentation.h"

typedef struct n00b_text_line_t {
    n00b_string_t *text;
    uint32_t      *grapheme_boundaries;
    n00b_isize_t   grapheme_count;
    int32_t        display_cols;
    int32_t        indent_cols;
} n00b_text_line_t;

typedef struct n00b_text_impl_t {
    n00b_text_t      public_state;
    n00b_text_line_t *lines;
    n00b_isize_t      line_capacity;
    int32_t           cached_content_width_px;
    bool              dragging_selection;
} n00b_text_impl_t;

static n00b_text_impl_t *
text_impl(n00b_plane_t *plane)
{
    return (n00b_text_impl_t *)n00b_widget_data_if_kind(plane, &n00b_widget_text);
}

static n00b_text_t *
text_state(n00b_plane_t *plane)
{
    n00b_text_impl_t *impl = text_impl(plane);
    return impl ? &impl->public_state : nullptr;
}

static bool
text_has_bounds(const n00b_plane_t *plane)
{
    return plane && plane->bounds.width > 0 && plane->bounds.height > 0;
}

static int32_t
text_cell_px_width(n00b_plane_t *plane)
{
    return n00b_widget_cell_px_width(plane);
}

static int32_t
text_line_px_height(n00b_plane_t *plane)
{
    return n00b_widget_line_px_height(plane);
}

static int32_t
text_fallback_width_px(n00b_plane_t *plane, int32_t cols)
{
    int32_t cell_w = text_cell_px_width(plane);
    if (cols < 1) {
        cols = 1;
    }
    return cols * cell_w;
}

static int32_t
text_wrap_cols_for_width(n00b_plane_t *plane, int32_t width_px)
{
    int32_t cols = n00b_plane_text_columns(plane, width_px, nullptr);
    return cols > 0 ? cols : 1;
}

static int32_t
text_current_content_width_px(n00b_plane_t *plane)
{
    if (!plane) {
        return 0;
    }

    if (plane->width > 0) {
        return plane->width;
    }

    if (plane->bounds.width > 0) {
        return plane->bounds.width;
    }

    return 0;
}

static void
text_release_capture_if_owned(n00b_plane_t *plane)
{
    if (plane && plane->canvas
        && n00b_canvas_get_mouse_capture_plane(plane->canvas) == plane) {
        n00b_canvas_release_mouse(plane->canvas);
    }
}

static void
text_free_lines(n00b_text_impl_t *impl)
{
    int32_t wrapped_line_count;

    if (!impl || !impl->lines) {
        return;
    }

    wrapped_line_count = impl->public_state.wrapped_line_count;
    for (int32_t i = 0; i < wrapped_line_count; i++) {
        if (impl->lines[i].grapheme_boundaries) {
            n00b_free(impl->lines[i].grapheme_boundaries);
        }
    }

    n00b_free(impl->lines);
    impl->lines = nullptr;
    impl->line_capacity = 0;
}

static void
text_invalidate_cache(n00b_text_impl_t *impl)
{
    if (!impl) {
        return;
    }

    text_free_lines(impl);
    impl->public_state.wrapped_line_count = 0;
    impl->public_state.cached_wrap_cols   = 0;
    impl->cached_content_width_px         = -1;
}

static n00b_string_t *
text_slice_preserving_styles(n00b_string_t *source, uint32_t start, uint32_t end)
{
    n00b_string_t *result;

    if (!source) {
        return nullptr;
    }

    if (start > (uint32_t)source->u8_bytes) {
        start = (uint32_t)source->u8_bytes;
    }
    if (end > (uint32_t)source->u8_bytes) {
        end = (uint32_t)source->u8_bytes;
    }
    if (end < start) {
        end = start;
    }

    result = n00b_string_from_raw(source->data + start, (int64_t)(end - start));

    auto info_opt = n00b_str_get_style_info(source);
    if (!n00b_option_is_set(info_opt)) {
        return result;
    }

    n00b_string_style_info_t *info = n00b_option_get(info_opt);
    if (info->base_style) {
        result = n00b_str_set_base_style(result, info->base_style);
    }

    for (int64_t i = 0; i < info->num_styles; i++) {
        n00b_style_record_t *rec = &info->styles[i];
        size_t               overlap_start;
        size_t               overlap_end;
        n00b_option_t(size_t) end_opt;

        if (rec->start >= end) {
            continue;
        }

        overlap_start = rec->start > start ? rec->start : start;
        overlap_end   = n00b_option_is_set(rec->end) ? n00b_option_get(rec->end) : end;
        if (overlap_end > end) {
            overlap_end = end;
        }
        if (overlap_start >= overlap_end) {
            continue;
        }

        if (!n00b_option_is_set(rec->end) && overlap_end == end) {
            end_opt = n00b_option_none(size_t);
        }
        else {
            end_opt = n00b_option_set(size_t, overlap_end - start);
        }

        result = n00b_str_add_style(result,
                                    rec->info,
                                    overlap_start - start,
                                    end_opt,
                                    .tag = rec->tag);
    }

    return result;
}

static uint32_t
text_advance_past_newline(n00b_string_t *source, uint32_t pos)
{
    if (!source || pos >= (uint32_t)source->u8_bytes) {
        return pos;
    }

    if (source->data[pos] == '\r') {
        pos++;
        if (pos < (uint32_t)source->u8_bytes && source->data[pos] == '\n') {
            pos++;
        }
        return pos;
    }

    if (source->data[pos] == '\n') {
        return pos + 1;
    }

    return pos;
}

static void
text_build_grapheme_boundaries(n00b_text_line_t *line)
{
    uint32_t                    cap;
    uint32_t                    count = 0;
    n00b_unicode_break_iter_t  *it;
    int32_t                     boundary;

    line->display_cols = line->text ? n00b_unicode_display_width(line->text) : 0;

    if (!line->text) {
        line->grapheme_boundaries = n00b_alloc_array(uint32_t, 1);
        line->grapheme_boundaries[0] = 0;
        line->grapheme_count = 0;
        return;
    }

    cap = n00b_unicode_grapheme_count(line->text) + 1;
    if (cap < 1) {
        cap = 1;
    }

    line->grapheme_boundaries = n00b_alloc_array(uint32_t, cap + 1);
    line->grapheme_boundaries[count++] = 0;

    it = n00b_unicode_grapheme_iter(line->text);
    while ((boundary = n00b_unicode_break_next(it)) >= 0) {
        line->grapheme_boundaries[count++] = (uint32_t)boundary;
    }
    n00b_unicode_break_iter_free(it);

    if (count == 0 || line->grapheme_boundaries[count - 1] != (uint32_t)line->text->u8_bytes) {
        line->grapheme_boundaries[count++] = (uint32_t)line->text->u8_bytes;
    }

    line->grapheme_count = count - 1;
}

static bool
text_reserve_lines(n00b_text_impl_t *impl,
                   n00b_isize_t      current_count,
                   n00b_isize_t      needed)
{
    n00b_text_line_t *new_lines;
    n00b_isize_t      new_cap;

    if (!impl) {
        return false;
    }

    if (needed <= impl->line_capacity) {
        return true;
    }

    new_cap = impl->line_capacity > 0 ? impl->line_capacity : 8;
    while (new_cap < needed) {
        new_cap *= 2;
    }

    new_lines = n00b_alloc_array(n00b_text_line_t, new_cap);
    if (impl->lines && current_count > 0) {
        memcpy(new_lines,
               impl->lines,
               (size_t)current_count * sizeof(n00b_text_line_t));
        n00b_free(impl->lines);
    }
    else if (impl->lines) {
        n00b_free(impl->lines);
    }

    impl->lines = new_lines;
    impl->line_capacity = new_cap;
    return true;
}

static void
text_append_line(n00b_text_impl_t *impl,
                 n00b_isize_t      *count,
                 n00b_string_t     *text,
                 int32_t            indent_cols)
{
    n00b_text_line_t *line;

    if (!impl || !count) {
        return;
    }

    if (!text_reserve_lines(impl, *count, *count + 1)) {
        return;
    }

    line = &impl->lines[*count];
    memset(line, 0, sizeof(*line));
    line->text        = text ? text : r"";
    line->indent_cols = indent_cols;
    text_build_grapheme_boundaries(line);
    (*count)++;
}

static int32_t
text_cached_wrap_cols_for_width(n00b_plane_t *plane,
                                n00b_text_impl_t *impl,
                                int32_t       content_width_px)
{
    if (!impl || !impl->public_state.wrap) {
        return 0;
    }

    if (content_width_px <= 0) {
        content_width_px = text_fallback_width_px(plane, 80);
    }

    return text_wrap_cols_for_width(plane, content_width_px);
}

static void
text_build_cache(n00b_plane_t *plane, n00b_text_impl_t *impl, int32_t content_width_px)
{
    n00b_text_t               *state;
    n00b_array_t(n00b_string_t *) hard_lines = {};
    n00b_isize_t               visual_count = 0;
    int32_t                    wrap_cols = 0;
    uint32_t                   source_pos = 0;

    if (!impl) {
        return;
    }

    text_free_lines(impl);
    state = &impl->public_state;

    if (content_width_px < 0) {
        content_width_px = 0;
    }

    impl->cached_content_width_px = content_width_px;
    wrap_cols = text_cached_wrap_cols_for_width(plane, impl, content_width_px);

    state->cached_wrap_cols = wrap_cols;

    if (!state->text || state->text->u8_bytes == 0) {
        text_append_line(impl, &visual_count, r"", 0);
        state->wrapped_line_count = (int32_t)visual_count;
        return;
    }

    hard_lines = n00b_unicode_str_split_lines(state->text);

    for (n00b_isize_t i = 0; i < hard_lines.len; i++) {
        n00b_string_t *hard_line = hard_lines.data[i];
        uint32_t       hard_start = source_pos;
        uint32_t       hard_end = hard_start + (uint32_t)hard_line->u8_bytes;

        if (!state->wrap) {
            text_append_line(impl,
                             &visual_count,
                             text_slice_preserving_styles(state->text, hard_start, hard_end),
                             0);
        }
        else {
            n00b_array_t(n00b_string_t *) wrapped =
                n00b_unicode_str_wrap(hard_line,
                                      .width = wrap_cols,
                                      .hang  = state->hang_indent_cols);

            if (wrapped.len == 0) {
                text_append_line(impl,
                                 &visual_count,
                                 text_slice_preserving_styles(state->text, hard_start, hard_end),
                                 0);
            }
            else {
                uint32_t piece_start = hard_start;

                for (n00b_isize_t j = 0; j < wrapped.len; j++) {
                    n00b_string_t *segment = wrapped.data[j];
                    uint32_t       piece_end = piece_start + (uint32_t)segment->u8_bytes;
                    int32_t        indent = j == 0 ? 0 : state->hang_indent_cols;

                    text_append_line(impl,
                                     &visual_count,
                                     text_slice_preserving_styles(state->text, piece_start, piece_end),
                                     indent);
                    piece_start = piece_end;
                }
            }

            n00b_array_free(wrapped);
        }

        source_pos = text_advance_past_newline(state->text, hard_end);
    }

    n00b_array_free(hard_lines);

    if (visual_count == 0) {
        text_append_line(impl, &visual_count, r"", 0);
    }

    state->wrapped_line_count = (int32_t)visual_count;
}

static void
text_ensure_cache_for_width(n00b_plane_t *plane, n00b_text_impl_t *impl, int32_t content_width_px)
{
    if (!impl) {
        return;
    }

    int32_t wrap_cols = text_cached_wrap_cols_for_width(plane,
                                                        impl,
                                                        content_width_px);

    if (impl->lines
        && impl->public_state.wrapped_line_count > 0
        && impl->cached_content_width_px == content_width_px
        && impl->public_state.cached_wrap_cols == wrap_cols) {
        return;
    }

    text_build_cache(plane, impl, content_width_px);
}

static void
text_ensure_cache_current_width(n00b_plane_t *plane, n00b_text_impl_t *impl)
{
    int32_t width_px = text_current_content_width_px(plane);

    if (impl && impl->public_state.wrap && width_px <= 0) {
        width_px = text_fallback_width_px(plane, 80);
    }

    text_ensure_cache_for_width(plane, impl, width_px);
}

static bool
text_normalize_selection(n00b_text_impl_t *impl,
                         int32_t          *start_line,
                         int32_t          *start_col,
                         int32_t          *end_line,
                         int32_t          *end_col)
{
    n00b_text_selection_t selection;
    int32_t               max_line;

    if (!impl || !impl->public_state.selection.active || !impl->lines
        || impl->public_state.wrapped_line_count < 1) {
        return false;
    }

    selection = impl->public_state.selection;
    max_line  = impl->public_state.wrapped_line_count - 1;

    selection.start_line = n00b_max(0, n00b_min(selection.start_line, max_line));
    selection.end_line   = n00b_max(0, n00b_min(selection.end_line, max_line));

    selection.start_col = n00b_max(0,
                                   n00b_min(selection.start_col,
                                            (int32_t)impl->lines[selection.start_line].grapheme_count));
    selection.end_col = n00b_max(0,
                                 n00b_min(selection.end_col,
                                          (int32_t)impl->lines[selection.end_line].grapheme_count));

    if (selection.start_line > selection.end_line
        || (selection.start_line == selection.end_line
            && selection.start_col > selection.end_col)) {
        int32_t swap_line = selection.start_line;
        int32_t swap_col  = selection.start_col;
        selection.start_line = selection.end_line;
        selection.start_col  = selection.end_col;
        selection.end_line   = swap_line;
        selection.end_col    = swap_col;
    }

    if (start_line) {
        *start_line = selection.start_line;
    }
    if (start_col) {
        *start_col = selection.start_col;
    }
    if (end_line) {
        *end_line = selection.end_line;
    }
    if (end_col) {
        *end_col = selection.end_col;
    }

    return true;
}

static void
text_relayout_immediately(n00b_plane_t *plane)
{
    if (!text_has_bounds(plane)) {
        return;
    }

    if (plane->canvas) {
        n00b_display_scene_run_layout(plane->canvas);
    }
    else {
        n00b_widget_layout(plane, plane->bounds);
    }
}

static int32_t
text_line_width_px(n00b_plane_t *plane, const n00b_text_line_t *line)
{
    if (!plane || !line || !line->text) {
        return 0;
    }

    return n00b_plane_text_width(plane, line->text, nullptr);
}

static int32_t
text_line_draw_x(n00b_plane_t *plane,
                 const n00b_text_line_t *line,
                 int32_t content_w)
{
    n00b_text_t   *state = text_state(plane);
    n00b_alignment_t halign = state ? (state->alignment & N00B_HORIZONTAL_MASK)
                                    : N00B_ALIGN_LEFT;
    int32_t        indent_px = line ? line->indent_cols * text_cell_px_width(plane) : 0;
    int32_t        line_width = text_line_width_px(plane, line);
    int32_t        draw_x = indent_px;
    int32_t        available = content_w - indent_px;

    if (available < 0) {
        available = 0;
    }

    if (halign == N00B_ALIGN_CENTER && line_width < available) {
        draw_x += (available - line_width) / 2;
    }
    else if (halign == N00B_ALIGN_RIGHT && line_width < available) {
        draw_x += available - line_width;
    }

    return draw_x;
}

static int32_t
text_prefix_width_px(n00b_plane_t *plane, const n00b_text_line_t *line, int32_t slot)
{
    uint32_t       end_byte;
    n00b_string_t *prefix;

    if (!plane || !line || !line->text || slot <= 0) {
        return 0;
    }

    if (slot >= (int32_t)line->grapheme_count) {
        return text_line_width_px(plane, line);
    }

    end_byte = line->grapheme_boundaries[slot];
    prefix   = text_slice_preserving_styles(line->text, 0, end_byte);
    return n00b_plane_text_width(plane, prefix, nullptr);
}

static int32_t
text_line_index_from_local_y(n00b_plane_t *plane, n00b_text_impl_t *impl, int32_t local_y)
{
    int32_t line_h;
    int32_t line;

    if (!impl || impl->public_state.wrapped_line_count < 1) {
        return 0;
    }

    line_h = text_line_px_height(plane);
    if (line_h < 1) {
        line_h = 1;
    }

    if (local_y <= 0) {
        return 0;
    }

    line = local_y / line_h;
    if (line >= impl->public_state.wrapped_line_count) {
        line = impl->public_state.wrapped_line_count - 1;
    }
    return line;
}

static int32_t
text_slot_from_local_x(n00b_plane_t      *plane,
                       const n00b_text_line_t *line,
                       int32_t            content_w,
                       int32_t            local_x)
{
    int32_t line_x;
    int32_t line_width;
    int32_t target;
    int32_t prev_width = 0;

    if (!line) {
        return 0;
    }

    line_x     = text_line_draw_x(plane, line, content_w);
    line_width = text_line_width_px(plane, line);

    if (local_x <= line_x) {
        return 0;
    }

    if (local_x >= line_x + line_width) {
        return (int32_t)line->grapheme_count;
    }

    target = local_x - line_x;
    for (int32_t slot = 1; slot <= (int32_t)line->grapheme_count; slot++) {
        int32_t next_width = text_prefix_width_px(plane, line, slot);
        int32_t midpoint   = prev_width + (next_width - prev_width) / 2;

        if (target < midpoint) {
            return slot - 1;
        }
        if (target < next_width) {
            return slot;
        }

        prev_width = next_width;
    }

    return (int32_t)line->grapheme_count;
}

static void
text_update_selection_tail_from_mouse(n00b_plane_t       *plane,
                                      n00b_text_impl_t   *impl,
                                      const n00b_event_t *event)
{
    int32_t content_w;
    int32_t content_h;
    int32_t line_ix;
    int32_t slot;

    if (!plane || !impl || !event || event->type != N00B_EVENT_MOUSE) {
        return;
    }

    text_ensure_cache_current_width(plane, impl);
    if (!impl->lines || impl->public_state.wrapped_line_count < 1) {
        return;
    }

    n00b_plane_content_size(plane, &content_w, &content_h);
    line_ix = text_line_index_from_local_y(plane, impl, event->mouse.y);
    slot    = text_slot_from_local_x(plane, &impl->lines[line_ix], content_w, event->mouse.x);

    impl->public_state.selection.end_line = line_ix;
    impl->public_state.selection.end_col  = slot;
    n00b_plane_mark_dirty(plane);
}

static void
text_destroy(n00b_plane_t *plane, void *data)
{
    n00b_text_impl_t *impl = data;

    text_release_capture_if_owned(plane);
    if (impl) {
        text_invalidate_cache(impl);
        n00b_free(impl);
    }
}

static void
text_cancel_mouse_capture(n00b_plane_t *plane, void *data)
{
    n00b_text_impl_t *impl = data;

    (void)plane;

    if (!impl) {
        return;
    }

    impl->dragging_selection = false;
}

static n00b_text_style_t
text_selection_overlay_style(void)
{
    return (n00b_text_style_t){
        .bold             = N00B_TRI_UNSPECIFIED,
        .italic           = N00B_TRI_UNSPECIFIED,
        .underline        = N00B_TRI_UNSPECIFIED,
        .double_underline = N00B_TRI_UNSPECIFIED,
        .strikethrough    = N00B_TRI_UNSPECIFIED,
        .reverse          = N00B_TRI_UNSPECIFIED,
        .dim              = N00B_TRI_UNSPECIFIED,
        .blink            = N00B_TRI_UNSPECIFIED,
        .text_case        = N00B_TEXT_CASE_NONE,
        .font_hint        = N00B_FONT_DEFAULT,
        .font_index       = -1,
        .fg_palette_ix    = N00B_PAL_SELECTION_FG,
        .bg_palette_ix    = N00B_PAL_SELECTION_BG,
        .fg_rgb           = n00b_theme_resolve_color(N00B_PAL_SELECTION_FG),
        .bg_rgb           = n00b_theme_resolve_color(N00B_PAL_SELECTION_BG),
        .font_size        = 0,
    };
}

static void
text_render(n00b_plane_t *plane, void *data)
{
    n00b_text_impl_t  *impl = data;
    n00b_text_style_t  selection_style = text_selection_overlay_style();
    int32_t            content_w;
    int32_t            content_h;
    int32_t            line_h;
    int32_t            start_line = 0;
    int32_t            start_col = 0;
    int32_t            end_line = 0;
    int32_t            end_col = 0;
    bool               has_selection;

    if (!plane || !impl) {
        return;
    }

    n00b_plane_clear(plane);
    n00b_plane_content_size(plane, &content_w, &content_h);
    if (content_w <= 0 || content_h <= 0) {
        return;
    }

    text_ensure_cache_for_width(plane, impl, content_w);
    if (!impl->lines || impl->public_state.wrapped_line_count < 1) {
        return;
    }

    line_h = text_line_px_height(plane);
    if (line_h < 1) {
        line_h = 1;
    }

    has_selection = text_normalize_selection(impl,
                                             &start_line,
                                             &start_col,
                                             &end_line,
                                             &end_col)
                 && (start_line != end_line || start_col != end_col);

    for (int32_t line_ix = 0, y = 0;
         line_ix < impl->public_state.wrapped_line_count && y < content_h;
         line_ix++, y += line_h) {
        n00b_text_line_t *line = &impl->lines[line_ix];
        n00b_string_t    *draw_text = line->text;

        if (has_selection && line_ix >= start_line && line_ix <= end_line) {
            int32_t start_slot = line_ix == start_line ? start_col : 0;
            int32_t end_slot = line_ix == end_line ? end_col : (int32_t)line->grapheme_count;
            uint32_t start_byte = line->grapheme_boundaries[start_slot];
            uint32_t end_byte   = line->grapheme_boundaries[end_slot];

            if (start_byte < end_byte) {
                n00b_option_t(size_t) end_opt = end_byte == (uint32_t)line->text->u8_bytes
                                              ? n00b_option_none(size_t)
                                              : n00b_option_set(size_t, end_byte);
                draw_text = n00b_str_add_style(line->text,
                                               &selection_style,
                                               start_byte,
                                               end_opt);
            }
        }

        n00b_plane_draw_text(plane,
                             text_line_draw_x(plane, line, content_w),
                             y,
                             draw_text);
    }
}

static void
text_measure(n00b_plane_t *plane, void *data,
             int32_t *pref_w, int32_t *pref_h,
             int32_t *min_w, int32_t *min_h)
{
    n00b_text_impl_t *impl = data;
    n00b_text_t      *state = impl ? &impl->public_state : nullptr;
    int32_t           width_px;
    int32_t           line_h;
    int32_t           cell_w;
    int32_t           max_width = 1;

    if (!plane || !impl) {
        *pref_w = *pref_h = *min_w = *min_h = 0;
        return;
    }

    if (state->wrap) {
        width_px = plane->width > 0 ? plane->width : plane->bounds.width;
        if (width_px <= 0) {
            width_px = text_fallback_width_px(plane, 80);
        }
    }
    else {
        width_px = 0;
    }

    text_ensure_cache_for_width(plane, impl, width_px);

    line_h = text_line_px_height(plane);
    cell_w = text_cell_px_width(plane);

    for (int32_t i = 0; i < state->wrapped_line_count; i++) {
        int32_t line_width = text_line_width_px(plane, &impl->lines[i]);
        int32_t total_width = line_width + impl->lines[i].indent_cols * cell_w;

        if (total_width > max_width) {
            max_width = total_width;
        }
    }

    *pref_w = n00b_max(max_width, 1);
    *pref_h = n00b_max(state->wrapped_line_count, 1) * line_h;

    // Athens falls back to one text cell when width-sensitive widgets
    // are measured before an available width exists.
    *min_w = cell_w;
    *min_h = line_h;
}

static bool
text_handle_event(n00b_plane_t *plane, void *data, const n00b_event_t *event)
{
    n00b_text_impl_t *impl = data;

    if (!plane || !impl || !event) {
        return false;
    }

    if (event->type == N00B_EVENT_KEY) {
        if (event->key.key == 'c'
            && (event->key.mods & N00B_MOD_CTRL)
            && impl->public_state.selectable
            && n00b_text_has_selection(plane)) {
            return n00b_text_copy_selection(plane);
        }

        return false;
    }

    if (event->type != N00B_EVENT_MOUSE || !impl->public_state.selectable) {
        return false;
    }

    if (event->mouse.button == N00B_MOUSE_LEFT
        && event->mouse.action == N00B_MOUSE_PRESS) {
        text_ensure_cache_current_width(plane, impl);
        if (!impl->lines || impl->public_state.wrapped_line_count < 1) {
            return true;
        }

        impl->public_state.selection.active = true;
        impl->dragging_selection            = true;
        text_update_selection_tail_from_mouse(plane, impl, event);
        impl->public_state.selection.start_line = impl->public_state.selection.end_line;
        impl->public_state.selection.start_col  = impl->public_state.selection.end_col;
        if (plane->canvas) {
            n00b_canvas_capture_mouse(plane->canvas, plane);
        }
        return true;
    }

    if ((event->mouse.action == N00B_MOUSE_DRAG
         || event->mouse.action == N00B_MOUSE_MOVE)
        && impl->dragging_selection) {
        text_update_selection_tail_from_mouse(plane, impl, event);
        return true;
    }

    if (event->mouse.button == N00B_MOUSE_LEFT
        && event->mouse.action == N00B_MOUSE_RELEASE
        && impl->dragging_selection) {
        text_update_selection_tail_from_mouse(plane, impl, event);
        impl->dragging_selection = false;
        text_release_capture_if_owned(plane);
        if (impl->public_state.copy_on_release && n00b_text_has_selection(plane)) {
            (void)n00b_text_copy_selection(plane);
        }
        return true;
    }

    return false;
}

static bool
text_can_focus(n00b_plane_t *plane, void *data)
{
    (void)plane;
    return data ? ((n00b_text_impl_t *)data)->public_state.selectable : false;
}

static void
text_layout(n00b_plane_t *plane, void *data, n00b_rect_t bounds)
{
    n00b_text_impl_t *impl = data;

    if (!plane || !impl) {
        return;
    }

    text_ensure_cache_for_width(plane, impl, bounds.width);
}

const n00b_widget_vtable_t n00b_widget_text = {
    .kind                 = "text",
    .destroy              = text_destroy,
    .render               = text_render,
    .measure              = text_measure,
    .handle_event         = text_handle_event,
    .can_focus            = text_can_focus,
    .cancel_mouse_capture = text_cancel_mouse_capture,
    .layout               = text_layout,
};

n00b_plane_t *
n00b_text_new(n00b_string_t *text) _kargs {
    n00b_alignment_t  alignment        = N00B_ALIGN_LEFT;
    bool              wrap             = true;
    int32_t           hang_indent_cols = 0;
    bool              selectable       = false;
    bool              copy_on_release  = true;
    n00b_canvas_t    *canvas           = nullptr;
    n00b_allocator_t *allocator        = nullptr;
}
{
    n00b_plane_t     *plane = n00b_new_kargs(n00b_plane_t, plane,
                                             .canvas    = canvas,
                                             .allocator = allocator);
    n00b_text_impl_t *impl  = n00b_alloc(n00b_text_impl_t);

    memset(impl, 0, sizeof(*impl));
    impl->public_state.text             = text;
    impl->public_state.alignment        = alignment;
    impl->public_state.wrap             = wrap;
    impl->public_state.hang_indent_cols = hang_indent_cols < 0 ? 0 : hang_indent_cols;
    impl->public_state.selectable       = selectable;
    impl->public_state.copy_on_release  = copy_on_release;
    impl->cached_content_width_px       = -1;

    n00b_widget_attach(plane, &n00b_widget_text, impl);
    n00b_plane_mark_dirty(plane);
    return plane;
}

void
n00b_text_set_text(n00b_plane_t *text_plane, n00b_string_t *text)
{
    n00b_text_impl_t *impl = text_impl(text_plane);

    if (!impl) {
        return;
    }

    impl->public_state.text             = text;
    impl->public_state.selection.active = false;
    impl->dragging_selection            = false;
    text_invalidate_cache(impl);
    text_release_capture_if_owned(text_plane);
    n00b_plane_mark_dirty(text_plane);
    text_relayout_immediately(text_plane);
}

n00b_string_t *
n00b_text_get_text(n00b_plane_t *text_plane)
{
    n00b_text_t *state = text_state(text_plane);
    return state ? state->text : nullptr;
}

void
n00b_text_set_alignment(n00b_plane_t *text_plane, n00b_alignment_t alignment)
{
    n00b_text_t *state = text_state(text_plane);

    if (!state) {
        return;
    }

    state->alignment = alignment;
    n00b_plane_mark_dirty(text_plane);
}

void
n00b_text_set_hang_indent(n00b_plane_t *text_plane, int32_t hang_indent_cols)
{
    n00b_text_impl_t *impl = text_impl(text_plane);

    if (!impl) {
        return;
    }

    impl->public_state.hang_indent_cols = hang_indent_cols < 0 ? 0 : hang_indent_cols;
    text_invalidate_cache(impl);
    n00b_plane_mark_dirty(text_plane);
    text_relayout_immediately(text_plane);
}

void
n00b_text_set_selectable(n00b_plane_t *text_plane, bool selectable)
{
    n00b_text_impl_t *impl = text_impl(text_plane);

    if (!impl) {
        return;
    }

    impl->public_state.selectable = selectable;
    if (!selectable) {
        impl->public_state.selection.active = false;
        impl->dragging_selection            = false;
        text_release_capture_if_owned(text_plane);
    }

    if (text_plane->canvas && text_plane->canvas->focus) {
        n00b_focus_mgr_rebuild(text_plane->canvas->focus);
    }

    n00b_plane_mark_dirty(text_plane);
}

bool
n00b_text_has_selection(n00b_plane_t *text_plane)
{
    n00b_text_impl_t *impl = text_impl(text_plane);
    int32_t           start_line;
    int32_t           start_col;
    int32_t           end_line;
    int32_t           end_col;

    if (!impl) {
        return false;
    }

    text_ensure_cache_current_width(text_plane, impl);
    if (!text_normalize_selection(impl, &start_line, &start_col, &end_line, &end_col)) {
        return false;
    }

    return start_line != end_line || start_col != end_col;
}

void
n00b_text_clear_selection(n00b_plane_t *text_plane)
{
    n00b_text_t *state = text_state(text_plane);

    if (!state) {
        return;
    }

    state->selection.active = false;
    n00b_plane_mark_dirty(text_plane);
}

n00b_string_t *
n00b_text_get_selection(n00b_plane_t *text_plane)
{
    n00b_text_impl_t *impl = text_impl(text_plane);
    int32_t           start_line;
    int32_t           start_col;
    int32_t           end_line;
    int32_t           end_col;
    n00b_array_t(n00b_string_t *) parts;
    n00b_string_t    *selection;

    if (!impl) {
        return nullptr;
    }

    text_ensure_cache_current_width(text_plane, impl);
    if (!text_normalize_selection(impl, &start_line, &start_col, &end_line, &end_col)) {
        return nullptr;
    }
    if (start_line == end_line && start_col == end_col) {
        return nullptr;
    }

    parts = n00b_array_new(n00b_string_t *, (n00b_isize_t)(end_line - start_line + 1));
    parts.len = (n00b_isize_t)(end_line - start_line + 1);

    for (int32_t line_ix = start_line; line_ix <= end_line; line_ix++) {
        n00b_text_line_t *line = &impl->lines[line_ix];
        int32_t           line_start = line_ix == start_line ? start_col : 0;
        int32_t           line_end = line_ix == end_line ? end_col : (int32_t)line->grapheme_count;
        uint32_t          start_byte = line->grapheme_boundaries[line_start];
        uint32_t          end_byte = line->grapheme_boundaries[line_end];

        parts.data[line_ix - start_line] =
            n00b_unicode_str_slice_bytes(line->text, start_byte, end_byte);
    }

    selection = n00b_unicode_str_join(r"\n", parts);
    n00b_array_free(parts);
    return selection;
}

bool
n00b_text_copy_selection(n00b_plane_t *text_plane)
{
    n00b_string_t *selection;

    if (!text_plane) {
        return false;
    }

    selection = n00b_text_get_selection(text_plane);
    if (!selection || !text_plane->canvas) {
        return false;
    }

    return n00b_canvas_clipboard_copy(text_plane->canvas, selection);
}

int32_t
n00b_text_get_wrapped_line_count(n00b_plane_t *text_plane)
{
    n00b_text_impl_t *impl = text_impl(text_plane);

    if (!impl) {
        return 0;
    }

    text_ensure_cache_current_width(text_plane, impl);
    return impl->public_state.wrapped_line_count;
}

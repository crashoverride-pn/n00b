#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "internal/display/table_text_primitives.h"
#include "text/strings/string_ops.h"
#include "text/unicode/properties.h"

static int32_t
longest_line_width(n00b_string_t *text)
{
    if (!text || text->u8_bytes == 0) {
        return 0;
    }

    n00b_array_t(n00b_string_t *) lines = n00b_unicode_str_split_lines(text);
    int32_t max_w = 0;

    n00b_array_foreach(lines, lp) {
        int32_t w = n00b_unicode_display_width(*lp);
        if (w > max_w) {
            max_w = w;
        }
    }

    n00b_array_free(lines);
    return max_w;
}

static int32_t
longest_word_width(n00b_string_t *text)
{
    if (!text || text->u8_bytes == 0) {
        return 0;
    }

    n00b_string_t *space = n00b_string_from_raw(" ", 1);
    n00b_array_t(n00b_string_t *) lines = n00b_unicode_str_split_lines(text);
    int32_t max_w = 0;

    n00b_array_foreach(lines, lp) {
        n00b_array_t(n00b_string_t *) words =
            n00b_unicode_str_split(*lp, space);

        n00b_array_foreach(words, wp) {
            int32_t w = n00b_unicode_display_width(*wp);
            if (w > max_w) {
                max_w = w;
            }
        }

        n00b_array_free(words);
    }

    n00b_array_free(lines);
    return max_w;
}

n00b_table_text_metrics_t
n00b_table_text_measure(n00b_string_t *text)
{
    return (n00b_table_text_metrics_t){
        .longest_line = longest_line_width(text),
        .longest_word = longest_word_width(text),
    };
}

n00b_array_t(n00b_string_t *)
n00b_table_text_lines_for_width(n00b_string_t *text,
                                 int32_t width,
    bool wrap)
{
    if (!text || text->u8_bytes == 0) {
        n00b_array_t(n00b_string_t *) empty = {};
        return empty;
    }

    if (width < 1) {
        width = 1;
    }

    if (wrap) {
        // Hard-split on embedded newlines FIRST, then soft-wrap each hard line
        // to width. n00b_unicode_str_wrap does NOT treat '\n' as a hard break,
        // so wrapping the raw text would leave newlines inside the returned
        // lines and corrupt the per-cell plane render (missing borders / shifted
        // columns). Mirrors the widget text path (display/widgets/text.c).
        n00b_array_t(n00b_string_t *) hard = n00b_unicode_str_split_lines(text);
        n00b_isize_t n_hard = n00b_array_len(hard);
        if (n_hard <= 1) {
            // No embedded hard break: wrap directly (common case).
            n00b_array_free(hard);
            return n00b_unicode_str_wrap(text, .width = width);
        }

        // Pass 1: count the soft lines each hard line wraps to (a blank hard
        // line still occupies one visual line).
        int64_t total = 0;
        for (n00b_isize_t i = 0; i < n_hard; i++) {
            n00b_array_t(n00b_string_t *) w =
                n00b_unicode_str_wrap(n00b_array_get(hard, i), .width = width);
            n00b_isize_t wl = n00b_array_len(w);
            total += wl > 0 ? (int64_t)wl : 1;
            n00b_array_free(w);
        }

        // Pass 2: emit the wrapped lines in order.
        n00b_array_t(n00b_string_t *) out =
            n00b_array_new(n00b_string_t *, (n00b_isize_t)total);
        int64_t oi = 0;
        for (n00b_isize_t i = 0; i < n_hard; i++) {
            n00b_array_t(n00b_string_t *) w =
                n00b_unicode_str_wrap(n00b_array_get(hard, i), .width = width);
            n00b_isize_t wl = n00b_array_len(w);
            if (wl == 0) {
                out.data[oi++] = r"";
            }
            else {
                for (n00b_isize_t j = 0; j < wl; j++) {
                    out.data[oi++] = n00b_array_get(w, j);
                }
            }
            n00b_array_free(w);
        }
        out.len = total;
        n00b_array_free(hard);
        return out;
    }

    n00b_array_t(n00b_string_t *) hard_lines = n00b_unicode_str_split_lines(text);
    n00b_isize_t n_hard = n00b_array_len(hard_lines);
    size_t cap = n_hard > 0 ? (size_t)n_hard : 1;

    n00b_array_t(n00b_string_t *) lines = {};
    lines.cap = cap;
    lines.data = n00b_alloc_array(n00b_string_t *, cap);

    for (n00b_isize_t i = 0; i < n_hard; i++) {
        n00b_string_t *raw = n00b_array_get(hard_lines, i);
        n00b_string_t *trunc = n00b_unicode_str_truncate(raw, width);
        n00b_array_set(lines, i, trunc);
    }

    n00b_array_free(hard_lines);
    return lines;
}

n00b_string_t *
n00b_table_text_align_line(n00b_string_t *line,
                            int32_t width,
                            n00b_alignment_t alignment)
{
    if (!line) {
        line = r"";
    }

    if (width < 1) {
        width = 1;
    }

    if (alignment & N00B_ALIGN_CENTER) {
        return n00b_unicode_str_center(line, width);
    }

    if (alignment & N00B_ALIGN_RIGHT) {
        return n00b_unicode_str_pad_left(line, width);
    }

    return n00b_unicode_str_pad_right(line, width);
}

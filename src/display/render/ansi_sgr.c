#include <stdio.h>

#include "n00b.h"
#include "text/strings/theme.h"
#include "internal/display/ansi_sgr.h"

void
n00b_display_ansi_emit_reset(n00b_ansi_emit_fn emit, void *ctx)
{
    if (!emit) {
        return;
    }
    /* NO_COLOR: emit no SGR at all (there is nothing to reset since no style
     * was ever emitted), keeping terminal output pure plain text. */
    if (!n00b_terminal_color_enabled()) {
        return;
    }
    emit(ctx, "\033[0m", 4);
}

void
n00b_display_ansi_emit_style(const n00b_text_style_t *style,
                              n00b_ansi_emit_fn         emit,
                              void                     *ctx)
{
    if (!emit) {
        return;
    }

    /* NO_COLOR (https://no-color.org): skip all style application to the
     * terminal so output is unstyled plain text. */
    if (!n00b_terminal_color_enabled()) {
        return;
    }

    if (!style) {
        n00b_display_ansi_emit_reset(emit, ctx);
        return;
    }

    emit(ctx, "\033[0", 3);

    if (style->bold == N00B_TRI_YES) {
        emit(ctx, ";1", 2);
    }
    if (style->dim == N00B_TRI_YES) {
        emit(ctx, ";2", 2);
    }
    if (style->italic == N00B_TRI_YES) {
        emit(ctx, ";3", 2);
    }
    if (style->underline == N00B_TRI_YES) {
        emit(ctx, ";4", 2);
    }
    if (style->blink == N00B_TRI_YES) {
        emit(ctx, ";5", 2);
    }
    if (style->reverse == N00B_TRI_YES) {
        emit(ctx, ";7", 2);
    }
    if (style->strikethrough == N00B_TRI_YES) {
        emit(ctx, ";9", 2);
    }
    if (style->double_underline == N00B_TRI_YES) {
        emit(ctx, ";21", 3);
    }

    if (n00b_color_is_set(style->fg_rgb)) {
        int  rgb = n00b_color_rgb(style->fg_rgb);
        char buf[32];
        int  len = snprintf(buf,
                            sizeof(buf),
                            ";38;2;%d;%d;%d",
                            (rgb >> 16) & 0xFF,
                            (rgb >> 8) & 0xFF,
                            rgb & 0xFF);
        if (len > 0) {
            emit(ctx, buf, (size_t)len);
        }
    }
    else if (style->fg_palette_ix >= 0 && style->fg_palette_ix < N00B_PAL_SIZE) {
        n00b_color_t resolved = n00b_theme_resolve_color(style->fg_palette_ix);
        if (n00b_color_is_set(resolved)) {
            int  rgb = n00b_color_rgb(resolved);
            char buf[32];
            int  len = snprintf(buf,
                                sizeof(buf),
                                ";38;2;%d;%d;%d",
                                (rgb >> 16) & 0xFF,
                                (rgb >> 8) & 0xFF,
                                rgb & 0xFF);
            if (len > 0) {
                emit(ctx, buf, (size_t)len);
            }
        }
    }

    if (n00b_color_is_set(style->bg_rgb)) {
        int  rgb = n00b_color_rgb(style->bg_rgb);
        char buf[32];
        int  len = snprintf(buf,
                            sizeof(buf),
                            ";48;2;%d;%d;%d",
                            (rgb >> 16) & 0xFF,
                            (rgb >> 8) & 0xFF,
                            rgb & 0xFF);
        if (len > 0) {
            emit(ctx, buf, (size_t)len);
        }
    }
    else if (style->bg_palette_ix >= 0 && style->bg_palette_ix < N00B_PAL_SIZE) {
        n00b_color_t resolved = n00b_theme_resolve_color(style->bg_palette_ix);
        if (n00b_color_is_set(resolved)) {
            int  rgb = n00b_color_rgb(resolved);
            char buf[32];
            int  len = snprintf(buf,
                                sizeof(buf),
                                ";48;2;%d;%d;%d",
                                (rgb >> 16) & 0xFF,
                                (rgb >> 8) & 0xFF,
                                rgb & 0xFF);
            if (len > 0) {
                emit(ctx, buf, (size_t)len);
            }
        }
    }

    emit(ctx, "m", 1);
}

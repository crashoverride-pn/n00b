/*
 * Dumb terminal renderer backend.
 *
 * Outputs line-by-line plain text with no cursor movement, no colors,
 * and no escape sequences.  Content is width-wrapped at the output
 * column count.  Suitable for pipe output or terminals with no
 * capabilities.
 */

#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#define n00b_dumb_write(fd, data, len) _write((fd), (data), (unsigned int)(len))
#else
#include <unistd.h>
#define n00b_dumb_write(fd, data, len) write((fd), (data), (len))
#endif
#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "display/render/backend.h"
#include "display/render/composite.h"

// -------------------------------------------------------------------
// Dumb context
// -------------------------------------------------------------------

typedef struct {
    int          fd;
    n00b_isize_t rows;
    n00b_isize_t cols;

    // Persistent compositing grid.
    n00b_rcell_t *comp_grid;
    n00b_isize_t  comp_grid_rows;
    n00b_isize_t  comp_grid_cols;
    n00b_composite_style_pool_t style_pool;
} dumb_ctx_t;

#define DUMB_DEFAULT_ROWS 25
#define DUMB_DEFAULT_COLS 80

// -------------------------------------------------------------------
// Vtable implementation
// -------------------------------------------------------------------

static void *
dumb_init(n00b_conduit_topic_t(n00b_buffer_t *) *output)
{
    (void)output;
    dumb_ctx_t *ctx = n00b_alloc_with_opts(dumb_ctx_t,
                                          &(n00b_alloc_opts_t){.no_scan = true});
    ctx->fd   = STDOUT_FILENO;
    ctx->rows = DUMB_DEFAULT_ROWS;
    ctx->cols = DUMB_DEFAULT_COLS;
    return ctx;
}

static void
dumb_destroy(void *vctx)
{
    dumb_ctx_t *ctx = vctx;
    if (ctx) {
        if (ctx->comp_grid) {
            n00b_free(ctx->comp_grid);
        }
        n00b_composite_style_pool_destroy(&ctx->style_pool);
        n00b_free(ctx);
    }
}

static n00b_render_cap_t
dumb_capabilities(void *vctx)
{
    (void)vctx;
    return N00B_RCAP_NONE;
}

static n00b_render_size_t
dumb_get_size(void *vctx)
{
    dumb_ctx_t *ctx = vctx;
    return (n00b_render_size_t){
        .rows = ctx->rows,
        .cols = ctx->cols,
    };
}

static void
dumb_render_frame(void *vctx, n00b_rcell_t *cells,
                  n00b_isize_t rows, n00b_isize_t cols,
                  n00b_rcell_t *prev_cells)
{
    (void)prev_cells;
    dumb_ctx_t *ctx = vctx;

    for (n00b_isize_t r = 0; r < rows; r++) {
        // Find last non-space column.
        n00b_isize_t last = 0;
        for (n00b_isize_t c = 0; c < cols; c++) {
            n00b_rcell_t *cell = &cells[r * cols + c];
            if ((cell->flags & N00B_CELL_OCCUPIED)
                && !(cell->flags & N00B_CELL_WIDE_CONT)
                && !(cell->grapheme_len == 1 && cell->grapheme[0] == ' ')) {
                last = c + 1;
            }
        }

        // Emit the line.
        for (n00b_isize_t c = 0; c < last; c++) {
            n00b_rcell_t *cell = &cells[r * cols + c];
            if (cell->flags & N00B_CELL_WIDE_CONT) {
                continue;
            }
            if (cell->flags & N00B_CELL_OCCUPIED) {
                n00b_dumb_write(ctx->fd, cell->grapheme, cell->grapheme_len);
            }
            else {
                n00b_dumb_write(ctx->fd, " ", 1);
            }
        }

        n00b_dumb_write(ctx->fd, "\n", 1);
    }
}

static void
dumb_flush(void *vctx)
{
    (void)vctx;
}

static bool
dumb_clipboard_copy(void *vctx, const char *utf8, size_t len)
{
    (void)vctx;
    (void)utf8;
    (void)len;
    return false;
}

// -------------------------------------------------------------------
// Plane-based rendering
// -------------------------------------------------------------------

static void
dumb_render_planes(void                         *vctx,
                   const n00b_composite_entry_t *entries,
                   n00b_isize_t                  count,
                   n00b_isize_t                  total_rows,
                   n00b_isize_t                  total_cols,
                   n00b_text_style_t            *default_style,
                   n00b_render_cap_t             caps)
{
    dumb_ctx_t *ctx = vctx;

    if (total_rows != ctx->comp_grid_rows
        || total_cols != ctx->comp_grid_cols) {
        if (ctx->comp_grid) {
            n00b_free(ctx->comp_grid);
        }
        size_t total = (size_t)total_rows * total_cols;
        ctx->comp_grid = n00b_alloc_array(n00b_rcell_t, total);
        ctx->comp_grid_rows = total_rows;
        ctx->comp_grid_cols = total_cols;
    }

    n00b_composite_style_pool_clear(&ctx->style_pool);
    n00b_composite_commands_to_grid(entries, count, ctx->comp_grid,
                                     total_rows, total_cols,
                                     1, 1,
                                     default_style, caps,
                                     &ctx->style_pool);

    dumb_render_frame(vctx, ctx->comp_grid, total_rows, total_cols, nullptr);
}

// -------------------------------------------------------------------
// Public vtable
// -------------------------------------------------------------------

const n00b_renderer_vtable_t n00b_renderer_dumb = {
    .name          = "dumb",
    .version       = N00B_RENDERER_ABI_VERSION,
    .init          = dumb_init,
    .destroy       = dumb_destroy,
    .capabilities  = dumb_capabilities,
    .get_size      = dumb_get_size,
    .render_frame  = dumb_render_frame,
    .flush         = dumb_flush,
    .render_planes = dumb_render_planes,
    .clipboard_copy = dumb_clipboard_copy,
};

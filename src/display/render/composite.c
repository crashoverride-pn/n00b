/*
 * Compositing pipeline: flatten, ordered composite, degrade.
 */

#include <limits.h>
#include "n00b.h"
#include "core/alloc.h"
#include "display/render/composite.h"
#include "display/render/draw_cmd.h"
#include "display/render/box.h"
#include "display/widgets/zstack.h"
#include "internal/display/plane_geometry.h"
#include "text/strings/string_style.h"
#include "text/unicode/properties.h"

// -------------------------------------------------------------------
// Internal: flatten recursion
// -------------------------------------------------------------------

typedef struct {
    n00b_plane_t *plane;
    n00b_plane_t *stack;
    int32_t       abs_z;
    uint32_t      order;
    uint32_t      index;
} layer_marker_t;

typedef struct {
    n00b_composite_entry_t entry;
    layer_marker_t        *layers;
    size_t                 layer_count;
} flatten_record_t;

typedef struct {
    flatten_record_t *records;
    n00b_isize_t      count;
    n00b_isize_t      capacity;
    layer_marker_t   *layer_path;
    size_t            layer_count;
    size_t            layer_capacity;
} flatten_ctx_t;

static void
flatten_grow(flatten_ctx_t *ctx)
{
    n00b_isize_t new_cap = ctx->capacity ? ctx->capacity * 2 : 16;
    flatten_record_t *new_arr = n00b_alloc_array_with_opts(
        flatten_record_t, new_cap,
        &(n00b_alloc_opts_t){.no_scan = true});

    if (ctx->records) {
        memcpy(new_arr, ctx->records, ctx->count * sizeof(flatten_record_t));
        n00b_free(ctx->records);
    }

    ctx->records  = new_arr;
    ctx->capacity = new_cap;
}

static void
flatten_path_grow(flatten_ctx_t *ctx)
{
    size_t new_cap = ctx->layer_capacity ? ctx->layer_capacity * 2 : 4;
    layer_marker_t *new_arr = n00b_alloc_array_with_opts(
        layer_marker_t, new_cap,
        &(n00b_alloc_opts_t){.no_scan = true});

    if (ctx->layer_path) {
        memcpy(new_arr,
               ctx->layer_path,
               ctx->layer_count * sizeof(layer_marker_t));
        n00b_free(ctx->layer_path);
    }

    ctx->layer_path = new_arr;
    ctx->layer_capacity = new_cap;
}

static void
flatten_path_push(flatten_ctx_t *ctx, layer_marker_t marker)
{
    if (ctx->layer_count >= ctx->layer_capacity) {
        flatten_path_grow(ctx);
    }

    ctx->layer_path[ctx->layer_count++] = marker;
}

static void
flatten_path_pop(flatten_ctx_t *ctx)
{
    if (ctx->layer_count > 0) {
        ctx->layer_count--;
    }
}

static bool
plane_is_zstack(const n00b_plane_t *plane)
{
    return plane && plane->widget_vtable == &n00b_widget_zstack;
}

static uint32_t
plane_child_index(n00b_plane_t *parent, n00b_plane_t *child)
{
    if (!parent || !child || !parent->children.data) {
        return 0;
    }

    for (size_t i = 0; i < parent->children.len; i++) {
        if (parent->children.data[i] == child) {
            return (uint32_t)i;
        }
    }

    return 0;
}

static inline int32_t
imax32(int32_t a, int32_t b) { return a > b ? a : b; }

static inline int32_t
imin32(int32_t a, int32_t b) { return a < b ? a : b; }

static void
composite_style_pool_grow(n00b_composite_style_pool_t *pool)
{
    n00b_isize_t       new_cap = pool->capacity > 0 ? pool->capacity * 2 : 8;
    n00b_text_style_t **new_items = n00b_alloc_array(n00b_text_style_t *, new_cap);

    if (pool->items && pool->count > 0) {
        memcpy(new_items,
               pool->items,
               (size_t)pool->count * sizeof(n00b_text_style_t *));
        n00b_free(pool->items);
    }
    else if (pool->items) {
        n00b_free(pool->items);
    }

    pool->items    = new_items;
    pool->capacity = new_cap;
}

void
n00b_composite_style_pool_clear(n00b_composite_style_pool_t *pool)
{
    if (!pool) {
        return;
    }

    for (n00b_isize_t i = 0; i < pool->count; i++) {
        if (pool->items[i]) {
            n00b_free(pool->items[i]);
        }
    }

    pool->count = 0;
}

void
n00b_composite_style_pool_destroy(n00b_composite_style_pool_t *pool)
{
    if (!pool) {
        return;
    }

    n00b_composite_style_pool_clear(pool);
    if (pool->items) {
        n00b_free(pool->items);
        pool->items = nullptr;
    }
    pool->capacity = 0;
}

n00b_text_style_t *
n00b_composite_style_pool_take(n00b_composite_style_pool_t *pool,
                                n00b_text_style_t           *style)
{
    if (!pool || !style) {
        return style;
    }

    if (pool->count >= pool->capacity) {
        composite_style_pool_grow(pool);
    }

    pool->items[pool->count++] = style;
    return style;
}

static size_t
text_next_style_boundary(n00b_string_t *text, size_t byte_pos)
{
    size_t boundary;

    if (!text) {
        return 0;
    }

    boundary = text->u8_bytes;

    auto info_opt = n00b_str_get_style_info(text);
    if (!n00b_option_is_set(info_opt)) {
        return boundary;
    }

    n00b_string_style_info_t *info = n00b_option_get(info_opt);

    for (int64_t i = 0; i < info->num_styles; i++) {
        n00b_style_record_t *rec = &info->styles[i];

        if (rec->start > byte_pos && rec->start < boundary) {
            boundary = rec->start;
        }

        if (n00b_option_is_set(rec->end)) {
            size_t end = n00b_option_get(rec->end);

            if (end > byte_pos && end < boundary) {
                boundary = end;
            }
        }
    }

    return boundary;
}

static n00b_text_style_t *
text_resolve_effective_style(n00b_string_t      *text,
                             n00b_text_style_t  *fallback_style,
                             size_t              byte_pos,
                             n00b_composite_style_pool_t *style_pool)
{
    auto info_opt = n00b_str_get_style_info(text);

    if (!n00b_option_is_set(info_opt)) {
        return fallback_style;
    }

    n00b_text_style_t *resolved = n00b_str_resolve_style_at(text, byte_pos);
    n00b_text_style_t *merged;

    if (!fallback_style) {
        return n00b_composite_style_pool_take(style_pool, resolved);
    }

    merged = n00b_str_style_merge(fallback_style, resolved);
    n00b_free(resolved);

    return n00b_composite_style_pool_take(style_pool, merged);
}

static inline int32_t
floor_div_i32(int32_t v, int32_t d)
{
    if (d <= 0) {
        return v;
    }
    if (v >= 0) {
        return v / d;
    }
    return -(((-v) + d - 1) / d);
}

static inline int32_t
ceil_div_i32(int32_t v, int32_t d)
{
    if (d <= 0) {
        return v;
    }
    return -floor_div_i32(-v, d);
}

static int
compare_entry_key(int32_t abs_z_a, uint32_t order_a,
                  int32_t abs_z_b, uint32_t order_b)
{
    if (abs_z_a != abs_z_b) {
        return abs_z_a < abs_z_b ? -1 : 1;
    }
    if (order_a != order_b) {
        return order_a < order_b ? -1 : 1;
    }

    return 0;
}

static int
compare_record_component(const flatten_record_t *a,
                         size_t                  a_ix,
                         const flatten_record_t *b,
                         size_t                  b_ix)
{
    bool a_has_layer = a_ix < a->layer_count;
    bool b_has_layer = b_ix < b->layer_count;

    if (a_has_layer
        && b_has_layer
        && a->layers[a_ix].stack == b->layers[b_ix].stack
        && a->layers[a_ix].plane != b->layers[b_ix].plane) {
        return a->layers[a_ix].index < b->layers[b_ix].index ? -1 : 1;
    }

    int32_t a_abs_z = a_has_layer ? a->layers[a_ix].abs_z : a->entry.abs_z;
    uint32_t a_order = a_has_layer ? a->layers[a_ix].order : a->entry.order;
    int32_t b_abs_z = b_has_layer ? b->layers[b_ix].abs_z : b->entry.abs_z;
    uint32_t b_order = b_has_layer ? b->layers[b_ix].order : b->entry.order;

    return compare_entry_key(a_abs_z, a_order, b_abs_z, b_order);
}

static int
compare_flatten_record(const void *a, const void *b)
{
    const flatten_record_t *ra = a;
    const flatten_record_t *rb = b;
    size_t                  ix = 0;

    while (ix < ra->layer_count
           && ix < rb->layer_count
           && ra->layers[ix].plane == rb->layers[ix].plane) {
        ix++;
    }

    int cmp = compare_record_component(ra, ix, rb, ix);
    if (cmp != 0) {
        return cmp;
    }

    return compare_entry_key(ra->entry.abs_z,
                             ra->entry.order,
                             rb->entry.abs_z,
                             rb->entry.order);
}

static void
flatten_recurse(flatten_ctx_t *ctx, n00b_plane_t *p,
                int32_t parent_x, int32_t parent_y, int32_t parent_z,
                int32_t clip_x, int32_t clip_y,
                int32_t clip_w, int32_t clip_h,
                int32_t cell_px_w, int32_t cell_px_h)
{
    if (!(p->flags & N00B_PLANE_VISIBLE)) {
        return;
    }

    int32_t abs_x = 0;
    int32_t abs_y = 0;
    int32_t abs_z = parent_z + p->z;

    // Layout assigns absolute bounds, while manually parented planes keep
    // parent-relative x/y. Prefer layout bounds when present so nested
    // container children do not double-apply ancestor offsets.
    n00b_plane_resolve_absolute_origin(p,
                                       parent_x,
                                       parent_y,
                                       &abs_x,
                                       &abs_y);

    int32_t plane_w = p->width;
    int32_t plane_h = p->height;

    // Add box insets and margins (already in pixels via n00b_box_insets_px).
    if (p->box) {
        int32_t it, ib, il, ir;
        n00b_box_insets_px(p->box, cell_px_w, cell_px_h,
                            &it, &ib, &il, &ir);
        plane_w += il + ir;
        plane_h += it + ib;

        plane_w += p->box->margin_left * cell_px_w
                 + p->box->margin_right * cell_px_w;
        plane_h += p->box->margin_top * cell_px_h
                 + p->box->margin_bottom * cell_px_h;
    }

    int32_t my_clip_x = imax32(clip_x, abs_x);
    int32_t my_clip_y = imax32(clip_y, abs_y);
    int32_t my_clip_r = imin32(clip_x + clip_w, abs_x + plane_w);
    int32_t my_clip_b = imin32(clip_y + clip_h, abs_y + plane_h);
    int32_t my_clip_w = imax32(0, my_clip_r - my_clip_x);
    int32_t my_clip_h = imax32(0, my_clip_b - my_clip_y);

    if (my_clip_w == 0 || my_clip_h == 0) {
        return; // Fully clipped by parent.
    }

    if (ctx->count >= ctx->capacity) {
        flatten_grow(ctx);
    }

    n00b_isize_t entry_ix = ctx->count++;
    bool pushed_layer = plane_is_zstack(p->parent);

    if (pushed_layer) {
        flatten_path_push(ctx,
                          (layer_marker_t){
                              .plane  = p,
                              .stack  = p->parent,
                              .abs_z  = abs_z,
                              .order  = (uint32_t)entry_ix,
                              .index  = plane_child_index(p->parent, p),
                          });
    }

    ctx->records[entry_ix].entry = (n00b_composite_entry_t){
        .plane  = p,
        .abs_x  = abs_x,
        .abs_y  = abs_y,
        .abs_z  = abs_z,
        .order  = (uint32_t)entry_ix,
        .clip_x = my_clip_x,
        .clip_y = my_clip_y,
        .clip_w = my_clip_w,
        .clip_h = my_clip_h,
    };
    ctx->records[entry_ix].layer_count = ctx->layer_count;
    ctx->records[entry_ix].layers = nullptr;

    if (ctx->layer_count > 0) {
        ctx->records[entry_ix].layers = n00b_alloc_array_with_opts(
            layer_marker_t, ctx->layer_count,
            &(n00b_alloc_opts_t){.no_scan = true});
        memcpy(ctx->records[entry_ix].layers,
               ctx->layer_path,
               ctx->layer_count * sizeof(layer_marker_t));
    }

    if (p->children.len == 0) {
        if (pushed_layer) {
            flatten_path_pop(ctx);
        }
        return;
    }

    for (size_t i = 0; i < p->children.len; i++) {
        n00b_plane_t *child = p->children.data[i];
        if (!child) {
            continue;
        }
        flatten_recurse(ctx, child, abs_x, abs_y, abs_z + 1,
                        my_clip_x, my_clip_y, my_clip_w, my_clip_h,
                        cell_px_w, cell_px_h);
    }

    if (pushed_layer) {
        flatten_path_pop(ctx);
    }
}

// -------------------------------------------------------------------
// Public: flatten
// -------------------------------------------------------------------

n00b_array_t(n00b_composite_entry_t)
n00b_composite_flatten(n00b_plane_t **planes,
                        n00b_isize_t   num_planes,
                        int32_t        cell_px_w,
                        int32_t        cell_px_h)
{
    flatten_ctx_t ctx = {};
    n00b_composite_entry_t *entries = nullptr;

    // Top-level planes get an effectively unbounded clip rectangle.
    // The compositing loop will clip to the actual frame bounds.
    int32_t max_dim = INT32_MAX / 2;

    for (n00b_isize_t i = 0; i < num_planes; i++) {
        if (!planes[i]) {
            continue;
        }
        flatten_recurse(&ctx, planes[i], 0, 0, 0,
                        0, 0, max_dim, max_dim,
                        cell_px_w, cell_px_h);
    }

    if (ctx.count > 1) {
        qsort(ctx.records,
              (size_t)ctx.count,
              sizeof(flatten_record_t),
              compare_flatten_record);
    }

    if (ctx.count > 0) {
        entries = n00b_alloc_array_with_opts(
            n00b_composite_entry_t, ctx.count,
            &(n00b_alloc_opts_t){.no_scan = true});

        for (n00b_isize_t i = 0; i < ctx.count; i++) {
            entries[i] = ctx.records[i].entry;
            if (ctx.records[i].layers) {
                n00b_free(ctx.records[i].layers);
            }
        }
    }

    if (ctx.records) {
        n00b_free(ctx.records);
    }
    if (ctx.layer_path) {
        n00b_free(ctx.layer_path);
    }

    return (n00b_array_t(n00b_composite_entry_t)){
        .data = entries,
        .len  = (size_t)ctx.count,
        .cap  = (size_t)ctx.count,
    };
}

// -------------------------------------------------------------------
// Internal: resolve effective style for a plane's current state
// -------------------------------------------------------------------

n00b_text_style_t *
n00b_composite_resolve_style(n00b_plane_t *p, n00b_text_style_t *base_style,
                              int style_field) // 0=text, 1=border, 2=fill
{
    if (!p->box || p->widget_state == N00B_WSTATE_NORMAL) {
        return base_style;
    }

    n00b_state_style_t *ss = p->box->state_styles[p->widget_state];
    if (!ss) {
        return base_style;
    }

    n00b_text_style_t *override = nullptr;
    switch (style_field) {
    case 0:
        override = ss->text_style;
        break;
    case 1:
        override = ss->border_style;
        break;
    case 2:
        override = ss->fill_style;
        break;
    }

    return override ? override : base_style;
}

// -------------------------------------------------------------------
// Public: per-cell degradation
// -------------------------------------------------------------------

// Map common box-drawing codepoints to ASCII.
static n00b_codepoint_t
degrade_unicode_to_ascii(n00b_codepoint_t cp)
{
    // Horizontal lines.
    if ((cp >= 0x2500 && cp <= 0x2501)
        || (cp >= 0x2504 && cp <= 0x2509)
        || cp == 0x2550) {
        return '-';
    }
    // Vertical lines.
    if ((cp >= 0x2502 && cp <= 0x2503)
        || (cp >= 0x2506 && cp <= 0x250B)
        || cp == 0x2551) {
        return '|';
    }
    // Corners and T-junctions.
    if ((cp >= 0x250C && cp <= 0x254B)
        || (cp >= 0x2554 && cp <= 0x256C)
        || (cp >= 0x256D && cp <= 0x2570)) {
        return '+';
    }
    return cp;
}

void
n00b_composite_degrade_cell(n00b_rcell_t *cell, n00b_render_cap_t caps)
{
    if (!(cell->flags & N00B_CELL_OCCUPIED)) {
        return;
    }

    bool no_unicode = !(caps & N00B_RCAP_UNICODE);

    if (no_unicode && cell->grapheme_len > 1) {
        const uint8_t *g = (const uint8_t *)cell->grapheme;
        n00b_codepoint_t cp;

        if ((g[0] & 0xE0) == 0xC0 && cell->grapheme_len >= 2) {
            cp = ((g[0] & 0x1F) << 6) | (g[1] & 0x3F);
        }
        else if ((g[0] & 0xF0) == 0xE0 && cell->grapheme_len >= 3) {
            cp = ((g[0] & 0x0F) << 12) | ((g[1] & 0x3F) << 6)
                 | (g[2] & 0x3F);
        }
        else {
            return;
        }

        n00b_codepoint_t ascii = degrade_unicode_to_ascii(cp);
        if (ascii != cp && ascii < 0x80) {
            cell->grapheme[0]   = (char)ascii;
            cell->grapheme[1]   = '\0';
            cell->grapheme_len  = 1;
            cell->display_width = 1;
        }
    }
}

// -------------------------------------------------------------------
// Public: entry info
// -------------------------------------------------------------------

void
n00b_composite_entry_info(const n00b_composite_entry_t *entry,
                           n00b_entry_info_t            *out,
                           int32_t                       cell_px_w,
                           int32_t                       cell_px_h)
{
    n00b_plane_t *p = entry->plane;

    memset(out, 0, sizeof(*out));

    out->box = p->box;

    // Compute box insets in pixels.
    int32_t inset_top = 0;
    int32_t inset_bot = 0;
    int32_t inset_left = 0;
    int32_t inset_right = 0;
    n00b_box_insets_px(p->box, cell_px_w, cell_px_h,
                        &inset_top, &inset_bot,
                        &inset_left, &inset_right);
    out->inset_top = (n00b_isize_t)inset_top;
    out->inset_bot = (n00b_isize_t)inset_bot;
    out->inset_left = (n00b_isize_t)inset_left;
    out->inset_right = (n00b_isize_t)inset_right;

    // Outer box origin (after margins, in pixels).
    int32_t margin_top  = p->box ? p->box->margin_top  * cell_px_h : 0;
    int32_t margin_left = p->box ? p->box->margin_left * cell_px_w : 0;

    out->outer_x = entry->abs_x + margin_left;
    out->outer_y = entry->abs_y + margin_top;

    // Total outer dimensions in pixels (border + padding + content).
    // width/height are already in pixels.
    out->outer_rows = p->height + out->inset_top + out->inset_bot;
    out->outer_cols = p->width + out->inset_left + out->inset_right;

    // Content area origin in pixels.
    out->content_x = out->outer_x + (int32_t)out->inset_left;
    out->content_y = out->outer_y + (int32_t)out->inset_top;

    // Resolve styles for current widget state.
    out->border_style = n00b_composite_resolve_style(
        p, p->box ? p->box->border_style : nullptr, 1);
    out->fill_style = n00b_composite_resolve_style(
        p, p->box ? p->box->fill_style : nullptr, 2);
    out->text_style = n00b_composite_resolve_style(
        p, p->default_style, 0);
}

void
n00b_composite_snap_rect_to_cells(n00b_rect_t *rect,
                                   int32_t      cell_px_w,
                                   int32_t      cell_px_h)
{
    if (!rect) {
        return;
    }

    int32_t cpw = cell_px_w > 0 ? cell_px_w : 1;
    int32_t cph = cell_px_h > 0 ? cell_px_h : 1;

    if (rect->width <= 0 || rect->height <= 0) {
        rect->width = 0;
        rect->height = 0;
        return;
    }

    int32_t right = rect->x + rect->width;
    int32_t bottom = rect->y + rect->height;
    int32_t snapped_x = floor_div_i32(rect->x, cpw) * cpw;
    int32_t snapped_y = floor_div_i32(rect->y, cph) * cph;
    int32_t snapped_right = ceil_div_i32(right, cpw) * cpw;
    int32_t snapped_bottom = ceil_div_i32(bottom, cph) * cph;

    rect->x = snapped_x;
    rect->y = snapped_y;
    rect->width = snapped_right - snapped_x;
    rect->height = snapped_bottom - snapped_y;
}

// -------------------------------------------------------------------
// Internal: write a single codepoint into the cell grid
// -------------------------------------------------------------------

static void
write_cp_to_grid(n00b_rcell_t      *frame,
                  n00b_isize_t       cell_cols,
                  n00b_isize_t       cell_rows,
                  int32_t            cell_col,
                  int32_t            cell_row,
                  n00b_codepoint_t   cp,
                  int                cp_width,
                  n00b_text_style_t *style,
                  int32_t            clip_cell_y,
                  int32_t            clip_cell_b,
                  int32_t            clip_cell_x,
                  int32_t            clip_cell_r)
{
    if (cell_row < 0 || cell_row >= (int32_t)cell_rows
        || cell_col < 0 || cell_col >= (int32_t)cell_cols) {
        return;
    }

    // Clip to parent bounds (in cells).
    if (cell_row < clip_cell_y || cell_row >= clip_cell_b
        || cell_col < clip_cell_x || cell_col >= clip_cell_r) {
        return;
    }

    n00b_rcell_t *dst = &frame[cell_row * cell_cols + cell_col];
    n00b_rcell_set_codepoint(dst, cp, (uint8_t)cp_width, style);

    // Mark continuation cells for wide characters.
    if (cp_width == 2 && cell_col + 1 < (int32_t)cell_cols
        && cell_col + 1 < clip_cell_r) {
        n00b_rcell_t *cont = &frame[cell_row * cell_cols + cell_col + 1];
        n00b_rcell_clear(cont);
        cont->flags = N00B_CELL_WIDE_CONT | N00B_CELL_DIRTY;
        cont->style = style;
    }
}

// -------------------------------------------------------------------
// Internal: decode one UTF-8 codepoint from a byte stream
// -------------------------------------------------------------------

static inline n00b_codepoint_t
decode_utf8_cp(const uint8_t *p, size_t remaining, size_t *out_len)
{
    if (remaining == 0) {
        *out_len = 0;
        return 0;
    }

    uint8_t b0 = p[0];

    if (b0 < 0x80) {
        *out_len = 1;
        return b0;
    }
    if ((b0 & 0xE0) == 0xC0 && remaining >= 2) {
        *out_len = 2;
        return ((b0 & 0x1F) << 6) | (p[1] & 0x3F);
    }
    if ((b0 & 0xF0) == 0xE0 && remaining >= 3) {
        *out_len = 3;
        return ((b0 & 0x0F) << 12) | ((p[1] & 0x3F) << 6)
               | (p[2] & 0x3F);
    }
    if ((b0 & 0xF8) == 0xF0 && remaining >= 4) {
        *out_len = 4;
        return ((b0 & 0x07) << 18) | ((p[1] & 0x3F) << 12)
               | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
    }

    // Invalid — skip one byte.
    *out_len = 1;
    return 0xFFFD;
}

// -------------------------------------------------------------------
// Public: composite draw commands to cell grid
// -------------------------------------------------------------------

void
n00b_composite_commands_to_grid(const n00b_composite_entry_t *entries,
                                 n00b_isize_t                  count,
                                 n00b_rcell_t                 *frame,
                                 n00b_isize_t                  cell_rows,
                                 n00b_isize_t                  cell_cols,
                                 int32_t                       cell_px_w,
                                 int32_t                       cell_px_h,
                                 n00b_text_style_t            *default_style,
                                 n00b_render_cap_t             caps,
                                 n00b_composite_style_pool_t  *style_pool)
{
    // Clear frame.
    for (n00b_isize_t i = 0; i < cell_rows * cell_cols; i++) {
        n00b_rcell_set_ascii(&frame[i], ' ', default_style);
        n00b_rcell_mark_clean(&frame[i]);
    }

    // Composite each entry in back-to-front painter order.
    for (n00b_isize_t e = 0; e < count; e++) {
        const n00b_composite_entry_t *entry = &entries[e];
        n00b_plane_t *p = entry->plane;

        if (!(p->flags & N00B_PLANE_VISIBLE)) {
            continue;
        }

        n00b_entry_info_t info;
        n00b_composite_entry_info(entry, &info, cell_px_w, cell_px_h);

        n00b_rect_t outer_rect = {
            .x = info.outer_x,
            .y = info.outer_y,
            .width = (int32_t)info.outer_cols,
            .height = (int32_t)info.outer_rows,
        };
        n00b_rect_t content_rect = {
            .x = info.content_x,
            .y = info.content_y,
            .width = p->width,
            .height = p->height,
        };
        n00b_rect_t clip_rect = {
            .x = entry->clip_x,
            .y = entry->clip_y,
            .width = entry->clip_w,
            .height = entry->clip_h,
        };

        if (cell_px_w > 1 || cell_px_h > 1) {
            n00b_composite_snap_rect_to_cells(&outer_rect, cell_px_w, cell_px_h);
            n00b_composite_snap_rect_to_cells(&clip_rect, cell_px_w, cell_px_h);
        }

        // Stamp box decoration.
        n00b_isize_t stamp_row  = (n00b_isize_t)floor_div_i32(outer_rect.y, cell_px_h);
        n00b_isize_t stamp_col  = (n00b_isize_t)floor_div_i32(outer_rect.x, cell_px_w);
        n00b_isize_t stamp_rows = (n00b_isize_t)(outer_rect.height / cell_px_h);
        n00b_isize_t stamp_cols = (n00b_isize_t)(outer_rect.width / cell_px_w);

        if (info.box && info.box->border_theme) {
            if (stamp_row >= 0
                && stamp_col >= 0
                && stamp_row + stamp_rows <= cell_rows
                && stamp_col + stamp_cols <= cell_cols) {

                n00b_box_stamp(info.box, frame, cell_cols,
                               stamp_row, stamp_col,
                               stamp_rows, stamp_cols,
                               info.border_style, info.fill_style);
            }
        }

        // Clip rectangle in cells.
        int32_t clip_cell_y = floor_div_i32(clip_rect.y, cell_px_h);
        int32_t clip_cell_x = floor_div_i32(clip_rect.x, cell_px_w);
        int32_t clip_cell_b = clip_cell_y + (clip_rect.height / cell_px_h);
        int32_t clip_cell_r = clip_cell_x + (clip_rect.width / cell_px_w);

        // Walk draw commands, converting pixel coords to cells.
        for (n00b_isize_t c = 0; c < p->draw_list.count; c++) {
            const n00b_draw_cmd_t *cmd = &p->draw_list.cmds[c];

            switch (cmd->type) {
            case N00B_DRAW_TEXT: {
                n00b_string_t *text = cmd->string;
                size_t         byte_pos = 0;
                size_t         run_end = 0;
                bool           has_string_style;
                if (!text || text->u8_bytes == 0) {
                    break;
                }

                n00b_text_style_t *style = cmd->style
                                             ? cmd->style
                                             : info.text_style;
                has_string_style = n00b_option_is_set(n00b_str_get_style_info(text));
                run_end = has_string_style
                              ? text_next_style_boundary(text, 0)
                              : text->u8_bytes;
                n00b_text_style_t *run_style = has_string_style
                                                   ? text_resolve_effective_style(text,
                                                                                  style,
                                                                                  0,
                                                                                  style_pool)
                                                   : style;

                // Draw commands are in pixels; for cell backends
                // cell_px_w == cell_px_h == 1, so pixel == cell.
                int32_t base_col = floor_div_i32(content_rect.x
                                                 + cmd->text.x
                                                 - p->scroll_x,
                                                 cell_px_w);
                int32_t base_row = floor_div_i32(content_rect.y
                                                 + cmd->text.y
                                                 - p->scroll_y,
                                                 cell_px_h);

                // Decode each codepoint and place into cells.
                const uint8_t *bytes = (const uint8_t *)text->data;
                size_t remaining = text->u8_bytes;
                int32_t col_cursor = base_col;

                while (remaining > 0) {
                    size_t cp_len;
                    n00b_codepoint_t cp = decode_utf8_cp(bytes, remaining,
                                                          &cp_len);
                    if (cp_len == 0) {
                        break;
                    }

                    if (has_string_style && byte_pos >= run_end) {
                        run_end   = text_next_style_boundary(text, byte_pos);
                        run_style = text_resolve_effective_style(text,
                                                                 style,
                                                                 byte_pos,
                                                                 style_pool);
                    }

                    int cp_width = n00b_unicode_char_width(cp);

                    write_cp_to_grid(frame, cell_cols, cell_rows,
                                     col_cursor, base_row,
                                     cp, cp_width, run_style,
                                     clip_cell_y, clip_cell_b,
                                     clip_cell_x, clip_cell_r);

                    col_cursor += cp_width > 0 ? cp_width : 1;
                    bytes      += cp_len;
                    remaining  -= cp_len;
                    byte_pos   += cp_len;
                }
                break;
            }

            case N00B_DRAW_GLYPH: {
                n00b_text_style_t *style = cmd->style
                                             ? cmd->style
                                             : info.text_style;

                int32_t col = floor_div_i32(content_rect.x
                                            + cmd->glyph.x
                                            - p->scroll_x,
                                            cell_px_w);
                int32_t row = floor_div_i32(content_rect.y
                                            + cmd->glyph.y
                                            - p->scroll_y,
                                            cell_px_h);

                int cp_width = n00b_unicode_char_width(cmd->glyph.cp);

                write_cp_to_grid(frame, cell_cols, cell_rows,
                                 col, row,
                                 cmd->glyph.cp, cp_width, style,
                                 clip_cell_y, clip_cell_b,
                                 clip_cell_x, clip_cell_r);
                break;
            }

            case N00B_DRAW_FILL_RECT: {
                n00b_text_style_t *style = cmd->style
                                             ? cmd->style
                                             : info.fill_style;

                n00b_rect_t fill_rect = {
                    .x = content_rect.x + cmd->fill_rect.x - p->scroll_x,
                    .y = content_rect.y + cmd->fill_rect.y - p->scroll_y,
                    .width = cmd->fill_rect.w,
                    .height = cmd->fill_rect.h,
                };

                if (cell_px_w > 1 || cell_px_h > 1) {
                    n00b_composite_snap_rect_to_cells(&fill_rect,
                                                      cell_px_w,
                                                      cell_px_h);
                }

                int32_t start_col = floor_div_i32(fill_rect.x, cell_px_w);
                int32_t start_row = floor_div_i32(fill_rect.y, cell_px_h);
                int32_t end_col = start_col + (fill_rect.width / cell_px_w);
                int32_t end_row = start_row + (fill_rect.height / cell_px_h);

                n00b_codepoint_t cp = cmd->fill_rect.cp;
                int cp_width = n00b_unicode_char_width(cp);
                if (cp_width < 1) cp_width = 1;

                for (int32_t r = start_row; r < end_row; r++) {
                    for (int32_t cc = start_col; cc < end_col;
                         cc += cp_width) {
                        write_cp_to_grid(frame, cell_cols, cell_rows,
                                         cc, r, cp, cp_width, style,
                                         clip_cell_y, clip_cell_b,
                                         clip_cell_x, clip_cell_r);
                    }
                }
                break;
            }
            }
        }
    }

    // Degrade based on capabilities.
    for (n00b_isize_t i = 0; i < cell_rows * cell_cols; i++) {
        n00b_composite_degrade_cell(&frame[i], caps);
    }
}

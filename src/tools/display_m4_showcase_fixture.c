#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "display/backend_stream_internal.h"
#include "display/event.h"
#include "display/focus.h"
#include "display/hexdump.h"
#include "display/render/backend.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "display/table/table.h"
#include "display/widget.h"
#include "display/widgets/button.h"
#include "display/widgets/checkbox.h"
#include "display/widgets/label.h"
#include "display_m4_showcase_fixture.h"
#include "internal/display/event_dispatch.h"
#include "text/strings/string_ops.h"

typedef struct {
    n00b_plane_t *status;
    int           button_clicks;
} n00b_display_m4_showcase_state_t;

static n00b_string_t *
make_str(const char *s)
{
    return n00b_string_from_raw(s, (int64_t)strlen(s));
}

static void
on_run_click(n00b_plane_t *plane, void *data)
{
    (void)plane;

    n00b_display_m4_showcase_state_t *state = data;
    state->button_clicks++;
    n00b_label_set_text(state->status, r"status=run");
}

static n00b_string_t *
first_hexdump_line(void)
{
    uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x41, 0x42, 0x43, 0x44};
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)payload, sizeof(payload));
    n00b_option_t(n00b_buffer_t *) hex_opt = n00b_hexdump_buf(buf, .width = 48);
    if (!n00b_option_is_set(hex_opt)) {
        return r"hexdump unavailable";
    }
    n00b_buffer_t *hex = n00b_option_get(hex_opt);

    int64_t len = 0;
    char *data = n00b_buffer_to_c(hex, &len);
    if (!data || len <= 0) {
        return r"hexdump unavailable";
    }

    int64_t line_len = 0;
    while (line_len < len && data[line_len] != '\n') {
        line_len++;
    }

    return n00b_string_from_raw(data, line_len);
}

int
n00b_display_m4_showcase_run(n00b_display_m4_showcase_summary_t *out)
{
    n00b_canvas_t                      *canvas = nullptr;
    n00b_plane_t                       *root = nullptr;
    n00b_plane_t                       *status = nullptr;
    n00b_plane_t                       *button = nullptr;
    n00b_plane_t                       *checkbox = nullptr;
    n00b_plane_t                       *table_plane = nullptr;
    n00b_plane_t                       *hexdump_label = nullptr;
    n00b_focus_mgr_t                   *fm = nullptr;
    n00b_table_t                       *table = nullptr;
    n00b_display_m4_showcase_state_t    state = {};
    n00b_display_m4_showcase_summary_t  summary = {};
    int                                 rc = -1;

    canvas = n00b_new_kargs(n00b_canvas_t, canvas, .vtable = &n00b_renderer_stream);
    if (!canvas) {
        goto done;
    }

    n00b_stream_backend_set_size(canvas->backend_ctx,
                                 N00B_DISPLAY_M4_SHOWCASE_ROWS,
                                 N00B_DISPLAY_M4_SHOWCASE_COLS);
    n00b_canvas_resize(canvas,
                       N00B_DISPLAY_M4_SHOWCASE_ROWS,
                       N00B_DISPLAY_M4_SHOWCASE_COLS);

    root = n00b_new_kargs(n00b_plane_t, plane);
    if (!root) {
        goto done;
    }

    root->width  = N00B_DISPLAY_M4_SHOWCASE_COLS;
    root->height = N00B_DISPLAY_M4_SHOWCASE_ROWS;

    status = n00b_label_new(
        r"status=idle",
        .canvas = canvas,
        .width  = 20,
        .height = 1);
    if (!status) {
        goto done;
    }

    state.status = status;

    button = n00b_button_new(
        r"Run",
        .canvas        = canvas,
        .width         = 10,
        .height        = 1,
        .on_click      = on_run_click,
        .on_click_data = &state);
    if (!button) {
        goto done;
    }

    checkbox = n00b_checkbox_new(
        r"Enable",
        .canvas = canvas,
        .width  = 14,
        .height = 1);
    if (!checkbox) {
        goto done;
    }

    n00b_table_style_t style = n00b_table_style_ascii();
    table = n00b_new_kargs(
        n00b_table_t,
        table,
        .num_cols    = 2,
        .table_props = style.table_props,
        .cell_props  = style.cell_props);
    if (!table) {
        goto done;
    }

    n00b_table_add_cell(table, make_str("Component"));
    n00b_table_add_cell(table, make_str("State"));
    n00b_table_end_row(table);
    n00b_table_add_cell(table, make_str("widget"));
    n00b_table_add_cell(table, make_str("ready"));
    n00b_table_end_row(table);

    table_plane = n00b_table_render(table, .width = 34);
    if (!table_plane) {
        goto done;
    }

    hexdump_label = n00b_label_new(
        first_hexdump_line(),
        .canvas = canvas,
        .width  = 48,
        .height = 1);
    if (!hexdump_label) {
        goto done;
    }

    n00b_plane_add_child(root, status, 2, 1);
    n00b_plane_add_child(root, button, 2, 3);
    n00b_plane_add_child(root, checkbox, 16, 3);
    n00b_plane_add_child(root, table_plane, 2, 5);
    n00b_plane_add_child(root, hexdump_label, 2, 12);
    n00b_canvas_add_plane(canvas, root);

    fm = n00b_focus_mgr_new(canvas);
    if (!fm || !n00b_focus_mgr_set(fm, button)) {
        goto done;
    }

    n00b_event_t enter = {
        .type = N00B_EVENT_KEY,
        .key = {.key = N00B_KEY_ENTER, .mods = N00B_MOD_NONE},
    };
    summary.enter_handled = n00b_display_dispatch_event(canvas, fm, &enter).handled;

    n00b_event_t click_checkbox = {
        .type = N00B_EVENT_MOUSE,
        .mouse = {
            .x = 16,
            .y = 3,
            .button = N00B_MOUSE_LEFT,
            .action = N00B_MOUSE_PRESS,
            .mods = N00B_MOD_NONE,
        },
    };
    summary.checkbox_click_handled =
        n00b_display_dispatch_event(canvas, fm, &click_checkbox).handled;

    n00b_canvas_render(canvas);

    n00b_string_t *buf = n00b_stream_backend_get_buffer(canvas->backend_ctx);
    if (!buf || !buf->data) {
        goto done;
    }

    summary.showcase_stream = n00b_unicode_str_copy(buf);
    if (!summary.showcase_stream) {
        goto done;
    }

    summary.status_is_run = n00b_unicode_str_contains(n00b_label_get_text(status),
                                                      r"status=run");
    summary.checkbox_checked = n00b_checkbox_is_checked(checkbox);
    summary.button_clicks    = state.button_clicks;

    if (out) {
        *out = summary;
    }

    rc = 0;

done:
    if (fm) {
        n00b_focus_mgr_destroy(fm);
    }
    if (canvas && root) {
        n00b_canvas_remove_plane(canvas, root);
    }
    if (root && status) {
        n00b_plane_remove_child(root, status);
    }
    if (root && button) {
        n00b_plane_remove_child(root, button);
    }
    if (root && checkbox) {
        n00b_plane_remove_child(root, checkbox);
    }
    if (root && table_plane) {
        n00b_plane_remove_child(root, table_plane);
    }
    if (root && hexdump_label) {
        n00b_plane_remove_child(root, hexdump_label);
    }
    if (status) {
        n00b_widget_detach(status);
        n00b_plane_destroy(status);
    }
    if (button) {
        n00b_widget_detach(button);
        n00b_plane_destroy(button);
    }
    if (checkbox) {
        n00b_widget_detach(checkbox);
        n00b_plane_destroy(checkbox);
    }
    if (hexdump_label) {
        n00b_widget_detach(hexdump_label);
        n00b_plane_destroy(hexdump_label);
    }
    if (table_plane) {
        n00b_plane_destroy(table_plane);
    }
    if (root) {
        n00b_plane_destroy(root);
    }
    if (canvas) {
        n00b_canvas_destroy(canvas);
    }
    if (table) {
        n00b_table_destroy(table);
    }

    return rc;
}

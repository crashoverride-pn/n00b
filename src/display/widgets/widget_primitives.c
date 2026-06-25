#include "n00b.h"
#include "core/string.h"
#include "display/render/box.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "internal/display/widget_primitives.h"

int32_t
n00b_widget_cell_px_width(n00b_plane_t *plane)
{
    if (!plane) {
        return 1;
    }

    int32_t cpw = n00b_plane_text_width(plane, r"M", nullptr);
    if (cpw <= 0) {
        cpw = 1;
    }

    return cpw;
}

int32_t
n00b_widget_line_px_height(n00b_plane_t *plane)
{
    if (!plane) {
        return 1;
    }

    int32_t lh = n00b_plane_line_height(plane, nullptr);
    if (lh <= 0) {
        lh = 1;
    }

    return lh;
}

bool
n00b_widget_state_is_focused_or_active(const n00b_plane_t *plane)
{
    if (!plane) {
        return false;
    }

    n00b_widget_state_t state = n00b_plane_get_state((n00b_plane_t *)plane);
    return state == N00B_WSTATE_FOCUSED || state == N00B_WSTATE_ACTIVE;
}

bool
n00b_widget_event_is_left_press(const n00b_event_t *event)
{
    if (!event || event->type != N00B_EVENT_MOUSE) {
        return false;
    }

    return event->mouse.button == N00B_MOUSE_LEFT
        && event->mouse.action == N00B_MOUSE_PRESS;
}

bool
n00b_widget_event_is_keyboard_activate(const n00b_event_t *event)
{
    if (!event || event->type != N00B_EVENT_KEY) {
        return false;
    }

    return event->key.key == N00B_KEY_ENTER || event->key.key == ' ';
}

void
n00b_widget_measure_plain_plane(n00b_plane_t *plane,
                                int32_t      *pref_w,
                                int32_t      *pref_h,
                                int32_t      *min_w,
                                int32_t      *min_h)
{
    int32_t width = plane ? plane->width : 0;
    int32_t height = plane ? plane->height : 0;

    if (plane && plane->box) {
        int32_t cpw = 1;
        int32_t cph = 1;
        int32_t inset_top = 0;
        int32_t inset_bot = 0;
        int32_t inset_left = 0;
        int32_t inset_right = 0;

        if (plane->canvas) {
            cpw = (int32_t)(plane->canvas->cell_px_w > 0
                            ? plane->canvas->cell_px_w
                            : 1);
            cph = (int32_t)(plane->canvas->cell_px_h > 0
                            ? plane->canvas->cell_px_h
                            : 1);
        }

        n00b_box_insets_px(plane->box,
                           cpw,
                           cph,
                           &inset_top,
                           &inset_bot,
                           &inset_left,
                           &inset_right);

        width += inset_left + inset_right;
        height += inset_top + inset_bot;
    }

    *pref_w = width;
    *pref_h = height;
    *min_w = width;
    *min_h = height;
}

void *
n00b_widget_data_if_kind(n00b_plane_t *plane,
                          const n00b_widget_vtable_t *expected)
{
    if (!plane || !expected) {
        return nullptr;
    }

    if (plane->widget_vtable != expected) {
        return nullptr;
    }

    return plane->widget_data;
}

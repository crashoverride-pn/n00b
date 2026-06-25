#include <string.h>

#include "n00b.h"
#include "display/backend_stream_internal.h"
#include "display/focus.h"
#include "display/render/backend.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "display/widget.h"
#include "display/widgets/button.h"
#include "display/widgets/label.h"
#include "display_demo_scene.h"

bool
n00b_display_demo_scene_init(n00b_display_demo_scene_t *scene,
                             n00b_isize_t               rows,
                             n00b_isize_t               cols)
{
    if (!scene) {
        return false;
    }

    *scene = (n00b_display_demo_scene_t){};

    scene->canvas = n00b_new_kargs(n00b_canvas_t, canvas,
                                   .vtable = &n00b_renderer_stream);
    if (!scene->canvas) {
        return false;
    }

    n00b_stream_backend_set_size(scene->canvas->backend_ctx, rows, cols);
    n00b_canvas_resize(scene->canvas, rows, cols);

    scene->root = n00b_new_kargs(n00b_plane_t, plane);
    if (!scene->root) {
        n00b_display_demo_scene_destroy(scene);
        return false;
    }
    scene->root->width  = cols;
    scene->root->height = rows;

    scene->title = n00b_label_new(
        r"Display Baseline Scene",
        .canvas = scene->canvas,
        .width  = 30,
        .height = 1);

    scene->status = n00b_label_new(
        r"Status: baseline-ready",
        .canvas = scene->canvas,
        .width  = 36,
        .height = 1);

    scene->button = n00b_button_new(
        r"Execute",
        .canvas = scene->canvas,
        .width  = 12,
        .height = 1);

    n00b_plane_add_child(scene->root, scene->title, 2, 1);
    n00b_plane_add_child(scene->root, scene->status, 2, 3);
    n00b_plane_add_child(scene->root, scene->button, 2, 5);
    n00b_canvas_add_plane(scene->canvas, scene->root);

    scene->focus_mgr = n00b_focus_mgr_new(scene->canvas);
    if (scene->focus_mgr) {
        (void)n00b_focus_mgr_set(scene->focus_mgr, scene->button);
    }

    return true;
}

void
n00b_display_demo_scene_destroy(n00b_display_demo_scene_t *scene)
{
    if (!scene) {
        return;
    }

    if (scene->focus_mgr) {
        n00b_focus_mgr_destroy(scene->focus_mgr);
    }
    if (scene->canvas && scene->root) {
        n00b_canvas_remove_plane(scene->canvas, scene->root);
    }
    if (scene->root && scene->title) {
        n00b_plane_remove_child(scene->root, scene->title);
    }
    if (scene->root && scene->status) {
        n00b_plane_remove_child(scene->root, scene->status);
    }
    if (scene->root && scene->button) {
        n00b_plane_remove_child(scene->root, scene->button);
    }
    if (scene->title) {
        n00b_widget_detach(scene->title);
        n00b_plane_destroy(scene->title);
    }
    if (scene->status) {
        n00b_widget_detach(scene->status);
        n00b_plane_destroy(scene->status);
    }
    if (scene->button) {
        n00b_widget_detach(scene->button);
        n00b_plane_destroy(scene->button);
    }
    if (scene->root) {
        n00b_plane_destroy(scene->root);
    }
    if (scene->canvas) {
        n00b_canvas_destroy(scene->canvas);
    }

    *scene = (n00b_display_demo_scene_t){};
}

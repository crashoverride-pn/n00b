#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "internal/display/scene_contracts.h"
#include "display_demo_scene.h"

#define SCENE_ROWS 10
#define SCENE_COLS 52

static int
ensure_dir_recursive(const char *dir)
{
    char path[PATH_MAX];
    size_t len = strlen(dir);

    if (len == 0) {
        errno = EINVAL;
        return -1;
    }
    if (len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(path, dir, len + 1);

    if (path[len - 1] == '/') {
        if (len == 1) {
            return 0;
        }
        path[len - 1] = '\0';
    }

    char *p;
    for (p = path + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        *p = '/';
    }

    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

static int
ensure_parent_dir(const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen(path);

    if (len == 0) {
        errno = EINVAL;
        return -1;
    }
    if (len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1);

    char *slash = strrchr(tmp, '/');
    if (!slash) {
        return 0;
    }
    if (slash == tmp) {
        return 0;
    }

    *slash = '\0';
    return ensure_dir_recursive(tmp);
}

static int
plane_depth(n00b_plane_t *plane)
{
    int depth = 0;
    n00b_plane_t *p;
    for (p = plane; p && p->parent; p = p->parent) {
        depth++;
    }
    return depth;
}

static int
scene_report_printf(FILE *fp, const char *fmt, ...)
{
    va_list args;
    int result;
    int saved_errno;

    errno = 0;
    va_start(args, fmt);
    result = vfprintf(fp, fmt, args);
    saved_errno = errno;
    va_end(args);

    if (result < 0) {
        errno = saved_errno ? saved_errno : EIO;
        return -1;
    }

    return 0;
}

static int
write_scene_report(const char *path)
{
    int rc = -1;
    int saved_errno = 0;
    n00b_display_demo_scene_t demo = {};
    n00b_array_t(n00b_composite_entry_t) scene = {};
    FILE *fp = nullptr;

    errno = 0;

    if (!n00b_display_demo_scene_init(&demo, SCENE_ROWS, SCENE_COLS)) {
        errno = EIO;
        goto done;
    }

    n00b_display_scene_run_layout(demo.canvas);
    n00b_display_scene_mark_all_dirty(demo.canvas);
    n00b_display_scene_rerender_dirty(demo.canvas);
    scene = n00b_display_scene_build(demo.canvas);

    fp = fopen(path, "wb");
    if (!fp) {
        goto done;
    }

    if (scene_report_printf(fp, "tool=display_scene_inspect\n") != 0) {
        goto done;
    }
    if (scene_report_printf(fp, "entries=%zu\n", scene.len) != 0) {
        goto done;
    }

    for (size_t i = 0; i < scene.len; i++) {
        n00b_composite_entry_t *entry = &scene.data[i];
        n00b_plane_t *plane = entry->plane;
        const char *kind = "plane";

        if (plane && plane->widget_vtable && plane->widget_vtable->kind) {
            kind = plane->widget_vtable->kind;
        }

        if (scene_report_printf(
                fp,
                "%03zu depth=%d z=%d abs=(%d,%d) clip=(%d,%d,%d,%d) "
                "plane=(x=%d,y=%d,w=%d,h=%d) kind=%s visible=%d dirty=%d gen=%u\n",
                i,
                plane_depth(plane),
                entry->abs_z,
                entry->abs_x,
                entry->abs_y,
                entry->clip_x,
                entry->clip_y,
                entry->clip_w,
                entry->clip_h,
                plane ? plane->x : 0,
                plane ? plane->y : 0,
                plane ? plane->width : 0,
                plane ? plane->height : 0,
                kind,
                plane ? ((plane->flags & N00B_PLANE_VISIBLE) != 0) : 0,
                plane ? ((plane->flags & N00B_PLANE_DIRTY) != 0) : 0,
                plane ? plane->render_gen : 0) != 0) {
            goto done;
        }
    }

    errno = 0;
    if (ferror(fp)) {
        errno = EIO;
        goto done;
    }

    errno = 0;
    if (fclose(fp) != 0) {
        fp = nullptr;
        if (errno == 0) {
            errno = EIO;
        }
        goto done;
    }
    fp = nullptr;
    rc = 0;

done:
    saved_errno = errno;

    if (fp) {
        if (fclose(fp) != 0 && saved_errno == 0) {
            saved_errno = errno ? errno : EIO;
        }
    }
    n00b_display_scene_free(scene);
    n00b_display_demo_scene_destroy(&demo);

    if (rc != 0) {
        errno = saved_errno ? saved_errno : EIO;
    }

    return rc;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --out PATH\n"
            "Capture deterministic display scene-inspection output.\n",
            prog);
}

int
main(int argc, char **argv)
{
    const char *out = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --out requires a value.\n");
                return 1;
            }
            out = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }

        fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
        print_usage(argv[0]);
        return 1;
    }

    if (!out) {
        fprintf(stderr, "Error: --out is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    if (ensure_parent_dir(out) != 0) {
        int err = errno ? errno : EIO;
        fprintf(stderr,
                "failed to create output directory for %s: %s\n",
                out,
                strerror(err));
        n00b_shutdown();
        return 1;
    }

    if (write_scene_report(out) != 0) {
        int err = errno ? errno : EIO;
        fprintf(stderr,
                "failed to write scene report to %s: %s\n",
                out,
                strerror(err));
        n00b_shutdown();
        return 1;
    }

    printf("wrote %s\n", out);
    n00b_shutdown();
    return 0;
}

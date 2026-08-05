#include <errno.h>
#include <limits.h>
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
#include "display/render/backend.h"
#include "display/backend_stream_internal.h"
#include "display/table/table.h"
#include "display_demo_scene.h"

#define TOOL_VERSION      "1"
#define SCENE_ROWS        10
#define SCENE_COLS        52
#define TABLE_RENDER_COLS 52

static n00b_string_t *
make_str(const char *s)
{
    return n00b_string_from_raw(s, (int64_t)strlen(s));
}

static int
ensure_dir_recursive(const char *dir)
{
    char path[PATH_MAX];
    size_t len = strlen(dir);

    if (len == 0 || len >= sizeof(path)) {
        return -1;
    }

    memcpy(path, dir, len + 1);

    if (path[len - 1] == '/') {
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
build_path(char *out, size_t out_sz, const char *dir, const char *name)
{
    int n = snprintf(out, out_sz, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_sz) {
        return -1;
    }
    return 0;
}

static int
write_bytes_file(const char *path, const char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    return 0;
}

static size_t
trim_trailing_blank_line(const char *data, size_t len)
{
    while (len >= 2 && data[len - 1] == '\n' && data[len - 2] == '\n') {
        len--;
    }

    return len;
}

static int
write_scene_snapshot(const char *out_dir)
{
    int rc = -1;
    n00b_display_demo_scene_t scene = {};

    if (!n00b_display_demo_scene_init(&scene, SCENE_ROWS, SCENE_COLS)) {
        goto cleanup;
    }

    n00b_canvas_render(scene.canvas);
    n00b_string_t *buf = n00b_stream_backend_get_buffer(scene.canvas->backend_ctx);
    if (!buf || !buf->data) {
        goto cleanup;
    }

    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "scene_stream.txt") != 0) {
        goto cleanup;
    }

    size_t scene_len = trim_trailing_blank_line(buf->data, buf->u8_bytes);

    if (write_bytes_file(path, buf->data, scene_len) != 0) {
        goto cleanup;
    }

    rc = 0;
cleanup:
    n00b_display_demo_scene_destroy(&scene);

    if (rc == 0) {
        printf("wrote scene_stream.txt\n");
    }
    return rc;
}

static int
write_table_snapshot(const char *out_dir)
{
    int rc = -1;

    n00b_table_style_t style = n00b_table_style_ascii();
    n00b_table_t      *table = n00b_new_kargs(
        n00b_table_t,
        table,
        .num_cols    = 3,
        .table_props = style.table_props,
        .cell_props  = style.cell_props);
    n00b_plane_t *plane      = nullptr;
    n00b_canvas_t *canvas    = nullptr;

    n00b_table_add_cell(table, make_str("Component"));
    n00b_table_add_cell(table, make_str("Status"));
    n00b_table_add_cell(table, make_str("Notes"));
    n00b_table_end_row(table);

    n00b_table_add_cell(table, make_str("render"));
    n00b_table_add_cell(table, make_str("stable"));
    n00b_table_add_cell(table, make_str("stream baseline"));
    n00b_table_end_row(table);

    n00b_table_add_cell(table, make_str("focus"));
    n00b_table_add_cell(table, make_str("stable"));
    n00b_table_add_cell(table, make_str("single control path"));
    n00b_table_end_row(table);

    plane = n00b_table_render(table, .width = TABLE_RENDER_COLS);
    if (!plane) {
        goto cleanup;
    }

    canvas = n00b_new_kargs(n00b_canvas_t, canvas,
                            .vtable = &n00b_renderer_stream);
    n00b_stream_backend_set_size(canvas->backend_ctx, plane->height, plane->width);
    n00b_canvas_resize(canvas, plane->height, plane->width);
    n00b_canvas_add_plane(canvas, plane);
    n00b_canvas_render(canvas);

    n00b_string_t *buf = n00b_stream_backend_get_buffer(canvas->backend_ctx);
    if (!buf || !buf->data) {
        goto cleanup;
    }

    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "table_stream.txt") != 0) {
        goto cleanup;
    }

    if (write_bytes_file(path, buf->data, buf->u8_bytes) != 0) {
        goto cleanup;
    }

    rc = 0;
cleanup:
    if (canvas && plane) {
        n00b_canvas_remove_plane(canvas, plane);
    }
    if (canvas) {
        n00b_canvas_destroy(canvas);
    }
    if (table) {
        n00b_table_destroy(table);
    }

    if (rc == 0) {
        printf("wrote table_stream.txt\n");
    }
    return rc;
}

static int
write_metadata(const char *out_dir)
{
    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "metadata.txt") != 0) {
        return -1;
    }

    char contents[512];
    int  n = snprintf(contents,
                     sizeof(contents),
                     "tool=display_baseline_capture\n"
                     "tool_version=%s\n"
                     "backend=stream\n"
                     "scene_rows=%d\n"
                     "scene_cols=%d\n"
                     "table_render_cols=%d\n"
                     "n00b_version=%u.%u.%u\n",
                     TOOL_VERSION,
                     SCENE_ROWS,
                     SCENE_COLS,
                     TABLE_RENDER_COLS,
                     (unsigned)N00B_VERS_MAJOR,
                     (unsigned)N00B_VERS_MINOR,
                     (unsigned)N00B_VERS_PATCH);
    if (n < 0 || (size_t)n >= sizeof(contents)) {
        return -1;
    }

    if (write_bytes_file(path, contents, (size_t)n) != 0) {
        return -1;
    }

    printf("wrote metadata.txt\n");
    return 0;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --out-dir PATH\n"
            "Capture deterministic display baseline artifacts.\n",
            prog);
}

int
main(int argc, char **argv)
{
    int rc = 1;
    bool runtime_inited = false;
    const char *out_dir = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out-dir") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --out-dir requires a value.\n");
                return 1;
            }
            out_dir = argv[i];
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

    if (!out_dir) {
        fprintf(stderr, "Error: --out-dir is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    runtime_inited = true;

    if (ensure_dir_recursive(out_dir) != 0) {
        fprintf(stderr, "Error: could not create output directory '%s': %s\n",
                out_dir, strerror(errno));
        goto out;
    }

    if (write_scene_snapshot(out_dir) != 0) {
        fprintf(stderr, "Error: failed writing scene snapshot.\n");
        goto out;
    }

    if (write_table_snapshot(out_dir) != 0) {
        fprintf(stderr, "Error: failed writing table snapshot.\n");
        goto out;
    }

    if (write_metadata(out_dir) != 0) {
        fprintf(stderr, "Error: failed writing metadata.\n");
        goto out;
    }

    rc = 0;
out:
    if (runtime_inited) {
        n00b_shutdown();
    }
    return rc;
}

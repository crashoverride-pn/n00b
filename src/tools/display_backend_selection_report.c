#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "n00b.h"
#include "core/runtime.h"
#include "display/render/backend_registry.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "display/widget.h"
#include "display/widgets/label.h"

#define DEFAULT_OUT_DIR "plans/artifacts/display-rewrite/m5"
#define TOOL_VERSION    "1"

typedef struct selection_case_t {
    const char *label;
    const char *requested_backend;
    const char *env_backend;
    bool        allow_fallback;
} selection_case_t;

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

static void
set_backend_override(const char *value)
{
#ifdef _WIN32
    _putenv_s("N00B_RENDERER_BACKEND", value ? value : "");
#else
    if (value) {
        setenv("N00B_RENDERER_BACKEND", value, 1);
    }
    else {
        unsetenv("N00B_RENDERER_BACKEND");
    }
#endif
}

static int
render_probe_scene(n00b_canvas_t *canvas)
{
    n00b_plane_t *root = n00b_new_kargs(n00b_plane_t, plane);
    root->width        = 28;
    root->height       = 6;

    n00b_plane_t *label = n00b_label_new(
        n00b_string_from_cstr("m5 runtime selection"),
        .canvas = canvas,
        .width  = 24,
        .height = 1);

    n00b_plane_add_child(root, label, 2, 2);
    n00b_canvas_add_plane(canvas, root);
    n00b_canvas_resize(canvas, 6, 28);
    n00b_canvas_render(canvas);

    n00b_canvas_remove_plane(canvas, root);
    n00b_plane_remove_child(root, label);
    n00b_widget_detach(label);
    n00b_plane_destroy(label);
    n00b_plane_destroy(root);

    return 0;
}

static int
run_selection_case(const selection_case_t             *spec,
                   FILE                               *report,
                   n00b_conduit_topic_t(n00b_buffer_t *) *output)
{
    if (!spec || !report) {
        return -1;
    }

    const char *saved_env_raw = getenv("N00B_RENDERER_BACKEND");
    // Copy the original env value into GC memory (it must survive the setenv
    // below, which can invalidate the getenv pointer).  Runs post-n00b_init.
    n00b_string_t *saved_env = saved_env_raw ? n00b_string_from_cstr(saved_env_raw)
                                             : nullptr;

    set_backend_override(spec->env_backend);

    const char *requested = spec->requested_backend ? spec->requested_backend : "auto";
    n00b_string_t *requested_name = n00b_string_from_cstr(requested);
    n00b_list_t(n00b_string_t *) candidates =
        n00b_renderer_candidate_names(requested_name,
                                      .allow_fallback     = spec->allow_fallback,
                                      .allow_env_override = true);

    const char *primary_candidate = "none";
    if (candidates.len > 0) {
        n00b_string_t *first = n00b_list_get(candidates, 0);
        if (first && first->data && first->data[0]) {
            primary_candidate = first->data;
        }
    }

    n00b_canvas_t *canvas = n00b_alloc(n00b_canvas_t);
    n00b_canvas_init(canvas,
                     .backend_name               = requested_name,
                     .backend_allow_fallback     = spec->allow_fallback,
                     .backend_allow_dynamic_load = false,
                     .backend_allow_env_override = true,
                     .output                     = output);

    bool startup_ok = n00b_canvas_backend_ready(canvas);
    const char *selected_backend = "none";
    bool fallback_used = false;

    if (startup_ok && canvas->vtable && canvas->vtable->name) {
        selected_backend = canvas->vtable->name;
        fallback_used =
            n00b_renderer_selection_uses_fallback(requested_name,
                                                  canvas->vtable,
                                                  .allow_fallback     = spec->allow_fallback,
                                                  .allow_dynamic_load = false,
                                                  .allow_env_override = true);
        (void)render_probe_scene(canvas);
    }

    fprintf(report,
            "case=%s requested=%s env_override=%s allow_fallback=%s selected=%s startup=%s fallback_used=%s primary_candidate=%s\n",
            spec->label ? spec->label : "unnamed",
            requested,
            spec->env_backend ? spec->env_backend : "none",
            spec->allow_fallback ? "true" : "false",
            selected_backend,
            startup_ok ? "true" : "false",
            fallback_used ? "true" : "false",
            primary_candidate);

    n00b_canvas_destroy(canvas);

    if (saved_env) {
        set_backend_override(saved_env->data);
    }
    else {
        set_backend_override(nullptr);
    }

    return 0;
}

static int
write_selection_metadata(const char *out_dir)
{
    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "selection_metadata.txt") != 0) {
        return -1;
    }

    char contents[512];
    int  n = snprintf(contents,
                      sizeof(contents),
                      "tool=display_backend_selection_report\n"
                      "tool_version=%s\n"
                      "n00b_version=%u.%u.%u\n"
                      "cases=5\n",
                      TOOL_VERSION,
                      (unsigned)N00B_VERS_MAJOR,
                      (unsigned)N00B_VERS_MINOR,
                      (unsigned)N00B_VERS_PATCH);
    if (n < 0 || (size_t)n >= sizeof(contents)) {
        return -1;
    }

    if (write_bytes_file(path, contents, (size_t)n) != 0) {
        return -1;
    }

    printf("wrote selection_metadata.txt\n");
    return 0;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--out-dir PATH]\n"
            "Generate deterministic runtime backend-selection report artifacts.\n",
            prog);
}

int
main(int argc, char **argv)
{
    const char *out_dir = DEFAULT_OUT_DIR;

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

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    if (ensure_dir_recursive(out_dir) != 0) {
        fprintf(stderr, "Error: could not create output directory '%s': %s\n",
                out_dir, strerror(errno));
        return 1;
    }

    char report_path[PATH_MAX];
    if (build_path(report_path, sizeof(report_path), out_dir, "selection_report.txt") != 0) {
        fprintf(stderr, "Error: output path is too long.\n");
        return 1;
    }

    FILE *report = fopen(report_path, "wb");
    if (!report) {
        fprintf(stderr, "Error: could not open report file '%s': %s\n",
                report_path, strerror(errno));
        return 1;
    }

    selection_case_t cases[] = {
        { "explicit_stream",       "stream",          nullptr,  false },
        { "explicit_ansi_beats_env", "ansi",          "stream", true  },
        { "auto_default",          "auto",            nullptr,  true  },
        { "missing_with_fallback", "missing-backend", nullptr,  true  },
        { "env_override_stream",   "auto",            "stream", true  },
    };

    for (size_t i = 0; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        if (run_selection_case(&cases[i], report, nullptr) != 0) {
            fclose(report);
            fprintf(stderr, "Error: failed running selection case '%s'.\n",
                    cases[i].label);
            return 1;
        }
    }

    if (fclose(report) != 0) {
        fprintf(stderr, "Error: failed closing '%s'.\n", report_path);
        return 1;
    }

    printf("wrote selection_report.txt\n");

    if (write_selection_metadata(out_dir) != 0) {
        fprintf(stderr, "Error: failed writing selection metadata.\n");
        return 1;
    }

    n00b_shutdown();
    return 0;
}

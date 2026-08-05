#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#define isatty _isatty
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "internal/display/startup_probe.h"
#include "display/render/backend_registry.h"

#define DEFAULT_OUT_DIR "test/fixtures/display/baselines/m6"
#define TOOL_VERSION    "1"

typedef struct cutover_case_t {
    const char *label;
    const char *requested_backend;
    bool        allow_fallback;
    bool        allow_env_override;
} cutover_case_t;

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

static int
run_cutover_case(const cutover_case_t               *spec,
                 FILE                                *report,
                 n00b_conduit_topic_t(n00b_buffer_t *) *output)
{
    if (!spec || !report) {
        return -1;
    }

    const char *requested = spec->requested_backend ? spec->requested_backend : "auto";
    n00b_display_startup_probe_t result =
        n00b_display_probe_startup(requested,
                                   .allow_fallback = spec->allow_fallback,
                                   .allow_env_override = spec->allow_env_override,
                                   .output = output);

    fprintf(report,
            "case=%s requested=%s allow_fallback=%s allow_env_override=%s selected=%s startup=%s fallback_used=%s\n",
            spec->label ? spec->label : "unnamed",
            requested,
            spec->allow_fallback ? "true" : "false",
            spec->allow_env_override ? "true" : "false",
            result.selected_backend,
            result.startup_ok ? "true" : "false",
            result.fallback_used ? "true" : "false");

    return 0;
}

static int
write_cutover_metadata(const char *out_dir,
                       bool        gui_available,
                       bool        notcurses_available,
                       bool        x11_built,
                       bool        cocoa_built)
{
    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "cutover_metadata.txt") != 0) {
        return -1;
    }

    const char *display_env = getenv("DISPLAY");
    const char *wayland_env = getenv("WAYLAND_DISPLAY");
    const char *tty_env = isatty(STDIN_FILENO) ? "true" : "false";

    char contents[1024];
    int n = snprintf(contents,
                     sizeof(contents),
                     "tool=display_m6_cutover_report\n"
                     "tool_version=%s\n"
                     "n00b_version=%u.%u.%u\n"
                     "cases=5\n"
                     "gui_available=%s\n"
                     "notcurses_available=%s\n"
                     "x11_built=%s\n"
                     "cocoa_built=%s\n"
                     "stdin_is_tty=%s\n"
                     "display_env=%s\n"
                     "wayland_display_env=%s\n",
                     TOOL_VERSION,
                     (unsigned)N00B_VERS_MAJOR,
                     (unsigned)N00B_VERS_MINOR,
                     (unsigned)N00B_VERS_PATCH,
                     gui_available ? "true" : "false",
                     notcurses_available ? "true" : "false",
                     x11_built ? "true" : "false",
                     cocoa_built ? "true" : "false",
                     tty_env,
                     (display_env && display_env[0]) ? "set" : "unset",
                     (wayland_env && wayland_env[0]) ? "set" : "unset");
    if (n < 0 || (size_t)n >= sizeof(contents)) {
        return -1;
    }

    if (write_bytes_file(path, contents, (size_t)n) != 0) {
        return -1;
    }

    printf("wrote cutover_metadata.txt\n");
    return 0;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--out-dir PATH]\n"
            "Generate deterministic display rewrite M6 cutover report artifacts.\n",
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
    if (build_path(report_path, sizeof(report_path), out_dir, "cutover_report.txt") != 0) {
        fprintf(stderr, "Error: output path is too long.\n");
        return 1;
    }

    FILE *report = fopen(report_path, "wb");
    if (!report) {
        fprintf(stderr, "Error: could not open report file '%s': %s\n",
                report_path, strerror(errno));
        return 1;
    }

    const char *saved_override_raw = getenv("N00B_RENDERER_BACKEND");
    // Copy original env into GC memory before the setenv-driven probe below
    // (the getenv pointer can be invalidated).  Runs post-n00b_init.
    n00b_string_t *saved_override = saved_override_raw
                                        ? n00b_string_from_cstr(saved_override_raw)
                                        : nullptr;

    n00b_runtime_t *rt = n00b_get_runtime();
    auto *stdout_topic =
        (n00b_conduit_topic_t(n00b_buffer_t *) *)rt->stdout_topic;

    n00b_display_startup_probe_t gui_probe =
        n00b_display_probe_startup("gui",
                                   .allow_fallback = false,
                                   .allow_env_override = false,
                                   .output = stdout_topic);
    n00b_display_startup_probe_t notcurses_probe =
        n00b_display_probe_startup("notcurses",
                                   .allow_fallback = false,
                                   .allow_env_override = false,
                                   .output = stdout_topic);
    bool gui_available = gui_probe.startup_ok;
    bool notcurses_available = notcurses_probe.startup_ok;
    bool x11_built = n00b_result_is_ok(
        n00b_renderer_resolve_exact(r"x11", .allow_dynamic_load = false));
    bool cocoa_built = n00b_result_is_ok(
        n00b_renderer_resolve_exact(r"cocoa", .allow_dynamic_load = false));

    const char *display_env = getenv("DISPLAY");
    const char *wayland_env = getenv("WAYLAND_DISPLAY");
    fprintf(report,
            "environment gui_available=%s notcurses_available=%s x11_built=%s cocoa_built=%s display_env=%s wayland_display_env=%s\n",
            gui_available ? "true" : "false",
            notcurses_available ? "true" : "false",
            x11_built ? "true" : "false",
            cocoa_built ? "true" : "false",
            (display_env && display_env[0]) ? "set" : "unset",
            (wayland_env && wayland_env[0]) ? "set" : "unset");

    cutover_case_t cases[] = {
        { "explicit_stream", "stream", false, false },
        { "auto_default", "auto", true, false },
        { "env_override_stream", "auto", true, true },
        { "gui_strict", "gui", false, false },
        { "gui_with_fallback", "gui", true, false },
    };

    for (size_t i = 0; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        if (strcmp(cases[i].label, "env_override_stream") == 0) {
            n00b_display_set_backend_override("stream");
        }
        else if (saved_override) {
            n00b_display_set_backend_override(saved_override->data);
        }
        else {
            n00b_display_set_backend_override(nullptr);
        }

        if (run_cutover_case(&cases[i], report, stdout_topic) != 0) {
            fclose(report);
            fprintf(stderr, "Error: failed running cutover case '%s'.\n",
                    cases[i].label);
            return 1;
        }
    }

    if (saved_override) {
        n00b_display_set_backend_override(saved_override->data);
    }
    else {
        n00b_display_set_backend_override(nullptr);
    }

    if (fclose(report) != 0) {
        fprintf(stderr, "Error: failed closing '%s'.\n", report_path);
        return 1;
    }

    printf("wrote cutover_report.txt\n");

    if (write_cutover_metadata(out_dir,
                               gui_available,
                               notcurses_available,
                               x11_built,
                               cocoa_built) != 0) {
        fprintf(stderr, "Error: failed writing cutover metadata.\n");
        return 1;
    }

    n00b_shutdown();
    return 0;
}

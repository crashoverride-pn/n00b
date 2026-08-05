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
#define mkdir(path, mode) _mkdir(path)
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "display_m3_parity_fixture.h"

#define DEFAULT_OUT_DIR "test/fixtures/display/baselines/m3"
#define TOOL_VERSION    "2"

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
write_parity_report(const char                       *out_dir,
                    const n00b_m3_parity_result_t   *terminal,
                    const n00b_m3_parity_result_t   *gui)
{
    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "parity_report.txt") != 0) {
        return -1;
    }

    bool equivalent = n00b_m3_parity_equivalent(terminal, gui);
    char report[4096];
    int n = snprintf(report,
                     sizeof(report),
                     "evidence_scope=synthetic_contract_parity\n"
                     "scenario=focus,key,mouse,resize,stop\n"
                     "gui_profile.cell_pixel_w=9\n"
                     "gui_profile.cell_pixel_h=16\n"
                     "real_gui_backends_exercised=0\n"
                     "terminal.resize.calls=%d\n"
                     "terminal.resize.rows=%d\n"
                     "terminal.resize.cols=%d\n"
                     "terminal.left.key_events=%d\n"
                     "terminal.right.key_events=%d\n"
                     "terminal.left.activations=%d\n"
                     "terminal.right.activations=%d\n"
                     "terminal.left.mouse_presses=%d\n"
                     "terminal.right.mouse_presses=%d\n"
                     "terminal.cursor.hide=%d\n"
                     "terminal.cursor.show=%d\n"
                     "terminal.events_consumed=%zu\n"
                     "terminal.events_total=%zu\n"
                     "terminal.next_key_after_stop=%u\n"
                     "gui.resize.calls=%d\n"
                     "gui.resize.rows=%d\n"
                     "gui.resize.cols=%d\n"
                     "gui.left.key_events=%d\n"
                     "gui.right.key_events=%d\n"
                     "gui.left.activations=%d\n"
                     "gui.right.activations=%d\n"
                     "gui.left.mouse_presses=%d\n"
                     "gui.right.mouse_presses=%d\n"
                     "gui.cursor.hide=%d\n"
                     "gui.cursor.show=%d\n"
                     "gui.events_consumed=%zu\n"
                     "gui.events_total=%zu\n"
                     "gui.next_key_after_stop=%u\n"
                     "parity.equivalent=%d\n",
                     terminal->resize_calls,
                     (int)terminal->resize_rows,
                     (int)terminal->resize_cols,
                     terminal->left_key_events,
                     terminal->right_key_events,
                     terminal->left_activations,
                     terminal->right_activations,
                     terminal->left_mouse_presses,
                     terminal->right_mouse_presses,
                     terminal->cursor_hide ? 1 : 0,
                     terminal->cursor_show ? 1 : 0,
                     terminal->events_consumed,
                     terminal->events_total,
                     (unsigned)terminal->next_key_after_stop,
                     gui->resize_calls,
                     (int)gui->resize_rows,
                     (int)gui->resize_cols,
                     gui->left_key_events,
                     gui->right_key_events,
                     gui->left_activations,
                     gui->right_activations,
                     gui->left_mouse_presses,
                     gui->right_mouse_presses,
                     gui->cursor_hide ? 1 : 0,
                     gui->cursor_show ? 1 : 0,
                     gui->events_consumed,
                     gui->events_total,
                     (unsigned)gui->next_key_after_stop,
                     equivalent ? 1 : 0);

    if (n < 0 || (size_t)n >= sizeof(report)) {
        return -1;
    }

    if (write_bytes_file(path, report, (size_t)n) != 0) {
        return -1;
    }

    printf("wrote parity_report.txt\n");
    return 0;
}

static int
write_parity_metadata(const char *out_dir,
                      bool        cocoa_built)
{
    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "parity_metadata.txt") != 0) {
        return -1;
    }

    char text[1024];
    int n = snprintf(text,
                     sizeof(text),
                     "tool=display_gui_parity_report\n"
                     "tool_version=%s\n"
                     "evidence_scope=synthetic_contract_parity\n"
                     "subset=focus_traversal,key_activation,mouse_press,resize,stop\n"
                     "gui_profile.cell_pixel_w=9\n"
                     "gui_profile.cell_pixel_h=16\n"
                     "real_gui_backends_exercised=0\n"
                     "cocoa_built=%d\n"
                     "n00b_version=%u.%u.%u\n",
                     TOOL_VERSION,
                     cocoa_built ? 1 : 0,
                     (unsigned)N00B_VERS_MAJOR,
                     (unsigned)N00B_VERS_MINOR,
                     (unsigned)N00B_VERS_PATCH);

    if (n < 0 || (size_t)n >= sizeof(text)) {
        return -1;
    }

    if (write_bytes_file(path, text, (size_t)n) != 0) {
        return -1;
    }

    printf("wrote parity_metadata.txt\n");
    return 0;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--out-dir PATH]\n"
            "Run deterministic synthetic GUI-profile parity and write M3 artifacts.\n",
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
        fprintf(stderr,
                "Error: could not create output directory '%s': %s\n",
                out_dir,
                strerror(errno));
        n00b_shutdown();
        return 1;
    }

    n00b_m3_parity_result_t terminal = {};
    n00b_m3_parity_result_t gui = {};

    if (n00b_m3_parity_run_case(false, &terminal) != 0
        || n00b_m3_parity_run_case(true, &gui) != 0) {
        fprintf(stderr, "Error: synthetic parity scenario failed.\n");
        n00b_shutdown();
        return 1;
    }

    if (write_parity_report(out_dir, &terminal, &gui) != 0) {
        fprintf(stderr, "Error: failed writing parity_report.txt\n");
        n00b_shutdown();
        return 1;
    }

    bool cocoa_built = false;
#if defined(__APPLE__)
    cocoa_built = true;
#endif

    if (write_parity_metadata(out_dir, cocoa_built) != 0) {
        fprintf(stderr, "Error: failed writing parity_metadata.txt\n");
        n00b_shutdown();
        return 1;
    }

    bool equivalent = n00b_m3_parity_equivalent(&terminal, &gui);
    n00b_shutdown();

    if (!equivalent) {
        fprintf(stderr, "Error: synthetic parity mismatch (see parity_report.txt).\n");
        return 1;
    }

    return 0;
}

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "display_terminal_replay_fixture.h"

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

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --out-dir PATH\n"
            "Run deterministic terminal replay and write artifact logs.\n",
            prog);
}

int
main(int argc, char **argv)
{
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

    if (ensure_dir_recursive(out_dir) != 0) {
        fprintf(stderr, "Error: could not create output directory '%s': %s\n",
                out_dir, strerror(errno));
        n00b_shutdown();
        return 1;
    }

    n00b_display_terminal_replay_summary_t summary = {};
    int rc = n00b_display_terminal_replay_run(&summary);
    if (rc != 0) {
        fprintf(stderr, "Error: terminal replay failed.\n");
        n00b_shutdown();
        return rc;
    }

    rc = n00b_display_terminal_replay_write_artifacts(out_dir, &summary);
    if (rc != 0) {
        fprintf(stderr, "Error: could not write terminal replay artifacts.\n");
    }

    n00b_shutdown();
    return rc;
}

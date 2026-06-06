#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "display/hexdump.h"
#include "display_m4_showcase_fixture.h"

#define DEFAULT_OUT_DIR "test/fixtures/display/baselines/m4"
#define TOOL_VERSION    "1"

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
write_showcase_stream(const char *out_dir,
                      const n00b_display_m4_showcase_summary_t *summary)
{
    if (!summary || !summary->showcase_stream || !summary->showcase_stream->data) {
        return -1;
    }

    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "showcase_stream.txt") != 0) {
        return -1;
    }

    size_t showcase_len = trim_trailing_blank_line(summary->showcase_stream->data,
                                                   summary->showcase_stream->u8_bytes);
    if (write_bytes_file(path, summary->showcase_stream->data, showcase_len) != 0) {
        return -1;
    }

    printf("wrote showcase_stream.txt\n");
    return 0;
}

static int
write_hexdump_stream(const char *out_dir)
{
    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)i;
    }

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)payload, sizeof(payload));
    n00b_option_t(n00b_buffer_t *) hex_opt = n00b_hexdump_buf(buf, .width = 64);
    if (!n00b_option_is_set(hex_opt)) {
        return -1;
    }
    n00b_buffer_t *hex = n00b_option_get(hex_opt);

    int64_t len = 0;
    char *data = n00b_buffer_to_c(hex, &len);
    if (!data || len <= 0) {
        return -1;
    }

    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "hexdump_stream.txt") != 0) {
        return -1;
    }

    if (write_bytes_file(path, data, (size_t)len) != 0) {
        return -1;
    }

    printf("wrote hexdump_stream.txt\n");
    return 0;
}

static int
write_showcase_metadata(const char *out_dir,
                        const n00b_display_m4_showcase_summary_t *summary)
{
    if (!summary) {
        return -1;
    }

    char path[PATH_MAX];
    if (build_path(path, sizeof(path), out_dir, "showcase_metadata.txt") != 0) {
        return -1;
    }

    char contents[512];
    int n = snprintf(contents,
                     sizeof(contents),
                     "tool=display_m4_showcase\n"
                     "tool_version=%s\n"
                     "backend=stream\n"
                     "rows=%d\n"
                     "cols=%d\n"
                     "button_clicks=%d\n"
                     "n00b_version=%u.%u.%u\n",
                     TOOL_VERSION,
                     N00B_DISPLAY_M4_SHOWCASE_ROWS,
                     N00B_DISPLAY_M4_SHOWCASE_COLS,
                     summary->button_clicks,
                     (unsigned)N00B_VERS_MAJOR,
                     (unsigned)N00B_VERS_MINOR,
                     (unsigned)N00B_VERS_PATCH);
    if (n < 0 || (size_t)n >= sizeof(contents)) {
        return -1;
    }

    if (write_bytes_file(path, contents, (size_t)n) != 0) {
        return -1;
    }

    printf("wrote showcase_metadata.txt\n");
    return 0;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--out-dir PATH]\n"
            "Generate deterministic Milestone 4 showcase artifacts.\n",
            prog);
}

int
main(int argc, char **argv)
{
    const char *out_dir = DEFAULT_OUT_DIR;
    bool runtime_started = false;
    int exit_code = 1;
    n00b_display_m4_showcase_summary_t summary = {};

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
    runtime_started = true;

    if (ensure_dir_recursive(out_dir) != 0) {
        fprintf(stderr, "Error: could not create output directory '%s': %s\n",
                out_dir, strerror(errno));
        goto cleanup;
    }

    if (n00b_display_m4_showcase_run(&summary) != 0) {
        fprintf(stderr, "Error: failed rendering showcase scenario.\n");
        goto cleanup;
    }

    if (write_showcase_stream(out_dir, &summary) != 0) {
        fprintf(stderr, "Error: failed writing showcase stream.\n");
        goto cleanup;
    }

    if (write_hexdump_stream(out_dir) != 0) {
        fprintf(stderr, "Error: failed writing hexdump stream.\n");
        goto cleanup;
    }

    if (write_showcase_metadata(out_dir, &summary) != 0) {
        fprintf(stderr, "Error: failed writing showcase metadata.\n");
        goto cleanup;
    }

    exit_code = 0;

cleanup:
    if (runtime_started) {
        n00b_shutdown();
    }

    return exit_code;
}

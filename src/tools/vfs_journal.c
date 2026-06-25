/**
 * @file vfs_journal.c
 * @brief VFS journaling daemon / demo.
 *
 * Mounts a local directory via the VFS with a journaling hook that
 * logs every operation as NDJSON to a journal file.  Uses the
 * platform-appropriate frontend (FUSE on macOS, NFSv3 on Linux).
 *
 * If no frontend is available (e.g., macFUSE not installed), falls
 * back to a library-mode demo that exercises the VFS API directly
 * and prints the journal to stdout.
 *
 * Usage:
 *   vfs_journal --source /path/to/dir --mount /path/to/mountpoint
 *   vfs_journal --source /path/to/dir --journal /path/to/journal.ndjson
 *   vfs_journal --source /path/to/dir   (journal to stdout, library demo)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "vfs/vfs.h"
#include "vfs/backend_local.h"
#include "vfs/frontend.h"
#include "vfs/cache.h"

// ============================================================================
// Journal hook
// ============================================================================

typedef struct {
    FILE *fp;
    bool  owns_fp;    // true if we opened it (vs stdout)
} journal_ctx_t;

static uint64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static const char *
hook_point_name(n00b_vfs_hook_point_t p)
{
    switch (p) {
    case N00B_VFS_HOOK_PRE_OPEN:     return "pre_open";
    case N00B_VFS_HOOK_POST_OPEN:    return "post_open";
    case N00B_VFS_HOOK_PRE_READ:     return "pre_read";
    case N00B_VFS_HOOK_POST_READ:    return "post_read";
    case N00B_VFS_HOOK_PRE_WRITE:    return "pre_write";
    case N00B_VFS_HOOK_POST_WRITE:   return "post_write";
    case N00B_VFS_HOOK_PRE_CLOSE:    return "pre_close";
    case N00B_VFS_HOOK_POST_CLOSE:   return "post_close";
    case N00B_VFS_HOOK_PRE_DELETE:   return "pre_delete";
    case N00B_VFS_HOOK_PRE_RENAME:   return "pre_rename";
    case N00B_VFS_HOOK_PRE_MKDIR:    return "pre_mkdir";
    case N00B_VFS_HOOK_PRE_STAT:     return "pre_stat";
    case N00B_VFS_HOOK_ACCESS_CHECK: return "access_check";
    default:                          return "unknown";
    }
}

static void
journal_hook(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    journal_ctx_t *jc = cookie;

    uint64_t ts = now_ms();

    // Build NDJSON line.
    fprintf(jc->fp,
        "{\"ts\":%llu,\"op\":\"%s\",\"path\":\"%.*s\"",
        (unsigned long long)ts,
        hook_point_name(ctx->point),
        (int)(ctx->path ? ctx->path->u8_bytes : 0),
        ctx->path ? ctx->path->data : "");

    if (ctx->fh != 0) {
        fprintf(jc->fp, ",\"fh\":%llu", (unsigned long long)ctx->fh);
    }

    if (ctx->data != nullptr) {
        fprintf(jc->fp, ",\"data_len\":%llu",
                (unsigned long long)n00b_buffer_len(ctx->data));
    }

    if (ctx->offset > 0 || ctx->length > 0) {
        fprintf(jc->fp, ",\"offset\":%llu,\"length\":%llu",
                (unsigned long long)ctx->offset,
                (unsigned long long)ctx->length);
    }

    if (ctx->flags != 0) {
        fprintf(jc->fp, ",\"flags\":%u", ctx->flags);
    }

    if (ctx->rename_dst != nullptr) {
        fprintf(jc->fp, ",\"dst\":\"%.*s\"",
                (int)ctx->rename_dst->u8_bytes,
                ctx->rename_dst->data);
    }

    fprintf(jc->fp, "}\n");
    fflush(jc->fp);
}

static void
register_journal_hooks(n00b_vfs_mount_t *mount, journal_ctx_t *jc)
{
    // Register on every hook point.
    for (int i = 0; i < N00B_VFS_HOOK_COUNT_; i++) {
        n00b_vfs_hook_add(mount, (n00b_vfs_hook_point_t)i,
                          journal_hook, jc, 0);
    }
}

// ============================================================================
// Library-mode demo: exercise the VFS API directly
// ============================================================================

static void
run_demo(n00b_vfs_t *vfs)
{
    printf("\n--- Library-mode demo (no OS mount) ---\n\n");

    n00b_string_t *base = r"/src";

    // List the source directory.
    printf("Listing %.*s:\n", (int)base->u8_bytes, base->data);
    n00b_result_t(n00b_vfs_list_result_t *) lr =
        n00b_vfs_readdir(vfs, base, 50);
    if (n00b_result_is_ok(lr)) {
        n00b_vfs_list_result_t *list = n00b_result_get(lr);
        for (uint32_t i = 0; i < list->count; i++) {
            n00b_vfs_list_entry_t *e = &list->entries[i];
            printf("  %c %8llu  %.*s\n",
                   e->kind == N00B_VFS_OBJ_DIR ? 'd' : '-',
                   (unsigned long long)e->size,
                   (int)e->name->u8_bytes, e->name->data);
        }
        printf("  (%u entries)\n", list->count);
    }
    else {
        printf("  (readdir failed: %s)\n",
               n00b_vfs_err_name(n00b_result_get_err(lr)));
    }

    // Create a test file.
    n00b_string_t *test_path = r"/src/.vfs_journal_test";
    printf("\nCreating %.*s ...\n", (int)test_path->u8_bytes, test_path->data);

    n00b_result_t(n00b_vfs_fh_t) ofh =
        n00b_vfs_open(vfs, test_path, N00B_VFS_O_W);
    if (n00b_result_is_ok(ofh)) {
        n00b_vfs_fh_t fh = n00b_result_get(ofh);

        n00b_buffer_t *data = n00b_buffer_from_cstr(
            "Hello from VFS journal demo!\n");
        n00b_vfs_write(vfs, fh, data);
        printf("  Wrote %llu bytes\n",
               (unsigned long long)n00b_buffer_len(data));

        n00b_vfs_flush(vfs, fh);
        printf("  Flushed to backend\n");

        n00b_vfs_close(vfs, fh);
        printf("  Closed\n");
    }
    else {
        printf("  (create failed: %s)\n",
               n00b_vfs_err_name(n00b_result_get_err(ofh)));
    }

    // Read it back.
    printf("\nReading back ...\n");
    ofh = n00b_vfs_open(vfs, test_path, N00B_VFS_O_R);
    if (n00b_result_is_ok(ofh)) {
        n00b_vfs_fh_t fh = n00b_result_get(ofh);
        n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, fh, 4096);
        if (n00b_result_is_ok(rr)) {
            int64_t len;
            char *d = n00b_buffer_to_c(n00b_result_get(rr), &len);
            printf("  Got %lld bytes: %.*s",
                   (long long)len, (int)len, d);
        }
        n00b_vfs_close(vfs, fh);
    }

    // Stat it.
    printf("Stat:\n");
    n00b_result_t(n00b_vfs_obj_stat_t) sr = n00b_vfs_stat(vfs, test_path);
    if (n00b_result_is_ok(sr)) {
        n00b_vfs_obj_stat_t st = n00b_result_get(sr);
        printf("  size=%llu mode=%04o mtime=%llu\n",
               (unsigned long long)st.size,
               st.mode,
               (unsigned long long)st.mtime_ns / 1000000000ULL);
    }

    // Rename it.
    n00b_string_t *renamed = r"/src/.vfs_journal_renamed";
    printf("\nRenaming to %.*s ...\n",
           (int)renamed->u8_bytes, renamed->data);
    n00b_result_t(bool) rr = n00b_vfs_rename(vfs, test_path, renamed);
    printf("  %s\n", n00b_result_is_ok(rr) ? "OK" : "FAILED");

    // Delete it.
    printf("Deleting ...\n");
    rr = n00b_vfs_delete(vfs, renamed);
    printf("  %s\n", n00b_result_is_ok(rr) ? "OK" : "FAILED");

    // Truncate test.
    printf("\nTruncate test:\n");
    ofh = n00b_vfs_open(vfs, r"/src/.vfs_trunc_test",
                        N00B_VFS_O_W);
    if (n00b_result_is_ok(ofh)) {
        n00b_vfs_write(vfs, n00b_result_get(ofh),
                       n00b_buffer_from_cstr("1234567890"));
        n00b_vfs_close(vfs, n00b_result_get(ofh));

        n00b_vfs_truncate(vfs,
                          r"/src/.vfs_trunc_test", 5);

        sr = n00b_vfs_stat(vfs,
                           r"/src/.vfs_trunc_test");
        if (n00b_result_is_ok(sr)) {
            printf("  After truncate(5): size=%llu\n",
                   (unsigned long long)n00b_result_get(sr).size);
        }

        n00b_vfs_delete(vfs, r"/src/.vfs_trunc_test");
    }

    printf("\n--- Demo complete ---\n");
}

// ============================================================================
// Arg parsing
// ============================================================================

static void
usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --source <dir> [--mount <point>] [--journal <file>]\n"
        "\n"
        "  --source <dir>     Source directory to serve (required)\n"
        "  --mount <point>    Mount point (uses platform frontend)\n"
        "  --journal <file>   Journal file (default: stdout)\n"
        "\n"
        "If --mount is omitted, runs a library-mode demo.\n",
        prog);
}

// ============================================================================
// Signal handling for clean shutdown
// ============================================================================

static volatile sig_atomic_t g_shutdown = 0;

static void
sig_handler(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    const char *source_dir  = nullptr;
    const char *mount_point = nullptr;
    const char *journal_file = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--source") == 0 && i + 1 < argc) {
            source_dir = argv[++i];
        }
        else if (strcmp(argv[i], "--mount") == 0 && i + 1 < argc) {
            mount_point = argv[++i];
        }
        else if (strcmp(argv[i], "--journal") == 0 && i + 1 < argc) {
            journal_file = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (source_dir == nullptr) {
        usage(argv[0]);
        return 1;
    }

    // ── Set up journal ──

    journal_ctx_t jc = {};
    if (journal_file != nullptr) {
        jc.fp = fopen(journal_file, "a");
        if (jc.fp == nullptr) {
            fprintf(stderr, "Cannot open journal file: %s\n", journal_file);
            return 1;
        }
        jc.owns_fp = true;
        printf("Journaling to: %s\n", journal_file);
    }
    else {
        jc.fp = stdout;
        jc.owns_fp = false;
    }

    // ── Create backend ──

    n00b_string_t *src = n00b_string_from_cstr(source_dir);

    n00b_result_t(n00b_vfs_backend_t *) br = n00b_vfs_backend_local_new(src);
    if (n00b_result_is_err(br)) {
        fprintf(stderr, "Cannot open source directory: %s (%s)\n",
                source_dir,
                n00b_vfs_err_name(n00b_result_get_err(br)));
        return 1;
    }
    n00b_vfs_backend_t *be = n00b_result_get(br);

    // ── Create VFS + mount ──

    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());

    n00b_result_t(n00b_vfs_mount_t *) mr =
        n00b_vfs_mount(vfs, r"/src", be, 0);
    if (n00b_result_is_err(mr)) {
        fprintf(stderr, "Mount failed: %s\n",
                n00b_vfs_err_name(n00b_result_get_err(mr)));
        return 1;
    }
    n00b_vfs_mount_t *mount = n00b_result_get(mr);

    // ── Register journal hooks ──

    register_journal_hooks(mount, &jc);
    printf("Journal hooks registered on /src -> %s\n", source_dir);

    // ── Frontend or demo ──

    if (mount_point != nullptr) {
        // Try platform frontend.
        n00b_string_t *mp = n00b_string_from_cstr(mount_point);

        n00b_result_t(n00b_vfs_frontend_t *) fr =
            n00b_vfs_frontend_auto(vfs, mp);

        if (n00b_result_is_err(fr)) {
            fprintf(stderr,
                "No frontend available for this platform.\n"
                "  macOS: install macFUSE (https://osxfuse.github.io)\n"
                "  Linux: should work out of the box (NFSv3)\n"
                "\nFalling back to library-mode demo.\n\n");
            run_demo(vfs);
        }
        else {
            n00b_vfs_frontend_t *fe = n00b_result_get(fr);
            printf("Starting frontend: %.*s\n",
                   (int)fe->ops->name()->u8_bytes,
                   fe->ops->name()->data);
            printf("Mount point: %s\n", mount_point);

            n00b_result_t(bool) sr = n00b_vfs_frontend_start(fe);
            if (n00b_result_is_err(sr)) {
                fprintf(stderr, "Frontend start failed.\n");
                return 1;
            }

            printf("Serving. Press Ctrl-C to stop.\n");
            fflush(stdout);

            signal(SIGINT, sig_handler);
            signal(SIGTERM, sig_handler);

            while (!g_shutdown) {
                sleep(1);
            }

            printf("\nShutting down...\n");
            n00b_vfs_frontend_stop(fe);
        }
    }
    else {
        // Library-mode demo.
        run_demo(vfs);
    }

    // ── Cleanup ──

    n00b_vfs_destroy(vfs);

    if (jc.owns_fp) {
        fclose(jc.fp);
    }

    printf("Done.\n");
    n00b_shutdown();
    return 0;
}

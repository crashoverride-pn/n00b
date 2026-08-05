#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <direct.h>
#include <process.h>
#else
#include <unistd.h>
#endif
#include <sys/stat.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "test_portability.h"
#include "vfs/vfs.h"
#include "vfs/backend_local.h"

// ============================================================================
// Journal hook (same as the daemon's, but captures to a buffer)
// ============================================================================

#define MAX_JOURNAL_LINES 64
#define MAX_LINE_LEN      512

static char  journal_lines[MAX_JOURNAL_LINES][MAX_LINE_LEN];
static int   journal_count = 0;

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
    (void)cookie;
    if (journal_count >= MAX_JOURNAL_LINES) return;

    snprintf(journal_lines[journal_count], MAX_LINE_LEN,
             "%s:%.*s",
             hook_point_name(ctx->point),
             (int)(ctx->path ? ctx->path->u8_bytes : 0),
             ctx->path ? ctx->path->data : "");
    journal_count++;
}

static void
register_hooks(n00b_vfs_mount_t *m)
{
    for (int i = 0; i < N00B_VFS_HOOK_COUNT_; i++) {
        n00b_vfs_hook_add(m, (n00b_vfs_hook_point_t)i,
                          journal_hook, nullptr, 0);
    }
}

static void
reset_journal(void)
{
    journal_count = 0;
}

static bool
journal_contains(const char *op, const char *path)
{
    char needle[MAX_LINE_LEN];
    snprintf(needle, sizeof(needle), "%s:%s", op, path);
    for (int i = 0; i < journal_count; i++) {
        if (strcmp(journal_lines[i], needle) == 0) return true;
    }
    return false;
}

// ============================================================================
// Helpers
// ============================================================================

static char tmp_dir[256];
#ifdef _WIN32
static int  tmp_dir_id = 0;
#endif

#ifdef _WIN32
static void
remove_child(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", tmp_dir, name);
    (void)remove(path);
}
#endif

static void
make_tmpdir(void)
{
#ifdef _WIN32
    snprintf(tmp_dir, sizeof(tmp_dir),
             "n00b_vfs_journal_%d_%d", _getpid(), tmp_dir_id++);
    assert(_mkdir(tmp_dir) == 0);
#else
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/n00b_vfs_journal_XXXXXX");
    assert(mkdtemp(tmp_dir) != nullptr);
#endif
}

static void
rm_tmpdir(void)
{
#ifdef _WIN32
    remove_child("test.txt");
    remove_child("read.txt");
    remove_child("del.txt");
    remove_child("old.txt");
    remove_child("new.txt");
    remove_child("stat.txt");
    remove_child("round.txt");
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/subdir", tmp_dir);
        (void)_rmdir(path);
    }
    (void)_rmdir(tmp_dir);
#else
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
    (void)system(cmd);
#endif
}

// ============================================================================
// 1. Write+close journals pre/post open, write, close
// ============================================================================

static void
test_write_journal(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    reset_journal();

    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/test.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("hello"));
    n00b_vfs_close(vfs, fh);

    assert(journal_contains("pre_open", "/d/test.txt"));
    assert(journal_contains("post_open", "/d/test.txt"));
    assert(journal_contains("pre_write", "/d/test.txt"));
    assert(journal_contains("post_write", "/d/test.txt"));
    assert(journal_contains("pre_close", "/d/test.txt"));
    assert(journal_contains("post_close", "/d/test.txt"));

    // Verify file actually landed on disk.
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/test.txt", tmp_dir);
    struct stat st;
    assert(stat(fpath, &st) == 0);
    assert(st.st_size == 5);

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] write_journal\n");
}

// ============================================================================
// 2. Read journals pre/post read
// ============================================================================

static void
test_read_journal(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    // Write a file first (not journaled — reset after).
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/read.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("read me"));
    n00b_vfs_close(vfs, wfh);

    reset_journal();

    // Now read it.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/read.txt"), N00B_VFS_O_R));
    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));

    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 7);
    assert(memcmp(data, "read me", 7) == 0);

    n00b_vfs_close(vfs, rfh);

    assert(journal_contains("pre_open", "/d/read.txt"));
    assert(journal_contains("pre_read", "/d/read.txt"));
    assert(journal_contains("post_read", "/d/read.txt"));
    assert(journal_contains("pre_close", "/d/read.txt"));

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] read_journal\n");
}

// ============================================================================
// 3. Delete journals pre_delete
// ============================================================================

static void
test_delete_journal(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    // Create file.
    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/del.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("x"));
    n00b_vfs_close(vfs, fh);

    reset_journal();

    n00b_result_t(bool) dr =
        n00b_vfs_delete(vfs, n00b_string_from_cstr("/d/del.txt"));
    assert(n00b_result_is_ok(dr));

    assert(journal_contains("pre_delete", "/d/del.txt"));

    // Verify gone from disk.
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/del.txt", tmp_dir);
    struct stat st;
    assert(stat(fpath, &st) != 0);

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] delete_journal\n");
}

// ============================================================================
// 4. Rename journals pre_rename with destination
// ============================================================================

static void
test_rename_journal(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    // Create file.
    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/old.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("move me"));
    n00b_vfs_close(vfs, fh);

    reset_journal();

    n00b_result_t(bool) rr = n00b_vfs_rename(
        vfs, n00b_string_from_cstr("/d/old.txt"),
        n00b_string_from_cstr("/d/new.txt"));
    assert(n00b_result_is_ok(rr));

    assert(journal_contains("pre_rename", "/d/old.txt"));

    // Verify on disk.
    char old_path[512], new_path[512];
    snprintf(old_path, sizeof(old_path), "%s/old.txt", tmp_dir);
    snprintf(new_path, sizeof(new_path), "%s/new.txt", tmp_dir);
    struct stat st;
    assert(stat(old_path, &st) != 0);
    assert(stat(new_path, &st) == 0);

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] rename_journal\n");
}

// ============================================================================
// 5. Stat journals pre_stat
// ============================================================================

static void
test_stat_journal(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    // Create file.
    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/stat.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("stat me"));
    n00b_vfs_close(vfs, fh);

    reset_journal();

    n00b_result_t(n00b_vfs_obj_stat_t) sr =
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/d/stat.txt"));
    assert(n00b_result_is_ok(sr));
    assert(n00b_result_get(sr).size == 7);

    assert(journal_contains("pre_stat", "/d/stat.txt"));

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] stat_journal\n");
}

// ============================================================================
// 6. Mkdir journals pre_mkdir
// ============================================================================

static void
test_mkdir_journal(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    reset_journal();

    n00b_result_t(bool) mr =
        n00b_vfs_mkdir(vfs, n00b_string_from_cstr("/d/subdir"));
    assert(n00b_result_is_ok(mr));

    assert(journal_contains("pre_mkdir", "/d/subdir"));

    // Verify on disk.
    char dpath[512];
    snprintf(dpath, sizeof(dpath), "%s/subdir", tmp_dir);
    struct stat st;
    assert(stat(dpath, &st) == 0);
    assert(S_ISDIR(st.st_mode));

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] mkdir_journal\n");
}

// ============================================================================
// 7. Full round-trip: write, flush, read, verify data on disk
// ============================================================================

static void
test_full_roundtrip(void)
{
    make_tmpdir();
    n00b_vfs_backend_t *be = n00b_result_get(
        n00b_vfs_backend_local_new(n00b_string_from_cstr(tmp_dir)));
    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount_t *m = n00b_result_get(
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/d"), be, 0));
    register_hooks(m);

    reset_journal();

    // Write.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/round.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("round trip data"));

    // Flush without close.
    n00b_result_t(bool) fr = n00b_vfs_flush(vfs, wfh);
    assert(n00b_result_is_ok(fr));

    // Verify on disk after flush (before close).
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/round.txt", tmp_dir);
    struct stat st;
    assert(stat(fpath, &st) == 0);
    assert(st.st_size == 15);

    n00b_vfs_close(vfs, wfh);

    // Read back via VFS.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/d/round.txt"), N00B_VFS_O_R));
    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));

    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 15);
    assert(memcmp(data, "round trip data", 15) == 0);
    n00b_vfs_close(vfs, rfh);

    // Verify journal captured the full lifecycle.
    assert(journal_count >= 8);  // open, write, close x2 + read
    assert(journal_contains("pre_open", "/d/round.txt"));
    assert(journal_contains("pre_write", "/d/round.txt"));
    assert(journal_contains("post_write", "/d/round.txt"));
    assert(journal_contains("pre_read", "/d/round.txt"));
    assert(journal_contains("post_read", "/d/round.txt"));

    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] full_roundtrip\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running VFS journal tests...\n");

    test_write_journal();
    test_read_journal();
    test_delete_journal();
    test_rename_journal();
    test_stat_journal();
    test_mkdir_journal();
    test_full_roundtrip();

    printf("All VFS journal tests passed.\n");
    n00b_shutdown();
    return 0;
}

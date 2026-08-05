#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <direct.h>
#include "internal/win32_sockets.h"
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "vfs/vfs.h"
#include "vfs/backend_local.h"

// ============================================================================
// Helpers
// ============================================================================

static char tmp_dir[256];

static void
make_tmpdir(void)
{
#ifdef _WIN32
    snprintf(tmp_dir, sizeof(tmp_dir), "n00b_vfs_local_%lu",
             (unsigned long)GetCurrentProcessId());
    assert(_mkdir(tmp_dir) == 0);
#else
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/n00b_vfs_local_XXXXXX");
    assert(mkdtemp(tmp_dir) != nullptr);
#endif
}

static void
rm_tmpdir(void)
{
    char cmd[512];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "rmdir /S /Q %s", tmp_dir);
#else
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
#endif
    (void)system(cmd);
}

// ============================================================================
// 1. Local backend put + get
// ============================================================================

static void
test_local_put_get(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);

    n00b_result_t(n00b_vfs_backend_t *) br = n00b_vfs_backend_local_new(root);
    assert(n00b_result_is_ok(br));
    n00b_vfs_backend_t *be = n00b_result_get(br);

    n00b_string_t *path = n00b_string_from_cstr("test.txt");

    n00b_result_t(bool) pr = be->ops->put(be->ctx, path,
        n00b_buffer_from_cstr("local data"));
    assert(n00b_result_is_ok(pr));

    // Verify file exists on disk.
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/test.txt", tmp_dir);
    struct stat st;
    assert(stat(fpath, &st) == 0);
    assert(st.st_size == 10);

    // Get it back.
    n00b_result_t(n00b_buffer_t *) gr = be->ops->get(be->ctx, path);
    assert(n00b_result_is_ok(gr));

    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(gr), &len);
    assert(len == 10);
    assert(memcmp(data, "local data", 10) == 0);

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_put_get\n");
}

// ============================================================================
// 2. Local backend stat
// ============================================================================

static void
test_local_stat(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    be->ops->put(be->ctx, n00b_string_from_cstr("stat.txt"),
                 n00b_buffer_from_cstr("twelve bytes"));

    n00b_result_t(n00b_vfs_obj_stat_t) sr =
        be->ops->stat(be->ctx, n00b_string_from_cstr("stat.txt"));
    assert(n00b_result_is_ok(sr));

    n00b_vfs_obj_stat_t st = n00b_result_get(sr);
    assert(st.kind == N00B_VFS_OBJ_FILE);
    assert(st.size == 12);
    assert(st.mtime_ns > 0);

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_stat\n");
}

// ============================================================================
// 3. Local backend mkdir + list
// ============================================================================

static void
test_local_mkdir_list(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    n00b_result_t(bool) mr = be->ops->mkdir(be->ctx,
        n00b_string_from_cstr("subdir"));
    assert(n00b_result_is_ok(mr));

    // Write a file in the subdir.
    be->ops->put(be->ctx, n00b_string_from_cstr("subdir/file.txt"),
                 n00b_buffer_from_cstr("nested"));

    // List the subdir.
    n00b_result_t(n00b_vfs_list_result_t *) lr =
        be->ops->list(be->ctx, n00b_string_from_cstr("subdir"), nullptr, 100);
    assert(n00b_result_is_ok(lr));
    assert(n00b_result_get(lr)->count == 1);

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_mkdir_list\n");
}

// ============================================================================
// 4. Local backend delete
// ============================================================================

static void
test_local_delete(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    n00b_string_t *path = n00b_string_from_cstr("del.txt");
    be->ops->put(be->ctx, path, n00b_buffer_from_cstr("x"));

    n00b_result_t(bool) dr = be->ops->del(be->ctx, path);
    assert(n00b_result_is_ok(dr));

    n00b_result_t(n00b_buffer_t *) gr = be->ops->get(be->ctx, path);
    assert(n00b_result_is_err(gr));

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_delete\n");
}

// ============================================================================
// 5. Local backend rename
// ============================================================================

static void
test_local_rename(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    n00b_string_t *old_path = n00b_string_from_cstr("old.txt");
    n00b_string_t *new_path = n00b_string_from_cstr("new.txt");

    be->ops->put(be->ctx, old_path, n00b_buffer_from_cstr("moved"));

    n00b_result_t(bool) rr = be->ops->rename(be->ctx, old_path, new_path);
    assert(n00b_result_is_ok(rr));

    assert(n00b_result_is_err(be->ops->get(be->ctx, old_path)));
    assert(n00b_result_is_ok(be->ops->get(be->ctx, new_path)));

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_rename\n");
}

// ============================================================================
// 6. Local backend hard link
// ============================================================================

static void
test_local_link(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    n00b_string_t *target = n00b_string_from_cstr("original.txt");
    n00b_string_t *lnk    = n00b_string_from_cstr("linked.txt");

    be->ops->put(be->ctx, target, n00b_buffer_from_cstr("shared"));

    assert(be->ops->supports_link(be->ctx));

    n00b_result_t(bool) lr = be->ops->link(be->ctx, target, lnk);
    assert(n00b_result_is_ok(lr));

    // Both should return the same data.
    n00b_result_t(n00b_buffer_t *) gr1 = be->ops->get(be->ctx, target);
    n00b_result_t(n00b_buffer_t *) gr2 = be->ops->get(be->ctx, lnk);
    assert(n00b_result_is_ok(gr1));
    assert(n00b_result_is_ok(gr2));

    int64_t l1, l2;
    char *d1 = n00b_buffer_to_c(n00b_result_get(gr1), &l1);
    char *d2 = n00b_buffer_to_c(n00b_result_get(gr2), &l2);
    assert(l1 == l2);
    assert(memcmp(d1, d2, (size_t)l1) == 0);

    // Verify they're the same inode.
    char p1[512], p2[512];
    snprintf(p1, sizeof(p1), "%s/original.txt", tmp_dir);
    snprintf(p2, sizeof(p2), "%s/linked.txt", tmp_dir);
    struct stat s1, s2;
    assert(stat(p1, &s1) == 0);
    assert(stat(p2, &s2) == 0);
#ifndef _WIN32
    assert(s1.st_ino == s2.st_ino);
#endif

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_link\n");
}

// ============================================================================
// 7. VFS integration with local backend
// ============================================================================

static void
test_vfs_local_roundtrip(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    n00b_vfs_t *vfs = n00b_result_get(n00b_vfs_new());
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/local"), be, 0);

    // Write through VFS.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/local/vfs.txt"),
                      N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("via vfs"));
    n00b_vfs_close(vfs, wfh);

    // Verify on disk.
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/vfs.txt", tmp_dir);
    struct stat st;
    assert(stat(fpath, &st) == 0);
    assert(st.st_size == 7);

    // Read back through VFS.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/local/vfs.txt"),
                      N00B_VFS_O_R));
    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));

    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 7);
    assert(memcmp(data, "via vfs", 7) == 0);

    n00b_vfs_close(vfs, rfh);
    n00b_vfs_destroy(vfs);
    rm_tmpdir();
    printf("  [PASS] vfs_local_roundtrip\n");
}

// ============================================================================
// 8. Get range on local backend
// ============================================================================

static void
test_local_get_range(void)
{
    make_tmpdir();
    n00b_string_t *root = n00b_string_from_cstr(tmp_dir);
    n00b_vfs_backend_t *be = n00b_result_get(n00b_vfs_backend_local_new(root));

    be->ops->put(be->ctx, n00b_string_from_cstr("range.txt"),
                 n00b_buffer_from_cstr("hello world"));

    n00b_result_t(n00b_buffer_t *) gr =
        be->ops->get_range(be->ctx, n00b_string_from_cstr("range.txt"), 6, 5);
    assert(n00b_result_is_ok(gr));

    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(gr), &len);
    assert(len == 5);
    assert(memcmp(data, "world", 5) == 0);

    n00b_vfs_backend_cleanup(be);
    rm_tmpdir();
    printf("  [PASS] local_get_range\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running VFS local backend tests...\n");

    test_local_put_get();
    test_local_stat();
    test_local_mkdir_list();
    test_local_delete();
    test_local_rename();
    test_local_link();
    test_vfs_local_roundtrip();
    test_local_get_range();

    printf("All VFS local backend tests passed.\n");
    n00b_shutdown();
    return 0;
}

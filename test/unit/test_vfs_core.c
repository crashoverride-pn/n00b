#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "vfs/vfs.h"
#include "vfs/backend_memory.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_vfs_t *
make_vfs(void)
{
    n00b_result_t(n00b_vfs_t *) r = n00b_vfs_new();
    assert(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_vfs_backend_t *
make_backend(void)
{
    n00b_result_t(n00b_vfs_backend_t *) r = n00b_vfs_backend_memory_new();
    assert(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// ============================================================================
// 1. Mount and unmount
// ============================================================================

static void
test_mount_unmount(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();

    n00b_result_t(n00b_vfs_mount_t *) mr =
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/data"), be, 0);
    assert(n00b_result_is_ok(mr));

    // Duplicate mount should fail.
    n00b_vfs_backend_t *be2 = make_backend();
    mr = n00b_vfs_mount(vfs, n00b_string_from_cstr("/data"), be2, 0);
    assert(n00b_result_is_err(mr));
    assert(n00b_result_get_err(mr) == N00B_VFS_ERR_EXISTS);

    // Unmount.
    n00b_result_t(bool) ur =
        n00b_vfs_unmount(vfs, n00b_string_from_cstr("/data"));
    assert(n00b_result_is_ok(ur));

    // Unmount again should fail.
    ur = n00b_vfs_unmount(vfs, n00b_string_from_cstr("/data"));
    assert(n00b_result_is_err(ur));

    n00b_vfs_destroy(vfs);
    printf("  [PASS] mount_unmount\n");
}

// ============================================================================
// 2. Open, write, close, read round-trip
// ============================================================================

static void
test_open_write_read(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    // Write a file.
    n00b_result_t(n00b_vfs_fh_t) or = n00b_vfs_open(
        vfs, n00b_string_from_cstr("/hello.txt"), N00B_VFS_O_W);
    assert(n00b_result_is_ok(or));
    n00b_vfs_fh_t wfh = n00b_result_get(or);

    n00b_result_t(uint64_t) wr =
        n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("hello world"));
    assert(n00b_result_is_ok(wr));
    assert(n00b_result_get(wr) == 11);

    n00b_result_t(bool) cr = n00b_vfs_close(vfs, wfh);
    assert(n00b_result_is_ok(cr));

    // Read it back.
    or = n00b_vfs_open(vfs, n00b_string_from_cstr("/hello.txt"), N00B_VFS_O_R);
    assert(n00b_result_is_ok(or));
    n00b_vfs_fh_t rfh = n00b_result_get(or);

    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));

    n00b_buffer_t *buf = n00b_result_get(rr);
    int64_t len;
    char *data = n00b_buffer_to_c(buf, &len);
    assert(len == 11);
    assert(memcmp(data, "hello world", 11) == 0);

    n00b_vfs_close(vfs, rfh);
    n00b_vfs_destroy(vfs);
    printf("  [PASS] open_write_read\n");
}

// ============================================================================
// 3. Open non-existent file without CREATE fails
// ============================================================================

static void
test_open_not_found(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    n00b_result_t(n00b_vfs_fh_t) or = n00b_vfs_open(
        vfs, n00b_string_from_cstr("/nope.txt"), N00B_VFS_O_R);
    assert(n00b_result_is_err(or));
    assert(n00b_result_get_err(or) == N00B_VFS_ERR_NOT_FOUND);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] open_not_found\n");
}

// ============================================================================
// 4. Seek
// ============================================================================

static void
test_seek(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    // Write file.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/seek.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("abcdefghij"));
    n00b_vfs_close(vfs, wfh);

    // Read with seeking.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/seek.txt"), N00B_VFS_O_R));

    // SEEK_SET to 5.
    n00b_result_t(uint64_t) sr = n00b_vfs_seek(vfs, rfh, 5, 0);
    assert(n00b_result_is_ok(sr));
    assert(n00b_result_get(sr) == 5);

    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 5);
    assert(n00b_result_is_ok(rr));
    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 5);
    assert(memcmp(data, "fghij", 5) == 0);

    // SEEK_SET back to 0, read 3.
    n00b_vfs_seek(vfs, rfh, 0, 0);
    rr = n00b_vfs_read(vfs, rfh, 3);
    data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 3);
    assert(memcmp(data, "abc", 3) == 0);

    // SEEK_CUR +2.
    sr = n00b_vfs_seek(vfs, rfh, 2, 1);
    assert(n00b_result_get(sr) == 5);  // was at 3, +2 = 5

    n00b_vfs_close(vfs, rfh);
    n00b_vfs_destroy(vfs);
    printf("  [PASS] seek\n");
}

// ============================================================================
// 5. Path resolution with multiple mounts
// ============================================================================

static void
test_path_resolution(void)
{
    n00b_vfs_t *vfs = make_vfs();

    n00b_vfs_backend_t *be_root = make_backend();
    n00b_vfs_backend_t *be_data = make_backend();

    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be_root, 0);
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/data"), be_data, 0);

    // Write to /data/x.txt — should go to be_data backend.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/data/x.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("data-content"));
    n00b_vfs_close(vfs, wfh);

    // Write to /root.txt — should go to be_root backend.
    wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/root.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("root-content"));
    n00b_vfs_close(vfs, wfh);

    // Verify /data/x.txt is in be_data, not be_root.
    n00b_result_t(n00b_buffer_t *) gr =
        be_data->ops->get(be_data->ctx, n00b_string_from_cstr("x.txt"));
    assert(n00b_result_is_ok(gr));
    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(gr), &len);
    assert(memcmp(data, "data-content", 12) == 0);

    // Verify /root.txt is in be_root.
    gr = be_root->ops->get(be_root->ctx, n00b_string_from_cstr("root.txt"));
    assert(n00b_result_is_ok(gr));
    data = n00b_buffer_to_c(n00b_result_get(gr), &len);
    assert(memcmp(data, "root-content", 12) == 0);

    // /data/x.txt should NOT be in be_root.
    gr = be_root->ops->get(be_root->ctx, n00b_string_from_cstr("data/x.txt"));
    assert(n00b_result_is_err(gr));

    n00b_vfs_destroy(vfs);
    printf("  [PASS] path_resolution\n");
}

// ============================================================================
// 6. Stat via VFS
// ============================================================================

static void
test_stat(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    // Write a file.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/stat.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("twelve bytes"));
    n00b_vfs_close(vfs, wfh);

    n00b_result_t(n00b_vfs_obj_stat_t) sr =
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/stat.txt"));
    assert(n00b_result_is_ok(sr));

    n00b_vfs_obj_stat_t st = n00b_result_get(sr);
    assert(st.kind == N00B_VFS_OBJ_FILE);
    assert(st.size == 12);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] stat\n");
}

// ============================================================================
// 7. Readdir via VFS
// ============================================================================

static void
test_readdir(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    // Create some files.
    n00b_vfs_fh_t fh;
    fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/a.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("a"));
    n00b_vfs_close(vfs, fh);

    fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/b.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("bb"));
    n00b_vfs_close(vfs, fh);

    n00b_result_t(n00b_vfs_list_result_t *) lr =
        n00b_vfs_readdir(vfs, n00b_string_from_cstr("/"), 100);
    assert(n00b_result_is_ok(lr));
    assert(n00b_result_get(lr)->count == 2);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] readdir\n");
}

// ============================================================================
// 8. Mkdir via VFS
// ============================================================================

static void
test_mkdir(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    n00b_result_t(bool) mr =
        n00b_vfs_mkdir(vfs, n00b_string_from_cstr("/mydir"));
    assert(n00b_result_is_ok(mr));

    n00b_result_t(n00b_vfs_obj_stat_t) sr =
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/mydir"));
    assert(n00b_result_is_ok(sr));
    assert(n00b_result_get(sr).kind == N00B_VFS_OBJ_DIR);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] mkdir\n");
}

// ============================================================================
// 9. Delete via VFS
// ============================================================================

static void
test_delete(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/del.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("x"));
    n00b_vfs_close(vfs, fh);

    n00b_result_t(bool) dr =
        n00b_vfs_delete(vfs, n00b_string_from_cstr("/del.txt"));
    assert(n00b_result_is_ok(dr));

    n00b_result_t(n00b_vfs_obj_stat_t) sr =
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/del.txt"));
    assert(n00b_result_is_err(sr));

    n00b_vfs_destroy(vfs);
    printf("  [PASS] delete\n");
}

// ============================================================================
// 10. Rename via VFS
// ============================================================================

static void
test_rename(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/old.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("content"));
    n00b_vfs_close(vfs, fh);

    n00b_result_t(bool) rr = n00b_vfs_rename(
        vfs, n00b_string_from_cstr("/old.txt"),
        n00b_string_from_cstr("/new.txt"));
    assert(n00b_result_is_ok(rr));

    // Old path should be gone.
    assert(n00b_result_is_err(
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/old.txt"))));

    // New path should exist.
    assert(n00b_result_is_ok(
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/new.txt"))));

    n00b_vfs_destroy(vfs);
    printf("  [PASS] rename\n");
}

// ============================================================================
// 11. Cross-mount rename fails
// ============================================================================

static void
test_rename_cross_mount(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/a"), make_backend(), 0);
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/b"), make_backend(), 0);

    // Create file in /a.
    n00b_vfs_fh_t fh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/a/file.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, fh, n00b_buffer_from_cstr("x"));
    n00b_vfs_close(vfs, fh);

    n00b_result_t(bool) rr = n00b_vfs_rename(
        vfs, n00b_string_from_cstr("/a/file.txt"),
        n00b_string_from_cstr("/b/file.txt"));
    assert(n00b_result_is_err(rr));
    assert(n00b_result_get_err(rr) == N00B_VFS_ERR_CROSS_DEVICE);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] rename_cross_mount\n");
}

// ============================================================================
// 12. Hook denies open
// ============================================================================

static void
deny_hook(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    (void)cookie;
    ctx->denied   = true;
    ctx->deny_err = N00B_VFS_ERR_PERMISSION;
}

static void
test_hook_deny(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();

    n00b_result_t(n00b_vfs_mount_t *) mr =
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);
    n00b_vfs_mount_t *m = n00b_result_get(mr);

    n00b_vfs_hook_add(m, N00B_VFS_HOOK_PRE_OPEN, deny_hook, nullptr, 0);

    n00b_result_t(n00b_vfs_fh_t) or = n00b_vfs_open(
        vfs, n00b_string_from_cstr("/denied.txt"), N00B_VFS_O_W);
    assert(n00b_result_is_err(or));
    assert(n00b_result_get_err(or) == N00B_VFS_ERR_PERMISSION);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] hook_deny\n");
}

// ============================================================================
// 13. Hook transforms read data
// ============================================================================

static void
upcase_hook(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    (void)cookie;
    if (ctx->data == nullptr) {
        return;
    }

    int64_t len;
    char *data = n00b_buffer_to_c(ctx->data, &len);

    for (int64_t i = 0; i < len; i++) {
        if (data[i] >= 'a' && data[i] <= 'z') {
            data[i] -= 32;
        }
    }
}

static void
test_hook_transform(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();

    n00b_result_t(n00b_vfs_mount_t *) mr =
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);
    n00b_vfs_mount_t *m = n00b_result_get(mr);

    n00b_vfs_hook_add(m, N00B_VFS_HOOK_POST_READ, upcase_hook, nullptr, 0);

    // Write lowercase data.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/xform.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("hello"));
    n00b_vfs_close(vfs, wfh);

    // Read back — should be uppercase.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/xform.txt"), N00B_VFS_O_R));

    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));

    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 5);
    assert(memcmp(data, "HELLO", 5) == 0);

    n00b_vfs_close(vfs, rfh);
    n00b_vfs_destroy(vfs);
    printf("  [PASS] hook_transform\n");
}

// ============================================================================
// 14. Read-only mount rejects writes
// ============================================================================

static void
test_readonly_mount(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();

    // Pre-populate data in backend directly.
    be->ops->put(be->ctx, n00b_string_from_cstr("ro.txt"),
                 n00b_buffer_from_cstr("read-only"));

    n00b_vfs_mount(vfs, n00b_string_from_cstr("/ro"), be,
                   N00B_VFS_MOUNT_READONLY);

    // Read should work.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/ro/ro.txt"), N00B_VFS_O_R));
    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));
    n00b_vfs_close(vfs, rfh);

    // Write should fail.
    n00b_result_t(n00b_vfs_fh_t) or = n00b_vfs_open(
        vfs, n00b_string_from_cstr("/ro/new.txt"), N00B_VFS_O_W);
    assert(n00b_result_is_err(or));
    assert(n00b_result_get_err(or) == N00B_VFS_ERR_READ_ONLY);

    // Delete should fail.
    n00b_result_t(bool) dr =
        n00b_vfs_delete(vfs, n00b_string_from_cstr("/ro/ro.txt"));
    assert(n00b_result_is_err(dr));
    assert(n00b_result_get_err(dr) == N00B_VFS_ERR_READ_ONLY);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] readonly_mount\n");
}

// ============================================================================
// 15. Close without handle fails
// ============================================================================

static void
test_invalid_handle(void)
{
    n00b_vfs_t *vfs = make_vfs();

    n00b_result_t(bool) r = n00b_vfs_close(vfs, 999);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_VFS_ERR_INVALID_HANDLE);

    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, 999, 10);
    assert(n00b_result_is_err(rr));

    n00b_vfs_destroy(vfs);
    printf("  [PASS] invalid_handle\n");
}

// ============================================================================
// 16. No mount for path
// ============================================================================

static void
test_no_mount(void)
{
    n00b_vfs_t *vfs = make_vfs();

    n00b_result_t(n00b_vfs_fh_t) or = n00b_vfs_open(
        vfs, n00b_string_from_cstr("/nothing"), N00B_VFS_O_R);
    assert(n00b_result_is_err(or));
    assert(n00b_result_get_err(or) == N00B_VFS_ERR_MOUNT);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] no_mount\n");
}

// ============================================================================
// 17. Hook priority ordering
// ============================================================================

static int priority_log[4];
static int priority_ix;

static void
priority_hook_a(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    (void)ctx;
    (void)cookie;
    priority_log[priority_ix++] = 1;
}

static void
priority_hook_b(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    (void)ctx;
    (void)cookie;
    priority_log[priority_ix++] = 2;
}

static void
priority_hook_c(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    (void)ctx;
    (void)cookie;
    priority_log[priority_ix++] = 3;
}

static void
test_hook_priority(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();

    n00b_result_t(n00b_vfs_mount_t *) mr =
        n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);
    n00b_vfs_mount_t *m = n00b_result_get(mr);

    // Register in non-priority order: B(10), A(0), C(20).
    n00b_vfs_hook_add(m, N00B_VFS_HOOK_PRE_STAT, priority_hook_b, nullptr, 10);
    n00b_vfs_hook_add(m, N00B_VFS_HOOK_PRE_STAT, priority_hook_a, nullptr, 0);
    n00b_vfs_hook_add(m, N00B_VFS_HOOK_PRE_STAT, priority_hook_c, nullptr, 20);

    // Pre-populate so stat succeeds.
    be->ops->put(be->ctx, n00b_string_from_cstr("p.txt"),
                 n00b_buffer_from_cstr("x"));

    priority_ix = 0;
    n00b_vfs_stat(vfs, n00b_string_from_cstr("/p.txt"));

    // Should have run in priority order: A(0), B(10), C(20) -> 1, 2, 3.
    assert(priority_ix == 3);
    assert(priority_log[0] == 1);
    assert(priority_log[1] == 2);
    assert(priority_log[2] == 3);

    n00b_vfs_destroy(vfs);
    printf("  [PASS] hook_priority\n");
}

// ============================================================================
// 18. Truncate
// ============================================================================

static void
test_truncate(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    // Write 10 bytes.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/trunc.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("1234567890"));
    n00b_vfs_close(vfs, wfh);

    // Truncate to 5.
    n00b_result_t(bool) tr = n00b_vfs_truncate(
        vfs, n00b_string_from_cstr("/trunc.txt"), 5);
    assert(n00b_result_is_ok(tr));

    // Verify size.
    n00b_result_t(n00b_vfs_obj_stat_t) sr =
        n00b_vfs_stat(vfs, n00b_string_from_cstr("/trunc.txt"));
    assert(n00b_result_is_ok(sr));
    assert(n00b_result_get(sr).size == 5);

    // Read and verify content.
    n00b_vfs_fh_t rfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/trunc.txt"), N00B_VFS_O_R));
    n00b_result_t(n00b_buffer_t *) rr = n00b_vfs_read(vfs, rfh, 100);
    assert(n00b_result_is_ok(rr));
    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(rr), &len);
    assert(len == 5);
    assert(memcmp(data, "12345", 5) == 0);

    n00b_vfs_close(vfs, rfh);
    n00b_vfs_destroy(vfs);
    printf("  [PASS] truncate\n");
}

// ============================================================================
// 19. Flush
// ============================================================================

static void
test_flush(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    // Open for write, write data, flush without closing.
    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs, n00b_string_from_cstr("/flush.txt"), N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("flushed"));

    // Before flush, backend should NOT have data (it's buffered).
    n00b_result_t(n00b_buffer_t *) br =
        be->ops->get(be->ctx, n00b_string_from_cstr("flush.txt"));
    assert(n00b_result_is_err(br));

    // Flush.
    n00b_result_t(bool) fr = n00b_vfs_flush(vfs, wfh);
    assert(n00b_result_is_ok(fr));

    // Now backend should have it.
    br = be->ops->get(be->ctx, n00b_string_from_cstr("flush.txt"));
    assert(n00b_result_is_ok(br));
    int64_t len;
    char *data = n00b_buffer_to_c(n00b_result_get(br), &len);
    assert(len == 7);
    assert(memcmp(data, "flushed", 7) == 0);

    n00b_vfs_close(vfs, wfh);
    n00b_vfs_destroy(vfs);
    printf("  [PASS] flush\n");
}

// ============================================================================
// 20. Close frees committed write buffer
// ============================================================================

static void
test_close_frees_write_buffer(void)
{
    n00b_vfs_t *vfs = make_vfs();
    n00b_vfs_backend_t *be = make_backend();
    n00b_vfs_mount(vfs, n00b_string_from_cstr("/"), be, 0);

    n00b_vfs_fh_t wfh = n00b_result_get(
        n00b_vfs_open(vfs,
                      n00b_string_from_cstr("/close-free.txt"),
                      N00B_VFS_O_W));
    n00b_vfs_write(vfs, wfh, n00b_buffer_from_cstr("close frees"));

    n00b_vfs_handle_t *handle = vfs->handles[wfh - 1];
    assert(handle != nullptr);
    assert(handle->write_buf != nullptr);

    n00b_result_t(bool) fr = n00b_vfs_flush(vfs, wfh);
    assert(n00b_result_is_ok(fr));
    assert(handle->write_buf != nullptr);

    n00b_result_t(bool) cr = n00b_vfs_close(vfs, wfh);
    assert(n00b_result_is_ok(cr));
    assert(handle->state == N00B_VFS_HANDLE_CLOSED);
    assert(handle->write_buf == nullptr);

    n00b_result_t(n00b_vfs_fh_t) rr =
        n00b_vfs_open(vfs,
                      n00b_string_from_cstr("/close-free.txt"),
                      N00B_VFS_O_R);
    assert(n00b_result_is_ok(rr));

    n00b_vfs_destroy(vfs);
    printf("  [PASS] close_frees_write_buffer\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running VFS core tests...\n");

    test_mount_unmount();
    test_open_write_read();
    test_open_not_found();
    test_seek();
    test_path_resolution();
    test_stat();
    test_readdir();
    test_mkdir();
    test_delete();
    test_rename();
    test_rename_cross_mount();
    test_hook_deny();
    test_hook_transform();
    test_readonly_mount();
    test_invalid_handle();
    test_no_mount();
    test_hook_priority();
    test_truncate();
    test_flush();
    test_close_frees_write_buffer();

    printf("All VFS core tests passed.\n");
    n00b_shutdown();
    return 0;
}

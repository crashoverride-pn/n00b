/**
 * FUSE frontend — maps FUSE high-level callbacks to n00b VFS operations.
 *
 * Compiled only when N00B_HAVE_FUSE is defined (macFUSE or libfuse present).
 */

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "vfs/frontend_fuse.h"
#include "core/alloc.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

// ============================================================================
// Context: stored in fuse_get_context()->private_data
// ============================================================================

typedef struct {
    n00b_vfs_frontend_t *frontend;
    n00b_vfs_t          *vfs;
    struct fuse         *fuse_handle;
    pthread_t            thread;
} fuse_ctx_t;

static fuse_ctx_t *
get_ctx(void)
{
    return (fuse_ctx_t *)fuse_get_context()->private_data;
}

// ============================================================================
// Error mapping: VFS error → -errno
// ============================================================================

static int
vfs_err_to_errno(n00b_err_t err)
{
    switch (err) {
    case N00B_VFS_ERR_NOT_FOUND:      return -ENOENT;
    case N00B_VFS_ERR_EXISTS:         return -EEXIST;
    case N00B_VFS_ERR_IS_DIR:         return -EISDIR;
    case N00B_VFS_ERR_NOT_DIR:        return -ENOTDIR;
    case N00B_VFS_ERR_NOT_EMPTY:      return -ENOTEMPTY;
    case N00B_VFS_ERR_PERMISSION:     return -EACCES;
    case N00B_VFS_ERR_HOOK_DENIED:    return -EACCES;
    case N00B_VFS_ERR_READ_ONLY:      return -EROFS;
    case N00B_VFS_ERR_NO_SPACE:       return -ENOSPC;
    case N00B_VFS_ERR_CROSS_DEVICE:   return -EXDEV;
    case N00B_VFS_ERR_NOT_SUPPORTED:  return -ENOSYS;
    case N00B_VFS_ERR_INVALID_HANDLE: return -EBADF;
    case N00B_VFS_ERR_INVALID_PATH:   return -EINVAL;
    default:                          return -EIO;
    }
}

// ============================================================================
// FUSE callbacks
// ============================================================================

static int
fuse_vfs_getattr(const char *path, struct stat *stbuf)
{
    fuse_ctx_t *fc = get_ctx();
    n00b_string_t *sp = n00b_string_from_cstr(path);

    n00b_result_t(n00b_vfs_obj_stat_t) r = n00b_vfs_stat(fc->vfs, sp);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }

    n00b_vfs_obj_stat_t st = n00b_result_get(r);
    memset(stbuf, 0, sizeof(*stbuf));

    switch (st.kind) {
    case N00B_VFS_OBJ_DIR:
        stbuf->st_mode = S_IFDIR | (st.mode ? st.mode : 0755);
        stbuf->st_nlink = 2;
        break;
    case N00B_VFS_OBJ_SYMLINK:
        stbuf->st_mode = S_IFLNK | 0777;
        stbuf->st_nlink = 1;
        break;
    default:
        stbuf->st_mode = S_IFREG | (st.mode ? st.mode : 0644);
        stbuf->st_nlink = 1;
        break;
    }

    stbuf->st_size = (off_t)st.size;
#ifdef __APPLE__
    stbuf->st_mtimespec.tv_sec  = (time_t)(st.mtime_ns / 1000000000ULL);
    stbuf->st_mtimespec.tv_nsec = (long)(st.mtime_ns % 1000000000ULL);
    stbuf->st_ctimespec.tv_sec  = (time_t)(st.ctime_ns / 1000000000ULL);
    stbuf->st_ctimespec.tv_nsec = (long)(st.ctime_ns % 1000000000ULL);
#else
    stbuf->st_mtim.tv_sec  = (time_t)(st.mtime_ns / 1000000000ULL);
    stbuf->st_mtim.tv_nsec = (long)(st.mtime_ns % 1000000000ULL);
    stbuf->st_ctim.tv_sec  = (time_t)(st.ctime_ns / 1000000000ULL);
    stbuf->st_ctim.tv_nsec = (long)(st.ctime_ns % 1000000000ULL);
#endif

    return 0;
}

static int
fuse_vfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi)
{
    (void)offset;
    (void)fi;

    fuse_ctx_t *fc = get_ctx();
    n00b_string_t *sp = n00b_string_from_cstr(path);

    filler(buf, ".", nullptr, 0);
    filler(buf, "..", nullptr, 0);

    n00b_result_t(n00b_vfs_list_result_t *) r =
        n00b_vfs_readdir(fc->vfs, sp, 10000);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }

    n00b_vfs_list_result_t *lr = n00b_result_get(r);
    for (uint32_t i = 0; i < lr->count; i++) {
        // n00b_string_t data is NUL-terminated.
        filler(buf, lr->entries[i].name->data, nullptr, 0);
    }

    return 0;
}

static int
fuse_vfs_open(const char *path, struct fuse_file_info *fi)
{
    fuse_ctx_t *fc = get_ctx();
    n00b_string_t *sp = n00b_string_from_cstr(path);

    uint32_t flags = 0;
    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        flags = N00B_VFS_OPEN_READ;
    }
    else if ((fi->flags & O_ACCMODE) == O_WRONLY) {
        flags = N00B_VFS_OPEN_WRITE;
    }
    else {
        flags = N00B_VFS_OPEN_READ | N00B_VFS_OPEN_WRITE;
    }

    if (fi->flags & O_CREAT)  flags |= N00B_VFS_OPEN_CREATE;
    if (fi->flags & O_TRUNC)  flags |= N00B_VFS_OPEN_TRUNC;
    if (fi->flags & O_APPEND) flags |= N00B_VFS_OPEN_APPEND;
    if (fi->flags & O_EXCL)   flags |= N00B_VFS_OPEN_EXCL;

    n00b_result_t(n00b_vfs_fh_t) r = n00b_vfs_open(fc->vfs, sp, flags);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }

    fi->fh = n00b_result_get(r);
    return 0;
}

static int
fuse_vfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)mode;

    fuse_ctx_t *fc = get_ctx();
    n00b_string_t *sp = n00b_string_from_cstr(path);

    uint32_t flags = N00B_VFS_OPEN_WRITE | N00B_VFS_OPEN_CREATE | N00B_VFS_OPEN_TRUNC;

    n00b_result_t(n00b_vfs_fh_t) r = n00b_vfs_open(fc->vfs, sp, flags);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }

    fi->fh = n00b_result_get(r);
    return 0;
}

static int
fuse_vfs_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
    (void)path;

    fuse_ctx_t *fc = get_ctx();

    // Seek to offset.
    n00b_vfs_seek(fc->vfs, fi->fh, offset, 0);

    n00b_result_t(n00b_buffer_t *) r = n00b_vfs_read(fc->vfs, fi->fh, size);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }

    n00b_buffer_t *result = n00b_result_get(r);
    int64_t        len;
    char          *data = n00b_buffer_to_c(result, &len);

    memcpy(buf, data, (size_t)len);
    return (int)len;
}

static int
fuse_vfs_write(const char *path, const char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
    (void)path;

    fuse_ctx_t *fc = get_ctx();

    n00b_vfs_seek(fc->vfs, fi->fh, offset, 0);

    n00b_buffer_t *data = n00b_buffer_from_bytes((char *)buf, (int64_t)size);

    n00b_result_t(uint64_t) r = n00b_vfs_write(fc->vfs, fi->fh, data);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }

    return (int)n00b_result_get(r);
}

static int
fuse_vfs_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;

    fuse_ctx_t *fc = get_ctx();
    n00b_result_t(bool) r = n00b_vfs_close(fc->vfs, fi->fh);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }
    return 0;
}

static int
fuse_vfs_unlink(const char *path)
{
    fuse_ctx_t *fc = get_ctx();
    n00b_result_t(bool) r =
        n00b_vfs_delete(fc->vfs, n00b_string_from_cstr(path));
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }
    return 0;
}

static int
fuse_vfs_rename(const char *from, const char *to)
{
    fuse_ctx_t *fc = get_ctx();
    n00b_result_t(bool) r = n00b_vfs_rename(
        fc->vfs, n00b_string_from_cstr(from), n00b_string_from_cstr(to));
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }
    return 0;
}

static int
fuse_vfs_mkdir(const char *path, mode_t mode)
{
    (void)mode;

    fuse_ctx_t *fc = get_ctx();
    n00b_result_t(bool) r =
        n00b_vfs_mkdir(fc->vfs, n00b_string_from_cstr(path));
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }
    return 0;
}

static int
fuse_vfs_rmdir(const char *path)
{
    // VFS delete handles both files and dirs.
    return fuse_vfs_unlink(path);
}

static int
fuse_vfs_truncate(const char *path, off_t size)
{
    fuse_ctx_t *fc = get_ctx();
    n00b_string_t *sp = n00b_string_from_cstr(path);

    n00b_result_t(bool) r = n00b_vfs_truncate(fc->vfs, sp, (uint64_t)size);
    if (n00b_result_is_err(r)) {
        return vfs_err_to_errno(n00b_result_get_err(r));
    }
    return 0;
}

// ============================================================================
// FUSE operations table
// ============================================================================

static struct fuse_operations fuse_vfs_ops = {
    .getattr  = fuse_vfs_getattr,
    .readdir  = fuse_vfs_readdir,
    .open     = fuse_vfs_open,
    .create   = fuse_vfs_create,
    .read     = fuse_vfs_read,
    .write    = fuse_vfs_write,
    .release  = fuse_vfs_release,
    .unlink   = fuse_vfs_unlink,
    .rename   = fuse_vfs_rename,
    .mkdir    = fuse_vfs_mkdir,
    .rmdir    = fuse_vfs_rmdir,
    .truncate = fuse_vfs_truncate,
};

// ============================================================================
// Frontend vtable implementation
// ============================================================================

static n00b_string_t *
fuse_fe_name(void)
{
    return n00b_string_from_cstr("fuse");
}

static void *
fuse_thread_main(void *arg)
{
    fuse_ctx_t *fc = arg;

    const char *mount = fc->frontend->mount_point->data;
    char *argv[] = {"n00b_vfs", (char *)mount, "-f", "-s", nullptr};
    int   argc   = 4;

    struct fuse_args fargs = FUSE_ARGS_INIT(argc, argv);

    struct fuse_chan *ch = fuse_mount(mount, &fargs);
    if (ch == nullptr) {
        atomic_store(&fc->frontend->running, false);
        return nullptr;
    }

    fc->fuse_handle = fuse_new(ch, &fargs, &fuse_vfs_ops,
                               sizeof(fuse_vfs_ops), fc);
    if (fc->fuse_handle == nullptr) {
        fuse_unmount(mount, ch);
        atomic_store(&fc->frontend->running, false);
        return nullptr;
    }

    atomic_store(&fc->frontend->running, true);
    fuse_loop(fc->fuse_handle);

    fuse_unmount(mount, ch);
    fuse_destroy(fc->fuse_handle);
    fc->fuse_handle = nullptr;
    atomic_store(&fc->frontend->running, false);

    return nullptr;
}

static n00b_result_t(bool)
fuse_fe_start(n00b_vfs_frontend_t *fe)
{
    fuse_ctx_t *fc = fe->ctx;

    // WP-001 residual (OUT OF PROJECT): this VFS server thread is a raw
    // libpthread thread that runs OUTSIDE the n00b thread lifecycle (no
    // n00b_thread_init, no n00b callstack).  It is the source of the
    // Phase-4 foreign-thread self() read-fault limitation documented in
    // include/core/thread.h's n00b_thread_self() @brief: a foreign pthread
    // that reaches an n00b allocation and calls self() lands its masked
    // base in its own non-aligned stack mapping, where the ID-word read at
    // (base + S - 8) is not guaranteed mapped.  Excising these two VFS
    // pthreads (here and src/vfs/frontend_nfs.c) is tracked for a later WP
    // under D-002/D-011 and must precede project close; until then the
    // four WP-001 thread tests never start a VFS frontend, so no foreign
    // SP reaches the worker-masking branch under test.
    if (pthread_create(&fc->thread, nullptr, fuse_thread_main, fc) != 0) {
        return n00b_result_err(bool, N00B_VFS_ERR_IO);
    }

    // Brief wait for mount to become ready.
    for (int i = 0; i < 50; i++) {
        if (atomic_load(&fe->running)) break;
        usleep(10000);  // 10ms
    }

    return n00b_result_ok(bool, true);
}

static void
fuse_fe_stop(n00b_vfs_frontend_t *fe)
{
    fuse_ctx_t *fc = fe->ctx;

    if (fc->fuse_handle != nullptr) {
        fuse_exit(fc->fuse_handle);
    }

    pthread_join(fc->thread, nullptr);
    atomic_store(&fe->running, false);
}

static bool
fuse_fe_is_running(n00b_vfs_frontend_t *fe)
{
    return atomic_load(&fe->running);
}

const n00b_vfs_frontend_ops_t n00b_vfs_frontend_fuse_ops = {
    .name       = fuse_fe_name,
    .start      = fuse_fe_start,
    .stop       = fuse_fe_stop,
    .is_running = fuse_fe_is_running,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_vfs_frontend_t *)
n00b_vfs_frontend_fuse_new(n00b_vfs_t *vfs, n00b_string_t *mount_point)
{
    if (vfs == nullptr || mount_point == nullptr) {
        return n00b_result_err(n00b_vfs_frontend_t *, N00B_VFS_ERR_NULL_ARG);
    }

    fuse_ctx_t *fc = n00b_alloc(fuse_ctx_t);

    n00b_vfs_frontend_t *fe = n00b_alloc(n00b_vfs_frontend_t);
    fe->ops         = &n00b_vfs_frontend_fuse_ops;
    fe->vfs         = vfs;
    fe->mount_point = mount_point;
    fe->ctx         = fc;
    atomic_store(&fe->running, false);

    fc->frontend = fe;
    fc->vfs      = vfs;

    return n00b_result_ok(n00b_vfs_frontend_t *, fe);
}

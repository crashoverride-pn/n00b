/*
 * file.c — unified file API over STREAM (conduit) and MMAP substrates.
 *
 * The façade hides the substrate behind a single read/write/seek/close
 * surface. Stream callers get event-driven I/O via conduit/fd_managed;
 * mmap callers get random access into a buffer aliasing the mapping.
 */

#include "n00b.h"
#include "core/file.h"
#include "core/file_map.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/rt_access.h"
#include "core/alloc.h"
#include "core/condition.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/inbox.h"
#include "conduit/rw.h"

#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// ============================================================================
// Internal state
// ============================================================================

struct n00b_file {
    n00b_file_kind_t kind;
    n00b_string_t   *path;
    uint32_t         mode;
    int64_t          size;     // -1 if unknown
    int64_t          pos;
    bool             eof;

    // STREAM substrate.
    n00b_conduit_t                              *conduit;
    n00b_conduit_io_backend_t                   *io;
    int                                          fd;          // -1 if not owned
    n00b_conduit_fd_owner_t                     *owner;
    n00b_conduit_topic_t(n00b_buffer_t *)       *read_topic;
    n00b_conduit_inbox_t(n00b_buffer_t *)       *read_inbox;
    n00b_conduit_sub_handle_t                    read_sub;
    n00b_conduit_fd_status_inbox_t              *status_inbox;
    n00b_conduit_sub_handle_t                    status_sub;

    // MMAP substrate.
    n00b_buffer_t *buf;
};

// Drain pending status events from the IO thread. Reports the first
// I/O error encountered; does NOT set f->eof. EOF is authoritatively
// signalled by TOPIC_CLOSED in the read inbox's sys queue (which is
// in-order with respect to data chunks) or by the size-based check,
// not by the status event (which travels on a separate topic with
// no ordering guarantee versus the chunk stream).
static int
drain_stream_status(n00b_file_t *f)
{
    if (!f->status_inbox) return 0;
    int err = 0;
    n00b_conduit_fd_status_msg_t *m;
    while ((m = n00b_conduit_fd_status_inbox_pop(f->status_inbox)) != nullptr) {
        uint32_t s = m->payload.status;
        if (s & (N00B_CONDUIT_FD_ST_READ_ERR | N00B_CONDUIT_FD_ST_WRITE_ERR)) {
            if (!err) err = m->payload.error_code ? m->payload.error_code : EIO;
        }
    }
    return err;
}

static n00b_err_t
file_errno_to_file_err(int e)
{
    switch (e) {
    case 0:       return N00B_FILE_OK;
    case EINVAL:  return N00B_FILE_ERR_ARG;
    case ENOENT:  return N00B_FILE_ERR_NOT_FOUND;
    case EEXIST:  return N00B_FILE_ERR_EXISTS;
    case EISDIR:  return N00B_FILE_ERR_IS_DIR;
    case ENOTDIR: return N00B_FILE_ERR_NOT_DIR;
    case EACCES:
    case EPERM:   return N00B_FILE_ERR_PERMISSION;
    case ENOSPC:  return N00B_FILE_ERR_NO_SPACE;
#ifdef ENOTSUP
    case ENOTSUP: return N00B_FILE_ERR_NOT_SUPPORTED;
#endif
#ifdef ENOSYS
    case ENOSYS:  return N00B_FILE_ERR_NOT_SUPPORTED;
#endif
    default:      return N00B_FILE_ERR_IO;
    }
}

n00b_string_t *
n00b_file_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_FILE_OK:                return r"OK";
    case N00B_FILE_ERR_ARG:           return r"ARG";
    case N00B_FILE_ERR_IO:            return r"IO";
    case N00B_FILE_ERR_NOT_FOUND:     return r"NOT_FOUND";
    case N00B_FILE_ERR_PERMISSION:    return r"PERMISSION";
    case N00B_FILE_ERR_NOT_SUPPORTED: return r"NOT_SUPPORTED";
    case N00B_FILE_ERR_NO_SPACE:      return r"NO_SPACE";
    case N00B_FILE_ERR_IS_DIR:        return r"IS_DIR";
    case N00B_FILE_ERR_NOT_DIR:       return r"NOT_DIR";
    case N00B_FILE_ERR_EXISTS:        return r"EXISTS";
    }
    return r"UNKNOWN";
}

#ifndef _WIN32
static int
file_host_open_readonly(const char *path)
{
#if defined(SYS_openat)
    return (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
#elif defined(SYS_open)
    return (int)syscall(SYS_open, path, O_RDONLY, 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
file_host_close(int fd)
{
#ifdef SYS_close
    return (int)syscall(SYS_close, fd);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
file_host_fsync(int fd)
{
#ifdef SYS_fsync
    return (int)syscall(SYS_fsync, fd);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
file_host_fdatasync(int fd)
{
#ifdef SYS_fdatasync
    return (int)syscall(SYS_fdatasync, fd);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
file_host_fullfsync(int fd)
{
#if defined(__APPLE__) && defined(SYS_fcntl) && defined(F_FULLFSYNC)
    return (int)syscall(SYS_fcntl, fd, F_FULLFSYNC);
#else
    errno = ENOSYS;
    return -1;
#endif
}
#endif

// ============================================================================
// Mode translation
// ============================================================================

static int
mode_to_oflags(uint32_t m)
{
    int oflags;
    bool r = (m & N00B_FILE_READ)  != 0;
    bool w = (m & N00B_FILE_WRITE) != 0;
    if (r && w)      oflags = O_RDWR;
    else if (w)      oflags = O_WRONLY;
    else             oflags = O_RDONLY;
    if (m & N00B_FILE_CREATE)   oflags |= O_CREAT;
    if (m & N00B_FILE_TRUNCATE) oflags |= O_TRUNC;
    if (m & N00B_FILE_APPEND)   oflags |= O_APPEND;
    return oflags;
}

static bool
mode_bits_valid(uint32_t mode)
{
    return (mode & ~07777u) == 0;
}

// ============================================================================
// AUTO resolution
// ============================================================================

static n00b_file_kind_t
resolve_kind(const char *cpath, uint32_t mode, n00b_file_kind_t hint)
{
    if (hint != N00B_FILE_KIND_AUTO) return hint;

#ifndef _WIN32
    // Writable opens always go through STREAM — mmap-write semantics
    // (knowing the final size, MAP_SHARED flushes) are different
    // enough that we don't pretend they're symmetric with read-only
    // mmap. Callers who want writable mmap can ask for it explicitly.
    if (mode & N00B_FILE_WRITE) return N00B_FILE_KIND_STREAM;

    struct stat st;
    if (stat(cpath, &st) != 0) {
        // Let the substrate-specific open report the real error.
        return N00B_FILE_KIND_STREAM;
    }
    if (S_ISREG(st.st_mode)) return N00B_FILE_KIND_MMAP;
#else
    (void)cpath;
    (void)mode;
#endif
    return N00B_FILE_KIND_STREAM;
}

// ============================================================================
// STREAM open helper
// ============================================================================

static n00b_result_t(n00b_file_t *)
open_stream_with_flags(n00b_string_t *path, uint32_t mode,
                       int oflags, uint32_t file_mode,
                       n00b_allocator_t *allocator)
{
#ifdef _WIN32
    (void)path;
    (void)mode;
    (void)oflags;
    (void)file_mode;
    (void)allocator;
    return n00b_result_err(n00b_file_t *, ENOSYS);
#else
    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_conduit_t *c  = rt ? rt->default_conduit : nullptr;
    if (!c) return n00b_result_err(n00b_file_t *, EAGAIN);

    auto io_opt = n00b_conduit_default_backend(c);
    if (!n00b_option_is_set(io_opt)) {
        return n00b_result_err(n00b_file_t *, EAGAIN);
    }
    n00b_conduit_io_backend_t *io = n00b_option_get(io_opt);

    // Open the fd ourselves so we can subscribe *before* reads
    // activate. n00b_conduit_fd_manage leaves read_active=false and
    // wires `on_first_subscribe` to activate on the first subscriber
    // — that's the only way to avoid losing chunks the IO thread
    // would otherwise publish to a topic with no subscribers.
    int fd = open((const char *)path->data, oflags, (mode_t)file_mode);
    if (fd < 0) {
        return n00b_result_err(n00b_file_t *, errno);
    }

    struct stat st;
    bool        have_stat = fstat(fd, &st) == 0;
    bool        regular   = have_stat && S_ISREG(st.st_mode);
    if ((mode & N00B_FILE_READ) && !(mode & N00B_FILE_WRITE) && regular) {
        n00b_file_t *f = n00b_alloc(n00b_file_t, .allocator = allocator);
        f->kind         = N00B_FILE_KIND_STREAM;
        f->path         = path;
        f->mode         = mode;
        f->size         = (int64_t)st.st_size;
        f->pos          = 0;
        f->eof          = f->size == 0;
        f->conduit      = nullptr;
        f->io           = nullptr;
        f->fd           = fd;
        f->owner        = nullptr;
        f->read_topic   = nullptr;
        f->read_inbox   = nullptr;
        f->read_sub     = N00B_CONDUIT_INVALID_SUB_HANDLE;
        f->status_inbox = nullptr;
        f->status_sub   = N00B_CONDUIT_INVALID_SUB_HANDLE;
        return n00b_result_ok(n00b_file_t *, f);
    }

    auto mr = n00b_conduit_fd_manage(c, io, fd, /*close_on_done=*/true);
    if (n00b_result_is_err(mr)) {
        close(fd);
        return n00b_result_err(n00b_file_t *, n00b_result_get_err(mr));
    }
    n00b_conduit_fd_owner_t *owner = n00b_result_get(mr);

    n00b_file_t *f = n00b_alloc(n00b_file_t, .allocator = allocator);
    f->kind         = N00B_FILE_KIND_STREAM;
    f->path         = path;
    f->mode         = mode;
    f->pos          = 0;
    f->eof          = false;
    f->conduit      = c;
    f->io           = io;
    f->fd           = fd;
    f->owner        = owner;
    f->read_topic   = nullptr;
    f->read_inbox   = nullptr;
    f->read_sub     = N00B_CONDUIT_INVALID_SUB_HANDLE;
    f->status_inbox = nullptr;
    f->status_sub   = N00B_CONDUIT_INVALID_SUB_HANDLE;

    if (mode & N00B_FILE_READ) {
        // Subscribe to fd status events FIRST so EOF/error events
        // can never race ahead of our subscribers.
        f->status_inbox   = n00b_conduit_fd_status_inbox_new(c);
        auto status_topic = n00b_conduit_fd_status_topic_typed(owner);
        if (status_topic && f->status_inbox) {
            f->status_sub = n00b_conduit_fd_status_subscribe(
                status_topic, f->status_inbox,
                .flags = 0);
        }

        // Now subscribe persistently to the read topic. This is the
        // subscription that triggers `fd_read_on_first_subscribe` →
        // sets read_active=true → IO thread starts pumping data. No
        // chunks can be published before we're subscribed.
        f->read_topic = n00b_conduit_fd_read_topic_typed(owner);
        n00b_allocator_t *cp =
            (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
        f->read_inbox = n00b_alloc_with_opts(
            n00b_conduit_inbox_t(n00b_buffer_t *),
            &(n00b_alloc_opts_t){.allocator = cp});
        n00b_conduit_inbox_init(n00b_buffer_t *, f->read_inbox, c,
                                 N00B_CONDUIT_BP_UNBOUNDED, 0);
        if (f->read_topic) {
            auto ar = n00b_conduit_read_async(n00b_buffer_t *,
                                              f->read_topic, f->read_inbox);
            if (n00b_result_is_ok(ar)) {
                f->read_sub = n00b_result_get(ar).handle;
            }
        }
    }

    // Try to learn the size cheaply (regular files); pipes leave -1.
    f->size = -1;
    if (regular) {
        f->size = (int64_t)st.st_size;
    }

    return n00b_result_ok(n00b_file_t *, f);
#endif
}

static n00b_result_t(n00b_file_t *)
open_stream(n00b_string_t *path, uint32_t mode)
{
    return open_stream_with_flags(path, mode, mode_to_oflags(mode), 0666,
                                  nullptr);
}

// ============================================================================
// MMAP open helper
// ============================================================================

static n00b_result_t(n00b_file_t *)
open_mmap(n00b_string_t *path, uint32_t mode, bool populate)
{
    bool writable = (mode & N00B_FILE_WRITE) != 0;
    auto mr = n00b_file_mmap(path, .writable = writable, .populate = populate);
    if (n00b_result_is_err(mr)) {
        return n00b_result_err(n00b_file_t *, n00b_result_get_err(mr));
    }
    n00b_buffer_t *buf = n00b_result_get(mr);

    n00b_file_t *f = n00b_alloc(n00b_file_t);
    f->kind = N00B_FILE_KIND_MMAP;
    f->path = path;
    f->mode = mode;
    f->size = (int64_t)buf->byte_len;
    f->pos  = 0;
    f->eof  = f->size == 0;
    f->buf  = buf;
    return n00b_result_ok(n00b_file_t *, f);
}

// ============================================================================
// Public open / close
// ============================================================================

n00b_result_t(n00b_file_t *)
n00b_file_open(n00b_string_t *path) _kargs
{
    uint32_t         mode     = N00B_FILE_R;
    n00b_file_kind_t kind     = N00B_FILE_KIND_AUTO;
    bool             populate = false;
}
{
    if (!path || !path->data) {
        return n00b_result_err(n00b_file_t *, EINVAL);
    }

    n00b_file_kind_t resolved = resolve_kind((const char *)path->data,
                                              mode, kind);

    if (resolved == N00B_FILE_KIND_MMAP) {
        return open_mmap(path, mode, populate);
    }
    return open_stream(path, mode);
}

n00b_result_t(n00b_file_t *)
n00b_file_open_exclusive(n00b_string_t *path) _kargs
{
    uint32_t          file_mode = 0600;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!path || !path->data || !mode_bits_valid(file_mode)) {
        return n00b_result_err(n00b_file_t *, EINVAL);
    }

#ifdef _WIN32
    (void)path;
    (void)allocator;
    return n00b_result_err(n00b_file_t *, ENOSYS);
#else
    int oflags = O_WRONLY | O_CREAT | O_EXCL | O_TRUNC;
#ifdef O_NOFOLLOW
    oflags |= O_NOFOLLOW;
#endif
    uint32_t mode = N00B_FILE_WRITE | N00B_FILE_CREATE | N00B_FILE_TRUNCATE;
    return open_stream_with_flags(path, mode, oflags, file_mode, allocator);
#endif
}

static int
close_stream_result(n00b_file_t *f)
{
    int err = 0;

    if (f->read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(f->read_sub);
        f->read_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    if (f->status_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(f->status_sub);
        f->status_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    f->read_inbox   = nullptr;
    f->status_inbox = nullptr;

    if (f->owner) {
        n00b_conduit_fd_owner_t *owner = f->owner;
        auto close_r = n00b_conduit_fd_owner_close_result(owner);
        f->owner = nullptr;

        if (n00b_result_is_err(close_r)) {
            err = n00b_result_get_err(close_r);
        }
    }
    else if (f->fd >= 0) {
        if (close(f->fd) != 0) {
            err = errno;
        }
    }

    f->fd = -1;
    return err;
}

n00b_result_t(bool)
n00b_file_close_result(n00b_file_t *f)
{
    if (!f) {
        return n00b_result_ok(bool, false);
    }

    int flush_err = 0;
    if (f->kind == N00B_FILE_KIND_STREAM) {
#ifndef _WIN32
        if (f->fd >= 0 && (f->mode & N00B_FILE_WRITE)) {
            struct stat st;
            if (fstat(f->fd, &st) == 0 && S_ISREG(st.st_mode)
                && fsync(f->fd) != 0) {
                flush_err = errno;
            }
        }
#endif
        int close_err = close_stream_result(f);
        f->buf = nullptr;
        if (flush_err) {
            return n00b_result_err(bool, flush_err);
        }
        if (close_err) {
            return n00b_result_err(bool, close_err);
        }
        return n00b_result_ok(bool, true);
    }

    // MMAP buffer is GC-collected; munmap fires from its finalizer.
    f->buf = nullptr;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_file_sync_path(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return n00b_result_err(bool, N00B_FILE_ERR_ARG);
    }

#ifdef _WIN32
    (void)path;
    return n00b_result_err(bool, N00B_FILE_ERR_NOT_SUPPORTED);
#else
    int fd = file_host_open_readonly((const char *)path->data);
    if (fd < 0) {
        return n00b_result_err(bool, file_errno_to_file_err(errno));
    }

    int sync_rc = 0;
    int saved_errno = 0;
#ifdef __APPLE__
    sync_rc = file_host_fullfsync(fd);
    if (sync_rc != 0) {
        saved_errno = errno;
        sync_rc = file_host_fsync(fd);
    }
#else
    sync_rc = file_host_fdatasync(fd);
    if (sync_rc != 0) {
        saved_errno = errno;
        sync_rc = file_host_fsync(fd);
    }
#endif
    if (sync_rc != 0) {
        saved_errno = errno;
    }

    if (file_host_close(fd) != 0 && sync_rc == 0) {
        sync_rc     = -1;
        saved_errno = errno;
    }

    if (sync_rc != 0) {
        if (saved_errno == EINVAL) {
            return n00b_result_err(bool, N00B_FILE_ERR_NOT_SUPPORTED);
        }
        return n00b_result_err(bool, file_errno_to_file_err(saved_errno));
    }

    return n00b_result_ok(bool, true);
#endif
}

void
n00b_file_close(n00b_file_t *f)
{
    (void)n00b_file_close_result(f);
}

// ============================================================================
// Read
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_file_read(n00b_file_t *f, size_t max_n)
{
    if (!f) return n00b_result_err(n00b_buffer_t *, EINVAL);

    if (f->kind == N00B_FILE_KIND_MMAP) {
        if (!f->buf) return n00b_result_err(n00b_buffer_t *, EBADF);
        int64_t remaining = f->size - f->pos;
        if (remaining <= 0) {
            f->eof = true;
            return n00b_result_ok(n00b_buffer_t *,
                                  n00b_buffer_from_bytes("", 0));
        }
        size_t n = (size_t)remaining;
        if (max_n > 0 && max_n < n) n = max_n;
        // Borrowed slice — aliases the parent mmap without copying.
        // The borrowed flag tells the finalizer not to free the
        // pointer; the parent buffer owns the mapping and stays
        // reachable for as long as this file handle holds it.
        n00b_buffer_t *slice = n00b_alloc(n00b_buffer_t);
        slice->data      = f->buf->data + f->pos;
        slice->byte_len  = n;
        slice->alloc_len = 0;
        slice->allocator = nullptr;
        slice->flags     = N00B_BUF_F_BORROWED;
        slice->lock      = n00b_data_lock_new();
        f->pos += (int64_t)n;
        if (f->pos >= f->size) f->eof = true;
        return n00b_result_ok(n00b_buffer_t *, slice);
    }

    // STREAM path. Pop from the persistent read_inbox; on empty,
    // wait on its condition variable. The IO thread closes the
    // read_topic on EOF/error AFTER publishing the last chunk on
    // the same topic, so a TOPIC_CLOSED system message reaches our
    // inbox in-order after every data chunk. We detect EOF by
    // either: pop returning null + sys-queue has TOPIC_CLOSED, or
    // pos >= known size (regular files).
    if (!f->read_inbox && f->fd >= 0 && (f->mode & N00B_FILE_READ)) {
        if (f->eof) {
            return n00b_result_ok(n00b_buffer_t *, n00b_buffer_from_bytes("", 0));
        }

        size_t want = max_n ? max_n : 65536;
        if (f->size >= 0) {
            int64_t remaining = f->size - f->pos;
            if (remaining <= 0) {
                f->eof = true;
                return n00b_result_ok(n00b_buffer_t *, n00b_buffer_from_bytes("", 0));
            }
            if ((int64_t)want > remaining) want = (size_t)remaining;
        }

        n00b_buffer_t *buf = n00b_buffer_new((int64_t)want);
        ssize_t n = read(f->fd, buf->data, want);
        if (n < 0) {
            return n00b_result_err(n00b_buffer_t *, errno);
        }
        buf->byte_len = (size_t)n;
        f->pos += (int64_t)n;
        if (n == 0 || (f->size >= 0 && f->pos >= f->size)) {
            f->eof = true;
        }
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    if (!f->read_inbox) return n00b_result_err(n00b_buffer_t *, EBADF);
    (void)max_n;

    if (f->eof) {
        return n00b_result_ok(n00b_buffer_t *, n00b_buffer_from_bytes("", 0));
    }

    for (;;) {
        // Status events still arrive on a parallel topic; drain so a
        // READ_ERR gets surfaced quickly. The READ_EOF event isn't
        // load-bearing for ordering — TOPIC_CLOSED on read_topic is.
        int err = drain_stream_status(f);
        if (err) return n00b_result_err(n00b_buffer_t *, err);

        n00b_conduit_message_t(n00b_buffer_t *) *msg =
            n00b_conduit_inbox_pop_msg(n00b_buffer_t *, f->read_inbox);
        if (msg) {
            n00b_buffer_t *chunk = msg->payload;
            if (!chunk || chunk->byte_len == 0) {
                f->eof = true;
                return n00b_result_ok(n00b_buffer_t *,
                                      n00b_buffer_from_bytes("", 0));
            }
            f->pos += (int64_t)chunk->byte_len;
            return n00b_result_ok(n00b_buffer_t *, chunk);
        }

        // No data. Genuine EOF if either:
        //   - we know the file's size and have read all of it, or
        //   - size is unknown (pipe/etc) and the read_topic has
        //     been closed (TOPIC_CLOSED in our sys queue).
        //
        // When size IS known, we MUST NOT exit on TOPIC_CLOSED if
        // pos < size: the inbox queue may have chunks not yet
        // visible to our pop (atomic visibility lag), and the IO
        // thread's plain `prev->next = msg` write is paired with
        // fences that may not have committed yet. Keep waiting for
        // the cv until pos catches up.
        if (f->size >= 0) {
            if (f->pos >= f->size) {
                f->eof = true;
                return n00b_result_ok(n00b_buffer_t *,
                                      n00b_buffer_from_bytes("", 0));
            }
            // Drain sys queue so it doesn't stall — but don't act on
            // TOPIC_CLOSED yet. Chunks still pending.
            while (n00b_conduit_inbox_has_sys(f->read_inbox)) {
                (void)n00b_conduit_inbox_pop_sys(f->read_inbox);
            }
        }
        else if (n00b_conduit_inbox_has_sys(f->read_inbox)) {
            n00b_conduit_sys_msg_t *sys =
                n00b_conduit_inbox_pop_sys(f->read_inbox);
            if (sys && sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
                f->eof = true;
                return n00b_result_ok(n00b_buffer_t *,
                                      n00b_buffer_from_bytes("", 0));
            }
        }

        // `.auto_unlock = true` releases the inbox CV mutex after the
        // wait returns. Without it, the consumer leaves the mutex
        // held — and the IO thread's topic_close → notify path on
        // the same CV would block forever.
        n00b_condition_wait(&f->read_inbox->cv,
                            .timeout_ms = 50,
                            .auto_unlock = true);
    }
}

// ============================================================================
// Write
// ============================================================================

n00b_result_t(n00b_file_write_attempt_t)
n00b_file_write_attempt(n00b_file_t *f, const void *p, size_t n)
{
    if (!f || !p) return n00b_result_err(n00b_file_write_attempt_t, EINVAL);
    if (n == 0) {
        return n00b_result_ok(
            n00b_file_write_attempt_t,
            ((n00b_file_write_attempt_t){.bytes_written = 0}));
    }

    if (f->kind == N00B_FILE_KIND_MMAP) {
        if (!(f->mode & N00B_FILE_WRITE)) {
            return n00b_result_ok(
                n00b_file_write_attempt_t,
                ((n00b_file_write_attempt_t){
                    .bytes_written = 0,
                    .error         = true,
                    .error_code    = EROFS,
                }));
        }
        if (!f->buf) {
            return n00b_result_ok(
                n00b_file_write_attempt_t,
                ((n00b_file_write_attempt_t){
                    .bytes_written = 0,
                    .error         = true,
                    .error_code    = EBADF,
                }));
        }
        int64_t remaining = f->size - f->pos;
        if (remaining <= 0) {
            return n00b_result_ok(
                n00b_file_write_attempt_t,
                ((n00b_file_write_attempt_t){
                    .bytes_written = 0,
                    .error         = true,
                    .error_code    = ENOSPC,
                }));
        }
        size_t k = n;
        if ((int64_t)k > remaining) k = (size_t)remaining;
        memcpy(f->buf->data + f->pos, p, k);
        f->pos += (int64_t)k;
        return n00b_result_ok(
            n00b_file_write_attempt_t,
            ((n00b_file_write_attempt_t){.bytes_written = k}));
    }

    // STREAM path: blocking write via conduit fd_owner.
    if (!f->owner) {
        return n00b_result_ok(
            n00b_file_write_attempt_t,
            ((n00b_file_write_attempt_t){
                .bytes_written = 0,
                .error         = true,
                .error_code    = EBADF,
            }));
    }
    auto wr = n00b_fd_owner_write_attempt(f->owner, p, n);
    if (n00b_result_is_err(wr)) {
        return n00b_result_err(n00b_file_write_attempt_t,
                               (int)n00b_result_get_err(wr));
    }
    n00b_fd_owner_write_attempt_t owner_attempt = n00b_result_get(wr);
    f->pos += (int64_t)owner_attempt.bytes_written;
    return n00b_result_ok(
        n00b_file_write_attempt_t,
        ((n00b_file_write_attempt_t){
            .bytes_written = owner_attempt.bytes_written,
            .error         = owner_attempt.error,
            .error_code    = owner_attempt.error_code,
        }));
}

n00b_result_t(size_t)
n00b_file_write(n00b_file_t *f, const void *p, size_t n)
{
    auto attempt_r = n00b_file_write_attempt(f, p, n);
    if (n00b_result_is_err(attempt_r)) {
        return n00b_result_err(size_t, n00b_result_get_err(attempt_r));
    }

    n00b_file_write_attempt_t attempt = n00b_result_get(attempt_r);
    if (attempt.error) {
        return n00b_result_err(size_t, attempt.error_code);
    }

    return n00b_result_ok(size_t, attempt.bytes_written);
}

n00b_result_t(size_t)
n00b_file_write_all(n00b_file_t *f, n00b_buffer_t *buffer)
{
    if (!f || !buffer) {
        return n00b_result_err(size_t, EINVAL);
    }

    size_t total = buffer->byte_len;
    if (total == 0) {
        return n00b_result_ok(size_t, 0);
    }
    if (buffer->data == nullptr) {
        return n00b_result_err(size_t, EINVAL);
    }

    size_t written = 0;
    while (written < total) {
        size_t remaining = total - written;
        auto wr = n00b_file_write_attempt(f,
                                          buffer->data + written,
                                          remaining);
        if (n00b_result_is_err(wr)) {
            return n00b_result_err(size_t, n00b_result_get_error(wr));
        }

        n00b_file_write_attempt_t attempt = n00b_result_get(wr);
        if (attempt.error) {
            written += attempt.bytes_written;
            return n00b_result_err(size_t, attempt.error_code);
        }
        if (attempt.bytes_written == 0 || attempt.bytes_written > remaining) {
            return n00b_result_err(size_t, EIO);
        }
        written += attempt.bytes_written;
    }

    return n00b_result_ok(size_t, written);
}

n00b_result_t(uint32_t)
n00b_file_apply_mode(n00b_file_t *f, uint32_t mode)
{
    if (!f || !mode_bits_valid(mode)) {
        return n00b_result_err(uint32_t, EINVAL);
    }

#ifdef _WIN32
    (void)f;
    (void)mode;
    return n00b_result_err(uint32_t, ENOSYS);
#else
    struct stat st;
    if (f->kind == N00B_FILE_KIND_STREAM && f->fd >= 0) {
        if (fchmod(f->fd, (mode_t)mode) != 0) {
            return n00b_result_err(uint32_t, errno);
        }
        if (fstat(f->fd, &st) != 0) {
            return n00b_result_err(uint32_t, errno);
        }
        return n00b_result_ok(uint32_t, (uint32_t)(st.st_mode & 07777));
    }

    if (!f->path || !f->path->data) {
        return n00b_result_err(uint32_t, EBADF);
    }
    if (chmod(f->path->data, (mode_t)mode) != 0) {
        return n00b_result_err(uint32_t, errno);
    }
    if (stat(f->path->data, &st) != 0) {
        return n00b_result_err(uint32_t, errno);
    }
    return n00b_result_ok(uint32_t, (uint32_t)(st.st_mode & 07777));
#endif
}

// ============================================================================
// Seek / tell / size / eof / kind
// ============================================================================

n00b_result_t(int64_t)
n00b_file_seek(n00b_file_t *f, int64_t off, int whence)
{
    if (!f) return n00b_result_err(int64_t, EINVAL);

    if (f->kind == N00B_FILE_KIND_MMAP) {
        int64_t target;
        switch (whence) {
        case SEEK_SET: target = off; break;
        case SEEK_CUR: target = f->pos + off; break;
        case SEEK_END: target = f->size + off; break;
        default:       return n00b_result_err(int64_t, EINVAL);
        }
        if (target < 0 || target > f->size) {
            return n00b_result_err(int64_t, EINVAL);
        }
        f->pos = target;
        f->eof = (target >= f->size);
        return n00b_result_ok(int64_t, target);
    }

    // STREAM: forward-only.
    int64_t target;
    switch (whence) {
    case SEEK_SET: target = off; break;
    case SEEK_CUR: target = f->pos + off; break;
    case SEEK_END: return n00b_result_err(int64_t, EINVAL);
    default:       return n00b_result_err(int64_t, EINVAL);
    }
    if (target < f->pos) return n00b_result_err(int64_t, EINVAL);
    while (f->pos < target && !f->eof) {
        size_t want = (size_t)(target - f->pos);
        auto rr = n00b_file_read(f, want);
        if (n00b_result_is_err(rr)) {
            return n00b_result_err(int64_t, (int)n00b_result_get_err(rr));
        }
        n00b_buffer_t *chunk = n00b_result_get(rr);
        if (!chunk || chunk->byte_len == 0) break;
        // pos is already advanced by n00b_file_read.
    }
    if (f->pos < target) {
        // EOF before reaching target — return current pos (POSIX-ish).
        return n00b_result_ok(int64_t, f->pos);
    }
    return n00b_result_ok(int64_t, f->pos);
}

int64_t          n00b_file_tell(n00b_file_t *f)     { return f ? f->pos : -1; }
int64_t          n00b_file_size(n00b_file_t *f)     { return f ? f->size : -1; }
bool             n00b_file_at_eof(n00b_file_t *f)   { return f ? f->eof : true; }
n00b_file_kind_t n00b_file_get_kind(n00b_file_t *f) { return f ? f->kind : N00B_FILE_KIND_AUTO; }

// ============================================================================
// MMAP escape hatch
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_file_as_buffer(n00b_file_t *f)
{
    if (!f) return n00b_result_err(n00b_buffer_t *, EINVAL);
    if (f->kind != N00B_FILE_KIND_MMAP) {
        return n00b_result_err(n00b_buffer_t *, ENOTSUP);
    }
    if (!f->buf) return n00b_result_err(n00b_buffer_t *, EBADF);
    return n00b_result_ok(n00b_buffer_t *, f->buf);
}

// ============================================================================
// Async read
// ============================================================================

static n00b_result_t(n00b_conduit_async_read_t(n00b_buffer_t *))
file_read_async_inline(n00b_file_t                           *f,
                       size_t                                 max_n,
                       n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    auto rr = n00b_file_read(f, max_n);
    if (n00b_result_is_err(rr)) {
        return n00b_result_err(n00b_conduit_async_read_t(n00b_buffer_t *),
                               (int)n00b_result_get_err(rr));
    }
    n00b_buffer_t *chunk = n00b_result_get(rr);

    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_alloc(n00b_conduit_message_t(n00b_buffer_t *));
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = nullptr;
    msg->header.generation = 0;
    msg->header.epoch      = 0;
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload           = chunk;

    n00b_conduit_inbox_push_msg(n00b_buffer_t *, inbox, msg);

    n00b_conduit_async_read_t(n00b_buffer_t *) async = {
        .inbox  = inbox,
        .handle = N00B_CONDUIT_INVALID_SUB_HANDLE,
    };
    return n00b_result_ok(n00b_conduit_async_read_t(n00b_buffer_t *), async);
}

n00b_result_t(n00b_conduit_async_read_t(n00b_buffer_t *))
n00b_file_read_async(n00b_file_t                           *f,
                     size_t                                 max_n,
                     n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    if (!f || !inbox) {
        return n00b_result_err(n00b_conduit_async_read_t(n00b_buffer_t *),
                               EINVAL);
    }

    if (f->kind == N00B_FILE_KIND_STREAM) {
        if (!f->read_topic) {
            if (f->fd >= 0 && (f->mode & N00B_FILE_READ)) {
                return file_read_async_inline(f, max_n, inbox);
            }
            return n00b_result_err(n00b_conduit_async_read_t(n00b_buffer_t *),
                                   EBADF);
        }
        return n00b_conduit_read_async(n00b_buffer_t *, f->read_topic, inbox);
    }

    // MMAP path: synchronous read + immediate inbox post. The async
    // contract is satisfied by the inbox delivery; the read itself
    // was synchronous because the bytes are already in our address
    // space. The returned handle is INVALID_SUB_HANDLE since no real
    // subscription exists; sub_cancel on it is a documented no-op.
    return file_read_async_inline(f, max_n, inbox);
}

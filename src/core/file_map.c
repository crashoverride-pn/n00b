/*
 * file_map.c — implementation of n00b_file_mmap / n00b_file_mmap_advise.
 *
 * Wraps an mmap'd region in an n00b_buffer_t. The buffer carries the
 * N00B_BUF_F_MMAP flag, which n00b_buffer_free reads to dispatch to
 * munmap(2) instead of n00b_free on collection.
 */

#include "n00b.h"
#include "core/file_map.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"

#include <errno.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
static bool
file_map_windows_has_drive_prefix(const char *path)
{
    if (path == nullptr || path[0] == '\0' || path[1] == '\0') {
        return false;
    }

    char drive = path[0];
    return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z'))
           && path[1] == ':';
}

static char *
file_map_windows_native_cstr(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return nullptr;
    }

    size_t start = 0;
    if (path->u8_bytes >= 3 && path->data[0] == '/'
        && file_map_windows_has_drive_prefix(path->data + 1)) {
        start = 1;
    }

    size_t len = (size_t)path->u8_bytes - start;
    char  *buf = n00b_alloc_array(char, len + 1);

    for (size_t i = 0; i < len; i++) {
        char c = path->data[start + i];
        buf[i] = c == '/' ? '\\' : c;
    }

    buf[len] = '\0';
    return buf;
}

static int
file_map_windows_errno(DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:     return ENOENT;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:        return EEXIST;
    case ERROR_ACCESS_DENIED:      return EACCES;
    case ERROR_INVALID_PARAMETER:  return EINVAL;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:        return ENOMEM;
    default:                       return EIO;
    }
}
#endif

n00b_result_t(n00b_buffer_t *)
n00b_file_mmap(n00b_string_t *path) _kargs
{
    bool writable = false;
    bool populate = false;
}
{
    if (!path || !path->data) {
        return n00b_result_err(n00b_buffer_t *, EINVAL);
    }
#ifdef _WIN32
    (void)populate;

    char *native = file_map_windows_native_cstr(path);
    if (native == nullptr) {
        return n00b_result_err(n00b_buffer_t *, EINVAL);
    }

    DWORD access = GENERIC_READ | (writable ? GENERIC_WRITE : 0);
    HANDLE file = CreateFileA(native,
                              access,
                              FILE_SHARE_READ | FILE_SHARE_WRITE
                                  | FILE_SHARE_DELETE,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return n00b_result_err(n00b_buffer_t *,
                               file_map_windows_errno(GetLastError()));
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size)) {
        int err = file_map_windows_errno(GetLastError());
        CloseHandle(file);
        return n00b_result_err(n00b_buffer_t *, err);
    }

    n00b_buffer_t *buf = n00b_alloc(n00b_buffer_t);
    if (size.QuadPart == 0) {
        CloseHandle(file);
        n00b_buffer_init(buf, .length = 0);
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    DWORD protect = writable ? PAGE_READWRITE : PAGE_READONLY;
    HANDLE mapping = CreateFileMappingA(file,
                                        nullptr,
                                        protect,
                                        0,
                                        0,
                                        nullptr);
    if (mapping == nullptr) {
        int err = file_map_windows_errno(GetLastError());
        CloseHandle(file);
        return n00b_result_err(n00b_buffer_t *, err);
    }

    DWORD view_access = writable ? FILE_MAP_WRITE : FILE_MAP_READ;
    void *addr = MapViewOfFile(mapping, view_access, 0, 0, 0);
    if (addr == nullptr) {
        int err = file_map_windows_errno(GetLastError());
        CloseHandle(mapping);
        CloseHandle(file);
        return n00b_result_err(n00b_buffer_t *, err);
    }

    CloseHandle(mapping);
    CloseHandle(file);

    buf->data      = (char *)addr;
    buf->byte_len  = (size_t)size.QuadPart;
    buf->alloc_len = 0;
    buf->allocator = nullptr;
    buf->flags     = N00B_BUF_F_MMAP;
    buf->lock      = n00b_data_lock_new();

    return n00b_result_ok(n00b_buffer_t *, buf);
#else
    const char *cpath = (const char *)path->data;

    int oflags = writable ? O_RDWR : O_RDONLY;
    int fd     = open(cpath, oflags);
    if (fd < 0) {
        return n00b_result_err(n00b_buffer_t *, errno);
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int e = errno;
        close(fd);
        return n00b_result_err(n00b_buffer_t *, e);
    }

    n00b_buffer_t *buf = n00b_alloc(n00b_buffer_t);

    if (st.st_size == 0) {
        // Empty file — close the fd and return a regular empty buffer.
        // No mapping is needed; the resulting buffer behaves like any
        // other empty n00b_buffer_t (and is freed via n00b_free, not
        // munmap).
        close(fd);
        n00b_buffer_init(buf, .length = 0);
        return n00b_result_ok(n00b_buffer_t *, buf);
    }

    int prot  = PROT_READ | (writable ? PROT_WRITE : 0);
    int mflag = writable ? MAP_SHARED : MAP_PRIVATE;
#ifdef MAP_POPULATE
    if (populate) {
        mflag |= MAP_POPULATE;
    }
#else
    (void)populate;
#endif

    void *addr = mmap(NULL, (size_t)st.st_size, prot, mflag, fd, 0);
    int   merr = errno;
    close(fd);
    if (addr == MAP_FAILED) {
        return n00b_result_err(n00b_buffer_t *, merr);
    }

    // Initialize the buffer to alias the mapping. We can't use
    // n00b_buffer_init's .ptr path here because it leaves alloc_len
    // at zero (correct) but doesn't flag the buffer as mmap-backed —
    // and we need n00b_buffer_free to call munmap, not n00b_free.
    buf->data      = (char *)addr;
    buf->byte_len  = (size_t)st.st_size;
    buf->alloc_len = 0;
    buf->allocator = nullptr;
    buf->flags     = N00B_BUF_F_MMAP;
    buf->lock      = n00b_data_lock_new();

    return n00b_result_ok(n00b_buffer_t *, buf);
#endif
}

void
n00b_file_mmap_advise(n00b_buffer_t *buf, n00b_file_mmap_advice_t advice)
{
    if (!buf || !buf->data || !(buf->flags & N00B_BUF_F_MMAP)) {
        return;
    }
#ifdef _WIN32
    (void)advice;
#else
    int a;
    switch (advice) {
    case N00B_MMAP_ADVICE_SEQUENTIAL:
        a = MADV_SEQUENTIAL;
        break;
    case N00B_MMAP_ADVICE_RANDOM:
        a = MADV_RANDOM;
        break;
    case N00B_MMAP_ADVICE_WILLNEED:
        a = MADV_WILLNEED;
        break;
    case N00B_MMAP_ADVICE_DONTNEED:
        a = MADV_DONTNEED;
        break;
    case N00B_MMAP_ADVICE_NORMAL:
    default:
        a = MADV_NORMAL;
        break;
    }
    (void)madvise(buf->data, buf->byte_len, a);
#endif
}

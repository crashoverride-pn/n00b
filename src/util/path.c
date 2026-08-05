#include "n00b.h"
#include "adt/list.h"
#include "adt/array.h"
#include "text/strings/string_ops.h"
#include "text/strings/format.h"
#include "text/strings/fmt_numbers.h"
#include "core/random.h"
#include "core/gc.h"
#include "core/file.h"
#include "core/runtime.h"
#include "adt/result.h"
#include "util/path.h"

#include <stdio.h>
#include <errno.h>

#if defined(__MACH__)
#include <libproc.h>
#endif

#ifdef _WIN32
#include "internal/win32_sockets.h"
#include <direct.h>
#include <io.h>
#include <limits.h>
#include <process.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef NGROUPS_MAX
#define NGROUPS_MAX 1
#endif

#define getcwd _getcwd
#define chdir _chdir
#define mkdir(path, mode) _mkdir(path)
#define rmdir _rmdir
#define unlink _unlink
#define lstat stat

#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif

#ifndef MOVEFILE_REPLACE_EXISTING
#define MOVEFILE_REPLACE_EXISTING 0x00000001UL
#endif
#ifndef MOVEFILE_WRITE_THROUGH
#define MOVEFILE_WRITE_THROUGH 0x00000008UL
#endif

typedef struct {
    int unused;
} DIR;

struct dirent {
    char d_name[PATH_MAX + 1];
};

static DIR *
opendir(const char *path)
{
    (void)path;
    errno = ENOSYS;
    return nullptr;
}

static struct dirent *
readdir(DIR *dir)
{
    (void)dir;
    errno = 0;
    return nullptr;
}

static int
closedir(DIR *dir)
{
    (void)dir;
    return 0;
}

static ssize_t
readlink(const char *path, char *buf, size_t len)
{
    (void)path;
    (void)buf;
    (void)len;
    errno = ENOSYS;
    return -1;
}

static char *
realpath(const char *path, char *resolved)
{
    (void)path;
    (void)resolved;
    errno = ENOSYS;
    return nullptr;
}
#else
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#if defined(__MACH__)
#include <sys/stdio.h>
#endif
#if defined(__linux__)
#include <linux/fs.h>
#endif

// ============================================================================
// Helpers
// ============================================================================

static n00b_string_t *cached_slash;

static n00b_string_t *
join_child_path(n00b_string_t *dir, n00b_string_t *child,
                n00b_allocator_t *allocator);
static n00b_string_t *
remove_extra_slashes(n00b_string_t *result);
static n00b_string_t *
path_normalize_absolute(n00b_string_t *path, n00b_allocator_t *allocator);
static n00b_string_t *cached_period;

static inline void
ensure_cached(void)
{
    if (!cached_slash) {
        cached_slash  = r"/";
        cached_period = r".";
    }
}

static n00b_list_t(n00b_string_t *) *
split_on_slash(n00b_string_t *s)
{
    ensure_cached();

    n00b_array_t(n00b_string_t *) arr = n00b_unicode_str_split(s, cached_slash);
    // Canonical idiom: build the list as a fully-initialized lvalue
    // (scan_kind / scan_cb / scan_user / allocator threaded), populate,
    // then struct-copy into the heap-allocated return shell.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);
    size_t n = n00b_array_len(arr);

    for (size_t i = 0; i < n; i++) {
        n00b_list_push(lst, n00b_array_get(arr, i));
    }

    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *result = lst;
    return result;
}

static int
rfind_slash(n00b_string_t *s)
{
    ensure_cached();
    n00b_option_t(int32_t) r = n00b_unicode_str_find(s, cached_slash, .reverse = true);
    return n00b_option_is_set(r) ? n00b_option_get(r) : -1;
}

static int
rfind_period(n00b_string_t *s)
{
    ensure_cached();
    n00b_option_t(int32_t) r = n00b_unicode_str_find(s, cached_period, .reverse = true);
    return n00b_option_is_set(r) ? n00b_option_get(r) : -1;
}

static int
find_slash(n00b_string_t *s)
{
    ensure_cached();
    n00b_option_t(int32_t) r = n00b_unicode_str_find(s, cached_slash);
    return n00b_option_is_set(r) ? n00b_option_get(r) : -1;
}

static bool
mode_bits_valid(uint32_t mode)
{
    return (mode & ~07777u) == 0;
}

static n00b_string_t *
path_string_from_bytes(const char *data, size_t len,
                       n00b_allocator_t *allocator)
{
    return n00b_string_from_raw(data, (int64_t)len, .allocator = allocator);
}

#ifdef _WIN32
static bool
path_windows_has_drive_prefix(const char *path)
{
    if (path == nullptr) {
        return false;
    }
    if (path[0] == '\0' || path[1] == '\0') {
        return false;
    }

    char drive = path[0];
    return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z'))
           && path[1] == ':';
}

static n00b_string_t *
path_windows_api_string(const char *native, n00b_allocator_t *allocator)
{
    if (native == nullptr) {
        return nullptr;
    }

    size_t len = strlen(native);
    bool prefix_drive = path_windows_has_drive_prefix(native);
    char *buf = n00b_alloc_array(char, len + (prefix_drive ? 2 : 1));
    size_t off = 0;

    if (prefix_drive) {
        buf[off++] = '/';
    }

    for (size_t i = 0; i < len; i++) {
        char c = native[i];
        buf[off++] = c == '\\' ? '/' : c;
    }

    buf[off] = '\0';
    return path_string_from_bytes(buf, off, allocator);
}

static char *
path_windows_native_cstr(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return nullptr;
    }

    size_t start = 0;
    if (path->u8_bytes >= 3 && path->data[0] == '/'
        && path_windows_has_drive_prefix(path->data + 1)) {
        start = 1;
    }

    size_t len = (size_t)path->u8_bytes - start;
    char *buf = n00b_alloc_array(char, len + 1);

    for (size_t i = 0; i < len; i++) {
        char c = path->data[start + i];
        buf[i] = c == '/' ? '\\' : c;
    }

    buf[len] = '\0';
    return buf;
}

static int
path_windows_errno(DWORD error)
{
    switch (error) {
    case ERROR_SUCCESS:         return 0;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:  return ENOENT;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:     return EEXIST;
    case ERROR_ACCESS_DENIED:   return EACCES;
    case ERROR_INVALID_NAME:
    case ERROR_INVALID_PARAMETER:
    case ERROR_BAD_PATHNAME:    return EINVAL;
    case ERROR_DIR_NOT_EMPTY:   return ENOTEMPTY;
    default:                    return EIO;
    }
}

static char *
path_windows_find_pattern(const char *native)
{
    size_t len        = strlen(native);
    bool   need_slash = len > 0 && native[len - 1] != '\\'
                     && native[len - 1] != '/';
    char  *buf        = n00b_alloc_array(char, len + (need_slash ? 3 : 2));
    size_t off        = 0;

    memcpy(buf, native, len);
    off += len;

    if (need_slash) {
        buf[off++] = '\\';
    }

    buf[off++] = '*';
    buf[off]   = '\0';
    return buf;
}

static bool
path_windows_posix_absolute(n00b_string_t *path)
{
    return path != nullptr && path->data != nullptr && path->u8_bytes > 0
           && path->data[0] == '/'
           && !path_windows_has_drive_prefix(path->data + 1);
}

static bool
path_windows_stat_native(const char *path)
{
    struct stat st;

    return path != nullptr && stat(path, &st) == 0;
}

static bool
path_windows_has_file_extension(const char *path)
{
    const char *slash = strrchr(path, '\\');
    const char *base  = slash == nullptr ? path : slash + 1;

    return strchr(base, '.') != nullptr;
}

static char *
path_windows_with_exe(const char *path)
{
    size_t len = strlen(path);
    char  *buf = n00b_alloc_array(char, len + 5);

    memcpy(buf, path, len);
    memcpy(buf + len, ".exe", 5);
    return buf;
}

static char *
path_windows_existing_candidate(char *path)
{
    if (path_windows_stat_native(path)) {
        return path;
    }

    if (!path_windows_has_file_extension(path)) {
        char *exe = path_windows_with_exe(path);

        if (path_windows_stat_native(exe)) {
            return exe;
        }
    }

    return nullptr;
}

static char *
path_windows_join_root_relative(const char *root,
                                const char *relative,
                                bool        add_usr)
{
    if (root == nullptr || root[0] == '\0') {
        return nullptr;
    }

    const char *usr       = add_usr ? "usr\\" : "";
    size_t      root_len  = strlen(root);
    size_t      usr_len   = strlen(usr);
    size_t      rel_len   = strlen(relative);
    bool        need_slash = root_len > 0 && root[root_len - 1] != '\\'
                          && root[root_len - 1] != '/';
    char       *buf       = n00b_alloc_array(char,
                                             root_len + (need_slash ? 1 : 0)
                                                 + usr_len + rel_len + 1);
    size_t      off       = 0;

    for (size_t i = 0; i < root_len; i++) {
        char c = root[i];
        buf[off++] = c == '/' ? '\\' : c;
    }

    if (need_slash) {
        buf[off++] = '\\';
    }

    memcpy(buf + off, usr, usr_len);
    off += usr_len;

    for (size_t i = 0; i < rel_len; i++) {
        char c = relative[i];
        buf[off++] = c == '/' ? '\\' : c;
    }

    buf[off] = '\0';
    return buf;
}

static char *
path_windows_try_posix_root(const char *root, const char *relative)
{
    char *candidate = path_windows_join_root_relative(root, relative, false);
    char *existing  = candidate == nullptr
                        ? nullptr
                        : path_windows_existing_candidate(candidate);

    if (existing != nullptr) {
        return existing;
    }

    if (strncmp(relative, "bin/", 4) == 0
        || strncmp(relative, "bin\\", 4) == 0) {
        candidate = path_windows_join_root_relative(root, relative, true);
        existing  = candidate == nullptr
                      ? nullptr
                      : path_windows_existing_candidate(candidate);
        if (existing != nullptr) {
            return existing;
        }
    }

    return nullptr;
}

static char *
path_windows_posix_native_cstr(n00b_string_t *path)
{
    if (!path_windows_posix_absolute(path)) {
        return nullptr;
    }

    const char *relative = path->data + 1;
    const char *override = getenv("N00B_WINDOWS_POSIX_ROOT");
    char       *existing = path_windows_try_posix_root(override, relative);

    if (existing != nullptr) {
        return existing;
    }

    const char *system_drive = getenv("SystemDrive");
    if (system_drive == nullptr || system_drive[0] == '\0') {
        system_drive = "C:";
    }

    char msys_root[PATH_MAX + 1];
    char cygwin_root[PATH_MAX + 1];
    snprintf(msys_root, sizeof(msys_root), "%s\\msys64", system_drive);
    snprintf(cygwin_root, sizeof(cygwin_root), "%s\\cygwin64", system_drive);

    const char *program_files = getenv("ProgramFiles");
    char        git_root[PATH_MAX + 1] = "";
    if (program_files != nullptr && program_files[0] != '\0') {
        snprintf(git_root, sizeof(git_root), "%s\\Git", program_files);
    }

    const char *roots[] = {
        msys_root,
        cygwin_root,
        git_root,
        nullptr,
    };

    for (size_t i = 0; roots[i] != nullptr; i++) {
        existing = path_windows_try_posix_root(roots[i], relative);
        if (existing != nullptr) {
            return existing;
        }
    }

    return nullptr;
}

static char *
path_windows_existing_native_cstr(n00b_string_t *path)
{
    char *native = path_windows_native_cstr(path);

    if (path_windows_stat_native(native) || !path_windows_posix_absolute(path)) {
        return native;
    }

    char *posix = path_windows_posix_native_cstr(path);

    return posix == nullptr ? native : posix;
}

static n00b_string_t *
path_windows_normalize_drive_path(n00b_string_t    *path,
                                  n00b_allocator_t *allocator)
{
    n00b_string_t *api_path = path_windows_api_string(path->data, allocator);

    if (api_path == nullptr) {
        return nullptr;
    }

    return path_normalize_absolute(api_path, allocator);
}
#endif

static n00b_string_t *
path_slash(n00b_allocator_t *allocator)
{
    return path_string_from_bytes("/", 1, allocator);
}

static n00b_string_t *
path_getenv_alloc(n00b_string_t *name, n00b_allocator_t *allocator)
{
    if (name == nullptr || name->data == nullptr || name->u8_bytes == 0) {
        return nullptr;
    }

    n00b_runtime_t *rt      = n00b_get_runtime();
    char          **entries = rt->envp.data;
    size_t          count   = rt->envp.len;
    size_t          n       = (size_t)name->u8_bytes;

    if (entries == nullptr) {
        return nullptr;
    }

    for (size_t i = 0; i < count; i++) {
        char *entry = entries[i];

        if (entry == nullptr) {
            continue;
        }

        bool match = true;
        for (size_t j = 0; j < n; j++) {
            if (entry[j] != name->data[j]) {
                match = false;
                break;
            }
        }

        if (!match || entry[n] != '=') {
            continue;
        }

        const char *value = entry + n + 1;
        size_t      len   = 0;

        while (value[len] != '\0') {
            len++;
        }

        return path_string_from_bytes(value, len, allocator);
    }

    return nullptr;
}

static n00b_string_t *
path_current_directory(n00b_allocator_t *allocator)
{
    char buf[PATH_MAX + 1];

    if (getcwd(buf, PATH_MAX) == nullptr) {
        return nullptr;
    }

#ifdef _WIN32
    return path_windows_api_string(buf, allocator);
#else
    return n00b_string_from_cstr(buf, .allocator = allocator);
#endif
}

static n00b_string_t *
path_user_dir(n00b_string_t *user, n00b_allocator_t *allocator)
{
#ifdef _WIN32
    if (user != nullptr) {
        return remove_extra_slashes(
            path_string_from_bytes(user->data, user->u8_bytes, allocator));
    }

    n00b_string_t *home = path_getenv_alloc(r"HOME", allocator);

    if (home == nullptr) {
        home = path_getenv_alloc(r"USERPROFILE", allocator);
    }

    return home == nullptr
        ? path_slash(allocator)
        : remove_extra_slashes(path_windows_api_string(home->data, allocator));
#else
    n00b_string_t *result;
    struct passwd *pw;

    if (user == nullptr) {
        n00b_string_t *home = path_getenv_alloc(r"HOME", allocator);

        if (home != nullptr) {
            result = home;
        }
        else {
            pw = getpwent();
            result = pw == nullptr
                ? path_slash(allocator)
                : n00b_string_from_cstr(pw->pw_dir, .allocator = allocator);
        }
    }
    else {
        pw = getpwnam(user->data);
        result = pw == nullptr
            ? path_string_from_bytes(user->data, user->u8_bytes, allocator)
            : n00b_string_from_cstr(pw->pw_dir, .allocator = allocator);
    }

    return remove_extra_slashes(result);
#endif
}

static n00b_list_t(n00b_string_t *) *
path_split_components(n00b_string_t *path, n00b_allocator_t *allocator)
{
    n00b_list_t(n00b_string_t *) parts =
        n00b_list_new(n00b_string_t *, .allocator = allocator);
    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *), .allocator = allocator);
    *result = parts;

    if (path == nullptr || path->data == nullptr || path->u8_bytes == 0) {
        return result;
    }

    size_t start = 0;

    for (size_t i = 0; i <= path->u8_bytes; i++) {
        if (i != path->u8_bytes && path->data[i] != '/') {
            continue;
        }

        if (i > start) {
            n00b_list_push(
                *result,
                path_string_from_bytes(path->data + start,
                                       i - start,
                                       allocator));
        }

        start = i + 1;
    }

    return result;
}

static bool
path_component_is_dot(n00b_string_t *component)
{
    return component != nullptr
           && component->u8_bytes == 1
           && component->data[0] == '.';
}

static bool
path_component_is_dot_dot(n00b_string_t *component)
{
    return component != nullptr
           && component->u8_bytes == 2
           && component->data[0] == '.'
           && component->data[1] == '.';
}

static n00b_string_t *
path_normalize_absolute(n00b_string_t *path, n00b_allocator_t *allocator)
{
    n00b_list_t(n00b_string_t *) *pieces =
        path_split_components(path, allocator);
    n00b_list_t(n00b_string_t *) normalized =
        n00b_list_new(n00b_string_t *, .allocator = allocator);

    for (size_t i = 0; i < n00b_list_len(*pieces); i++) {
        n00b_string_t *piece = n00b_list_get(*pieces, i);

        if (path_component_is_dot(piece)) {
            continue;
        }

        if (path_component_is_dot_dot(piece)) {
            size_t n = n00b_list_len(normalized);

            if (n == 0) {
                return nullptr;
            }

            (void)n00b_list_delete(normalized, n - 1);
            continue;
        }

        n00b_list_push(normalized, piece);
    }

    if (n00b_list_len(normalized) == 0) {
        return path_slash(allocator);
    }

    n00b_string_t *result = path_slash(allocator);

    for (size_t i = 0; i < n00b_list_len(normalized); i++) {
        result = join_child_path(result, n00b_list_get(normalized, i),
                                 allocator);
    }

    return result;
}

static n00b_string_t *
path_tilde_expand_alloc(n00b_string_t *path, n00b_allocator_t *allocator)
{
    if (path == nullptr || path->data == nullptr || path->u8_bytes == 0) {
        return path_user_dir(nullptr, allocator);
    }

    if (path->data[0] != '~') {
        return path_normalize_absolute(path, allocator);
    }

    size_t slash = path->u8_bytes;

    for (size_t i = 1; i < path->u8_bytes; i++) {
        if (path->data[i] == '/') {
            slash = i;
            break;
        }
    }

    n00b_string_t *user = nullptr;
    if (slash > 1) {
        user = path_string_from_bytes(path->data + 1, slash - 1, allocator);
    }

    n00b_string_t *home = path_user_dir(user, allocator);
    n00b_string_t *expanded = home;

    if (slash < path->u8_bytes) {
        n00b_string_t *rest =
            path_string_from_bytes(path->data + slash + 1,
                                   path->u8_bytes - slash - 1,
                                   allocator);
        expanded = join_child_path(home, rest, allocator);
    }

    return path_normalize_absolute(expanded, allocator);
}

#ifdef _WIN32
static bool
path_is_windows_af_unix_socket(const char *path)
{
    WIN32_FIND_DATAA data = {};
    HANDLE h = FindFirstFileA(path, &data);

    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }

    (void)FindClose(h);

    return (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
           && data.dwReserved0 == IO_REPARSE_TAG_AF_UNIX;
}
#endif

static n00b_file_kind
path_file_kind_at(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return N00B_FK_NOT_FOUND;
    }

    struct stat file_info;

#ifdef _WIN32
    char *native = path_windows_existing_native_cstr(path);
    if (native == nullptr || lstat(native, &file_info) != 0) {
        return N00B_FK_NOT_FOUND;
    }

    if (path_is_windows_af_unix_socket(native)) {
        return N00B_FK_IS_SOCK;
    }
#else
    if (lstat(path->data, &file_info) != 0) {
        return N00B_FK_NOT_FOUND;
    }
#endif

    switch (file_info.st_mode & S_IFMT) {
    case S_IFREG:  return N00B_FK_IS_REG_FILE;
    case S_IFDIR:  return N00B_FK_IS_DIR;
    case S_IFSOCK: return N00B_FK_IS_SOCK;
    case S_IFCHR:  return N00B_FK_IS_CHR_DEVICE;
    case S_IFBLK:  return N00B_FK_IS_BLOCK_DEVICE;
    case S_IFIFO:  return N00B_FK_IS_FIFO;
    case S_IFLNK:
#ifdef _WIN32
        if (stat(native, &file_info) != 0) {
            return N00B_FK_NOT_FOUND;
        }
#else
        if (stat(path->data, &file_info) != 0) {
            return N00B_FK_NOT_FOUND;
        }
#endif
        switch (file_info.st_mode & S_IFMT) {
        case S_IFREG: return N00B_FK_IS_FLINK;
        case S_IFDIR: return N00B_FK_IS_DLINK;
        default:      return N00B_FK_OTHER;
        }
    default: return N00B_FK_OTHER;
    }
}

static bool
path_file_kind_is_directory(n00b_file_kind kind)
{
    return kind == N00B_FK_IS_DIR || kind == N00B_FK_IS_DLINK;
}

// ============================================================================
// Basic directory operations
// ============================================================================

n00b_string_t *
n00b_get_current_directory(void)
{
    return path_current_directory(nullptr);
}

bool
n00b_set_current_directory(n00b_string_t *s)
{
#ifdef _WIN32
    char *native = path_windows_native_cstr(s);
    return native != nullptr && chdir(native) == 0;
#else
    return chdir(s->data) == 0;
#endif
}

// ============================================================================
// libc-free directory listing (worker-safe: no opendir/readdir/stat, which
// allocate via libsystem_malloc and trap on n00b worker threads).
// ============================================================================

static inline n00b_dirent_t *
dirent_alloc(n00b_allocator_t *a)
{
    if (a != nullptr) {
        return n00b_alloc_with_opts(n00b_dirent_t,
                                    &(n00b_alloc_opts_t){.allocator = a});
    }
    return n00b_alloc(n00b_dirent_t);
}

n00b_list_t(n00b_dirent_t *)
n00b_path_list_dir(n00b_string_t *path, bool *ok)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    n00b_list_t(n00b_dirent_t *) out =
        allocator ? n00b_list_new(n00b_dirent_t *, .allocator = allocator)
                  : n00b_list_new(n00b_dirent_t *);
    if (ok != nullptr) {
        *ok = false;
    }
    if (path == nullptr || path->data == nullptr) {
        return out;
    }

#if defined(_WIN32)
    // Build "<path>\\*" search pattern.
    size_t plen = strlen(path->data);
    char  *pat  = n00b_alloc_array(char, plen + 3,
                                   .allocator = allocator);
    memcpy(pat, path->data, plen);
    pat[plen]     = '\\';
    pat[plen + 1] = '*';
    pat[plen + 2] = '\0';

    WIN32_FIND_DATAA fd;
    HANDLE           h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return out;
    }
    do {
        const char *nm = fd.cFileName;
        if (nm[0] == '.' && (nm[1] == '\0'
            || (nm[1] == '.' && nm[2] == '\0'))) {
            continue;
        }
        n00b_dirent_t *e = dirent_alloc(allocator);
        e->name   = allocator ? n00b_string_from_cstr(nm, .allocator = allocator)
                              : n00b_string_from_cstr(nm);
        e->is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        e->size   = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        // FILETIME: 100ns ticks since 1601-01-01; convert to ns since 1970.
        uint64_t ft = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32)
                    | fd.ftLastWriteTime.dwLowDateTime;
        e->mtime_ns = (ft >= 116444736000000000ULL)
                          ? (ft - 116444736000000000ULL) * 100ULL
                          : 0;
        n00b_list_push(out, e);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path->data,
                          O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        return out;
    }

    char buf[16384];
#if defined(__MACH__)
    long long pos = 0;
#endif
    for (;;) {
#if defined(__MACH__)
        long n = syscall(SYS_getdirentries64, fd, buf, sizeof(buf), &pos);
#else
        long n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
#endif
        if (n <= 0) {
            break;
        }
        long off = 0;
        while (off < n) {
#if defined(__MACH__)
            struct dirent *de = (struct dirent *)(buf + off);
#else
            // struct linux_dirent64 layout (kernel ABI).
            struct linux_dirent64 {
                uint64_t       d_ino;
                int64_t        d_off;
                unsigned short d_reclen;
                unsigned char  d_type;
                char           d_name[];
            } *de = (struct linux_dirent64 *)(buf + off);
#endif
            if (de->d_reclen == 0) {
                break;
            }
            off += de->d_reclen;

            const char *nm = de->d_name;
            if (nm[0] == '.' && (nm[1] == '\0'
                || (nm[1] == '.' && nm[2] == '\0'))) {
                continue;
            }

            n00b_dirent_t *e = dirent_alloc(allocator);
            e->name = allocator
                          ? n00b_string_from_cstr(nm, .allocator = allocator)
                          : n00b_string_from_cstr(nm);
            e->is_dir = (de->d_type == DT_DIR);

            struct stat st;
#if defined(__MACH__)
            long sr = syscall(SYS_fstatat64, fd, nm, &st, 0);
#else
            long sr = syscall(SYS_newfstatat, fd, nm, &st, 0);
#endif
            if (sr == 0) {
                e->size = (uint64_t)st.st_size;
#if defined(__MACH__)
                e->mtime_ns = (uint64_t)st.st_mtimespec.tv_sec * 1000000000ULL
                            + (uint64_t)st.st_mtimespec.tv_nsec;
#else
                e->mtime_ns = (uint64_t)st.st_mtim.tv_sec * 1000000000ULL
                            + (uint64_t)st.st_mtim.tv_nsec;
#endif
                if (de->d_type == DT_UNKNOWN) {
                    e->is_dir = S_ISDIR(st.st_mode);
                }
            }
            n00b_list_push(out, e);
        }
    }
    syscall(SYS_close, fd);
#endif

    if (ok != nullptr) {
        *ok = true;
    }
    return out;
}

// ============================================================================
// Temp files / dirs
// ============================================================================

static n00b_string_t *base_tmp_dir;

static n00b_string_t *
acquire_base_tmp_dir(void)
{
    if (base_tmp_dir) {
        return base_tmp_dir;
    }

    const char *v;

    if ((v = getenv("TMPDIR")) && *v) {
        base_tmp_dir = n00b_string_from_cstr(v);
    }
    else if ((v = getenv("TMP")) && *v) {
        base_tmp_dir = n00b_string_from_cstr(v);
    }
    else if ((v = getenv("TEMP")) && *v) {
        base_tmp_dir = n00b_string_from_cstr(v);
    }
    else {
        base_tmp_dir = r"/tmp/";
    }

    return base_tmp_dir;
}

n00b_string_t *
_n00b_new_temp_path(n00b_string_t *prefix, n00b_string_t *suffix) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_string_t *tmpdir = acquire_base_tmp_dir();
    n00b_string_t *random_string = n00b_fmt_hex(n00b_rand64(),
                                                 .allocator = allocator);

    if (prefix != nullptr) {
        random_string = n00b_unicode_str_cat(prefix,
                                             random_string,
                                             .allocator = allocator);
    }
    if (suffix != nullptr) {
        random_string = n00b_unicode_str_cat(random_string,
                                             suffix,
                                             .allocator = allocator);
    }

    return join_child_path(tmpdir, random_string, allocator);
}

n00b_result_t(n00b_string_t *)
n00b_new_temp_dir(n00b_string_t *prefix, n00b_string_t *suffix)
{
    n00b_string_t *dirname = n00b_new_temp_path(prefix, suffix);

    if (mkdir(dirname->data, 0774)) {
        return n00b_result_err(n00b_string_t *, errno);
    }

    return n00b_result_ok(n00b_string_t *, dirname);
}

n00b_result_t(uint32_t)
n00b_path_get_mode(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return n00b_result_err(uint32_t, EINVAL);
    }

    struct stat st;
#ifdef _WIN32
    char *native = path_windows_existing_native_cstr(path);
    if (native == nullptr || stat(native, &st) != 0) {
        return n00b_result_err(uint32_t, errno);
    }
#else
    if (stat(path->data, &st) != 0) {
        return n00b_result_err(uint32_t, errno);
    }
#endif
    return n00b_result_ok(uint32_t, (uint32_t)(st.st_mode & 07777));
}

/* libn00b ↔ POSIX boundary (n00b-api-guidelines §11): the stat(2) syscall for
 * file metadata is intentional and confined to this function so that consumers
 * use the n00b primitive (n00b_path_stat) instead of calling stat directly. */
n00b_result_t(n00b_path_info_t)
n00b_path_stat(n00b_string_t *path)
{
    n00b_path_info_t info = {};

    if (path == nullptr || path->data == nullptr) {
        return n00b_result_err(n00b_path_info_t, EINVAL);
    }

    struct stat st;
    if (stat(path->data, &st) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            /* A missing path is a normal result, not an error. */
            return n00b_result_ok(n00b_path_info_t, info);
        }
        return n00b_result_err(n00b_path_info_t, errno);
    }

    info.exists = true;
    info.is_dir = S_ISDIR(st.st_mode) ? true : false;
    info.size   = (int64_t)st.st_size;
#if defined(__APPLE__)
    info.mtime_ns = (uint64_t)st.st_mtimespec.tv_sec * 1000000000ULL
                  + (uint64_t)st.st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    info.mtime_ns = (uint64_t)st.st_mtime * 1000000000ULL;
#else
    info.mtime_ns = (uint64_t)st.st_mtim.tv_sec * 1000000000ULL
                  + (uint64_t)st.st_mtim.tv_nsec;
#endif

    return n00b_result_ok(n00b_path_info_t, info);
}

n00b_result_t(uint32_t)
n00b_path_set_mode(n00b_string_t *path, uint32_t mode)
{
    if (path == nullptr || path->data == nullptr || !mode_bits_valid(mode)) {
        return n00b_result_err(uint32_t, EINVAL);
    }

#ifdef _WIN32
    struct stat st;
    char       *native = path_windows_existing_native_cstr(path);

    if (native == nullptr || stat(native, &st) != 0) {
        return n00b_result_err(uint32_t, errno);
    }

    return n00b_result_err(uint32_t, ENOSYS);
#else
    if (chmod(path->data, (mode_t)mode) != 0) {
        return n00b_result_err(uint32_t, errno);
    }
    return n00b_path_get_mode(path);
#endif
}

n00b_result_t(bool)
_n00b_path_mkdir_p(n00b_string_t *path) _kargs
{
    uint32_t          mode           = 0775;
    bool              allow_existing = true;
    n00b_allocator_t *allocator      = nullptr;
}
{
    if (path == nullptr || path->data == nullptr || path->u8_bytes == 0
        || !mode_bits_valid(mode)) {
        return n00b_result_err(bool, EINVAL);
    }

    n00b_string_t *resolved = n00b_resolve_path_alloc(
        path,
        .allocator = allocator);
    if (resolved == nullptr || resolved->data == nullptr
        || resolved->u8_bytes == 0) {
        return n00b_result_err(bool, EINVAL);
    }

    n00b_file_kind target_kind = path_file_kind_at(resolved);

    if (target_kind == N00B_FK_IS_DIR || target_kind == N00B_FK_IS_DLINK) {
        return allow_existing ? n00b_result_ok(bool, false)
                              : n00b_result_err(bool, EEXIST);
    }
    if (target_kind != N00B_FK_NOT_FOUND) {
        return n00b_result_err(bool, EEXIST);
    }

    n00b_list_t(n00b_string_t *) *parts =
        path_split_components(resolved, allocator);
    size_t         start_ix = 0;
    n00b_string_t *current =
        n00b_string_from_raw("/", 1, .allocator = allocator);
#ifdef _WIN32
    if (resolved->u8_bytes >= 3 && resolved->data[0] == '/'
        && path_windows_has_drive_prefix(resolved->data + 1)
        && n00b_list_len(*parts) > 0) {
        current  = path_string_from_bytes(resolved->data, 3, allocator);
        start_ix = 1;
    }
#endif
    bool created = false;

    for (size_t i = start_ix; i < n00b_list_len(*parts); i++) {
        n00b_string_t *part = n00b_list_get(*parts, i);

        if (part == nullptr || part->u8_bytes == 0) {
            continue;
        }

        current = join_child_path(current, part, allocator);
        n00b_file_kind kind = path_file_kind_at(current);

        if (kind == N00B_FK_IS_DIR || kind == N00B_FK_IS_DLINK) {
            continue;
        }
        if (kind != N00B_FK_NOT_FOUND) {
            return n00b_result_err(bool, EEXIST);
        }

#ifdef _WIN32
        char *native = path_windows_native_cstr(current);
        if (native == nullptr || mkdir(native, (mode_t)mode) != 0) {
#else
        if (mkdir(current->data, (mode_t)mode) != 0) {
#endif
            int err = errno;

            if (err == EEXIST
                && path_file_kind_is_directory(path_file_kind_at(current))) {
                continue;
            }

            return n00b_result_err(bool, err);
        }

        created = true;
    }

    return n00b_result_ok(bool, created);
}

n00b_string_t *
n00b_get_temp_root(void)
{
    return acquire_base_tmp_dir();
}

// ============================================================================
// Sibling temp paths / files
// ============================================================================

static n00b_string_t *
join_child_path(n00b_string_t *dir, n00b_string_t *child,
                n00b_allocator_t *allocator)
{
    if (dir->u8_bytes && dir->data[dir->u8_bytes - 1] == '/') {
        return n00b_unicode_str_cat(dir, child, .allocator = allocator);
    }

    n00b_string_t *with_slash = n00b_unicode_str_cat(
        dir, n00b_string_from_raw("/", 1, .allocator = allocator),
        .allocator = allocator);
    return n00b_unicode_str_cat(with_slash, child, .allocator = allocator);
}

n00b_result_t(n00b_string_t *)
_n00b_new_sibling_temp_path(n00b_string_t *destination_path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!destination_path || !destination_path->u8_bytes) {
        return n00b_result_err(n00b_string_t *, EINVAL);
    }

    n00b_list_t(n00b_string_t *) *parts = n00b_path_parts(destination_path);
    if ((int)n00b_list_len(*parts) < 3) {
        return n00b_result_err(n00b_string_t *, EINVAL);
    }

    n00b_string_t *dir  = n00b_list_get(*parts, 0);
    n00b_string_t *base = n00b_list_get(*parts, 1);
    n00b_string_t *ext  = n00b_list_get(*parts, 2);
    if (!base || base->u8_bytes == 0) {
        if (!ext || ext->u8_bytes == 0) {
            return n00b_result_err(n00b_string_t *, EINVAL);
        }
        base = n00b_unicode_str_cat(
            n00b_string_from_raw(".", 1, .allocator = allocator),
            ext, .allocator = allocator);
        ext = nullptr;
    }

    n00b_string_t *name = base;
    if (ext && ext->u8_bytes) {
        n00b_string_t *dot = n00b_string_from_raw(".", 1,
                                                  .allocator = allocator);
        name = n00b_unicode_str_cat(
            n00b_unicode_str_cat(base, dot, .allocator = allocator),
            ext, .allocator = allocator);
    }

    n00b_string_t *hidden = n00b_unicode_str_cat(
        n00b_string_from_raw(".", 1, .allocator = allocator),
        name, .allocator = allocator);
    n00b_string_t *tagged = n00b_unicode_str_cat(
        hidden, n00b_string_from_raw(".n00b-", 6, .allocator = allocator),
        .allocator = allocator);
    n00b_string_t *random = n00b_fmt_hex(n00b_rand64(),
                                         .allocator = allocator);
    n00b_string_t *with_random = n00b_unicode_str_cat(tagged, random,
                                                       .allocator = allocator);
    n00b_string_t *temp_name = n00b_unicode_str_cat(
        with_random, n00b_string_from_raw(".tmp", 4, .allocator = allocator),
        .allocator = allocator);

    return n00b_result_ok(n00b_string_t *,
                          join_child_path(dir, temp_name, allocator));
}

n00b_result_t(n00b_sibling_temp_file_t *)
_n00b_new_sibling_temp_file(n00b_string_t *destination_path) _kargs
{
    uint32_t          file_mode    = 0600;
    uint32_t          max_attempts = 64;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (!mode_bits_valid(file_mode) || max_attempts == 0) {
        return n00b_result_err(n00b_sibling_temp_file_t *, EINVAL);
    }

    int last_err = EEXIST;
    for (uint32_t i = 0; i < max_attempts; i++) {
        auto path_r = n00b_new_sibling_temp_path(destination_path,
                                                 .allocator = allocator);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_err(n00b_sibling_temp_file_t *,
                                   n00b_result_get_error(path_r));
        }
        n00b_string_t *path = n00b_result_get(path_r);

        auto open_r = n00b_file_open_exclusive(path,
                                               .file_mode = file_mode,
                                               .allocator = allocator);
        if (n00b_result_is_ok(open_r)) {
            n00b_sibling_temp_file_t *temp =
                n00b_alloc(n00b_sibling_temp_file_t, .allocator = allocator);
            temp->path = path;
            temp->file = n00b_result_get(open_r);
            return n00b_result_ok(n00b_sibling_temp_file_t *, temp);
        }

        last_err = n00b_result_get_err(open_r);
        if (last_err != EEXIST) {
            return n00b_result_err(n00b_sibling_temp_file_t *, last_err);
        }
    }

    return n00b_result_err(n00b_sibling_temp_file_t *, last_err);
}

static bool
sibling_parent_and_base(n00b_string_t     *destination_path,
                        n00b_string_t    **parent,
                        n00b_string_t    **base,
                        n00b_allocator_t  *allocator)
{
    if (destination_path == nullptr
        || destination_path->data == nullptr
        || destination_path->u8_bytes == 0) {
        return false;
    }

    n00b_string_t *resolved =
        n00b_resolve_path_alloc(destination_path, .allocator = allocator);
    if (resolved == nullptr
        || resolved->data == nullptr
        || resolved->u8_bytes == 0) {
        return false;
    }

    size_t end = resolved->u8_bytes;
    while (end > 1 && resolved->data[end - 1] == '/') {
        end--;
    }

    if (end == 1) {
        return false;
    }

    size_t slash = SIZE_MAX;
    for (size_t i = 0; i < end; i++) {
        if (resolved->data[i] == '/') {
            slash = i;
        }
    }

    if (slash == SIZE_MAX || slash + 1 >= end) {
        return false;
    }

    if (slash == 0) {
        *parent = n00b_string_from_raw("/", 1, .allocator = allocator);
    }
    else {
        *parent = n00b_string_from_raw(resolved->data,
                                       (int64_t)slash,
                                       .allocator = allocator);
    }

    *base = n00b_string_from_raw(resolved->data + slash + 1,
                                 (int64_t)(end - slash - 1),
                                 .allocator = allocator);
    return *base != nullptr && (*base)->u8_bytes != 0;
}

static n00b_string_t *
sibling_temp_dir_candidate(n00b_string_t    *parent,
                           n00b_string_t    *base,
                           n00b_allocator_t *allocator)
{
    n00b_string_t *hidden = n00b_unicode_str_cat(
        n00b_string_from_raw(".", 1, .allocator = allocator),
        base,
        .allocator = allocator);
    n00b_string_t *tagged = n00b_unicode_str_cat(
        hidden,
        n00b_string_from_raw(".n00b-", 6, .allocator = allocator),
        .allocator = allocator);
    n00b_string_t *random =
        n00b_fmt_hex(n00b_rand64(), .allocator = allocator);
    n00b_string_t *with_random =
        n00b_unicode_str_cat(tagged, random, .allocator = allocator);
    n00b_string_t *name = n00b_unicode_str_cat(
        with_random,
        n00b_string_from_raw(".tmpdir", 7, .allocator = allocator),
        .allocator = allocator);

    return join_child_path(parent, name, allocator);
}

n00b_result_t(n00b_string_t *)
_n00b_new_sibling_temp_dir(n00b_string_t *destination_path) _kargs
{
    uint32_t          directory_mode = 0775;
    uint32_t          max_attempts   = 64;
    n00b_allocator_t *allocator      = nullptr;
}
{
    if (!mode_bits_valid(directory_mode) || max_attempts == 0) {
        return n00b_result_err(n00b_string_t *, EINVAL);
    }

    n00b_string_t *parent = nullptr;
    n00b_string_t *base   = nullptr;
    if (!sibling_parent_and_base(destination_path,
                                 &parent,
                                 &base,
                                 allocator)) {
        return n00b_result_err(n00b_string_t *, EINVAL);
    }

    int last_err = EEXIST;
    for (uint32_t i = 0; i < max_attempts; i++) {
        n00b_string_t *path =
            sibling_temp_dir_candidate(parent, base, allocator);

#ifdef _WIN32
        char *native = path_windows_native_cstr(path);
        if (native != nullptr && mkdir(native, (mode_t)directory_mode) == 0) {
#else
        if (mkdir(path->data, (mode_t)directory_mode) == 0) {
#endif
            return n00b_result_ok(n00b_string_t *, path);
        }

        last_err = errno;
        if (last_err != EEXIST) {
            return n00b_result_err(n00b_string_t *, last_err);
        }
    }

    return n00b_result_err(n00b_string_t *, last_err);
}

// ============================================================================
// Path normalization
// ============================================================================

static n00b_string_t *
remove_extra_slashes(n00b_string_t *result)
{
    int i = result->codepoints;

    while (i > 1 && result->data[--i] == '/') {
        result->data[i]  = 0;
        result->codepoints--;
        result->u8_bytes--;
    }

    return result;
}

n00b_string_t *
n00b_get_user_dir(n00b_string_t *user)
{
#ifdef _WIN32
    if (user != nullptr) {
        return user;
    }

    const char *home = getenv("HOME");
    if (home == nullptr || home[0] == '\0') {
        home = getenv("USERPROFILE");
    }

    return remove_extra_slashes(
        home == nullptr ? n00b_string_from_cstr("/")
                        : path_windows_api_string(home, nullptr));
#else
    n00b_string_t *result;
    struct passwd *pw;

    if (user == nullptr) {
        const char *home = getenv("HOME");

        if (home) {
            result = n00b_string_from_cstr(home);
        }
        else {
            pw = getpwent();
            result = (pw == nullptr)
                ? r"/"
                : n00b_string_from_cstr(pw->pw_dir);
        }
    }
    else {
        pw = getpwnam(user->data);
        if (pw == nullptr) {
            return user;
        }
        result = n00b_string_from_cstr(pw->pw_dir);
    }

    return remove_extra_slashes(result);
#endif
}

static n00b_string_t *
internal_normalize_and_join(n00b_list_t(n00b_string_t *) *pieces)
{
    int partlen = (int)n00b_list_len(*pieces);
    int nextout = 0;

    for (int i = 0; i < partlen; i++) {
        n00b_string_t *s = n00b_list_get(*pieces, i);

        if (s->codepoints == 0) continue;

        if (s->data[0] == '.') {
            if (s->codepoints == 1) continue;
            if (s->codepoints == 2 && s->data[1] == '.') {
                --nextout;
                continue;
            }
        }

        if (nextout < 0) return nullptr;

        n00b_list_set(*pieces, nextout++, s);
    }

    if (nextout == 0) {
        return r"/";
    }

    n00b_string_t *result = nullptr;

    for (int i = 0; i < nextout; i++) {
        n00b_string_t *s = n00b_list_get(*pieces, i);
        if (!s->codepoints) continue;

        if (!result) {
            result = n00b_cformat("/«#»", s);
        }
        else {
            result = n00b_cformat("«#»/«#»", result, s);
        }
    }

    return result;
}

n00b_string_t *
n00b_path_tilde_expand(n00b_string_t *in)
{
    ensure_cached();

    if (!in || !in->codepoints) {
        in = cached_slash;
    }

    if (in->data[0] != '~') {
        return internal_normalize_and_join(split_on_slash(in));
    }

    n00b_list_t(n00b_string_t *) *parts = split_on_slash(in);
    n00b_string_t *home = n00b_list_get(*parts, 0);

    n00b_list_t(n00b_string_t *) *home_parts;

    if (home->codepoints == 1) {
        n00b_list_set(*parts, 0, n00b_string_empty());
        home_parts = split_on_slash(n00b_get_user_dir(nullptr));
    }
    else {
        n00b_string_t *username =
            n00b_unicode_str_slice(home, 1, home->codepoints);
        n00b_list_set(*parts, 0, n00b_string_empty());
        home_parts = split_on_slash(n00b_get_user_dir(username));
    }

    // Canonical idiom: the list is internally-scoped (passed to
    // internal_normalize_and_join which only reads it), so use a
    // by-value lvalue and pass `&lst` to the consumer.
    n00b_list_t(n00b_string_t *) combined = n00b_list_new(n00b_string_t *);

    for (size_t i = 0; i < n00b_list_len(*home_parts); i++) {
        n00b_list_push(combined, n00b_list_get(*home_parts, i));
    }
    for (size_t i = 0; i < n00b_list_len(*parts); i++) {
        n00b_list_push(combined, n00b_list_get(*parts, i));
    }

    return internal_normalize_and_join(&combined);
}

n00b_string_t *
n00b_resolve_path(n00b_string_t *s)
{
    if (s == nullptr || s->codepoints == 0) {
        return n00b_get_user_dir(nullptr);
    }

    switch (s->data[0]) {
    case '~':
        return n00b_path_tilde_expand(s);
    case '/':
        return internal_normalize_and_join(split_on_slash(s));
    default: {
#ifdef _WIN32
        if (path_windows_has_drive_prefix(s->data)) {
            return path_windows_normalize_drive_path(s, nullptr);
        }
#endif
        n00b_list_t(n00b_string_t *) *parts =
            split_on_slash(n00b_get_current_directory());
        n00b_list_t(n00b_string_t *) *rel = split_on_slash(s);
        size_t rn = n00b_list_len(*rel);

        for (size_t i = 0; i < rn; i++) {
            n00b_list_push(*parts, n00b_list_get(*rel, i));
        }

        return internal_normalize_and_join(parts);
    }
    }
}

n00b_string_t *
_n00b_resolve_path_alloc(n00b_string_t *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (path == nullptr || path->codepoints == 0) {
        return path_user_dir(nullptr, allocator);
    }

    switch (path->data[0]) {
    case '~':
        return path_tilde_expand_alloc(path, allocator);
    case '/':
        return path_normalize_absolute(path, allocator);
    default: {
#ifdef _WIN32
        if (path_windows_has_drive_prefix(path->data)) {
            return path_windows_normalize_drive_path(path, allocator);
        }
#endif
        n00b_string_t *cwd = path_current_directory(allocator);

        if (cwd == nullptr) {
            return nullptr;
        }

        return path_normalize_absolute(join_child_path(cwd,
                                                       path,
                                                       allocator),
                                       allocator);
    }
    }
}

// ============================================================================
// Path joining
// ============================================================================

n00b_string_t *
n00b_path_join(n00b_list_t(n00b_string_t *) *items)
{
    int len   = 0;
    int first = 0;
    int last  = (int)n00b_list_len(*items);
    int tmplen;

    for (int i = 0; i < last; i++) {
        n00b_string_t *tmp = n00b_list_get(*items, i);
        tmplen = (int)tmp->u8_bytes;

        if (tmplen == 0) continue;

        if (tmp->data[0] == '/') {
            len   = tmplen;
            first = i;
        }
        else {
            len += tmplen;
        }

        if ((i + 1 != last) && (tmp->data[tmplen - 1] != '/'))
            len++;
    }

    char *buf = n00b_alloc_array(char, len + 1);
    char *p   = buf;

    for (int i = first; i < last; i++) {
        n00b_string_t *tmp = n00b_list_get(*items, i);
        tmplen = (int)tmp->u8_bytes;

        if (tmplen == 0) continue;

        memcpy(p, tmp->data, tmplen);
        p += tmplen;

        if ((i + 1 != last) && (tmp->data[tmplen - 1] != '/'))
            *p++ = '/';
    }

    *p = '\0';
    return n00b_string_from_cstr(buf);
}

// ============================================================================
// File kind / stat
// ============================================================================

n00b_file_kind
n00b_get_file_kind(n00b_string_t *p)
{
    struct stat file_info;

    p = n00b_resolve_path(p);

#ifdef _WIN32
    char *native = path_windows_existing_native_cstr(p);
    if (native == nullptr || lstat(native, &file_info) != 0) {
        return N00B_FK_NOT_FOUND;
    }

    if (path_is_windows_af_unix_socket(native)) {
        return N00B_FK_IS_SOCK;
    }
#else
    if (lstat(p->data, &file_info) != 0)
        return N00B_FK_NOT_FOUND;
#endif

    switch (file_info.st_mode & S_IFMT) {
    case S_IFREG:  return N00B_FK_IS_REG_FILE;
    case S_IFDIR:  return N00B_FK_IS_DIR;
    case S_IFSOCK: return N00B_FK_IS_SOCK;
    case S_IFCHR:  return N00B_FK_IS_CHR_DEVICE;
    case S_IFBLK:  return N00B_FK_IS_BLOCK_DEVICE;
    case S_IFIFO:  return N00B_FK_IS_FIFO;
    case S_IFLNK:
#ifdef _WIN32
        if (stat(native, &file_info) != 0) return N00B_FK_NOT_FOUND;
#else
        if (stat(p->data, &file_info) != 0) return N00B_FK_NOT_FOUND;
#endif
        switch (file_info.st_mode & S_IFMT) {
        case S_IFREG: return N00B_FK_IS_FLINK;
        case S_IFDIR: return N00B_FK_IS_DLINK;
        default:      return N00B_FK_OTHER;
        }
    default: return N00B_FK_OTHER;
    }
}

// ============================================================================
// Directory walking
// ============================================================================

typedef struct {
    n00b_string_t                *sc_proc;
    n00b_string_t                *sc_dev;
    n00b_list_t(n00b_string_t *) *result;
    n00b_string_t                *resolved;
    bool                          recurse;
    bool                          yield_links;
    bool                          yield_dirs;
    bool                          follow_links;
    bool                          ignore_special;
    bool                          done_with_safety_checks;
    bool                          have_recursed;
} n00b_walk_ctx;

static n00b_string_t *
add_slash_if_needed(n00b_string_t *s)
{
    if (s->u8_bytes && s->data[s->u8_bytes - 1] == '/') return s;
    return n00b_cformat("«#»/", s);
}

static void
internal_path_walk(n00b_walk_ctx *ctx)
{
    DIR           *dirobj;
    struct dirent *entry;
    n00b_string_t *saved;
    struct stat    file_info;

    if (!ctx->done_with_safety_checks) {
        if (n00b_unicode_str_starts_with(ctx->resolved, ctx->sc_proc)) return;
        if (n00b_unicode_str_starts_with(ctx->resolved, ctx->sc_dev))  return;
        if (ctx->resolved->codepoints != 1) ctx->done_with_safety_checks = true;
    }

    if (lstat(ctx->resolved->data, &file_info) != 0) return;

    switch (file_info.st_mode & S_IFMT) {
    case S_IFREG:
        n00b_list_push(*ctx->result, ctx->resolved);
        return;

    case S_IFDIR:
        if (ctx->yield_dirs) {
            n00b_list_push(*ctx->result, ctx->resolved);
            return;
        }

actual_directory:
        if (!ctx->recurse) {
            if (ctx->have_recursed) return;
            ctx->have_recursed = true;
        }

        ctx->resolved = add_slash_if_needed(ctx->resolved);
        dirobj = opendir(ctx->resolved->data);
        if (dirobj == nullptr) return;

        saved = ctx->resolved;

        while (true) {
            entry = readdir(dirobj);
            if (entry == nullptr) {
                closedir(dirobj);
                ctx->resolved = saved;
                return;
            }

            if (!strcmp(entry->d_name, "..") || !strcmp(entry->d_name, "."))
                continue;

            ctx->resolved = n00b_unicode_str_cat(
                saved, n00b_string_from_cstr(entry->d_name));
            internal_path_walk(ctx);
        }

        ctx->resolved = saved;
        return;

    case S_IFLNK:
        if (stat(ctx->resolved->data, &file_info) != 0) return;

        switch (file_info.st_mode & S_IFMT) {
        case S_IFREG:
            if (ctx->follow_links && ctx->yield_links) {
                char buf[PATH_MAX + 1] = {0};
                int n = readlink(ctx->resolved->data, buf, PATH_MAX);
                if (n == -1) return;
                buf[n] = 0;
                n00b_list_push(*ctx->result,
                               n00b_resolve_path(n00b_string_from_cstr(buf)));
            }
            else if (ctx->yield_links) {
                n00b_list_push(*ctx->result, ctx->resolved);
            }
            return;

        case S_IFDIR:
            if (ctx->yield_dirs && ctx->yield_links)
                n00b_list_push(*ctx->result, ctx->resolved);

            if (!ctx->follow_links || !ctx->recurse) return;

            saved = ctx->resolved;
            char lbuf[PATH_MAX + 1] = {0};
            int ln = readlink(ctx->resolved->data, lbuf, PATH_MAX);
            if (ln == -1) return;
            lbuf[ln] = 0;

            ctx->resolved = n00b_resolve_path(n00b_string_from_cstr(lbuf));
            if (ctx->yield_dirs && !ctx->yield_links)
                n00b_list_push(*ctx->result, ctx->resolved);

            goto actual_directory;

        default:
            if (!ctx->ignore_special)
                n00b_list_push(*ctx->result, ctx->resolved);
            return;
        }

    default:
        if (!ctx->ignore_special)
            n00b_list_push(*ctx->result, ctx->resolved);
        return;
    }
}

n00b_list_t(n00b_string_t *) *
_n00b_path_walk(n00b_string_t *dir) _kargs
{
    bool recurse        = true;
    bool yield_links    = false;
    bool yield_dirs     = false;
    bool ignore_special = true;
    bool follow_links   = false;
}
{
    // Canonical idiom for by-pointer return: build the list as a
    // fully scan-info-threaded lvalue, populate via internal_path_walk
    // (which pushes via the result pointer), then struct-copy the
    // populated lvalue into the heap-allocated return shell. The
    // struct-copy carries scan_kind / scan_cb / scan_user / allocator
    // into the heap allocation so the GC sees the correct shape.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);

    n00b_walk_ctx ctx = {
        .sc_proc                 = r"/proc/",
        .sc_dev                  = r"/dev/",
        .recurse                 = recurse,
        .yield_links             = yield_links,
        .yield_dirs              = yield_dirs,
        .follow_links            = follow_links,
        .ignore_special          = ignore_special,
        .done_with_safety_checks = false,
        .have_recursed           = false,
        .result                  = &lst,
        .resolved                = n00b_resolve_path(dir),
    };

    internal_path_walk(&ctx);

    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *result = lst;
    return result;
}

// ============================================================================
// App path
// ============================================================================

#ifdef __linux__
n00b_string_t *
n00b_app_path(void)
{
    char buf[PATH_MAX];
    char proc_path[PATH_MAX];

    snprintf(proc_path, PATH_MAX, "/proc/%d/exe", getpid());
    ssize_t n = readlink(proc_path, buf, PATH_MAX - 1);
    if (n < 0) return r".";
    buf[n] = 0;

    return n00b_resolve_path(n00b_string_from_cstr(buf));
}
#elif defined(__MACH__)
n00b_string_t *
n00b_app_path(void)
{
    char buf[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(getpid(), buf, PROC_PIDPATHINFO_MAXSIZE);
    return n00b_resolve_path(n00b_string_from_cstr(buf));
}
#elif defined(_WIN32)
n00b_string_t *
n00b_app_path(void)
{
    return n00b_string_from_cstr(".");
}
#else
#error "Unsupported platform"
#endif

// ============================================================================
// Path trimming / stripping / extension
// ============================================================================

n00b_string_t *
n00b_path_trim_trailing_slashes(n00b_string_t *s)
{
    int b_len = (int)s->u8_bytes;

    if (!b_len || s->data[b_len - 1] != '/') return s;

    s = n00b_unicode_str_copy(s);

    do {
        s->data[--b_len] = 0;
        s->codepoints--;
        s->u8_bytes--;
    } while (b_len && s->data[b_len - 1] == '/');

    return s;
}

void
n00b_path_strip_slashes_both_ends(n00b_string_t *s)
{
    while (s->u8_bytes && s->data[0] == '/') {
        s->data++;
        s->u8_bytes--;
        s->codepoints--;
    }

    while (s->u8_bytes && s->data[s->u8_bytes - 1] == '/') {
        s->data[--s->u8_bytes] = 0;
        s->codepoints--;
    }
}

n00b_string_t *
n00b_path_chop_extension(n00b_string_t *s)
{
    int n = rfind_period(s);
    int m = rfind_slash(s);

    if (n <= m) return n00b_string_empty();

    n00b_string_t *result = n00b_unicode_str_slice(s, n, s->codepoints);
    s->codepoints -= result->codepoints;
    s->u8_bytes   -= result->u8_bytes;
    s->data[s->u8_bytes] = 0;

    return result;
}

n00b_string_t *
n00b_filename_from_path(n00b_string_t *s)
{
    if (find_slash(s) == -1) return s;

    n00b_string_t *resolved = n00b_resolve_path(s);
    n00b_path_strip_slashes_both_ends(resolved);

    int n = rfind_slash(resolved);
    if (n == -1) return resolved;

    return n00b_unicode_str_slice(resolved, n + 1, resolved->codepoints);
}

n00b_string_t *
n00b_path_get_extension(n00b_string_t *s)
{
    int n = rfind_period(s);
    int m = rfind_slash(s);

    if (n <= m) return n00b_string_empty();
    return n00b_unicode_str_slice(s, n, s->codepoints);
}

n00b_string_t *
n00b_path_remove_extension(n00b_string_t *s)
{
    int n = rfind_period(s);
    int m = rfind_slash(s);

    if (n <= m) return s;
    return n00b_unicode_str_slice(s, 0, n);
}

n00b_list_t(n00b_string_t *) *
n00b_path_parts(n00b_string_t *p)
{
    // Canonical idiom for by-pointer return: populate a fully
    // scan-info-threaded lvalue first, then struct-copy into the
    // heap-allocated return shell so the GC sees the threaded
    // scan_kind / scan_cb / scan_user / allocator on the heap struct.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);

    if (p && p->u8_bytes) {
        n00b_string_t *resolved = n00b_resolve_path(p);

        if (p->data[p->u8_bytes - 1] == '/'
            || resolved->data[resolved->u8_bytes - 1] == '/') {
            n00b_list_push(lst, resolved);
            n00b_list_push(lst, n00b_string_empty());
            n00b_list_push(lst, n00b_string_empty());
        }
        else {
            int n = rfind_slash(resolved);

            n00b_list_push(lst, n00b_unicode_str_slice(resolved, 0, n));

            n00b_string_t *filename =
                n00b_unicode_str_slice(resolved, n + 1, resolved->codepoints);

            int dot = rfind_period(filename);

            if (dot == -1) {
                n00b_list_push(lst, filename);
                n00b_list_push(lst, n00b_string_empty());
            }
            else {
                n00b_list_push(lst, n00b_unicode_str_slice(filename, 0, dot));
                n00b_list_push(lst,
                               n00b_unicode_str_slice(filename, dot + 1,
                                                      filename->codepoints));
            }
        }
    }

    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *result = lst;
    return result;
}

// ============================================================================
// File finding / command paths
// ============================================================================

n00b_list_t(n00b_string_t *) *
n00b_find_file_in_program_path(n00b_string_t *cmd,
                                n00b_list_t(n00b_string_t *) *path_list)
{
    // Canonical idiom for by-pointer return: populate a fully
    // scan-info-threaded lvalue first, then struct-copy into the
    // heap-allocated return shell.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);

    if (!path_list) {
        path_list = n00b_get_program_search_path();
    }

    cmd = n00b_filename_from_path(cmd);

    size_t n = n00b_list_len(*path_list);

    for (size_t i = 0; i < n; i++) {
        n00b_string_t *dir       = n00b_list_get(*path_list, i);
        dir                      = n00b_resolve_path(dir);
        n00b_string_t *full_path = n00b_path_simple_join(dir, cmd);

        switch (n00b_get_file_kind(full_path)) {
        case N00B_FK_IS_REG_FILE:
        case N00B_FK_IS_FLINK:
            n00b_list_push(lst, full_path);
            break;
        default:
            break;
        }
    }

    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *result = lst;
    return result;
}

n00b_list_t(n00b_string_t *) *
n00b_find_command_paths(n00b_string_t *cmd,
                         n00b_list_t(n00b_string_t *) *path_list,
                         bool self_ok)
{
    n00b_list_t(n00b_string_t *) *result =
        n00b_find_file_in_program_path(cmd, path_list);

    int            n          = (int)n00b_list_len(*result);
    n00b_string_t *my_path    = nullptr;

#ifdef _WIN32
    if (!self_ok) {
        my_path = n00b_app_path();
    }

    while (n--) {
        n00b_string_t *path = n00b_list_get(*result, n);

        if (!self_ok && n00b_unicode_str_eq(path, my_path)) {
            n00b_list_delete(*result, n);
        }
    }

    return result;
#else
    uid_t          my_euid    = geteuid();
    int            num_groups = -1;
    gid_t          groups[NGROUPS_MAX];

    if (!self_ok) {
        my_path = n00b_app_path();
    }

    while (n--) {
        n00b_string_t *path = n00b_list_get(*result, n);

        if (!self_ok && n00b_unicode_str_eq(path, my_path)) {
            (void)n00b_list_delete(*result, n);
            continue;
        }

        struct stat file_info;

        if (stat(path->data, &file_info) != 0) {
            (void)n00b_list_delete(*result, n);
            continue;
        }

        int exe_bits = file_info.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH);

        if (!exe_bits) {
            (void)n00b_list_delete(*result, n);
            continue;
        }

        if (exe_bits & S_IXOTH) continue;
        if ((exe_bits & S_IXUSR) && file_info.st_uid == my_euid) continue;

        if (num_groups < 0) {
            num_groups = getgroups(NGROUPS_MAX, groups);
        }

        gid_t program_gid = file_info.st_gid;

        for (int i = 0; i < num_groups; i++) {
            if (program_gid == groups[i]) goto on_success;
        }

        (void)n00b_list_delete(*result, n);
on_success:
        continue;
    }

    return result;
#endif
}

// ============================================================================
// Rename
// ============================================================================

n00b_result_t(n00b_string_t *)
n00b_rename(n00b_string_t *from, n00b_string_t *to)
{
    from = n00b_resolve_path(from);
    to   = n00b_resolve_path(to);

    if (!n00b_file_exists(from)) {
        return n00b_result_err(n00b_string_t *, ENOENT);
    }

    if (n00b_file_exists(to)) {
        n00b_list_t(n00b_string_t *) *parts = n00b_path_parts(to);

        if ((int)n00b_list_len(*parts) < 3) {
            return n00b_result_err(n00b_string_t *, EINVAL);
        }

        n00b_string_t *base = n00b_list_get(*parts, 0);
        n00b_string_t *name = n00b_list_get(*parts, 1);
        n00b_string_t *ext  = n00b_list_get(*parts, 2);
        int            i    = 0;

        if (ext->codepoints) {
            ext = n00b_cformat(".«#»", ext);
        }

        do {
            to = n00b_cformat("«#»/«#».«#:d»«#»", base, name, (int64_t)++i, ext);
        } while (n00b_file_exists(to));
    }

    if (rename(from->data, to->data)) {
        return n00b_result_err(n00b_string_t *, errno);
    }

    return n00b_result_ok(n00b_string_t *, to);
}

static n00b_result_t(int)
rename_no_replace(n00b_string_t *from, n00b_string_t *to)
{
#if defined(_WIN32)
    char *native_from = path_windows_native_cstr(from);
    char *native_to   = path_windows_native_cstr(to);

    if (native_from == nullptr || native_to == nullptr) {
        return n00b_result_err(int, EINVAL);
    }

    if (!MoveFileExA(native_from, native_to, MOVEFILE_WRITE_THROUGH)) {
        return n00b_result_err(int, path_windows_errno(GetLastError()));
    }
    return n00b_result_ok(int, 0);
#elif defined(__MACH__) && defined(RENAME_EXCL)
    if (renamex_np(from->data, to->data, RENAME_EXCL) != 0) {
        return n00b_result_err(int, errno);
    }
    return n00b_result_ok(int, 0);
#elif defined(__linux__) && defined(SYS_renameat2) && defined(RENAME_NOREPLACE)
    long rc = syscall(SYS_renameat2,
                      AT_FDCWD, from->data,
                      AT_FDCWD, to->data,
                      RENAME_NOREPLACE);
    if (rc != 0) {
        return n00b_result_err(int, errno);
    }
    return n00b_result_ok(int, 0);
#else
    (void)from;
    (void)to;
    return n00b_result_err(int, ENOSYS);
#endif
}

n00b_result_t(n00b_string_t *)
_n00b_path_commit_exact(n00b_string_t *source_path,
                        n00b_string_t *destination_path) _kargs
{
    n00b_path_commit_policy_t policy = N00B_PATH_COMMIT_REJECT_EXISTING;
}
{
    if (!source_path || !source_path->data
        || !destination_path || !destination_path->data
        || source_path->u8_bytes == 0 || destination_path->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *, EINVAL);
    }

    switch (policy) {
    case N00B_PATH_COMMIT_REPLACE_EXISTING:
#ifdef _WIN32
    {
        char *native_source = path_windows_native_cstr(source_path);
        char *native_dest   = path_windows_native_cstr(destination_path);

        if (native_source == nullptr || native_dest == nullptr) {
            return n00b_result_err(n00b_string_t *, EINVAL);
        }

        if (!MoveFileExA(native_source,
                         native_dest,
                         MOVEFILE_REPLACE_EXISTING
                             | MOVEFILE_WRITE_THROUGH)) {
            return n00b_result_err(n00b_string_t *,
                                   path_windows_errno(GetLastError()));
        }
        return n00b_result_ok(n00b_string_t *, destination_path);
    }
#else
        if (rename(source_path->data, destination_path->data) != 0) {
            return n00b_result_err(n00b_string_t *, errno);
        }
        return n00b_result_ok(n00b_string_t *, destination_path);
#endif

    case N00B_PATH_COMMIT_REJECT_EXISTING: {
        auto rr = rename_no_replace(source_path, destination_path);
        if (n00b_result_is_err(rr)) {
            return n00b_result_err(n00b_string_t *, n00b_result_get_error(rr));
        }
        return n00b_result_ok(n00b_string_t *, destination_path);
    }

    default:
        return n00b_result_err(n00b_string_t *, EINVAL);
    }
}

// ============================================================================
// Unlink
// ============================================================================
//
// `n00b_file_unlink` is the canonical libn00b wrapper for POSIX
// `unlink(2)`. It is the project's "n00b<->POSIX line" for delete
// semantics — consumer modules must not reach for `<unistd.h>` /
// `<errno.h>` to perform a remove, since the wrapper is here. The
// `ignore_missing` kwarg gives idempotent delete semantics for the
// common "remove if present" case.

n00b_result_t(bool)
_n00b_file_unlink(n00b_string_t *path) _kargs
{
    bool ignore_missing = false;
}
{
#ifdef _WIN32
    char *native = path_windows_native_cstr(path);
    if (native == nullptr) {
        return n00b_result_err(bool, EINVAL);
    }
    if (unlink(native) == 0) {
#else
    if (unlink(path->data) == 0) {
#endif
        return n00b_result_ok(bool, true);
    }
    int err = errno;
    if (err == ENOENT && ignore_missing) {
        return n00b_result_ok(bool, false);
    }
    return n00b_result_err(bool, err);
}

static n00b_result_t(bool)
path_remove_tree_inner(n00b_string_t    *path,
                       n00b_allocator_t *allocator)
{
    struct stat st;

#ifdef _WIN32
    char *native = path_windows_native_cstr(path);

    if (native == nullptr) {
        return n00b_result_err(bool, EINVAL);
    }

    if (lstat(native, &st) != 0) {
        return n00b_result_err(bool, errno);
    }

    if ((st.st_mode & S_IFMT) != S_IFDIR) {
        if (unlink(native) != 0) {
            return n00b_result_err(bool, errno);
        }

        return n00b_result_ok(bool, true);
    }

    char *pattern = path_windows_find_pattern(native);
    WIN32_FIND_DATAA data = {};
    HANDLE dir = FindFirstFileA(pattern, &data);
    int err = 0;

    if (dir == INVALID_HANDLE_VALUE) {
        err = path_windows_errno(GetLastError());
        if (err != ENOENT) {
            return n00b_result_err(bool, err);
        }
        err = 0;
    }
    else {
        do {
            if (strcmp(data.cFileName, ".") == 0
                || strcmp(data.cFileName, "..") == 0) {
                continue;
            }

            n00b_string_t *name =
                n00b_string_from_cstr(data.cFileName, .allocator = allocator);
            n00b_string_t *child = join_child_path(path, name, allocator);
            auto child_r = path_remove_tree_inner(child, allocator);

            if (n00b_result_is_err(child_r)) {
                err = n00b_result_get_err(child_r);
                break;
            }
        } while (FindNextFileA(dir, &data));

        if (err == 0) {
            DWORD last = GetLastError();
            if (last != ERROR_NO_MORE_FILES) {
                err = path_windows_errno(last);
            }
        }

        if (!FindClose(dir) && err == 0) {
            err = path_windows_errno(GetLastError());
        }

        if (err != 0) {
            return n00b_result_err(bool, err);
        }
    }

    if (rmdir(native) != 0) {
        return n00b_result_err(bool, errno);
    }

    return n00b_result_ok(bool, true);
#else
    if (lstat(path->data, &st) != 0) {
        return n00b_result_err(bool, errno);
    }

    if ((st.st_mode & S_IFMT) != S_IFDIR) {
        if (unlink(path->data) != 0) {
            return n00b_result_err(bool, errno);
        }

        return n00b_result_ok(bool, true);
    }

    DIR *dir = opendir(path->data);
    if (dir == nullptr) {
        return n00b_result_err(bool, errno);
    }

    int err = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);

        if (entry == nullptr) {
            err = errno;
            break;
        }

        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        n00b_string_t *name =
            n00b_string_from_cstr(entry->d_name, .allocator = allocator);
        n00b_string_t *child = join_child_path(path, name, allocator);
        auto child_r = path_remove_tree_inner(child, allocator);

        if (n00b_result_is_err(child_r)) {
            err = n00b_result_get_err(child_r);
            break;
        }
    }

    if (closedir(dir) != 0 && err == 0) {
        err = errno;
    }

    if (err != 0) {
        return n00b_result_err(bool, err);
    }

    if (rmdir(path->data) != 0) {
        return n00b_result_err(bool, errno);
    }

    return n00b_result_ok(bool, true);
#endif
}

n00b_result_t(bool)
_n00b_path_remove_tree(n00b_string_t *path) _kargs
{
    bool              ignore_missing = false;
    n00b_allocator_t *allocator      = nullptr;
}
{
    if (path == nullptr || path->data == nullptr || path->u8_bytes == 0) {
        return n00b_result_err(bool, EINVAL);
    }

    n00b_string_t *resolved =
        n00b_resolve_path_alloc(path, .allocator = allocator);
    if (resolved == nullptr
        || resolved->data == nullptr
        || resolved->u8_bytes == 0
        || (resolved->u8_bytes == 1 && resolved->data[0] == '/')) {
        return n00b_result_err(bool, EINVAL);
    }

    auto remove_r = path_remove_tree_inner(resolved, allocator);
    if (n00b_result_is_ok(remove_r)) {
        return remove_r;
    }

    int err = n00b_result_get_err(remove_r);
    if (err == ENOENT && ignore_missing) {
        return n00b_result_ok(bool, false);
    }

    return n00b_result_err(bool, err);
}

// ============================================================================
// List directory
// ============================================================================

// ============================================================================
// Typed-variadic path join
// ============================================================================
//
// User direction 2026-05-21: "if we use our typed varargs, we don't
// really need the array version. The implementation could even do a
// list wrapper around the input for join." The variadic accepts a
// required leading component plus zero or more `n00b_string_t *`
// pieces, packs them into a by-value private-list lvalue, and
// delegates to the existing list-based `n00b_path_join` core.

n00b_string_t *
n00b_path_join_v(n00b_string_t *first, n00b_string_t * +)
{
    n00b_list_t(n00b_string_t *) parts =
        n00b_list_new_private(n00b_string_t *);

    n00b_list_push(parts, first);

    unsigned int count = n00b_remaining_vargs(vargs);
    for (unsigned int i = 0; i < count; i++) {
        n00b_string_t *piece = (n00b_string_t *)n00b_vargs_next(vargs);
        n00b_list_push(parts, piece);
    }

    return n00b_path_join(&parts);
}

// ============================================================================
// XDG Base Directory resolvers
// ============================================================================
//
// Per https://specifications.freedesktop.org/basedir-spec/latest/ —
// the `*_HOME` variants fall back to a `$HOME/`-relative default
// when the corresponding env var is unset or empty; `XDG_RUNTIME_DIR`
// has no spec-mandated fallback. Trailing slashes are stripped per
// the spec's "no trailing slash" convention.
//
// `getenv` use here matches the existing path-module pattern at
// `acquire_base_tmp_dir` and `n00b_get_program_search_path`.

static n00b_string_t *
xdg_home_or_fallback(const char *env_name, const char *home_relative)
{
    const char *v = getenv(env_name);
    if (v != nullptr && v[0] != '\0') {
        return remove_extra_slashes(n00b_string_from_cstr(v));
    }
    // Spec: empty $XDG_*_HOME = treated as unset, use $HOME-relative
    // fallback. n00b_get_user_dir(nullptr) returns $HOME (or pwent
    // fallback), already with trailing slashes stripped.
    return remove_extra_slashes(
        n00b_cformat("«#»«#»",
                     n00b_get_user_dir(nullptr),
                     n00b_string_from_cstr(home_relative)));
}

n00b_string_t *
n00b_xdg_config_home(void)
{
    return xdg_home_or_fallback("XDG_CONFIG_HOME", "/.config");
}

n00b_string_t *
n00b_xdg_data_home(void)
{
    return xdg_home_or_fallback("XDG_DATA_HOME", "/.local/share");
}

n00b_string_t *
n00b_xdg_cache_home(void)
{
    return xdg_home_or_fallback("XDG_CACHE_HOME", "/.cache");
}

n00b_string_t *
n00b_xdg_state_home(void)
{
    return xdg_home_or_fallback("XDG_STATE_HOME", "/.local/state");
}

n00b_string_t *
n00b_xdg_runtime_dir(void)
{
    const char *v = getenv("XDG_RUNTIME_DIR");
    if (v == nullptr || v[0] == '\0') {
        return nullptr;
    }
    return remove_extra_slashes(n00b_string_from_cstr(v));
}

// Shared helper: join base + app + variadic-tail pieces into a list
// and delegate to n00b_path_join. base = nullptr (e.g. runtime-dir
// unset) propagates nullptr.
static n00b_string_t *
xdg_join_under(n00b_string_t *base,
               n00b_string_t *app,
               n00b_vargs_t  *tail_vargs)
{
    if (base == nullptr) {
        return nullptr;
    }

    n00b_list_t(n00b_string_t *) parts =
        n00b_list_new_private(n00b_string_t *);

    n00b_list_push(parts, base);
    n00b_list_push(parts, app);

    unsigned int count = n00b_remaining_vargs(tail_vargs);
    for (unsigned int i = 0; i < count; i++) {
        n00b_string_t *piece =
            (n00b_string_t *)n00b_vargs_next(tail_vargs);
        n00b_list_push(parts, piece);
    }

    return n00b_path_join(&parts);
}

n00b_string_t *
n00b_xdg_config_path(n00b_string_t *app, n00b_string_t * +)
{
    return xdg_join_under(n00b_xdg_config_home(), app, vargs);
}

n00b_string_t *
n00b_xdg_data_path(n00b_string_t *app, n00b_string_t * +)
{
    return xdg_join_under(n00b_xdg_data_home(), app, vargs);
}

n00b_string_t *
n00b_xdg_cache_path(n00b_string_t *app, n00b_string_t * +)
{
    return xdg_join_under(n00b_xdg_cache_home(), app, vargs);
}

n00b_string_t *
n00b_xdg_state_path(n00b_string_t *app, n00b_string_t * +)
{
    return xdg_join_under(n00b_xdg_state_home(), app, vargs);
}

n00b_string_t *
n00b_xdg_runtime_path(n00b_string_t *app, n00b_string_t * +)
{
    return xdg_join_under(n00b_xdg_runtime_dir(), app, vargs);
}

// ============================================================================
// n00b_path_canonical — combined env-var + tilde + absolute + realpath
// ============================================================================
//
// Composes the four canonicalization steps in order:
//   1. $VAR / ${VAR} env-var expansion (when expand_env_vars).
//   2. Leading ~ / ~user tilde expansion (when expand_tilde).
//   3. Absolute-rooting via cwd (when make_absolute).
//   4. realpath() symlink resolution (when resolve_symlinks).
//
// Env-var expansion is the only genuinely new piece; it walks the
// input scanning for `$NAME` or `${NAME}` markers, resolves each
// via getenv (matching the module's existing pattern), and emits
// the empty string for unresolved names.

static bool
is_env_var_char(char c, bool first)
{
    if (c == '_') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (!first && c >= '0' && c <= '9') return true;
    return false;
}

static n00b_string_t *
expand_env_vars_impl(n00b_string_t *in)
{
    if (in == nullptr || in->u8_bytes == 0) {
        return in;
    }

    // Scratch buffer: worst-case the result is bounded by
    // (input bytes) + (sum of env-var values). We don't know the
    // upper bound a priori; build with a power-of-two grow.
    size_t cap = (size_t)in->u8_bytes * 2 + 16;
    char  *buf = n00b_alloc_array(char, cap);
    size_t off = 0;

    for (size_t i = 0; i < (size_t)in->u8_bytes; ) {
        char c = in->data[i];

        if (c != '$') {
            if (off + 1 >= cap) {
                cap *= 2;
                char *nb = n00b_alloc_array(char, cap);
                memcpy(nb, buf, off);
                buf = nb;
            }
            buf[off++] = c;
            i++;
            continue;
        }

        // `$` — try to parse a name.
        size_t name_start;
        size_t name_end;
        size_t consumed;
        bool   braced = false;

        if (i + 1 < (size_t)in->u8_bytes && in->data[i + 1] == '{') {
            // ${NAME}
            braced     = true;
            name_start = i + 2;
            name_end   = name_start;
            while (name_end < (size_t)in->u8_bytes
                   && in->data[name_end] != '}') {
                name_end++;
            }
            if (name_end >= (size_t)in->u8_bytes) {
                // No closing brace; emit `$` literally and continue.
                if (off + 1 >= cap) {
                    cap *= 2;
                    char *nb = n00b_alloc_array(char, cap);
                    memcpy(nb, buf, off);
                    buf = nb;
                }
                buf[off++] = '$';
                i++;
                continue;
            }
            consumed = (name_end - i) + 1; // include closing `}`
        }
        else {
            // $NAME — accept [A-Za-z_][A-Za-z0-9_]*.
            name_start = i + 1;
            if (name_start >= (size_t)in->u8_bytes
                || !is_env_var_char(in->data[name_start], true)) {
                // Lone `$` — emit literally.
                if (off + 1 >= cap) {
                    cap *= 2;
                    char *nb = n00b_alloc_array(char, cap);
                    memcpy(nb, buf, off);
                    buf = nb;
                }
                buf[off++] = '$';
                i++;
                continue;
            }
            name_end = name_start + 1;
            while (name_end < (size_t)in->u8_bytes
                   && is_env_var_char(in->data[name_end], false)) {
                name_end++;
            }
            consumed = name_end - i;
        }

        // Look up the env var and emit its value.
        size_t name_len = name_end - name_start;
        char   name_buf[256];
        if (name_len < sizeof(name_buf)) {
            memcpy(name_buf, in->data + name_start, name_len);
            name_buf[name_len] = '\0';
            const char *val = getenv(name_buf);
            if (val != nullptr) {
                size_t val_len = strlen(val);
                while (off + val_len + 1 >= cap) {
                    cap *= 2;
                    char *nb = n00b_alloc_array(char, cap);
                    memcpy(nb, buf, off);
                    buf = nb;
                }
                memcpy(buf + off, val, val_len);
                off += val_len;
            }
            // Unset / unknown → emit nothing (POSIX-shell convention).
        }
        // name_len >= sizeof(name_buf): pathological; emit nothing.

        i += consumed;
        (void)braced;
    }

    buf[off] = '\0';
    return n00b_string_from_raw(buf, (int64_t)off);
}

n00b_string_t *
_n00b_path_canonical(n00b_string_t *p) _kargs
{
    bool expand_env_vars  = true;
    bool expand_tilde     = true;
    bool make_absolute    = true;
    bool resolve_symlinks = false;
}
{
    if (p == nullptr) {
        return nullptr;
    }

    n00b_string_t *cur = p;

    if (expand_env_vars) {
        cur = expand_env_vars_impl(cur);
    }

    if (expand_tilde && cur != nullptr && cur->u8_bytes > 0
        && cur->data[0] == '~') {
        cur = n00b_path_tilde_expand(cur);
    }

    if (make_absolute && cur != nullptr && cur->u8_bytes > 0
        && cur->data[0] != '/') {
        cur = n00b_path_simple_join(n00b_get_current_directory(), cur);
    }

    if (resolve_symlinks && cur != nullptr) {
        char  buf[PATH_MAX + 1];
        char *r = realpath(cur->data, buf);
        if (r != nullptr) {
            cur = n00b_string_from_cstr(r);
        }
        // realpath failure (e.g., path doesn't exist): preserve cur.
    }

    return cur;
}

n00b_list_t(n00b_string_t *) *
_n00b_list_directory(n00b_string_t *dir) _kargs
{
    n00b_string_t *extension   = nullptr;
    bool           files       = true;
    bool           directories = true;
    bool           links       = true;
    bool           specials    = true;
    bool           full_path   = false;
    bool           dot_files   = true;
}
{
    dir         = n00b_resolve_path(dir);
    DIR *dirent = opendir(dir->data);

    // Canonical idiom for by-pointer return: populate a fully
    // scan-info-threaded lvalue first, then struct-copy into the
    // heap-allocated return shell at the end.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);

    if (dirent) {
        if (extension && extension->codepoints && extension->data[0] != '.') {
            extension = n00b_cformat(".«#»", extension);
        }

        while (true) {
            struct dirent *entry = readdir(dirent);

            if (!entry) {
                closedir(dirent);
                break;
            }

            if (!strcmp(entry->d_name, "..") || !strcmp(entry->d_name, "."))
                continue;

            if (!dot_files && *entry->d_name == '.')
                continue;

            n00b_string_t *fname = n00b_string_from_cstr(entry->d_name);
            n00b_string_t *full  = n00b_path_simple_join(dir, fname);
            struct stat    file_info;
            bool           add = false;

            if (lstat(full->data, &file_info) != 0) continue;

            switch (file_info.st_mode & S_IFMT) {
            case S_IFREG: add = files;       break;
            case S_IFDIR: add = directories;  break;
            case S_IFLNK: add = links;       break;
            default:      add = specials;     break;
            }

            if (!add) continue;

            if (extension && !n00b_unicode_str_ends_with(fname, extension))
                continue;

            n00b_list_push(lst, full_path ? full : fname);
        }
    }

    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *result = lst;
    return result;
}

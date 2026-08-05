#ifndef N00B_TEST_PORTABILITY_H
#define N00B_TEST_PORTABILITY_H

#if defined(_WIN32)

#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <process.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#ifndef N00B_SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#define N00B_SSIZE_T_DEFINED 1
#endif

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

static int
n00b_test_asprintf(char **out, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list copy;
    va_copy(copy, ap);

    int needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);

    if (needed < 0) {
        va_end(ap);
        *out = NULL;
        return -1;
    }

    char *buf = malloc((size_t)needed + 1);

    if (!buf) {
        va_end(ap);
        *out = NULL;
        return -1;
    }

    int written = vsnprintf(buf, (size_t)needed + 1, fmt, ap);
    va_end(ap);

    if (written < 0) {
        free(buf);
        *out = NULL;
        return -1;
    }

    *out = buf;
    return written;
}

#define asprintf n00b_test_asprintf

static int
n00b_test_setenv(const char *name, const char *value, int overwrite)
{
    if (!overwrite) {
        char  *existing     = NULL;
        size_t existing_len = 0;

        if (_dupenv_s(&existing, &existing_len, name) == 0) {
            if (existing != NULL) {
                free(existing);
                return 0;
            }
        }
        free(existing);
    }

    return _putenv_s(name, value ? value : "");
}

static int
n00b_test_unsetenv(const char *name)
{
    return _putenv_s(name, "");
}

static int
n00b_test_mkdir(const char *path, int mode)
{
    (void)mode;
    return _mkdir(path);
}

static int
n00b_test_windows_errno_from_last_error(DWORD err)
{
    switch (err) {
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        return EEXIST;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return ENOENT;
    case ERROR_ACCESS_DENIED:
        return EACCES;
    case ERROR_PRIVILEGE_NOT_HELD:
        return EPERM;
    case ERROR_NOT_SUPPORTED:
    case ERROR_INVALID_FUNCTION:
        return ENOSYS;
    default:
        return EINVAL;
    }
}

static int
n00b_test_symlink(const char *target, const char *linkpath)
{
    DWORD target_attrs = GetFileAttributesA(target);
    DWORD flags        = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;

    if (target_attrs != INVALID_FILE_ATTRIBUTES
        && (target_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    }

    if (CreateSymbolicLinkA(linkpath, target, flags) != 0) {
        return 0;
    }

    DWORD err = GetLastError();
    if ((flags & SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0
        && err == ERROR_INVALID_PARAMETER) {
        flags &= ~SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        if (CreateSymbolicLinkA(linkpath, target, flags) != 0) {
            return 0;
        }
        err = GetLastError();
    }

    errno = n00b_test_windows_errno_from_last_error(err);
    return -1;
}

#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef F_SETFL
#define F_SETFL 4
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x4000
#endif

#define N00B_TEST_FD_TABLE_SIZE 64
static int n00b_test_fd_flags[N00B_TEST_FD_TABLE_SIZE];
static int n00b_test_fd_seen[N00B_TEST_FD_TABLE_SIZE];

static int
n00b_test_fcntl(int fd, int cmd, ...)
{
    if (fd < 0 || fd >= N00B_TEST_FD_TABLE_SIZE) {
        errno = EINVAL;
        return -1;
    }

    if (cmd == F_GETFL) {
        return n00b_test_fd_seen[fd] ? n00b_test_fd_flags[fd] : 0;
    }

    if (cmd == F_SETFL) {
        va_list ap;
        va_start(ap, cmd);
        int flags = va_arg(ap, int);
        va_end(ap);
        n00b_test_fd_flags[fd] = flags;
        n00b_test_fd_seen[fd]  = 1;
        return 0;
    }

    errno = EINVAL;
    return -1;
}

static ssize_t
n00b_test_read(int fd, void *buf, size_t len)
{
    if (fd >= 0 && fd < N00B_TEST_FD_TABLE_SIZE
        && n00b_test_fd_seen[fd]
        && (n00b_test_fd_flags[fd] & O_NONBLOCK) != 0) {
        intptr_t raw = _get_osfhandle(fd);
        if (raw != -1) {
            DWORD avail = 0;
            if (PeekNamedPipe((HANDLE)raw, NULL, 0, NULL, &avail, NULL)) {
                if (avail == 0) {
                    errno = EAGAIN;
                    return -1;
                }
                if (len > (size_t)avail) {
                    len = (size_t)avail;
                }
            }
        }
    }

    unsigned int chunk = len > (size_t)UINT_MAX ? UINT_MAX : (unsigned int)len;
    return (ssize_t)_read(fd, buf, chunk);
}

static void *
n00b_test_memmem(const void *haystack,
                 size_t      haystack_len,
                 const void *needle,
                 size_t      needle_len)
{
    if (needle_len == 0) {
        return (void *)haystack;
    }
    if (haystack_len < needle_len) {
        return NULL;
    }

    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    size_t              limit = haystack_len - needle_len;

    for (size_t i = 0; i <= limit; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needle_len) == 0) {
            return (void *)(h + i);
        }
    }

    return NULL;
}

static char
n00b_test_mkdtemp_digit(unsigned value)
{
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    return digits[value % 36u];
}

static char *
n00b_test_mkdtemp(char *tmpl)
{
    if (!tmpl) {
        errno = EINVAL;
        return NULL;
    }

    size_t len = strlen(tmpl);
    if (len < 6u) {
        errno = EINVAL;
        return NULL;
    }

    char *x = tmpl + len - 6u;
    for (size_t i = 0; i < 6u; i++) {
        if (x[i] != 'X') {
            errno = EINVAL;
            return NULL;
        }
    }

    unsigned seed = (unsigned)_getpid() ^ (unsigned)(uintptr_t)tmpl;
    for (unsigned attempt = 0; attempt < 1000000u; attempt++) {
        unsigned value = seed + attempt;
        for (size_t i = 0; i < 6u; i++) {
            x[i] = n00b_test_mkdtemp_digit(value);
            value /= 36u;
        }

        if (_mkdir(tmpl) == 0) {
            return tmpl;
        }
        if (errno != EEXIST) {
            return NULL;
        }
    }

    errno = EEXIST;
    return NULL;
}

#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif

#define chdir _chdir
#define fcntl n00b_test_fcntl
#define getcwd _getcwd
#define memmem n00b_test_memmem
#define mkdir(path, mode) n00b_test_mkdir((path), (mode))
#define mkdtemp n00b_test_mkdtemp
#define pclose _pclose
#define pipe(fds) _pipe((fds), 65536, _O_BINARY)
#define popen _popen
#define read n00b_test_read
#define rmdir _rmdir
#define symlink n00b_test_symlink
#ifndef setenv
#define setenv n00b_test_setenv
#endif
#ifndef unsetenv
#define unsetenv n00b_test_unsetenv
#endif

#else

#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#endif

static int
n00b_test_run_bash_script(const char *script)
{
#if defined(_WIN32)
    return _spawnlp(_P_WAIT, "bash", "bash", script, NULL);
#else
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execlp("bash", "bash", script, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    if (!WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
#endif
}

#endif

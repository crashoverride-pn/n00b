#pragma once

#ifdef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>

#include "internal/win32_sockets.h"

#ifndef _WINDOWS
void __attribute__((__stdcall__)) Sleep(unsigned long milliseconds);
#endif

#ifndef N00B_SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#define N00B_SSIZE_T_DEFINED 1
#endif

typedef unsigned int useconds_t;

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef F_OK
#define F_OK 0
#endif
#ifndef X_OK
#define X_OK 0
#endif
#ifndef W_OK
#define W_OK 2
#endif
#ifndef R_OK
#define R_OK 4
#endif

static inline char
n00b_win_mkstemp_digit(unsigned value)
{
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    return digits[value % 36u];
}

static inline int
n00b_win_mkstemps(char *tmpl, int suffix_len)
{
    if (!tmpl || suffix_len < 0) {
        errno = EINVAL;
        return -1;
    }

    size_t len = strlen(tmpl);
    if ((size_t)suffix_len > len || len < (size_t)suffix_len + 6u) {
        errno = EINVAL;
        return -1;
    }

    char *x = tmpl + len - (size_t)suffix_len - 6u;
    for (size_t i = 0; i < 6u; i++) {
        if (x[i] != 'X') {
            errno = EINVAL;
            return -1;
        }
    }

    unsigned seed = (unsigned)_getpid();
    for (unsigned attempt = 0; attempt < 1000000u; attempt++) {
        unsigned value = seed + attempt;
        for (size_t i = 0; i < 6u; i++) {
            x[i] = n00b_win_mkstemp_digit(value);
            value /= 36u;
        }

        int fd = _open(tmpl,
                       _O_RDWR | _O_CREAT | _O_EXCL | _O_BINARY,
                       _S_IREAD | _S_IWRITE);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }

    errno = EEXIST;
    return -1;
}

static inline int
n00b_win_mkstemp(char *tmpl)
{
    return n00b_win_mkstemps(tmpl, 0);
}

static inline int
usleep(useconds_t usec)
{
    Sleep((unsigned long)((usec + 999u) / 1000u));
    return 0;
}

static inline int
n00b_win_fchmod(int fd, int mode)
{
    (void)fd;
    (void)mode;
    errno = ENOSYS;
    return -1;
}

static inline int
n00b_win_close(int fd)
{
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

    int socket_type = 0;
    int socket_type_len = (int)sizeof(socket_type);
    if (getsockopt((SOCKET)fd,
                   SOL_SOCKET,
                   SO_TYPE,
                   (char *)&socket_type,
                   &socket_type_len)
        == 0) {
        if (closesocket((SOCKET)fd) == 0) {
            return 0;
        }
        errno = WSAGetLastError();
        return -1;
    }

    return _close(fd);
}

#define access _access
#define close n00b_win_close
#define dup _dup
#define dup2 _dup2
#define fchmod n00b_win_fchmod
#define getpid _getpid
#define isatty _isatty
#define lseek _lseeki64
#define mkstemp n00b_win_mkstemp
#define mkstemps n00b_win_mkstemps
#define read _read
#define unlink _unlink
#define write _write

#else
#include_next <unistd.h>
#endif

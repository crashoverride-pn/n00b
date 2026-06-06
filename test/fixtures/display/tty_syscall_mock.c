#include "tty_syscall_mock.h"

#ifndef _WIN32
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/ioctl.h>
#endif

static n00b_test_tty_faults_t g_tty_faults;

void
n00b_test_tty_faults_reset(void)
{
    g_tty_faults = (n00b_test_tty_faults_t){
        .stdin_isatty    = true,
        .stdout_isatty   = true,
        .tcgetattr_ok    = true,
        .tcsetattr_errno = EIO,
    };
}

n00b_test_tty_faults_t
n00b_test_tty_faults_get(void)
{
    return g_tty_faults;
}

void
n00b_test_tty_faults_set(n00b_test_tty_faults_t faults)
{
    g_tty_faults = faults;
}

static bool
bytes_eq(const void *buf, size_t count, const char *expected)
{
    size_t len = strlen(expected);
    return count == len && memcmp(buf, expected, len) == 0;
}

static bool
is_mouse_enable_write(const void *buf, size_t count)
{
    return bytes_eq(buf, count, "\033[?1000h")
        || bytes_eq(buf, count, "\033[?1002h")
        || bytes_eq(buf, count, "\033[?1006h");
}

static int
mock_isatty(int fd, int (*real_fn)(int))
{
    if (g_tty_faults.enabled) {
        if (fd == STDIN_FILENO) {
            return g_tty_faults.stdin_isatty ? 1 : 0;
        }
        if (fd == STDOUT_FILENO) {
            return g_tty_faults.stdout_isatty ? 1 : 0;
        }
    }

    return real_fn(fd);
}

static int
mock_tcgetattr(int fd,
               struct termios *termios_p,
               int (*real_fn)(int, struct termios *))
{
    if (g_tty_faults.enabled && fd == STDIN_FILENO) {
        g_tty_faults.tcgetattr_calls++;
        if (!g_tty_faults.tcgetattr_ok) {
            errno = ENOTTY;
            return -1;
        }
        memset(termios_p, 0, sizeof(*termios_p));
        return 0;
    }

    return real_fn(fd, termios_p);
}

static int
mock_tcsetattr(int fd,
               int optional_actions,
               const struct termios *termios_p,
               int (*real_fn)(int, int, const struct termios *))
{
    if (g_tty_faults.enabled && fd == STDIN_FILENO) {
        (void)optional_actions;
        (void)termios_p;
        g_tty_faults.tcsetattr_calls++;
        if (g_tty_faults.tcsetattr_fails) {
            errno = g_tty_faults.tcsetattr_errno;
            return -1;
        }
        return 0;
    }

    return real_fn(fd, optional_actions, termios_p);
}

static ssize_t
mock_write(int fd,
           const void *buf,
           size_t count,
           ssize_t (*real_fn)(int, const void *, size_t))
{
    if (g_tty_faults.enabled && fd == STDOUT_FILENO) {
        g_tty_faults.stdout_write_calls++;
        if (is_mouse_enable_write(buf, count)) {
            g_tty_faults.mouse_enable_writes++;
        }
        return (ssize_t)count;
    }

    return real_fn(fd, buf, count);
}

#if defined(__APPLE__)
static int
real_isatty(int fd)
{
    struct termios termios_p;
    return ioctl(fd, TIOCGETA, &termios_p) == 0 ? 1 : 0;
}

static int
real_tcgetattr(int fd, struct termios *termios_p)
{
    return ioctl(fd, TIOCGETA, termios_p);
}

static int
real_tcsetattr(int fd, int optional_actions, const struct termios *termios_p)
{
    unsigned long request;

    switch (optional_actions) {
    case TCSANOW:
        request = TIOCSETA;
        break;
    case TCSADRAIN:
        request = TIOCSETAW;
        break;
    case TCSAFLUSH:
        request = TIOCSETAF;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    return ioctl(fd, request, termios_p);
}

int
n00b_test_tty_isatty(int fd)
{
    return mock_isatty(fd, real_isatty);
}

int
n00b_test_tty_tcgetattr(int fd, struct termios *termios_p)
{
    return mock_tcgetattr(fd, termios_p, real_tcgetattr);
}

int
n00b_test_tty_tcsetattr(int fd,
                        int optional_actions,
                        const struct termios *termios_p)
{
    return mock_tcsetattr(fd, optional_actions, termios_p, real_tcsetattr);
}

typedef struct {
    const void *replacement;
    const void *replacee;
} interpose_entry_t;

__attribute__((used, section("__DATA,__interpose")))
static const interpose_entry_t tty_interpose[] = {
    {(const void *)n00b_test_tty_isatty, (const void *)isatty},
    {(const void *)n00b_test_tty_tcgetattr, (const void *)tcgetattr},
    {(const void *)n00b_test_tty_tcsetattr, (const void *)tcsetattr},
};
#else
extern int     __real_isatty(int fd);
extern int     __real_tcgetattr(int fd, struct termios *termios_p);
extern int     __real_tcsetattr(int fd,
                                int optional_actions,
                                const struct termios *termios_p);
extern ssize_t __real_write(int fd, const void *buf, size_t count);

int
__wrap_isatty(int fd)
{
    return mock_isatty(fd, __real_isatty);
}

int
__wrap_tcgetattr(int fd, struct termios *termios_p)
{
    return mock_tcgetattr(fd, termios_p, __real_tcgetattr);
}

int
__wrap_tcsetattr(int fd,
                 int optional_actions,
                 const struct termios *termios_p)
{
    return mock_tcsetattr(fd, optional_actions, termios_p, __real_tcsetattr);
}

ssize_t
__wrap_write(int fd, const void *buf, size_t count)
{
    return mock_write(fd, buf, count, __real_write);
}
#endif
#endif

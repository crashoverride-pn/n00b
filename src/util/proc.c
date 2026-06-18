/*
 * libn00b ↔ POSIX boundary (n00b-api-guidelines §11): this file is the
 * designated platform shim for arbitrary-PID process introspection. The raw
 * process syscall (`kill(pid, 0)`) is intentional and confined here so that
 * consumers call the n00b primitive (`n00b_proc_is_alive`) instead of libc.
 */

#include "n00b.h"
#include "util/proc.h"

#include <errno.h>
#if !defined(_WIN32)
#include <signal.h>
#endif

bool
n00b_proc_is_alive(int64_t pid)
{
    if (pid <= 0) {
        return false;
    }

#if defined(_WIN32)
    /* Windows process liveness (OpenProcess + GetExitCodeProcess) is
     * anticipated but not built this round (POSIX is the tested target). */
    return false;
#else
    if (kill((pid_t)pid, 0) == 0) {
        return true;
    }
    /* EPERM => the process exists but is owned by another user. */
    return errno == EPERM;
#endif
}

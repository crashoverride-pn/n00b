/**
 * @file syscall.h
 * @brief Libc-free raw syscalls for async-signal-safe / TSD-independent code.
 *
 * Why this exists: a bare syscall instruction takes no lock and touches no
 * errno-TLS, so it is async-signal-safe AND safe on a thread whose TSD is torn
 * down or wrecked.  Neither is true of libc's `write()` / `_exit()` wrappers —
 * which are also exactly the libc symbols the no-libc effort removes (NCC.md
 * "NO LIBC ALLOWED").  Use these in the crash handler and any other fault- or
 * teardown-context output / process-exit path.
 *
 * Platform status: macOS/arm64 is fully raw (`svc #0x80`, x16 = BSD syscall
 * number — the same sequence `_n00b_darwin_syscall` (thread.c) and
 * `core/futex.h` already use).  Other POSIX (Linux, x86-64 macOS) currently
 * routes through libc's thin `syscall()` trampoline with `SYS_*` numbers,
 * matching `core/futex.h`; converting those to raw `svc #0` / `syscall` asm is
 * part of the same broader no-libc syscall pass and is tracked separately.
 * No-op-free on Windows: not provided (no POSIX fault-handler path).
 */
#pragma once

#if !defined(_WIN32)

#include <stdint.h>      // uintptr_t
#include <sys/syscall.h> // SYS_write / SYS_exit / SYS_exit_group

#if defined(__APPLE__) && defined(__aarch64__)

// Raw BSD syscall via the arm64 unix trap (x16 = number, svc #0x80), returning
// x0.  Mirrors _n00b_darwin_syscall (thread.c); duplicated here so the crash
// handler does not depend on a static-inline buried in thread.c.
static inline long
_n00b_raw_bsd_syscall3(long n, long a0, long a1, long a2)
{
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0")   = a0;
    register long x1 __asm__("x1")   = a1;
    register long x2 __asm__("x2")   = a2;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2)
                     : "cc", "memory");
    return x0;
}

/// Async-signal-safe, libc-free write to @p fd.  Best-effort (return ignored).
static inline void
n00b_raw_write(int fd, const void *buf, unsigned long len)
{
    (void)_n00b_raw_bsd_syscall3(SYS_write,
                                 (long)fd,
                                 (long)(uintptr_t)buf,
                                 (long)len);
}

/// Libc-free immediate whole-process exit (kernel `exit`, no atexit handlers).
[[noreturn]] static inline void
n00b_raw_exit(int code)
{
    (void)_n00b_raw_bsd_syscall3(SYS_exit, (long)code, 0, 0);
    __builtin_unreachable();
}

#else // other POSIX: thin syscall() trampoline (matches core/futex.h's Linux path)

#include <unistd.h> // syscall

static inline void
n00b_raw_write(int fd, const void *buf, unsigned long len)
{
    (void)syscall(SYS_write, fd, buf, len);
}

[[noreturn]] static inline void
n00b_raw_exit(int code)
{
#if defined(SYS_exit_group)
    (void)syscall(SYS_exit_group, code); // terminate the whole process
#else
    (void)syscall(SYS_exit, code);
#endif
    __builtin_unreachable();
}

#endif // __APPLE__ && __aarch64__

#endif // !_WIN32

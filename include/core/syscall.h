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
 * `core/futex.h` already use).  Linux arm64/x86-64 are also raw for the small
 * syscall arities needed by crash/worker-thread code; raw-clone workers do not
 * have a full pthread TCB, so libc's cancellation/errno wrappers are unsafe
 * there. Other POSIX still routes through libc's thin `syscall()` trampoline.
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

static inline long
_n00b_raw_bsd_syscall5(long n, long a0, long a1, long a2, long a3, long a4)
{
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0")   = a0;
    register long x1 __asm__("x1")   = a1;
    register long x2 __asm__("x2")   = a2;
    register long x3 __asm__("x3")   = a3;
    register long x4 __asm__("x4")   = a4;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "cc", "memory");
    return x0;
}

#if !defined(SYS_getentropy)
#error "macOS arm64 requires SYS_getentropy."
#endif

/// Libc-free getentropy(2); macOS limits each request to 256 bytes.
static inline long
n00b_raw_getentropy(void *buf, unsigned long len)
{
    return _n00b_raw_bsd_syscall3(SYS_getentropy,
                                  (long)(uintptr_t)buf,
                                  (long)len,
                                  0);
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

#elif defined(__linux__)

static inline long
_n00b_raw_linux_syscall1(long n, long a0)
{
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8)
                     : "cc", "memory");
    return x0;
#elif defined(__x86_64__)
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a0;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi)
                     : "rcx", "r11", "cc", "memory");
    return rax;
#else
    return syscall(n, a0);
#endif
}

static inline long
_n00b_raw_linux_syscall3(long n, long a0, long a1, long a2)
{
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8)
                     : "cc", "memory");
    return x0;
#elif defined(__x86_64__)
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a0;
    register long rsi __asm__("rsi") = a1;
    register long rdx __asm__("rdx") = a2;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx)
                     : "rcx", "r11", "cc", "memory");
    return rax;
#else
    return syscall(n, a0, a1, a2);
#endif
}

static inline long
_n00b_raw_linux_syscall4(long n, long a0, long a1, long a2, long a3)
{
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "cc", "memory");
    return x0;
#elif defined(__x86_64__)
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a0;
    register long rsi __asm__("rsi") = a1;
    register long rdx __asm__("rdx") = a2;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10)
                     : "rcx", "r11", "cc", "memory");
    return rax;
#else
    return syscall(n, a0, a1, a2, a3);
#endif
}

static inline long
_n00b_raw_linux_syscall5(long n, long a0, long a1, long a2, long a3, long a4)
{
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
                     : "cc", "memory");
    return x0;
#elif defined(__x86_64__)
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a0;
    register long rsi __asm__("rsi") = a1;
    register long rdx __asm__("rdx") = a2;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8")   = a4;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
                     : "rcx", "r11", "cc", "memory");
    return rax;
#else
    return syscall(n, a0, a1, a2, a3, a4);
#endif
}

static inline long
_n00b_raw_linux_syscall6(long n,
                         long a0,
                         long a1,
                         long a2,
                         long a3,
                         long a4,
                         long a5)
{
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "cc", "memory");
    return x0;
#elif defined(__x86_64__)
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a0;
    register long rsi __asm__("rsi") = a1;
    register long rdx __asm__("rdx") = a2;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8")   = a4;
    register long r9 __asm__("r9")   = a5;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "cc", "memory");
    return rax;
#else
    return syscall(n, a0, a1, a2, a3, a4, a5);
#endif
}

static inline void
n00b_raw_write(int fd, const void *buf, unsigned long len)
{
    (void)_n00b_raw_linux_syscall3(SYS_write,
                                   (long)fd,
                                   (long)(uintptr_t)buf,
                                   (long)len);
}

[[noreturn]] static inline void
n00b_raw_exit(int code)
{
#if defined(SYS_exit_group)
    (void)_n00b_raw_linux_syscall1(SYS_exit_group, (long)code);
#else
    (void)_n00b_raw_linux_syscall1(SYS_exit, (long)code);
#endif
    __builtin_unreachable();
}

#else // other POSIX: thin syscall() trampoline

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

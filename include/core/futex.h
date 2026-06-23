/**
 * @file futex.h
 * @brief Futex (fast userspace mutex) abstraction.
 *
 * Provides a cross-platform futex API using Linux futex(2) or macOS
 * __ulock_wait2/__ulock_wake, with spin-wait, timed-wait, and
 * mask-based wait helpers.
 */
#pragma once

// IWYU pragma: no_include <sys/errno.h>

#include <errno.h> // IWYU pragma: keep
#include <limits.h>
#include <time.h>
#include "n00b.h"
#include "core/atomic.h"
#include "core/time.h"
#include "core/stw.h"

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

#define n00b_mac_barrier()

/** @brief Exit the current thread with a status code (Linux). */
extern void n00b_thread_exit(uint64_t code);

static inline bool
_n00b_linux_syscall_is_errno(long r)
{
    return r < 0 && r >= -4095;
}

static inline long
_n00b_linux_syscall6(long nr, long a0, long a1, long a2,
                     long a3, long a4, long a5)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "cc", "memory");
    return x0;
#elif defined(__x86_64__)
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a0;
    register long rsi __asm__("rsi") = a1;
    register long rdx __asm__("rdx") = a2;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return rax;
#else
    long r = syscall(nr, a0, a1, a2, a3, a4, a5);
    if (r == -1) {
        return -errno;
    }
    return r;
#endif
}

/**
 * @brief Wait on a futex word (Linux implementation).
 * @param futex Futex address.
 * @param v32   Expected value.
 * @param tptr  Timeout (may be nullptr for indefinite).
 * @return      0 on success, errno on error.
 */
static inline int
n00b_futex_wait_timespec(n00b_futex_t *futex, uint32_t v32, struct timespec *tptr)
{
    long r = _n00b_linux_syscall6(SYS_futex,
                                  (long)(uintptr_t)futex,
                                  FUTEX_WAIT_PRIVATE,
                                  (long)v32,
                                  (long)(uintptr_t)tptr,
                                  0,
                                  0);

    if (_n00b_linux_syscall_is_errno(r)) {
        return (int)-r;
    }

    return 0;
}

/**
 * @brief Wake one or all waiters on a futex (Linux implementation).
 * @param futex Futex address.
 * @param all   If true, wake all waiters; otherwise wake one.
 * @return      Number of threads woken.
 */
static inline int
n00b_futex_wake(n00b_futex_t *futex, bool all)
{
    uint32_t n = all ? INT_MAX : 1;
    long r = _n00b_linux_syscall6(SYS_futex,
                                  (long)(uintptr_t)futex,
                                  FUTEX_WAKE_PRIVATE,
                                  (long)n,
                                  0,
                                  0,
                                  0);

    return (int)r;
}

/**
 * @brief Check whether a futex wait should retry (Linux).
 * @param err Error code from futex_wait_timespec.
 * @return    true if the wait should continue.
 */
static inline bool
n00b_futex_should_continue(int err)
{
    return !err || err == EAGAIN;
}

#elifdef __APPLE__
#include <sys/syscall.h>

extern int __ulock_wait2(uint32_t, void *, uint64_t, uint64_t, uint64_t);

// WAKE is issued as a direct svc syscall rather than via libsyscall's
// __ulock_wake wrapper.  On a raw Mach thread (n00b_thread_spawn's worker,
// WP-001 Phase 3) TPIDRRO_EL0 is zero — there is no thread-local storage —
// so the wrapper's error path (cerror_nocancel) faults when it stores
// errno through the null TSD base, and a wake with no waiter returns
// -ENOENT (an "error").  The direct syscall returns the raw -errno without
// touching errno/TSD, so the SAME wake is safe from a fully
// pthread-registered thread AND a TLS-free worker (D-012); callers already
// treat the result as a negative errno.
//
// WAIT is issued the same way, for the same reason: worker-safe sleeps
// (base_nanosleep_ns) now wait on TSD-less workers, so the libsyscall
// __ulock_wait2 wrapper's cerror_nocancel errno store would fault on them on
// any error return (EINTR/EFAULT/ETIMEDOUT).  The direct svc returns the raw
// -errno without touching errno/TSD; the macOS n00b_futex_should_continue
// already expects a negative errno, and timeouts are caught by the deadline
// loop in n00b_futex_timed_wait_for_value regardless of the return value.
static inline long
_n00b_darwin_ulock_wake_syscall(long op, long addr)
{
    register long x16 __asm__("x16") = SYS_ulock_wake;
    register long x0 __asm__("x0")   = op;
    register long x1 __asm__("x1")   = addr;
    register long x2 __asm__("x2")   = 0;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2)
                     : "cc", "memory");
    return x0;
}

// Direct svc for __ulock_wait2(op, addr, value, timeout_ns, value2) — see the
// WAIT note above.  SYS_ulock_wait2 == 544 (sys/syscall.h).
static inline long
_n00b_darwin_ulock_wait2_syscall(long op, long addr, long value, long tout_ns, long value2)
{
    register long x16 __asm__("x16") = SYS_ulock_wait2;
    register long x0 __asm__("x0")   = op;
    register long x1 __asm__("x1")   = addr;
    register long x2 __asm__("x2")   = value;
    register long x3 __asm__("x3")   = tout_ns;
    register long x4 __asm__("x4")   = value2;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "cc", "memory");
    return x0;
}

#define N00B_LOCK_COMPARE_AND_WAIT          1
#define N00B_LOCK_UNFAIR_LOCK               2
#define N00B_LOCK_COMPARE_AND_WAIT_SHARED   3
#define N00B_LOCK_UNFAIR_LOCK64_SHARED      4
#define N00B_LOCK_COMPARE_AND_WAIT64        5
#define N00B_LOCK_COMPARE_AND_WAIT64_SHARED 6
#define N00B_LOCK_WAKE_ALL                  0x00000100
#define N00B_LOCK_WAKE_THREAD               0x00000200
#define N00B_LOCK_WAKE_ALLOW_NON_OWNER      0x00000400

#define N00B_WAKE_ALL    (N00B_LOCK_COMPARE_AND_WAIT | N00B_LOCK_WAKE_ALL)
#define N00B_WAKE_THREAD (N00B_LOCK_COMPARE_AND_WAIT | N00B_LOCK_WAKE_THREAD)

#define n00b_mac_barrier() n00b_barrier()

/**
 * @brief Wait on a futex word (macOS implementation via __ulock_wait2).
 * @param futex Futex address.
 * @param v32   Expected value.
 * @param tout  Timeout (may be nullptr for indefinite).
 * @return      0 on success, negative errno on error.
 */
static inline int
n00b_futex_wait_timespec(n00b_futex_t *futex, uint32_t v32, struct timespec *tout)
{
    // Direct svc (not the libsyscall __ulock_wait2 wrapper) so the errno store
    // on an error return cannot fault on a TSD-less worker — see the WAIT note
    // by _n00b_darwin_ulock_wait2_syscall.  Returns -errno on error, >= 0 on
    // success/timeout.
    return (int)_n00b_darwin_ulock_wait2_syscall(N00B_LOCK_COMPARE_AND_WAIT,
                                                 (long)(uintptr_t)futex,
                                                 (long)v32,
                                                 (long)(tout ? tout->tv_nsec : 0),
                                                 0);
}

/**
 * @brief Wake one or all waiters on a futex (macOS implementation).
 * @param futex Futex address.
 * @param all   If true, wake all waiters; otherwise wake one.
 * @return      0 on success, negative errno on error.
 */
static inline int
n00b_futex_wake(n00b_futex_t *futex, bool all)
{
    uint32_t op = N00B_LOCK_COMPARE_AND_WAIT;
    if (all) {
        op |= N00B_LOCK_WAKE_ALL;
    }
    // Direct ulock_wake(op, addr, 0) — see the TSD note above.  A wake with
    // no waiter returns -ENOENT; issuing it directly means that error never
    // trips libsyscall's errno write (which would fault on a TSD-less worker
    // thread).
    return (int)_n00b_darwin_ulock_wake_syscall((long)op, (long)(uintptr_t)futex);
}

/**
 * @brief Check whether a futex wait should retry (macOS).
 * @param err Error code from futex_wait_timespec.
 * @return    true if the wait should continue.
 */
static inline bool
n00b_futex_should_continue(int err)
{
    return !err || err == -EINTR || err == -EFAULT;
}

#elifdef _WIN32
#include "core/platform.h"

#define n00b_mac_barrier()

extern void n00b_thread_exit(int);

static inline int
n00b_futex_wait_timespec(n00b_futex_t *futex, uint32_t v32, struct timespec *tptr)
{
    DWORD ms = INFINITE;
    if (tptr) {
        ms = (DWORD)(tptr->tv_sec * 1000 + tptr->tv_nsec / 1000000);
        if (ms == 0 && (tptr->tv_sec || tptr->tv_nsec)) {
            ms = 1;
        }
    }
    BOOL ok = WaitOnAddress(futex, &v32, sizeof(uint32_t), ms);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_TIMEOUT) {
            return ETIMEDOUT;
        }
        return EAGAIN;
    }
    return 0;
}

static inline int
n00b_futex_wake(n00b_futex_t *futex, bool all)
{
    if (all) {
        WakeByAddressAll(futex);
    }
    else {
        WakeByAddressSingle(futex);
    }
    return 0;
}

static inline bool
n00b_futex_should_continue(int err)
{
    return !err || err == EAGAIN;
}

#else
#error "Unsupported platform."
#endif

/** @brief Wake a single waiter on a futex. */
#define n00b_futex_wake_one(f) n00b_futex_wake((f), false)

/** @brief Wake all waiters on a futex. */
#define n00b_futex_wake_all(f) n00b_futex_wake((f), true)

/**
 * @brief Initialize a futex to 0.
 * @param futex Futex to initialize.
 */
static inline void
n00b_futex_init(n00b_futex_t *futex)
{
    n00b_atomic_store(futex, 0);
}

/**
 * @brief Wait on a futex with a nanosecond timeout.
 * @param futex Futex to wait on.
 * @param v32   Expected value (only blocks if futex == v32).
 * @param nsec  Timeout in nanoseconds.
 * @return      0 on wake, ETIMEDOUT on timeout.
 * @pre @p futex has been initialized via n00b_futex_init().
 */
static inline int
n00b_futex_wait(n00b_futex_t *futex, uint32_t v32, uint64_t nsec)
{
    struct timespec tout = {.tv_sec = 0, .tv_nsec = nsec};
    // No cooperative STW check-in after the wait (WP-001): a thread blocked in a
    // futex wait is preempted by the stop-the-world initiator, not self-parked,
    // so there is nothing to check in on.
    return n00b_futex_wait_timespec(futex, v32, &tout);
}

/**
 * @brief Wait until the futex equals @p v32, or @p timeout ns elapse.
 * @param futex   Futex to poll.
 * @param v32     Desired value.
 * @param timeout Maximum wait in nanoseconds.
 * @return        true if value reached, false on timeout.
 */
static inline bool
n00b_futex_timed_wait_for_value(volatile n00b_futex_t *futex, uint32_t v32, int64_t timeout)
{
    uint32_t cur       = n00b_atomic_load(futex);
    int64_t  start     = n00b_ns_timestamp();
    int64_t  remaining = timeout;
    int64_t  now;

    if (cur == v32) {
        return true;
    }
    while (true) {
        if (n00b_futex_wait((void *)futex, cur, remaining) == ETIMEDOUT) {
            return false; // Got timeout
        }
        cur = n00b_atomic_load(futex);
        // If some other thread is canceled, the check doesn't matter
        // anyway.
        if (cur == v32) {
            return true;
        }
        // Bail out if the program is exiting — the thread we're
        // waiting on may have already been reaped, and continuing
        // to wait would block shutdown.  Surfaces as a timeout to
        // the caller, which is the closest meaningful semantic.
        if (n00b_default_runtime_is_set()
            && n00b_atomic_load(
                &n00b_get_runtime()->shutdown_started)) {
            return false;
        }
        now = n00b_ns_timestamp();
        remaining -= (now - start); // Subtract time elapsed.

        if (remaining < 0) {
            return false;
        }
        start = now;
    }
}

/**
 * @brief Spin-wait until the futex equals @p v32 (no timeout).
 * @param futex Futex to poll.
 * @param v32   Desired value.
 */
static inline void
n00b_futex_wait_for_value(volatile n00b_futex_t *futex, uint32_t v32)
{
    // Always timeout and requeue so that, if the futex transparently
    // moves during GC we are waiting in the right place.
    while (!n00b_futex_timed_wait_for_value(futex, v32, 10000))
        // nada.
        ;
}

/**
 * @brief Wait until any bit in @p mask is set in the futex.
 * @param futex Futex to poll.
 * @param mask  Bitmask of bits to wait for.
 */
static inline void
n00b_futex_wait_on_mask(n00b_futex_t *futex, uint32_t mask)
{
    uint32_t cur = n00b_atomic_load(futex);
    while (!(cur & mask)) {
        n00b_futex_wait(futex, cur, 0);
        cur = n00b_atomic_load(futex);
        // Bail on shutdown so a teardown doesn't wedge waiting for
        // a wake that's never coming.  Same shape as the timed-wait
        // variant above.
        if (n00b_default_runtime_is_set()
            && n00b_atomic_load(
                &n00b_get_runtime()->shutdown_started)) {
            return;
        }
    }
}

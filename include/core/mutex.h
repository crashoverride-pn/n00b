/**
 * @file mutex.h
 * @brief Futex-based mutex with lock accounting.
 *
 * Provides a mutex that spins briefly before falling back to the OS,
 * supports recursive locking, and integrates with the per-thread lock
 * chain for crash debugging and thread-exit cleanup.
 */
#pragma once

#include <stdatomic.h> // IWYU pragma: keep
#include "n00b.h"
#include "core/lock_common.h"

// NOTE: `n00b_futex_t` is the typedef from n00b.h; this header deliberately
// does NOT include core/futex.h.  futex.h carries inline functions that
// dereference the runtime struct, and core/runtime.h embeds an n00b_mutex_t by
// value (the critical_execution gate) — pulling futex.h in here would parse
// those inlines before n00b_runtime_t is complete (an include cycle).  Code
// that calls the futex API includes core/futex.h directly.
struct n00b_mutex_t {
    N00B_COMMON_LOCK_BASE;
    n00b_futex_t     futex;
    _Atomic uint32_t should_wake;
};

/**
 * @brief Initialize a mutex (with lock accounting).
 * @param lock Mutex to initialize.
 * @param loc  Source location (auto-filled by macro).
 * @pre @p lock points to zeroed or uninitialized memory.
 * @post The mutex is ready for use.
 */
extern void _n00b_mutex_init(n00b_mutex_t *, char *);

/**
 * @brief Initialize a system mutex (no lock logging, minimal setup).
 * @param lock Mutex to initialize.
 * @param loc  Source location (auto-filled by macro).
 */
extern void n00b_sys_mutex_init(n00b_mutex_t *, char *);

/**
 * @brief Acquire the mutex, blocking if necessary.
 * @param lock Mutex to acquire.
 * @param loc  Source location (auto-filled by macro).
 * @return     0 on success.
 */
extern int  _n00b_mutex_lock(n00b_mutex_t *, char *);

/**
 * @brief Release the mutex.
 * @param lock Mutex to release.
 * @param loc  Source location (auto-filled by macro).
 * @return     true if fully unlocked, false if still nested.
 */
extern bool _n00b_mutex_unlock(n00b_mutex_t *, char *);

/**
 * @brief Try to acquire the mutex with a timeout.
 * @param lock Mutex to acquire.
 * @param usec Timeout in microseconds.
 * @param loc  Source location (auto-filled by macro).
 * @return     true if acquired, false on timeout.
 */
extern bool _n00b_mutex_try_lock(n00b_mutex_t *, int usec, char *);

#define n00b_mutex_init(x)   _n00b_mutex_init((x), N00B_LOC_STRING())
#define n00b_mutex_lock(x)   _n00b_mutex_lock((x), N00B_LOC_STRING())
#define n00b_mutex_unlock(x) _n00b_mutex_unlock((x), N00B_LOC_STRING())
// Try to acquire with a timeout in microseconds; returns true if acquired,
// false on timeout. Public wrapper so callers never reach around the
// underscore boundary to _n00b_mutex_try_lock directly.
#define n00b_mutex_try_lock(x, usec) \
    _n00b_mutex_try_lock((x), (usec), N00B_LOC_STRING())

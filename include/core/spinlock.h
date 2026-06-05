/**
 * @file spinlock.h
 * @brief Re-entrant, non-parking spinlock built on the common lock layer.
 *
 * Like @ref n00b_mutex_t, this lock tracks owner + nesting through the lock
 * accounting subsystem, so it is recursive (a thread that already holds it
 * just bumps the nesting count) and is force-released from the per-thread
 * lock chain when its owner exits.
 *
 * UNLIKE the mutex, it NEVER parks: a waiter busy-spins on the lock word
 * rather than falling back to a futex wait.  That is the whole point of the
 * class — it is the lock used inside the can't-STW barrier (the mmap interval
 * tree, see core/mmaps.c).  A thread that parked while holding a barrier slot
 * would stall the stop-the-world drain forever (the drain waits for every
 * barrier participant to leave before suspending anyone, and a parked thread
 * never leaves).  Because the barrier guarantees a holder is never suspended
 * mid-critical-section, the spin always makes progress and stays short.
 */
#pragma once

#include <stdatomic.h> // IWYU pragma: keep
#include "n00b.h"
#include "core/lock_common.h"

struct n00b_spin_lock_t {
    N00B_COMMON_LOCK_BASE;
    _Atomic uint32_t spin; // 0 = unlocked, 1 = held (mutual-exclusion word).
};

/**
 * @brief Initialize a spinlock (with lock accounting).
 * @param lock Spinlock to initialize.
 * @param loc  Source location (auto-filled by macro).
 * @pre @p lock points to zeroed or uninitialized memory.
 */
extern void _n00b_spinlock_init(n00b_spin_lock_t *, char *);

/**
 * @brief Acquire the spinlock, busy-waiting if necessary.  Recursive.
 * @param lock Spinlock to acquire.
 * @param loc  Source location (auto-filled by macro).
 * @return     0 on success.
 */
extern int _n00b_spinlock_lock(n00b_spin_lock_t *, char *);

/**
 * @brief Release one level of the spinlock.
 * @param lock Spinlock to release.
 * @param loc  Source location (auto-filled by macro).
 * @return     true if fully unlocked, false if still nested.
 */
extern bool _n00b_spinlock_unlock(n00b_spin_lock_t *, char *);

#define n00b_spinlock_init(x)   _n00b_spinlock_init((x), N00B_LOC_STRING())
#define n00b_spinlock_lock(x)   _n00b_spinlock_lock((x), N00B_LOC_STRING())
#define n00b_spinlock_unlock(x) _n00b_spinlock_unlock((x), N00B_LOC_STRING())

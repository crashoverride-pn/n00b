/*
 * Re-entrant, non-parking spinlock.
 *
 * Owner + nesting are tracked by the shared lock-accounting subsystem
 * (the same one mutexes and rwlocks use), so the lock is recursive and is
 * force-released from the per-thread exclusive-lock chain when its owner
 * exits (see n00b_release_locks_on_thread_exit).  Mutual exclusion between
 * different threads is a single lock word that a waiter busy-spins on; the
 * lock NEVER falls back to a futex wait.  See spinlock.h for why parking is
 * forbidden (the can't-STW barrier).
 */

#define N00B_USE_INTERNAL_API

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/spinlock.h"
#include "core/atomic.h"

void
_n00b_spinlock_init(n00b_spin_lock_t *lock, char *loc)
{
    /* Mirror n00b_lock_init_accounting's field setup, but skip its
     * n00b_find_alloc_info() probe: a spinlock is embedded in long-lived
     * runtime infrastructure (e.g. the mmap registry), not a GC allocation,
     * and the probe runs before the allocators it consults are up. */
    n00b_core_lock_info_t info = {
        .owner    = N00B_NO_OWNER,
        .type     = N00B_NLT_SPIN,
        .nesting  = 0,
        .reserved = 0,
    };

    atomic_store(&lock->data, info);
    atomic_store(&lock->next_thread_lock, nullptr);
    atomic_store(&lock->prev_thread_lock, nullptr);
    atomic_store(&lock->spin, 0);

    lock->creation_loc = loc;
    lock->inited       = true;
    lock->no_log       = true;
}

int
_n00b_spinlock_lock(n00b_spin_lock_t *lock, char *loc)
{
    // STW-active short-circuit (WP-001): no-op acquire while the world is
    // stopped (the collector is the sole runner).
    if (n00b_atomic_load(&n00b_get_runtime()->stw_active)) {
        return 0;
    }

    n00b_thread_t        *thread = n00b_thread_self();
    int64_t               tid    = n00b_os_thread_id();
    n00b_core_lock_info_t info   = n00b_atomic_load(&lock->data);

    // Recursive acquire: already the owner, just bump the nesting count.
    if (info.owner == tid) {
        n00b_lock_acquire_accounting((void *)lock, thread, loc);
        return 0;
    }

    // Win mutual exclusion by flipping the lock word 0 -> 1.  Pure spin: no
    // futex wait, no n00b_thread_suspend — a barrier participant must never
    // park (see spinlock.h).  The barrier keeps the holder running, so the
    // wait is short.
    while (n00b_atomic_or(&lock->spin, 1)) {
        ;
    }

    n00b_lock_acquire_accounting((void *)lock, thread, loc);
    return 0;
}

bool
_n00b_spinlock_unlock(n00b_spin_lock_t *lock, char *loc)
{
    // STW-active short-circuit (WP-001): no-op release while the world is
    // stopped (mirrors the acquire short-circuit).
    if (n00b_atomic_load(&n00b_get_runtime()->stw_active)) {
        return true;
    }

    // Only the outermost release (nesting back to 0) clears the lock word; a
    // nested release just unwinds the count so the outer hold still owns it.
    if (!n00b_lock_release_accounting((void *)lock, loc)) {
        return false;
    }

    n00b_atomic_store(&lock->spin, 0);
    return true;
}

/*
 * Enhanced condition variable with per-thread futex wait queue.
 *
 * The CV has a built-in mutex and supports selective wake via predicate
 * callbacks or state numbers.  The epoch protocol ensures that the
 * notifier's operation completes before any waiters resume.
 *
 * Each waiter blocks on its own thread's `cv_wake` futex.  The notifier
 * snapshots and clears the waiters list, then bumps each thread's
 * `cv_wake` to wake it.  Non-matching waiters re-enqueue themselves.
 * The epoch handshake (epoch+1 from last waiter, epoch+2 from notifier)
 * serializes notification rounds.
 */

#define N00B_USE_INTERNAL_API

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/condition.h"
#include "core/mutex.h"
#include "core/futex.h"
#include "core/stw.h"
#include "core/atomic.h"
#include "core/memory_info.h"
#include "core/gc.h"

void
_n00b_condition_init(n00b_condition_t *cv, char *loc)
{
    n00b_lock_init_accounting((void *)cv, N00B_NLT_CV, loc);

    n00b_futex_init(&cv->mutex);
    n00b_futex_init(&cv->notify_epoch);
    cv->ovalue    = nullptr;
    cv->predicate = nullptr;
    cv->cv_param  = nullptr;
    n00b_atomic_store(&cv->waiters_to_process, 0);
    n00b_atomic_store(&cv->wakes_remaining, 0);

    n00b_allocator_t *sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    cv->waiters = n00b_list_new(n00b_thread_t *, .allocator = sp);

    if (!n00b_in_heap(cv) && !n00b_in_stack(cv)
        && !n00b_current_thread_stack_contains(cv)) {
        _n00b_gc_register_root(&cv->cv_param, 2);
    }
}

void
n00b_condition_set_callback(n00b_condition_t            *cv,
                            n00b_condition_predicate_fn  fn,
                            void                        *param)
{
    n00b_condition_lock(cv);
    cv->predicate = fn;
    cv->cv_param  = param;

    if (!n00b_in_heap(cv) && !n00b_in_stack(cv)
        && !n00b_current_thread_stack_contains(cv)) {
        _n00b_gc_register_root(&cv->cv_param, 1);
    }
    n00b_condition_unlock(cv);
}

int
_n00b_condition_lock(n00b_condition_t *cv, char *loc)
{
    if (n00b_lock_already_owner((void *)cv)) {
        return 1;
    }

    _n00b_mutex_lock((void *)cv, loc);

    return 1;
}

bool
_n00b_condition_unlock(n00b_condition_t *cv, char *loc)
{
    if (!n00b_lock_already_owner((void *)cv)) {
        return false;
    }

    _n00b_mutex_unlock((void *)cv, loc);

    return true;
}

static void *
base_wait(n00b_condition_t *cv,
          n00b_thread_t    *thread,
          int64_t           timeout,
          bool              wake_unlocked,
          char             *loc)
{
    void   *result = nullptr;
    bool    want_to_wake;
    bool    waking = false;
    bool    timed;
    int64_t last_ts;
    int64_t cur_ts;

    n00b_thread_record_t *rec = thread->record;

    if (timeout <= 0) {
        timeout = 0;
        timed   = false;
    }
    else {
        timed   = true;
        last_ts = n00b_ns_timestamp();
    }

    _n00b_condition_lock(cv, loc);

    if (!rec->cv_info.current_cv || rec->cv_info.current_cv != cv) {
        memset(&rec->cv_info, 0, sizeof(n00b_condition_thread_state_t));
        rec->cv_info.current_cv     = cv;
        rec->cv_info.wait_predicate = N00B_CV_ANY;
    }

    rec->lock_wait_loc = loc;

    // Arm this thread's cv_wake futex for the wait.
    n00b_atomic_store(&thread->cv_wake, 0);

    // Enqueue ourselves on the CV's waiter list.
    n00b_list_push(cv->waiters, thread);

    n00b_register_lock_wait(thread, cv, loc);
    uint32_t epoch;

    _n00b_condition_unlock(cv, loc);

    do {
        // Wait on this thread's cv_wake futex.  No cooperative self-park
        // bracketing (WP-001): a waiter is preempted by the STW initiator, not
        // self-parked, so it does not advertise GC-safe state around the wait.
        n00b_futex_wait(&thread->cv_wake, 0, timeout);

        if (n00b_atomic_load(&thread->cv_wake) == 0) {
            // Spurious wake or timeout — cv_wake still 0.
            if (timed) {
                cur_ts = n00b_ns_timestamp();
                int64_t elapsed = cur_ts - last_ts;
                timeout -= elapsed;
                last_ts = cur_ts;

                if (timeout < 0) {
                    // Timed out: remove ourselves from waiter list
                    // (list has its own rwlock, safe outside CV mutex).
                    (void)n00b_list_remove_all(cv->waiters, thread);
                    n00b_wait_done(thread);
                    return (void *)~0ULL;
                }
            }
            // Spurious wake — loop back and re-wait.
            continue;
        }

        // cv_wake != 0: we were woken by a notification round.
        epoch = n00b_atomic_load(&cv->notify_epoch);

        // Check predicate match.
        if (cv->predicate) {
            want_to_wake = (*cv->predicate)(cv->pvalue,
                                            rec->cv_info.wait_predicate,
                                            cv->ovalue,
                                            cv->cv_param,
                                            rec->cv_info.thread_param);
        }
        else {
            want_to_wake = (cv->pvalue == rec->cv_info.wait_predicate
                            || rec->cv_info.wait_predicate == N00B_CV_ANY);
        }

        if (want_to_wake) {
            int32_t old = n00b_atomic_add(&cv->wakes_remaining, -1);
            if (old > 0) {
                waking = true;
                result = cv->ovalue;
            }
            else {
                // No wake slots left — undo the decrement.
                n00b_atomic_add(&cv->wakes_remaining, 1);
            }
        }

        if (!waking) {
            // Reset cv_wake BEFORE re-enqueuing — once we're on the
            // list a notifier may set cv_wake=1 at any moment.
            n00b_atomic_store(&thread->cv_wake, 0);
            n00b_list_push(cv->waiters, thread);
        }

        // Signal completion of our processing in this round.
        int32_t prev = n00b_atomic_add(&cv->waiters_to_process, -1);

        if (prev == 1) {
            // Last waiter — signal notifier (epoch+1).
            n00b_atomic_add(&cv->notify_epoch, 1);
            n00b_futex_wake(&cv->notify_epoch, false);
        }

        // Wait for the notifier to complete (epoch+2).
        n00b_futex_wait_for_value(&cv->notify_epoch, epoch + 2);
    } while (!waking);

    _n00b_condition_lock(cv, loc);
    n00b_wait_done(thread);

    if (wake_unlocked) {
        _n00b_condition_unlock(cv, loc);
    }

    return result;
}

static int32_t
_internal_cv_notify(n00b_condition_t *cv,
                    int64_t           pvalue,
                    void             *ovalue,
                    int32_t           max,
                    bool              unlock,
                    char             *loc)
{
    n00b_thread_t *thread = n00b_thread_self();

    _n00b_condition_lock(cv, loc);

    cv->pvalue = pvalue;
    cv->ovalue = ovalue;
    n00b_atomic_store(&cv->wakes_remaining, max);

    int32_t nwaiters = (int32_t)n00b_list_len(cv->waiters);

    if (!nwaiters) {
        if (unlock) {
            _n00b_condition_unlock(cv, loc);
        }
        return 0;
    }

    // Snapshot all waiters into a local array, then clear the list.
    // Non-matching waiters will re-enqueue themselves.
    n00b_thread_t *snapshot[nwaiters];

    for (int32_t i = 0; i < nwaiters; i++) {
        snapshot[i] = n00b_list_get(cv->waiters, i);
    }
    n00b_list_clear(cv->waiters);

    n00b_atomic_store(&cv->waiters_to_process, nwaiters);

    uint32_t epoch = n00b_atomic_load(&cv->notify_epoch);

    // Wake each waiter by setting its cv_wake to 1.
    for (int32_t i = 0; i < nwaiters; i++) {
        n00b_atomic_store(&snapshot[i]->cv_wake, 1);
        n00b_futex_wake(&snapshot[i]->cv_wake, false);
    }

    _n00b_condition_unlock(cv, loc);

    n00b_register_lock_wait(thread, cv, loc);

    // Wait for all waiters to finish processing (epoch+1).
    n00b_futex_wait_for_value(&cv->notify_epoch, epoch + 1);

    _n00b_condition_lock(cv, loc);
    n00b_wait_done(thread);

    // Signal all waiters that the notification round is complete (epoch+2).
    n00b_atomic_add(&cv->notify_epoch, 1);
    n00b_futex_wake(&cv->notify_epoch, true);

    if (unlock) {
        _n00b_condition_unlock(cv, loc);
    }
    n00b_mac_barrier();

    return nwaiters;
}

void *
_n00b_condition_wait(n00b_condition_t *cv, char *loc) _kargs
{
    int64_t predicate   = ~0LL;
    int64_t timeout_ms  = 0;
    bool    auto_unlock = false;
    void   *wake_param  = nullptr;
}
{
    void                 *result;
    n00b_thread_t        *thread = n00b_thread_self();
    n00b_thread_record_t *rec    = thread->record;

    rec->cv_info.current_cv     = cv;
    rec->cv_info.wait_predicate = predicate;
    rec->cv_info.thread_param   = wake_param;
    rec->cv_info.wait_loc       = loc;

    /* base_wait takes nanoseconds; the public kwarg is ms. Convert
     * with saturation so a caller-visible "10s" stays "10s" rather
     * than overflowing int64_t in pathological cases. */
    int64_t timeout_ns;
    if (timeout_ms <= 0) {
        timeout_ns = 0;
    }
    else if (timeout_ms > INT64_MAX / N00B_NS_PER_MS) {
        timeout_ns = INT64_MAX;
    }
    else {
        timeout_ns = timeout_ms * N00B_NS_PER_MS;
    }

    result = base_wait(cv, thread, timeout_ns, auto_unlock, loc);

    return result;
}

int32_t
_n00b_condition_notify(n00b_condition_t *cv, char *loc) _kargs
{
    int64_t predicate   = 0;
    int64_t max         = 1;
    void   *value       = nullptr;
    bool    all         = false;
    bool    auto_unlock = false;
}
{
    if (all || max <= 0) {
        max = 0x7fffffff;
    }

    return _internal_cv_notify(cv, predicate, value, (int32_t)max, auto_unlock, loc);
}

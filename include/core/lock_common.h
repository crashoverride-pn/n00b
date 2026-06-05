/**
 * @file lock_common.h
 * @brief Common lock base types, accounting declarations, and read-log types.
 *
 * Provides the shared infrastructure used by mutexes, rwlocks, and condition
 * variables: the `N00B_COMMON_LOCK_BASE` field set, the `n00b_lock_base_t`
 * generic lock, lock-log types for debugging, and read-lock nesting records.
 */
#pragma once

#include <stdio.h>
#include "n00b.h"
#include "core/atomic.h"
#include "core/alloc_mdata.h"
#include "core/thread.h"

/**
 * @brief Fields common to every lock type.
 *
 * Embedded via `N00B_COMMON_LOCK_BASE` in `n00b_mutex_t`, `n00b_rwlock_t`,
 * and `n00b_condition_t`.  The linked list (`next_thread_lock` /
 * `prev_thread_lock`) threads through the owning thread's
 * `n00b_thread_record_t::exclusive_locks` chain.
 */
#define N00B_COMMON_LOCK_BASE                       \
    _Atomic(n00b_lock_base_t *)   next_thread_lock; \
    _Atomic(n00b_lock_base_t *)   prev_thread_lock; \
    char                         *debug_name;       \
    _Atomic n00b_core_lock_info_t data;             \
    n00b_alloc_info_t             allocation;       \
    n00b_lock_log_t              *logs;             \
    char                         *creation_loc;     \
    uint32_t                      inited : 1;       \
    uint32_t                      no_log : 1

/**
 * @brief Packed owner/nesting/type stored atomically per lock.
 */
typedef struct {
    int64_t owner;
    int16_t nesting;
    uint8_t type;
    uint8_t reserved;
} n00b_core_lock_info_t;

struct n00b_lock_base_t {
    N00B_COMMON_LOCK_BASE;
};

enum {
    N00B_NLT_MUTEX = 1,
    N00B_NLT_RW    = 2,
    N00B_NLT_CV    = 3,
    N00B_NLT_SPIN  = 4,
};

#define N00B_SPIN_LIMIT 16
#define N00B_NO_OWNER   -1
#define N00B_PTR_WORDS  4

/**
 * @brief Debug log entry for lock/unlock operations.
 */
struct n00b_lock_log_t {
    n00b_lock_log_t *next_entry;
    n00b_lock_log_t *prev_entry;
    void            *obj;
    char            *loc;
    bool             lock_op;
    int32_t          thread_id;
};

/**
 * @brief Per-thread read-lock record, one per rwlock per thread.
 *
 * Tracks the nesting level via `level`.  Records are cached in
 * `n00b_thread_record_t::log_alloc_cache` for reuse.
 */
struct n00b_thread_read_log_t {
    n00b_thread_read_log_t *next_entry;
    n00b_thread_read_log_t *prev_entry;
    void                   *obj;
    int32_t                 level;
};

/**
 * @brief Check whether the current thread already owns a lock.
 * @param lock Lock to check.
 * @return     true if the calling thread is the lock owner.
 */
static inline bool
n00b_lock_already_owner(n00b_lock_base_t *lock)
{
    int64_t tid = n00b_os_thread_id();
    assert(tid >= 0);
    n00b_core_lock_info_t info = n00b_atomic_load(&lock->data);
    return info.owner == tid;
}

/**
 * @brief Set a human-readable debug name on a lock.
 * @param l    Lock to name.
 * @param name Debug name string (not copied; must outlive the lock).
 */
static inline void
_n00b_lock_set_debug_name(n00b_lock_base_t *l, char *name)
{
    l->debug_name = name;
}

#define n00b_lock_set_debug_name(x, y) _n00b_lock_set_debug_name((n00b_lock_base_t *)(x), y)

// Lock accounting functions (implemented in lock_accounting.c).
extern void n00b_lock_init_accounting(n00b_lock_base_t *lock, int type, char *loc);
extern int  n00b_lock_acquire_accounting(n00b_lock_base_t *lock,
                                         n00b_thread_t    *thread,
                                         char             *loc);
extern bool n00b_lock_release_accounting(n00b_lock_base_t *lock, char *loc);
extern void n00b_register_lock_wait(n00b_thread_t *thread, void *lock, char *loc);
extern void _n00b_wait_done(n00b_thread_t *thread, char *loc);

/* Scrub every thread's exclusive-lock chain of entries whose
 * address falls within [lo, hi).  Call from an allocator's destroy
 * callback before its pages are unmapped so the chain can't be left
 * holding dangling pointers into freed memory. */
extern void n00b_lock_chains_scrub_range(uint64_t lo, uint64_t hi);

#define n00b_wait_done(thread) _n00b_wait_done((thread), N00B_LOC_STRING())

// Debug/inspection functions.
extern void n00b_debug_thread_locks(n00b_thread_t *t, FILE *f);
extern void n00b_debug_all_locks(char *fname);
extern void n00b_debug_locks_stream(FILE *stream);

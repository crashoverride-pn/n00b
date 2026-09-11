/*
 * Lock accounting: per-thread lock chain management and debug inspection.
 *
 * Every exclusive lock acquired is linked into the owning thread's
 * `record->exclusive_locks` chain.  On release the link is removed.
 * Read locks get their own per-thread linked list in
 * `record->read_locks`.
 *
 * The debug helpers (`n00b_debug_thread_locks`, `n00b_debug_all_locks`)
 * walk these chains and are safe to call from signal handlers or crash
 * reporters because the records live in the system pool (not TLS).
 */

#define N00B_USE_INTERNAL_API

#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/lock_common.h"
#include "core/rwlock.h"
#include "core/alloc.h"
#include "core/memory_info.h"
#include "core/gc.h"
#include "core/atomic.h"
#include "core/pool.h"

void
n00b_lock_init_accounting(n00b_lock_base_t *lock, int type, char *loc)
{
    n00b_core_lock_info_t info = {
        .owner    = N00B_NO_OWNER,
        .type     = type,
        .nesting  = 0,
        .reserved = 0,
    };

    atomic_store(&lock->data, info);
    atomic_store(&lock->next_thread_lock, nullptr);
    // Init accepts memory holding anything, and an unranked lock has to read
    // as unranked rather than as whatever byte was already there.
    atomic_store(&lock->rank, (uint8_t)N00B_LOCK_RANK_NONE);
    atomic_store(&lock->prev_thread_lock, nullptr);

    lock->creation_loc = loc;
    lock->inited       = true;
    /* Default debug lock-log OFF. Each acquire/release otherwise
     * appends a `n00b_lock_log_t` to `lock->logs` from system_pool
     * (lock_accounting.c:86, :210). For long-lived locks (e.g. the
     * rwlock embedded in every n00b_list_t / created by
     * n00b_data_lock_new), the chain grows unbounded — observed
     * ~6.5 MB/s system_pool growth under sustained ES burst load,
     * directly traced to this site. Mutexes already opt out via
     * mutex.c:33; do the same for rwlocks and CVs here so all
     * default-constructed locks are non-leaking. Callers needing
     * lock-op tracing can flip `lock->no_log = false` per-lock
     * after init, or wire a build flag if a global debug switch
     * is wanted. */
    lock->no_log       = true;
    // lock->allocation is WRITE-ONLY: nothing anywhere reads it (only this init
    // and the zeroing in the destroy path touch it). Computing it via
    // n00b_find_alloc_info(.scan_for_header=true) ran a backward word-scan for
    // the object guard on EVERY lock init -- every rwlock/CV, including the
    // data-lock embedded in every buffer. That scan is both a per-lock cost
    // under load and crash-prone: for a buffer built by a ROCS ingest worker it
    // walked a page that raced a concurrent unmap and faulted (SIGSEGV in
    // _find_sentinal, fault_addr a wild scan pointer). Since the value has no
    // consumer, don't compute it. A future consumer should resolve it safely at
    // point-of-use (the allocator metadata dict), never by scanning for a guard.
    lock->allocation   = (n00b_alloc_info_t){0};
}

#ifdef N00B_DEBUG
// Lock ranks live in the lock, in tail padding N00B_COMMON_LOCK_BASE already
// carries, so a rank costs no space in any build and cannot be separated from
// or outlive the lock it describes.
//
// Unconditional rather than debug-only. It is free either way, and one layout
// across debug and release means a library and a consumer built with different
// flags still agree on where every other field sits.
//
// Atomic because a lock can be ranked while another thread is already
// acquiring it, and an unranked read is skipped rather than checked wrongly.
void
_n00b_lock_set_rank(n00b_lock_base_t *l, n00b_lock_rank_t rank)
{
    if (l == nullptr) {
        return;
    }

    atomic_store(&l->rank, (uint8_t)rank);
}

n00b_lock_rank_t
_n00b_lock_get_rank(const n00b_lock_base_t *l)
{
    if (l == nullptr) {
        return N00B_LOCK_RANK_NONE;
    }

    return (n00b_lock_rank_t)atomic_load(&l->rank);
}

// Lock order, checked against what this thread already holds.
//
// Reports and continues rather than aborting: a suite run then enumerates
// every inversion it reaches instead of stopping at the first, which is the
// difference between one fix per run and one run per fix. Each ordered pair is
// reported once, because an inversion on a hot path would otherwise bury the
// rest. Set N00B_LOCK_ORDER_ABORT in the environment to stop at the first
// one instead.
//
// Both chains are walked. A read lock taken while holding a higher-ranked
// write lock deadlocks exactly as an exclusive one does, and checking only
// exclusive acquisitions would see neither side of that.
#define N00B_LOCK_ORDER_REPORTS 64

static _Atomic(uint64_t) lock_order_reported[N00B_LOCK_ORDER_REPORTS];
static _Atomic(uint32_t) lock_order_report_count = 0;

static bool
lock_order_first_report(uint32_t held_rank, uint32_t rank)
{
    uint64_t key = ((uint64_t)held_rank << 32) | (uint64_t)rank;
    uint32_t n   = atomic_load(&lock_order_report_count);

    for (uint32_t i = 0; i < n && i < N00B_LOCK_ORDER_REPORTS; i++) {
        if (atomic_load(&lock_order_reported[i]) == key) {
            return false;
        }
    }
    if (n >= N00B_LOCK_ORDER_REPORTS) {
        return false;
    }
    // Claim the slot before writing it. Two threads that both read the same
    // count would otherwise write the same index, and the pair that lost is
    // then absent from the table and reported again on its next occurrence.
    if (!atomic_compare_exchange_strong(&lock_order_report_count, &n, n + 1)) {
        // Somebody else took it. Their key may or may not be ours; reporting
        // once more is the cost of not holding a lock on a debug path.
        return true;
    }
    atomic_store(&lock_order_reported[n], key);
    return true;
}

static void
lock_order_report(n00b_lock_base_t *lock,
                  n00b_lock_base_t *held,
                  const char       *held_kind,
                  char             *loc)
{
    if (!lock_order_first_report(_n00b_lock_get_rank(held),
                                 _n00b_lock_get_rank(lock))) {
        return;
    }
    fprintf(stderr,
            "%s: lock order inversion.\n"
            "  acquiring %s (rank %u) at %p\n"
            "  while holding %s %s (rank %u) at %p\n"
            "  A lock may only be taken when every lock already held ranks "
            "strictly lower.\n",
            loc,
            lock->debug_name ? lock->debug_name : "<unnamed>",
            (unsigned)_n00b_lock_get_rank(lock),
            (void *)lock,
            held_kind,
            held->debug_name ? held->debug_name : "<unnamed>",
            (unsigned)_n00b_lock_get_rank(held),
            (void *)held);

    if (getenv("N00B_LOCK_ORDER_ABORT") != nullptr) {
        abort();
    }
}

static void
n00b_lock_order_check(n00b_lock_base_t *lock, n00b_thread_t *thread, char *loc)
{
    // Declared as block items: ncc's GC stack maps do not take a root
    // introduced in a for-init clause.
    n00b_lock_rank_t        rank = N00B_LOCK_RANK_NONE;
    n00b_thread_record_t   *rec  = nullptr;
    n00b_lock_base_t       *held = nullptr;
    n00b_thread_read_log_t *log  = nullptr;
    n00b_lock_base_t       *rheld = nullptr;
    n00b_lock_rank_t        hr   = N00B_LOCK_RANK_NONE;

    if (lock == nullptr || thread == nullptr || thread->record == nullptr) {
        return;
    }

    rec  = thread->record;
    held = n00b_atomic_load(&rec->exclusive_locks);
    log  = n00b_atomic_load(&rec->read_locks);

    // An acquisition inverts nothing when the thread holds nothing, which is
    // the overwhelming majority of them. Tested before the lock's own rank so
    // an unranked-heavy workload does no work at all here.
    if (held == nullptr && log == nullptr) {
        return;
    }

    rank = _n00b_lock_get_rank(lock);

    if (rank == N00B_LOCK_RANK_NONE) {
        return;
    }

    while (held != nullptr) {
        hr = _n00b_lock_get_rank(held);
        if (held != lock && hr != N00B_LOCK_RANK_NONE && hr >= rank) {
            lock_order_report(lock, held, "exclusive", loc);
        }
        held = n00b_atomic_load(&held->next_thread_lock);
    }

    while (log != nullptr) {
        rheld = (n00b_lock_base_t *)log->obj;
        if (rheld != nullptr && rheld != lock) {
            hr = _n00b_lock_get_rank(rheld);
            if (hr != N00B_LOCK_RANK_NONE && hr >= rank) {
                lock_order_report(lock, rheld, "read-locked", loc);
            }
        }
        log = log->next_entry;
    }
}
#endif

int
n00b_lock_acquire_accounting(n00b_lock_base_t *lock,
                             n00b_thread_t    *thread,
                             char             *loc)
{
    // Owner / reentrancy key is the OS thread id, NOT the runtime slot id
    // (WP-001): a thread holds critical_execution during its whole init and
    // whole destroy, windows in which n00b_thread_self() is null.  The OS id
    // is resolvable in those windows; the slot id is not.
    int64_t               tid  = n00b_os_thread_id();
    n00b_core_lock_info_t info = n00b_atomic_load(&lock->data);

    if (!lock->inited) {
        fprintf(stderr,
                "%s: Fatal: Lock at address %p "
                "was not initialized before use.\n",
                loc,
                (void *)lock);
        abort();
    }

    // The per-thread lock CHAIN links via the thread record (for the GC scan
    // and for thread-exit release).  When n00b_thread_self() does not resolve
    // (the pre/post-registration window — a thread holding critical_execution
    // during init/destroy), skip the chain link but still set owner+nesting
    // from the OS id.
    //
    // The critical_execution STW gate is NEVER linked into the chain: a thread
    // holds it across its WHOLE destroy, and n00b_release_locks_on_thread_exit
    // (run mid-destroy) force-releases every chained lock — which would drop the
    // gate out from under the rest of teardown and then double-free it at the
    // explicit unlock.  The gate's lifecycle is managed explicitly by the
    // init/destroy bracket and stop/restart, not by the chain.
    n00b_runtime_t       *acc_rt = n00b_get_runtime();
    bool                  is_gate =
        (acc_rt != nullptr
         && lock == (n00b_lock_base_t *)&acc_rt->critical_execution);
    n00b_thread_record_t *rec =
        (thread != nullptr && !is_gate) ? thread->record : nullptr;

    if (info.owner == tid) {
        ++info.nesting;
    }
    else {
        if (info.owner != N00B_NO_OWNER) {
            abort();
        }
        assert(info.owner == N00B_NO_OWNER);
        info.owner   = tid;
        info.nesting = 1;

#ifdef N00B_DEBUG
        n00b_lock_order_check(lock, thread, loc);
#endif

        if (rec != nullptr) {
            n00b_lock_base_t *top_held = n00b_atomic_load(&rec->exclusive_locks);

            if (top_held) {
                atomic_store(&top_held->prev_thread_lock, lock);
            }

            atomic_store(&lock->next_thread_lock, top_held);
            n00b_atomic_store(&rec->exclusive_locks, lock);
        }
    }

    if (!lock->no_log) {
        n00b_runtime_t   *rt  = n00b_get_runtime();
        n00b_allocator_t *sp  = (n00b_allocator_t *)&rt->system_pool;
        n00b_lock_log_t  *log = n00b_alloc_with_opts(n00b_lock_log_t, &(n00b_alloc_opts_t){.allocator = sp});

        log->loc        = loc;
        log->lock_op    = true;
        log->thread_id  = (int32_t)tid;
        log->next_entry = lock->logs;
        lock->logs      = log;
    }
    atomic_store(&lock->data, info);

    return 0;
}

void
_n00b_rlock_accounting(n00b_rwlock_t          *lock,
                       n00b_thread_read_log_t *record,
                       n00b_thread_t          *thread,
                       int                     value,
                       char                   *loc)
{
    (void)value;

#ifdef N00B_DEBUG
    n00b_lock_order_check((n00b_lock_base_t *)lock, thread, loc);
#else
    (void)record;
    (void)lock;
    (void)thread;
    (void)loc;
#endif
}

void
_n00b_runlock_accounting(n00b_rwlock_t          *lock,
                         n00b_thread_read_log_t *record,
                         n00b_thread_t          *thread,
                         int                     value,
                         char                   *loc)
{
    (void)lock;
    (void)record;
    (void)thread;
    (void)value;
    (void)loc;
}

bool
n00b_lock_release_accounting(n00b_lock_base_t *lock, char *loc)
{
    bool                  unlock = false;
    n00b_thread_t        *thread = n00b_thread_self();
    n00b_core_lock_info_t info   = n00b_atomic_load(&lock->data);
    // Owner key is the OS thread id (WP-001) — resolvable even when
    // n00b_thread_self() is null (init/destroy window holding
    // critical_execution).  The chain unlink below is skipped when there is
    // no resolvable record (it was never linked in that window either).
    int64_t               tid    = n00b_os_thread_id();
    n00b_lock_base_t     *prev   = nullptr;
    n00b_lock_base_t     *next   = nullptr;
    n00b_thread_record_t *rec    = (thread != nullptr) ? thread->record : nullptr;

    if (info.type != N00B_NLT_CV) {
        if (info.owner == N00B_NO_OWNER) {
            fprintf(stderr,
                    "Fatal: Attempt to unlock %p, which is unlocked.\n",
                    (void *)lock);
            abort();
        }

        if (info.owner != tid) {
            switch (info.type) {
            case N00B_NLT_CV:
                return false;
            default:
                fprintf(stderr,
                        "Fatal: tid %lld tried to unlock %p (owned by %lld)\n",
                        (long long)tid,
                        (void *)lock,
                        (long long)info.owner);
                abort();
            }
        }
        assert(info.nesting > 0);
        assert(lock->inited);
    }
    else {
        if (info.owner != tid) {
            return false;
        }
    }

    if (!--info.nesting) {
        unlock     = true;
        info.owner = N00B_NO_OWNER;

        prev = n00b_atomic_load(&lock->prev_thread_lock);
        next = n00b_atomic_load(&lock->next_thread_lock);

        if (prev) {
            if (prev != next) {
                atomic_store(&prev->next_thread_lock, next);
            }
        }

        if (next) {
            if (prev != next) {
                atomic_store(&next->prev_thread_lock, prev);
            }
        }

        atomic_store(&lock->prev_thread_lock, nullptr);
        atomic_store(&lock->next_thread_lock, nullptr);

        // The chain head lives on the thread record; skip it when there is no
        // resolvable record (the init/destroy window where the lock was never
        // chain-linked — see the acquire path).
        if (rec != nullptr) {
            if (n00b_atomic_load(&rec->exclusive_locks) == lock) {
                n00b_atomic_store(&rec->exclusive_locks, next);
            }

            if (n00b_atomic_load(&rec->exclusive_locks) == lock) {
                n00b_atomic_store(&rec->exclusive_locks, nullptr);
            }
        }

        lock->allocation = (n00b_alloc_info_t){0};
        lock->logs       = nullptr;
    }
    else {
        if (!lock->no_log) {
            n00b_runtime_t   *rt  = n00b_get_runtime();
            n00b_allocator_t *sp  = (n00b_allocator_t *)&rt->system_pool;
            n00b_lock_log_t  *log = n00b_alloc_with_opts(n00b_lock_log_t, &(n00b_alloc_opts_t){.allocator = sp});

            log->obj        = lock;
            log->loc        = loc;
            log->lock_op    = false;
            log->thread_id  = (int32_t)tid;
            log->next_entry = lock->logs;
            lock->logs      = log;
        }
    }

    atomic_store(&lock->data, info);

    return unlock;
}

// Unlink any locks in this thread's exclusive-lock chain whose
// address falls within `[lo, hi)` — used when a non-hidden allocator
// (typically a per-regex compile pool) is about to unmap its pages.
// Without this scrub, the chain holds dangling pointers into freed
// memory and the next n00b_lock_acquire_accounting crashes when it
// dereferences `top_held->prev_thread_lock`.
//
// Locks aren't released here in the normal sense (we don't update
// `lock->data` — the lock is about to vanish).  We only patch the
// chain pointers to skip the dying entry.
void
n00b_lock_chains_scrub_range(uint64_t lo, uint64_t hi)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    if (!rt) return;

    /* Fast path: if no thread has any chain entries we can skip the
     * whole scrub.  This is the common case (only the regex builder
     * holds locks, and only briefly). */
    bool any = false;
    for (int i = 0; i < N00B_THREADS_MAX; i++) {
        if (n00b_atomic_load(&rt->threads[i].exclusive_locks)) {
            any = true;
            break;
        }
    }
    if (!any) return;

    for (int i = 0; i < N00B_THREADS_MAX; i++) {
        n00b_thread_record_t *rec = &rt->threads[i];
        n00b_lock_base_t     *cur = n00b_atomic_load(&rec->exclusive_locks);

        /* Bounded walk — a chain that's been corrupted (e.g. by an
         * earlier dangling `next_thread_lock` overwritten with random
         * bytes) can form a cycle when we follow it through partially
         * freed memory.  Cap the walk so we don't spin forever; a
         * real chain doesn't get nearly this deep. */
        int budget = 256;
        while (cur && budget-- > 0) {
            uintptr_t addr = (uintptr_t)cur;
            n00b_lock_base_t *next = (n00b_lock_base_t *)
                n00b_atomic_load(&cur->next_thread_lock);
            if (addr >= lo && addr < hi) {
                /* Unlink `cur` from the chain. */
                n00b_lock_base_t *prev = (n00b_lock_base_t *)
                    n00b_atomic_load(&cur->prev_thread_lock);
                if (prev) {
                    atomic_store(&prev->next_thread_lock, next);
                }
                else {
                    /* `cur` was the head. */
                    n00b_atomic_store(&rec->exclusive_locks, next);
                }
                if (next) {
                    atomic_store(&next->prev_thread_lock, prev);
                }
            }
            cur = next;
        }
        /* If the walk hit the budget, the chain is in an unrecoverable
         * state — there's a cycle or it's pointing into freed memory.
         * Drop the whole head; better an empty chain than a corrupt
         * one that segfaults next acquire. */
        if (cur != nullptr) {
            n00b_atomic_store(&rec->exclusive_locks, (n00b_lock_base_t *)nullptr);
        }
    }
}

/* True if `addr` falls inside any live page of `pool`. */
static inline bool
lock_addr_in_pool(n00b_pool_t *pool, uintptr_t addr)
{
    n00b_pool_page_t *pg = pool->page_table;
    while (pg != nullptr) {
        uintptr_t lo = (uintptr_t)pg;
        size_t    sz = pg->mapped_size != 0 ? pg->mapped_size : n00b_page_size;
        if (addr >= lo && addr < lo + sz) {
            return true;
        }
        pg = pg->next;
    }
    return false;
}

/* Scrub every thread's exclusive-lock chain of entries that live in
 * `pool`, called from pool_destroy before its pages are unmapped.
 *
 * This walks the 4096-slot thread table EXACTLY ONCE for the whole
 * pool.  (The previous shape called n00b_lock_chains_scrub_range once
 * per page, so a pool with P pages paid P * 4096 thread-record walks
 * every destroy — and a GC's cleanup destroys many pools, which froze
 * the process for the duration of the collection.)  Membership is
 * tested against the pool's page table per chain entry; held-lock
 * chains are nearly always empty (only briefly-held locks like the
 * regex builder ever appear), so the inner page walk runs rarely. */
void
n00b_lock_chains_scrub_pool(n00b_pool_t *pool)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) return;

    /* Fast path: if no thread holds any chain entry there is nothing
     * to scrub regardless of how many pages the pool has. */
    bool any = false;
    for (int i = 0; i < N00B_THREADS_MAX; i++) {
        if (n00b_atomic_load(&rt->threads[i].exclusive_locks)) {
            any = true;
            break;
        }
    }
    if (!any) return;

    for (int i = 0; i < N00B_THREADS_MAX; i++) {
        n00b_thread_record_t *rec = &rt->threads[i];
        n00b_lock_base_t     *cur = n00b_atomic_load(&rec->exclusive_locks);

        /* Bounded walk — a corrupted chain can form a cycle through
         * partially freed memory; cap so we never spin forever. */
        int budget = 256;
        while (cur && budget-- > 0) {
            n00b_lock_base_t *next = (n00b_lock_base_t *)
                n00b_atomic_load(&cur->next_thread_lock);
            if (lock_addr_in_pool(pool, (uintptr_t)cur)) {
                n00b_lock_base_t *prev = (n00b_lock_base_t *)
                    n00b_atomic_load(&cur->prev_thread_lock);
                if (prev) {
                    atomic_store(&prev->next_thread_lock, next);
                }
                else {
                    n00b_atomic_store(&rec->exclusive_locks, next);
                }
                if (next) {
                    atomic_store(&next->prev_thread_lock, prev);
                }
            }
            cur = next;
        }
        if (cur != nullptr) {
            n00b_atomic_store(&rec->exclusive_locks, (n00b_lock_base_t *)nullptr);
        }
    }
}

static inline void
show_lock_logs(n00b_lock_log_t *log, FILE *f)
{
    while (log) {
        fprintf(f,
                "      %s: %s (tid:%x)\n",
                log->lock_op ? "lock" : "unlock",
                log->loc,
                (int)log->thread_id);
        log = log->next_entry;
    }
}

static inline void
show_lock(n00b_lock_base_t *l, FILE *f)
{
    n00b_core_lock_info_t info = n00b_atomic_load(&l->data);

    fprintf(f,
            "    %s (owner 0x%llx, init @%s)",
            l->debug_name ? l->debug_name : "(not named)",
            (long long)info.owner,
            l->creation_loc);
}

static inline void
n00b_show_write_locks(n00b_thread_record_t *rec, FILE *f)
{
    n00b_lock_base_t *l = n00b_atomic_load(&rec->exclusive_locks);
    n00b_thread_t    *thread = n00b_atomic_load(&rec->thread);

    if (!l) {
        if (thread) {
            fprintf(f, "  No write locks for thread %d.\n",
                    thread->id_info.parts.id);
        }
        return;
    }

    if (thread) {
        fprintf(f, "  Write Locks for thread %d:\n",
                thread->id_info.parts.id);
    }

    while (l) {
        show_lock(l, f);
        fprintf(f, " (@%p)\n", (void *)l);
        show_lock_logs(l->logs, f);
        l = n00b_atomic_load(&l->next_thread_lock);
    }
}

static inline void
show_read_trail(n00b_rwlock_t *lock, FILE *f)
{
    n00b_rwdebug_t *log = n00b_atomic_load(&lock->first_entry);

    while (log) {
        fprintf(f,
                "      -- %c @%s by %x (%d)\n",
                log->lock_op ? 'l' : 'u',
                log->loc,
                log->thread_id,
                log->nest);
        if (log->trace) {
            fprintf(f, "*****Backtrace****:\n%s\n", log->trace);
        }
        log = n00b_atomic_load(&log->next);
    }
    fprintf(f,
            "    ** Current mutex value: %x\n",
            n00b_atomic_load(&lock->futex));
}

static inline void
n00b_show_read_locks(n00b_thread_record_t *rec, FILE *f)
{
    n00b_thread_read_log_t *log = n00b_atomic_load(&rec->read_locks);
    n00b_thread_t          *thread = n00b_atomic_load(&rec->thread);

    if (!log) {
        if (thread) {
            fprintf(f, "  No read locks for thread %d.\n",
                    thread->id_info.parts.id);
        }
        return;
    }

    if (thread) {
        fprintf(f, "  Read Locks for thread %d:\n",
                thread->id_info.parts.id);
    }

    while (log) {
        show_lock(log->obj, f);
        fprintf(f, " (@%p; ", log->obj);
        fprintf(f, " %d times)\n", log->level);
        n00b_rwlock_t *rw = log->obj;
        if (n00b_atomic_load(&rw->first_entry)) {
            show_read_trail((void *)log->obj, f);
        }
        log = log->next_entry;
    }
}

static inline void
n00b_show_wait_status(n00b_thread_record_t *rec, FILE *f)
{
    if (rec->lock_wait_target) {
        fprintf(f,
                "  BLOCKED waiting on %s for lock (@%p)\n  ",
                rec->lock_wait_loc,
                (void *)rec->lock_wait_target);
        show_lock(rec->lock_wait_target, f);
        fprintf(f, "\n");
        if (rec->lock_wait_trace) {
            fprintf(f, "%s\n", rec->lock_wait_trace);
        }

        n00b_core_lock_info_t info = n00b_atomic_load(&rec->lock_wait_target->data);
        if (info.type == N00B_NLT_RW) {
            fprintf(f, "    Read trail:\n");
            show_read_trail((void *)rec->lock_wait_target, f);
        }
    }
}

void
n00b_debug_thread_locks(n00b_thread_t *t, FILE *f)
{
    if (!t) {
        t = n00b_thread_self();
    }

    n00b_thread_record_t *rec = t->record;
    if (!rec) {
        return;
    }

    n00b_show_write_locks(rec, f);
    n00b_show_read_locks(rec, f);
    n00b_show_wait_status(rec, f);
    fflush(f);
}

void
n00b_debug_locks_stream(FILE *stream)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        n00b_thread_record_t *rec = &rt->threads[i];
        n00b_thread_t        *t   = n00b_atomic_load(&rec->thread);

        if (!t) {
            continue;
        }

        if (!n00b_atomic_load(&rec->exclusive_locks)
            && !n00b_atomic_load(&rec->read_locks)
            && !rec->lock_wait_target) {
            fprintf(stream, "Thread %d: unlocked.\n\n", i);
        }
        else {
            fprintf(stream, "Thread %d: ", i);
            n00b_debug_thread_locks(t, stream);
            fprintf(stream, "\n");
        }
    }
}

void
n00b_debug_all_locks(char *fname)
{
    FILE *stream = stderr;
    bool  close  = false;

    if (fname) {
        FILE *f = fopen(fname, "w");
        close   = true;

        if (f) {
            stream = f;
        }
    }

    n00b_debug_locks_stream(stream);

    if (close) {
        fclose(stream);
    }
}

void
n00b_register_lock_wait(n00b_thread_t *thread, void *lock, char *loc)
{
    // A thread can block acquiring critical_execution during its own init,
    // before n00b_thread_self() resolves (thread == nullptr).  This is just
    // debug wait-tracking, so skip it when there is no record yet.
    if (thread == nullptr) {
        return;
    }
    n00b_thread_record_t *rec = thread->record;

    assert(lock);
    rec->lock_wait_target = lock;
    rec->lock_wait_loc    = loc;
}

void
_n00b_wait_done(n00b_thread_t *thread, char *loc)
{
    if (thread == nullptr) {
        return;
    }
    n00b_thread_record_t *rec = thread->record;

    rec->lock_wait_target = nullptr;
}

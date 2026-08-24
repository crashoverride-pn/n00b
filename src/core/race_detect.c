/*
 * Hybrid race detection: lockset (Eraser) intersected with happens-before.
 *
 * Neither half is sufficient alone, and they fail in opposite directions.
 *
 * Lockset (Savage et al., 1997) says a field consistently guarded by some
 * lock is, on every access, accessed with that lock held; track the set common
 * to all accesses and report when it empties. It is schedule-independent, so
 * it finds a race the run did not happen to expose. It is also blind to every
 * form of ordering that is not a lock, and reports all of them.
 *
 * Happens-before (Lamport; Djit+, FastTrack) says two accesses ordered by
 * synchronization cannot race whatever locks were held. It has no false
 * alarms and sees unsynchronized publish, which lockset structurally cannot,
 * but it only judges the interleaving it observed.
 *
 * So a report needs both: the lockset empty AND the accesses unordered. This
 * is the arrangement of the hybrid detectors (O'Callahan and Choi, RaceTrack,
 * MultiRace), and the reason for it here is concrete -- sealing a shard is
 * ordered by a pin drain rather than by a lock, and a pure lockset run
 * reported every posting list it touched.
 *
 * Both inputs are cheap because n00b already maintains them. locks_held(t) is
 * the two chains off the thread record that lock_accounting.c updates on every
 * acquire and release. The happens-before edges hang off the same two calls,
 * plus thread fork and join.
 *
 * Shadow cells hold an epoch, not a vector clock: a thread id and a clock
 * packed in a word, which is FastTrack's observation that the common case
 * needs no more than that.
 *
 * Synchronization of the detector's own tables. A thread's own clock is
 * written only by that thread and its slot pointer is cached in TLS, so the
 * hot path takes no shared lock to reach it. The shadow table and the
 * published lock clocks are striped, and a stripe is derived from the table
 * slot rather than from the address, so two entries that share a slot always
 * share a guard.
 *
 * Debug builds only, and only for fields somebody annotated.
 */

#define N00B_USE_INTERNAL_API

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"

#ifdef N00B_DEBUG

#include "core/race_detect.h"

// Shadow entries, open addressed. A collision evicts, which forgets what was
// learned about the old address and starts it at virgin again. That direction
// is safe: a forgotten field goes quiet, it does not report falsely.
#define N00B_RACE_SLOTS    4096
// Locks a candidate set can hold. A thread holding more than this cannot have
// its held set represented, and an access it makes refines nothing rather
// than refining wrongly, because a set that dropped members it could not fit
// would empty early and report a field that is properly guarded.
#define N00B_RACE_LOCKS    8

// Threads a vector clock can describe. A thread past this is not tracked and
// its accesses refine nothing, because a clock that silently dropped a thread
// would call an ordered pair unordered and report it. Slots are returned at
// thread exit, so this bounds threads alive at once rather than threads over
// the life of the process.
#define N00B_RACE_THREADS  64

// Striped, not one lock. Annotated fields sit on hot paths, and a single flag
// would serialize every thread that touches any of them, which changes the
// interleaving the detector exists to observe.
#define N00B_RACE_STRIPES  64

// One clock per lock, published on release and joined on acquire. Keyed by
// lock address; a collision evicts, which forgets an edge and can only cost a
// false alarm rather than hide one, so the table stays small.
#define N00B_RACE_LOCK_SLOTS 1024

// An epoch is one thread's clock: which thread, and where it was. Packed so a
// shadow cell stays a word (FastTrack's point: a full vector clock per cell is
// what made happens-before look too expensive to run).
typedef uint64_t race_epoch_t;

#define RACE_EPOCH(tid, clk) (((uint64_t)(tid) << 48) | (uint64_t)(clk))
#define RACE_EPOCH_TID(e)    ((uint16_t)((e) >> 48))
#define RACE_EPOCH_CLK(e)    ((uint64_t)((e) & UINT64_C(0xFFFFFFFFFFFF)))
#define RACE_EPOCH_NONE      UINT64_C(0)

typedef struct {
    // Zero means the slot is free. Atomic because the allocating scan reads
    // other threads' slots, and because a thread reads its own cached slot's
    // id to notice a stale TLS value after slot reuse.
    _Atomic(int64_t) os_tid;
    uint64_t         vc[N00B_RACE_THREADS];
} race_thread_t;

static race_thread_t race_threads[N00B_RACE_THREADS];

// Taken only to hand out or return a slot, which happens once per thread at
// each end of its life. The hot path reaches its slot through TLS and never
// touches this.
static atomic_flag race_thread_guard = ATOMIC_FLAG_INIT;

static _Thread_local race_thread_t *race_tls_self = nullptr;

typedef struct {
    const void *obj;
    uint64_t    vc[N00B_RACE_THREADS];
} race_lock_t;

static race_lock_t race_locks[N00B_RACE_LOCK_SLOTS];

typedef enum : uint8_t {
    RACE_VIRGIN = 0,   // never accessed
    RACE_EXCLUSIVE,    // one thread only; no lockset is required yet
    RACE_SHARED,       // a second thread has read it; refine, do not report
    RACE_SHARED_MOD,   // a second thread has written it; refine and report
    RACE_LOCKFREE,     // annotated as deliberately unlocked
} race_state_t;

typedef struct {
    const void  *addr;
    const char  *name;
    int64_t      owner;
    void        *locks[N00B_RACE_LOCKS];
    uint8_t      lock_count;
    race_state_t state;
    bool         truncated;   // held set was too large to represent
    // The write this cell last saw. An access ordered after it cannot race
    // it, whatever locks either side held.
    race_epoch_t last_write;
} race_entry_t;

static race_entry_t      race_table[N00B_RACE_SLOTS];
static _Atomic(uint64_t) race_report_count = 0;

static atomic_flag race_stripe[N00B_RACE_STRIPES]      = {};
static atomic_flag race_lock_stripe[N00B_RACE_STRIPES] = {};

// A spin, not one of n00b's locks. Taking a tracked lock here would recurse
// through lock accounting and back into this table.
static inline void
race_flag_lock(atomic_flag *f)
{
    while (atomic_flag_test_and_set_explicit(f, memory_order_acquire)) {
        ;
    }
}

static inline void
race_flag_unlock(atomic_flag *f)
{
    atomic_flag_clear_explicit(f, memory_order_release);
}

static inline uint64_t
race_mix(const void *p)
{
    uint64_t h = (uint64_t)(uintptr_t)p;
    h ^= h >> 33;
    h *= UINT64_C(0xFF51AFD7ED558CCD);
    h ^= h >> 33;
    return h;
}

static inline size_t
race_slot(const void *addr)
{
    return (size_t)(race_mix(addr) & (N00B_RACE_SLOTS - 1));
}

static inline size_t
race_lock_slot(const void *obj)
{
    return (size_t)(race_mix(obj) & (N00B_RACE_LOCK_SLOTS - 1));
}

// The stripe follows the slot, not the address. Deriving it from the address
// with a second hash lets two entries that share a slot be guarded by
// different flags, which leaves the table with no mutual exclusion at all on
// exactly the collisions eviction exists to handle.
static inline atomic_flag *
race_stripe_for(const void *addr)
{
    return &race_stripe[race_slot(addr) & (N00B_RACE_STRIPES - 1)];
}

static inline atomic_flag *
race_lock_stripe_for(size_t slot)
{
    return &race_lock_stripe[slot & (N00B_RACE_STRIPES - 1)];
}

static inline int
race_index(race_thread_t *t)
{
    return (int)(t - race_threads);
}

// This thread's clock slot. Cached in TLS after the first call, so the guard
// below is taken once per thread rather than once per access.
static race_thread_t *
race_self(void)
{
    int64_t        tid    = n00b_os_thread_id();
    race_thread_t *cached = race_tls_self;

    if (cached != nullptr
        && atomic_load_explicit(&cached->os_tid, memory_order_relaxed) == tid) {
        return cached;
    }

    race_flag_lock(&race_thread_guard);

    race_thread_t *found = nullptr;
    for (int i = 0; i < N00B_RACE_THREADS; i++) {
        if (atomic_load_explicit(&race_threads[i].os_tid, memory_order_relaxed)
            == tid) {
            found = &race_threads[i];
            break;
        }
    }
    if (found == nullptr) {
        for (int i = 0; i < N00B_RACE_THREADS; i++) {
            if (atomic_load_explicit(&race_threads[i].os_tid,
                                     memory_order_relaxed)
                != 0) {
                continue;
            }
            // What the previous occupant learned about other threads is not
            // ours, so it goes. Its own clock stays and advances: an epoch the
            // dead thread stamped into a shadow cell still names this index,
            // and a clock that restarted below it would read as a fresh
            // ordering claim from a thread that no longer exists.
            uint64_t own = race_threads[i].vc[i];
            memset(race_threads[i].vc, 0, sizeof(race_threads[i].vc));
            race_threads[i].vc[i] = own + 1;
            atomic_store_explicit(&race_threads[i].os_tid,
                                  tid,
                                  memory_order_relaxed);
            found = &race_threads[i];
            break;
        }
    }

    race_flag_unlock(&race_thread_guard);

    race_tls_self = found;
    return found;
}

void
n00b_race_thread_exit(void)
{
    race_thread_t *self = race_tls_self;

    if (self == nullptr) {
        return;
    }
    race_tls_self = nullptr;

    race_flag_lock(&race_thread_guard);
    // The clock stays; only the ownership goes. See the reuse note above.
    atomic_store_explicit(&self->os_tid, 0, memory_order_relaxed);
    race_flag_unlock(&race_thread_guard);
}

// Ordered after `e`? True when this thread's clock already covers the point
// the writing thread was at, which is exactly what a synchronization edge
// between them would have established.
static bool
race_happens_after(race_thread_t *self, race_epoch_t e)
{
    if (e == RACE_EPOCH_NONE) {
        return true;
    }
    uint16_t tid = RACE_EPOCH_TID(e);
    if (tid >= N00B_RACE_THREADS) {
        return true;
    }
    if (race_index(self) == (int)tid) {
        return true;
    }
    return self->vc[tid] >= RACE_EPOCH_CLK(e);
}

static race_entry_t *
race_find(const void *addr, bool create, const char *name)
{
    size_t at = race_slot(addr);

    if (race_table[at].addr == addr) {
        return &race_table[at];
    }
    if (!create) {
        return nullptr;
    }
    // Evicting rather than probing: a shadow table that never forgets grows
    // without bound, and forgetting is the safe direction.
    race_table[at] = (race_entry_t){
        .addr  = addr,
        .name  = name,
        .state = RACE_VIRGIN,
    };
    return &race_table[at];
}

// The locks this thread holds, both chains. Read locks count: a field read
// under a read lock is protected against writers, which is what the read
// needed. A write under a read lock alone is not protected, and shows up as
// an empty intersection against the writers' exclusive set.
static uint8_t
race_held(void *out[N00B_RACE_LOCKS], bool *truncated)
{
    n00b_thread_t *self = n00b_thread_self();
    uint8_t        n    = 0;

    *truncated = false;
    if (self == nullptr || self->record == nullptr) {
        return 0;
    }
    n00b_thread_record_t *rec = self->record;

    n00b_lock_base_t *held = n00b_atomic_load(&rec->exclusive_locks);
    while (held != nullptr) {
        if (n == N00B_RACE_LOCKS) {
            *truncated = true;
            return n;
        }
        out[n++] = held;
        held     = n00b_atomic_load(&held->next_thread_lock);
    }

    n00b_thread_read_log_t *log = n00b_atomic_load(&rec->read_locks);
    while (log != nullptr) {
        if (log->obj != nullptr) {
            if (n == N00B_RACE_LOCKS) {
                *truncated = true;
                return n;
            }
            out[n++] = log->obj;
        }
        log = log->next_entry;
    }
    return n;
}

// Keep only the locks the entry and this access have in common.
static void
race_intersect(race_entry_t *e, void *held[], uint8_t held_n)
{
    uint8_t out = 0;

    for (uint8_t i = 0; i < e->lock_count; i++) {
        for (uint8_t j = 0; j < held_n; j++) {
            if (e->locks[i] == held[j]) {
                e->locks[out++] = e->locks[i];
                break;
            }
        }
    }
    e->lock_count = out;
}

static void
race_access(const void *addr, const char *name, bool writing)
{
    void          *held[N00B_RACE_LOCKS];
    bool           truncated = false;
    uint8_t        held_n    = race_held(held, &truncated);
    int64_t        tid       = n00b_os_thread_id();
    race_thread_t *self      = race_self();
    // Stamped into the cell on a write. Read before the stripe is taken
    // because only this thread writes its own clock.
    race_epoch_t   now       = self == nullptr
                                 ? RACE_EPOCH_NONE
                                 : RACE_EPOCH(race_index(self),
                                              self->vc[race_index(self)]);

    atomic_flag *stripe = race_stripe_for(addr);
    race_flag_lock(stripe);

    race_entry_t *e = race_find(addr, true, name);

    switch (e->state) {
    case RACE_LOCKFREE:
        race_flag_unlock(stripe);
        return;

    case RACE_VIRGIN:
        // First touch seeds the candidate set and the owner. Initialization
        // runs unlocked in almost every design, so reporting here would bury
        // every real finding. The epoch is still stamped: a second thread
        // arriving next has to be judged against this write, and leaving the
        // cell at "no epoch" would call that pair ordered whatever happened.
        e->state      = RACE_EXCLUSIVE;
        e->owner      = tid;
        e->name       = name;
        e->truncated  = truncated;
        e->lock_count = truncated ? 0 : held_n;
        for (uint8_t i = 0; i < e->lock_count; i++) {
            e->locks[i] = held[i];
        }
        if (writing) {
            e->last_write = now;
        }
        race_flag_unlock(stripe);
        return;

    case RACE_EXCLUSIVE:
        if (e->owner == tid) {
            if (writing) {
                e->last_write = now;
            }
            race_flag_unlock(stripe);
            return;
        }
        // A second thread. A read makes it shared, which is refined but never
        // reported: a field written once and then only read needs no lock.
        e->state = writing ? RACE_SHARED_MOD : RACE_SHARED;
        break;

    case RACE_SHARED:
        if (writing) {
            e->state = RACE_SHARED_MOD;
        }
        break;

    case RACE_SHARED_MOD:
        break;
    }

    if (truncated || e->truncated) {
        // Cannot represent one of the two sets, so refining would be guessing.
        e->truncated = true;
        race_flag_unlock(stripe);
        return;
    }

    race_intersect(e, held, held_n);

    // Both halves, or neither reports. An empty lockset on its own says only
    // that no lock orders these accesses; a pin drain, a thread join, or a
    // seal barrier orders them just as well, and lockset cannot see any of
    // them. Ordered accesses do not race however they were guarded.
    bool ordered = self == nullptr || race_happens_after(self, e->last_write);

    if (writing && self != nullptr) {
        e->last_write = now;
    }

    if (e->state == RACE_SHARED_MOD && e->lock_count == 0 && !ordered) {
        atomic_fetch_add_explicit(&race_report_count, 1, memory_order_relaxed);
        // Reported once per location. A racing field is usually racing on a
        // hot path, and the second report says nothing the first did not.
        e->state = RACE_LOCKFREE;
        race_flag_unlock(stripe);

        fprintf(stderr,
                "n00b race: '%s' at %p accessed by thread %lld with no lock "
                "in common with earlier accesses (%s).\n"
                "  Either guard every access with one lock, or annotate it "
                "with n00b_race_lockfree if it is correct without one.\n",
                name ? name : "<unnamed>",
                addr,
                (long long)tid,
                writing ? "write" : "read");
        return;
    }

    race_flag_unlock(stripe);
}

// A release edge: everything this thread has done becomes visible to whoever
// acquires the same object next. Called from lock release, from thread fork,
// and by hand for the orderings that are not locks.
void
n00b_race_release_edge(const void *obj)
{
    race_thread_t *self = race_self();

    if (self == nullptr || obj == nullptr) {
        return;
    }

    size_t       slot = race_lock_slot(obj);
    atomic_flag *g    = race_lock_stripe_for(slot);

    race_flag_lock(g);
    race_lock_t *l = &race_locks[slot];
    if (l->obj != obj) {
        *l = (race_lock_t){.obj = obj};
    }
    for (int i = 0; i < N00B_RACE_THREADS; i++) {
        if (self->vc[i] > l->vc[i]) {
            l->vc[i] = self->vc[i];
        }
    }
    race_flag_unlock(g);

    // Past this point is a new epoch, so a later access by this thread is not
    // covered by the edge it just published. Outside the stripe: this word is
    // written by no other thread.
    self->vc[race_index(self)]++;
}

// The matching acquire: take on everything the last releaser had done.
void
n00b_race_acquire_edge(const void *obj)
{
    race_thread_t *self = race_self();

    if (self == nullptr || obj == nullptr) {
        return;
    }

    size_t       slot = race_lock_slot(obj);
    atomic_flag *g    = race_lock_stripe_for(slot);

    race_flag_lock(g);
    race_lock_t *l = &race_locks[slot];
    if (l->obj == obj) {
        for (int i = 0; i < N00B_RACE_THREADS; i++) {
            if (l->vc[i] > self->vc[i]) {
                self->vc[i] = l->vc[i];
            }
        }
    }
    race_flag_unlock(g);
}

void
n00b_race_read(const void *addr, const char *name)
{
    race_access(addr, name, false);
}

void
n00b_race_write(const void *addr, const char *name)
{
    race_access(addr, name, true);
}

void
n00b_race_lockfree(const void *addr)
{
    atomic_flag *stripe = race_stripe_for(addr);
    race_flag_lock(stripe);
    race_entry_t *e = race_find(addr, true, "<lock-free>");
    e->state        = RACE_LOCKFREE;
    race_flag_unlock(stripe);
}

void
n00b_race_scrub_range(uint64_t lo, uint64_t hi)
{
    // Every stripe, because a range spans them all. Rare enough that the
    // sweep does not matter.
    for (int k = 0; k < N00B_RACE_STRIPES; k++) {
        race_flag_lock(&race_stripe[k]);
    }
    for (size_t i = 0; i < N00B_RACE_SLOTS; i++) {
        uint64_t a = (uint64_t)(uintptr_t)race_table[i].addr;
        if (a >= lo && a < hi) {
            race_table[i] = (race_entry_t){};
        }
    }
    for (int k = N00B_RACE_STRIPES - 1; k >= 0; k--) {
        race_flag_unlock(&race_stripe[k]);
    }

    // Published clocks are keyed the same way, so an object freed out of this
    // range would hand its ordering to whatever the allocator puts there next.
    for (int k = 0; k < N00B_RACE_STRIPES; k++) {
        race_flag_lock(&race_lock_stripe[k]);
    }
    for (size_t i = 0; i < N00B_RACE_LOCK_SLOTS; i++) {
        uint64_t a = (uint64_t)(uintptr_t)race_locks[i].obj;
        if (a >= lo && a < hi) {
            race_locks[i].obj = nullptr;
        }
    }
    for (int k = N00B_RACE_STRIPES - 1; k >= 0; k--) {
        race_flag_unlock(&race_lock_stripe[k]);
    }
}

uint64_t
n00b_race_reports(void)
{
    return atomic_load_explicit(&race_report_count, memory_order_relaxed);
}

#endif

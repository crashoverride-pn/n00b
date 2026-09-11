/*
 * Shared synchronization policy for the two hash tables (src/adt/dict.c and
 * src/adt/dict_untyped.c).
 *
 * Both tables use the same scheme: a per-bucket flag word carrying MUTEX,
 * COPYING and MOVING, plus a dict-wide `_migration_state` word whose top bit
 * says a migrator currently owns the table. Every wait, bound, backoff and
 * repair decision that scheme needs lives here, so the two tables cannot
 * drift apart (n00b-lang/n00b#365 found the untyped reader had a bound the
 * typed one lacked, and neither had one on the path that actually wedged).
 *
 * Internal API: only the dict implementations and their tests include this.
 */
#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "n00b.h"
#include "core/atomic.h"
#include "core/platform.h"

#ifdef N00B_USE_INTERNAL_API

// Per-bucket flags. Identical to the definitions in adt/dict.h and
// adt/dict_untyped.h (identical redefinition is permitted).
#define N00B_HT_FLAG_MUTEX   1
#define N00B_HT_FLAG_COPYING 2
#define N00B_HT_FLAG_DELETED 4
#define N00B_HT_FLAG_MOVING  8

// The bits a migrator ORs onto every bucket of the store it is copying.
#define N00B_HT_FLAGS_MIGRATING (N00B_HT_FLAG_COPYING | N00B_HT_FLAG_MOVING)

// Top bit of `_migration_state`: set for exactly as long as one thread owns
// the migration of this dict. Every COPYING/MOVING bit on a live store is
// backed by this bit; a migrator raises it BEFORE touching any bucket and
// lowers it only after publishing the new store or clearing the bits again.
#define N00B_DICT_MIGRATION_ACTIVE (1U << 31)

static inline bool
n00b_dict_migration_active(volatile n00b_futex_t *migration_state)
{
    return (n00b_atomic_load(migration_state) & N00B_DICT_MIGRATION_ACTIVE) != 0;
}

// ---------------------------------------------------------------------------
// Reader-side bucket MUTEX wait.
//
// A live holder releases within a few instructions, so a MUTEX that stays set
// for the whole time gate is treated as likely stranded; without a bound each
// waiter pins a core indefinitely. Past the spin threshold the waiter starts a
// clock (the threshold keeps clock reads off the fast path); past the gate it
// sleeps between retries and emits one diagnostic. The wait itself is never
// abandoned: returning early would report a present key as absent while a
// holder still owns the bucket. The gate must stay far above any legitimate
// losing streak under write contention -- sleeping on a merely-contended
// bucket collapses writer throughput.
// ---------------------------------------------------------------------------
#define N00B_DICT_READER_SPIN_THRESHOLD (1ULL << 20)
#define N00B_DICT_READER_CLOCK_MASK     0x3ff

extern _Atomic uint64_t n00b_dict_reader_strand_gate_ns;

/** @brief Slow path of the reader wait: count, warn once, sleep a millisecond. */
extern void n00b_dict_reader_strand_backoff(void);

// Called on every losing iteration of a bucket-MUTEX wait.
static inline void
n00b_dict_reader_wait_tick(uint64_t *spins, uint64_t *wait_start_ns)
{
    if (++*spins < N00B_DICT_READER_SPIN_THRESHOLD
        || (*spins & N00B_DICT_READER_CLOCK_MASK) != 0) {
        return;
    }
    uint64_t now = base_monotonic_ns();
    if (*wait_start_ns == 0) {
        *wait_start_ns = now;
        return;
    }
    uint64_t gate
        = atomic_load_explicit(&n00b_dict_reader_strand_gate_ns, memory_order_relaxed);
    if (now - *wait_start_ns >= gate) {
        n00b_dict_reader_strand_backoff();
    }
}

// ---------------------------------------------------------------------------
// Reader-side stranded COPYING/MOVING repair (n00b-lang/n00b#365).
//
// A reader that ORs MUTEX onto a bucket and sees COPYING/MOVING in the
// pre-OR value normally releases MUTEX and parks on `_migration_state` until
// the migrator is done. That is only right while a migrator actually owns the
// dict. If the bits outlive their migrator (MIGRATION_ACTIVE clear, store
// unchanged), the park returns instantly, the reader reloads the same store,
// sees the same bit, and spins at full CPU forever -- sixteen threads did
// exactly that for hours in the #365 capture.
//
// The caller decides the bit is stranded by checking, in this order, that
// MIGRATION_ACTIVE is clear and that the store it is probing is still the
// current one (a migrator publishes its new store before clearing the word,
// so a clear word followed by an unchanged store means no migration completed
// against, or is running against, this store). It then calls this holding
// MUTEX, and may proceed with the bucket afterwards.
//
// The strip is safe because the caller holds MUTEX: a migrator that starts
// now raises MIGRATION_ACTIVE, ORs the buckets, sees our MUTEX and waits for
// us. The only hazard is its OR landing BEFORE our strip (a no-op on an
// already-set bit, which our strip then removes), which is why we re-check
// the word after stripping and put the bits back if a migrator has appeared.
// It has not copied anything yet -- it is waiting on the MUTEX we hold -- so
// restoring recreates exactly the state it intended.
// ---------------------------------------------------------------------------

/** @brief Count and one-shot diagnostic for a repaired strand. */
extern void n00b_dict_stranded_flags_repaired(void);

static inline void
n00b_dict_stranded_flags_repair(_Atomic uint32_t *flags, volatile n00b_futex_t *migration_state)
{
    n00b_atomic_and(flags, ~(uint32_t)N00B_HT_FLAGS_MIGRATING);
    if (n00b_dict_migration_active(migration_state)) {
        n00b_atomic_or(flags, (uint32_t)N00B_HT_FLAGS_MIGRATING);
    }
    n00b_dict_stranded_flags_repaired();
}

// ---------------------------------------------------------------------------
// Migrator-side drain wait (n00b-lang/n00b#221, #360).
//
// Once a migrator has OR'd COPYING/MOVING onto every bucket it must wait for
// the in-flight bucket MUTEX holders it recorded to release, because it cannot
// copy a bucket somebody is still writing. While it waits, MIGRATION_ACTIVE is
// set and every other thread that touches the dict is parked, so this wait is
// the whole dict's latency.
//
// A real holder releases within a few instructions, so the wait starts as a
// tight spin: a sleep on the common path measurably slowed
// rocs_async_seal_stress. Past the spin threshold the spin has failed, and
// two things change:
//
//  * it yields between polls. #360 caught the holder RUNNABLE BUT NEVER
//    SCHEDULED under core saturation: the spinning migrator (and the readers
//    it parked) consumed the cores the holder needed for its few instructions.
//    A non-yielding spin keeps that true; sleeping breaks it.
//
//  * it is bounded by ONE wall-clock gate across all recorded buckets, not an
//    iteration count per bucket. #360 found the per-bucket 2^32 budget was
//    hours on a wide table and had never fired in the field.
//
// Past the gate the migrator abandons: it clears the bits it set and lowers
// MIGRATION_ACTIVE, leaving the table oversized but live. Abandoning is only
// safe because the writers treat it as "insert into the oversized store", not
// "retry the resize" (see n00b-lang/n00b#358).
// ---------------------------------------------------------------------------
#define N00B_DICT_MIGRATE_SPIN_THRESHOLD (1ULL << 16)
#define N00B_DICT_MIGRATE_YIELD_NS       (100ULL * 1000)

extern _Atomic uint64_t n00b_dict_migrate_abandon_gate_ns;

// Called on every losing iteration of the drain wait. Returns false once the
// gate has elapsed, at which point the caller abandons the migration.
static inline bool
n00b_dict_migrate_wait_tick(uint64_t *spins, uint64_t *wait_start_ns)
{
    if (++*spins < N00B_DICT_MIGRATE_SPIN_THRESHOLD) {
        return true;
    }
    uint64_t now = base_monotonic_ns();
    if (*wait_start_ns == 0) {
        *wait_start_ns = now;
        return true;
    }
    uint64_t gate
        = atomic_load_explicit(&n00b_dict_migrate_abandon_gate_ns, memory_order_relaxed);
    if (now - *wait_start_ns >= gate) {
        return false;
    }
    base_nanosleep_ns(N00B_DICT_MIGRATE_YIELD_NS);
    return true;
}

/** @brief Count and one-shot diagnostic for an abandoned migration. */
extern void n00b_dict_migration_abandoned(void);

// ---------------------------------------------------------------------------
// Stopped-world migration (n00b-lang/n00b#272).
//
// While the world is stopped the collector is the sole running thread, so it
// must never wait on a bucket MUTEX or a migration owned by another thread:
// the owner is suspended and cannot release. The acquire helpers already
// short-circuit to a lockless scan under STW; the migrator's two waits did
// not, and a resize of the collector's memo dict inside a collection could
// park on a suspended mutator forever. Under STW the migrator therefore
// waits on nothing. Finding anything to wait on means the collector is
// resizing a dict a suspended mutator is inside, which no collector-side
// dict should ever be; it is counted and reported once, and the migration
// proceeds (the alternative, waiting, is the #272 deadlock).
// ---------------------------------------------------------------------------

/** @brief Count and one-shot diagnostic for the collector finding a
 *  suspended mutator inside a dict it is resizing. */
extern void n00b_dict_stw_contention(void);

/** @brief Count and one-shot diagnostic for an insert refused because the
 *  store was full and its one resize attempt did not run. A put has no way
 *  to report this to its caller (nullptr is also "newly inserted"), so this
 *  is the only signal the field gets. */
extern void n00b_dict_insert_dropped(void);

// ---------------------------------------------------------------------------
// Test hooks. Production code must not call the setters. Counters are never
// reset; a test needing a clean count must run in a fresh process or diff.
// ---------------------------------------------------------------------------
extern void     n00b_dict_reader_strand_gate_set(uint64_t ns);
extern uint64_t n00b_dict_reader_backoff_count_get(void);
extern void     n00b_dict_migrate_abandon_gate_set(uint64_t ns);
extern uint64_t n00b_dict_migrate_abandon_count_get(void);
extern uint64_t n00b_dict_stranded_flags_repair_count_get(void);
extern uint64_t n00b_dict_stw_contention_count_get(void);
extern uint64_t n00b_dict_insert_dropped_count_get(void);

#endif // N00B_USE_INTERNAL_API

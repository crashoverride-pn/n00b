/*
 * Slow paths, counters and diagnostics behind include/adt/dict_sync.h. The
 * inline fast paths live in the header; everything here is off the hot path.
 */

#define N00B_USE_INTERNAL_API
#include <stdatomic.h>

#include "n00b.h"
#include "core/syscall.h"
#include "core/time.h"
#include "adt/dict_sync.h"

// Gates default to a second: far above any legitimate hold of a bucket MUTEX
// (a few instructions), and the value the field captures in #221/#360/#365
// were all measured in hours.
_Atomic uint64_t n00b_dict_reader_strand_gate_ns   = 1000000000ULL;
_Atomic uint64_t n00b_dict_migrate_abandon_gate_ns = 1000000000ULL;

static _Atomic uint64_t reader_backoff_count        = 0;
static _Atomic uint64_t migrate_abandon_count       = 0;
static _Atomic uint64_t stranded_flags_repair_count = 0;
static _Atomic uint64_t stw_contention_count        = 0;
static _Atomic uint64_t insert_dropped_count        = 0;

static _Atomic bool reader_strand_warned   = false;
static _Atomic bool migrate_abandon_warned = false;
static _Atomic bool stranded_flags_warned  = false;
static _Atomic bool stw_contention_warned  = false;
static _Atomic bool insert_dropped_warned  = false;

// Diagnostics go out raw: these paths can run with the world stopped or from
// a TLS-free worker, where stdio is not safe. Each fires once per process.
static inline void
warn_once(_Atomic bool *warned, const char *m, size_t len)
{
    if (!atomic_exchange(warned, true)) {
        n00b_raw_write(2, m, len);
    }
}

#define WARN_ONCE(flag, msg) warn_once(&(flag), msg, sizeof(msg) - 1)

void
n00b_dict_reader_strand_backoff(void)
{
    atomic_fetch_add_explicit(&reader_backoff_count, 1, memory_order_relaxed);
    WARN_ONCE(reader_strand_warned,
              "n00b_dict: a bucket mutex stayed held past the reader wait gate; "
              "treating it as stranded and sleeping between retries instead of "
              "spinning\n");
    base_nanosleep_ns(N00B_NS_PER_MS);
}

void
n00b_dict_stranded_flags_repaired(void)
{
    atomic_fetch_add_explicit(&stranded_flags_repair_count, 1, memory_order_relaxed);
    WARN_ONCE(stranded_flags_warned,
              "n00b_dict: a bucket carried COPYING/MOVING with no migration in "
              "progress; cleared the stranded bits and continued\n");
}

void
n00b_dict_migration_abandoned(void)
{
    atomic_fetch_add_explicit(&migrate_abandon_count, 1, memory_order_relaxed);
    WARN_ONCE(migrate_abandon_warned,
              "n00b_dict: a bucket mutex stayed held for the whole migration "
              "wait gate; abandoning the resize and leaving the table "
              "oversized\n");
}

void
n00b_dict_stw_contention(void)
{
    atomic_fetch_add_explicit(&stw_contention_count, 1, memory_order_relaxed);
    WARN_ONCE(stw_contention_warned,
              "n00b_dict: the collector resized a dict a suspended thread was "
              "inside; not waiting on it\n");
}

void
n00b_dict_insert_dropped(void)
{
    atomic_fetch_add_explicit(&insert_dropped_count, 1, memory_order_relaxed);
    WARN_ONCE(insert_dropped_warned,
              "n00b_dict: an insert was refused: the store is full and its "
              "resize could not run\n");
}

// ---------------------------------------------------------------------------
// Test hooks.
// ---------------------------------------------------------------------------

void
n00b_dict_reader_strand_gate_set(uint64_t ns)
{
    atomic_store_explicit(&n00b_dict_reader_strand_gate_ns, ns, memory_order_relaxed);
}

uint64_t
n00b_dict_reader_backoff_count_get(void)
{
    return atomic_load_explicit(&reader_backoff_count, memory_order_relaxed);
}

void
n00b_dict_migrate_abandon_gate_set(uint64_t ns)
{
    atomic_store_explicit(&n00b_dict_migrate_abandon_gate_ns, ns, memory_order_relaxed);
}

uint64_t
n00b_dict_migrate_abandon_count_get(void)
{
    return atomic_load_explicit(&migrate_abandon_count, memory_order_relaxed);
}

uint64_t
n00b_dict_stranded_flags_repair_count_get(void)
{
    return atomic_load_explicit(&stranded_flags_repair_count, memory_order_relaxed);
}

uint64_t
n00b_dict_stw_contention_count_get(void)
{
    return atomic_load_explicit(&stw_contention_count, memory_order_relaxed);
}

uint64_t
n00b_dict_insert_dropped_count_get(void)
{
    return atomic_load_explicit(&insert_dropped_count, memory_order_relaxed);
}

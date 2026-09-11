/*
 * What the untyped dict does when a migration cannot run cleanly.
 *
 * Three field outages on the same table (n00b-lang/n00b#221, #360, #365) all
 * came down to a wait with no bound, or a bound that could not fire, on one
 * of the dict's two synchronization words. These pin the policy now shared by
 * both dict implementations through adt/dict_sync.h:
 *
 *  - the migrator's drain wait is bounded by ONE wall-clock gate for the whole
 *    table (#360), and abandoning is reported to the writer so it lands in the
 *    oversized store instead of retrying the resize forever (#358);
 *
 *  - a reader that finds COPYING/MOVING on a bucket with no migration in
 *    progress repairs the bucket and proceeds instead of spinning (#365);
 *
 *  - with the world stopped the migrator waits on nothing (#272).
 *
 * Hashing is supplied by the test rather than left to n00b_hash_word, because
 * which bucket a key lands in is the whole setup. A probe locks every bucket
 * it walks past, so a probe that reached a stranded bucket would spin there
 * forever and the test would hang on the wrong thing entirely.
 */
#include <stdio.h>
#include <assert.h>

#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/time.h"
#include "adt/dict_untyped.h"
#include "adt/dict_sync.h"

// Far enough below the real (1s) gate to run in a suite, far enough above a
// real hand-off that a scheduler cannot reach it by accident.
#define TEST_GATE_NS (20ULL * N00B_NS_PER_MS)

// How long an abandon is allowed to take end to end. Generous for a loaded CI
// box, but still orders of magnitude under the old per-bucket 2^32 spin.
#define ABANDON_DEADLINE_NS (2ULL * 1000 * N00B_NS_PER_MS)

// Key k lands in bucket k. Low 32 bits are nonzero for every k used here,
// which is what bucket_reserved() reads.
static n00b_hash_value_t
bucket_is_the_key(void *key)
{
    return (n00b_hash_value_t)(uintptr_t)key;
}

// The store's own numbers, not constants: N00B_DICT_MIN_SIZE_LOG is a build
// option, and the resize threshold is derived from whatever it came out as.
typedef struct {
    uint64_t capacity;
    uint64_t threshold;
    // The bucket left stranded, and the last key used. Keys run 1..last_key
    // and land in the bucket of the same number, so no probe reaches the
    // strand -- a probe locks every bucket it walks past, and one that reached
    // a stranded bucket would spin there instead of exercising the migration.
    uint32_t stranded;
    uint64_t last_key;
} layout_t;

static layout_t
init_dict(n00b_dict_untyped_t *d)
{
    n00b_dict_untyped_init(d,
                           .hash          = bucket_is_the_key,
                           .skip_obj_hash = true,
                           .locked        = true);

    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d->store);
    layout_t                   out   = {
                          .capacity  = (uint64_t)store->last_slot + 1,
                          .threshold = store->threshold,
                          .stranded  = store->last_slot,
                          .last_key  = (uint64_t)store->last_slot - 1,
    };

    // The fill below has to cross the threshold before it runs out of keys.
    assert(out.threshold <= out.last_key);
    // Keys `capacity - 1` and `capacity` home on the last bucket and bucket 0
    // respectively; the full-store tests use them to fill every slot.
    assert(out.capacity >= 8);
    return out;
}

static void
set_bucket_flags(n00b_dict_untyped_t *d, uint32_t at, uint32_t bits)
{
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d->store);
    n00b_atomic_or(&store->buckets[at].flags, bits);
}

static void
strand_bucket(n00b_dict_untyped_t *d, uint32_t at)
{
    set_bucket_flags(d, at, N00B_HT_FLAG_MUTEX);
}

static uint32_t
bucket_flags(n00b_dict_untyped_t *d, uint32_t at)
{
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d->store);
    return n00b_atomic_load(&store->buckets[at].flags);
}

static void
fill(n00b_dict_untyped_t *d, uint64_t first, uint64_t last)
{
    for (uint64_t k = first; k <= last; k++) {
        uint64_t v = 1000 + k;
        assert(n00b_dict_untyped_add(d, k, v));
    }
}

static void
check_all_readable(n00b_dict_untyped_t *d, uint64_t last)
{
    for (uint64_t k = 1; k <= last; k++) {
        bool     found = false;
        void    *got   = n00b_dict_untyped_get(d, k, &found);
        uint64_t want  = 1000 + k;
        assert(found);
        assert((uint64_t)(uintptr_t)got == want);
    }
}

// ---------------------------------------------------------------------------
// Migration gives up, and the writers cope (#221 / #358 / #360).
// ---------------------------------------------------------------------------

// The abandon path itself, taken directly.
//
// A give-up has to be distinguishable from losing the race for the migration:
// losing means the store changes and a writer should look again, abandoning
// means it does not. Both return false, so the difference is the out-param,
// and a writer that could not see it is the livelock #358 exists for.
static void
test_lock_reports_abandonment(void)
{
    n00b_dict_untyped_t d;
    layout_t            l    = init_dict(&d);
    uint64_t            seed = 1001;
    assert(n00b_dict_untyped_add(&d, 1, seed));

    n00b_dict_untyped_store_t *before = n00b_atomic_load(&d.store);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_abandon_gate_set(TEST_GATE_NS);

    uint64_t abandons = n00b_dict_migrate_abandon_count_get();
    uint32_t count     = 0;
    bool     abandoned = false;
    uint64_t t0        = base_monotonic_ns();
    assert(!n00b_dict_untyped_lock(&d, &count, &abandoned, false));
    uint64_t elapsed = base_monotonic_ns() - t0;
    assert(abandoned);
    assert(n00b_dict_migrate_abandon_count_get() == abandons + 1);

    // It waited the gate -- not less, or a merely slow holder would lose its
    // resize -- and not the old iteration budget, which is seconds per bucket.
    assert(elapsed >= TEST_GATE_NS);
    assert(elapsed < ABANDON_DEADLINE_NS);

    // The migration bit is back down, so nothing is parked behind a migration
    // that is not happening.
    assert(n00b_atomic_load(&d._migration_state) == 0);

    // And the bits the walk set are off again, so a reader does not keep
    // taking the try_again path against a store nobody is migrating. Only the
    // strand is left, which is not ours to clear.
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d.store);
    for (uint32_t i = 0; i <= store->last_slot; i++) {
        uint32_t flags = n00b_atomic_load(&store->buckets[i].flags);
        assert(!(flags & N00B_HT_FLAGS_MIGRATING));
        assert((flags & N00B_HT_FLAG_MUTEX) == (i == l.stranded
                                                    ? N00B_HT_FLAG_MUTEX
                                                    : 0u));
    }
    assert(n00b_atomic_load(&d.store) == before);

    printf("  [PASS] lock_reports_abandonment\n");
}

// The drain wait's bound is one gate for the whole table (#360).
//
// The old bound was an iteration count declared inside the per-bucket loop,
// so it reset for every bucket in the active range: two stranded buckets at
// opposite ends of the table meant two full budgets, and on a wide table the
// budget was hours. Strand both ends and check the whole abandon still fits
// in about one gate.
static void
test_abandon_gate_is_total_not_per_bucket(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    // Bucket 0 is never a key's home (key 0 would read as unreserved), and
    // the last bucket is the usual strand: together they make the recorded
    // active range the entire table.
    strand_bucket(&d, 0);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_abandon_gate_set(TEST_GATE_NS);

    uint32_t count     = 0;
    bool     abandoned = false;
    uint64_t t0        = base_monotonic_ns();
    assert(!n00b_dict_untyped_lock(&d, &count, &abandoned, false));
    uint64_t elapsed = base_monotonic_ns() - t0;
    assert(abandoned);
    assert(elapsed >= TEST_GATE_NS);
    assert(elapsed < ABANDON_DEADLINE_NS);

    printf("  [PASS] abandon_gate_is_total_not_per_bucket\n");
}

// Writes past the threshold with the migration abandoned.
//
// Before #358 this did not return: each insert past the threshold spun the
// bound, abandoned, found the same store still over its threshold, and
// started over. There is no assertion that catches that, which is why the
// test is shaped as "does this terminate" and run with a small gate rather
// than as a count of anything.
static void
test_writes_terminate_with_migration_abandoned(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);

    // Below the threshold first, so the strand goes in with the dict healthy.
    fill(&d, 1, l.threshold - 1);

    n00b_dict_untyped_store_t *before = n00b_atomic_load(&d.store);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_abandon_gate_set(TEST_GATE_NS);

    // Each of these crosses the threshold and asks for a resize that cannot
    // happen.
    fill(&d, l.threshold, l.last_key);

    // No migration ran, and every key is still there: abandoning leaves the
    // store oversized, not damaged.
    assert(n00b_atomic_load(&d.store) == before);
    check_all_readable(&d, l.last_key);

    printf("  [PASS] writes_terminate_with_migration_abandoned\n");
}

// The reservation a writer takes before asking for a migration has to come
// back when the migration is abandoned.
//
// used_count is what the threshold is read against, so a reservation left on a
// store that survives pushes it further over on every attempt. Nothing
// observable changes as a result, which is the reason to assert on the counter
// rather than on a query.
static void
test_abandoned_migration_leaks_no_reservation(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d.store);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_abandon_gate_set(TEST_GATE_NS);

    fill(&d, l.threshold, l.last_key);

    assert(n00b_atomic_load(&d.store) == store);

    // One slot per key that landed, and nothing for the attempts that were
    // refused a resize. An uncorrected reservation shows up here as a count
    // above the number of keys in the table.
    assert(n00b_atomic_load(&store->used_count) == l.last_key);

    printf("  [PASS] abandoned_migration_leaks_no_reservation\n");
}

// A dict whose migrations run is untouched by any of this: the same fill with
// nothing stranded resizes and keeps every key.
static void
test_unstranded_dict_still_migrates(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);

    uint64_t count = l.capacity * 4;
    fill(&d, 1, count);

    assert((uint64_t)n00b_atomic_load(&d.store)->last_slot + 1 > l.capacity);
    check_all_readable(&d, count);

    printf("  [PASS] unstranded_dict_still_migrates\n");
}

// ---------------------------------------------------------------------------
// A store that filled up while its resize could not run.
//
// Abandoning lets writes land in the oversized store, so it can fill to the
// last slot. Once full, acquire-or-add returns nullptr for any new key. That
// path used to be a bare failure, which made the fullness permanent: even
// after the mutex that blocked the resize had cleared, no later insert ever
// asked for one again. Each insert now gets one bounded resize attempt there.
// ---------------------------------------------------------------------------

// The realistic shape: a writer holds a bucket it owns (an existing key) for
// a long time; resizes abandon; the table fills; the writer finishes. The
// next new key must grow the table, not be refused.
static void
test_full_store_recovers_once_the_holder_releases(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    uint64_t held = l.threshold / 2; // reserved bucket, off every home path
    assert(held >= 1);
    strand_bucket(&d, (uint32_t)held);
    n00b_dict_migrate_abandon_gate_set(TEST_GATE_NS);

    // Every remaining slot has a key whose HOME it is, so no probe crosses
    // the held bucket: 1..last_slot directly, and `capacity` for bucket 0.
    fill(&d, l.threshold, l.capacity - 1);
    uint64_t v0 = 1000 + l.capacity;
    assert(n00b_dict_untyped_add(&d, l.capacity, v0));

    n00b_dict_untyped_store_t *full = n00b_atomic_load(&d.store);
    assert(full->last_slot + 1 == l.capacity);
    for (uint32_t i = 0; i <= full->last_slot; i++) {
        assert(full->buckets[i].hv != 0);
    }

    // The holder finishes.
    n00b_atomic_and(&full->buckets[held].flags, ~(uint32_t)N00B_HT_FLAG_MUTEX);

    // A new key whose home is taken probes the whole table, finds nothing,
    // and must resize rather than fail.
    uint64_t abandons = n00b_dict_migrate_abandon_count_get();
    uint64_t dropped  = n00b_dict_insert_dropped_count_get();
    uint64_t k        = l.capacity + 1;
    uint64_t v        = 1000 + k;
    assert(n00b_dict_untyped_add(&d, k, v));
    assert(n00b_atomic_load(&d.store) != full);
    assert(n00b_atomic_load(&d.store)->last_slot + 1 > l.capacity);
    assert(n00b_dict_migrate_abandon_count_get() == abandons);
    assert(n00b_dict_insert_dropped_count_get() == dropped);

    // Nothing lost across the recovery, including bucket 0 and the held key.
    check_all_readable(&d, l.capacity + 1);

    printf("  [PASS] full_store_recovers_once_the_holder_releases\n");
}

// Same shape through put and cas, which have their own copies of the path.
static void
test_full_store_recovers_via_put_and_cas(void)
{
    for (int which = 0; which < 2; which++) {
        n00b_dict_untyped_t d;
        layout_t            l = init_dict(&d);
        fill(&d, 1, l.threshold - 1);

        uint64_t held = l.threshold / 2;
        strand_bucket(&d, (uint32_t)held);
        n00b_dict_migrate_abandon_gate_set(TEST_GATE_NS);
        fill(&d, l.threshold, l.capacity - 1);
        uint64_t v0 = 1000 + l.capacity;
        assert(n00b_dict_untyped_add(&d, l.capacity, v0));
        n00b_dict_untyped_store_t *full = n00b_atomic_load(&d.store);
        n00b_atomic_and(&full->buckets[held].flags, ~(uint32_t)N00B_HT_FLAG_MUTEX);

        uint64_t k = l.capacity + 1;
        uint64_t v = 1000 + k;
        if (which == 0) {
            void *prev = n00b_dict_untyped_put(&d, k, v);
            assert(prev == nullptr);
        }
        else {
            assert(n00b_dict_untyped_cas(&d, k, 0, v, .null_old_means_absence = true));
        }
        assert(n00b_atomic_load(&d.store) != full);
        check_all_readable(&d, l.capacity + 1);
    }
    printf("  [PASS] full_store_recovers_via_put_and_cas\n");
}

// When the resize STILL cannot run, the refusal is bounded (one attempt per
// call, no spin) and counted, and the very next call after the blocker
// clears succeeds. Modelled under STW with the migration word held by a
// phantom owner, the one blocker a full-table probe cannot itself wedge on.
static void
test_full_store_refusal_is_bounded_and_counted(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    n00b_atomic_or(&d._migration_state, N00B_DICT_MIGRATION_ACTIVE);

    n00b_stop_the_world();
    fill(&d, l.threshold, l.capacity - 1);
    uint64_t v0 = 1000 + l.capacity;
    assert(n00b_dict_untyped_add(&d, l.capacity, v0)); // bucket 0: table full
    n00b_dict_untyped_store_t *full = n00b_atomic_load(&d.store);

    uint64_t dropped    = n00b_dict_insert_dropped_count_get();
    uint64_t contention = n00b_dict_stw_contention_count_get();
    uint64_t k          = l.capacity + 1;
    uint64_t v          = 1000 + k;
    uint64_t t0         = base_monotonic_ns();
    assert(!n00b_dict_untyped_add(&d, k, v));
    uint64_t elapsed = base_monotonic_ns() - t0;
    assert(elapsed < 500ULL * N00B_NS_PER_MS);
    assert(n00b_dict_insert_dropped_count_get() == dropped + 1);
    assert(n00b_dict_stw_contention_count_get() == contention + 1); // ONE attempt
    assert(n00b_atomic_load(&d.store) == full);

    // Blocker gone: the next call resizes and lands, still under STW.
    atomic_store(&d._migration_state, 0);
    assert(n00b_dict_untyped_add(&d, k, v));
    n00b_restart_the_world();

    assert(n00b_atomic_load(&d.store) != full);
    check_all_readable(&d, l.capacity + 1);

    printf("  [PASS] full_store_refusal_is_bounded_and_counted\n");
}

// ---------------------------------------------------------------------------
// COPYING/MOVING with no migration behind it (#365).
//
// The #365 capture: sixteen threads in n00b_acquire_if_present, each seeing
// MOVING on its bucket, parking on a _migration_state that was already zero
// (so the park returned at once), reloading the same store and going round
// again, at full CPU, for hours. Nothing was migrating. These reproduce that
// state directly -- the bits set by hand, the migration word left clear --
// and check the reader repairs the bucket and finishes. Before the fix both
// cases run until the harness timeout.
// ---------------------------------------------------------------------------

static void
test_get_repairs_stranded_moving_flag(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    uint64_t key = l.threshold / 2;
    assert(key >= 1);
    set_bucket_flags(&d, (uint32_t)key, N00B_HT_FLAGS_MIGRATING);
    assert(n00b_atomic_load(&d._migration_state) == 0);

    uint64_t repairs = n00b_dict_stranded_flags_repair_count_get();
    bool     found   = false;
    void    *got     = n00b_dict_untyped_get(&d, key, &found);
    assert(found);
    assert((uint64_t)(uintptr_t)got == 1000 + key);

    // The bucket is clean again and the reader released it.
    assert(bucket_flags(&d, (uint32_t)key) == 0);
    assert(n00b_dict_stranded_flags_repair_count_get() == repairs + 1);

    // A second read goes through the ordinary path: no further repair.
    got = n00b_dict_untyped_get(&d, key, &found);
    assert(found && (uint64_t)(uintptr_t)got == 1000 + key);
    assert(n00b_dict_stranded_flags_repair_count_get() == repairs + 1);

    printf("  [PASS] get_repairs_stranded_moving_flag\n");
}

// Same state, other helper: a writer's acquire-or-add keys off COPYING rather
// than MOVING, and the home bucket here is EMPTY (the insert has not happened
// yet), which is the shape the stw scan and the writers see.
static void
test_add_repairs_stranded_copying_flag(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold / 2);

    uint64_t key = l.threshold - 1; // empty home bucket, under threshold
    assert(key > l.threshold / 2);
    set_bucket_flags(&d, (uint32_t)key, N00B_HT_FLAGS_MIGRATING);

    uint64_t repairs = n00b_dict_stranded_flags_repair_count_get();
    uint64_t v       = 1000 + key;
    assert(n00b_dict_untyped_add(&d, key, v));
    assert(bucket_flags(&d, (uint32_t)key) == 0);
    assert(n00b_dict_stranded_flags_repair_count_get() == repairs + 1);

    bool  found = false;
    void *got   = n00b_dict_untyped_get(&d, key, &found);
    assert(found && (uint64_t)(uintptr_t)got == v);

    printf("  [PASS] add_repairs_stranded_copying_flag\n");
}

// A stranded bit must not be mistaken for a live migration's, and a live
// migration's must not be mistaken for a strand: raise the migration word by
// hand alongside the bits and the reader has to park, not repair. Parking is
// unobservable from one thread except by never returning, so check from the
// other side: with the word raised, a reader that is NOT on a flagged bucket
// still completes (the bits are per bucket), and once the word is lowered
// again the flagged bucket is repaired on first touch, not before.
static void
test_live_migration_bits_are_not_repaired(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    uint64_t flagged = l.threshold / 2;
    uint64_t other   = flagged + 1;
    set_bucket_flags(&d, (uint32_t)flagged, N00B_HT_FLAGS_MIGRATING);
    n00b_atomic_or(&d._migration_state, N00B_DICT_MIGRATION_ACTIVE);

    uint64_t repairs = n00b_dict_stranded_flags_repair_count_get();
    bool     found   = false;
    void    *got     = n00b_dict_untyped_get(&d, other, &found);
    assert(found && (uint64_t)(uintptr_t)got == 1000 + other);
    assert(bucket_flags(&d, (uint32_t)flagged) == N00B_HT_FLAGS_MIGRATING);
    assert(n00b_dict_stranded_flags_repair_count_get() == repairs);

    atomic_store(&d._migration_state, 0);
    got = n00b_dict_untyped_get(&d, flagged, &found);
    assert(found && (uint64_t)(uintptr_t)got == 1000 + flagged);
    assert(bucket_flags(&d, (uint32_t)flagged) == 0);
    assert(n00b_dict_stranded_flags_repair_count_get() == repairs + 1);

    printf("  [PASS] live_migration_bits_are_not_repaired\n");
}

// ---------------------------------------------------------------------------
// Migration with the world stopped (#272).
//
// The collector is the only thread that runs while the world is stopped, so a
// bucket MUTEX or a migration owned by anyone else belongs to a suspended
// thread and can never clear. The acquire helpers already knew that; the
// migrator's two waits did not. Nor may the migrator copy AROUND a held
// bucket: its owner will finish writing into this store when resumed, so a
// published copy would lose that write. Both cases abandon at once. A
// stranded MUTEX stands in for the suspended mutator here; the first test
// resumes it by hand and checks its write is not lost.
// ---------------------------------------------------------------------------

static void
test_stw_migration_abandons_on_a_held_bucket_mutex(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    // A "suspended writer": it acquired the bucket for `held` (an existing
    // key) and was stopped before storing its new value. That is exactly a
    // reserved bucket with MUTEX set and no running owner.
    uint64_t held = l.threshold / 2;
    assert(held >= 1);
    n00b_dict_untyped_store_t *before = n00b_atomic_load(&d.store);
    strand_bucket(&d, (uint32_t)held);
    // The default gate: if the migrator waits at all this takes a second per
    // attempt, and the deadline below catches it.
    n00b_dict_migrate_abandon_gate_set(1000ULL * N00B_NS_PER_MS);

    uint64_t contention = n00b_dict_stw_contention_count_get();
    uint64_t abandons   = n00b_dict_migrate_abandon_count_get();
    // The threshold test reads the PRE-increment count, so the insert that
    // reaches the threshold lands quietly and every one after it asks for a
    // resize: last_key - threshold asks, one abandon each.
    uint64_t attempts   = l.last_key - l.threshold;

    n00b_stop_the_world();
    uint64_t t0 = base_monotonic_ns();
    fill(&d, l.threshold, l.last_key);
    uint64_t elapsed = base_monotonic_ns() - t0;
    n00b_restart_the_world();

    // No wait, no copy: every resize was abandoned at once and the writes
    // landed in the store the suspended writer is still inside.
    assert(elapsed < 500ULL * N00B_NS_PER_MS);
    assert(n00b_atomic_load(&d.store) == before);
    assert(n00b_dict_stw_contention_count_get() == contention + attempts);
    assert(n00b_dict_migrate_abandon_count_get() == abandons + attempts);
    assert(n00b_atomic_load(&d._migration_state) == 0);
    for (uint32_t i = 0; i <= before->last_slot; i++) {
        assert(!(n00b_atomic_load(&before->buckets[i].flags) & N00B_HT_FLAGS_MIGRATING));
    }

    // Resume the writer: it finishes its update in the bucket it holds and
    // releases. Had the collector published a copy, this write would land in
    // a dead store and the lookup below would read the stale 1000 + held.
    uint64_t v2 = 2000 + held;
    before->buckets[held].value = (void *)(uintptr_t)v2;
    n00b_atomic_and(&before->buckets[held].flags, ~(uint32_t)N00B_HT_FLAG_MUTEX);

    bool  found = false;
    void *got   = n00b_dict_untyped_get(&d, held, &found);
    assert(found && (uint64_t)(uintptr_t)got == v2);
    for (uint64_t k = 1; k <= l.last_key; k++) {
        if (k == held) {
            continue;
        }
        got = n00b_dict_untyped_get(&d, k, &found);
        assert(found && (uint64_t)(uintptr_t)got == 1000 + k);
    }

    printf("  [PASS] stw_migration_abandons_on_a_held_bucket_mutex\n");
}

// The other wait: the migration word already raised by a (suspended) thread.
// Under STW that can never lower, so the collector must not park on it. The
// write has to land anyway, in the oversized store.
static void
test_stw_migration_does_not_wait_on_a_foreign_migration(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);
    fill(&d, 1, l.threshold - 1);

    n00b_dict_untyped_store_t *before = n00b_atomic_load(&d.store);
    n00b_atomic_or(&d._migration_state, N00B_DICT_MIGRATION_ACTIVE);

    uint64_t contention = n00b_dict_stw_contention_count_get();

    n00b_stop_the_world();
    uint64_t t0 = base_monotonic_ns();
    fill(&d, l.threshold, l.last_key);
    uint64_t elapsed = base_monotonic_ns() - t0;
    n00b_restart_the_world();

    assert(n00b_atomic_load(&d.store) == before);
    assert(n00b_dict_stw_contention_count_get() > contention);
    assert(elapsed < 500ULL * N00B_NS_PER_MS);

    // Hand the word back and confirm nothing was lost.
    atomic_store(&d._migration_state, 0);
    check_all_readable(&d, l.last_key);

    printf("  [PASS] stw_migration_does_not_wait_on_a_foreign_migration\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    printf("test_dict_untyped_migrate:\n");
    test_unstranded_dict_still_migrates();
    test_lock_reports_abandonment();
    test_abandon_gate_is_total_not_per_bucket();
    test_writes_terminate_with_migration_abandoned();
    test_abandoned_migration_leaks_no_reservation();
    test_get_repairs_stranded_moving_flag();
    test_add_repairs_stranded_copying_flag();
    test_live_migration_bits_are_not_repaired();
    test_full_store_recovers_once_the_holder_releases();
    test_full_store_recovers_via_put_and_cas();
    test_full_store_refusal_is_bounded_and_counted();
    test_stw_migration_abandons_on_a_held_bucket_mutex();
    test_stw_migration_does_not_wait_on_a_foreign_migration();
    printf("test_dict_untyped_migrate: OK\n");

    n00b_shutdown();
    return 0;
}

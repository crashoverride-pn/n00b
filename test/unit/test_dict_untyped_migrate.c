/*
 * What the untyped dict does when a migration cannot run.
 *
 * A bucket MUTEX that never clears blocks the resize: the migration has to
 * wait for in-flight writers, and it cannot copy a bucket somebody may still
 * be inside. n00b-lang/n00b#221 is what an unbounded wait costs, so the wait
 * gives up after a bound and ABANDONS the migration.
 *
 * Abandoning is only half an answer. The store is then still over its resize
 * threshold, so a writer that read the give-up as "try again" would trip the
 * same threshold, re-take the dict-wide migration bit, re-park every reader
 * for another full bound, and never finish. These pin the other half: one
 * attempt per write, the write then lands in the oversized store, and the
 * reservation it took while asking comes back.
 *
 * Hashing is supplied by the test rather than left to n00b_hash_word, because
 * which bucket a key lands in is the whole setup. A probe locks every bucket
 * it walks past, so a probe that reached the stranded bucket would spin there
 * forever and the test would hang on the wrong thing entirely.
 */
#include <stdio.h>
#include <assert.h>

#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "adt/dict_untyped.h"

#ifndef N00B_DEBUG
#error "test_dict_untyped_migrate requires N00B_DEBUG (spin-limit override)"
#endif

// Far enough below the real bound to run in a suite, far enough above a real
// hand-off that a scheduler cannot reach it by accident.
#define TEST_SPIN_LIMIT 4096

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
    return out;
}

static void
strand_bucket(n00b_dict_untyped_t *d, uint32_t at)
{
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d->store);
    n00b_atomic_or(&store->buckets[at].flags, N00B_HT_FLAG_MUTEX);
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

// The abandon path itself, taken directly.
//
// A give-up has to be distinguishable from losing the race for the migration:
// losing means the store changes and a writer should look again, abandoning
// means it does not. Both return false, so the difference is the out-param,
// and a writer that could not see it is the livelock this file exists for.
static void
test_lock_reports_abandonment(void)
{
    n00b_dict_untyped_t d;
    layout_t            l    = init_dict(&d);
    uint64_t            seed = 1001;
    assert(n00b_dict_untyped_add(&d, 1, seed));

    n00b_dict_untyped_store_t *before = n00b_atomic_load(&d.store);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_spin_limit_set(TEST_SPIN_LIMIT);

    uint32_t count     = 0;
    bool     abandoned = false;
    assert(!n00b_dict_untyped_lock(&d, true, &count, &abandoned));
    assert(abandoned);

    // The migration bit is back down, so nothing is parked behind a migration
    // that is not happening.
    assert(n00b_atomic_load(&d._migration_state) == 0);

    // And the bits the walk set are off again, so a reader does not keep
    // taking the try_again path against a store nobody is migrating. Only the
    // strand is left, which is not ours to clear.
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d.store);
    for (uint32_t i = 0; i <= store->last_slot; i++) {
        uint32_t flags = n00b_atomic_load(&store->buckets[i].flags);
        assert(!(flags & N00B_HT_FLAG_COPYING));
        assert(!(flags & N00B_HT_FLAG_MOVING));
        assert((flags & N00B_HT_FLAG_MUTEX) == (i == l.stranded
                                                    ? N00B_HT_FLAG_MUTEX
                                                    : 0u));
    }
    assert(n00b_atomic_load(&d.store) == before);

    n00b_dict_migrate_spin_limit_set(0);
    printf("  [PASS] lock_reports_abandonment\n");
}

// Writes past the threshold with the migration abandoned.
//
// Before the fix this did not return: each insert past the threshold spun the
// bound, abandoned, found the same store still over its threshold, and started
// over. There is no assertion that catches that, which is why the test is
// shaped as "does this terminate" and run with a small bound rather than as a
// count of anything.
static void
test_writes_terminate_with_migration_abandoned(void)
{
    n00b_dict_untyped_t d;
    layout_t            l = init_dict(&d);

    // Below the threshold first, so the strand goes in with the dict healthy.
    for (uint64_t k = 1; k < l.threshold; k++) {
        uint64_t v = 1000 + k;
        assert(n00b_dict_untyped_add(&d, k, v));
    }

    n00b_dict_untyped_store_t *before = n00b_atomic_load(&d.store);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_spin_limit_set(TEST_SPIN_LIMIT);

    // Each of these crosses the threshold and asks for a resize that cannot
    // happen.
    for (uint64_t k = l.threshold; k <= l.last_key; k++) {
        uint64_t v = 1000 + k;
        assert(n00b_dict_untyped_add(&d, k, v));
    }

    // No migration ran, and every key is still there: abandoning leaves the
    // store oversized, not damaged.
    assert(n00b_atomic_load(&d.store) == before);
    check_all_readable(&d, l.last_key);

    n00b_dict_migrate_spin_limit_set(0);
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

    for (uint64_t k = 1; k < l.threshold; k++) {
        uint64_t v = 1000 + k;
        assert(n00b_dict_untyped_add(&d, k, v));
    }

    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d.store);
    strand_bucket(&d, l.stranded);
    n00b_dict_migrate_spin_limit_set(TEST_SPIN_LIMIT);

    for (uint64_t k = l.threshold; k <= l.last_key; k++) {
        uint64_t v = 1000 + k;
        assert(n00b_dict_untyped_add(&d, k, v));
    }

    assert(n00b_atomic_load(&d.store) == store);

    // One slot per key that landed, and nothing for the attempts that were
    // refused a resize. An uncorrected reservation shows up here as a count
    // above the number of keys in the table.
    assert(n00b_atomic_load(&store->used_count) == l.last_key);

    n00b_dict_migrate_spin_limit_set(0);
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
    for (uint64_t k = 1; k <= count; k++) {
        uint64_t v = 1000 + k;
        assert(n00b_dict_untyped_add(&d, k, v));
    }

    assert((uint64_t)n00b_atomic_load(&d.store)->last_slot + 1 > l.capacity);
    check_all_readable(&d, count);

    printf("  [PASS] unstranded_dict_still_migrates\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    printf("test_dict_untyped_migrate:\n");
    test_unstranded_dict_still_migrates();
    test_lock_reports_abandonment();
    test_writes_terminate_with_migration_abandoned();
    test_abandoned_migration_leaks_no_reservation();
    printf("test_dict_untyped_migrate: OK\n");

    return 0;
}

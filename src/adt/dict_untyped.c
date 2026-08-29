/*
 * For internal system use. Thread-safe, but not typed.
 *
 *  Author:         John Viega, john@crashoverride.com
 *
 */

#define N00B_USE_INTERNAL_API
#include <stdatomic.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/align.h"
#include "adt/dict_untyped.h"
#include "core/atomic.h"
#include "core/epoch.h"
#include "core/futex.h"
#include "core/runtime.h"

// WP-001: while the world is stopped, the collector is the SOLE running thread,
// so it must IGNORE all lock ops (it can never contend) — otherwise it blocks
// forever on a per-bucket MUTEX flag or an in-progress migration that a
// Mach-suspended mutator left held.  This dict's locking is hand-rolled (raw
// flag bits + a migration futex), so it does not get the n00b_mutex/rwlock
// stw_active short-circuit automatically; this helper provides it.  Safe before
// the runtime exists (returns false), mirroring stw.c's runtime access.
static inline bool
n00b_dict_in_stw(void)
{
    if (!n00b_default_runtime_is_set()) {
        return false;
    }
    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    return rt != nullptr && n00b_atomic_load(&rt->stw_active);
}

static inline n00b_uint128_t
compute_hash(n00b_dict_untyped_t *dict, void *key)
{
    if (dict->skip_obj_hash) {
        n00b_hash_fn fn = dict->fn ? dict->fn : n00b_hash_word;
        return (*fn)(key);
    }
    else {
        return n00b_hash(key, dict->fn);
    }
}

// 75%
static inline uint32_t
resize_threshold(uint32_t size)
{
    return size - (size >> 2) - 1;
}

static inline int
bucket_reserved(n00b_dict_untyped_bucket_t *b)
{
    return (int)b->hv != 0;
}

static inline int
bucket_deleted(n00b_dict_untyped_bucket_t *b)
{
    return (n00b_atomic_load(&b->flags) & N00B_HT_FLAG_DELETED) != 0;
}

static inline uint32_t
new_dict_untyped_size(uint32_t last_bucket, uint32_t size)
{
    uint32_t table_size = last_bucket + 1;

    if (size >= table_size >> 1) {
        return table_size << 1;
    }
    // We will never bother to size back down to the smallest few
    // table sizes.
    if (size <= (N00B_DICT_UNTYPED_MIN_SIZE << 2)) {
        return N00B_DICT_UNTYPED_MIN_SIZE << 3;
    }
    if (size <= (table_size >> 2)) {
        return table_size >> 1;
    }

    return table_size;
}

static inline n00b_dict_untyped_store_t *
new_dict_untyped_store(n00b_dict_untyped_t *d, uint32_t alloc_items)
{
    n00b_dict_untyped_store_t *result;
    n00b_alloc_opts_t          opts = {
        .allocator = d->allocator,
        .scan_kind = d->scan_kind,
        .scan_cb   = d->scan_cb,
        .scan_user = d->scan_user,
    };

    if (d->epoch_store) {
        size_t bytes = sizeof(n00b_dict_untyped_store_t)
                    + sizeof(n00b_dict_untyped_bucket_t) * alloc_items;
        result       = n00b_epoch_alloc(bytes, &opts);
    }
    else {
        result = n00b_alloc_flex_with_opts(n00b_dict_untyped_store_t,
                                           n00b_dict_untyped_bucket_t,
                                           alloc_items,
                                           &opts);
    }

    result->last_slot = alloc_items - 1;
    result->threshold = resize_threshold(alloc_items);

    return result;
}

static inline void
free_dict_untyped_store(n00b_dict_untyped_t *d, n00b_dict_untyped_store_t *store)
{
    if (store == nullptr) {
        return;
    }

    if (d->epoch_store) {
        n00b_retire(store);
        return;
    }

    // Callback / offset-sensitive scan policies cannot use n00b_epoch_alloc's
    // hidden header safely. Locked dicts may still have concurrent readers, so
    // keep old stores rather than handing out dangling bucket pointers.
    if (d->lock != nullptr) {
        return;
    }

    n00b_allocator_opt_t alloc_opt = n00b_mem_get_allocator(store);
    if (n00b_option_is_set(alloc_opt)) {
        n00b_free(store);
    }
    else if (d->allocator != nullptr) {
        n00b_free_from_allocator(d->allocator, store);
    }
    else {
        n00b_free(store);
    }
}

static inline bool
dict_untyped_epoch_enter(n00b_dict_untyped_t *d, bool in_stw)
{
    if (d->lock == nullptr || in_stw) {
        return false;
    }

    n00b_epoch_acquire();
    return true;
}

static inline void
dict_untyped_epoch_exit(bool active)
{
    if (active) {
        n00b_epoch_yield();
    }
}

// Bound on the per-bucket mutex wait in n00b_dict_untyped_lock. A real holder
// releases within a few instructions, so the wait stays a tight spin -- adding
// a sleep here measurably slowed rocs_async_seal_stress, because migrations are
// frequent and the common wait is very short. The bound exists only to convert
// a PERMANENTLY stranded mutex from a whole-dict outage into a skipped
// migration; it is deliberately far above any legitimate wait.
#define N00B_DICT_MIGRATE_SPIN_LIMIT (1ULL << 32)

// Undo a partially-acquired migration: drop the COPYING/MOVING bits we OR'd
// onto the buckets, then release the dict-wide migration bit and wake everyone
// parked on it. Without the flag clear, readers would keep taking the
// try_again path against a store nobody is migrating.
static inline void
dict_untyped_abandon_migration(n00b_dict_untyped_t       *d,
                               n00b_dict_untyped_store_t *s,
                               uint32_t                   flags)
{
    for (uint32_t i = 0; i <= s->last_slot; i++) {
        n00b_atomic_and(&s->buckets[i].flags, ~flags);
    }

    atomic_store(&d->_migration_state, 0);

    if (n00b_atomic_load(&d->wait_ct)) {
        n00b_futex_wake(&d->_migration_state, true);
    }
}

bool
n00b_dict_untyped_lock(n00b_dict_untyped_t *d, bool try, uint32_t *count)
{
    uint32_t flags    = N00B_HT_FLAG_COPYING;
    uint32_t new_used = 0;

    if (try) {
        flags |= N00B_HT_FLAG_MOVING;
    }
    else {
        n00b_atomic_add(&d->wait_ct, 1);
    }

    uint32_t v = n00b_atomic_or(&d->_migration_state, 1UL << 31);

    while (v & (1UL << 31)) {
        if (try) {
            return false;
        }
        n00b_futex_wait_timespec(&d->_migration_state, v, nullptr);
        v = n00b_atomic_or(&d->_migration_state, 1UL << 31);
    }

    if (!try) {
        n00b_atomic_add(&d->wait_ct, -1);
    }

    n00b_dict_untyped_store_t  *s = n00b_atomic_load(&d->store);
    n00b_dict_untyped_bucket_t *b;

    int first_active = -1;
    int last_active  = -1;

    for (uint32_t i = 0; i <= s->last_slot; i++) {
        b = &s->buckets[i];

        uint32_t f = n00b_atomic_or(&b->flags, flags);

        new_used += (bucket_reserved(b) & !bucket_deleted(b));

        if (f & N00B_HT_FLAG_MUTEX) {
            last_active = i;
            if (first_active == -1) {
                first_active = i;
            }
        }
    }

    // If we noticed writes in progress, go through the range of the store that
    // contained threads and wait for those bucket mutexes to clear.
    //
    // The dict-wide migration bit is ALREADY SET at this point, so every reader
    // and remover on this dict is parked on _migration_state until we clear it.
    // An unbounded, non-yielding spin here therefore turns one stranded bucket
    // mutex into a permanent whole-dict outage: n00b-lang/n00b#221 saw 63
    // threads parked on the migration futex for 2h43m, taking out socket
    // creation, HTTP serve, egress and shard sealing at once because the wedged
    // dict was the conduit fd registry.
    //
    // So: give up after a bound rather than spinning forever. On give-up we
    // ABANDON the migration and clear the bits we set, which keeps the dict
    // live -- readers and removers make progress against the un-migrated store
    // instead of parking forever. The dict stays oversized until a later
    // migration succeeds; that is strictly better than wedging every thread
    // that touches it.
    if (last_active != -1) {
        for (int i = first_active; i <= last_active; i++) {
            uint64_t spins = 0;

            while (n00b_atomic_load(&s->buckets[i].flags) & N00B_HT_FLAG_MUTEX) {
                if (++spins >= N00B_DICT_MIGRATE_SPIN_LIMIT) {
                    dict_untyped_abandon_migration(d, s, flags);
                    return false;
                }
            }
        }
    }

    *count = new_used;

    return true;
}

static void
dict_untyped_unlock_post_migrate(n00b_dict_untyped_t *d, n00b_dict_untyped_store_t *s)
{
    atomic_store(&d->store, s);
    atomic_store(&d->_migration_state, 0);

    if (n00b_atomic_load(&d->wait_ct)) {
        n00b_futex_wake(&d->_migration_state, true);
    }
}

void
n00b_dict_untyped_unlock_post_copy(n00b_dict_untyped_t *d)
{
    n00b_dict_untyped_store_t *s = n00b_atomic_load(&d->store);

    for (uint32_t i = 0; i <= s->last_slot; i++) {
        n00b_atomic_and(&s->buckets[i].flags, ~N00B_HT_FLAG_COPYING);
    }

    atomic_store(&d->_migration_state, 0);

    if (n00b_atomic_load(&d->wait_ct)) {
        n00b_futex_wake(&d->_migration_state, true);
    }
}

static void
n00b_dict_untyped_migrate(n00b_dict_untyped_t *d)
{
    uint32_t                    nitems = 0;
    n00b_dict_untyped_store_t  *olds;
    n00b_dict_untyped_bucket_t *bold;

    if (!n00b_dict_untyped_lock(d, true, &nitems)) {
        // Either another thread owns the migration, or we owned it and
        // abandoned a stranded bucket-mutex wait (in which case the migration
        // bit is already clear and this wait falls straight through). Balance
        // the wait_ct increment on both paths: it gates the futex_wake in the
        // unlock helpers, so leaking it made every later migration issue a
        // wake syscall for a waiter that no longer exists.
        n00b_atomic_add(&d->wait_ct, 1);
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        n00b_atomic_add(&d->wait_ct, -1);
        return;
    }
    olds = n00b_atomic_load(&d->store);

    uint32_t                   alloc_items = new_dict_untyped_size(olds->last_slot, nitems);
    n00b_dict_untyped_store_t *news        = new_dict_untyped_store(d, alloc_items);
    uint32_t                   last        = news->last_slot;
    uint32_t                   bix;

    atomic_store(&news->used_count, nitems);

    for (uint32_t i = 0; i <= olds->last_slot; i++) {
        bold = &olds->buckets[i];
        if (!bucket_reserved(bold) || bucket_deleted(bold)) {
            continue;
        }

        bix = bold->hv & last;

        for (uint32_t j = 0; j <= last; j++) {
            n00b_dict_untyped_bucket_t *bnew = &news->buckets[bix];

            if (!bucket_reserved(bnew)) {
                bnew->hv           = bold->hv;
                bnew->key          = bold->key;
                bnew->value        = bold->value;
                bnew->insert_order = bold->insert_order;
                break;
            }

            bix = (bix + 1) & news->last_slot;
        }
    }

    dict_untyped_unlock_post_migrate(d, news);
    free_dict_untyped_store(d, olds);
}

// Gives us the correct bucket if and only if the key is found in the
// table already. It can return a bucket where the item has been deleted,
// so the value needs to be checked.

// Lockless bucket scan for the STW collector: read the store directly, ignoring
// the MUTEX/MOVING flags (a suspended thread may hold them).  Returns the bucket
// whose hv matches, or the first unreserved (empty) bucket / nullptr on miss.
// `add` controls miss handling: a GET returns nullptr at the first empty slot; a
// PUT (acquire-or-add) returns the empty bucket so the caller can fill it.
static inline n00b_dict_untyped_bucket_t *
n00b_dict_stw_scan(n00b_dict_untyped_store_t *store, __int128_t hv, bool add)
{
    uint32_t last_slot = store->last_slot;
    uint32_t bix       = hv & last_slot;

    for (uint32_t i = 0; i <= last_slot; i++) {
        n00b_dict_untyped_bucket_t *cur = &store->buckets[bix];
        if (cur->hv == hv) {
            return cur;
        }
        if (!bucket_reserved(cur)) {
            return add ? cur : nullptr;
        }
        bix = (bix + 1) & last_slot;
    }
    return nullptr;
}

static inline n00b_dict_untyped_bucket_t *
n00b_dict_untyped_readonly_scan(n00b_dict_untyped_store_t *store, __int128_t hv)
{
    uint32_t last_slot = store->last_slot;
    uint32_t bix       = hv & last_slot;

    for (uint32_t i = 0; i <= last_slot; i++) {
        n00b_dict_untyped_bucket_t *cur = &store->buckets[bix];
        if (cur->hv == hv) {
            return cur;
        }
        if (!bucket_reserved(cur)) {
            return nullptr;
        }
        bix = (bix + 1) & last_slot;
    }
    return nullptr;
}

static inline n00b_dict_untyped_bucket_t *
n00b_acquire_if_present(n00b_dict_untyped_t       *d,
                        n00b_dict_untyped_store_t *store,
                        __int128_t                 hv,
                        bool                       in_stw)
{
    uint32_t                    last_slot;
    uint32_t                    bix;
    uint32_t                    flags;
    n00b_dict_untyped_bucket_t *cur;
    bool                        miss = false;

    // STW collector: lockless read (see n00b_dict_in_stw). `in_stw` is the
    // value the CALLER sampled once for the whole operation, so the matching
    // unlock_bucket() makes the same lock/no-lock decision we did here.
    if (in_stw) {
        return n00b_dict_stw_scan(store, hv, false);
    }

    do {
        last_slot = store->last_slot;
        bix       = hv & last_slot;

        for (uint32_t i = 0; i <= last_slot; i++) {
            cur = &store->buckets[bix];

            do {
                flags = n00b_atomic_or(&cur->flags, N00B_HT_FLAG_MUTEX);
                if (flags & N00B_HT_FLAG_MOVING) {
                    // If pre-OR had no MUTEX, we just took it; clear
                    // it before parking on the migration futex.  A
                    // migration thread may have pre-recorded this
                    // bucket in its [first_active, last_active] range
                    // (because a prior reader briefly held MUTEX
                    // pre-migration-OR), and is busy-waiting for the
                    // MUTEX to clear.  Leaving it set deadlocks us
                    // against migration.
                    if (!(flags & N00B_HT_FLAG_MUTEX)) {
                        n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
                    }
                    goto try_again;
                }
            } while (flags & N00B_HT_FLAG_MUTEX);

            if (cur->hv == hv) {
                // Keep it locked.
                // Note: We don't check for deletion here.
                return cur;
            }
            if (!bucket_reserved(cur)) {
                miss = true;
            }

            bix   = (bix + 1) & last_slot;
            flags = n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);

            if (miss) {
                return nullptr;
            }
        }

        return nullptr;

try_again:
        if (d->lock != nullptr) {
            n00b_epoch_yield();
        }
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        if (d->lock != nullptr) {
            n00b_epoch_acquire();
        }
        store = n00b_atomic_load(&d->store);
    } while (true);
}

static inline n00b_dict_untyped_bucket_t *
n00b_acquire_or_add(n00b_dict_untyped_t        *d,
                    n00b_dict_untyped_store_t **store_pp,
                    __int128_t                  hv,
                    bool                        in_stw)
{
    n00b_dict_untyped_store_t  *store = *store_pp;
    uint32_t                    last_slot;
    uint32_t                    bix;
    uint32_t                    flags;
    n00b_dict_untyped_bucket_t *cur;

    // STW collector: lockless read/add (see n00b_dict_in_stw). `in_stw` is the
    // caller's single sample for the whole operation -- see the sibling note in
    // n00b_acquire_if_present.
    if (in_stw) {
        return n00b_dict_stw_scan(store, hv, true);
    }

    do {
        last_slot = store->last_slot;
        bix       = hv & last_slot;

        for (uint32_t i = 0; i <= last_slot; i++) {
            cur = &store->buckets[bix];

            do {
                flags = n00b_atomic_or(&cur->flags, N00B_HT_FLAG_MUTEX);
                if (flags & (N00B_HT_FLAG_COPYING)) {
                    // See sibling note in acquire_if_present: clear
                    // MUTEX before parking on the migration futex, or
                    // we deadlock the migration's bucket busy-wait.
                    if (!(flags & N00B_HT_FLAG_MUTEX)) {
                        n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
                    }
                    goto try_again;
                }
            } while (flags & N00B_HT_FLAG_MUTEX);

            if (cur->hv == hv || !bucket_reserved(cur)) {
                // Keep it locked.
                //
                // We don't add in the hash value if it's not present;
                // that way the caller will know to do whatever
                // accounting needs to be done.

                *store_pp = store;
                return cur;
            }

            bix   = (bix + 1) & last_slot;
            flags = n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
        }

        *store_pp = store;
        return nullptr;

try_again:
        if (d->lock != nullptr) {
            n00b_epoch_yield();
        }
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        if (d->lock != nullptr) {
            n00b_epoch_acquire();
        }
        store = n00b_atomic_load(&d->store);
    } while (true);
}

// Release a bucket MUTEX. `locked` MUST be the acquire-time answer to "did this
// operation take the bucket lock?", i.e. !in_stw for the SAME in_stw sample the
// acquire used -- not a fresh n00b_dict_in_stw() reading.
//
// Re-sampling here was a latent deadlock (n00b-lang/n00b#221). The STW
// collector takes buckets locklessly and never sets MUTEX, so clearing on its
// behalf would stomp a flag a Mach-suspended mutator still holds -- hence the
// guard. But an operation that acquired with stw_active false (setting MUTEX)
// and then reached the unlock after stw_active had flipped true read the guard
// as "collector, don't clear" and returned with the mutex STILL SET. Nothing
// ever cleared it again. The next migration on that dict sets the dict-wide
// migration bit, then busy-waits for that bucket's MUTEX to clear, so the bit
// stays set forever and every subsequent reader and remover parks on the
// migration futex -- one stranded bit wedges the whole dict.
static inline void
unlock_bucket(n00b_dict_untyped_bucket_t *b, bool locked)
{
    if (!locked) {
        return;
    }
    n00b_atomic_and(&b->flags, ~N00B_HT_FLAG_MUTEX);
}

// Returns the old value if found, nullptr otherwise.
void *
_n00b_dict_untyped_put(n00b_dict_untyped_t *d, void *key, void *value)
{
    bool                       in_stw       = n00b_dict_in_stw();
    bool                       epoch_active = dict_untyped_epoch_enter(d, in_stw);
    __int128_t                 hv     = compute_hash(d, key);
    n00b_dict_untyped_store_t *store  = n00b_atomic_load(&d->store);
    void                      *result = nullptr;
try_again:
    n00b_dict_untyped_bucket_t *bucket      = n00b_acquire_or_add(d, &store, hv, in_stw);
    bool                        reset_epoch = false;

    if (!bucket->hv) {
        if (n00b_atomic_add(&store->used_count, 1) >= store->threshold) {
            unlock_bucket(bucket, !in_stw);
            n00b_dict_untyped_migrate(d);
            store = n00b_atomic_load(&d->store);
            goto try_again;
        }
        reset_epoch = true;
        bucket->hv  = hv;
    }
    else {
        if (bucket_deleted(bucket)) {
            reset_epoch = true;
            bucket->flags &= ~N00B_HT_FLAG_DELETED;
        }
        else {
            result = bucket->value;
        }
    }

    if (reset_epoch) {
        bucket->insert_order =
            (uint32_t)(n00b_atomic_add(&d->insertion_epoch, 1) + 1);
        n00b_atomic_add(&d->length, 1);
    }

    bucket->key   = key;
    bucket->value = value;
    unlock_bucket(bucket, !in_stw);

    dict_untyped_epoch_exit(epoch_active);
    return result;
}

void *
_n00b_dict_untyped_get(n00b_dict_untyped_t *d, void *key, bool *found)
{
    bool                        in_stw       = n00b_dict_in_stw();
    bool                        epoch_active = dict_untyped_epoch_enter(d, in_stw);
    __int128_t                  hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store = n00b_atomic_load(&d->store);
    // Baked grammar-image dictionaries are scrubbed to a lockless/private
    // shape before marshal; reads must not set bucket mutex bits after the
    // containing section is protected read-only.
    bool readonly = d->lock == nullptr && d->allocator == nullptr;
    n00b_dict_untyped_bucket_t *b =
        readonly ? n00b_dict_untyped_readonly_scan(store, hv)
                 : n00b_acquire_if_present(d, store, hv, in_stw);
    void                       *result;

    if (!b) {
        if (found) {
            *found = false;
        }

        dict_untyped_epoch_exit(epoch_active);
        return nullptr;
    }
    if (bucket_deleted(b)) {
        if (found) {
            *found = false;
        }
        if (!readonly) {
            unlock_bucket(b, !in_stw);
        }
        dict_untyped_epoch_exit(epoch_active);
        return nullptr;
    }

    if (found) {
        *found = true;
    }

    result = b->value;

    if (!readonly) {
        unlock_bucket(b, !in_stw);
    }

    dict_untyped_epoch_exit(epoch_active);
    return result;
}

bool
_n00b_dict_untyped_replace(n00b_dict_untyped_t *d, void *key, void *value)
{
    bool                        in_stw       = n00b_dict_in_stw();
    bool                        epoch_active = dict_untyped_epoch_enter(d, in_stw);
    __int128_t                  hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store = n00b_atomic_load(&d->store);
    n00b_dict_untyped_bucket_t *b     = n00b_acquire_if_present(d, store, hv, in_stw);

    if (!b) {
        dict_untyped_epoch_exit(epoch_active);
        return false;
    }
    if (!bucket_reserved(b) || bucket_deleted(b)) {
        unlock_bucket(b, !in_stw);
        dict_untyped_epoch_exit(epoch_active);
        return false;
    }

    b->value = value;
    unlock_bucket(b, !in_stw);
    dict_untyped_epoch_exit(epoch_active);
    return true;
}

bool
_n00b_dict_untyped_add(n00b_dict_untyped_t *d, void *key, void *value)
{
    bool                       in_stw       = n00b_dict_in_stw();
    bool                       epoch_active = dict_untyped_epoch_enter(d, in_stw);
    __int128_t                 hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d->store);
try_again:
    n00b_dict_untyped_bucket_t *bucket = n00b_acquire_or_add(d, &store, hv, in_stw);

    if (!bucket->hv) {
        uint64_t used = n00b_atomic_add(&store->used_count, 1);
        if (used >= store->threshold) {
            unlock_bucket(bucket, !in_stw);
            n00b_dict_untyped_migrate(d);
            store = n00b_atomic_load(&d->store);
            goto try_again;
        }
        bucket->hv           = hv;
        bucket->insert_order =
            (uint32_t)(n00b_atomic_add(&d->insertion_epoch, 1) + 1);
    }
    else {
        if (bucket_deleted(bucket)) {
            bucket->flags &= ~N00B_HT_FLAG_DELETED;
            bucket->insert_order =
                (uint32_t)(n00b_atomic_add(&d->insertion_epoch, 1) + 1);
        }
        else {
            unlock_bucket(bucket, !in_stw);
            dict_untyped_epoch_exit(epoch_active);
            return false;
        }
    }

    bucket->key   = key;
    bucket->value = value;

    n00b_atomic_add(&d->length, 1);
    unlock_bucket(bucket, !in_stw);

    dict_untyped_epoch_exit(epoch_active);
    return true;
}

bool
_n00b_dict_untyped_remove(n00b_dict_untyped_t *d, void *key)
{
    bool                        in_stw       = n00b_dict_in_stw();
    bool                        epoch_active = dict_untyped_epoch_enter(d, in_stw);
    __int128_t                  hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store = n00b_atomic_load(&d->store);
    n00b_dict_untyped_bucket_t *b     = n00b_acquire_if_present(d, store, hv, in_stw);

    if (!b) {
        dict_untyped_epoch_exit(epoch_active);
        return false;
    }
    if (!bucket_reserved(b) || bucket_deleted(b)) {
        unlock_bucket(b, !in_stw);
        dict_untyped_epoch_exit(epoch_active);
        return false;
    }

    b->value = nullptr;
    b->flags |= N00B_HT_FLAG_DELETED;
    n00b_atomic_add(&d->length, -1);
    unlock_bucket(b, !in_stw);

    dict_untyped_epoch_exit(epoch_active);
    return true;
}

bool
_n00b_dict_untyped_cas(n00b_dict_untyped_t *d,
                       void                *key,
                       void               **old_item_ptr,
                       void                *new_item) _kargs
{
    bool null_old_means_absence = false;
    bool null_new_means_delete  = false;
}
{
    bool                        in_stw       = n00b_dict_in_stw();
    bool                        epoch_active = dict_untyped_epoch_enter(d, in_stw);
    __int128_t                  hv           = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store        = n00b_atomic_load(&d->store);
    void                       *old_item     = old_item_ptr ? *old_item_ptr : nullptr;
    bool                        expect_empty = !old_item && null_old_means_absence;
    bool                        delete_it    = !new_item && null_new_means_delete;
    n00b_dict_untyped_bucket_t *b;

    if (expect_empty) {
try_again:
        b = n00b_acquire_or_add(d, &store, hv, in_stw);
        if (bucket_reserved(b) && !bucket_deleted(b)) {
            if (old_item_ptr) {
                *old_item_ptr = b->value;
            }
            unlock_bucket(b, !in_stw);
            dict_untyped_epoch_exit(epoch_active);
            return false;
        }

        if (!bucket_deleted(b)) {
            if (n00b_atomic_add(&store->used_count, 1) >= store->threshold) {
                unlock_bucket(b, !in_stw);
                n00b_dict_untyped_migrate(d);
                store = n00b_atomic_load(&d->store);
                goto try_again;
            }
        }

        b->hv = hv;
        b->flags &= ~N00B_HT_FLAG_DELETED;
        b->value        = new_item;
        b->insert_order =
            (uint32_t)(n00b_atomic_add(&d->insertion_epoch, 1) + 1);
        n00b_atomic_add(&d->length, 1);
        unlock_bucket(b, !in_stw);

        dict_untyped_epoch_exit(epoch_active);
        return true;
    }
    else {
        b = n00b_acquire_if_present(d, store, hv, in_stw);

        if (!b) {
            dict_untyped_epoch_exit(epoch_active);
            return false;
        }
        if (b->value != old_item) {
            *old_item_ptr = b->value;
            unlock_bucket(b, !in_stw);
            dict_untyped_epoch_exit(epoch_active);
            return false;
        }

        if (delete_it) {
            b->value = nullptr;
            b->flags |= N00B_HT_FLAG_DELETED;
            n00b_atomic_add(&d->length, -1);
        }
        else {
            b->value = new_item;
        }
        unlock_bucket(b, !in_stw);
        dict_untyped_epoch_exit(epoch_active);
        return true;
    }
}

extern void
n00b_dict_untyped_init(n00b_dict_untyped_t *dict) _kargs
{
    uint32_t             start_capacity = N00B_DICT_MIN_SIZE;
    n00b_allocator_t    *allocator      = nullptr;
    n00b_hash_fn         hash           = nullptr;
    bool                 skip_obj_hash  = false;
    bool                 locked         = true;
    n00b_gc_scan_kind_t  scan_kind      = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_cb_t    scan_cb        = nullptr;
    void                *scan_user      = nullptr;
}
{
    // This is also the set initializer now.

    if (start_capacity < N00B_DICT_MIN_SIZE) {
        start_capacity = N00B_DICT_MIN_SIZE;
    }

    start_capacity = n00b_align_closest_pow2_ceil(start_capacity);

    bool epoch_store = scan_cb == nullptr
                    && (scan_kind == N00B_GC_SCAN_KIND_DEFAULT
                        || scan_kind == N00B_GC_SCAN_KIND_ALL
                        || scan_kind == N00B_GC_SCAN_KIND_NONE);

    *dict = (n00b_dict_untyped_t){
        .fn               = hash,
        .allocator        = allocator,
        .insertion_epoch  = 0,
        .wait_ct          = 0,
        .length           = 0,
        ._migration_state = 0,
        .lock             = locked
                               ? n00b_data_lock_new(.allocator = allocator)
                               : (n00b_rwlock_t *)nullptr,
        .skip_obj_hash    = skip_obj_hash,
        .scan_kind        = scan_kind,
        .scan_cb          = scan_cb,
        .scan_user        = scan_user,
        .epoch_store      = epoch_store,
    };

    dict->store = new_dict_untyped_store(dict, start_capacity);
}

n00b_size_t
n00b_dict_untyped_len(n00b_dict_untyped_t *d)
{
    return n00b_atomic_load(&d->length);
}

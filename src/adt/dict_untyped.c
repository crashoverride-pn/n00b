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

    result            = n00b_alloc_flex_with_opts(n00b_dict_untyped_store_t,
                                                  n00b_dict_untyped_bucket_t,
                                                  alloc_items,
                                                  &(n00b_alloc_opts_t){
                                                      .allocator = d->allocator,
                                                      .scan_kind = d->scan_kind,
                                                      .scan_cb   = d->scan_cb,
                                                      .scan_user = d->scan_user,
                                                  });
    result->last_slot = alloc_items - 1;
    result->threshold = resize_threshold(alloc_items);

    return result;
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

    // If we noticed writes in progress, go through the range of the
    // store that contained threads, and busy-wait if needed.
    if (last_active != -1) {
        for (int i = first_active; i <= last_active; i++) {
            while (n00b_atomic_load(&s->buckets[i].flags) & N00B_HT_FLAG_MUTEX) {}
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
        n00b_atomic_add(&d->wait_ct, 1);
        n00b_futex_wait_for_value(&d->_migration_state, 0);
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

    n00b_allocator_opt_t old_alloc_opt = n00b_mem_get_allocator(olds);
    if (n00b_option_is_set(old_alloc_opt)) {
        n00b_free(olds);
    }
    else if (d->allocator != nullptr) {
        n00b_free_from_allocator(d->allocator, olds);
    }
    else {
        n00b_free(olds);
    }

    dict_untyped_unlock_post_migrate(d, news);
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
n00b_acquire_if_present(n00b_dict_untyped_t *d, n00b_dict_untyped_store_t *store, __int128_t hv)
{
    uint32_t                    last_slot;
    uint32_t                    bix;
    uint32_t                    flags;
    n00b_dict_untyped_bucket_t *cur;
    bool                        miss = false;

    // STW collector: lockless read (see n00b_dict_in_stw).
    if (n00b_dict_in_stw()) {
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
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        store = n00b_atomic_load(&d->store);
    } while (true);
}

static inline n00b_dict_untyped_bucket_t *
n00b_acquire_or_add(n00b_dict_untyped_t *d, n00b_dict_untyped_store_t *store, __int128_t hv)
{
    uint32_t                    last_slot;
    uint32_t                    bix;
    uint32_t                    flags;
    n00b_dict_untyped_bucket_t *cur;

    // STW collector: lockless read/add (see n00b_dict_in_stw).
    if (n00b_dict_in_stw()) {
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

                return cur;
            }

            bix   = (bix + 1) & last_slot;
            flags = n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
        }

        return nullptr;

try_again:
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        store = n00b_atomic_load(&d->store);
    } while (true);
}

static inline void
unlock_bucket(n00b_dict_untyped_bucket_t *b)
{
    // STW collector took the bucket locklessly (n00b_dict_in_stw); it never set
    // MUTEX, so clearing it here would stomp a flag a suspended thread holds.
    if (n00b_dict_in_stw()) {
        return;
    }
    n00b_atomic_and(&b->flags, ~N00B_HT_FLAG_MUTEX);
}

// Returns the old value if found, nullptr otherwise.
void *
_n00b_dict_untyped_put(n00b_dict_untyped_t *d, void *key, void *value)
{
    __int128_t                 hv     = compute_hash(d, key);
    n00b_dict_untyped_store_t *store  = n00b_atomic_load(&d->store);
    void                      *result = nullptr;
try_again:
    n00b_dict_untyped_bucket_t *bucket      = n00b_acquire_or_add(d, store, hv);
    bool                        reset_epoch = false;

    if (!bucket->hv) {
        if (n00b_atomic_add(&store->used_count, 1) >= store->threshold) {
            unlock_bucket(bucket);
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
    unlock_bucket(bucket);

    return result;
}

void *
_n00b_dict_untyped_get(n00b_dict_untyped_t *d, void *key, bool *found)
{
    __int128_t                  hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store = n00b_atomic_load(&d->store);
    // Baked grammar-image dictionaries are scrubbed to a lockless/private
    // shape before marshal; reads must not set bucket mutex bits after the
    // containing section is protected read-only.
    bool readonly = d->lock == nullptr && d->allocator == nullptr;
    n00b_dict_untyped_bucket_t *b =
        readonly ? n00b_dict_untyped_readonly_scan(store, hv)
                 : n00b_acquire_if_present(d, store, hv);
    void                       *result;

    if (!b) {
        if (found) {
            *found = false;
        }

        return nullptr;
    }
    if (bucket_deleted(b)) {
        if (found) {
            *found = false;
        }
        if (!readonly) {
            unlock_bucket(b);
        }
        return nullptr;
    }

    if (found) {
        *found = true;
    }

    result = b->value;

    if (!readonly) {
        unlock_bucket(b);
    }

    return result;
}

bool
_n00b_dict_untyped_replace(n00b_dict_untyped_t *d, void *key, void *value)
{
    __int128_t                  hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store = n00b_atomic_load(&d->store);
    n00b_dict_untyped_bucket_t *b     = n00b_acquire_if_present(d, store, hv);

    if (!b) {
        return false;
    }
    if (!bucket_reserved(b) || bucket_deleted(b)) {
        unlock_bucket(b);
        return false;
    }

    b->value = value;
    unlock_bucket(b);
    return true;
}

bool
_n00b_dict_untyped_add(n00b_dict_untyped_t *d, void *key, void *value)
{
    __int128_t                 hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&d->store);
try_again:
    n00b_dict_untyped_bucket_t *bucket = n00b_acquire_or_add(d, store, hv);

    if (!bucket->hv) {
        uint64_t used = n00b_atomic_add(&store->used_count, 1);
        if (used >= store->threshold) {
            unlock_bucket(bucket);
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
            unlock_bucket(bucket);
            return false;
        }
    }

    bucket->key   = key;
    bucket->value = value;

    n00b_atomic_add(&d->length, 1);
    unlock_bucket(bucket);

    return true;
}

bool
_n00b_dict_untyped_remove(n00b_dict_untyped_t *d, void *key)
{
    __int128_t                  hv    = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store = n00b_atomic_load(&d->store);
    n00b_dict_untyped_bucket_t *b     = n00b_acquire_if_present(d, store, hv);

    if (!b) {
        return false;
    }
    if (!bucket_reserved(b) || bucket_deleted(b)) {
        unlock_bucket(b);
        return false;
    }

    b->value = nullptr;
    b->flags |= N00B_HT_FLAG_DELETED;
    n00b_atomic_add(&d->length, -1);
    unlock_bucket(b);

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
    __int128_t                  hv           = compute_hash(d, key);
    n00b_dict_untyped_store_t  *store        = n00b_atomic_load(&d->store);
    void                       *old_item     = old_item_ptr ? *old_item_ptr : nullptr;
    bool                        expect_empty = !old_item && null_old_means_absence;
    bool                        delete_it    = !new_item && null_new_means_delete;
    n00b_dict_untyped_bucket_t *b;

    if (expect_empty) {
try_again:
        b = n00b_acquire_or_add(d, store, hv);
        if (bucket_reserved(b) && !bucket_deleted(b)) {
            if (old_item_ptr) {
                *old_item_ptr = b->value;
            }
            unlock_bucket(b);
            return false;
        }

        if (!bucket_deleted(b)) {
            if (n00b_atomic_add(&store->used_count, 1) >= store->threshold) {
                unlock_bucket(b);
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
        unlock_bucket(b);

        return true;
    }
    else {
        b = n00b_acquire_if_present(d, store, hv);

        if (!b) {
            return false;
        }
        if (b->value != old_item) {
            *old_item_ptr = b->value;
            unlock_bucket(b);
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
        unlock_bucket(b);
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
    };

    dict->store = new_dict_untyped_store(dict, start_capacity);
}

n00b_size_t
n00b_dict_untyped_len(n00b_dict_untyped_t *d)
{
    return n00b_atomic_load(&d->length);
}

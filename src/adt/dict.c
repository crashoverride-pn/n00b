/*
 * Typed dictionary — split-storage, size-aware port of dict_untyped.c.
 *
 * Keys and values are stored in separate flat arrays at their actual
 * size (via memcpy), not as void *.  All internal functions receive
 * ksz/vsz so the implementation is fully type-erased at runtime.
 *
 *  Author:         John Viega, john@crashoverride.com
 */

#define N00B_USE_INTERNAL_API
#include <stdatomic.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/align.h"
#include "adt/dict.h"
#include "core/atomic.h"
#include "core/futex.h"
#include "core/epoch.h"

static inline n00b_uint128_t
compute_hash(_n00b_dict_internal_t *dict, void *key, uint32_t ksz)
{
    if (dict->skip_obj_hash) {
        if (dict->fn) {
            // Custom hash function (e.g., n00b_hash_cstring for char * keys).
            // Dereference the key pointer to get the stored value (e.g., the
            // char * itself) and pass that to the function.
            return dict->fn(*(void **)key);
        }
        // Default: hash the raw key contents at their actual size.
        return n00b_hash_raw(key, ksz);
    }
    else {
        return n00b_hash(*(void **)key, dict->fn);
    }
}

// 75%
static inline uint32_t
resize_threshold(uint32_t size)
{
    return size - (size >> 2) - 1;
}

static inline int
bucket_reserved(n00b_dict_bucket_t *b)
{
    return b->hv != (n00b_uint128_t)0;
}

static inline int
bucket_deleted(n00b_dict_bucket_t *b)
{
    return (n00b_atomic_load(&b->flags) & N00B_HT_FLAG_DELETED) != 0;
}

static inline uint32_t
new_dict_size(uint32_t last_bucket, uint32_t size)
{
    uint32_t table_size = last_bucket + 1;

    if (size >= table_size >> 1) {
        return table_size << 1;
    }
    if (size <= (N00B_DICT_MIN_SIZE << 2)) {
        return N00B_DICT_MIN_SIZE << 3;
    }
    if (size <= (table_size >> 2)) {
        return table_size >> 1;
    }

    return table_size;
}

static inline void *
dict_alloc_store_part(size_t size, n00b_alloc_opts_t *opts)
{
    return n00b_epoch_alloc(size, opts);
}

static inline void
dict_free_store_part(_n00b_dict_internal_t *d, void *ptr)
{
    (void)d;
    if (ptr == nullptr) {
        return;
    }
    n00b_retire(ptr);
}

static inline __n00b_internal_type_erased_store_t *
new_dict_store(_n00b_dict_internal_t *d, uint32_t alloc_items, uint32_t ksz, uint32_t vsz)
{
    // Every store part goes through n00b_epoch_alloc so the matching
    // n00b_retire() has the hidden header it needs. n00b_retire owns the policy:
    // use_epochs allocators defer reclamation, others free immediately.
    n00b_alloc_opts_t store_opts  = {.allocator = d->allocator};
    n00b_alloc_opts_t bucket_opts = {
        .allocator = d->allocator,
        .scan_kind = N00B_GC_SCAN_KIND_NONE,
    };
    n00b_alloc_opts_t key_opts = {
        .allocator = d->allocator,
        .scan_kind = (d->key_scan_kind == N00B_GC_SCAN_KIND_NONE)
                         ? N00B_GC_SCAN_KIND_NONE
                         : N00B_GC_SCAN_KIND_DEFAULT,
    };
    n00b_alloc_opts_t value_opts = {
        .allocator = d->allocator,
        .scan_kind = (d->value_scan_kind == N00B_GC_SCAN_KIND_NONE)
                         ? N00B_GC_SCAN_KIND_NONE
                         : N00B_GC_SCAN_KIND_DEFAULT,
    };

    __n00b_internal_type_erased_store_t *result
        = dict_alloc_store_part(sizeof(__n00b_internal_type_erased_store_t),
                                &store_opts);

    result->buckets = dict_alloc_store_part((size_t)alloc_items
                                                * sizeof(n00b_dict_bucket_t),
                                            &bucket_opts);
    result->keys   = dict_alloc_store_part((size_t)alloc_items * ksz, &key_opts);
    result->values = dict_alloc_store_part((size_t)alloc_items * vsz, &value_opts);

    result->last_slot = alloc_items - 1;
    result->threshold = resize_threshold(alloc_items);

    return result;
}

static inline void
unlock_bucket(n00b_dict_bucket_t *b)
{
    n00b_atomic_and(&b->flags, ~N00B_HT_FLAG_MUTEX);
}

bool
n00b_dict_internal_lock(_n00b_dict_internal_t *d, bool try, uint32_t *count)
{
    if (!d->lock) {
        // Private (unlocked) dict: no concurrent access, so skip the migration
        // futex + per-bucket COPYING/MOVING flag work. We MUST still report the
        // live entry count, though: the caller (dict_migrate) feeds it to
        // new_dict_size() and used_count. Leaving it unset (it was) sizes the
        // new store from count 0 -> a fixed 128 slots regardless of real size,
        // dropping entries on a grow. A plain count walk suffices here.
        __n00b_internal_type_erased_store_t *s
            = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
        uint32_t new_used = 0;
        for (uint32_t i = 0; i <= s->last_slot; i++) {
            n00b_dict_bucket_t *b = &s->buckets[i];
            new_used += (bucket_reserved(b) & !bucket_deleted(b));
        }
        *count = new_used;
        return true;
    }

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

    __n00b_internal_type_erased_store_t *s
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    n00b_dict_bucket_t *b;

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

    if (last_active != -1) {
        for (int i = first_active; i <= last_active; i++) {
            while (n00b_atomic_load(&s->buckets[i].flags) & N00B_HT_FLAG_MUTEX) {}
        }
    }

    *count = new_used;

    return true;
}

static void
dict_unlock_post_migrate(_n00b_dict_internal_t *d, __n00b_internal_type_erased_store_t *s)
{
    // Always install the migrated store — dict_migrate has already freed the old
    // one, so a private dict that skipped this would be left pointing at freed
    // memory (use-after-free). Only the migration-futex release is private-skippable.
    atomic_store(&d->store, (void **)s);

    if (!d->lock) {
        return;
    }

    atomic_store(&d->_migration_state, 0);

    if (n00b_atomic_load(&d->wait_ct)) {
        n00b_futex_wake(&d->_migration_state, true);
    }
}

void
n00b_dict_internal_unlock_post_copy(_n00b_dict_internal_t *d)
{
    if (!d->lock) {
        return;
    }

    __n00b_internal_type_erased_store_t *s
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

    for (uint32_t i = 0; i <= s->last_slot; i++) {
        n00b_atomic_and(&s->buckets[i].flags, ~N00B_HT_FLAG_COPYING);
    }

    atomic_store(&d->_migration_state, 0);

    if (n00b_atomic_load(&d->wait_ct)) {
        n00b_futex_wake(&d->_migration_state, true);
    }
}

static void
dict_migrate(_n00b_dict_internal_t *d, uint32_t ksz, uint32_t vsz)
{
    uint32_t nitems = 0;

    if (!n00b_dict_internal_lock(d, true, &nitems)) {
        n00b_atomic_add(&d->wait_ct, 1);
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        return;
    }

    __n00b_internal_type_erased_store_t *olds
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

    uint32_t                             alloc_items = new_dict_size(olds->last_slot, nitems);
    __n00b_internal_type_erased_store_t *news        = new_dict_store(d, alloc_items, ksz, vsz);
    uint32_t                             last        = news->last_slot;
    uint32_t                             bix;

    char *old_keys = (char *)olds->keys;
    char *old_vals = (char *)olds->values;
    char *new_keys = (char *)news->keys;
    char *new_vals = (char *)news->values;

    atomic_store(&news->used_count, nitems);

    for (uint32_t i = 0; i <= olds->last_slot; i++) {
        n00b_dict_bucket_t *bold = &olds->buckets[i];

        if (!bucket_reserved(bold) || bucket_deleted(bold)) {
            continue;
        }

        bix = bold->hv & last;

        for (uint32_t j = 0; j <= last; j++) {
            n00b_dict_bucket_t *bnew = &news->buckets[bix];

            if (!bucket_reserved(bnew)) {
                bnew->hv           = bold->hv;
                bnew->insert_order = bold->insert_order;

                memcpy(new_keys + bix * ksz, old_keys + i * ksz, ksz);
                memcpy(new_vals + bix * vsz, old_vals + i * vsz, vsz);
                break;
            }

            bix = (bix + 1) & news->last_slot;
        }
    }

    // Publish before retiring the old store. Locked callers that raced into
    // olds see COPYING/MOVING, wait for _migration_state to clear, then reload
    // d->store. Retiring first leaves d->store pointing at reclaimed memory for
    // non-epoch allocators such as allocator metadata pools.
    dict_unlock_post_migrate(d, news);

    dict_free_store_part(d, olds->buckets);
    dict_free_store_part(d, olds->keys);
    dict_free_store_part(d, olds->values);
    dict_free_store_part(d, olds);
}

// Returns the bucket if the key is found. May return a deleted bucket.
// `*store_pp` is updated to the store the returned bucket belongs to: a
// concurrent migration here reloads the store, and the caller MUST recompute
// keys_base/vals_base/bix from the store handed back (else bucket and store are
// from different generations -> out-of-bounds index).
static inline n00b_dict_bucket_t *
n00b_dict_readonly_scan(__n00b_internal_type_erased_store_t *store,
                        n00b_uint128_t                       hv)
{
    uint32_t last_slot = store->last_slot;
    uint32_t bix       = hv & last_slot;

    for (uint32_t i = 0; i <= last_slot; i++) {
        n00b_dict_bucket_t *cur = &store->buckets[bix];
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

static inline n00b_dict_bucket_t *
acquire_if_present(_n00b_dict_internal_t                *d,
                   __n00b_internal_type_erased_store_t **store_pp,
                   n00b_uint128_t                        hv)
{
    __n00b_internal_type_erased_store_t *store = *store_pp;
    uint32_t            last_slot;
    uint32_t            bix;
    uint32_t            flags;
    n00b_dict_bucket_t *cur;
    bool                miss = false;

    do {
        last_slot = store->last_slot;
        bix       = hv & last_slot;

        for (uint32_t i = 0; i <= last_slot; i++) {
            cur = &store->buckets[bix];

            do {
                flags = n00b_atomic_or(&cur->flags, N00B_HT_FLAG_MUTEX);
                if (flags & N00B_HT_FLAG_MOVING) {
                    if (!(flags & N00B_HT_FLAG_MUTEX)) {
                        n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
                    }
                    goto try_again;
                }
            } while (flags & N00B_HT_FLAG_MUTEX);

            if (cur->hv == hv) {
                *store_pp = store;
                return cur;
            }
            if (!bucket_reserved(cur)) {
                miss = true;
            }

            bix   = (bix + 1) & last_slot;
            flags = n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);

            if (miss) {
                *store_pp = store;
                return nullptr;
            }
        }

        *store_pp = store;
        return nullptr;

try_again:
        // Concurrent migration. Drop our epoch reservation so the migrator can
        // reclaim the old store, wait for it to finish, then re-acquire the
        // epoch and reload the store. The reloaded store is handed back via
        // *store_pp so the caller recomputes keys_base/vals_base/bix against it.
        n00b_epoch_yield();
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        n00b_epoch_acquire();
        store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    } while (true);
}

// `*store_pp` is updated to the store the returned bucket belongs to (see
// acquire_if_present). On a concurrent migration we drop+reacquire the epoch,
// reload the store, and the caller recomputes keys_base/vals_base/bix from it.
static inline n00b_dict_bucket_t *
acquire_or_add(_n00b_dict_internal_t                *d,
               __n00b_internal_type_erased_store_t **store_pp,
               n00b_uint128_t                        hv)
{
    __n00b_internal_type_erased_store_t *store = *store_pp;
    uint32_t            last_slot;
    uint32_t            bix;
    uint32_t            flags;
    n00b_dict_bucket_t *cur;

    do {
        last_slot = store->last_slot;
        bix       = hv & last_slot;

        for (uint32_t i = 0; i <= last_slot; i++) {
            cur = &store->buckets[bix];

            do {
                flags = n00b_atomic_or(&cur->flags, N00B_HT_FLAG_MUTEX);
                if (flags & (N00B_HT_FLAG_COPYING)) {
                    if (!(flags & N00B_HT_FLAG_MUTEX)) {
                        n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
                    }
                    goto try_again;
                }
            } while (flags & N00B_HT_FLAG_MUTEX);

            if (cur->hv == hv || !bucket_reserved(cur)) {
                *store_pp = store;
                return cur;
            }

            bix   = (bix + 1) & last_slot;
            flags = n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
        }

        *store_pp = store;
        return nullptr;

try_again:
        n00b_epoch_yield();
        n00b_futex_wait_for_value(&d->_migration_state, 0);
        n00b_epoch_acquire();
        store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    } while (true);
}

// Returns a pointer to the old value in the store, or nullptr if newly inserted.
void *
_n00b_dict_internal_put(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        void                  *value)
{
    n00b_epoch_acquire();

    n00b_uint128_t                       hv = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    void *result    = nullptr;
    void *owned_old = nullptr;

try_again:;
    n00b_dict_bucket_t *bucket      = acquire_or_add(d, &store, hv);
    bool                reset_epoch = false;

    char    *keys_base = (char *)store->keys;
    char    *vals_base = (char *)store->values;
    // We need the bucket index for array indexing.
    uint32_t bix       = (uint32_t)(bucket - store->buckets);

    if (!bucket->hv) {
        if (n00b_atomic_add(&store->used_count, 1) >= store->threshold) {
            unlock_bucket(bucket);
            dict_migrate(d, ksz, vsz);
            store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
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
            result = vals_base + bix * vsz;
            // copy_values: overwriting a live key replaces its owned pointee,
            // so capture the displaced value and free it after the lock drops.
            if (d->copy_values) {
                owned_old = *(void **)(vals_base + bix * vsz);
            }
        }
    }

    if (reset_epoch) {
        bucket->insert_order =
            (uint32_t)(n00b_atomic_add(&d->insertion_epoch, 1) + 1);
        n00b_atomic_add(&d->length, 1);
    }

    memcpy(keys_base + bix * ksz, key, ksz);
    memcpy(vals_base + bix * vsz, value, vsz);
    unlock_bucket(bucket);

    if (owned_old != nullptr && owned_old != *(void **)value) {
        n00b_free(owned_old);
    }

    n00b_epoch_yield();
    return result;
}

// Returns a pointer to the value in the store, or nullptr if not found.
void *
_n00b_dict_internal_get(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        void                  *copy_dst,
                        bool                  *found)
{
    n00b_epoch_acquire();

    n00b_uint128_t                       hv = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

    // Baked grammar-image dictionaries are scrubbed to a lockless/private
    // shape before marshal; reads must not set bucket mutex bits after the
    // containing section is protected read-only.
    bool readonly = !d->lock && d->allocator == nullptr;
    n00b_dict_bucket_t *b =
        readonly ? n00b_dict_readonly_scan(store, hv)
                 : acquire_if_present(d, &store, hv);

    if (!b) {
        if (found) {
            *found = false;
        }
        n00b_epoch_yield();
        return nullptr;
    }
    if (bucket_deleted(b)) {
        if (found) {
            *found = false;
        }
        if (!readonly) {
            unlock_bucket(b);
        }
        n00b_epoch_yield();
        return nullptr;
    }

    if (found) {
        *found = true;
    }

    char    *vals_base = (char *)store->values;
    uint32_t bix       = (uint32_t)(b - store->buckets);
    void    *result    = vals_base + bix * vsz;

    // copy_values dicts live on non-GC storage: the store can be freed by a
    // concurrent migrate the instant we release the bucket lock, so the borrowed
    // `result` pointer would dangle. Copy the value out while still holding the
    // bucket MUTEX (which dict_migrate drains before freeing the old store), and
    // hand back the caller's stable buffer instead.
    if (d->copy_values && copy_dst != nullptr) {
        memcpy(copy_dst, result, vsz);
        result = copy_dst;
    }

    if (!readonly) {
        unlock_bucket(b);
    }
    n00b_epoch_yield();
    return result;
}

bool
_n00b_dict_internal_add(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        void                  *value)
{
    n00b_epoch_acquire();
    n00b_uint128_t                       hv = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

try_again:;
    n00b_dict_bucket_t *bucket = acquire_or_add(d, &store, hv);

    char    *keys_base = (char *)store->keys;
    char    *vals_base = (char *)store->values;
    uint32_t bix       = (uint32_t)(bucket - store->buckets);

    if (!bucket->hv) {
        uint64_t used = n00b_atomic_add(&store->used_count, 1);
        if (used >= store->threshold) {
            unlock_bucket(bucket);
            dict_migrate(d, ksz, vsz);
            store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
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
            n00b_epoch_yield();
            return false;
        }
    }

    memcpy(keys_base + bix * ksz, key, ksz);
    memcpy(vals_base + bix * vsz, value, vsz);

    n00b_atomic_add(&d->length, 1);
    unlock_bucket(bucket);
    n00b_epoch_yield();

    return true;
}

bool
_n00b_dict_internal_remove(_n00b_dict_internal_t *d, uint32_t ksz, uint32_t vsz, void *key)
{
    (void)vsz;

    n00b_epoch_acquire();
    n00b_uint128_t                       hv = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    n00b_dict_bucket_t *b = acquire_if_present(d, &store, hv);

    if (!b) {
        n00b_epoch_yield();
        return false;
    }
    if (!bucket_reserved(b) || bucket_deleted(b)) {
        unlock_bucket(b);
        n00b_epoch_yield();
        return false;
    }

    // Zero out the value slot.
    char    *vals_base = (char *)store->values;
    uint32_t bix       = (uint32_t)(b - store->buckets);

    // copy_values dicts own the value's pointee: capture it before zeroing and
    // free it after the lock is released (deferred so we don't hold the bucket
    // MUTEX across n00b_free).
    void *owned = (d->copy_values) ? *(void **)(vals_base + bix * vsz) : nullptr;

    memset(vals_base + bix * vsz, 0, vsz);

    b->flags |= N00B_HT_FLAG_DELETED;
    n00b_atomic_add(&d->length, -1);
    unlock_bucket(b);
    n00b_epoch_yield();

    if (owned != nullptr) {
        n00b_free(owned);
    }

    return true;
}

bool
_n00b_dict_internal_cas(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        void                 **old_item_ptr,
                        void                  *new_item) _kargs
{
    bool null_old_means_absence = false;
    bool null_new_means_delete  = false;
}
{
    n00b_epoch_acquire();
    n00b_uint128_t                       hv = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    void               *old_item     = old_item_ptr ? *old_item_ptr : nullptr;
    bool                expect_empty = !old_item && null_old_means_absence;
    bool                delete_it    = !new_item && null_new_means_delete;
    n00b_dict_bucket_t *b;

    char    *keys_base;
    char    *vals_base;
    uint32_t bix;

    if (expect_empty) {
try_again:
        b         = acquire_or_add(d, &store, hv);
        bix       = (uint32_t)(b - store->buckets);
        keys_base = (char *)store->keys;
        vals_base = (char *)store->values;

        if (bucket_reserved(b) && !bucket_deleted(b)) {
            if (old_item_ptr) {
                *old_item_ptr = vals_base + bix * vsz;
            }
            unlock_bucket(b);
            n00b_epoch_yield();
            return false;
        }

        if (!bucket_deleted(b)) {
            if (n00b_atomic_add(&store->used_count, 1) >= store->threshold) {
                unlock_bucket(b);
                dict_migrate(d, ksz, vsz);
                store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
                goto try_again;
            }
        }

        b->hv = hv;
        b->flags &= ~N00B_HT_FLAG_DELETED;
        memcpy(keys_base + bix * ksz, key, ksz);
        memcpy(vals_base + bix * vsz, new_item, vsz);
        b->insert_order =
            (uint32_t)(n00b_atomic_add(&d->insertion_epoch, 1) + 1);
        n00b_atomic_add(&d->length, 1);
        unlock_bucket(b);
        n00b_epoch_yield();

        return true;
    }
    else {
        b = acquire_if_present(d, &store, hv);

        if (!b) {
            n00b_epoch_yield();
            return false;
        }

        bix           = (uint32_t)(b - store->buckets);
        vals_base     = (char *)store->values;
        void *cur_val = vals_base + bix * vsz;

        if (memcmp(cur_val, old_item, vsz) != 0) {
            *old_item_ptr = cur_val;
            unlock_bucket(b);
            n00b_epoch_yield();

            return false;
        }

        if (delete_it) {
            memset(cur_val, 0, vsz);
            b->flags |= N00B_HT_FLAG_DELETED;
            n00b_atomic_add(&d->length, -1);
        }
        else {
            memcpy(cur_val, new_item, vsz);
        }
        unlock_bucket(b);
        n00b_epoch_yield();

        return true;
    }
}

extern void
_n00b_dict_internal_init(_n00b_dict_internal_t *dict,
                         size_t                 ksz,
                         size_t                 vsz,
                         uint64_t               key_tid,
                         uint64_t               value_tid) _kargs
{
    n00b_allocator_t   *allocator       = nullptr;
    uint32_t            start_capacity  = N00B_DICT_MIN_SIZE;
    n00b_hash_fn        hash            = nullptr;
    bool                skip_obj_hash   = false;
    bool                locked          = true;
    bool                copy_values     = false;
    n00b_gc_scan_kind_t scan_kind       = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_cb_t   scan_cb         = nullptr;
    void               *scan_user       = nullptr;
    n00b_gc_scan_kind_t key_scan_kind   = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_kind_t value_scan_kind = N00B_GC_SCAN_KIND_DEFAULT;
}
{
    if (start_capacity < N00B_DICT_MIN_SIZE) {
        start_capacity = N00B_DICT_MIN_SIZE;
    }

    start_capacity = n00b_align_closest_pow2_ceil(start_capacity);
    n00b_ensure_allocator(allocator);

    if (key_scan_kind == N00B_GC_SCAN_KIND_DEFAULT) {
        key_scan_kind = scan_kind;
    }
    if (value_scan_kind == N00B_GC_SCAN_KIND_DEFAULT) {
        value_scan_kind = scan_kind;
    }

    *dict = (_n00b_dict_internal_t){
        .fn               = hash,
        .allocator        = allocator,
        .insertion_epoch  = 0,
        .wait_ct          = 0,
        .length           = 0,
        ._migration_state = 0,
        .lock             = locked,
        .copy_values      = copy_values,
        .skip_obj_hash    = skip_obj_hash,
        .scan_kind        = scan_kind,
        .scan_cb          = scan_cb,
        .scan_user        = scan_user,
        .key_scan_kind    = key_scan_kind,
        .value_scan_kind  = value_scan_kind,
        .key_tid          = key_tid,
        .value_tid        = value_tid,
    };

    __n00b_internal_type_erased_store_t *s = new_dict_store(dict, start_capacity, ksz, vsz);
    atomic_store(&dict->store, (void **)s);
}

n00b_size_t
n00b_dict_internal_len(_n00b_dict_internal_t *d)
{
    return n00b_atomic_load(&d->length);
}

void
_n00b_finalize_dict(_n00b_dict_internal_t *d)
{
    __n00b_internal_type_erased_store_t *s
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

    if (s) {
        dict_free_store_part(d, s->buckets);
        dict_free_store_part(d, s->keys);
        dict_free_store_part(d, s->values);
        dict_free_store_part(d, s);
    }
}

/*
 * Drop every live entry without reallocating the backing store.
 *
 * Buckets are POD (`hv == 0` is the empty-slot sentinel — see
 * `bucket_reserved`), so a single memset of the bucket array re-empties
 * the dict.  Keys/values stay as garbage and are overwritten on next put.
 *
 * Use this when a memo dict's lifetime is "one logical operation, then
 * thrown away" — reallocating a fresh dict per operation works
 * functionally but allocates ~1 KB of bucket/key/value storage on every
 * call; with the regex algebra's `mk_binary` issuing tens of thousands
 * of clears during compile of an adversarial intersection pattern that
 * adds up to multi-GB of GC-managed scratch.
 *
 * Not safe under concurrent mutation.
 */
extern void
_n00b_dict_internal_clear(_n00b_dict_internal_t *d)
{
    __n00b_internal_type_erased_store_t *s
        = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    if (!s)
        return;

    uint32_t cap = s->last_slot + 1u;
    memset(s->buckets, 0, (size_t)cap * sizeof(n00b_dict_bucket_t));
    n00b_atomic_store(&s->used_count, 0u);
    n00b_atomic_store(&d->length, (n00b_isize_t)0);
}

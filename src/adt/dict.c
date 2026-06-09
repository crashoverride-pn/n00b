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

static inline __n00b_internal_type_erased_store_t *
new_dict_store(_n00b_dict_internal_t *d, uint32_t alloc_items,
               uint32_t ksz, uint32_t vsz)
{
    __n00b_internal_type_erased_store_t *result;

    result = n00b_alloc_with_opts(__n00b_internal_type_erased_store_t,
                                  &(n00b_alloc_opts_t){.allocator = d->allocator});

    // Re-apply the dict's stored scan shapes on every migration/resize.
    // Buckets are POD (`n00b_dict_bucket_t` has no pointer fields), so they
    // must not be scanned; key/value arrays carry their own item policies.
    n00b_alloc_opts_t _bucket_opts = {
        .allocator = d->allocator,
        .scan_kind = N00B_GC_SCAN_KIND_NONE,
    };
    n00b_alloc_opts_t _key_opts = {
        .allocator = d->allocator,
        .scan_kind = d->key_scan_kind,
        .scan_cb   = d->scan_cb,
        .scan_user = d->scan_user,
    };
    n00b_alloc_opts_t _value_opts = {
        .allocator = d->allocator,
        .scan_kind = d->value_scan_kind,
        .scan_cb   = d->scan_cb,
        .scan_user = d->scan_user,
    };

    result->buckets = n00b_alloc_array_with_opts(n00b_dict_bucket_t,
                                                  alloc_items,
                                                  &_bucket_opts);
    result->keys    = n00b_alloc_size_with_opts(alloc_items, ksz, &_key_opts);
    result->values  = n00b_alloc_size_with_opts(alloc_items, vsz, &_value_opts);

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

    n00b_atomic_add(&d->wait_ct, -1);

    __n00b_internal_type_erased_store_t *s =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
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
dict_unlock_post_migrate(_n00b_dict_internal_t              *d,
                         __n00b_internal_type_erased_store_t *s)
{
    atomic_store(&d->store, (void **)s);
    atomic_store(&d->_migration_state, 0);

    if (n00b_atomic_load(&d->wait_ct)) {
        n00b_futex_wake(&d->_migration_state, true);
    }
}

void
n00b_dict_internal_unlock_post_copy(_n00b_dict_internal_t *d)
{
    __n00b_internal_type_erased_store_t *s =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

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

    __n00b_internal_type_erased_store_t *olds =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

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

    n00b_free(olds->buckets);
    n00b_free(olds->keys);
    n00b_free(olds->values);
    n00b_free(olds);

    dict_unlock_post_migrate(d, news);
}

// Returns the bucket if the key is found. May return a deleted bucket.
static inline n00b_dict_bucket_t *
acquire_if_present(_n00b_dict_internal_t              *d,
                   __n00b_internal_type_erased_store_t *store,
                   n00b_uint128_t                       hv)
{
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
                    goto try_again;
                }
            } while (flags & N00B_HT_FLAG_MUTEX);

            if (cur->hv == hv) {
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
        store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    } while (true);
}

static inline n00b_dict_bucket_t *
acquire_or_add(_n00b_dict_internal_t              *d,
               __n00b_internal_type_erased_store_t *store,
               n00b_uint128_t                       hv)
{
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
                    goto try_again;
                }
            } while (flags & N00B_HT_FLAG_MUTEX);

            if (cur->hv == hv || !bucket_reserved(cur)) {
                return cur;
            }

            bix   = (bix + 1) & last_slot;
            flags = n00b_atomic_and(&cur->flags, ~N00B_HT_FLAG_MUTEX);
        }

        return nullptr;

try_again:
        n00b_futex_wait_for_value(&d->_migration_state, 0);
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
    n00b_uint128_t                       hv     = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store  =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    void *result = nullptr;

try_again:;
    n00b_dict_bucket_t *bucket      = acquire_or_add(d, store, hv);
    bool                reset_epoch = false;

    char *keys_base = (char *)store->keys;
    char *vals_base = (char *)store->values;
    // We need the bucket index for array indexing.
    uint32_t bix = (uint32_t)(bucket - store->buckets);

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
            reset_epoch    = true;
            bucket->flags &= ~N00B_HT_FLAG_DELETED;
        }
        else {
            result = vals_base + bix * vsz;
        }
    }

    if (reset_epoch) {
        bucket->insert_order = (uint32_t)n00b_atomic_add(&store->used_count, 1);
        n00b_atomic_add(&d->length, 1);
    }

    memcpy(keys_base + bix * ksz, key, ksz);
    memcpy(vals_base + bix * vsz, value, vsz);
    unlock_bucket(bucket);

    return result;
}

// Returns a pointer to the value in the store, or nullptr if not found.
void *
_n00b_dict_internal_get(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        bool                  *found)
{
    n00b_uint128_t                       hv    = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    n00b_dict_bucket_t                  *b     = acquire_if_present(d, store, hv);

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
        unlock_bucket(b);
        return nullptr;
    }

    if (found) {
        *found = true;
    }

    char    *vals_base = (char *)store->values;
    uint32_t bix       = (uint32_t)(b - store->buckets);
    void    *result    = vals_base + bix * vsz;

    unlock_bucket(b);

    return result;
}

bool
_n00b_dict_internal_add(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        void                  *value)
{
    n00b_uint128_t                       hv    = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

try_again:;
    n00b_dict_bucket_t *bucket = acquire_or_add(d, store, hv);
    uint64_t            order  = -1;

    char    *keys_base = (char *)store->keys;
    char    *vals_base = (char *)store->values;
    uint32_t bix       = (uint32_t)(bucket - store->buckets);

    if (!bucket->hv) {
        order = n00b_atomic_add(&store->used_count, 1);
        if (order >= store->threshold) {
            unlock_bucket(bucket);
            dict_migrate(d, ksz, vsz);
            store = (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
            goto try_again;
        }
        bucket->hv           = hv;
        bucket->insert_order = order;
    }
    else {
        if (bucket_deleted(bucket)) {
            bucket->flags &= ~N00B_HT_FLAG_DELETED;
        }
        else {
            unlock_bucket(bucket);
            return false;
        }
    }

    memcpy(keys_base + bix * ksz, key, ksz);
    memcpy(vals_base + bix * vsz, value, vsz);

    n00b_atomic_add(&d->length, 1);
    unlock_bucket(bucket);

    return true;
}

bool
_n00b_dict_internal_remove(_n00b_dict_internal_t *d,
                           uint32_t               ksz,
                           uint32_t               vsz,
                           void                  *key)
{
    (void)vsz;

    n00b_uint128_t                       hv    = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    n00b_dict_bucket_t                  *b     = acquire_if_present(d, store, hv);

    if (!b) {
        return false;
    }
    if (!bucket_reserved(b) || bucket_deleted(b)) {
        unlock_bucket(b);
        return false;
    }

    // Zero out the value slot.
    char    *vals_base = (char *)store->values;
    uint32_t bix       = (uint32_t)(b - store->buckets);
    memset(vals_base + bix * vsz, 0, vsz);

    b->flags |= N00B_HT_FLAG_DELETED;
    n00b_atomic_add(&d->length, -1);
    unlock_bucket(b);

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
    n00b_uint128_t                       hv           = compute_hash(d, key, ksz);
    __n00b_internal_type_erased_store_t *store        =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    void *old_item     = old_item_ptr ? *old_item_ptr : nullptr;
    bool  expect_empty = !old_item && null_old_means_absence;
    bool  delete_it    = !new_item && null_new_means_delete;
    n00b_dict_bucket_t *b;

    char *keys_base;
    char *vals_base;
    uint32_t bix;

    if (expect_empty) {
try_again:
        b         = acquire_or_add(d, store, hv);
        bix       = (uint32_t)(b - store->buckets);
        keys_base = (char *)store->keys;
        vals_base = (char *)store->values;

        if (bucket_reserved(b) && !bucket_deleted(b)) {
            if (old_item_ptr) {
                *old_item_ptr = vals_base + bix * vsz;
            }
            unlock_bucket(b);
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
        b->insert_order = (uint32_t)n00b_atomic_add(&store->used_count, 1);
        n00b_atomic_add(&d->length, 1);
        unlock_bucket(b);

        return true;
    }
    else {
        b = acquire_if_present(d, store, hv);

        if (!b) {
            return false;
        }

        bix       = (uint32_t)(b - store->buckets);
        vals_base = (char *)store->values;
        void *cur_val = vals_base + bix * vsz;

        if (memcmp(cur_val, old_item, vsz) != 0) {
            *old_item_ptr = cur_val;
            unlock_bucket(b);
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
        return true;
    }
}

extern void
_n00b_dict_internal_init(_n00b_dict_internal_t *dict, size_t ksz, size_t vsz) _kargs
{
    n00b_allocator_t    *allocator      = nullptr;
    uint32_t             start_capacity = N00B_DICT_MIN_SIZE;
    n00b_hash_fn         hash           = nullptr;
    bool                 skip_obj_hash  = false;
    bool                 locked         = true;
    n00b_gc_scan_kind_t  scan_kind      = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_cb_t    scan_cb        = nullptr;
    void                *scan_user      = nullptr;
    n00b_gc_scan_kind_t  key_scan_kind  = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_kind_t  value_scan_kind = N00B_GC_SCAN_KIND_DEFAULT;
}
{
    if (start_capacity < N00B_DICT_MIN_SIZE) {
        start_capacity = N00B_DICT_MIN_SIZE;
    }

    start_capacity = n00b_align_closest_pow2_ceil(start_capacity);

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
        .lock             = locked
                               ? n00b_data_lock_new(.allocator = allocator)
                               : nullptr,
        .skip_obj_hash    = skip_obj_hash,
        .scan_kind        = scan_kind,
        .scan_cb          = scan_cb,
        .scan_user        = scan_user,
        .key_scan_kind    = key_scan_kind,
        .value_scan_kind  = value_scan_kind,
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
    __n00b_internal_type_erased_store_t *s =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);

    if (s) {
        n00b_free(s->buckets);
        n00b_free(s->keys);
        n00b_free(s->values);
        n00b_free(s);
    }
}

/*
 * Vtable-callable static initializer stub. The real dict image is built
 * by the `container_kind dict` path in `n00b-static-init-helper` (the
 * helper carries typed K/V metadata that the generic request shape
 * cannot represent). This stub keeps the type registry from rejecting
 * dicts as "unsupported-policy" and steers any direct caller toward
 * the right path.
 */
n00b_static_image_status_t
n00b_dict_static_init(n00b_static_image_builder_t *builder)
{
    return n00b_static_image_builder_fail(
        builder,
        N00B_STATIC_IMAGE_ERR_UNSUPPORTED_POLICY,
        r"n00b_dict_t static images are produced by the container helper's `container_kind dict` path, not by n00b_static_image_build()");
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
    __n00b_internal_type_erased_store_t *s =
        (__n00b_internal_type_erased_store_t *)n00b_atomic_load(&d->store);
    if (!s) return;

    uint32_t cap = s->last_slot + 1u;
    memset(s->buckets, 0, (size_t)cap * sizeof(n00b_dict_bucket_t));
    n00b_atomic_store(&s->used_count, 0u);
    n00b_atomic_store(&d->length, (n00b_isize_t)0);
}

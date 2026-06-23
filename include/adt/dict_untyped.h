/**
 * @file dict_untyped.h
 * @brief Lock-free, untyped hash table (dictionary).
 *
 * An open-addressing hash table with robin-hood probing, lock-free
 * reads, and a single-writer migration scheme.  Stores void* keys
 * and values.  Type-safe wrappers are built on top of this.
 */
#pragma once

#include <stdint.h>
#include "n00b.h"
#include "core/alloc.h"
#include "core/gc_map.h"
#include "core/hash.h"
#include "core/data_lock.h"

#define N00B_DICT_UNTYPED_MIN_SIZE_LOG 4
#define N00B_DICT_UNTYPED_MIN_SIZE     (1 << N00B_DICT_UNTYPED_MIN_SIZE_LOG)

#if !defined(N00B_DICT_MIN_SIZE_LOG)
#define N00B_DICT_MIN_SIZE_LOG 4
#endif
#define N00B_DICT_MIN_SIZE (1 << N00B_DICT_MIN_SIZE_LOG)

typedef int (*n00b_dict_sort_fn)(const void *, const void *);

struct n00b_dict_untyped_bucket_t {
    __int128_t       hv;
    void            *key;
    void            *value;
    uint32_t         insert_order;
    _Atomic uint32_t flags;
};

struct n00b_dict_untyped_store_t {
    uint32_t                   last_slot;
    uint32_t                   threshold;
    _Atomic uint64_t           used_count;
    n00b_dict_untyped_bucket_t buckets[];
};

struct n00b_dict_untyped_t {
    n00b_hash_fn                         fn;
    n00b_allocator_t                    *allocator;
    _Atomic(n00b_dict_untyped_store_t *) store;
    _Atomic uint32_t                     insertion_epoch;
    _Atomic n00b_isize_t                 wait_ct; // Waiting on migration
    _Atomic n00b_isize_t                 length;  // Items in dict
    // `_migration_state` is the migration coordination word for the
    // lock-free table-resize protocol, NOT a user-facing lock. The
    // user-facing rwlock lives in the `lock` slot below (locked by
    // default for `n00b_dict_untyped_init` with `locked = true`, nullptr
    // when `locked = false`; static dict images default to nullptr).
    n00b_futex_t                         _migration_state;
    n00b_rwlock_t                       *lock;
    uint32_t                             skip_obj_hash : 1;
    // GC scan shape for the bucket-array backing store.  Buckets hold
    // key+value pointer fields, so the default is DEFAULT (legacy
    // conservative scan).  Caller can override with a CALLBACK +
    // struct_field descriptor when the bucket layout warrants it.
    n00b_gc_scan_kind_t                  scan_kind;
    n00b_gc_scan_cb_t                    scan_cb;
    void                                *scan_user;
    uint32_t                             epoch_store : 1;
};

struct n00b_dict_untyped_item_t {
    void    *key;
    void    *value;
    uint64_t order;
};

/**
 * @brief Insert or update a key/value pair.
 * @param d     Dictionary to update.
 * @param key   Key to insert.
 * @param value Value to associate with the key.
 * @return The previous value, or nullptr if newly inserted.
 * @pre @p d has been initialized via n00b_dict_untyped_init().
 */
extern void *_n00b_dict_untyped_put(n00b_dict_untyped_t *d, void *key, void *value);

/**
 * @brief Look up a key.
 *
 * @param d     Dictionary to search.
 * @param key   Key to look up.
 * @param found Set to true iff the key was present; set to false otherwise.
 *              The `found` out-parameter — NOT the return value — is the
 *              authoritative presence signal. This is consistent with
 *              §5.4's "no nullptr-as-absent sentinel" rule: an untyped
 *              dict legitimately stores `nullptr` as a value, so a
 *              `nullptr` return is ambiguous in isolation.
 * @return      The stored value when @p found is set to true. When
 *              @p found is set to false the return value is
 *              **unspecified** and MUST be ignored. The stored value MAY
 *              legitimately be `nullptr` if `nullptr` was the value
 *              previously `_put`; callers MUST disambiguate via the
 *              `found` flag, not by comparing the return to `nullptr`.
 */
extern void *_n00b_dict_untyped_get(n00b_dict_untyped_t *d, void *key, bool *found);

/** @brief Replace an existing key's value.  @return false if key absent. */
extern bool  _n00b_dict_untyped_replace(n00b_dict_untyped_t *d, void *key, void *value);

/** @brief Insert only if key is absent.  @return false if key exists. */
extern bool  _n00b_dict_untyped_add(n00b_dict_untyped_t *d, void *key, void *value);

/** @brief Remove a key.  @return false if key not found. */
extern bool  _n00b_dict_untyped_remove(n00b_dict_untyped_t *d, void *key);

/**
 * @brief Compare-and-swap on a dictionary entry.
 * @param d              Dictionary.
 * @param key            Key to operate on.
 * @param old_item_ptr   Pointer to expected old value (updated on failure).
 * @param new_item       New value to store.
 * @return               true on success.
 *
 * @kw null_old_means_absence  If true, a nullptr old_item_ptr means "expect empty slot".
 * @kw null_new_means_delete   If true, a nullptr new_item means "delete the entry".
 */
extern bool
_n00b_dict_untyped_cas(n00b_dict_untyped_t *d,
                       void                *key,
                       void               **old_item_ptr,
                       void                *new_item) _kargs
{
    bool null_old_means_absence = false;
    bool null_new_means_delete  = false;
};

#define n00b_dict_untyped_put(d, k, v)                                                         \
    _n00b_dict_untyped_put(d, ((void *)(uintptr_t)k), ((void *)(uintptr_t)v))
#define n00b_dict_untyped_get(d, k, b) _n00b_dict_untyped_get(d, ((void *)(uintptr_t)k), b)
#define n00b_dict_untyped_replace(d, k, v)                                                     \
    _n00b_dict_untyped_replace(d, ((void *)(uintptr_t)k), ((void *)(uintptr_t)v))
#define n00b_dict_untyped_add(d, k, v)                                                         \
    _n00b_dict_untyped_add(d, ((void *)(uintptr_t)k), ((void *)(uintptr_t)v))

#define n00b_dict_untyped_remove(d, k) _n00b_dict_untyped_remove(d, ((void *)(uintptr_t)k))

#define n00b_dict_untyped_cas(d, k, o, n, ...)                                                  \
    _n00b_dict_untyped_cas(d,                                                                  \
                           ((void *)(uintptr_t)k),                                               \
                           ((void *)(uintptr_t)o),                                               \
                           ((void *)(uintptr_t)n)                                                \
                           __VA_OPT__(, __VA_ARGS__))

/**
 * @brief Initialize an untyped dictionary.
 * @param dict Dictionary to initialize.
 *
 * @kw start_capacity Initial bucket count (default N00B_DICT_MIN_SIZE).
 * @kw allocator      Allocator for internal storage (nullptr = runtime default).
 * @kw hash           Hash function for keys (nullptr = n00b_hash_word).
 * @kw skip_obj_hash  If true, use the raw key bits instead of calling the hash function.
 * @kw locked         If true (default), allocate a fresh rwlock for the
 *                    `lock` slot; if false, leave `lock` nullptr (private,
 *                    single-thread use).
 */
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
};

/**
 * @brief Check whether a key exists in the dictionary.
 * @param d Dictionary to search.
 * @param v Key to look for.
 * @return  true if the key is present.
 */
static inline bool
n00b_dict_untyped_contains(n00b_dict_untyped_t *d, void *v)
{
    bool found;

    n00b_dict_untyped_get(d, v, &found);

    return found;
}

#ifdef N00B_USE_INTERNAL_API
/**
 * @brief Acquire the dictionary's migration mutex.
 * @param d     Dictionary to lock.
 * @param try   If true, return immediately on failure.
 * @param count Output: migration epoch when lock was acquired.
 * @return      true if lock was acquired.
 */
extern bool n00b_dict_untyped_lock(n00b_dict_untyped_t *d, bool try, uint32_t *count);

/** @brief Unlock the dictionary after a store migration. */
extern void n00b_dict_untyped_unlock_post_copy(n00b_dict_untyped_t *d);

#define N00B_HT_FLAG_MUTEX   1
#define N00B_HT_FLAG_COPYING 2
#define N00B_HT_FLAG_DELETED 4
#define N00B_HT_FLAG_MOVING  8

#endif

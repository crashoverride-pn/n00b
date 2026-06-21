#pragma once

#include "n00b.h"
#include "core/macros.h"
#include "core/alloc.h"
#include "core/epoch.h"
#include "core/gc_map.h"
#include "core/hash.h"
#include "core/static_image.h"

#include <stdint.h>
#include <assert.h>

#if !defined(N00B_DICT_MIN_SIZE_LOG)
#define N00B_DICT_MIN_SIZE_LOG 4
#define N00B_DICT_MIN_SIZE     (1 << N00B_DICT_MIN_SIZE_LOG)
#endif

#define n00b_dict_store_tid(k, v) typeid("store", k, v)
#define n00b_dict_store_t(k, v)                                                                \
    _generic_struct n00b_dict_store_tid(k, v)                                                  \
    {                                                                                          \
        uint32_t            last_slot;                                                         \
        uint32_t            threshold;                                                         \
        _Atomic uint32_t    used_count;                                                        \
        n00b_dict_bucket_t *buckets;                                                           \
        k                  *keys;                                                              \
        v                  *values;                                                            \
    }

typedef struct n00b_dict_bucket_t {
    n00b_uint128_t   hv;
    uint32_t         insert_order;
    _Atomic uint32_t flags; // Mutex, deleted.
} n00b_dict_bucket_t;

// NOTE: this layout is byte-exact with what rocs persists/maps (see the
// static_asserts in src/rocs/map.c). Do NOT add fields. Epoch-arena dicts
// carry their n00b_epoch_hdr_t as a HIDDEN prefix immediately before this
// struct (see new_dict_store / store_epoch_hdr in src/adt/dict.c), so the
// reclamation header never perturbs the persisted store layout.
typedef struct __n00b_internal_type_erased_store_t {
    uint32_t            last_slot;
    uint32_t            threshold;
    _Atomic uint32_t    used_count;
    n00b_dict_bucket_t *buckets;
    void              **keys;
    void              **values;
} __n00b_internal_type_erased_store_t;

#define n00b_dict_tid(k, v) typeid("n00b_dict", k, v)

// `_migration_state` is the migration coordination word for the custom rw-lock
// table-resize protocol, NOT a user-facing lock. The runtime futex bits
// gate writers during a store migration; readers do not consult it. The
// user-facing rwlock lives in the `lock` slot below and follows the
// WP-010 list precedent (locked by default for `n00b_dict_new`, nullptr
// for `n00b_dict_new_private`; static dict images default to nullptr).
//
// The `scan_kind` / `scan_cb` / `scan_user` triple is the legacy default GC
// scan shape for key/value backing arrays. Buckets are always POD and are
// always allocated with `N00B_GC_SCAN_KIND_NONE`; scanning bucket hashes as
// pointers is both unnecessary and unsafe for marshalable dictionaries.
//
// `key_scan_kind` and `value_scan_kind` let typed dictionaries with mixed
// POD/pointer storage describe their two item arrays independently while still
// using the existing dict implementation and resize path.
#define N00B_BASE_DICT_FIELDS                                                                  \
    n00b_hash_fn         fn;                                                                   \
    n00b_allocator_t    *allocator;                                                            \
    _Atomic uint32_t     insertion_epoch;                                                      \
    _Atomic n00b_isize_t wait_ct;                                                              \
    _Atomic n00b_isize_t length;                                                               \
    n00b_futex_t         _migration_state;                                                     \
    uint8_t              cache         : 1;                                                    \
    uint8_t              skip_obj_hash : 1;                                                    \
    uint8_t              lock          : 1;                                                    \
    uint8_t              copy_values   : 1;                                                    \
    n00b_gc_scan_kind_t  scan_kind;                                                            \
    n00b_gc_scan_cb_t    scan_cb;                                                              \
    void                *scan_user;                                                            \
    n00b_gc_scan_kind_t  key_scan_kind;                                                        \
    n00b_gc_scan_kind_t  value_scan_kind;                                                      \
    uint64_t             key_tid;                                                              \
    uint64_t             value_tid;

// The _n00b_dict_internal_t typedef is provided by n00b.h (opaque forward decl,
// mirroring n00b_dict_untyped_t) so foundational headers like core/alloc_base.h
// can hold an opaque pointer to it. Define only the struct body here.
struct _n00b_dict_internal_t {
    _Atomic(void **) store;
    N00B_BASE_DICT_FIELDS
};

#define n00b_dict_t(k, v)                                                                      \
    _generic_struct n00b_dict_tid(k, v)                                                        \
    {                                                                                          \
        _Atomic(n00b_dict_store_t(k, v) *) store;                                              \
        N00B_BASE_DICT_FIELDS                                                                  \
    }

// Structural type checking, ha!
#define _n00b_dict_structural_check(dict_ptr)                                                  \
    static_assert(sizeof(*(dict_ptr)) == sizeof(_n00b_dict_internal_t));                       \
    static_assert(offsetof(typeof(*(dict_ptr)), store)                                         \
                  == offsetof(_n00b_dict_internal_t, store));                                  \
    static_assert(offsetof(typeof(*(dict_ptr)), fn) == offsetof(_n00b_dict_internal_t, fn));   \
    static_assert(offsetof(typeof(*(dict_ptr)), allocator)                                     \
                  == offsetof(_n00b_dict_internal_t, allocator));                              \
    static_assert(offsetof(typeof(*(dict_ptr)), insertion_epoch)                               \
                  == offsetof(_n00b_dict_internal_t, insertion_epoch));                        \
    static_assert(offsetof(typeof(*(dict_ptr)), wait_ct)                                       \
                  == offsetof(_n00b_dict_internal_t, wait_ct));                                \
    static_assert(offsetof(typeof(*(dict_ptr)), length)                                        \
                  == offsetof(_n00b_dict_internal_t, length));                                 \
    static_assert(offsetof(typeof(*(dict_ptr)), _migration_state)                              \
                  == offsetof(_n00b_dict_internal_t, _migration_state))

#define _n00b_wrap_dict_call(opname, dict_ptr, ...)                                            \
    ({                                                                                         \
        _n00b_dict_structural_check(dict_ptr);                                                 \
        _n00b_dict_internal_##opname((_n00b_dict_internal_t *)(dict_ptr),                      \
                                     sizeof((dict_ptr)->store->keys[0]),                       \
                                     sizeof((dict_ptr)->store->values[0])                      \
                                         __VA_OPT__(, __VA_ARGS__));                           \
    })

#define _n00b_ditem_type(dict_ptr, field_name) typeof((dict_ptr)->store->field_name[0])

// init is special: besides the key/value element sizes it threads the key/value
// element typehashes so the backing arrays are allocated typed (not erased).
#define n00b_dict_init(dict, ...)                                                              \
    ({                                                                                         \
        _n00b_dict_structural_check(dict);                                                     \
        _n00b_dict_internal_init((_n00b_dict_internal_t *)(dict),                              \
                                 sizeof((dict)->store->keys[0]),                               \
                                 sizeof((dict)->store->values[0]),                             \
                                 typehash(_n00b_ditem_type(dict, keys) *),                     \
                                 typehash(_n00b_ditem_type(dict, values) *)                    \
                                     __VA_OPT__(, __VA_ARGS__));                               \
    })

/**
 * @brief Allocate and initialize a new typed dict (locked by default).
 *
 * For dict-specific kwargs (`.start_capacity`, `.hash`,
 * `.skip_obj_hash`), call `n00b_dict_init` separately after this macro
 * or pair with `n00b_alloc` directly. This `_new` surface accepts only
 * fields of `n00b_alloc_opts_t`.
 *
 * @param K    Key type.
 * @param V    Value type.
 * @param ...  Optional `n00b_alloc_opts_t` fields (allocator, scan_*,
 *             finalizer, etc.).
 */
#define n00b_dict_new(K, V, ...)                                                               \
    ({                                                                                         \
        n00b_alloc_opts_t _bl_o  = (n00b_alloc_opts_t){__VA_OPT__(__VA_ARGS__)};               \
        n00b_dict_t(K, V) *_bl_d = n00b_alloc_with_opts(n00b_dict_t(K, V), &_bl_o);            \
        n00b_dict_init(_bl_d,                                                                  \
                       .locked    = true,                                                      \
                       .allocator = _bl_o.allocator,                                           \
                       .scan_kind = _bl_o.scan_kind,                                           \
                       .scan_cb   = _bl_o.scan_cb,                                             \
                       .scan_user = _bl_o.scan_user);                                          \
        _bl_d;                                                                                 \
    })

/// @brief Allocate and initialize a new typed dict with no rwlock (private).
/// See `n00b_dict_new` for kwarg semantics.
#define n00b_dict_new_private(K, V, ...)                                                       \
    ({                                                                                         \
        n00b_alloc_opts_t _bl_o  = (n00b_alloc_opts_t){__VA_OPT__(__VA_ARGS__)};               \
        n00b_dict_t(K, V) *_bl_d = n00b_alloc_with_opts(n00b_dict_t(K, V), &_bl_o);            \
        n00b_dict_init(_bl_d,                                                                  \
                       .locked    = false,                                                     \
                       .allocator = _bl_o.allocator,                                           \
                       .scan_kind = _bl_o.scan_kind,                                           \
                       .scan_cb   = _bl_o.scan_cb,                                             \
                       .scan_user = _bl_o.scan_user);                                          \
        _bl_d;                                                                                 \
    })

/**
 * @brief Drop every entry in-place without reallocating the backing store.
 *
 * Use for memo dicts whose lifetime is "one logical operation, then thrown
 * away": clears the dict in O(buckets) without freeing/reallocating the
 * bucket/key/value arrays.  Not safe under concurrent mutation.
 */
#define n00b_dict_clear(dict)                                                                  \
    ({                                                                                         \
        _n00b_dict_structural_check(dict);                                                     \
        _n00b_dict_internal_clear((_n00b_dict_internal_t *)(dict));                            \
    })

#define n00b_dict_put(dict, key, value) _n00b_wrap_dict_call(put, dict, &(key), &(value))
#define n00b_dict_get(dict, key, found)                                                        \
    ({                                                                                         \
        _n00b_ditem_type(dict, values) _dg_zero = (_n00b_ditem_type(dict, values)){0};         \
        void *_dg_vp = _n00b_wrap_dict_call(get, dict, &(key), &_dg_zero, found);              \
        _dg_vp ? *(_n00b_ditem_type(dict, values) *)_dg_vp : _dg_zero;                         \
    })
#define n00b_dict_add(dict, key, value) _n00b_wrap_dict_call(add, dict, &(key), &(value))
#define n00b_dict_remove(dict, key)     _n00b_wrap_dict_call(remove, dict, &(key))
#define n00b_dict_cas(dict, key, old, new, ...)                                                \
    _n00b_wrap_dict_call(cas, dict, &(key), old, new __VA_OPT__(, __VA_ARGS__))

#define n00b_dict_contains(dict, key)                                                          \
    ({                                                                                         \
        bool found;                                                                            \
        (void)n00b_dict_get(dict, key, &found);                                                \
        found;                                                                                 \
    })

/**
 * @brief Iterate over all live entries in a typed dictionary.
 *
 * @param dict   Pointer to the typed dict.
 * @param kvar   Variable name to bind each key.
 * @param vvar   Variable name to bind each value.
 * @param body   Statement or block to execute per entry.
 *
 * Example:
 *     n00b_dict_foreach(my_dict, k, v, {
 *         n00b_printf("key=«#» val=«#»\n", (long long)k, v);
 *     });
 */
#define n00b_dict_foreach(dict, kvar, vvar, body)                                              \
    do {                                                                                       \
        _n00b_dict_structural_check(dict);                                                     \
        n00b_epoch_acquire();                                                                  \
        _n00b_dict_internal_t               *_df_d = (_n00b_dict_internal_t *)(dict);          \
        __n00b_internal_type_erased_store_t *_df_s = (__n00b_internal_type_erased_store_t *)   \
            atomic_load_explicit(&_df_d->store, memory_order_acquire);                         \
        if (_df_s) {                                                                           \
            typedef _n00b_ditem_type(dict, keys) _df_kt;                                       \
            typedef _n00b_ditem_type(dict, values) _df_vt;                                     \
            _df_kt *_df_keys = (_df_kt *)_df_s->keys;                                          \
            _df_vt *_df_vals = (_df_vt *)_df_s->values;                                        \
            for (uint32_t _df_i = 0; _df_i <= _df_s->last_slot; _df_i++) {                     \
                n00b_dict_bucket_t *_df_b = &_df_s->buckets[_df_i];                            \
                if (_df_b->hv != (n00b_uint128_t)0                                             \
                    && !(atomic_load_explicit(&_df_b->flags, memory_order_relaxed)             \
                         & N00B_HT_FLAG_DELETED)) {                                            \
                    _df_kt kvar = _df_keys[_df_i];                                             \
                    _df_vt vvar = _df_vals[_df_i];                                             \
                    (void)vvar;                                                                \
                    body                                                                       \
                }                                                                              \
            }                                                                                  \
        }                                                                                      \
        n00b_epoch_yield();                                                                    \
    } while (0)

// This private interface (from here, down) is untyped, and thus internal.
extern void        _n00b_finalize_dict(_n00b_dict_internal_t *);
extern n00b_size_t n00b_dict_internal_len(_n00b_dict_internal_t *);
extern void        _n00b_dict_internal_clear(_n00b_dict_internal_t *);

/**
 * @brief Initialize a typed dictionary.
 * @param dict Dictionary to initialize.
 *
 * @kw start_capacity Initial bucket count (default N00B_DICT_MIN_SIZE).
 * @kw allocator      Allocator for internal storage (nullptr = runtime default).
 * @kw hash           Hash function for keys (nullptr = n00b_hash_word).
 * @kw skip_obj_hash  If true, use the raw key bits instead of calling the hash function.
 * @kw locked         Single threaded; no need to lock mgrations.
 * @kw scan_kind      Legacy default scan policy for key/value backing arrays.
 * @kw key_scan_kind  Optional key-array scan policy. Defaults to `scan_kind`.
 * @kw value_scan_kind Optional value-array scan policy. Defaults to `scan_kind`.
 * @kw copy_values    The dict's values live in non-GC storage it cannot borrow
 *                    across reclamation. When set, `get` copies the value out
 *                    from under the bucket lock (so a concurrent migrate that
 *                    frees the old store cannot dangle the returned pointer),
 *                    and `n00b_free()` is called on the stored value pointer on
 *                    deletion AND on overwrite. The default (false) is the GC
 *                    case, where borrowing is safe and the GC reclaims values.
 *                    Not freed on migrate (the value pointers move to the new
 *                    store) or on finalize (wholesale pool reclaim handles it).
 */
extern void
_n00b_dict_internal_init(_n00b_dict_internal_t *,
                         size_t   ksz,
                         size_t   vsz,
                         uint64_t key_tid,
                         uint64_t value_tid) _kargs
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
};

extern void *_n00b_dict_internal_put(_n00b_dict_internal_t *d,
                                     uint32_t               ksz,
                                     uint32_t               vsz,
                                     void                  *key,
                                     void                  *value);
extern void *_n00b_dict_internal_get(_n00b_dict_internal_t *d,
                                     uint32_t               ksz,
                                     uint32_t               vsz,
                                     void                  *key,
                                     void                  *copy_dst,
                                     bool                  *found);
extern bool  _n00b_dict_internal_add(_n00b_dict_internal_t *d,
                                     uint32_t               ksz,
                                     uint32_t               vsz,
                                     void                  *key,
                                     void                  *value);
extern bool
_n00b_dict_internal_remove(_n00b_dict_internal_t *d, uint32_t ksz, uint32_t vsz, void *key);

extern bool
_n00b_dict_internal_cas(_n00b_dict_internal_t *d,
                        uint32_t               ksz,
                        uint32_t               vsz,
                        void                  *key,
                        void                 **old_item_ptr,
                        void                  *new_item) _kargs
{
    bool null_old_means_absence = false;
    bool null_new_means_delete  = false;
};

#define N00B_HT_FLAG_MUTEX   1
#define N00B_HT_FLAG_COPYING 2
#define N00B_HT_FLAG_DELETED 4
#define N00B_HT_FLAG_MOVING  8

/**
 * @brief Vtable-callable static initializer stub for dict types.
 *
 * The real dict static image is produced by the build-time helper's
 * `container_kind dict` path, which carries typed key/value metadata
 * (typenames, scan info, paired key/value records) that the generic
 * `n00b_static_image_request_t` does not represent.  This stub exists
 * so the type registry accepts dicts as constructor-image-policy types
 * and so a mistakenly-routed direct `n00b_static_image_build()` call
 * surfaces a targeted diagnostic instead of an `unsupported-policy`
 * rejection.
 *
 * @param builder The static image builder.
 * @return        Always fails with `N00B_STATIC_IMAGE_ERR_UNSUPPORTED_POLICY`
 *                and a clear error message pointing at the helper path.
 */
extern n00b_static_image_status_t n00b_dict_static_init(n00b_static_image_builder_t *builder);

#ifdef N00B_USE_INTERNAL_API
/**
 * @brief Acquire the dictionary's migration mutex.
 * @param d     Dictionary to lock.
 * @param try   If true, return immediately on failure.
 * @param count Output: migration epoch when lock was acquired.
 * @return      true if lock was acquired.
 */
extern bool n00b_dict_internal_lock(_n00b_dict_internal_t *d, bool try, uint32_t *count);

/** @brief Unlock the dictionary after a store migration. */
extern void n00b_dict_internal_unlock_post_copy(_n00b_dict_internal_t *d);

#endif

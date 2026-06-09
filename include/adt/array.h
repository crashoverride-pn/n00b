/**
 * @file array.h
 * @brief Type-safe dynamic array (growable array).
 *
 * @c n00b_array_t(T) provides a growable array that automatically resizes.
 * Type safety is enforced through ncc's @c typeid().
 *
 * All macros take lvalues directly (value semantics). They mutate
 * the struct in-place via statement expressions.
 *
 * **Thread safety:** Arrays are **not locked by default**.  Unlike
 * @c n00b_list_t and @c n00b_stack_t (which create a rwlock on
 * construction), arrays are intended for single-owner or
 * caller-managed synchronization.  Use @c n00b_array_new_locked()
 * if the array will be shared between threads.
 *
 * Usage:
 * @code
 *     n00b_array_t(int) arr = n00b_array_new(int, 16);
 *     n00b_array_set(arr, 0, 42);
 *     int x = n00b_array_get(arr, 0);
 *     n00b_array_free(arr);
 * @endcode
 */
#pragma once

#include <assert.h>

#include "core/macros.h"
#include "core/gc_map.h"
#include "core/data_lock.h"

// ============================================================================
// Type definition
// ============================================================================

#define n00b_array_tid(T) typeid("array", T)
/**
 * @brief Declare an array type for element type @p T.
 * @param T  Element type.
 *
 * Struct layout: @c { T *data; size_t len; size_t cap; n00b_rwlock_t *lock; }
 */
#define n00b_array_t(T)                                                                        \
    _generic_struct n00b_array_tid(T) {                                                        \
        T                   *data;                                                             \
        size_t               len;                                                              \
        size_t               cap;                                                              \
        n00b_rwlock_t       *lock;                                                             \
        n00b_allocator_t    *allocator;                                                        \
        n00b_gc_scan_kind_t  scan_kind;                                                        \
        n00b_gc_scan_cb_t    scan_cb;                                                          \
        void                *scan_user;                                                        \
    }

// ============================================================================
// Internal helpers
// ============================================================================

// ============================================================================
// Construction / destruction
// ============================================================================

/**
 * @brief Create a new array with the given capacity.
 *
 * Arrays are **unlocked by default**.  Pass `true` as the third argument
 * (or use the `_locked` compat macro) for a locked array.
 *
 * @param T       Element type.
 * @param N       Initial capacity.
 * @param locked  Whether to create a rwlock (default: false).
 * @param ...     Optional allocator.
 */
#define n00b_array_new(T, N, ...)              _n00b_array_new_sel(T, N, false, ##__VA_ARGS__)
#define n00b_array_new_locked(T, N, ...)       _n00b_array_new_sel(T, N, true, ##__VA_ARGS__) /**< @deprecated Use n00b_array_new(T, N, true) */

#define _n00b_array_new_sel(T, N, locked, ...)                                                 \
    ({                                                                                         \
        n00b_alloc_opts_t _bl_o = (n00b_alloc_opts_t){__VA_ARGS__};                            \
        (n00b_array_t(T)){                                                                     \
            .len       = 0,                                                                    \
            .cap       = N,                                                                    \
            .data      = n00b_alloc_array_with_opts(T, (N), &_bl_o),                           \
            .lock      = (locked) ? n00b_data_lock_new() : nullptr,                            \
            .allocator = _bl_o.allocator,                                                      \
            .scan_kind = _bl_o.scan_kind,                                                      \
            .scan_cb   = _bl_o.scan_cb,                                                        \
            .scan_user = _bl_o.scan_user,                                                      \
        };                                                                                     \
    })

/**
 * @brief Heap-allocate a array (returns pointer).
 * @param T     Element type.
 * @param ...   Optional initial capacity.
 */
#define n00b_array_checked_ptr(T, N, P)                                                        \
    ({                                                                                         \
        (n00b_array_t(T)){                                                                     \
            .len  = 0,                                                                         \
            .cap  = N,                                                                         \
            .data = P,                                                                         \
            .lock = nullptr,                                                                   \
        };                                                                                     \
    })

/**
 * @brief Free the backing storage of an array and zero the struct.
 * @param x  Array (lvalue).
 */
#define n00b_array_free(x)                                                                     \
    ({                                                                                         \
        auto _bl_ap = &(x);                                                                    \
        if (_bl_ap->data) {                                                                    \
            n00b_free(_bl_ap->data);                                                           \
        }                                                                                      \
        *_bl_ap = (typeof(x)){};                                                               \
    })

// ============================================================================
// Access
// ============================================================================

/**
 * @brief Get element at index (bounds-checked, aborts on OOB).
 * @param x  Array (lvalue).
 * @param i  Index.
 * @pre @p i < array length.
 */
#define n00b_array_get(x, i)                                                                   \
    ({                                                                                         \
        auto _bl_ap = &(x);                                                                    \
        n00b_data_read_lock(_bl_ap->lock);                                                     \
        size_t _bl_i = (i);                                                                    \
        if (_bl_i >= _bl_ap->len) {                                                            \
            n00b_data_unlock(_bl_ap->lock);                                                    \
            abort();                                                                           \
        }                                                                                      \
        typeof(*_bl_ap->data) _bl_r = _bl_ap->data[_bl_i];                                     \
        n00b_data_unlock(_bl_ap->lock);                                                        \
        _bl_r;                                                                                 \
    })

/**
 * @brief Set element at index (bounds-checked, aborts on OOB).
 * @param x    Array (lvalue).
 * @param i    Index.
 * @param val  Value to assign.
 * @pre @p i < array capacity.
 */
#define n00b_array_set(x, i, val)                                                              \
    ({                                                                                         \
        auto _bl_ap = &(x);                                                                    \
        n00b_data_write_lock(_bl_ap->lock);                                                    \
        size_t _bl_i = (i);                                                                    \
        if (_bl_i >= _bl_ap->cap) {                                                            \
            n00b_data_unlock(_bl_ap->lock);                                                    \
            abort();                                                                           \
        }                                                                                      \
        if (_bl_i >= _bl_ap->len) {                                                            \
            _bl_ap->len = _bl_i + 1;                                                           \
        }                                                                                      \
        _bl_ap->data[_bl_i] = (val);                                                           \
        n00b_data_unlock(_bl_ap->lock);                                                        \
    })

/** @brief Number of elements in the array. */
#define n00b_array_len(x)                                                                      \
    ({                                                                                         \
        auto _bl_ap = &(x);                                                                    \
        n00b_data_read_lock(_bl_ap->lock);                                                     \
        size_t _bl_r = _bl_ap->len;                                                            \
        n00b_data_unlock(_bl_ap->lock);                                                        \
        _bl_r;                                                                                 \
    })

/** @brief Allocated capacity. */
#define n00b_array_cap(x)                                                                      \
    ({                                                                                         \
        auto _bl_ap = &(x);                                                                    \
        n00b_data_read_lock(_bl_ap->lock);                                                     \
        size_t _bl_r = _bl_ap->cap;                                                            \
        n00b_data_unlock(_bl_ap->lock);                                                        \
        _bl_r;                                                                                 \
    })

/**
 * @brief Clone an array (deep copy of data buffer).
 * @param x  Array (lvalue).
 * @return A new array with copied data.
 */
#define n00b_array_clone(x)                                                                    \
    ({                                                                                         \
        auto _bl_sp = &(x);                                                                    \
        typeof(x) _bl_copy = (typeof(x)){                                                      \
            .len       = _bl_sp->len,                                                          \
            .cap       = _bl_sp->cap,                                                          \
            .data      = n00b_alloc_size_with_opts(_bl_sp->cap, sizeof(_bl_sp->data[0]),          \
                             &(n00b_alloc_opts_t){                                             \
                                 .allocator = _bl_sp->allocator,                               \
                                 .scan_kind = _bl_sp->scan_kind,                               \
                                 .scan_cb   = _bl_sp->scan_cb,                                 \
                                 .scan_user = _bl_sp->scan_user,                               \
                             }),                                                               \
            .lock      = _bl_sp->lock ? n00b_data_lock_new() : nullptr,                        \
            .allocator = _bl_sp->allocator,                                                    \
            .scan_kind = _bl_sp->scan_kind,                                                    \
            .scan_cb   = _bl_sp->scan_cb,                                                      \
            .scan_user = _bl_sp->scan_user,                                                    \
        };                                                                                     \
        memcpy(_bl_copy.data, _bl_sp->data, _bl_sp->len * sizeof(_bl_sp->data[0]));            \
        _bl_copy;                                                                              \
    })

/**
 * @brief Iterate over array elements (lock-aware).
 *
 * Acquires a shared read lock before iteration and releases it
 * afterwards.  If the array has no lock (lock == nullptr), the
 * lock/unlock calls are no-ops and the loop runs at zero overhead.
 *
 * @param arr  Array (lvalue).
 * @param var  Pointer variable name for the loop body.
 *
 * Example:
 * @code
 *     n00b_array_t(int) arr = ...;
 *
 *     n00b_array_foreach(arr, p) {
 *         printf("value @%p = %d\n", p, *p);
 *     }
 * @endcode
 */
#define n00b_array_foreach(arr, var)                                                           \
    for (int _afl_once = (n00b_data_read_lock((arr).lock), 1); _afl_once; )                   \
        for (typeof((arr).data) var = (arr).data;                                              \
             (var) < (arr).data + (arr).len                                                    \
                 ? 1                                                                            \
                 : (n00b_data_unlock((arr).lock), _afl_once = 0);                              \
             ++(var))

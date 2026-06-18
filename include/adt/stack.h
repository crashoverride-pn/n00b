/**
 * @file stack.h
 * @brief Type-safe dynamic stack (LIFO, optionally thread-safe).
 *
 * @c n00b_stack_t(T) provides a growable LIFO stack backed by a linear
 * buffer, with an optional rwlock for thread safety.
 *
 * Type safety is enforced through ncc's @c typeid().
 *
 * **Thread safety:** Stacks are **locked by default** — @c n00b_stack_new
 * creates a rwlock automatically.  Note that @c n00b_array_t is **not**
 * locked by default.
 *
 * Requires @c core/alloc.h to be included by the consumer for
 * @c n00b_alloc_array / @c n00b_alloc_size_typed / @c n00b_free.
 *
 * Usage:
 * @code
 *     n00b_stack_t(int) stk = n00b_stack_new(int);
 *     n00b_stack_push(stk, 42);
 *     int x = n00b_option_get(n00b_stack_pop(int, stk));
 *     n00b_stack_free(stk);
 * @endcode
 */
#pragma once

#include <assert.h>

#include "n00b.h"
#include "core/macros.h"
#include "core/atomic.h"
#include "core/align.h"
#include "core/gc_map.h"
#include "core/data_lock.h"
#include "adt/option.h"

// ============================================================================
// Constants
// ============================================================================

#define N00B_DEFAULT_STACK_SZ 16

// ============================================================================
// Type definition
// ============================================================================

#define n00b_stack_tid(T) typeid("n00b_stack", T)

#define n00b_stack_t(T)                                                                            \
    _generic_struct n00b_stack_tid(T) {                                                            \
        T                   *data;                                                                 \
        size_t               len;                                                                  \
        size_t               cap;                                                                  \
        n00b_rwlock_t       *lock;                                                                 \
        n00b_allocator_t    *allocator;                                                            \
        n00b_gc_scan_kind_t  scan_kind;                                                            \
        n00b_gc_scan_cb_t    scan_cb;                                                              \
        void                *scan_user;                                                            \
    }

// ============================================================================
// Internal helpers  (not part of public API)
// ============================================================================

/** @internal Acquire exclusive (write) lock. All stack ops are exclusive. */
#define _n00b_stack_lock(xptr)   n00b_data_write_lock((xptr)->lock)

/** @internal Release lock. */
#define _n00b_stack_unlock(xptr) n00b_data_unlock((xptr)->lock)

#define _n00b_stack_ensure_cap(xptr, needed)                                                       \
    do {                                                                                           \
        size_t _bl_need = (needed);                                                                \
        if (_bl_need > (xptr)->cap) {                                                              \
            size_t               _bl_nc = n00b_align_closest_pow2_ceil(_bl_need);                   \
            typeof((xptr)->data) _bl_nd = n00b_alloc_array_with_opts(                             \
                typeof(*(xptr)->data), _bl_nc,                                                     \
                &(n00b_alloc_opts_t){                                                              \
                    .allocator = (xptr)->allocator,                                                \
                    .scan_kind = (xptr)->scan_kind,                                                \
                    .scan_cb   = (xptr)->scan_cb,                                                  \
                    .scan_user = (xptr)->scan_user,                                                \
                });                                                                                \
            if ((xptr)->len > 0) {                                                                 \
                memcpy(_bl_nd, (xptr)->data, (xptr)->len * sizeof(*(xptr)->data));                  \
            }                                                                                      \
            if ((xptr)->data) {                                                                    \
                n00b_allocator_opt_t _bl_alloc_opt = n00b_mem_get_allocator((xptr)->data);          \
                if (n00b_option_is_set(_bl_alloc_opt)) {                                           \
                    n00b_free((xptr)->data);                                                       \
                }                                                                                  \
                else if ((xptr)->allocator != nullptr) {                                           \
                    n00b_free_from_allocator((xptr)->allocator, (xptr)->data);                      \
                }                                                                                  \
                else {                                                                             \
                    n00b_free((xptr)->data);                                                       \
                }                                                                                  \
            }                                                                                      \
            (xptr)->data = _bl_nd;                                                                 \
            (xptr)->cap  = _bl_nc;                                                                 \
        }                                                                                          \
    } while (0)

// ============================================================================
// Construction / destruction
// ============================================================================

/**
 * @brief Create a new stack with default capacity.
 *
 * Stacks are **locked by default**.  Pass `false` as the second argument
 * for an unlocked stack.
 *
 * @param T       Element type.
 * @param locked  Whether to create a rwlock (default: true).
 * @param ...     Optional allocator.
 */
#define n00b_stack_new(T, ...)              _n00b_stack_new_sel(T, true, ##__VA_ARGS__)
#define n00b_stack_new_private(T, ...)      _n00b_stack_new_sel(T, false, ##__VA_ARGS__) /**< @deprecated Use n00b_stack_new(T, false) */

#define _n00b_stack_new_sel(T, locked, ...)                                                        \
    ({                                                                                             \
        n00b_alloc_opts_t _bl_o = (n00b_alloc_opts_t){__VA_ARGS__};                                \
        (n00b_stack_t(T)){                                                                         \
            .data = n00b_alloc_array_with_opts(T, N00B_DEFAULT_STACK_SZ, &_bl_o),                  \
            .len       = 0,                                                                        \
            .cap       = N00B_DEFAULT_STACK_SZ,                                                    \
            .lock      = (locked) ? n00b_data_lock_new(.allocator = _bl_o.allocator) : nullptr,    \
            .allocator = _bl_o.allocator,                                                          \
            .scan_kind = _bl_o.scan_kind,                                                          \
            .scan_cb   = _bl_o.scan_cb,                                                            \
            .scan_user = _bl_o.scan_user,                                                          \
        };                                                                                         \
    })

/**
 * @brief Create a new stack with specific capacity.
 *
 * @param T       Element type.
 * @param N       Requested minimum capacity.
 * @param locked  Whether to create a rwlock (default: true).
 * @param ...     Optional allocator.
 */
#define n00b_stack_new_cap(T, N, ...)              _n00b_stack_new_cap_sel(T, N, true, ##__VA_ARGS__)
#define n00b_stack_new_cap_private(T, N, ...)      _n00b_stack_new_cap_sel(T, N, false, ##__VA_ARGS__) /**< @deprecated */

#define _n00b_stack_new_cap_sel(T, N, locked, ...)                                                 \
    ({                                                                                             \
        size_t _bl_rc = n00b_align_closest_pow2_ceil(n00b_max((size_t)(N), (size_t)1));             \
        n00b_alloc_opts_t _bl_o = (n00b_alloc_opts_t){__VA_ARGS__};                                \
        (n00b_stack_t(T)){                                                                         \
            .data = n00b_alloc_array_with_opts(T, _bl_rc, &_bl_o),                                 \
            .len       = 0,                                                                        \
            .cap       = _bl_rc,                                                                   \
            .lock      = (locked) ? n00b_data_lock_new(.allocator = _bl_o.allocator) : nullptr,    \
            .allocator = _bl_o.allocator,                                                          \
            .scan_kind = _bl_o.scan_kind,                                                          \
            .scan_cb   = _bl_o.scan_cb,                                                            \
            .scan_user = _bl_o.scan_user,                                                          \
        };                                                                                         \
    })

#define n00b_stack_free(x)                                                                         \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        if (_bl_lp->data) {                                                                        \
            n00b_allocator_opt_t _bl_alloc_opt = n00b_mem_get_allocator(_bl_lp->data);              \
            if (n00b_option_is_set(_bl_alloc_opt)) {                                               \
                n00b_free(_bl_lp->data);                                                           \
            }                                                                                      \
            else if (_bl_lp->allocator != nullptr) {                                               \
                n00b_free_from_allocator(_bl_lp->allocator, _bl_lp->data);                          \
            }                                                                                      \
            else {                                                                                 \
                n00b_free(_bl_lp->data);                                                           \
            }                                                                                      \
        }                                                                                          \
        *_bl_lp = (typeof(x)){};                                                                   \
    })

// ============================================================================
// Core operations  (all write-locked)
// ============================================================================

/** @brief Push a value onto the top of the stack. */
#define n00b_stack_push(x, val)                                                                    \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        _n00b_stack_lock(_bl_lp);                                                                  \
        _n00b_stack_ensure_cap(_bl_lp, _bl_lp->len + 1);                                           \
        _bl_lp->data[_bl_lp->len++] = (val);                                                       \
        _n00b_stack_unlock(_bl_lp);                                                                \
    })

/**
 * @brief Pop and return the top element as an option.
 * @param T  Element type.
 * @param x  Stack (lvalue).
 * @return   `n00b_option_t(T)` — none if the stack is empty.
 */
#define n00b_stack_pop(T, x)                                                                       \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        n00b_option_t(T) _bl_opt;                                                                  \
        _n00b_stack_lock(_bl_lp);                                                                  \
        if (_bl_lp->len > 0) {                                                                     \
            _bl_opt = n00b_option_set(T, _bl_lp->data[--_bl_lp->len]);                             \
        }                                                                                          \
        else {                                                                                     \
            _bl_opt = n00b_option_none(T);                                                         \
        }                                                                                          \
        _n00b_stack_unlock(_bl_lp);                                                                \
        _bl_opt;                                                                                   \
    })

/** @brief Read the top element without removing it.  Asserts non-empty. */
#define n00b_stack_peek(x)                                                                         \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        _n00b_stack_lock(_bl_lp);                                                                  \
        assert(_bl_lp->len > 0);                                                                   \
        typeof(*_bl_lp->data) _bl_r = _bl_lp->data[_bl_lp->len - 1];                               \
        _n00b_stack_unlock(_bl_lp);                                                                \
        _bl_r;                                                                                     \
    })

// ============================================================================
// Query  (write-locked since all stack ops are exclusive)
// ============================================================================

/** @brief Number of elements on the stack. */
#define n00b_stack_len(x)                                                                          \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        _n00b_stack_lock(_bl_lp);                                                                  \
        size_t _bl_r = _bl_lp->len;                                                                \
        _n00b_stack_unlock(_bl_lp);                                                                \
        _bl_r;                                                                                     \
    })

/** @brief True if the stack has no elements. */
#define n00b_stack_is_empty(x)                                                                     \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        _n00b_stack_lock(_bl_lp);                                                                  \
        bool _bl_r = (_bl_lp->len == 0);                                                           \
        _n00b_stack_unlock(_bl_lp);                                                                \
        _bl_r;                                                                                     \
    })

// ============================================================================
// Utilities
// ============================================================================

/** @brief Reset the stack to empty, keeping allocated capacity. */
#define n00b_stack_clear(x)                                                                        \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        _n00b_stack_lock(_bl_lp);                                                                  \
        _bl_lp->len = 0;                                                                           \
        _n00b_stack_unlock(_bl_lp);                                                                \
    })

/**
 * @brief Iterate bottom-to-top (lock-aware).
 *
 * Acquires a shared read lock before iteration and releases it
 * afterwards.  If the stack has no lock (lock == nullptr), the
 * lock/unlock calls are no-ops and the loop runs at zero overhead.
 *
 * @param x    Stack (lvalue).
 * @param var  Pointer variable name for the loop body.
 */
#define n00b_stack_foreach(x, var)                                                                 \
    for (int _sfl_once = (n00b_data_read_lock((x).lock), 1); _sfl_once; )                         \
        for (typeof((x).data) var = (x).data;                                                      \
             (var) < (x).data + (x).len                                                            \
                 ? 1                                                                                \
                 : (n00b_data_unlock((x).lock), _sfl_once = 0);                                    \
             ++(var))

#define n00b_stack_foreach_locked(x, var)  n00b_stack_foreach(x, var) /**< @deprecated Use n00b_stack_foreach */

// ============================================================================
// Conversion
// ============================================================================

/**
 * @brief Move a stack's data into an `n00b_array_t` of the same element type.
 *
 * The stack is consumed: its data pointer is transferred to the array
 * and the stack is zeroed.
 *
 * @param T  Element type (must match the stack's element type).
 * @param x  Stack (lvalue) — will be zeroed after conversion.
 * @return An `n00b_array_t(T)` owning the former stack data.
 *
 * @pre  No other thread holds the stack lock.
 * @post @p x has len/cap 0 and a nullptr data pointer.
 */
#define n00b_stack_to_array(T, x)                                                                  \
    ({                                                                                             \
        auto _bl_lp = &(x);                                                                        \
        _n00b_stack_lock(_bl_lp);                                                                  \
        n00b_array_t(T) _bl_arr = {                                                                \
            .data      = _bl_lp->data,                                                             \
            .len       = _bl_lp->len,                                                              \
            .cap       = _bl_lp->cap,                                                              \
            .allocator = _bl_lp->allocator,                                                        \
        };                                                                                         \
        _bl_lp->data      = nullptr;                                                               \
        _bl_lp->len       = 0;                                                                     \
        _bl_lp->cap       = 0;                                                                     \
        _n00b_stack_unlock(_bl_lp);                                                                \
        _bl_lp->lock      = nullptr;                                                               \
        _bl_lp->allocator = nullptr;                                                               \
        _bl_arr;                                                                                   \
    })

/**
 * @file heap.h
 * @brief Type-safe binary heap (priority queue).
 *
 * @c n00b_heap_t(T) provides an array-backed binary heap with O(log n)
 * push/pop and O(1) peek.  The ordering is determined by a caller-provided
 * comparator; a `cmp(a,b) < 0 means a < b` comparator gives a min-heap, the
 * inverse gives a max-heap.
 *
 * Common use: bounded "top-K largest" — keep a *min*-heap of size K and
 * call @ref n00b_heap_pushpop for every new element.  When the heap is at
 * capacity the smallest element is dropped, so the K largest remain.
 *
 * Example — min-heap of ints:
 * @code
 *     static int int_cmp(const void *a, const void *b) {
 *         int ai = *(const int *)a, bi = *(const int *)b;
 *         return (ai > bi) - (ai < bi);
 *     }
 *
 *     n00b_heap_t(int) h = n00b_heap_new(int, int_cmp);
 *     n00b_heap_push(h, 3);
 *     n00b_heap_push(h, 1);
 *     int top = n00b_heap_peek(h);   // 1
 * @endcode
 */
#pragma once

#include "n00b.h"
#include "core/macros.h"
#include "core/alloc.h"
#include "core/data_lock.h"

#include <stdint.h>
#include <stddef.h>
#include <assert.h>

/**
 * @brief Comparator: returns <0, 0, >0 like @c qsort.
 *
 * Both arguments point at elements stored in the heap (not pointers to
 * pointers).
 */
typedef int (*n00b_heap_cmp_fn)(const void *a, const void *b);

#if !defined(N00B_HEAP_DEFAULT_CAP)
#define N00B_HEAP_DEFAULT_CAP 8
#endif

#define n00b_heap_tid(T) typeid("n00b_heap", T)

/**
 * @brief Reference a heap type for element type @p T.
 *
 * Struct layout:
 *   `{ T *data; size_t len; size_t cap; n00b_heap_cmp_fn cmp;
 *      n00b_rwlock_t *lock; n00b_allocator_t *allocator; }`
 */
#define n00b_heap_t(T)                                                                             \
    _generic_struct n00b_heap_tid(T) {                                                             \
        T                *data;                                                                    \
        size_t            len;                                                                     \
        size_t            cap;                                                                     \
        n00b_heap_cmp_fn  cmp;                                                                     \
        n00b_rwlock_t    *lock;                                                                    \
        n00b_allocator_t *allocator;                                                               \
        uint64_t          elem_tid;                                                                \
    }

/**
 * @internal Type-erased mirror of @c n00b_heap_t(T) for the C-side helpers.
 */
typedef struct _n00b_heap_internal_t {
    void             *data;
    size_t            len;
    size_t            cap;
    n00b_heap_cmp_fn  cmp;
    n00b_rwlock_t    *lock;
    n00b_allocator_t *allocator;
    uint64_t          elem_tid;
} _n00b_heap_internal_t;

#define _n00b_heap_structural_check(hp)                                                            \
    static_assert(sizeof(*(hp)) == sizeof(_n00b_heap_internal_t));                                 \
    static_assert(offsetof(typeof(*(hp)), data)                                                    \
                  == offsetof(_n00b_heap_internal_t, data));                                       \
    static_assert(offsetof(typeof(*(hp)), len)                                                     \
                  == offsetof(_n00b_heap_internal_t, len));                                        \
    static_assert(offsetof(typeof(*(hp)), cap)                                                     \
                  == offsetof(_n00b_heap_internal_t, cap));                                        \
    static_assert(offsetof(typeof(*(hp)), cmp)                                                     \
                  == offsetof(_n00b_heap_internal_t, cmp))

// ----------------------------------------------------------------------------
// Internal C API (use the typed macros below).
// ----------------------------------------------------------------------------

/**
 * @brief Initialize a heap with capacity, comparator, and (optional) allocator.
 *
 * @kw cmp             Comparator (required).
 * @kw start_capacity  Initial capacity (default N00B_HEAP_DEFAULT_CAP).
 * @kw allocator       Allocator (nullptr = runtime default).
 * @kw no_lock         If true, do not allocate a rwlock.
 */
extern void _n00b_heap_internal_init(_n00b_heap_internal_t *h,
                                     size_t   esz,
                                     uint64_t elem_tid)
    _kargs {
        n00b_heap_cmp_fn  cmp            = nullptr;
        size_t            start_capacity = N00B_HEAP_DEFAULT_CAP;
        n00b_allocator_t *allocator      = nullptr;
        bool              no_lock        = false;
    };

extern void  _n00b_heap_internal_push(_n00b_heap_internal_t *h,
                                      size_t                 esz,
                                      const void            *val);
extern bool  _n00b_heap_internal_pop(_n00b_heap_internal_t *h,
                                     size_t                 esz,
                                     void                  *out_or_null);
extern void *_n00b_heap_internal_peek(_n00b_heap_internal_t *h);
extern bool  _n00b_heap_internal_pushpop(_n00b_heap_internal_t *h,
                                         size_t                 esz,
                                         const void            *val,
                                         void                  *out_or_null);

// ----------------------------------------------------------------------------
// Construction
// ----------------------------------------------------------------------------

/**
 * @brief Create a new heap with the given comparator.
 *
 * @param T   Element type.
 * @param C   Comparator function (an `n00b_heap_cmp_fn`).
 * @param ... Optional kargs (`.start_capacity`, `.allocator`, `.no_lock`).
 */
#define n00b_heap_new(T, C, ...)                                                                   \
    ({                                                                                             \
        n00b_heap_t(T) _bh_h = {0};                                                                \
        _n00b_heap_internal_init((_n00b_heap_internal_t *)&_bh_h,                                  \
                                 sizeof(T),                                                        \
                                 typehash(T *),                                                    \
                                 .cmp = (C) __VA_OPT__(, __VA_ARGS__));                            \
        _bh_h;                                                                                     \
    })

// ----------------------------------------------------------------------------
// Operations
// ----------------------------------------------------------------------------

/** @brief Number of elements currently in the heap. */
#define n00b_heap_len(h) ((h).len)

/**
 * @brief Push @p val onto the heap.
 *
 * @param h    Heap (lvalue).
 * @param val  Value to push (rvalue OK).
 */
#define n00b_heap_push(h, val)                                                                     \
    ({                                                                                             \
        _n00b_heap_structural_check(&(h));                                                         \
        typeof((h).data[0]) _bh_v = (val);                                                         \
        _n00b_heap_internal_push((_n00b_heap_internal_t *)&(h),                                    \
                                 sizeof(_bh_v),                                                    \
                                 &_bh_v);                                                          \
    })

/**
 * @brief Peek at the heap root without removing it.
 *
 * Returns a default-zero element when the heap is empty.
 */
#define n00b_heap_peek(h)                                                                          \
    ({                                                                                             \
        _n00b_heap_structural_check(&(h));                                                         \
        typeof((h).data[0]) _bh_r = (typeof((h).data[0])){0};                                      \
        void *_bh_p = _n00b_heap_internal_peek((_n00b_heap_internal_t *)&(h));                     \
        if (_bh_p) _bh_r = *(typeof((h).data[0]) *)_bh_p;                                          \
        _bh_r;                                                                                     \
    })

/**
 * @brief Pop the heap root.
 *
 * @param h        Heap (lvalue).
 * @param out_ptr  Where to write the popped value, or `NULL` to discard.
 * @return         `true` if a value was popped, `false` if the heap was empty.
 */
#define n00b_heap_pop(h, out_ptr)                                                                  \
    ({                                                                                             \
        _n00b_heap_structural_check(&(h));                                                         \
        _n00b_heap_internal_pop((_n00b_heap_internal_t *)&(h),                                     \
                                sizeof((h).data[0]),                                               \
                                (out_ptr));                                                        \
    })

/**
 * @brief Push @p val and pop the root in one operation.
 *
 * Useful for bounded top-K: keep a min-heap of size K and call this for
 * every new element when `len == K`.  The dropped element is the smallest
 * of `{old root, val}`.
 *
 * @param h        Heap (lvalue).
 * @param val      Value to push.
 * @param out_ptr  Where to write the dropped value, or `NULL` to discard.
 * @return         `true` if a value was dropped, `false` if the heap was
 *                 empty (in which case @p val was simply pushed).
 */
#define n00b_heap_pushpop(h, val, out_ptr)                                                         \
    ({                                                                                             \
        _n00b_heap_structural_check(&(h));                                                         \
        typeof((h).data[0]) _bh_v = (val);                                                         \
        _n00b_heap_internal_pushpop((_n00b_heap_internal_t *)&(h),                                 \
                                    sizeof(_bh_v),                                                 \
                                    &_bh_v,                                                        \
                                    (out_ptr));                                                    \
    })

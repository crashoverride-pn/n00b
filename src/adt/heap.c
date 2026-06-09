/**
 * @file heap.c
 * @brief Type-erased binary heap implementation.
 *
 * The typed `n00b_heap_t(T)` macros in `adt/heap.h` cast through to these
 * helpers, passing the runtime element size.
 */

#include "n00b.h"
#include "adt/heap.h"
#include "core/alloc.h"

#define _heap_lock_w(h) n00b_data_write_lock((h)->lock)
#define _heap_lock_r(h) n00b_data_read_lock((h)->lock)
#define _heap_unlock(h) n00b_data_unlock((h)->lock)

static inline void *
_at(_n00b_heap_internal_t *h, size_t esz, size_t i)
{
    return (char *)h->data + i * esz;
}

static inline void
_swap(_n00b_heap_internal_t *h, size_t esz, size_t i, size_t j)
{
    if (i == j) return;
    char    tmp[256];                  // small fast path
    void   *vi  = _at(h, esz, i);
    void   *vj  = _at(h, esz, j);
    void   *buf = (esz <= sizeof(tmp))
                      ? (void *)tmp
                      : n00b_alloc_size(1, esz);
    memcpy(buf, vi, esz);
    memcpy(vi, vj, esz);
    memcpy(vj, buf, esz);
}

static inline void
_sift_up(_n00b_heap_internal_t *h, size_t esz, size_t i)
{
    while (i > 0) {
        size_t parent = (i - 1) >> 1;
        if (h->cmp(_at(h, esz, i), _at(h, esz, parent)) >= 0) {
            break;
        }
        _swap(h, esz, i, parent);
        i = parent;
    }
}

static inline void
_sift_down(_n00b_heap_internal_t *h, size_t esz, size_t i)
{
    size_t n = h->len;
    for (;;) {
        size_t l    = 2 * i + 1;
        size_t r    = 2 * i + 2;
        size_t best = i;
        if (l < n && h->cmp(_at(h, esz, l), _at(h, esz, best)) < 0) {
            best = l;
        }
        if (r < n && h->cmp(_at(h, esz, r), _at(h, esz, best)) < 0) {
            best = r;
        }
        if (best == i) {
            break;
        }
        _swap(h, esz, i, best);
        i = best;
    }
}

// Caller must hold the write lock.
static inline void
_ensure_cap(_n00b_heap_internal_t *h, size_t esz, size_t needed)
{
    if (needed <= h->cap) return;
    size_t new_cap = h->cap ? h->cap : N00B_HEAP_DEFAULT_CAP;
    while (new_cap < needed) {
        new_cap *= 2;
    }
    void *new_data = n00b_alloc_size_with_opts(
        new_cap, esz, &(n00b_alloc_opts_t){.allocator = h->allocator});
    if (h->len > 0) {
        memcpy(new_data, h->data, h->len * esz);
    }
    if (h->data) {
        n00b_free(h->data);
    }
    h->data = new_data;
    h->cap  = new_cap;
}

void
_n00b_heap_internal_init(_n00b_heap_internal_t *h, size_t esz)
    _kargs {
        n00b_heap_cmp_fn  cmp            = nullptr;
        size_t            start_capacity = N00B_HEAP_DEFAULT_CAP;
        n00b_allocator_t *allocator      = nullptr;
        bool              no_lock        = false;
    }
{
    assert(cmp != nullptr && "n00b_heap_new requires a comparator");
    h->cmp       = cmp;
    h->allocator = allocator;
    h->len       = 0;
    h->cap       = start_capacity ? start_capacity : N00B_HEAP_DEFAULT_CAP;
    h->data      = n00b_alloc_size_with_opts(
        h->cap, esz, &(n00b_alloc_opts_t){.allocator = allocator});
    h->lock = no_lock ? nullptr : n00b_data_lock_new(.allocator = allocator);
}

void
_n00b_heap_internal_push(_n00b_heap_internal_t *h,
                         size_t                 esz,
                         const void            *val)
{
    _heap_lock_w(h);
    _ensure_cap(h, esz, h->len + 1);
    memcpy(_at(h, esz, h->len), val, esz);
    h->len++;
    _sift_up(h, esz, h->len - 1);
    _heap_unlock(h);
}

bool
_n00b_heap_internal_pop(_n00b_heap_internal_t *h,
                        size_t                 esz,
                        void                  *out_or_null)
{
    _heap_lock_w(h);
    if (h->len == 0) {
        _heap_unlock(h);
        return false;
    }
    if (out_or_null) {
        memcpy(out_or_null, _at(h, esz, 0), esz);
    }
    h->len--;
    if (h->len > 0) {
        memcpy(_at(h, esz, 0), _at(h, esz, h->len), esz);
        _sift_down(h, esz, 0);
    }
    _heap_unlock(h);
    return true;
}

void *
_n00b_heap_internal_peek(_n00b_heap_internal_t *h)
{
    _heap_lock_r(h);
    void *r = (h->len > 0) ? h->data : NULL;
    _heap_unlock(h);
    return r;
}

bool
_n00b_heap_internal_pushpop(_n00b_heap_internal_t *h,
                            size_t                 esz,
                            const void            *val,
                            void                  *out_or_null)
{
    _heap_lock_w(h);
    if (h->len == 0) {
        _ensure_cap(h, esz, 1);
        memcpy(_at(h, esz, 0), val, esz);
        h->len = 1;
        _heap_unlock(h);
        return false;
    }
    // If new value is <= root, nothing changes — root was already the min.
    if (h->cmp(val, _at(h, esz, 0)) <= 0) {
        if (out_or_null) {
            memcpy(out_or_null, val, esz);
        }
        _heap_unlock(h);
        return true;
    }
    // Replace root with val and sift down.
    if (out_or_null) {
        memcpy(out_or_null, _at(h, esz, 0), esz);
    }
    memcpy(_at(h, esz, 0), val, esz);
    _sift_down(h, esz, 0);
    _heap_unlock(h);
    return true;
}

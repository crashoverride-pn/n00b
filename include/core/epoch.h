#pragma once

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/atomic.h"
#include "core/alloc.h"

typedef struct n00b_epoch_hdr_t n00b_epoch_hdr_t;

struct n00b_epoch_hdr_t {
    n00b_epoch_hdr_t *next;
    _Atomic uint64_t  write_epoch;
    uint64_t          retire_epoch;
    n00b_allocator_t *allocator;
};

// The idea here is the data structure keeps a header at its start,
// whether or not people opt in. If it's zero'd, the system passes
// retires directly to n00b_free().
static inline void
n00b_epoch_stamp(n00b_epoch_hdr_t *hdr, n00b_allocator_t *allocator)
{
    hdr->allocator = allocator;

    if (!allocator || !allocator->use_epochs) {
        return;
    }

    n00b_runtime_t *rt = n00b_get_runtime();

    atomic_store(&hdr->write_epoch, n00b_atomic_add(&rt->mm_epoch, 1) + 1);
}

// Allocate `user_size` payload bytes preceded by a hidden n00b_epoch_hdr_t.
// Callers get an ordinary-looking pointer to the payload; the header rides as
// leading bytes of the same allocation (so freeing it frees the whole block)
// and n00b_retire() recovers it by backing up sizeof(n00b_epoch_hdr_t). The
// header is stamped here — a no-op on non-epoch allocators, which leaves
// write_epoch==0 so n00b_retire() falls through to an immediate n00b_free().
//
// type_hash is intentionally forced to 0 (no precise/typed GC map). The hidden
// header shifts the payload off the allocation base, and n00b's precise/
// callback scans derive their layout from the base + allocation length (see
// D-049 in _n00b_alloc_raw): a typed map would be applied at the wrong offset
// and could miss a real pointer. Only offset-invariant scan kinds are safe —
// NONE or conservative scan-every-word — selected via opts->scan_kind by the
// caller. Pass opts->scan_cb == nullptr for the same reason.
#define n00b_epoch_alloc(user_size, opts) \
    _n00b_epoch_alloc((user_size), (opts), N00B_LOC_STRING())

static inline void *
_n00b_epoch_alloc(size_t user_size, n00b_alloc_opts_t *opts, const char *loc)
{
    n00b_epoch_hdr_t *hdr = _n00b_alloc_raw(1,
                                            user_size + sizeof(n00b_epoch_hdr_t),
                                            0,
                                            loc,
                                            opts);

    n00b_epoch_stamp(hdr, opts ? opts->allocator : nullptr);

    return (char *)hdr + sizeof(n00b_epoch_hdr_t);
}

static inline void
n00b_epoch_free(n00b_epoch_hdr_t *hdr)
{
    if (hdr == nullptr) {
        return;
    }

    if (hdr->allocator != nullptr
        && !n00b_option_is_set(n00b_mem_get_allocator(hdr))) {
        n00b_free_from_allocator(hdr->allocator, hdr);
        return;
    }

    n00b_free(hdr);
}

static inline void
n00b_epoch_acquire(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    int32_t         id = n00b_thread_id();

    n00b_atomic_store(&rt->epoch_reservations[id], n00b_atomic_load(&rt->mm_epoch));
}

// Removes our reservation, indicating we are no longer performing
// a data structure operation.
//
// Also inserts a compiler barrier to make sure the rest of the
// operation is ordered AFTER everything that came before it.

static inline void
n00b_epoch_yield(void)
{
    atomic_signal_fence(memory_order_seq_cst);
    n00b_get_runtime()->epoch_reservations[n00b_thread_id()] = 0;
}

static inline void
n00b_epoch_reclaim(n00b_thread_t *self, n00b_runtime_t *rt, uint64_t lowest)
{
    n00b_epoch_hdr_t *next;
    n00b_epoch_hdr_t *top          = self->retire_list;
    n00b_epoch_hdr_t *cur          = top;
    n00b_epoch_hdr_t *prev         = nullptr;
    _Atomic uint64_t *reservations = rt->epoch_reservations;

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        uint64_t reservation = reservations[i];

        if (reservation != 0 && reservation < lowest) {
            lowest = reservation;
        }
    }

    // This list is for items *we* retired; we retire them in order.
    // We take advantage of the ordering-- newest on top.
    // We can skip down till we find something old enough to free.
    //
    // If we don't skip, the retirement list should be reset.

    while (cur && cur->retire_epoch >= lowest) {
        prev = cur;
        cur = cur->next;
    }

    if (!cur) {
        return;
    }

    if (prev == nullptr) {
        self->retire_list = nullptr;
    }
    else {
        prev->next = nullptr;
    }

    while (cur) {
        next = cur->next;
        n00b_epoch_free(cur);
        cur = next;
    }
}

// Takes the USER pointer returned by n00b_epoch_alloc(); backs up to the
// hidden header. Defers reclamation on epoch allocators; on non-epoch
// allocators (header never stamped) it just frees immediately.
static inline void
n00b_retire(void *user_ptr)
{
    n00b_epoch_hdr_t *hdr = (n00b_epoch_hdr_t *)((char *)user_ptr
                                                 - sizeof(n00b_epoch_hdr_t));

    // Alloc opted out of epoch reclaimation; instead just pass
    // directly to n00b_free().
    if (!hdr->write_epoch) {
        n00b_epoch_free(hdr);
        return;
    }
    n00b_thread_t  *self = n00b_thread_self();
    n00b_runtime_t *rt   = n00b_get_runtime();

    hdr->retire_epoch = n00b_atomic_load(&rt->mm_epoch);

    if (self->retire_list) {
        n00b_epoch_reclaim(self, rt, hdr->retire_epoch);
    }

    hdr->next         = self->retire_list;
    self->retire_list = hdr;
}

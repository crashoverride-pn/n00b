#pragma once

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/atomic.h"
#include "core/alloc.h"
#include "core/platform.h"

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
    n00b_atomic_store(&n00b_get_runtime()->epoch_reservations[n00b_thread_id()], 0);
}

static inline void
n00b_epoch_yield_thread(n00b_runtime_t *rt, n00b_thread_t *self)
{
    if (rt == nullptr || self == nullptr || rt->epoch_reservations == nullptr) {
        return;
    }

    int32_t id = self->id_info.parts.id;
    if (id < 0 || (uint32_t)id >= rt->max_threads) {
        return;
    }

    atomic_signal_fence(memory_order_seq_cst);
    n00b_atomic_store(&rt->epoch_reservations[id], 0);
}

static inline void
n00b_epoch_retire_list_push(_Atomic(n00b_epoch_hdr_t *) *listp,
                            n00b_epoch_hdr_t           *node)
{
    if (listp == nullptr || node == nullptr) {
        return;
    }

    n00b_epoch_hdr_t *head = n00b_atomic_load(listp);
    do {
        node->next = head;
    } while (!n00b_atomic_cas(listp, &head, node));
}

static inline uint64_t
n00b_epoch_lowest_reservation(n00b_runtime_t *rt, uint64_t lowest)
{
    _Atomic uint64_t *reservations = rt->epoch_reservations;

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        uint64_t reservation = reservations[i];

        if (reservation != 0 && reservation < lowest) {
            lowest = reservation;
        }
    }

    return lowest;
}

static inline void
n00b_epoch_reclaim(n00b_thread_t *self, n00b_runtime_t *rt, uint64_t lowest)
{
    if (self == nullptr || rt == nullptr) {
        return;
    }

    lowest = n00b_epoch_lowest_reservation(rt, lowest);

    n00b_epoch_hdr_t *cur =
        n00b_atomic_read_then_set(&self->retire_list,
                                  (n00b_epoch_hdr_t *)nullptr);
    while (cur != nullptr) {
        n00b_epoch_hdr_t *next = cur->next;
        cur->next = nullptr;
        if (cur->retire_epoch < lowest) {
            n00b_epoch_free(cur);
        }
        else {
            n00b_epoch_retire_list_push(&self->retire_list, cur);
        }
        cur = next;
    }
}

static inline void
n00b_epoch_dead_letter_push_one(n00b_runtime_t *rt, n00b_epoch_hdr_t *node)
{
    if (rt == nullptr || node == nullptr) {
        return;
    }

    n00b_epoch_hdr_t *head = n00b_atomic_load(&rt->epoch_dead_letters);
    do {
        node->next = head;
    } while (!n00b_atomic_cas(&rt->epoch_dead_letters, &head, node));
}

static inline void
n00b_epoch_dead_letter_push(n00b_runtime_t *rt, n00b_epoch_hdr_t *list)
{
    while (list != nullptr) {
        n00b_epoch_hdr_t *next = list->next;
        n00b_epoch_dead_letter_push_one(rt, list);
        list = next;
    }
}

static inline bool
n00b_epoch_reservations_past(n00b_runtime_t *rt, uint64_t fence)
{
    if (rt == nullptr || rt->epoch_reservations == nullptr) {
        return true;
    }

    n00b_thread_t *self    = n00b_thread_self();
    int32_t        self_id = -1;
    if (self != nullptr) {
        self_id = self->id_info.parts.id;
    }

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        if ((int32_t)i == self_id) {
            continue;
        }

        uint64_t reservation = n00b_atomic_load(&rt->epoch_reservations[i]);
        if (reservation != 0 && reservation <= fence) {
            return false;
        }
    }

    return true;
}

static inline void
n00b_epoch_wait_for_quiescence(n00b_runtime_t *rt, uint64_t fence)
{
    uint32_t spins = 0;

    while (!n00b_epoch_reservations_past(rt, fence)) {
        atomic_signal_fence(memory_order_seq_cst);
        if (spins++ >= 1024) {
            base_nanosleep_ns(1000000);
        }
    }
}

static inline void
n00b_epoch_drain_allocator_nodes(_Atomic(n00b_epoch_hdr_t *) *listp,
                                 n00b_allocator_t             *allocator)
{
    if (listp == nullptr || allocator == nullptr) {
        return;
    }

    n00b_epoch_hdr_t *cur =
        n00b_atomic_read_then_set(listp, (n00b_epoch_hdr_t *)nullptr);

    while (cur != nullptr) {
        n00b_epoch_hdr_t *next = cur->next;
        cur->next = nullptr;
        if (cur->allocator == allocator) {
            n00b_epoch_free(cur);
        }
        else {
            n00b_epoch_retire_list_push(listp, cur);
        }
        cur = next;
    }
}

static inline void
n00b_epoch_drain_allocator_dead_letters(n00b_runtime_t    *rt,
                                        n00b_allocator_t *allocator)
{
    if (rt == nullptr || allocator == nullptr) {
        return;
    }

    n00b_epoch_hdr_t *cur =
        n00b_atomic_read_then_set(&rt->epoch_dead_letters,
                                  (n00b_epoch_hdr_t *)nullptr);
    while (cur != nullptr) {
        n00b_epoch_hdr_t *next = cur->next;
        cur->next = nullptr;
        if (cur->allocator == allocator) {
            n00b_epoch_free(cur);
        }
        else {
            n00b_epoch_dead_letter_push_one(rt, cur);
        }
        cur = next;
    }
}

static inline void
n00b_epoch_drain_allocator(n00b_allocator_t *allocator)
{
    if (allocator == nullptr || !allocator->use_epochs) {
        return;
    }

    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    if (rt == nullptr || rt->epoch_reservations == nullptr) {
        return;
    }

    uint64_t fence = n00b_atomic_add(&rt->mm_epoch, 1) + 1;
    n00b_epoch_wait_for_quiescence(rt, fence);

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        n00b_thread_record_t *rec = &rt->threads[i];
        n00b_thread_t        *t   = n00b_atomic_load(&rec->thread);
        if (t != nullptr) {
            n00b_epoch_drain_allocator_nodes(&t->retire_list, allocator);
        }
    }

    n00b_epoch_drain_allocator_dead_letters(rt, allocator);
}

static inline void
n00b_epoch_reclaim_dead_letters(n00b_runtime_t *rt)
{
    if (rt == nullptr) {
        return;
    }

    n00b_epoch_hdr_t *cur =
        n00b_atomic_read_then_set(&rt->epoch_dead_letters,
                                  (n00b_epoch_hdr_t *)nullptr);
    if (cur == nullptr) {
        return;
    }

    uint64_t          lowest    = n00b_epoch_lowest_reservation(rt, UINT64_MAX);
    n00b_epoch_hdr_t *next      = nullptr;

    while (cur != nullptr) {
        next = cur->next;
        if (cur->retire_epoch < lowest) {
            n00b_epoch_free(cur);
        }
        else {
            n00b_epoch_dead_letter_push_one(rt, cur);
        }
        cur = next;
    }
}

static inline void
n00b_epoch_thread_exit(n00b_thread_t *self)
{
    if (self == nullptr) {
        return;
    }

    n00b_runtime_t    *rt   = n00b_get_runtime();
    n00b_epoch_yield_thread(rt, self);

    n00b_epoch_hdr_t *list =
        n00b_atomic_read_then_set(&self->retire_list,
                                  (n00b_epoch_hdr_t *)nullptr);
    if (list == nullptr) {
        n00b_epoch_reclaim_dead_letters(rt);
        return;
    }

    n00b_epoch_dead_letter_push(rt, list);
    n00b_epoch_reclaim_dead_letters(rt);
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

    if (n00b_atomic_load(&self->retire_list) != nullptr) {
        n00b_epoch_reclaim(self, rt, hdr->retire_epoch);
    }

    n00b_epoch_reclaim_dead_letters(rt);

    n00b_epoch_retire_list_push(&self->retire_list, hdr);
}

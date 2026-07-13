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

// A dict store keeps this header at its start. Deferred reclamation is opt-in
// per allocator via use_epochs: an allocator that individually reclaims and can
// be read concurrently (a pool, incl. the metadata pool) sets it, so a store
// retired on migration isn't freed out from under a slow reader, and allocator
// destroy drains its retired stores (n00b_epoch_drain_allocator is gated on the
// same flag). Allocators reclaimed some other way leave it false: a GC heap
// reclaims by reachability (which already keeps the old store alive for a
// reader), and a bump/scratch arena is freed wholesale, so per-node deferral is
// both unnecessary and unsafe (the retire list would dangle on bulk free). When
// unstamped, write_epoch stays 0 and n00b_retire() frees immediately.
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
// header is stamped here — see n00b_epoch_stamp: a GC store is left
// write_epoch==0 so n00b_retire() frees immediately (GC reclaims by
// reachability); a !gc store is stamped so n00b_retire() defers reclamation.
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

// Epoch-protected operations NEST: a dict op allocates -> _n00b_alloc_raw
// registers OOB metadata -> n00b_md_put/get is itself an epoch-protected dict
// op. The reservation is the earliest epoch this thread may still reference, so
// only the OUTERMOST acquire records it (nested acquires would only move it to a
// LATER epoch, which is less conservative and drops protection). We track nesting
// depth per-thread; the reservation is set on the 0->1 edge and left alone while
// nested. See n00b_epoch_yield for the matching clear.
static inline void
n00b_epoch_acquire(void)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return;
    }
    if (self->epoch_depth++ != 0) {
        return;
    }

    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr || rt->epoch_reservations == nullptr) {
        return;
    }
    int32_t id = self->id_info.parts.id;
    if (id < 0 || (uint32_t)id >= rt->max_threads) {
        return;
    }

    n00b_atomic_store(&rt->epoch_reservations[id], n00b_atomic_load(&rt->mm_epoch));
}

// Removes our reservation, indicating we are no longer performing a data
// structure operation. Only the OUTERMOST yield (depth 1->0) clears it: a nested
// yield must not drop the outer op's protection (the bug that let reclaim free a
// store the outer op still held). Inserts a compiler barrier so the rest of the
// operation is ordered AFTER everything that came before it.
static inline void
n00b_epoch_yield(void)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr || self->epoch_depth == 0) {
        return;
    }
    if (--self->epoch_depth != 0) {
        return;
    }

    atomic_signal_fence(memory_order_seq_cst);

    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr || rt->epoch_reservations == nullptr) {
        return;
    }
    int32_t id = self->id_info.parts.id;
    if (id < 0 || (uint32_t)id >= rt->max_threads) {
        return;
    }

    n00b_atomic_store(&rt->epoch_reservations[id], 0);
}

// Force-clear a thread's reservation (thread teardown / foreign-slot reap). This
// abandons any nesting, so reset the depth to 0 to keep acquire/yield balanced
// for the slot's next user.
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

    self->epoch_depth = 0;
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

typedef struct {
    n00b_runtime_t *rt;
    bool            held_gate;
    bool            held_lock;
} n00b_epoch_retire_guard_t;

static inline n00b_epoch_retire_guard_t
n00b_epoch_retire_center_lock(n00b_runtime_t *rt)
{
    n00b_epoch_retire_guard_t guard = {
        .rt        = rt,
        .held_gate = false,
        .held_lock = false,
    };

    if (rt == nullptr) {
        return guard;
    }

    if (rt->critical_execution.inited
        && !n00b_atomic_load(&rt->stw_active)) {
        n00b_rw_read_lock(&rt->critical_execution);
        guard.held_gate = true;
    }

    if (!n00b_atomic_load(&rt->stw_active)) {
        uint32_t spins = 0;
        while (n00b_atomic_or(&rt->epoch_retire_lock, 1u)) {
            atomic_signal_fence(memory_order_seq_cst);
            if (spins++ >= 1024) {
                base_nanosleep_ns(1000000);
            }
        }
        guard.held_lock = true;
    }

    return guard;
}

static inline void
n00b_epoch_retire_center_unlock(n00b_epoch_retire_guard_t guard)
{
    if (guard.rt == nullptr) {
        return;
    }

    if (guard.held_lock) {
        n00b_atomic_store(&guard.rt->epoch_retire_lock, 0u);
    }

    if (guard.held_gate) {
        n00b_rw_unlock(&guard.rt->critical_execution);
    }
}

static inline void
n00b_epoch_free_list_push(n00b_epoch_hdr_t **listp, n00b_epoch_hdr_t *node)
{
    if (listp == nullptr || node == nullptr) {
        return;
    }

    node->next = *listp;
    *listp     = node;
}

static inline void
n00b_epoch_free_list(n00b_epoch_hdr_t *list)
{
    while (list != nullptr) {
        n00b_epoch_hdr_t *next = list->next;
        list->next             = nullptr;
        n00b_epoch_free(list);
        list = next;
    }
}

// Reclaim EVERY parked retire-list node across all threads (+ dead letters).
// Called at stop-the-world entry: all mutators are suspended, so no reader can
// still hold a retired store, which makes it safe to free everything now
// regardless of epoch reservations. This is required because a GC collection
// tears down / compacts the metadata pool (n00b_forward_mdata rebuilds metadata,
// the old md_pool is freed) WITHOUT the per-allocator pre_destroy drain (that
// drain skips itself under STW). Any node left parked would then have its pool
// pages freed out from under the list -> dangling ->next -> crash in a later
// reclaim/drain. Freeing here empties the lists first. Each node is freed
// straight through its recorded allocator (n00b_free's .allocator short-circuit:
// no interval-tree discovery, no finalizers, no epoch lock), which is STW-safe;
// mmap-tree mutations for big/headerless frees run under the critical-execution
// gate that STW already holds.
static inline void
n00b_epoch_flush_all_stw(n00b_runtime_t *rt)
{
    if (rt == nullptr || rt->threads == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        n00b_thread_t *t = n00b_atomic_load(&rt->threads[i].thread);
        if (t == nullptr) {
            continue;
        }
        n00b_epoch_hdr_t *cur = n00b_atomic_read_then_set(&t->retire_list,
                                                          (n00b_epoch_hdr_t *)nullptr);
        while (cur != nullptr) {
            n00b_epoch_hdr_t *next = cur->next;
            cur->next             = nullptr;
            if (cur->allocator != nullptr) {
                n00b_free(cur, .allocator = cur->allocator);
            }
            cur = next;
        }
    }

    n00b_epoch_hdr_t *dl = n00b_atomic_read_then_set(&rt->epoch_dead_letters,
                                                     (n00b_epoch_hdr_t *)nullptr);
    while (dl != nullptr) {
        n00b_epoch_hdr_t *next = dl->next;
        dl->next               = nullptr;
        if (dl->allocator != nullptr) {
            n00b_free(dl, .allocator = dl->allocator);
        }
        dl = next;
    }
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
n00b_epoch_reclaim_locked(n00b_thread_t     *self,
                          n00b_runtime_t    *rt,
                          uint64_t           lowest,
                          n00b_epoch_hdr_t **free_list)
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
            n00b_epoch_free_list_push(free_list, cur);
        }
        else {
            n00b_epoch_retire_list_push(&self->retire_list, cur);
        }
        cur = next;
    }
}

// NB (all reclaim/drain paths): the detached free_list chain MUST be freed
// while the retire-center guard (and thus the critical-execution read gate)
// is still held. The chain is private, but its NODE MEMORY may live in the
// metadata pool: if stop-the-world lands between unlock and the free loop,
// the collector compacts/frees md_pool pages out from under the suspended
// chain, and the resumed free loop then frees recycled memory — corrupting
// whatever now lives there (seen as garbage llstack tags in a later drain's
// ->next walk). Freeing under the gate keeps STW out until the chain is gone.
static inline void
n00b_epoch_reclaim(n00b_thread_t *self, n00b_runtime_t *rt, uint64_t lowest)
{
    n00b_epoch_hdr_t          *free_list = nullptr;
    n00b_epoch_retire_guard_t  guard     = n00b_epoch_retire_center_lock(rt);
    n00b_epoch_reclaim_locked(self, rt, lowest, &free_list);
    n00b_epoch_free_list(free_list);
    n00b_epoch_retire_center_unlock(guard);
}

static inline void
n00b_epoch_dead_letter_push_one_locked(n00b_runtime_t *rt,
                                       n00b_epoch_hdr_t *node)
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
n00b_epoch_dead_letter_push_one(n00b_runtime_t *rt, n00b_epoch_hdr_t *node)
{
    n00b_epoch_retire_guard_t guard = n00b_epoch_retire_center_lock(rt);
    n00b_epoch_dead_letter_push_one_locked(rt, node);
    n00b_epoch_retire_center_unlock(guard);
}

static inline void
n00b_epoch_dead_letter_push_locked(n00b_runtime_t *rt, n00b_epoch_hdr_t *list)
{
    while (list != nullptr) {
        n00b_epoch_hdr_t *next = list->next;
        n00b_epoch_dead_letter_push_one_locked(rt, list);
        list = next;
    }
}

static inline void
n00b_epoch_dead_letter_push(n00b_runtime_t *rt, n00b_epoch_hdr_t *list)
{
    n00b_epoch_retire_guard_t guard = n00b_epoch_retire_center_lock(rt);
    n00b_epoch_dead_letter_push_locked(rt, list);
    n00b_epoch_retire_center_unlock(guard);
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
                                 n00b_allocator_t             *allocator,
                                 n00b_epoch_hdr_t            **free_list)
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
            n00b_epoch_free_list_push(free_list, cur);
        }
        else {
            n00b_epoch_retire_list_push(listp, cur);
        }
        cur = next;
    }
}

static inline void
n00b_epoch_drain_allocator_dead_letters(n00b_runtime_t    *rt,
                                        n00b_allocator_t *allocator,
                                        n00b_epoch_hdr_t **free_list)
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
            n00b_epoch_free_list_push(free_list, cur);
        }
        else {
            n00b_epoch_dead_letter_push_one_locked(rt, cur);
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

    n00b_epoch_hdr_t          *free_list = nullptr;
    n00b_epoch_retire_guard_t  guard     = n00b_epoch_retire_center_lock(rt);
    for (uint32_t i = 0; i < rt->max_threads; i++) {
        n00b_thread_record_t *rec = &rt->threads[i];
        n00b_thread_t        *t   = n00b_atomic_load(&rec->thread);
        if (t != nullptr) {
            n00b_epoch_drain_allocator_nodes(&t->retire_list,
                                             allocator,
                                             &free_list);
        }
    }

    n00b_epoch_drain_allocator_dead_letters(rt, allocator, &free_list);
    // Free under the guard — see the NB above n00b_epoch_reclaim.
    n00b_epoch_free_list(free_list);
    n00b_epoch_retire_center_unlock(guard);
}

static inline void
n00b_epoch_reclaim_dead_letters_locked(n00b_runtime_t    *rt,
                                       n00b_epoch_hdr_t **free_list)
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
            n00b_epoch_free_list_push(free_list, cur);
        }
        else {
            n00b_epoch_dead_letter_push_one_locked(rt, cur);
        }
        cur = next;
    }
}

static inline void
n00b_epoch_reclaim_dead_letters(n00b_runtime_t *rt)
{
    n00b_epoch_hdr_t          *free_list = nullptr;
    n00b_epoch_retire_guard_t  guard     = n00b_epoch_retire_center_lock(rt);
    n00b_epoch_reclaim_dead_letters_locked(rt, &free_list);
    // Free under the guard — see the NB above n00b_epoch_reclaim.
    n00b_epoch_free_list(free_list);
    n00b_epoch_retire_center_unlock(guard);
}

static inline void
n00b_epoch_thread_exit(n00b_thread_t *self)
{
    if (self == nullptr) {
        return;
    }

    n00b_runtime_t    *rt   = n00b_get_runtime();
    n00b_epoch_yield_thread(rt, self);

    n00b_epoch_hdr_t          *free_list = nullptr;
    n00b_epoch_retire_guard_t  guard     = n00b_epoch_retire_center_lock(rt);
    n00b_epoch_hdr_t *list =
        n00b_atomic_read_then_set(&self->retire_list,
                                  (n00b_epoch_hdr_t *)nullptr);
    if (list == nullptr) {
        n00b_epoch_reclaim_dead_letters_locked(rt, &free_list);
        // Free under the guard — see the NB above n00b_epoch_reclaim.
        n00b_epoch_free_list(free_list);
        n00b_epoch_retire_center_unlock(guard);
        return;
    }

    n00b_epoch_dead_letter_push_locked(rt, list);
    n00b_epoch_reclaim_dead_letters_locked(rt, &free_list);
    // Free under the guard — see the NB above n00b_epoch_reclaim.
    n00b_epoch_free_list(free_list);
    n00b_epoch_retire_center_unlock(guard);
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
    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    if (rt == nullptr) {
        n00b_epoch_free(hdr);
        return;
    }

    // During a stop-the-world collection there are NO concurrent readers, so
    // epoch deferral is unnecessary; worse, the collector reclaims/relocates
    // metadata-pool memory mid-collection (n00b_forward_mdata churns the
    // metadata dict, retiring stores), so parking a node on the per-thread
    // retire list here lets the collection free it out from under the list ->
    // corrupt list -> crash. Free immediately instead; the retire list stays
    // untouched across the collection.
    if (n00b_atomic_load(&rt->stw_active)) {
        n00b_epoch_free(hdr);
        return;
    }

    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        hdr->retire_epoch = n00b_atomic_load(&rt->mm_epoch);
        n00b_epoch_dead_letter_push_one(rt, hdr);
        return;
    }

    hdr->retire_epoch = n00b_atomic_load(&rt->mm_epoch);

    n00b_epoch_hdr_t          *free_list = nullptr;
    n00b_epoch_retire_guard_t  guard     = n00b_epoch_retire_center_lock(rt);
    if (n00b_atomic_load(&self->retire_list) != nullptr) {
        n00b_epoch_reclaim_locked(self, rt, hdr->retire_epoch, &free_list);
    }

    n00b_epoch_reclaim_dead_letters_locked(rt, &free_list);

    n00b_epoch_retire_list_push(&self->retire_list, hdr);
    n00b_epoch_retire_center_unlock(guard);
    n00b_epoch_free_list(free_list);
}

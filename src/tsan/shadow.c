/*
 * Shadow memory and the race check.
 *
 * Each 8-byte granule of application memory owns N00B_TSAN_SHADOW_CELLS shadow
 * cells recording recent accesses to it.  An access races with a remembered one
 * when they overlap in bytes, at least one is a write, they are not both
 * atomic, and the remembered access is not ordered before us by our vector
 * clock.
 *
 * Shadow is found through a lock-free hash on the region containing the
 * address, not through a fixed arithmetic map.  A fixed map has to reserve a
 * large contiguous span and push the program's own mappings out of the way,
 * which is exactly what n00b's mmap allocator and marshaller will not tolerate.
 */

#include "internal.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Diagnostic: N00B_TSAN_WATCH=<hex address> traces every check on that granule.
#if N00B_TSAN_DIAGNOSTICS
static uintptr_t watch_addr;
static _Atomic(bool) watch_ready;

static uintptr_t
watch_target(void)
{
    if (!atomic_load_explicit(&watch_ready, memory_order_acquire)) {
        const char *e = getenv("N00B_TSAN_WATCH");
        watch_addr    = (e != nullptr) ? (uintptr_t)strtoull(e, nullptr, 0) : 0;
        atomic_store_explicit(&watch_ready, true, memory_order_release);
    }
    return watch_addr;
}
#endif

// Fast path: the region this thread used last. Falls through to the hash on a
// miss. Callers that have no thread state use n00b_tsan_shadow_for directly.
n00b_tsan_cell_t *
n00b_tsan_shadow_cached(void *addr, n00b_tsan_thread_t *t)
{
    uintptr_t base = (uintptr_t)addr & ~(uintptr_t)N00B_TSAN_REGION_MASK;

    if (base == t->shadow_cache_base && t->shadow_cache_cells != nullptr) {
        uint64_t granule = ((uintptr_t)addr & N00B_TSAN_REGION_MASK) >> 3;
        return &((n00b_tsan_cell_t *)t->shadow_cache_cells)[granule
                                                            * N00B_TSAN_SHADOW_CELLS];
    }

    n00b_tsan_cell_t *cells = n00b_tsan_shadow_for(addr, true);
    if (cells == nullptr) {
        return nullptr;
    }

    uint64_t granule           = ((uintptr_t)addr & N00B_TSAN_REGION_MASK) >> 3;
    t->shadow_cache_base       = base;
    t->shadow_cache_cells      = cells - granule * N00B_TSAN_SHADOW_CELLS;
    return cells;
}

n00b_tsan_cell_t *
n00b_tsan_shadow_for(void *addr, bool create)
{
    n00b_tsan_state_t *st = &n00b_tsan_state;
    if (st->regions == nullptr) {
        return nullptr;
    }

    uintptr_t base = (uintptr_t)addr & ~(uintptr_t)N00B_TSAN_REGION_MASK;
    uint64_t  h    = n00b_tsan_mix((uint64_t)base >> N00B_TSAN_REGION_SHIFT)
              & st->region_mask;

    n00b_tsan_region_t *r = nullptr;

    for (uint64_t probe = 0; probe <= st->region_mask; probe++) {
        uint64_t  slot = (h + probe) & st->region_mask;
        r              = &st->regions[slot];
        uintptr_t cur  = atomic_load_explicit(&r->base_plus_one,
                                             memory_order_acquire);

        if (cur == base + 1) {
            break;
        }

        if (cur != 0) {
            continue;
        }

        if (!create) {
            return nullptr;
        }

        uintptr_t expected = 0;
        if (atomic_compare_exchange_strong_explicit(&r->base_plus_one,
                                                    &expected,
                                                    base + 1,
                                                    memory_order_release,
                                                    memory_order_acquire)) {
            size_t bytes = (N00B_TSAN_REGION_SIZE / 8) * N00B_TSAN_SHADOW_CELLS
                         * sizeof(n00b_tsan_cell_t);
            atomic_store_explicit(&r->cells,
                                  n00b_tsan_raw_alloc(bytes),
                                  memory_order_release);
            atomic_fetch_add_explicit(&st->region_count,
                                      1,
                                      memory_order_relaxed);
            break;
        }

        if (expected == base + 1) {
            break;
        }
    }

    if (r == nullptr) {
        return nullptr;
    }

    // The thread that claimed the slot publishes `cells` after the base, so a
    // reader that already saw the base may still be waiting on the allocation.
    n00b_tsan_cell_t *cells;
    while ((cells = atomic_load_explicit(&r->cells, memory_order_acquire))
           == nullptr) {
        n00b_tsan_cpu_relax();
    }

    uint64_t granule = ((uintptr_t)addr & N00B_TSAN_REGION_MASK) >> 3;
    return &cells[granule * N00B_TSAN_SHADOW_CELLS];
}

// Which bytes of the granule this access covers.
static inline uint8_t
byte_mask(uintptr_t addr, size_t size)
{
    uint32_t off = (uint32_t)(addr & 7);
    if (size >= 8 || off + size > 8) {
        return 0xff;
    }
    return (uint8_t)(((1u << size) - 1u) << off);
}

void
n00b_tsan_check_access(void *addr, size_t size, bool is_write, bool is_atomic,
                       void *pc)
{
    n00b_tsan_state_t *st = &n00b_tsan_state;

    if (!atomic_load_explicit(&st->inited, memory_order_relaxed)) {
        return;
    }
    if (atomic_load_explicit(&st->stw_depth, memory_order_relaxed) != 0) {
        return;
    }

    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t == nullptr || t->ignore_depth > 0) {
        return;
    }

    n00b_tsan_cell_t *cells = n00b_tsan_shadow_cached(addr, t);
    if (cells == nullptr) {
        return;
    }

#if N00B_TSAN_DIAGNOSTICS
    uintptr_t w = watch_target();
    if (w != 0 && ((uintptr_t)addr >> 3) == (w >> 3)) {
        n00b_tsan_trace_check(addr, is_write, t, cells);
    }
#endif

    n00b_tsan_vc_t *vc   = (n00b_tsan_vc_t *)t->vc;
    uint8_t         mask = byte_mask((uintptr_t)addr, size);
    n00b_tsan_cell_t mine
        = N00B_TSAN_CELL_MAKE(t->tid, t->epoch, mask, is_write, is_atomic);

    // Scan every cell before storing. Finding our own earlier access to this
    // granule does NOT end the scan: another thread's cell may sit in a later
    // slot, and that is the one a race is against.
    int  free_slot = -1;
    int  own_slot   = -1;
    bool redundant  = false;

    for (int i = 0; i < N00B_TSAN_SHADOW_CELLS; i++) {
        n00b_tsan_cell_t c = __atomic_load_n(&cells[i], __ATOMIC_RELAXED);

        if (c == 0) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }

        uint32_t other_tid = N00B_TSAN_CELL_TID(c);
        N00B_TSAN_DIAG_BUMP(d_checks);

        if (other_tid == t->tid) {
            N00B_TSAN_DIAG_BUMP(d_same_tid);
            // Our own earlier access. Reuse its slot when this access is at
            // least as strong, so the cell stays the strongest record we hold.
            if (own_slot < 0
                && (N00B_TSAN_CELL_MASK(c) & ~mask) == 0
                && (is_write || !N00B_TSAN_CELL_WRITE(c))) {
                own_slot = i;
                // Identical to what we are about to write, so writing it again
                // is pure cost.
                if (c == mine) {
                    redundant = true;
                }
            }
            continue;
        }

        if ((N00B_TSAN_CELL_MASK(c) & mask) == 0) {
            N00B_TSAN_DIAG_BUMP(d_no_overlap);
            continue;
        }
        if (!is_write && !N00B_TSAN_CELL_WRITE(c)) {
            N00B_TSAN_DIAG_BUMP(d_read_read);
            continue;
        }
        if (is_atomic && N00B_TSAN_CELL_ATOMIC(c)) {
            N00B_TSAN_DIAG_BUMP(d_atomic);
            continue;
        }
        if (N00B_TSAN_CELL_EPOCH(c) <= vc->e[other_tid]) {
            N00B_TSAN_DIAG_BUMP(d_hb);
            continue;
        }

        n00b_tsan_report_race(addr, size, is_write, c, pc);
    }

    if (redundant) {
        // This thread already recorded a covering access to this granule in
        // this epoch. The scan above still ran, so no race was missed; only the
        // rewrite is skipped.
        t->vc_version++;
        if (is_write) {
            t->n_writes++;
        }
        else {
            t->n_reads++;
        }
        return;
    }

    int slot = own_slot >= 0 ? own_slot : free_slot;

    if (slot < 0) {
        // All cells hold other threads' accesses. Which one we drop decides
        // whether a later access can still find the pair, and picking at random
        // can discard the only cell that would have caught the race
        // (Dorostkar 2025, ch. 6). Evict the narrowest access first, because a
        // narrow cell overlaps the fewest future accesses and so is the least
        // likely to be the one needed; break ties on the oldest epoch.
        int      victim     = 0;
        int      best_width = 9;
        uint64_t best_epoch = UINT64_MAX;

        for (int i = 0; i < N00B_TSAN_SHADOW_CELLS; i++) {
            n00b_tsan_cell_t c     = __atomic_load_n(&cells[i], __ATOMIC_RELAXED);
            int              width = __builtin_popcount(N00B_TSAN_CELL_MASK(c));
            uint64_t         epoch = N00B_TSAN_CELL_EPOCH(c);

            if (width < best_width
                || (width == best_width && epoch < best_epoch)) {
                best_width = width;
                best_epoch = epoch;
                victim     = i;
            }
        }
        slot = victim;
    }

    __atomic_store_n(&cells[slot], mine, __ATOMIC_RELAXED);

    t->vc_version++;

    if (is_write) {
        t->n_writes++;
    }
    else {
        t->n_reads++;
    }
}

void
n00b_tsan_mem_reset(void *addr, size_t size)
{
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)7;
    uintptr_t end   = ((uintptr_t)addr + size + 7) & ~(uintptr_t)7;

    for (uintptr_t p = start; p < end;) {
        n00b_tsan_cell_t *cells = n00b_tsan_shadow_for((void *)p, false);
        uintptr_t region_end = (p & ~(uintptr_t)N00B_TSAN_REGION_MASK)
                             + N00B_TSAN_REGION_SIZE;
        uintptr_t stop = end < region_end ? end : region_end;

        if (cells != nullptr) {
            size_t granules = (stop - p) / 8;
            memset(cells,
                   0,
                   granules * N00B_TSAN_SHADOW_CELLS
                       * sizeof(n00b_tsan_cell_t));
        }
        p = stop;
    }
}

void
n00b_tsan_mem_release(void *addr, size_t size)
{
    n00b_tsan_mem_reset(addr, size);
}

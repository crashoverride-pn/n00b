/*
 * Detector internals.  Nothing here may call into n00b: the allocator, the
 * locks and the logging paths are all instrumented, so using them would
 * re-enter the detector.  This code allocates with mmap and synchronizes with
 * plain C11 atomics.
 */

#pragma once

#include "tsan/n00b_tsan.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Probe window for the sync-object table. Every release-ordered atomic store
// hits this table, so the window is small and a full one evicts rather than
// walking further.
#define N00B_TSAN_SYNC_PROBE 16

// Suppression counters and the address/acquire traces. These sit on the hottest
// path and are contended, so they are off unless a build asks for them.
#ifndef N00B_TSAN_DIAGNOSTICS
#define N00B_TSAN_DIAGNOSTICS 0
#endif

#if N00B_TSAN_DIAGNOSTICS
#define N00B_TSAN_DIAG_BUMP(field)                                             \
    atomic_fetch_add_explicit(&n00b_tsan_state.field, 1, memory_order_relaxed)
#else
#define N00B_TSAN_DIAG_BUMP(field) ((void)0)
#endif

// Vector clock, one epoch per thread slot.  Kept as a flat array: the slot
// count is fixed and small enough that a join is a straight-line max loop, and
// the alternative (TSan's compressed clocks) buys nothing until slots run to
// the thousands.
typedef struct {
    uint64_t e[N00B_TSAN_MAX_THREADS];
} n00b_tsan_vc_t;

// A sync object's clock is compact: a sorted list of the (slot, epoch) pairs
// that are actually nonzero.  A process holds tens of thousands of locks but
// runs a handful of threads, so a flat clock per lock would cost more than the
// program under test.
typedef struct {
    uint32_t tid;
    uint64_t epoch;
} n00b_tsan_pair_t;

typedef struct {
    uint32_t          count;
    uint32_t          cap;
    n00b_tsan_pair_t *pairs;
} n00b_tsan_cvc_t;

// A sync object: the clock published by whoever last released `addr`.  Locks,
// condition variables, futex words and thread handles all land here.
typedef struct n00b_tsan_sync_s {
    _Atomic(uintptr_t) addr;
    _Atomic(uint32_t)  lock;
    n00b_tsan_cvc_t    vc;
    uint32_t           last_tid;
    uint64_t           last_version;
    bool               is_rw;
    bool               is_mutex;
} n00b_tsan_sync_t;

// Shadow for one N00B_TSAN_REGION_SIZE slice of the address space.
typedef struct n00b_tsan_region_s {
    // Stored offset by one, so a zero entry always means free even for the
    // region based at address zero.
    _Atomic(uintptr_t)          base_plus_one;
    _Atomic(n00b_tsan_cell_t *) cells;
} n00b_tsan_region_t;

typedef struct {
    _Atomic(bool)     inited;
    _Atomic(uint32_t) next_tid;
    _Atomic(uint64_t) races;
    _Atomic(uint64_t) sync_count;
    _Atomic(uint64_t) sync_evictions;
    _Atomic(uint64_t) sync_misses;
    // Why a candidate pair did not become a report. Diagnostic only.
    _Atomic(uint64_t) d_checks;
    _Atomic(uint64_t) d_same_tid;
    _Atomic(uint64_t) d_no_overlap;
    _Atomic(uint64_t) d_read_read;
    _Atomic(uint64_t) d_atomic;
    _Atomic(uint64_t) d_hb;
    _Atomic(uint64_t) region_count;
    _Atomic(int32_t)  stw_depth;
    _Atomic(uint32_t) global_lock;

    n00b_tsan_thread_t  *threads[N00B_TSAN_MAX_THREADS];
    n00b_tsan_vc_t      *thread_vc[N00B_TSAN_MAX_THREADS];
    _Atomic(uintptr_t)   thread_key[N00B_TSAN_MAX_THREADS];
    // Clock a dying thread leaves behind so a later join still sees its edge.
    n00b_tsan_vc_t      *thread_exit_vc[N00B_TSAN_MAX_THREADS];

    n00b_tsan_sync_t    *sync;
    uint64_t             sync_mask;
    n00b_tsan_region_t  *regions;
    uint64_t             region_mask;

    bool                 report_all;
    uint64_t             report_limit;
} n00b_tsan_state_t;

extern n00b_tsan_state_t n00b_tsan_state;

// Raw page allocation.  Zero-filled, never freed, invisible to n00b's mmap
// interval tree so the GC's pointer scan and the marshaller both pass over it.
extern void *n00b_tsan_raw_alloc(size_t size);

extern n00b_tsan_sync_t *n00b_tsan_sync_for(void *addr, bool create);
extern n00b_tsan_cell_t *n00b_tsan_shadow_for(void *addr, bool create);
extern n00b_tsan_cell_t *n00b_tsan_shadow_cached(void               *addr,
                                                 n00b_tsan_thread_t *t);

extern void n00b_tsan_vc_join(n00b_tsan_vc_t *dst, const n00b_tsan_vc_t *src);
extern void n00b_tsan_vc_copy(n00b_tsan_vc_t *dst, const n00b_tsan_vc_t *src);
extern void n00b_tsan_cvc_absorb(n00b_tsan_cvc_t *dst, const n00b_tsan_vc_t *src);
extern void n00b_tsan_cvc_apply(const n00b_tsan_cvc_t *src, n00b_tsan_vc_t *dst);
extern uint32_t n00b_tsan_tid_watermark(void);

extern void n00b_tsan_check_access(void  *addr,
                                   size_t size,
                                   bool   is_write,
                                   bool   is_atomic,
                                   void  *pc);

extern void n00b_tsan_trace_acquire(void    *addr,
                                    uint32_t tid,
                                    uint32_t src,
                                    uint64_t before,
                                    uint64_t after);

extern void n00b_tsan_trace_check(void               *addr,
                                  bool                is_write,
                                  n00b_tsan_thread_t *t,
                                  n00b_tsan_cell_t   *cells);

extern void n00b_tsan_report_race(void            *addr,
                                  size_t           size,
                                  bool             is_write,
                                  n00b_tsan_cell_t other,
                                  void            *pc);

static inline void
n00b_tsan_cpu_relax(void)
{
#if defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#elif defined(__x86_64__)
    __asm__ volatile("pause" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

static inline void
n00b_tsan_spin_lock(_Atomic(uint32_t) *l)
{
    for (;;) {
        uint32_t expected = 0;
        if (atomic_compare_exchange_weak_explicit(l,
                                                  &expected,
                                                  1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed)) {
            return;
        }
        while (atomic_load_explicit(l, memory_order_relaxed) != 0) {
            n00b_tsan_cpu_relax();
        }
    }
}

static inline void
n00b_tsan_spin_unlock(_Atomic(uint32_t) *l)
{
    atomic_store_explicit(l, 0, memory_order_release);
}

// 64-bit finalizer from splitmix64; the address low bits alone cluster badly
// because every lock in a struct shares a cache line.
static inline uint64_t
n00b_tsan_mix(uint64_t x)
{
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    x ^= x >> 31;
    return x;
}

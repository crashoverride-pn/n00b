/*
 * Vector clocks, the thread registry, and the sync-object table.
 *
 * Thread clocks are flat arrays indexed by slot, because the hot path reads
 * them by index on every access check.  Sync-object clocks are compact
 * (tid, epoch) pair lists instead: a process has a handful of threads but tens
 * of thousands of locks, and a flat clock per lock would cost more memory than
 * the program under test.
 */

#include "internal.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

n00b_tsan_state_t n00b_tsan_state;

// Highest slot ever handed out, so a clock join stops there instead of walking
// all N00B_TSAN_MAX_THREADS entries.
static _Atomic(uint32_t) tid_watermark = 0;

void *
n00b_tsan_raw_alloc(size_t size)
{
    size_t page = (size_t)getpagesize();
    size        = (size + page - 1) & ~(page - 1);

    void *p = mmap(nullptr,
                   size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON,
                   -1,
                   0);

    if (p == MAP_FAILED) {
        const char *msg = "n00b tsan: shadow mmap failed\n";
        write(2, msg, strlen(msg));
        _exit(70);
    }

    return p;
}

// ---------------------------------------------------------------- thread clocks

void
n00b_tsan_vc_copy(n00b_tsan_vc_t *dst, const n00b_tsan_vc_t *src)
{
    uint32_t n = atomic_load_explicit(&tid_watermark, memory_order_relaxed) + 1;
    memcpy(dst->e, src->e, n * sizeof(uint64_t));
}

void
n00b_tsan_vc_join(n00b_tsan_vc_t *dst, const n00b_tsan_vc_t *src)
{
    uint32_t n = atomic_load_explicit(&tid_watermark, memory_order_relaxed) + 1;

    for (uint32_t i = 0; i < n; i++) {
        if (src->e[i] > dst->e[i]) {
            dst->e[i] = src->e[i];
        }
    }
}

// ------------------------------------------------------------- thread identity

// The Mach thread port (Darwin) or the kernel tid (Linux), read without libc so
// it works on a raw worker that has no pthread.  This mirrors
// n00b_os_thread_id(); it is duplicated rather than called because thread.c is
// instrumented and calling into it here would re-enter the detector.
static inline uint64_t
tsan_os_tid(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    uint64_t tpidrro;
    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tpidrro));
    uint64_t *tsd = (uint64_t *)(uintptr_t)(tpidrro & ~(uint64_t)0x7);
    if (tsd == nullptr) {
        return 0;
    }
    return (uint64_t)(uint32_t)tsd[3];
#elif defined(__linux__) && defined(__aarch64__)
    uint64_t tp;
    __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(tp));
    return tp;
#elif defined(__linux__) && defined(__x86_64__)
    uint64_t tp;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(tp));
    return tp;
#else
#error "n00b tsan: add a libc-free thread-identity read for this platform"
#endif
}

#define TID_CACHE_SLOTS 4096
#define TID_CACHE_MASK  (TID_CACHE_SLOTS - 1)

typedef struct {
    _Atomic(uint64_t) key;
    _Atomic(void *)   val;
} tid_cache_entry_t;

static tid_cache_entry_t tid_cache[TID_CACHE_SLOTS];

#define STACK_CACHE_BITS  16
#define STACK_CACHE_SLOTS (1u << STACK_CACHE_BITS)
#define STACK_CACHE_MASK  (STACK_CACHE_SLOTS - 1)
// n00b worker stacks are one 8 MiB callstack region each, so the region base is
// a stable per-thread key recoverable from the stack pointer alone.
#define STACK_REGION_SHIFT 23

typedef struct {
    _Atomic(uintptr_t) base;
    _Atomic(void *)    val;
} stack_cache_entry_t;

static stack_cache_entry_t stack_cache[STACK_CACHE_SLOTS];

static void
stack_cache_put(n00b_tsan_thread_t *t)
{
    uintptr_t sp   = (uintptr_t)__builtin_frame_address(0);
    uintptr_t base = sp >> STACK_REGION_SHIFT;
    uint64_t  slot = base & STACK_CACHE_MASK;

    atomic_store_explicit(&stack_cache[slot].val, t, memory_order_relaxed);
    atomic_store_explicit(&stack_cache[slot].base, base, memory_order_release);
}

n00b_tsan_thread_t *
n00b_tsan_self(void)
{
    // Four instructions and one load on the hot path: shift the stack pointer
    // to its region, index, compare. Everything else here is the fallback.
    uintptr_t sp     = (uintptr_t)__builtin_frame_address(0);
    uintptr_t region = sp >> STACK_REGION_SHIFT;
    uint64_t  slot   = region & STACK_CACHE_MASK;

    if (atomic_load_explicit(&stack_cache[slot].base, memory_order_acquire)
        == region) {
        return atomic_load_explicit(&stack_cache[slot].val,
                                    memory_order_relaxed);
    }

    uint64_t key = tsan_os_tid();
    if (key == 0) {
        return nullptr;
    }

    uint64_t h = (key * UINT64_C(0x9e3779b97f4a7c15)) >> 52;
    h &= TID_CACHE_MASK;

    // The common case is the first slot; the walk only runs on a collision.
    if (atomic_load_explicit(&tid_cache[h].key, memory_order_acquire) == key) {
        n00b_tsan_thread_t *t = atomic_load_explicit(&tid_cache[h].val,
                                                     memory_order_relaxed);
        if (t != nullptr) {
            stack_cache_put(t);
        }
        return t;
    }

    for (uint32_t probe = 1; probe < 8; probe++) {
        uint64_t slot = (h + probe) & TID_CACHE_MASK;
        uint64_t k    = atomic_load_explicit(&tid_cache[slot].key,
                                          memory_order_acquire);
        if (k == key) {
            n00b_tsan_thread_t *t = atomic_load_explicit(&tid_cache[slot].val,
                                                         memory_order_relaxed);
            if (t != nullptr) {
                stack_cache_put(t);
            }
            return t;
        }
        if (k == 0) {
            return nullptr;
        }
    }

    return nullptr;
}

static void
tid_cache_put(uint64_t key, n00b_tsan_thread_t *val)
{
    uint64_t h = ((key * UINT64_C(0x9e3779b97f4a7c15)) >> 52) & TID_CACHE_MASK;

    for (uint32_t probe = 0; probe < 8; probe++) {
        uint64_t slot     = (h + probe) & TID_CACHE_MASK;
        uint64_t expected = 0;

        if (atomic_compare_exchange_strong_explicit(&tid_cache[slot].key,
                                                    &expected,
                                                    key,
                                                    memory_order_release,
                                                    memory_order_acquire)
            || expected == key) {
            atomic_store_explicit(&tid_cache[slot].val,
                                  val,
                                  memory_order_release);
            return;
        }
    }
}


uint32_t
n00b_tsan_tid_watermark(void)
{
    return atomic_load_explicit(&tid_watermark, memory_order_relaxed);
}

// ------------------------------------------------------------- compact clocks

// Fold every nonzero entry of a thread clock into a sync object's compact one,
// keeping the later epoch per slot.  Called under the sync object's spinlock.
void
n00b_tsan_cvc_absorb(n00b_tsan_cvc_t *dst, const n00b_tsan_vc_t *src)
{
    uint32_t n = atomic_load_explicit(&tid_watermark, memory_order_relaxed) + 1;

    for (uint32_t tid = 0; tid < n; tid++) {
        uint64_t epoch = src->e[tid];
        if (epoch == 0) {
            continue;
        }

        bool found = false;
        for (uint32_t i = 0; i < dst->count; i++) {
            if (dst->pairs[i].tid == tid) {
                if (epoch > dst->pairs[i].epoch) {
                    dst->pairs[i].epoch = epoch;
                }
                found = true;
                break;
            }
        }
        if (found) {
            continue;
        }

        if (dst->count == dst->cap) {
            uint32_t          cap   = dst->cap ? dst->cap * 2 : 4;
            n00b_tsan_pair_t *grown = n00b_tsan_raw_alloc(
                cap * sizeof(n00b_tsan_pair_t));
            if (dst->pairs != nullptr) {
                memcpy(grown, dst->pairs, dst->count * sizeof(*grown));
            }
            dst->pairs = grown;
            dst->cap   = cap;
        }

        dst->pairs[dst->count].tid   = tid;
        dst->pairs[dst->count].epoch = epoch;
        dst->count++;
    }
}

void
n00b_tsan_cvc_apply(const n00b_tsan_cvc_t *src, n00b_tsan_vc_t *dst)
{
    for (uint32_t i = 0; i < src->count; i++) {
        uint32_t tid = src->pairs[i].tid;
        if (src->pairs[i].epoch > dst->e[tid]) {
            dst->e[tid] = src->pairs[i].epoch;
        }
    }
}

// ------------------------------------------------------------- sync-object map

n00b_tsan_sync_t *
n00b_tsan_sync_for(void *addr, bool create)
{
    n00b_tsan_state_t *st = &n00b_tsan_state;
    if (st->sync == nullptr) {
        return nullptr;
    }

    uintptr_t key = (uintptr_t)addr;
    uint64_t  h   = n00b_tsan_mix((uint64_t)key) & st->sync_mask;

    // Every release-ordered atomic store reaches this, so the probe window is
    // bounded: a full-table walk here would cost more than the program.
    for (uint64_t probe = 0; probe < N00B_TSAN_SYNC_PROBE; probe++) {
        uint64_t          slot = (h + probe) & st->sync_mask;
        n00b_tsan_sync_t *s    = &st->sync[slot];
        uintptr_t         cur  = atomic_load_explicit(&s->addr,
                                              memory_order_acquire);

        if (cur == key) {
            return s;
        }

        if (cur == 0) {
            if (!create) {
                return nullptr;
            }
            uintptr_t expected = 0;
            if (atomic_compare_exchange_strong_explicit(&s->addr,
                                                        &expected,
                                                        key,
                                                        memory_order_release,
                                                        memory_order_acquire)) {
                atomic_fetch_add_explicit(&st->sync_count,
                                          1,
                                          memory_order_relaxed);
                return s;
            }
            if (expected == key) {
                return s;
            }
        }
    }

    if (!create) {
        return nullptr;
    }

    // Window full. Take the first slot over from whatever address held it and
    // start its clock empty. Dropping a sync object drops the edges it carried,
    // which can turn into a false positive later, so the eviction is counted
    // and reported in the summary rather than hidden.
    n00b_tsan_sync_t *s = &st->sync[h];

    n00b_tsan_spin_lock(&s->lock);
    if (!s->is_mutex) {
        atomic_store_explicit(&s->addr, key, memory_order_release);
        s->vc.count = 0;
        atomic_fetch_add_explicit(&st->sync_evictions, 1, memory_order_relaxed);
        n00b_tsan_spin_unlock(&s->lock);
        return s;
    }
    n00b_tsan_spin_unlock(&s->lock);

    // An annotated lock lives in the slot; leave it alone and give up the edge.
    atomic_fetch_add_explicit(&st->sync_misses, 1, memory_order_relaxed);
    return nullptr;
}

void
n00b_tsan_sync_forget(void *addr)
{
    n00b_tsan_sync_t *s = n00b_tsan_sync_for(addr, false);
    if (s == nullptr) {
        return;
    }

    n00b_tsan_spin_lock(&s->lock);
    s->vc.count = 0;
    n00b_tsan_spin_unlock(&s->lock);
}

// ------------------------------------------------------------ happens-before

void
n00b_tsan_acquire(void *addr)
{
    if (atomic_load_explicit(&n00b_tsan_state.stw_depth,
                             memory_order_relaxed)
        != 0) {
        return;
    }

    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t == nullptr) {
        return;
    }

    n00b_tsan_sync_t *s = n00b_tsan_sync_for(addr, false);
    if (s == nullptr) {
        return;
    }

    n00b_tsan_vc_t *vc = (n00b_tsan_vc_t *)t->vc;

    // Diagnostic: N00B_TSAN_TRACE_ACQ=<tid> names every sync address that
    // raises this thread's knowledge of that thread's clock.
    static _Atomic(int) trace_src = -2;
    int                 want      = atomic_load_explicit(&trace_src,
                                        memory_order_relaxed);
    if (want == -2) {
        const char *e = getenv("N00B_TSAN_TRACE_ACQ");
        want          = (e != nullptr) ? atoi(e) : -1;
        atomic_store_explicit(&trace_src, want, memory_order_relaxed);
    }

    uint64_t before = (want >= 0) ? vc->e[want] : 0;

    n00b_tsan_spin_lock(&s->lock);
    if (s->vc.count != 0) {
        n00b_tsan_cvc_apply(&s->vc, vc);
        t->vc_version++;
    }
    n00b_tsan_spin_unlock(&s->lock);

    if (want >= 0 && vc->e[want] > before) {
        n00b_tsan_trace_acquire(addr, t->tid, (uint32_t)want, before,
                                vc->e[want]);
    }
}

// A release ends the current epoch: the releasing thread ticks its own clock so
// anything it does after this point is ordered after, not concurrent with, the
// critical section it just left.
void
n00b_tsan_release(void *addr)
{
    if (atomic_load_explicit(&n00b_tsan_state.stw_depth,
                             memory_order_relaxed)
        != 0) {
        return;
    }

    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t == nullptr) {
        return;
    }

    n00b_tsan_sync_t *s = n00b_tsan_sync_for(addr, true);
    if (s == nullptr) {
        return;
    }

    // This object already holds this exact clock from us, so the merge would
    // change nothing. n00b runs long stretches of back-to-back atomics on the
    // same word where this holds.
    if (s->last_tid == t->tid && s->last_version == t->vc_version) {
        return;
    }

    n00b_tsan_vc_t *vc = (n00b_tsan_vc_t *)t->vc;

    n00b_tsan_spin_lock(&s->lock);
    n00b_tsan_cvc_absorb(&s->vc, vc);
    s->last_tid     = t->tid;
    s->last_version = t->vc_version;
    n00b_tsan_spin_unlock(&s->lock);

    t->epoch++;
    vc->e[t->tid] = t->epoch;
    t->vc_version++;
}

void
n00b_tsan_release_merge(void *addr)
{
    n00b_tsan_acquire(addr);
    n00b_tsan_release(addr);
}

// ------------------------------------------------------------ thread lifecycle

static n00b_tsan_thread_t *
thread_register(void)
{
    n00b_tsan_state_t *st  = &n00b_tsan_state;
    uint32_t           tid = atomic_fetch_add_explicit(&st->next_tid,
                                             1,
                                             memory_order_relaxed);

    if (tid >= N00B_TSAN_MAX_THREADS) {
        const char *msg = "n00b tsan: out of thread slots\n";
        write(2, msg, strlen(msg));
        return nullptr;
    }

    uint32_t seen = atomic_load_explicit(&tid_watermark, memory_order_relaxed);
    while (tid > seen
           && !atomic_compare_exchange_weak_explicit(&tid_watermark,
                                                     &seen,
                                                     tid,
                                                     memory_order_relaxed,
                                                     memory_order_relaxed)) {
    }

    n00b_tsan_thread_t *t = n00b_tsan_raw_alloc(sizeof(*t));
    n00b_tsan_vc_t     *v = n00b_tsan_raw_alloc(sizeof(*v));

    t->tid          = tid;
    t->epoch        = 1;
    t->vc           = v->e;
    t->ignore_depth = 0;
    t->live         = 1;
    v->e[tid]       = 1;

    st->threads[tid]   = t;
    st->thread_vc[tid] = v;

    tid_cache_put(tsan_os_tid(), t);
    stack_cache_put(t);
    return t;
}

void
n00b_tsan_thread_spawning(void *create_token)
{
    // Publish the spawner's clock where the new thread will look for it.
    n00b_tsan_release(create_token);
}

n00b_tsan_thread_t *
n00b_tsan_thread_start(void *create_token)
{
    if (!atomic_load_explicit(&n00b_tsan_state.inited, memory_order_acquire)) {
        return nullptr;
    }

    n00b_tsan_thread_t *t = thread_register();
    if (t == nullptr) {
        return nullptr;
    }

    // The spawner published its clock on the bundle before starting us, so
    // folding it in now is the create edge: everything the parent did before the
    // spawn happens-before everything we do.
    if (create_token != nullptr) {
        n00b_tsan_acquire(create_token);
    }

    return t;
}

void
n00b_tsan_thread_finish(void *join_token)
{
    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t == nullptr) {
        return;
    }

    // Publish our final clock on the handle so a later join picks up the edge.
    if (join_token != nullptr) {
        n00b_tsan_release(join_token);
    }

    n00b_tsan_state.thread_exit_vc[t->tid] = (n00b_tsan_vc_t *)t->vc;
    t->live                                = 0;

    // The thread stays registered. Everything after this point — thread_destroy,
    // the live_threads decrement that n00b_shutdown waits on, the join_futex
    // publish — is still this thread synchronizing with others, and a thread the
    // detector has forgotten publishes nothing at all. A later thread that
    // inherits this OS id overwrites the entry in thread_start.
}

void
n00b_tsan_thread_join(void *join_token)
{
    if (join_token != nullptr) {
        n00b_tsan_acquire(join_token);
    }
}

// ------------------------------------------------------------------ ignore/STW

void
n00b_tsan_ignore_begin(void)
{
    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t != nullptr) {
        t->ignore_depth++;
    }
}

void
n00b_tsan_ignore_end(void)
{
    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t != nullptr && t->ignore_depth > 0) {
        t->ignore_depth--;
    }
}

// Between these the collector is the only runner, so nothing it touches can
// race and every thread's view is ordered after the pause.
void
n00b_tsan_stw_begin(void)
{
    atomic_fetch_add_explicit(&n00b_tsan_state.stw_depth,
                              1,
                              memory_order_acq_rel);
}

void
n00b_tsan_stw_end(void)
{
    n00b_tsan_thread_t *t = n00b_tsan_self();
    if (t != nullptr) {
        n00b_tsan_vc_t *vc = (n00b_tsan_vc_t *)t->vc;
        t->epoch++;
        vc->e[t->tid] = t->epoch;

        // The collector ran alone, so its clock is now an upper bound on every
        // thread's; publishing it means resumed threads see the pause as
        // ordered before whatever they do next.
        uint32_t n = atomic_load_explicit(&tid_watermark, memory_order_relaxed);
        for (uint32_t i = 0; i <= n; i++) {
            n00b_tsan_vc_t *other = n00b_tsan_state.thread_vc[i];
            if (other != nullptr && other != vc) {
                n00b_tsan_vc_join(other, vc);
            }
        }
    }

    atomic_fetch_sub_explicit(&n00b_tsan_state.stw_depth,
                              1,
                              memory_order_acq_rel);
}

// ------------------------------------------------------------------ mutexes

void
n00b_tsan_mutex_create(void *addr, bool is_rw)
{
    n00b_tsan_sync_t *s = n00b_tsan_sync_for(addr, true);
    if (s != nullptr) {
        s->is_rw    = is_rw;
        s->is_mutex = true;
    }
}

void
n00b_tsan_mutex_destroy(void *addr)
{
    n00b_tsan_sync_forget(addr);
}

// A reader does not publish anything, so it only acquires.  A writer both
// acquires the prior critical sections and, on release, publishes its own.
void
n00b_tsan_mutex_acquired(void *addr, bool write_lock)
{
    (void)write_lock;
    n00b_tsan_acquire(addr);
}

void
n00b_tsan_mutex_releasing(void *addr, bool write_lock)
{
    if (write_lock) {
        n00b_tsan_release(addr);
    }
    else {
        // A read unlock still has to leave an edge for the next writer, but it
        // must not clobber what other concurrent readers published.
        n00b_tsan_release_merge(addr);
    }
}

// ----------------------------------------------------------------------- init

void
n00b_tsan_init(void)
{
    n00b_tsan_state_t *st = &n00b_tsan_state;

    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&st->inited,
                                                 &expected,
                                                 true,
                                                 memory_order_acq_rel,
                                                 memory_order_acquire)) {
        return;
    }

    const uint64_t sync_slots   = UINT64_C(1) << 20;
    const uint64_t region_slots = UINT64_C(1) << 16;

    st->sync        = n00b_tsan_raw_alloc(sync_slots * sizeof(*st->sync));
    st->sync_mask   = sync_slots - 1;
    st->regions     = n00b_tsan_raw_alloc(region_slots * sizeof(*st->regions));
    st->region_mask = region_slots - 1;

    st->report_limit = 64;
    st->report_all   = false;

    // The main thread is already running, so register it here.
    thread_register();
}

void
n00b_tsan_fini(void)
{
    n00b_tsan_report_summary();
}

uint64_t
n00b_tsan_race_count(void)
{
    return atomic_load_explicit(&n00b_tsan_state.races, memory_order_relaxed);
}

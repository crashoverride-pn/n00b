#define N00B_MEM_INTERNAL_API
#define N00B_USE_INTERNAL_API

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> /* getenv/strtol/abort: big-free quarantine (+ N00B_DEBUG) */

#include "n00b.h"
#include "core/alloc_mdata.h"
#include "core/alloc.h"
#include "core/memory_info.h"
#include "core/mmaps.h"
#include "core/atomic.h"

/* Forward decl to avoid pulling in lock_common.h (and its
 * transitive thread-id dependency) at this layer. */
extern void n00b_lock_chains_scrub_range(uint64_t lo, uint64_t hi);
#include "adt/llstack.h"
#include "adt/list.h"
#include "core/align.h"
#include "core/epoch.h"
#include "core/pool.h"
/* Declared after pool.h so n00b_pool_t is a complete file-scope type. */
extern void n00b_lock_chains_scrub_pool(n00b_pool_t *pool);
#include "core/runtime.h"
#include "util/math.h"

#define N00B_POOL_GLOBAL_REGISTRY_MAX 65536

typedef struct {
    n00b_pool_t *pool;
    const char  *name;
} n00b_pool_registry_entry_t;

static n00b_pool_registry_entry_t n00b_pool_registry[N00B_POOL_GLOBAL_REGISTRY_MAX];
static _Atomic uint32_t           n00b_pool_registry_lock;
static _Atomic uint64_t           n00b_pool_registry_init_count;
static _Atomic uint64_t           n00b_pool_registry_destroy_count;
static _Atomic uint64_t           n00b_pool_registry_overflow_count;
static _Atomic uint64_t           n00b_pool_destroy_unmap_count;
static _Atomic uint64_t           n00b_pool_destroy_unmap_bytes;
static _Atomic uint64_t           n00b_pool_destroy_unmap_fail_count;
static _Atomic uint64_t           n00b_pool_destroy_unmap_fail_bytes;
static _Atomic uint64_t           n00b_pool_big_unmap_fail_count;
static _Atomic uint64_t           n00b_pool_big_unmap_fail_bytes;

/* ---------------------------------------------------------------------------
 * Big-free quarantine (diagnostic; env N00B_POOL_BIG_QUARANTINE=<pages>).
 *
 * Every big (page-granular) pool allocation is its own mmap, so a
 * use-after-free of one dereferences unmapped (or, worse, since-remapped)
 * address space, and a double-free unmaps whatever NOW lives at the reused
 * address. Both present as delayed, unattributable crashes far from the bug.
 * When enabled, delete_one_page_entry parks a freed big page here instead of
 * unmapping it: the page is mprotect(PROT_NONE)'d — any later touch faults
 * immediately, with the page still attributable — and recorded with the
 * freeing call stack. The oldest parked page is truly munmapped only when
 * the ring wraps. A free landing inside a still-parked page is a definite
 * double-free: both call stacks are reported and the process aborts. The
 * crash handler calls n00b_pool_quarantine_find() (async-signal-safe: plain
 * atomic loads, no locks) to attribute a faulting address to its freeing
 * site. Off by default; parked pages cost address space, not RSS.
 * ------------------------------------------------------------------------- */

#define N00B_POOL_QUAR_RING_MAX 1024

typedef struct {
    _Atomic(uintptr_t) start; /* 0 = slot empty */
    _Atomic(uint32_t)  busy;  /* per-slot parker claim (see park below) */
    uint64_t           size;
    uint64_t           seq;
    const char        *pool_name;
    void              *frees[N00B_POOL_QUARANTINE_FRAMES];
} n00b_pool_quar_slot_t;

[[n00b::nogc]] static n00b_pool_quar_slot_t
    n00b_pool_quar_ring[N00B_POOL_QUAR_RING_MAX];
static _Atomic uint64_t n00b_pool_quar_cursor;
static _Atomic int32_t  n00b_pool_quar_capacity = -1; /* -1 = env unread */

/* Guard mode (env N00B_POOL_PAGE_PER_ALLOC): route EVERY allocation through
 * the single-entry mmap path so each alloc owns a full page. Combined with
 * the big-free quarantine this extends use-after-free / double-free
 * detection to slab-class allocations — a wrongly freed small object parks
 * its whole page and the next touch (or second free) faults attributably —
 * at the cost of a page plus an mmap syscall per allocation. Value "1" or
 * "all" applies to every pool; any other value is a substring filter on the
 * pool's debug_name (e.g. "system" to target only the system pool). */
static _Atomic int32_t n00b_pool_guard_mode = -1; /* -1 unread, 0 off,
                                                     1 all, 2 filtered */
static const char *n00b_pool_guard_filter;

static bool
pool_guard_page_per_alloc(n00b_pool_t *pool)
{
    int32_t mode = atomic_load(&n00b_pool_guard_mode);
    if (mode < 0) {
        /* Raw getenv: same allocator-layer bootstrap exception as
         * pool_quar_capacity above. */
        const char *env = getenv("N00B_POOL_PAGE_PER_ALLOC");
        int32_t     v   = 0;
        if (env != nullptr && env[0] != '\0') {
            if ((env[0] == '1' && env[1] == '\0')
                || strcmp(env, "all") == 0) {
                v = 1;
            }
            else {
                n00b_pool_guard_filter = env;
                v                      = 2;
            }
        }
        int32_t expected = -1;
        atomic_compare_exchange_strong(&n00b_pool_guard_mode, &expected, v);
        mode = atomic_load(&n00b_pool_guard_mode);
    }
    switch (mode) {
    case 1:
        return true;
    case 2: {
        const char *name = ((n00b_allocator_t *)pool)->debug_name;
        return name != nullptr
               && n00b_pool_guard_filter != nullptr
               && strstr(name, n00b_pool_guard_filter) != nullptr;
    }
    default:
        return false;
    }
}

static uint32_t
pool_quar_capacity(void)
{
    int32_t cap = atomic_load(&n00b_pool_quar_capacity);
    if (cap >= 0) {
        return (uint32_t)cap;
    }
    /* Raw getenv, not n00b_getenv: n00b_getenv allocates its result through
     * the runtime's default allocator, and this file IS the allocator layer —
     * routing a pool-internal gate through it is a bootstrap circularity.
     * Same documented exception as pool_mmap_audit_enabled below. */
    const char *env = getenv("N00B_POOL_BIG_QUARANTINE");
    int32_t     v   = 0;
    if (env != nullptr && env[0] != '\0') {
        v = (int32_t)strtol(env, nullptr, 10);
        if (v < 0) {
            v = 0;
        }
        if (v > N00B_POOL_QUAR_RING_MAX) {
            v = N00B_POOL_QUAR_RING_MAX;
        }
    }
    int32_t expected = -1;
    atomic_compare_exchange_strong(&n00b_pool_quar_capacity, &expected, v);
    return (uint32_t)atomic_load(&n00b_pool_quar_capacity);
}

/* Best-effort frame-pointer walk of the FREEING call stack. Unlike the crash
 * handler's walker (crash.c), this runs in ORDINARY context on the free path
 * where a fault is not an acceptable outcome — so every dereference is kept
 * inside the current thread's live stack: each fp must sit at or above this
 * frame and within a conservative window of it (the stack is mapped
 * contiguously up through the caller frames), and must advance monotonically
 * with a bounded stride (mirrors crash.c's 16 MB forward-progress cap). A
 * chain that leaves those bounds (tail calls, omitted frame pointers,
 * corruption) just truncates the capture. */
#define POOL_QUAR_FRAME_WINDOW (8u << 20)

static void
pool_quar_capture_frames(void **out)
{
    for (int i = 0; i < N00B_POOL_QUARANTINE_FRAMES; i++) {
        out[i] = nullptr;
    }
    void **anchor = (void **)__builtin_frame_address(0);
    void **fp     = anchor;
    for (int i = 0; i < N00B_POOL_QUARANTINE_FRAMES; i++) {
        if (fp == nullptr || (((uintptr_t)fp) & 0xf) != 0
            || fp < anchor
            || (uintptr_t)fp - (uintptr_t)anchor > POOL_QUAR_FRAME_WINDOW) {
            break;
        }
        void **next = (void **)fp[0];
        void  *ret  = fp[1];
        if (ret == nullptr) {
            break;
        }
        out[i] = ret;
        if (next <= fp
            || (uintptr_t)next - (uintptr_t)fp > POOL_QUAR_FRAME_WINDOW) {
            break;
        }
        fp = next;
    }
}

/* Park a freed big page. Returns true when parked (caller must NOT munmap).
 * Aborts on a detected double-free. */
static bool
pool_quarantine_park(n00b_pool_t *pool, void *addr, size_t mapped)
{
    uint32_t cap = pool_quar_capacity();
    if (cap == 0) {
        return false;
    }

    uintptr_t lo = (uintptr_t)addr;

    /* No explicit double-free scan is needed: a second free of a parked page
     * faults inside delete_one_page_entry's own entry-header reads (the page
     * is PROT_NONE), and the crash handler's quarantine lookup attributes it
     * — the faulting stack IS the double-freer, the recorded stack the first
     * free. */

    /* Release the PHYSICAL pages before revoking access: a parked page must
     * cost only address space. PROT_NONE alone leaves the dirty pages
     * resident/compressed until the ring-wrap munmap; MADV_FREE_REUSABLE
     * (macOS: immediate phys_footprint credit; MADV_FREE elsewhere) hands
     * them back now. Must precede the mprotect — the advice needs an
     * accessible mapping. */
#if defined(__APPLE__)
    (void)madvise(addr, mapped, MADV_FREE_REUSABLE);
#else
    (void)madvise(addr, mapped, MADV_FREE);
#endif

    /* Fault-on-touch before any slot work: the page is already unlinked and
     * private to this freeing thread, so no lock is needed around the
     * syscall. Failure is non-fatal: worst case the page stays readable
     * until the ring evicts it (same as no quarantine). */
    (void)mprotect(addr, mapped, PROT_NONE);

    /* Slot claim is PER-SLOT, not a global lock: the cursor hands every
     * parker a distinct sequence, so two frees contend on the same slot only
     * when `cap` parks are in flight at once (ring wrap onto an in-progress
     * slot). The busy bit makes that case correct without ever serializing
     * the normal path. */
    uint64_t               seq  = atomic_fetch_add(&n00b_pool_quar_cursor, 1);
    n00b_pool_quar_slot_t *slot = &n00b_pool_quar_ring[seq % cap];

    while (atomic_exchange(&slot->busy, 1) != 0) {}

    uintptr_t old_start = atomic_load(&slot->start);
    uint64_t  old_size  = slot->size;

    /* Publish order matters for the lock-free crash-time reader: empty the
     * slot first, fill the fields, then publish the new start LAST so a
     * concurrent find() never pairs the new range with stale attribution. */
    atomic_store(&slot->start, (uintptr_t)0);
    slot->size      = (uint64_t)mapped;
    slot->seq       = seq;
    slot->pool_name = ((n00b_allocator_t *)pool)->debug_name;
    pool_quar_capture_frames(slot->frees);
    atomic_store(&slot->start, lo);

    atomic_store(&slot->busy, 0);

    /* Evicted page (if any) is released outside the slot claim. */
    if (old_start != 0) {
        n00b_safe_munmap((void *)old_start, (size_t)old_size);
    }
    return true;
}

n00b_option_t(n00b_pool_quarantine_hit_t)
    n00b_pool_quarantine_find(uintptr_t addr)
{
    int32_t cap = atomic_load(&n00b_pool_quar_capacity);
    if (cap <= 0) {
        return n00b_option_none(n00b_pool_quarantine_hit_t);
    }
    for (int32_t i = 0; i < cap && i < N00B_POOL_QUAR_RING_MAX; i++) {
        n00b_pool_quar_slot_t *s     = &n00b_pool_quar_ring[i];
        uintptr_t              start = atomic_load(&s->start);
        if (start == 0 || addr < start || addr >= start + s->size) {
            continue;
        }
        n00b_pool_quarantine_hit_t hit = {
            .start     = start,
            .size      = s->size,
            .seq       = s->seq,
            .pool_name = s->pool_name,
        };
        for (int f = 0; f < N00B_POOL_QUARANTINE_FRAMES; f++) {
            hit.frees[f] = s->frees[f];
        }
        /* Seqlock-style re-check: park() zeroes start before recycling a
         * slot and republishes it last, so an unchanged start means the
         * fields copied above all belong to this range. A mismatch means
         * the ring wrapped mid-copy — skip rather than misattribute. */
        if (atomic_load(&s->start) != start) {
            continue;
        }
        return n00b_option_set(n00b_pool_quarantine_hit_t, hit);
    }
    return n00b_option_none(n00b_pool_quarantine_hit_t);
}

#define N00B_POOL_PAGE_DIAG_REGISTRY_MAX 262144

typedef struct {
    uintptr_t   start;
    uintptr_t   end;
    const char *name;
    const char *creation_loc;
    bool        registered;
    uint8_t     state; // 0 empty, 1 occupied, 2 tombstone
} n00b_pool_page_diag_entry_t;

static n00b_pool_page_diag_entry_t n00b_pool_page_diag_registry[N00B_POOL_PAGE_DIAG_REGISTRY_MAX];
static _Atomic uint32_t            n00b_pool_page_diag_lock;
static _Atomic uint64_t            n00b_pool_page_diag_count;
static _Atomic uint64_t            n00b_pool_page_diag_overflow_count;
static _Atomic uint64_t            n00b_pool_page_diag_lock_skip_count;

#define N00B_SYSTEM_POOL_AUDIT_SITE_MAX 2048
#define N00B_SYSTEM_POOL_AUDIT_PTR_MAX  262144

typedef struct {
    const char *site;
    uint64_t    alloc_count;
    uint64_t    free_count;
    uint64_t    alloc_bytes;
    uint64_t    free_bytes;
    uint64_t    live_count;
    uint64_t    live_bytes;
    uint8_t     state; // 0 empty, 1 occupied
} n00b_system_pool_audit_site_t;

typedef struct {
    uintptr_t ptr;
    uint64_t  bytes;
    uint32_t  site_ix;
    uint8_t   state; // 0 empty, 1 occupied, 2 tombstone
} n00b_system_pool_audit_ptr_t;

static n00b_system_pool_audit_site_t n00b_system_pool_audit_sites[N00B_SYSTEM_POOL_AUDIT_SITE_MAX];
static n00b_system_pool_audit_ptr_t  n00b_system_pool_audit_ptrs[N00B_SYSTEM_POOL_AUDIT_PTR_MAX];
static _Atomic uint32_t              n00b_system_pool_audit_lock_v;
static _Atomic uint64_t              n00b_system_pool_audit_alloc_count;
static _Atomic uint64_t              n00b_system_pool_audit_free_count;
static _Atomic uint64_t              n00b_system_pool_audit_alloc_bytes;
static _Atomic uint64_t              n00b_system_pool_audit_free_bytes;
static _Atomic uint64_t              n00b_system_pool_audit_ptr_overflow_count;
static _Atomic uint64_t              n00b_system_pool_audit_site_overflow_count;
static _Atomic uint64_t              n00b_system_pool_audit_free_miss_count;
static _Atomic uint64_t              n00b_system_pool_audit_lock_skip_count;

static inline void
pool_lock(n00b_pool_t *pool)
{
    while (n00b_atomic_or(&pool->lock, 1) != 0)
        ;
}

static inline void
pool_unlock(n00b_pool_t *pool)
{
    n00b_atomic_store(&pool->lock, 0);
}

static inline void
pool_registry_lock(void)
{
    while (atomic_exchange(&n00b_pool_registry_lock, 1) != 0)
        ;
}

static inline void
pool_registry_unlock(void)
{
    atomic_store(&n00b_pool_registry_lock, 0);
}

static void
pool_registry_register(n00b_pool_t *pool, const char *name)
{
    if (pool == nullptr) {
        return;
    }

    atomic_fetch_add(&n00b_pool_registry_init_count, 1);

    pool_registry_lock();
    for (uint64_t i = 0; i < N00B_POOL_GLOBAL_REGISTRY_MAX; i++) {
        if (n00b_pool_registry[i].pool == nullptr) {
            n00b_pool_registry[i] = (n00b_pool_registry_entry_t){
                .pool = pool,
                .name = name,
            };
            pool_registry_unlock();
            return;
        }
    }
    pool_registry_unlock();

    atomic_fetch_add(&n00b_pool_registry_overflow_count, 1);
}

static void
pool_registry_unregister(n00b_pool_t *pool)
{
    if (pool == nullptr) {
        return;
    }

    pool_registry_lock();
    for (uint64_t i = 0; i < N00B_POOL_GLOBAL_REGISTRY_MAX; i++) {
        if (n00b_pool_registry[i].pool == pool) {
            n00b_pool_registry[i] = (n00b_pool_registry_entry_t){};
            atomic_fetch_add(&n00b_pool_registry_destroy_count, 1);
            break;
        }
    }
    pool_registry_unlock();
}

// A pool's pages are registered in the global mmap tree (so
// n00b_mem_get_allocator / n00b_find_alloc_info can resolve an in-page
// pointer back to the pool — which is what makes n00b_free reclaim a
// pool allocation to its free list, and what lets the GC navigate it)
// when the pool is NOT __system AND either carries OOB metadata or is
// GC-visible (non-hidden):
//   - __system pools are bootstrap-critical (registering ctx->pool's
//     pages recurses through _n00b_alloc_raw) and are excluded.
//   - hidden, no-metadata, header-less pools are libn00b-internal, use
//     only the pool_free fast path, and never need address-to-allocator
//     resolution, so they stay out of the tree.
//   - everything else — external-metadata pools (incl. hidden ones like
//     user_pool) and plain non-hidden pools (e.g. a caller's claim pool)
//     — is registered so n00b_free works.
//   - hidden pools that carry INLINE headers are also registered. Such a
//     pool stays out of GC root scanning (n00b_mmap_is_gc_scannable is
//     false without a metadata pool) but still needs n00b_find_alloc_info
//     to resolve its allocations via the inline header — e.g. so the
//     self-contained rocs hot shard can be walked by n00b_marshal at seal
//     without paying a per-allocation OOB metadata dict. Inline headers on
//     a hidden pool are useless unless registered (find_alloc_info must
//     locate the page first), so gating on add_inline_header is exact.
static inline bool
pool_pages_registered(n00b_allocator_t *alloc)
{
    return !alloc->__system
        && (alloc->metadata_pool != nullptr || !alloc->hidden || alloc->add_inline_header);
}

[[n00b::nogc]] static inline bool
system_pool_audit_is_system(n00b_allocator_t *allocator)
{
    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    return rt != nullptr
        && allocator == (n00b_allocator_t *)&rt->system_pool;
}

[[n00b::nogc]] static inline bool
system_pool_audit_lock(void)
{
    for (uint32_t i = 0; i < 1024; i++) {
        uint32_t expected = 0;
        if (atomic_compare_exchange_weak(&n00b_system_pool_audit_lock_v,
                                         &expected,
                                         1)) {
            return true;
        }
    }
    atomic_fetch_add(&n00b_system_pool_audit_lock_skip_count, 1);
    return false;
}

[[n00b::nogc]] static inline void
system_pool_audit_unlock(void)
{
    atomic_store(&n00b_system_pool_audit_lock_v, 0);
}

[[n00b::nogc]] static inline uint64_t
system_pool_audit_site_hash(const char *site)
{
    return ((uintptr_t)site >> 4) & (N00B_SYSTEM_POOL_AUDIT_SITE_MAX - 1);
}

[[n00b::nogc]] static inline uint64_t
system_pool_audit_ptr_hash(uintptr_t ptr)
{
    return (ptr >> N00B_POST_ROUND_SHIFT) & (N00B_SYSTEM_POOL_AUDIT_PTR_MAX - 1);
}

[[n00b::nogc]] static bool
system_pool_audit_get_site(const char *site, uint32_t *out_ix)
{
    if (site == nullptr) {
        site = "";
    }

    uint64_t base = system_pool_audit_site_hash(site);
    for (uint64_t probe = 0; probe < N00B_SYSTEM_POOL_AUDIT_SITE_MAX; probe++) {
        uint64_t ix = (base + probe) & (N00B_SYSTEM_POOL_AUDIT_SITE_MAX - 1);
        n00b_system_pool_audit_site_t *slot = &n00b_system_pool_audit_sites[ix];
        if (slot->state == 1 && slot->site == site) {
            *out_ix = (uint32_t)ix;
            return true;
        }
        if (slot->state == 0) {
            *slot = (n00b_system_pool_audit_site_t){
                .site  = site,
                .state = 1,
            };
            *out_ix = (uint32_t)ix;
            return true;
        }
    }

    atomic_fetch_add(&n00b_system_pool_audit_site_overflow_count, 1);
    return false;
}

[[n00b::nogc]]
void
n00b_system_pool_audit_alloc(n00b_allocator_t *allocator,
                             void             *ptr,
                             uint64_t          bytes,
                             const char       *site)
{
    if (ptr == nullptr || !system_pool_audit_is_system(allocator)) {
        return;
    }

    atomic_fetch_add(&n00b_system_pool_audit_alloc_count, 1);
    atomic_fetch_add(&n00b_system_pool_audit_alloc_bytes, bytes);

    if (!system_pool_audit_lock()) {
        return;
    }

    uint32_t site_ix = 0;
    if (!system_pool_audit_get_site(site, &site_ix)) {
        system_pool_audit_unlock();
        return;
    }

    uintptr_t ptr_key         = (uintptr_t)ptr;
    uint64_t  base            = system_pool_audit_ptr_hash(ptr_key);
    uint64_t  first_tombstone = UINT64_MAX;
    for (uint64_t probe = 0; probe < N00B_SYSTEM_POOL_AUDIT_PTR_MAX; probe++) {
        uint64_t ix = (base + probe) & (N00B_SYSTEM_POOL_AUDIT_PTR_MAX - 1);
        n00b_system_pool_audit_ptr_t *slot = &n00b_system_pool_audit_ptrs[ix];
        if (slot->state == 1 && slot->ptr == ptr_key) {
            n00b_system_pool_audit_site_t *old_site =
                &n00b_system_pool_audit_sites[slot->site_ix];
            if (old_site->live_count > 0) {
                old_site->live_count--;
            }
            if (old_site->live_bytes >= slot->bytes) {
                old_site->live_bytes -= slot->bytes;
            }
            else {
                old_site->live_bytes = 0;
            }
            slot->bytes   = bytes;
            slot->site_ix = site_ix;
            goto recorded;
        }
        if (slot->state == 2 && first_tombstone == UINT64_MAX) {
            first_tombstone = ix;
            continue;
        }
        if (slot->state == 0) {
            if (first_tombstone != UINT64_MAX) {
                slot = &n00b_system_pool_audit_ptrs[first_tombstone];
            }
            *slot = (n00b_system_pool_audit_ptr_t){
                .ptr     = ptr_key,
                .bytes   = bytes,
                .site_ix = site_ix,
                .state   = 1,
            };
            goto recorded;
        }
    }

    if (first_tombstone != UINT64_MAX) {
        n00b_system_pool_audit_ptrs[first_tombstone] =
            (n00b_system_pool_audit_ptr_t){
                .ptr     = ptr_key,
                .bytes   = bytes,
                .site_ix = site_ix,
                .state   = 1,
            };
        goto recorded;
    }

    n00b_system_pool_audit_sites[site_ix].alloc_count++;
    n00b_system_pool_audit_sites[site_ix].alloc_bytes += bytes;
    atomic_fetch_add(&n00b_system_pool_audit_ptr_overflow_count, 1);
    system_pool_audit_unlock();
    return;

recorded:
    n00b_system_pool_audit_sites[site_ix].alloc_count++;
    n00b_system_pool_audit_sites[site_ix].alloc_bytes += bytes;
    n00b_system_pool_audit_sites[site_ix].live_count++;
    n00b_system_pool_audit_sites[site_ix].live_bytes += bytes;
    system_pool_audit_unlock();
}

[[n00b::nogc]]
void
n00b_system_pool_audit_free(n00b_allocator_t *allocator, void *ptr)
{
    if (ptr == nullptr || !system_pool_audit_is_system(allocator)) {
        return;
    }

    atomic_fetch_add(&n00b_system_pool_audit_free_count, 1);

    if (!system_pool_audit_lock()) {
        return;
    }

    uintptr_t ptr_key = (uintptr_t)ptr;
    uint64_t  base    = system_pool_audit_ptr_hash(ptr_key);
    for (uint64_t probe = 0; probe < N00B_SYSTEM_POOL_AUDIT_PTR_MAX; probe++) {
        uint64_t ix = (base + probe) & (N00B_SYSTEM_POOL_AUDIT_PTR_MAX - 1);
        n00b_system_pool_audit_ptr_t *slot = &n00b_system_pool_audit_ptrs[ix];
        if (slot->state == 0) {
            break;
        }
        if (slot->state != 1 || slot->ptr != ptr_key) {
            continue;
        }
        n00b_system_pool_audit_site_t *site =
            &n00b_system_pool_audit_sites[slot->site_ix];
        uint64_t bytes = slot->bytes;
        site->free_count++;
        site->free_bytes += bytes;
        if (site->live_count > 0) {
            site->live_count--;
        }
        if (site->live_bytes >= bytes) {
            site->live_bytes -= bytes;
        }
        else {
            site->live_bytes = 0;
        }
        atomic_fetch_add(&n00b_system_pool_audit_free_bytes, bytes);
        *slot = (n00b_system_pool_audit_ptr_t){
            .state = 2,
        };
        system_pool_audit_unlock();
        return;
    }

    atomic_fetch_add(&n00b_system_pool_audit_free_miss_count, 1);
    system_pool_audit_unlock();
}

[[n00b::nogc]] static void
system_pool_audit_record_top(n00b_system_pool_audit_stats_t *stats,
                             n00b_system_pool_audit_site_t  *site)
{
    if (site == nullptr || site->state != 1 || site->live_bytes == 0) {
        return;
    }

    uint64_t pos = stats->top_count;
    if (pos < N00B_SYSTEM_POOL_AUDIT_TOP_N) {
        stats->top_count++;
    }
    else {
        pos = N00B_SYSTEM_POOL_AUDIT_TOP_N - 1;
        if (site->live_bytes <= stats->top_live_bytes[pos]) {
            return;
        }
    }

    while (pos > 0 && site->live_bytes > stats->top_live_bytes[pos - 1]) {
        stats->top_site[pos]        = stats->top_site[pos - 1];
        stats->top_alloc_count[pos] = stats->top_alloc_count[pos - 1];
        stats->top_free_count[pos]  = stats->top_free_count[pos - 1];
        stats->top_alloc_bytes[pos] = stats->top_alloc_bytes[pos - 1];
        stats->top_free_bytes[pos]  = stats->top_free_bytes[pos - 1];
        stats->top_live_count[pos]  = stats->top_live_count[pos - 1];
        stats->top_live_bytes[pos]  = stats->top_live_bytes[pos - 1];
        pos--;
    }

    stats->top_site[pos]        = site->site != nullptr ? site->site : "";
    stats->top_alloc_count[pos] = site->alloc_count;
    stats->top_free_count[pos]  = site->free_count;
    stats->top_alloc_bytes[pos] = site->alloc_bytes;
    stats->top_free_bytes[pos]  = site->free_bytes;
    stats->top_live_count[pos]  = site->live_count;
    stats->top_live_bytes[pos]  = site->live_bytes;
}

[[n00b::nogc]]
n00b_system_pool_audit_stats_t
n00b_system_pool_audit_stats(void)
{
    n00b_system_pool_audit_stats_t stats = {
        .total_alloc_count   = atomic_load(&n00b_system_pool_audit_alloc_count),
        .total_free_count    = atomic_load(&n00b_system_pool_audit_free_count),
        .total_alloc_bytes   = atomic_load(&n00b_system_pool_audit_alloc_bytes),
        .total_free_bytes    = atomic_load(&n00b_system_pool_audit_free_bytes),
        .ptr_overflow_count  = atomic_load(&n00b_system_pool_audit_ptr_overflow_count),
        .site_overflow_count = atomic_load(&n00b_system_pool_audit_site_overflow_count),
        .free_miss_count     = atomic_load(&n00b_system_pool_audit_free_miss_count),
        .lock_skip_count     = atomic_load(&n00b_system_pool_audit_lock_skip_count),
    };

    if (!system_pool_audit_lock()) {
        return stats;
    }

    for (uint64_t i = 0; i < N00B_SYSTEM_POOL_AUDIT_SITE_MAX; i++) {
        n00b_system_pool_audit_site_t *site = &n00b_system_pool_audit_sites[i];
        if (site->state != 1) {
            continue;
        }
        stats.live_alloc_count += site->live_count;
        stats.live_bytes += site->live_bytes;
        system_pool_audit_record_top(&stats, site);
    }

    system_pool_audit_unlock();
    return stats;
}

[[n00b::nogc]] static inline bool
pool_page_diag_lock(void)
{
    for (uint32_t i = 0; i < 1024; i++) {
        uint32_t expected = 0;
        if (atomic_compare_exchange_weak(&n00b_pool_page_diag_lock, &expected, 1)) {
            return true;
        }
    }
    atomic_fetch_add(&n00b_pool_page_diag_lock_skip_count, 1);
    return false;
}

[[n00b::nogc]] static inline void
pool_page_diag_unlock(void)
{
    atomic_store(&n00b_pool_page_diag_lock, 0);
}

[[n00b::nogc]] static inline uint64_t
pool_page_diag_hash(uintptr_t start)
{
    return (start >> 12) & (N00B_POOL_PAGE_DIAG_REGISTRY_MAX - 1);
}

[[n00b::nogc]]
static void
pool_page_diag_register(n00b_pool_t *pool, n00b_pool_page_t *page)
{
    if (pool == nullptr || page == nullptr || page->mapped_size == 0) {
        return;
    }

    n00b_allocator_t *alloc = (n00b_allocator_t *)pool;
    uintptr_t         start = (uintptr_t)page;
    uintptr_t         end   = start + (uintptr_t)page->mapped_size;
    if (end <= start) {
        return;
    }

    n00b_pool_page_diag_entry_t new_entry = {
        .start        = start,
        .end          = end,
        .name         = alloc->debug_name,
        .creation_loc = alloc->creation_loc,
        .registered   = pool_pages_registered(alloc),
        .state        = 1,
    };

    if (!pool_page_diag_lock()) {
        return;
    }
    uint64_t first_tombstone = UINT64_MAX;
    uint64_t base            = pool_page_diag_hash(start);
    for (uint64_t probe = 0; probe < N00B_POOL_PAGE_DIAG_REGISTRY_MAX; probe++) {
        uint64_t ix = (base + probe) & (N00B_POOL_PAGE_DIAG_REGISTRY_MAX - 1);
        n00b_pool_page_diag_entry_t *slot = &n00b_pool_page_diag_registry[ix];
        if (slot->state == 1 && slot->start == start) {
            *slot = new_entry;
            pool_page_diag_unlock();
            return;
        }
        if (slot->state == 2 && first_tombstone == UINT64_MAX) {
            first_tombstone = ix;
            continue;
        }
        if (slot->state == 0) {
            if (first_tombstone != UINT64_MAX) {
                slot = &n00b_pool_page_diag_registry[first_tombstone];
            }
            *slot = new_entry;
            atomic_fetch_add(&n00b_pool_page_diag_count, 1);
            pool_page_diag_unlock();
            return;
        }
    }
    if (first_tombstone != UINT64_MAX) {
        n00b_pool_page_diag_registry[first_tombstone] = new_entry;
        atomic_fetch_add(&n00b_pool_page_diag_count, 1);
        pool_page_diag_unlock();
        return;
    }
    pool_page_diag_unlock();
    atomic_fetch_add(&n00b_pool_page_diag_overflow_count, 1);
}

[[n00b::nogc]]
static void
pool_page_diag_unregister(n00b_pool_page_t *page)
{
    if (page == nullptr) {
        return;
    }

    uintptr_t start = (uintptr_t)page;
    if (!pool_page_diag_lock()) {
        return;
    }
    uint64_t base = pool_page_diag_hash(start);
    for (uint64_t probe = 0; probe < N00B_POOL_PAGE_DIAG_REGISTRY_MAX; probe++) {
        uint64_t ix = (base + probe) & (N00B_POOL_PAGE_DIAG_REGISTRY_MAX - 1);
        n00b_pool_page_diag_entry_t *slot = &n00b_pool_page_diag_registry[ix];
        if (slot->state == 0) {
            break;
        }
        if (slot->state == 1 && slot->start == start) {
            *slot       = (n00b_pool_page_diag_entry_t){.state = 2};
            uint64_t old = atomic_load(&n00b_pool_page_diag_count);
            if (old != 0) {
                atomic_fetch_sub(&n00b_pool_page_diag_count, 1);
            }
            break;
        }
    }
    pool_page_diag_unlock();
}

[[n00b::nogc]]
static bool
pool_page_diag_lookup(uintptr_t addr,
                      uint64_t *out_start,
                      uint64_t *out_end,
                      const char **out_name,
                      const char **out_creation_loc,
                      bool *out_registered)
{
    if (addr == 0) {
        return false;
    }

    bool found = false;
    if (!pool_page_diag_lock()) {
        return false;
    }
    uint64_t base = pool_page_diag_hash(addr);
    for (uint64_t probe = 0; probe < N00B_POOL_PAGE_DIAG_REGISTRY_MAX; probe++) {
        uint64_t ix = (base + probe) & (N00B_POOL_PAGE_DIAG_REGISTRY_MAX - 1);
        n00b_pool_page_diag_entry_t *slot = &n00b_pool_page_diag_registry[ix];
        if (slot->state == 0) {
            break;
        }
        if (slot->state != 1 || slot->start != addr) {
            continue;
        }
        if (out_start != nullptr) {
            *out_start = (uint64_t)slot->start;
        }
        if (out_end != nullptr) {
            *out_end = (uint64_t)slot->end;
        }
        if (out_name != nullptr) {
            *out_name = slot->name != nullptr ? slot->name : "";
        }
        if (out_creation_loc != nullptr) {
            *out_creation_loc = slot->creation_loc;
        }
        if (out_registered != nullptr) {
            *out_registered = slot->registered;
        }
        found = true;
        break;
    }
    pool_page_diag_unlock();
    return found;
}

#ifdef N00B_DEBUG
static bool
pool_mmap_audit_enabled(void)
{
    static _Atomic int enabled;
    int cached = atomic_load(&enabled);
    if (cached != 0) {
        return cached == 2;
    }
    bool on = getenv("N00B_POOL_MMAP_AUDIT") != nullptr;
    atomic_store(&enabled, on ? 2 : 1);
    return on;
}

static void
pool_mmap_audit(n00b_pool_t *pool, const char *op, void *addr, size_t mapped)
{
    n00b_allocator_t *alloc = (n00b_allocator_t *)pool;
    if (!alloc->hidden || !pool_mmap_audit_enabled()) {
        return;
    }

    fprintf(stderr,
            "n00b pool-mmap-audit op=%s pool=%s hidden=1 system=%u registered=%u "
            "addr=%p size=%zu live_mapped=%llu pages=%llu big_maps=%llu big_unmaps=%llu\n",
            op,
            alloc->debug_name != nullptr ? alloc->debug_name : "",
            (unsigned)alloc->__system,
            (unsigned)pool_pages_registered(alloc),
            addr,
            mapped,
            (unsigned long long)n00b_pool_mapped_bytes(pool),
            (unsigned long long)n00b_pool_page_count(pool),
            (unsigned long long)n00b_pool_big_map_count(pool),
            (unsigned long long)n00b_pool_big_unmap_count(pool));
}
#else
static inline void
pool_mmap_audit(n00b_pool_t *pool, const char *op, void *addr, size_t mapped)
{
    (void)pool;
    (void)op;
    (void)addr;
    (void)mapped;
}
#endif

static inline void *
new_page_entry(n00b_pool_t *pool, uint64_t *sz_ptr)
{
    uint64_t sz     = *sz_ptr;
    uint64_t hdr_sz = n00b_align(sizeof(n00b_pool_page_t));
    sz += hdr_sz;

    n00b_allocator_t *alloc      = (n00b_allocator_t *)pool;
    char             *name       = (char *)alloc->debug_name;
    uint64_t          aligned_sz = n00b_page_align(sz);
    /* skip_register=true puts the page back under pool control —
     * the matching @ref n00b_mmap_register_pool_page below decides
     * whether (and how) this page enters the global mmap tree.
     * The pool side wants this control so the unregister at free
     * time strictly precedes munmap (avoiding a window where a
     * concurrent GC mark scan can dereference a tree entry whose
     * backing page is no longer mapped). */
    auto              mmap_r     = n00b_mmap(aligned_sz,
                            .allocator     = alloc,
                            .name          = name,
                            .kind          = n00b_mmap_pool,
                            .skip_register = true);
    assert(n00b_result_is_ok(mmap_r));
    n00b_pool_page_t *cur = n00b_result_get(mmap_r);

    /* Register the page with the allocator so @ref n00b_mem_get_allocator
     * can resolve in-page pointers back to this pool, which is what
     * makes n00b_free → pool_free work (the address-to-allocator
     * lookup goes through the mmap tree).
     *
     * Only register hidden pools that have @c external_metadata.
     * Two distinct exclusions:
     *
     *  - @c __system pools (the mmap context's own backing @c ctx->pool
     *    and @c rt->system_pool) are bootstrap-critical: registering
     *    @c ctx->pool's pages here recurses infinitely
     *    (register_pool_page → mmaps_insert_raw → _n00b_alloc_raw →
     *    pool_alloc on ctx->pool → new_page_entry → back here).
     *
     *  - Non-metadata hidden pools (@c conduit_pool, per-thread
     *    @c ctx->pool, etc.) are libn00b-internal and exclusively use
     *    the @c pool_free fast path; their pages do not need
     *    address-to-allocator resolution.  Putting them in the global
     *    mmap tree adds GC-scan tree traversal load and a race window
     *    (concurrent @c pool_free → unregister → munmap vs GC mark
     *    iterator) for no benefit. */
    if (pool_pages_registered(alloc)) {
        (void)n00b_mmap_register_pool_page((void *)cur, (char *)cur + aligned_sz, alloc, name);
    }

    *sz_ptr          = aligned_sz - hdr_sz;
    cur->mapped_size = aligned_sz;
    void *res        = (void *)cur + hdr_sz;

    pool_lock(pool);
    cur->next = pool->page_table;
    if (cur->next) {
        cur->next->prev = cur;
    }
    pool->page_table = cur;
    pool->mapped_bytes_total += (uint64_t)cur->mapped_size;
    pool_unlock(pool);

    pool_mmap_audit(pool, "map", (void *)cur, (size_t)cur->mapped_size);
    pool_page_diag_register(pool, cur);

    return res;
}

// Here, sz includes space for the n00b_pool_entry_t at the front.
static inline n00b_pool_entry_t *
big_mmap(n00b_pool_t *pool, uint64_t sz)
{
    n00b_pool_entry_t *entry = new_page_entry(pool, &sz);
    entry->list_index        = N00B_NUM_FREE_LISTS;

    /* Diagnostics: account for big-mmap allocations symmetrically
     * with delete_one_page_entry below so callers can verify the
     * fast path is balanced. */
    atomic_fetch_add(&pool->big_map_count, 1);

    return entry;
}

static inline void
delete_one_page_entry(n00b_pool_t *pool, n00b_pool_page_t *entry)
{
    pool_lock(pool);

    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    else {
        assert(pool->page_table == entry);
        pool->page_table = entry->next;
    }

    if (entry->next) {
        entry->next->prev = entry->prev;
    }

    /* Capture mapped_size while we still hold the lock; the munmap
     * itself is fine to do unlocked once the page is unlinked. */
    size_t mapped = entry->mapped_size;
    if (pool->mapped_bytes_total >= (uint64_t)mapped) {
        pool->mapped_bytes_total -= (uint64_t)mapped;
    }
    else {
        pool->mapped_bytes_total = 0;
    }

    pool_unlock(pool);

    /* Symmetric counterpart to new_page_entry's optional
     * @ref n00b_mmap_register_pool_page: pull the tree entry
     * BEFORE munmap so a concurrent GC mark pass can't follow a
     * stale interval-tree node into a no-longer-mapped page and
     * SIGBUS. The unregister is a no-op when the page was never
     * registered, so the check here mirrors the register-side gate
     * verbatim (skip @c __system bootstrap pools and skip pools
     * without @c external_metadata). */
    n00b_allocator_t *alloc = (n00b_allocator_t *)pool;
    if (pool_pages_registered(alloc)) {
        n00b_mmap_unregister((void *)entry);
    }

    pool_mmap_audit(pool, "unmap", (void *)entry, mapped);
    pool_page_diag_unregister(entry);

    /* Big-alloc free path: actually release the page back to the OS.
     * Without this the page stayed mapped until pool_destroy — any
     * pool client n00b_free-ing a >N00B_NUM_FREE_LISTS-class
     * allocation observed the slot count drop but RSS keep climbing.
     * Under the diagnostic quarantine the release is deferred: the page
     * is parked PROT_NONE so a use-after-free faults attributably (see
     * pool_quarantine_park above). */
    if (mapped != 0) {
        if (pool_quarantine_park(pool, (void *)entry, mapped)) {
            atomic_fetch_add(&pool->big_unmap_count, 1);
        }
        else {
            uint64_t fail_before = atomic_load(&n00b_munmap_fail_count);
            n00b_safe_munmap((void *)entry, mapped);
            if (atomic_load(&n00b_munmap_fail_count) != fail_before) {
                atomic_fetch_add(&n00b_pool_big_unmap_fail_count, 1);
                atomic_fetch_add(&n00b_pool_big_unmap_fail_bytes,
                                 (uint64_t)mapped);
            }
            atomic_fetch_add(&pool->big_unmap_count, 1);
        }
    }
}

static inline void *
add_page_to_list(n00b_pool_t *pool, uint64_t sz, n00b_llstack_t *stack)
{
    // Return one, and push the others to the free list.
    // Yes, we could pre-link the extras, but that's a PITA.
    uint64_t alloc_sz = n00b_page_size - n00b_align(sizeof(n00b_pool_page_t));
    void    *res      = new_page_entry(pool, &alloc_sz);

    assert(!(((uint64_t)sz) & 15));

    char    *p = ((char *)res) + n00b_align(sz);
    uint32_t n = (alloc_sz / n00b_align(sz));

    for (uint32_t i = 1; i < n; i++) {
        // Yes, we end up having to cast.
        n00b_llstack_node_t *node = (n00b_llstack_node_t *)p;
        p += n00b_align(sz);
        n00b_llstack_push_node(stack, node);
    }

    return res;
}

static void
pool_destroy(n00b_pool_t *pool)
{
    // Drop from the audit ring BEFORE freeing pages, so a concurrent census
    // never dereferences a half-freed pool (mirrors the arena delete hook).
    n00b_allocator_audit_unregister((n00b_allocator_t *)pool);
    pool_registry_unregister(pool);

    n00b_pool_page_t *entry = pool->page_table;
    n00b_pool_page_t *next;

    /* Scrub the lock chains FIRST, walking the page table, so that
     * the scrubber can chase chain links without ever reading from
     * a freed page.  Pool pages can hold n00b_mutex_t /
     * n00b_rwlock_t (e.g. as fields of an in-pool Regex), and
     * `n00b_lock_acquire_accounting` threads those onto each
     * thread's exclusive-lock chain.  The owning regex's teardown
     * destroys the pool without releasing them, so the chain would
     * otherwise be left with dangling pointers into freed memory. */
    if (pool->scrub_locks_on_destroy) {
        /* Walk the thread table ONCE for the whole pool (the scrubber
         * tests each held-lock chain entry against the pool's page
         * table).  The old per-page call paid pages * 4096 thread-record
         * walks per destroy, which froze the process during GC cleanup. */
        n00b_lock_chains_scrub_pool(pool);
    }

    /* If this pool's pages were registered in the global mmap tree,
     * pull each one out BEFORE munmap so a later n00b_mem_get_allocator
     * / GC mark can't follow a stale tree node into a freed page. */
    bool registered = pool_pages_registered((n00b_allocator_t *)pool);

    while (entry) {
        next          = entry->next;
        /* Big-alloc pages can be larger than n00b_page_size — use the
         * captured mapped_size so we unmap the right region length. */
        size_t mapped = entry->mapped_size != 0 ? entry->mapped_size : n00b_page_size;
        if (registered) {
            n00b_mmap_unregister((void *)entry);
        }
        pool_page_diag_unregister(entry);
        uint64_t fail_before = atomic_load(&n00b_munmap_fail_count);
        n00b_safe_munmap(entry, mapped);
        atomic_fetch_add(&n00b_pool_destroy_unmap_count, 1);
        atomic_fetch_add(&n00b_pool_destroy_unmap_bytes, (uint64_t)mapped);
        if (atomic_load(&n00b_munmap_fail_count) != fail_before) {
            atomic_fetch_add(&n00b_pool_destroy_unmap_fail_count, 1);
            atomic_fetch_add(&n00b_pool_destroy_unmap_fail_bytes, (uint64_t)mapped);
        }
        entry = next;
    }
}

static void
pool_free(n00b_pool_t *pool, void *ptr)
{
    n00b_system_pool_audit_free((n00b_allocator_t *)pool, ptr);

    n00b_pool_entry_t *entry = (n00b_pool_entry_t *)((char *)ptr - N00B_ALIGN);
    assert(entry->list_index <= N00B_NUM_FREE_LISTS);

    if (entry->list_index == N00B_NUM_FREE_LISTS) {
        /* `entry` sits at offset n00b_align(sizeof(n00b_pool_page_t))
         * past the page header (see `new_page_entry`).  Decrementing
         * a `n00b_pool_page_t *` by 1 only walks back
         * `sizeof(n00b_pool_page_t)` bytes, which is wrong when that
         * is smaller than N00B_ALIGN. */
        n00b_pool_page_t *page
            = (n00b_pool_page_t *)(((char *)entry) - n00b_align(sizeof(n00b_pool_page_t)));
        delete_one_page_entry(pool, page);
        return;
    }

    unsigned int ix = entry->list_index;
    /* Entry size at bucket index ix is (1u << ix) << POST_ROUND_SHIFT
     * bytes — the same formula pool_alloc uses to derive ix from the
     * rounded size.  Earlier the memset used `ix << POST_ROUND_SHIFT`,
     * which under-zeros the tail of every bucket (and zeros 0 bytes
     * at ix=0); freshly-popped entries then return non-zero bytes,
     * silently violating the documented zero-fill contract. */
    memset(entry, 0, (1u << ix) << N00B_POST_ROUND_SHIFT);
    n00b_llstack_node_t *node_ptr = (n00b_llstack_node_t *)entry;

    n00b_llstack_push_node(&pool->free_lists[ix], node_ptr);
}

static void *
pool_alloc(n00b_pool_t *pool, uint64_t request, void *ignore)
{
    request += n00b_align(sizeof(n00b_pool_entry_t));

    uint64_t     sz = n00b_align_closest_pow2_ceil(request);
    unsigned int ix = n00b_int_log2(sz >> N00B_POST_ROUND_SHIFT);

    n00b_pool_entry_t *entry;

    uint64_t slab_payload = n00b_page_size - n00b_align(sizeof(n00b_pool_page_t));

    /* On 4 KiB-page Linux, the 4 KiB/8 KiB nominal slab classes cannot fit
     * after the pool page header. Route those requests through the single-entry
     * mmap path instead of creating undersized slab slots. The guard-mode
     * check (page per alloc; see pool_guard_page_per_alloc) also lands here
     * so slab-class objects become individually parkable by the quarantine. */
    if (ix >= N00B_NUM_FREE_LISTS || sz > slab_payload
        || pool_guard_page_per_alloc(pool)) {
        entry = big_mmap(pool, request);
        ix    = N00B_NUM_FREE_LISTS;
    }
    else {
        n00b_llstack_t      *stack = &pool->free_lists[ix];
        n00b_llstack_node_t *nptr  = n00b_llstack_pop_node(stack);

        if (nptr) {
            entry = (n00b_pool_entry_t *)nptr;
        }
        else {
            entry = add_page_to_list(pool, sz, stack);
        }
    }

    entry->list_index = ix;
    void *p           = (void *)(((char *)entry) + N00B_ALIGN);

    assert(!(((uint64_t)p) & (N00B_ALIGN - 1)));
    return p;
}

size_t
n00b_pool_usable_size(void *ptr)
{
    /* Recover the usable byte count for a raw pool allocation (the
     * pointer returned by the pool's zero_alloc).  Used by the libc-malloc
     * interposition layer for realloc()/malloc_usable_size().  The size
     * class is stored in the n00b_pool_entry_t header at -N00B_ALIGN; the
     * formulas here mirror pool_alloc / pool_free exactly. */
    if (ptr == nullptr) {
        return 0;
    }

    n00b_pool_entry_t *entry = (n00b_pool_entry_t *)((char *)ptr - N00B_ALIGN);
    unsigned int       ix    = entry->list_index;

    if (ix < N00B_NUM_FREE_LISTS) {
        /* Small slab: the bucket is (1<<ix)<<POST_ROUND_SHIFT bytes; the
         * user gets all but the N00B_ALIGN-byte entry header. */
        size_t bucket = ((size_t)1u << ix) << N00B_POST_ROUND_SHIFT;
        return bucket - N00B_ALIGN;
    }

    /* Big mmap: the page header sits n00b_align(sizeof(page)) before the
     * entry, and the user pointer is N00B_ALIGN past the entry. */
    n00b_pool_page_t *page
        = (n00b_pool_page_t *)((char *)entry - n00b_align(sizeof(n00b_pool_page_t)));
    size_t hdr = n00b_align(sizeof(n00b_pool_page_t)) + N00B_ALIGN;

    if (page->mapped_size <= hdr) {
        return 0;
    }
    return page->mapped_size - hdr;
}

uint64_t
n00b_pool_mapped_bytes(n00b_pool_t *pool)
{
    if (pool == nullptr) {
        return 0;
    }
    // O(1): read the running total maintained under the pool lock by
    // new_page_entry / delete_one_page_entry (previously an O(pages)
    // page-table walk, which was called per record by
    // rocs_store_should_seal_hot -> O(records * pages)).
    pool_lock(pool);
    uint64_t total = pool->mapped_bytes_total;
    pool_unlock(pool);
    return total;
}

uint64_t
n00b_pool_page_count(n00b_pool_t *pool)
{
    if (pool == nullptr) {
        return 0;
    }
    uint64_t          total = 0;
    n00b_pool_page_t *p;
    pool_lock(pool);
    for (p = pool->page_table; p != nullptr; p = p->next) {
        total++;
    }
    pool_unlock(pool);
    return total;
}

static void
pool_global_stats_record_top(n00b_pool_global_stats_t *stats,
                             n00b_pool_t              *pool,
                             const char               *name,
                             uint64_t                  mapped,
                             uint64_t                  pages,
                             bool                      registered)
{
    uint64_t pos = stats->top_count;
    if (pos < N00B_POOL_STATS_TOP_N) {
        stats->top_count++;
    }
    else {
        pos = N00B_POOL_STATS_TOP_N - 1;
        if (mapped <= stats->top_mapped_bytes[pos]) {
            return;
        }
    }

    while (pos > 0 && mapped > stats->top_mapped_bytes[pos - 1]) {
        stats->top_name[pos]              = stats->top_name[pos - 1];
        stats->top_creation_loc[pos]      = stats->top_creation_loc[pos - 1];
        stats->top_mapped_bytes[pos]      = stats->top_mapped_bytes[pos - 1];
        stats->top_page_count[pos]        = stats->top_page_count[pos - 1];
        stats->top_big_map_count[pos]     = stats->top_big_map_count[pos - 1];
        stats->top_big_unmap_count[pos]   = stats->top_big_unmap_count[pos - 1];
        stats->top_hidden[pos]            = stats->top_hidden[pos - 1];
        stats->top_external_metadata[pos] = stats->top_external_metadata[pos - 1];
        stats->top_mmap_registered[pos]   = stats->top_mmap_registered[pos - 1];
        stats->top_system[pos]            = stats->top_system[pos - 1];
        pos--;
    }

    stats->top_name[pos]              = name != nullptr ? name : "";
    stats->top_creation_loc[pos]      = pool->vtable.creation_loc != nullptr
                                            ? pool->vtable.creation_loc
                                            : "";
    stats->top_mapped_bytes[pos]      = mapped;
    stats->top_page_count[pos]        = pages;
    stats->top_big_map_count[pos]     = n00b_pool_big_map_count(pool);
    stats->top_big_unmap_count[pos]   = n00b_pool_big_unmap_count(pool);
    stats->top_hidden[pos]            = pool->vtable.hidden ? 1 : 0;
    stats->top_external_metadata[pos] = pool->vtable.metadata_pool != nullptr ? 1 : 0;
    stats->top_mmap_registered[pos]   = registered ? 1 : 0;
    stats->top_system[pos]            = pool->vtable.__system ? 1 : 0;
}

// Insert-or-aggregate one live pool into the by-name census. Names are the
// static string literals passed to n00b_pool_init, so pointer-or-strcmp
// matching is exact; distinct names beyond the table fold into "(other)".
static void
pool_name_census_add(n00b_pool_name_census_t *census,
                     const char              *name,
                     uint64_t                 mapped)
{
    if (name == nullptr || name[0] == '\0') {
        name = "(unnamed)";
    }
    for (uint64_t i = 0; i < census->entry_count; i++) {
        if (census->name[i] == name || strcmp(census->name[i], name) == 0) {
            census->pool_count[i]++;
            census->mapped_bytes[i] += mapped;
            return;
        }
    }
    if (census->entry_count < N00B_POOL_NAME_CENSUS_MAX) {
        uint64_t i = census->entry_count++;
        census->name[i]         = name;
        census->pool_count[i]   = 1;
        census->mapped_bytes[i] = mapped;
        return;
    }
    uint64_t last = N00B_POOL_NAME_CENSUS_MAX - 1;
    census->name[last] = "(other)";
    census->pool_count[last]++;
    census->mapped_bytes[last] += mapped;
}

[[n00b::nogc]] n00b_pool_name_census_t
n00b_pool_name_census(void)
{
    n00b_pool_name_census_t census = {};

    pool_registry_lock();
    for (uint64_t i = 0; i < N00B_POOL_GLOBAL_REGISTRY_MAX; i++) {
        n00b_pool_t *pool = n00b_pool_registry[i].pool;
        if (pool == nullptr) {
            continue;
        }
        census.live_pool_total++;
        pool_name_census_add(&census,
                             n00b_pool_registry[i].name,
                             n00b_pool_mapped_bytes(pool));
    }
    pool_registry_unlock();

    // Sort by mapped bytes descending (small fixed table; insertion sort).
    for (uint64_t i = 1; i < census.entry_count; i++) {
        const char *name   = census.name[i];
        uint64_t    count  = census.pool_count[i];
        uint64_t    mapped = census.mapped_bytes[i];
        uint64_t    j      = i;
        while (j > 0 && census.mapped_bytes[j - 1] < mapped) {
            census.name[j]         = census.name[j - 1];
            census.pool_count[j]   = census.pool_count[j - 1];
            census.mapped_bytes[j] = census.mapped_bytes[j - 1];
            j--;
        }
        census.name[j]         = name;
        census.pool_count[j]   = count;
        census.mapped_bytes[j] = mapped;
    }
    return census;
}

[[n00b::nogc]] n00b_pool_global_stats_t
n00b_pool_global_stats(void)
{
    n00b_pool_global_stats_t stats = {
        .total_init_count        = atomic_load(&n00b_pool_registry_init_count),
        .total_destroy_count     = atomic_load(&n00b_pool_registry_destroy_count),
        .registry_overflow_count = atomic_load(&n00b_pool_registry_overflow_count),
        .destroy_unmap_count     = atomic_load(&n00b_pool_destroy_unmap_count),
        .destroy_unmap_bytes     = atomic_load(&n00b_pool_destroy_unmap_bytes),
        .destroy_unmap_fail_count =
            atomic_load(&n00b_pool_destroy_unmap_fail_count),
        .destroy_unmap_fail_bytes =
            atomic_load(&n00b_pool_destroy_unmap_fail_bytes),
        .big_unmap_fail_count = atomic_load(&n00b_pool_big_unmap_fail_count),
        .big_unmap_fail_bytes = atomic_load(&n00b_pool_big_unmap_fail_bytes),
        .diagnostic_page_count = atomic_load(&n00b_pool_page_diag_count),
        .diagnostic_page_overflow_count =
            atomic_load(&n00b_pool_page_diag_overflow_count),
        .diagnostic_page_lock_skip_count =
            atomic_load(&n00b_pool_page_diag_lock_skip_count),
    };

    pool_registry_lock();
    for (uint64_t i = 0; i < N00B_POOL_GLOBAL_REGISTRY_MAX; i++) {
        n00b_pool_t *pool = n00b_pool_registry[i].pool;
        if (pool == nullptr) {
            continue;
        }

        const char *name       = n00b_pool_registry[i].name;
        bool        hidden     = pool->vtable.hidden;
        bool        registered = pool_pages_registered((n00b_allocator_t *)pool);
        uint64_t    mapped     = n00b_pool_mapped_bytes(pool);
        uint64_t    pages      = n00b_pool_page_count(pool);

        stats.live_pool_count++;
        stats.live_page_count += pages;
        stats.live_mapped_bytes += mapped;
        if (hidden) {
            stats.live_hidden_pool_count++;
            stats.live_hidden_mapped_bytes += mapped;
        }
        if (registered) {
            stats.live_registered_pool_count++;
            stats.live_registered_mapped_bytes += mapped;
        }
        else {
            stats.live_unregistered_pool_count++;
            stats.live_unregistered_mapped_bytes += mapped;
        }
        if (pool->vtable.__system) {
            stats.live_system_pool_count++;
            stats.live_system_mapped_bytes += mapped;
        }

        pool_global_stats_record_top(&stats, pool, name, mapped, pages, registered);
    }
    pool_registry_unlock();

    return stats;
}

bool
n00b_pool_diagnostic_lookup_page(uintptr_t addr,
                                 uint64_t *out_start,
                                 uint64_t *out_end,
                                 const char **out_name,
                                 const char **out_creation_loc,
                                 bool *out_registered)
{
    if (addr == 0) {
        return false;
    }

    return pool_page_diag_lookup(addr,
                                 out_start,
                                 out_end,
                                 out_name,
                                 out_creation_loc,
                                 out_registered);
}

uint64_t
n00b_pool_big_map_count(n00b_pool_t *pool)
{
    return pool == nullptr ? 0 : atomic_load(&pool->big_map_count);
}

uint64_t
n00b_pool_big_unmap_count(n00b_pool_t *pool)
{
    return pool == nullptr ? 0 : atomic_load(&pool->big_unmap_count);
}

[[n00b::nogc]] static void
pool_pre_destroy(n00b_allocator_t *allocator)
{
    n00b_runtime_t *rt = n00b_default_runtime_or_null();

    if (rt != nullptr && n00b_atomic_load(&rt->stw_active)) {
        /* During STW the initiating thread is the only runnable thread.
         * Waiting for epoch quiescence here deadlocks if suspended threads
         * still have older reservations.  Non-STW pool teardown still drains
         * retire lists normally. */
        return;
    }

    n00b_epoch_drain_allocator(allocator);
}

n00b_allocator_t *
n00b_pool_init_at(n00b_pool_t *pool) _kargs
{
    bool        __system               = false;
    bool        inline_headers         = false;
    bool        external_metadata      = false;
    bool        hidden                 = false;
    bool        scrub_locks_on_destroy = true;
    const char *name                   = "pool";
    // "file:line" of the create-site, injected by the n00b_pool_init macro.
    const char *creation_loc           = nullptr;
    // Ref-counting (both force external_metadata; inline headers stay
    // marshal-only). pool_refcount: per-pool count, reclaim whole pool at last
    // unref. alloc_refcount: per-allocation count in the OOB flex tail, return
    // the alloc to the pool at its last unref.
    bool        pool_refcount          = false;
    bool        alloc_refcount         = false;
    bool        use_epochs             = true;
}
{
    // Only per-ALLOC refcounting needs OOB: its counter lives in the OOB flex
    // tail (the inline header is the marshal payload and must not change). So
    // .alloc_refcount forces OOB metadata on and inline headers off.
    //
    // Per-POOL refcounting does NOT touch metadata at all — its counter is a
    // slot in the pool header (pool_refs). It is therefore orthogonal to the
    // metadata strategy and leaves the caller's inline_headers/external_metadata
    // choice intact. This matters for the rocs hot shard, which is .pool_refcount
    // AND inline-headers-only (external_metadata=false) so marshal can resolve
    // every shard alloc via its inline header without paying OOB's per-alloc
    // dict put/get + STW-gate read-lock on the ingest hot path.
    if (alloc_refcount) {
        external_metadata = true;
        inline_headers    = false;
    }

    n00b_allocator_setup((n00b_allocator_t *)pool,
                         (n00b_calloc_fn)pool_alloc,
                         .free              = (n00b_free_fn)pool_free,
                         .pre_destroy       = pool_pre_destroy,
                         .destroy           = (n00b_allocator_destroy_fn)pool_destroy,
                         .name              = (char *)name,
                         .inline_headers    = inline_headers,
                         .external_metadata = external_metadata,
                         .hidden            = hidden,
                         .use_epochs        = use_epochs,
                         .__system          = __system,
                         .creation_loc      = creation_loc);

    // Allocator-specific OOB flex-tail size. .alloc_refcount reserves a
    // uint32_t counter at the end of each OOB record (n00b_oob_hdr_t.alloc_extra).
    // Must be set after n00b_allocator_setup, which overwrites the whole struct.
    pool->vtable.oob_extra_size = alloc_refcount ? (uint32_t)sizeof(uint32_t) : 0;

    pool->lock                   = 0;
    pool->page_table             = nullptr;
    pool->mapped_bytes_total     = 0;
    pool->scrub_locks_on_destroy = scrub_locks_on_destroy;
    atomic_store(&pool->big_map_count, 0);
    atomic_store(&pool->big_unmap_count, 0);

    // Per-pool refcount. Starts at 1 (the creator's ref) when armed; the last
    // n00b_pool_unref reclaims the pool via on_last_unref or n00b_allocator_destroy.
    // The optional last-unref hook is installed later via n00b_pool_set_unref_cb.
    pool->pool_refcounted = pool_refcount;
    atomic_store(&pool->pool_refs, pool_refcount ? 1 : 0);
    pool->on_last_unref = nullptr;
    pool->unref_ctx     = nullptr;

    for (int i = 0; i < N00B_NUM_FREE_LISTS; i++) {
        n00b_llstack_init(&pool->free_lists[i]);
    }

    pool_registry_register(pool, name);
    // Pools are arenas too for the memory census: track every live pool in the
    // shared allocator audit ring (debug-only; no-op otherwise).
    n00b_allocator_audit_register((n00b_allocator_t *)pool);

    return (n00b_allocator_t *)pool;
}

void
n00b_pool_set_unref_cb(n00b_pool_t *pool, n00b_pool_unref_cb_t cb, void *ctx)
{
    if (pool == nullptr || !pool->pool_refcounted) {
        return;
    }
    pool->on_last_unref = cb;
    pool->unref_ctx     = ctx;
}

void
n00b_pool_ref(n00b_pool_t *pool)
{
    if (pool == nullptr || !pool->pool_refcounted) {
        return;
    }
    atomic_fetch_add_explicit(&pool->pool_refs, 1, memory_order_relaxed);
}

void
n00b_pool_unref(n00b_pool_t *pool)
{
    if (pool == nullptr || !pool->pool_refcounted) {
        return;
    }
    // acq_rel so the thread that observes the 1->0 transition has a
    // happens-before edge to every prior ref-holder's last use of the pool.
    int32_t prev = atomic_fetch_sub_explicit(&pool->pool_refs, 1, memory_order_acq_rel);
    if (prev != 1) {
        return;
    }

    if (pool->on_last_unref != nullptr) {
        pool->on_last_unref(pool->unref_ctx);
    }
    else {
        n00b_allocator_destroy((n00b_allocator_t *)pool);
    }
}

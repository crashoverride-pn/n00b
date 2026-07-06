#define N00B_MEM_INTERNAL_API
#define N00B_USE_INTERNAL_API

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/alloc_mdata.h"
#include "core/alloc.h"
#include "core/memory_info.h"
#include "core/mmaps.h"
#include "core/align.h"
#include "core/arena.h"
#include "core/pool.h"
#include <stdio.h>
#include "core/atomic.h"
#include "core/gc.h"
#include "core/thread.h"
#include "core/random.h"
#include "adt/dict_untyped.h"
#include "core/stw.h"

// N00B_DEFAULT_SCRATCH_ARENA_SIZE now defined in arena.h

// ---------------------------------------------------------------------------
// Arena audit ring.
//
// Tracks EVERY live arena/pool so other subsystems can enumerate the full set:
// memory accounting attributes arena-backed bytes (including the otherwise-
// invisible hidden/no_map ones — the GC's md_pool metadata arenas, scratch
// arenas, collection spaces), and the GC's per-collect conservative-scan
// acceptance tree (n00b_build_scan_tree) walks it to find every allocator whose
// addresses the collector will accept. Each allocator registers its pointer on
// create and removes it on destroy.
//
// The RING ITSELF (storage + register/unregister/foreach) is ALWAYS compiled in:
// the GC scan-tree depends on it, so it is part of the core collect path, not a
// debug aid. register/unregister are lock-free CAS into a fixed array — cheap.
// Only the heavier CENSUS/heartbeat snapshot (further down) is gated behind
// N00B_ARENA_AUDIT_ON: it stop-the-worlds and livelocked the gateway when run on
// every status-file write (the temporary `-DN00B_DEBUG_ARENA_AUDIT` force-enable
// was dropped for exactly that reason), so it is compiled in only under
// N00B_DEBUG.
//
// [[n00b::nogc]]: holds GC-adjacent allocator pointers, so it must never be a GC
// root or be scanned.
#if defined(N00B_DEBUG) || defined(N00B_DEBUG_ARENA_AUDIT)
#define N00B_ARENA_AUDIT_ON 1
#endif

#define N00B_ARENA_AUDIT_MAX 8192

[[n00b::nogc]] static _Atomic(n00b_allocator_t *)
    n00b_arena_audit_ring[N00B_ARENA_AUDIT_MAX];
[[n00b::nogc]] static _Atomic uint64_t n00b_arena_audit_cursor;

// Register/unregister ANY allocator (arena or pool) — pools are arenas too for
// census purposes. Called from n00b_initialize_arena and n00b_pool_init_at /
// pool_destroy.
void
n00b_allocator_audit_register(n00b_allocator_t *a)
{
    // Stack-resident, GC-opaque allocator headers are not durable enough for
    // the global audit ring: the header storage dies with its frame/thread,
    // while the ring is walked by later collections. Do keep stack-resident
    // GC-visible pools such as a stack-local runtime's user_pool; D-035 relies
    // on those pages being in the scan tree.
    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    if (rt != nullptr
        && rt->mmaps.mmap_tree != nullptr
        && a->hidden
        && a->metadata_pool == nullptr
        && n00b_in_stack(a)) {
        return;
    }

    for (uint64_t i = 0; i < N00B_ARENA_AUDIT_MAX; i++) {
        if (n00b_atomic_load(&n00b_arena_audit_ring[i]) == a) {
            return;
        }
    }

    // Rotate the start slot to spread contention, then linear-probe with CAS for
    // the first empty slot.
    uint64_t start = n00b_atomic_add(&n00b_arena_audit_cursor, 1)
                     % (N00B_ARENA_AUDIT_MAX - 1);
    for (uint64_t i = 0; i < N00B_ARENA_AUDIT_MAX; i++) {
        uint64_t          slot     = (start + i) % N00B_ARENA_AUDIT_MAX;
        n00b_allocator_t *expected = nullptr;
        if (n00b_atomic_cas(&n00b_arena_audit_ring[slot], &expected, a)) {
            return;
        }
    }
    abort(); // ring full: raise N00B_ARENA_AUDIT_MAX.
}

void
n00b_allocator_audit_unregister(n00b_allocator_t *a)
{
    // Called BEFORE the allocator's backing is freed, so a concurrent metrics
    // scan never sees a pointer to a freed allocator: the slot is nulled while
    // the allocator is still alive.  Clear every matching slot; stack-allocated
    // pools can reuse the same address across calls, and older buggy duplicate
    // registrations must not leave a stale stack pointer behind for the GC audit
    // walk.
    for (uint64_t i = 0; i < N00B_ARENA_AUDIT_MAX; i++) {
        if (n00b_atomic_load(&n00b_arena_audit_ring[i]) == a) {
            n00b_atomic_store(&n00b_arena_audit_ring[i],
                              (n00b_allocator_t *)nullptr);
        }
    }
}

void
n00b_arena_audit_foreach(void (*cb)(n00b_allocator_t *al, void *arg), void *arg)
{
    // Walk the audit ring and hand every live allocator to `cb`. Callers run
    // this with the world stopped (the GC scan-tree builder), so the ring is
    // stable; we still load each slot atomically to match register/unregister.
    for (uint64_t i = 0; i < N00B_ARENA_AUDIT_MAX; i++) {
        n00b_allocator_t *al = n00b_atomic_load(&n00b_arena_audit_ring[i]);
        if (al != nullptr) {
            cb(al, arg);
        }
    }
}

// Arena-typed wrappers used by this file's create/delete hooks.
static inline void
n00b_arena_audit_register(n00b_arena_t *arena)
{
    n00b_allocator_audit_register((n00b_allocator_t *)arena);
}
static inline void
n00b_arena_audit_unregister(n00b_arena_t *arena)
{
    n00b_allocator_audit_unregister((n00b_allocator_t *)arena);
}

// ===========================================================================
// CENSUS / heartbeat snapshot — gated (debug only). See the ring header comment:
// this part stop-the-worlds and is for diagnostics, unlike the always-on ring.
// ===========================================================================
#if defined(N00B_ARENA_AUDIT_ON)

// Per-debug-name breakdown. arena debug_names are static string literals, so we
// group by pointer (same as the mmap source histogram). Distinct arena names are
// few (md_pool / arena / to-space / heap), so a small fixed table captures them.
#define N00B_ARENA_AUDIT_NAMES 64

[[n00b::nogc]] static _Atomic uint64_t n00b_arena_audit_cached_bytes;
[[n00b::nogc]] static n00b_arena_census_bucket_t
    n00b_arena_audit_cache[N00B_ARENA_AUDIT_NAMES];
[[n00b::nogc]] static _Atomic uint64_t n00b_arena_audit_cache_n;

// Census: STOP THE WORLD, then walk every live arena's segment chain, grouping
// by vtable.debug_name. STW is required (a plain read lock is not enough):
// segments are appended during normal allocation (n00b_add_arena_segment) on any
// thread WITHOUT holding critical_execution, and arenas are deleted
// concurrently, so walking current_segment -> next_segment can both tear and
// use-after-free. STW guarantees no thread is mutating or deleting an arena while
// we walk. Results are cached for the cheap readers below. Call from the
// heartbeat (debug only) so the STW cost is paid at heartbeat cadence, never on
// the hot status-write path.
// Walk the audit ring + refresh the cached snapshot WITHOUT stopping the world.
// The caller MUST already have all other threads frozen — call this from inside
// n00b_collect (the GC has already stopped the world for the collection), so the
// per-arena segment-chain walks can't tear / use-after-free. Riding the GC's
// existing STW means the audit costs no additional pause. Non-GC callers must use
// the n00b_arena_audit_census() STW wrapper below.
void
n00b_arena_audit_census_nolock(void)
{
    // Stack-local accumulator (no allocation).
    n00b_arena_census_bucket_t local[N00B_ARENA_AUDIT_NAMES] = {};
    uint32_t                   n     = 0;
    uint64_t                   total = 0;

    for (uint64_t i = 0; i < N00B_ARENA_AUDIT_MAX; i++) {
        n00b_allocator_t *al = n00b_atomic_load(&n00b_arena_audit_ring[i]);
        if (al == nullptr) {
            continue;
        }
        const char *name  = al->debug_name;
        uint64_t    bytes = 0;
        // Discriminate pool vs arena by the free op: arenas set none
        // (free == nullptr); pools install pool_free. Read each kind's byte total
        // directly (no locks) — safe because STW froze all mutation:
        //   - pool: the running mapped_bytes_total field (taking pool_lock here
        //     could deadlock against a thread suspended holding it).
        //   - arena: walk the segment chain.
        if (al->free != nullptr) {
            bytes = ((n00b_pool_t *)al)->mapped_bytes_total;
        }
        else {
            n00b_arena_t   *a   = (n00b_arena_t *)al;
            n00b_segment_t *seg = n00b_atomic_load(&a->current_segment);
            while (seg != nullptr) {
                bytes += seg->size;
                seg = seg->next_segment;
            }
        }
        total += bytes;

        uint32_t j = 0;
        for (; j < n; j++) {
            if (local[j].name == name) {
                break;
            }
        }
        if (j == n && n < N00B_ARENA_AUDIT_NAMES) {
            local[j].name  = name;
            local[j].count = 0;
            local[j].bytes = 0;
            n++;
        }
        if (j < n) {
            local[j].count++;
            local[j].bytes += bytes;
        }
    }
    for (uint32_t k = 0; k < n; k++) {
        n00b_arena_audit_cache[k] = local[k];
    }
    n00b_atomic_store(&n00b_arena_audit_cache_n, n);
    n00b_atomic_store(&n00b_arena_audit_cached_bytes, total);
}

// STW wrapper for callers that are NOT already inside a collection (an on-demand
// diagnostic). Inside the GC, call n00b_arena_audit_census_nolock() directly so
// the audit rides the collection's existing stop-the-world.
void
n00b_arena_audit_census(void)
{
    n00b_stop_the_world();
    n00b_arena_audit_census_nolock();
    n00b_restart_the_world();
}

// Cheap reader for the status path: returns the last census snapshot. No lock,
// no STW. Returns 0 until the first heartbeat census runs.
uint64_t
n00b_arena_audit_total_bytes(void)
{
    return n00b_atomic_load(&n00b_arena_audit_cached_bytes);
}

uint32_t
n00b_arena_audit_histogram(n00b_arena_census_bucket_t *out, uint32_t cap)
{
    if (out == nullptr || cap == 0) {
        return 0;
    }
    uint32_t n     = (uint32_t)n00b_atomic_load(&n00b_arena_audit_cache_n);
    uint32_t out_n = cap < n ? cap : n;
    // Selection-sort the top `cap` buckets by bytes, descending, into out.
    bool taken[N00B_ARENA_AUDIT_NAMES] = {};
    for (uint32_t k = 0; k < out_n; k++) {
        uint32_t best   = UINT32_MAX;
        uint64_t best_b = 0;
        for (uint32_t j = 0; j < n; j++) {
            if (!taken[j] && (best == UINT32_MAX
                              || n00b_arena_audit_cache[j].bytes > best_b)) {
                best   = j;
                best_b = n00b_arena_audit_cache[j].bytes;
            }
        }
        taken[best] = true;
        out[k]      = n00b_arena_audit_cache[best];
    }
    return out_n;
}
#else
// Only the CENSUS is compiled out here; the ring (register/unregister/foreach)
// above is always present because the GC scan-tree depends on it.
void
n00b_arena_audit_census(void)
{
}
void
n00b_arena_audit_census_nolock(void)
{
}
uint64_t
n00b_arena_audit_total_bytes(void)
{
    return 0;
}
uint32_t
n00b_arena_audit_histogram(n00b_arena_census_bucket_t *out, uint32_t cap)
{
    (void)out;
    (void)cap;
    return 0;
}
#endif

void
n00b_register_arena_segment(void *start, void *end, n00b_arena_t *arena) _kargs
{
    const char *file = nullptr;
}
{
    n00b_mmap_rec_kind_t kind = n00b_get_arena_addr_type(arena, (void *)start);

    (void)n00b_mmap_register(start,
                             end,
                             kind,
                             .file      = file,
                             .allocator = (n00b_allocator_t *)arena);
}

static void
n00b_add_arena_segment(n00b_arena_t *arena, uint64_t request_len)
{
    n00b_segment_t *old_segment;
    n00b_segment_t *segment;

    // Spin lock.
    while (n00b_atomic_or(&arena->mutex, 1))
        /* No body */;

    // Check to see if someone else added a segment. If so,
    // unlock and return.
    char *next = n00b_atomic_load(&arena->next_alloc);

    if (next && next + request_len < arena->segment_end) {
        n00b_atomic_store(&arena->mutex, 0);
        return;
    }

    // Give ourselves at least a page of overhead.  The segment descriptor now
    // lives in system_pool, so the data mmap carries NO inline-header overhead.
    uint64_t needed = request_len + n00b_page_size;
    uint64_t size   = 0;

    old_segment = n00b_atomic_load(&arena->current_segment);

    if (old_segment) {
        size = old_segment->size;
        if (size < needed) {
            size = needed;
        }
    }
    else {
        size = needed;
    }

    size       = n00b_page_align(size);
    auto seg_r = n00b_check_mmap(nullptr, size, N00B_MPROT, N00B_MFLAG, -1, 0);

    if (n00b_result_is_err(seg_r)) {
        abort(); // out of memory.
    }

    char *data = n00b_result_get(seg_r);

    // Descriptor: a small fixed struct from the (non-moving, persistent)
    // system_pool.  system_pool is initialized before any arena is created, and
    // allocating from a pool never triggers a collection, so this is safe
    // mid-segment-add.  Freed via the explicit allocator path (system_pool has
    // no metadata for the generic n00b_free to find it).
    segment = n00b_alloc_with_opts(
        n00b_segment_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)&n00b_get_runtime()->system_pool});

    // Save this info off for GC reporting and any sanity checking.
    if (old_segment) {
        old_segment->last_addr = n00b_atomic_load(&arena->next_alloc);
    }

    segment->size         = size;
    segment->data         = data;
    segment->retained     = false;
    segment->pin_bitmap   = nullptr;
    segment->next_segment = old_segment;
    arena->next_alloc     = (char *)n00b_align((uint64_t)data);
    arena->segment_end    = data + size;
    segment->last_addr    = arena->segment_end;
    n00b_atomic_store(&arena->current_segment, segment);

    if (!arena->vtable.hidden) {
        n00b_register_arena_segment(data, arena->segment_end, arena);
    }

    // Make the lock a full thread fence so we ensure our fields are
    // fully written before people use them.
    //
    // We don't care when they become visible within this function, but we
    // sure care about everything being visible by the time we open
    // up the mutex and other people can see us.
    n00b_atomic_fence();
    atomic_store(&arena->mutex, 0);
}

static inline bool
arena_changed(n00b_arena_t *arena, char *desired_value)
{
    if (desired_value > arena->segment_end) {
        return true;
    }
    // current_segment is now the DESCRIPTOR (in system_pool); the data region
    // base is desc->data.  Bound the low end against the data, not the header.
    n00b_segment_t *seg = n00b_atomic_load(&arena->current_segment);
    if (!seg || desired_value < seg->data) {
        return true;
    }

    return false;
}

static void *
n00b_arena_alloc(n00b_arena_t *arena, uint64_t request, void *ignore)
{
    char        *found_value;
    char        *desired_value;
    _Atomic bool already_collected = false;

    // Publish this reservation BEFORE committing the bump so a preemptive STW
    // between the CAS and the caller registering the object's GC metadata cannot
    // reclaim a live-but-unregistered region (see n00b_thread_t.gc_inflight_*).
    // Re-published each iteration against the current found_value; the caller
    // (_n00b_alloc_with_opts) clears it once the object is registered.  Only the
    // moving GC heap needs this; hidden/system pools are not collected.
    n00b_thread_t *self = arena->collection_enabled ? n00b_thread_self()
                                                     : nullptr;

    do {
        found_value   = n00b_atomic_load(&arena->next_alloc);
        desired_value = found_value + request;

        if (self != nullptr) {
            atomic_store_explicit(&self->gc_inflight_start,
                                  found_value,
                                  memory_order_relaxed);
            atomic_store_explicit(&self->gc_inflight_len,
                                  request,
                                  memory_order_relaxed);
        }

        if (arena_changed(arena, desired_value)) {
            if (already_collected || !arena->collection_enabled) {
                n00b_add_arena_segment(arena, request);
                continue;
            }

            n00b_stop_the_world();
            if (n00b_atomic_load(&arena->next_alloc) == found_value) {
                // Genuine memory pressure: the allocation did not fit, so this
                // collect IS due to the arena being out of room.  This is the
                // one caller that may pre-grow the to-space.
                n00b_collect(arena, .out_of_memory = true);
            }
            already_collected = true;
            n00b_restart_the_world();
            /* The conservative GC's stack scan can rewrite `found_value`
             * on this frame to a forwarded position (it looks like a
             * heap pointer; `scan_for_header` finds the previous
             * allocation's inline-header guard and forwards that alloc,
             * translating `found_value` to the corresponding to-space
             * offset).  After that, `found_value` may even happen to
             * match the new `arena->next_alloc`, but `desired_value`
             * was computed from the pre-collect `found_value` and is
             * stale.  If we let the CAS run as-is, it can spuriously
             * succeed and write a small `desired_value` back into
             * `arena->next_alloc` — leaving the bump pointer *inside*
             * live allocations.
             *
             * Recompute both from the current atomic state before the
             * CAS.  `continue` in a do-while goes to the while-condition
             * (the CAS), so we re-read here explicitly. */
            found_value   = n00b_atomic_load(&arena->next_alloc);
            desired_value = found_value + request;
            /* Re-check arena_changed against the recomputed desired:
             * the swap can put next_alloc near the new (possibly
             * smaller) segment_end, and we MUST NOT let the CAS bump
             * the pointer past it — that's how a 4 MB dict_store can
             * get assigned a slot whose tail falls outside the
             * segment, with a subsequent GC trying to memcpy off the
             * end of mapped memory.  add_arena_segment here and let
             * the CAS fail; the next iteration reloads against the
             * fresh segment. */
            if (arena_changed(arena, desired_value)) {
                n00b_add_arena_segment(arena, request);
                continue;
            }
        }
    } while (!n00b_atomic_cas(&arena->next_alloc, &found_value, desired_value));
    n00b_atomic_add(&arena->alloc_count, 1);

    return found_value;
}

static void
n00b_arena_delete(n00b_arena_t *arena)
{
    // Remove from the audit ring before freeing any segments, so a concurrent
    // metrics scan never dereferences a half-freed arena.
    n00b_arena_audit_unregister(arena);

    n00b_segment_t      *segment = n00b_atomic_load(&arena->current_segment);
    n00b_segment_t      *next;
    n00b_mmap_rec_kind_t kind = n00b_get_arena_addr_type(arena, nullptr);
    n00b_allocator_t    *sp   = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;

    while (segment) {
        next = segment->next_segment;
        // The descriptor lives in system_pool; the data region is a separate
        // mmap.  Unregister + unmap the DATA, then free the descriptor via the
        // explicit allocator path (system_pool has no metadata for n00b_free).
        if (!arena->vtable.hidden) {
            n00b_mmap_unregister(segment->data);
        }
        n00b_safe_munmap(segment->data, segment->size);
        sp->free(sp, segment);
        segment = next;
    }

    auto arena_map_opt = n00b_mmap_by_address(arena);
    if (n00b_option_is_set(arena_map_opt)
        && n00b_option_get(arena_map_opt)->kind == n00b_mmap_arena) {
        (void)n00b_munmap(arena);
        return;
    }

    switch (kind) {
    case n00b_mmap_arena:
        (void)n00b_munmap(arena);
        break;
    case n00b_mmap_static:
        memset(arena, 0, sizeof(n00b_arena_t));
        break;
    case n00b_mmap_managed_segment:
    case n00b_mmap_sys_segment:
#ifdef _WIN32
        VirtualFree(arena, 0, MEM_RELEASE);
#else
        munmap(arena, n00b_page_align(sizeof(n00b_arena_t)));
#endif
        break;
    default:
        // Bad (invalid or unsafe) storage location for arena header.
        abort();
    }
}

void
n00b_initialize_arena(n00b_arena_t *arena) _kargs
{
    uint64_t size           = N00B_DEFAULT_SCRATCH_ARENA_SIZE;
    bool     use_gc         = true;
    bool     no_map         = false;
    bool     hidden         = false;
    bool     __system       = false;
    bool     inline_headers = true;
    char    *name           = "arena";
    // "file:line" of the create-site, injected by the n00b_new_arena macro.
    const char *creation_loc = nullptr;
}
{
    n00b_atomic_store(&arena->next_alloc, nullptr);
    n00b_atomic_store(&arena->mutex, 0);

    *arena = (n00b_arena_t){
        .segment_end        = nullptr,
        .current_segment    = nullptr,
        .next_alloc         = nullptr,
        .alloc_count        = 0,
        .mutex              = 0,
        .collection_enabled = use_gc,
#if defined(N00B_GC_STATS)
        .collect_start_time = {},
        .collect_count      = 0,
#endif
    };
    bool external_metadata =
#if defined(N00B_RELEASE_BUILD) && !defined(N00B_DEBUG_LIVE_CENSUS)
        false;
#else
        !no_map;
#endif

    // clang-format off
    n00b_allocator_setup(
	(n00b_allocator_t *)arena,
	(n00b_calloc_fn)n00b_arena_alloc,
	.destroy           = (n00b_allocator_destroy_fn)n00b_arena_delete,
	.name              = name,
	.inline_headers    = inline_headers,
	.external_metadata = external_metadata,
	.hidden            = hidden,
	.__system          = __system,
	.creation_loc      = creation_loc);
    // clang-format on

    n00b_add_arena_segment(arena, size);
    n00b_arena_audit_register(arena);
}

// This is used to 'reset' a scratch arena. Either its old size was
// fine, in which case we need to memzero it, OR it required multiple
// segments, in which case we calculate the high water mark, and re-map.
// clang-format off
void
n00b_arena_reset(n00b_arena_t *arena)
// requires { arena != nullptr; }
{
    while (n00b_atomic_or(&arena->mutex, 1))
        /* No body */;

    n00b_segment_t *segment = n00b_atomic_load(&arena->current_segment);

    if (!segment->next_segment) {
        char *start = (char *)n00b_align((uint64_t)segment->data);
        char *high  = n00b_atomic_load(&arena->next_alloc);
        n00b_assert(high >= start);
        if (high > start) {
            memset(start, 0, (size_t)(high - start));
        }
        arena->next_alloc = start;
        n00b_atomic_store(&arena->alloc_count, 0);
        n00b_atomic_fence();
        n00b_atomic_store(&arena->mutex, 0);
        return;
    }

    // Grew to multiple segments; replace with one at the high-water total.
    // Free EVERY current segment (its data mmap + its system_pool descriptor),
    // then build a single fresh segment.
    uint64_t          total      = 0;
    bool              unregister = !arena->vtable.hidden;
    n00b_allocator_t *sp = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    n00b_segment_t   *dead;

    while (segment) {
        total  += segment->size;
        dead    = segment;
        segment = segment->next_segment;

        if (unregister) {
            n00b_mmap_unregister(dead->data);
        }
        n00b_safe_munmap(dead->data, dead->size);
        sp->free(sp, dead);
    }

    total = n00b_page_align(total);

    auto seg_r = n00b_check_mmap(nullptr, total, N00B_MPROT, N00B_MFLAG, -1, 0);

    if (n00b_result_is_err(seg_r)) {
        abort();
    }

    char *data = n00b_result_get(seg_r);

    segment = n00b_alloc_with_opts(
        n00b_segment_t,
        &(n00b_alloc_opts_t){.allocator = sp});
    segment->size         = total;
    segment->data         = data;
    segment->retained     = false;
    segment->pin_bitmap   = nullptr;
    segment->next_segment = nullptr;
    segment->last_addr    = data + total;
    arena->segment_end    = segment->last_addr;
    arena->next_alloc     = (char *)n00b_align((uint64_t)data);
    n00b_atomic_store(&arena->current_segment, segment);

    if (unregister) {
        n00b_register_arena_segment(data, arena->segment_end, arena);
    }

    n00b_atomic_fence();
    n00b_atomic_store(&arena->mutex, 0);
}
// clang-format on

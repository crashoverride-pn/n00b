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
#include <stdio.h>
#include "core/atomic.h"
#include "core/gc.h"
#include "core/thread.h"
#include "core/random.h"
#include "adt/dict_untyped.h"
#include "core/stw.h"

// N00B_DEFAULT_SCRATCH_ARENA_SIZE now defined in arena.h

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
    // clang-format off
    n00b_allocator_setup(
	(n00b_allocator_t *)arena,
	(n00b_calloc_fn)n00b_arena_alloc,
	.destroy           = (n00b_allocator_destroy_fn)n00b_arena_delete,
	.name              = name,
	.inline_headers    = inline_headers,
	.external_metadata = !no_map,
	.hidden            = hidden,
	.__system          = __system);
    // clang-format on

    n00b_add_arena_segment(arena, size);
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

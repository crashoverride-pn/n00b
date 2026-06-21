/**
 * @file arena.h
 * @brief Bump-pointer arena allocator.
 *
 * Arenas provide fast, sequential allocation with optional garbage
 * collection.  When collection is enabled and the arena runs out of
 * space, a copying GC pass is triggered.
 */
#pragma once

#include "n00b.h"
#include "core/alloc_base.h"
#include "core/alloc_mdata.h"
#include "core/mmaps.h"
#include "core/align.h"

#define N00B_MPROT (PROT_READ | PROT_WRITE)
#define N00B_MFLAG (MAP_PRIVATE | MAP_ANON)

#ifndef N00B_DEFAULT_SCRATCH_ARENA_SIZE
#define N00B_DEFAULT_SCRATCH_ARENA_SIZE (1 << 25) // 32M
#endif

struct n00b_segment_t {
    // Mostly-copying-GC segment DESCRIPTOR.  The descriptor is allocated from
    // the runtime system_pool (non-moving, persistent); the data region is a
    // SEPARATE mmap referenced by `data` (so a retained pinned page never has to
    // host a header at its start).  `size` is the byte length of that data mmap.
    uint64_t        size;
    n00b_segment_t *next_segment;
    char           *last_addr;     // high-water of used bytes within `data`
    char           *data;          // base of the separately-mmap'd data region
    bool            retained;      // pinned-page retained run (mostly-copying GC)
    // Transient, per-collect: a page-pin bitmap (one bit per n00b_page_size of
    // `data`) allocated for from-space segments at collect setup and freed at
    // cleanup.  Set by the ambiguous-root pin pre-pass; consumed by the forward
    // phase + page reclaim.  nullptr outside an active collection.
    uint8_t        *pin_bitmap;
};

struct n00b_arena_t {
    n00b_base_allocator_t     vtable;
    char                     *segment_end;
    _Atomic(char *)           next_alloc;
    _Atomic(n00b_segment_t *) current_segment;
    _Atomic uint32_t          mutex;
    _Atomic uint32_t          alloc_count;
    // If collection_enabled is off, when a heap / arena runs out of
    // memory, we just tack on a new segment of at least the same size
    // as the prior one.
    //
    // If collection_enabled is on, then when there isn't enough room
    // left for an allocation, a GC pass will be triggered. This GC
    // pass will trace from the roots specified in the heap only, but
    // if there are no roots specified, it will trace through the
    // global roots.
    //
    // When a GC is triggered, scanned memory allocations are traced,
    // even if out of the heap being collected, to find all pointers
    // into the heap being collected, both to make sure all needed
    // records are moved, and to find all places where pointers into
    // the heap need to be updated.
    //
    // For heaps with `no_pointers` set, when we're tracing that heap,
    // then we do not scan individual records for pointers. If we're
    // tracing some other heap, then pointers into the `no_pointers`
    // heap cannot ever lead to the heap we're collecting, so we do
    // not need to record anything.
    //
    // For heaps with `system_arena` set, they cannot be used as GC'd
    // heaps, only static arenas. They are never traced during garbage
    // collection in any way, and are not returned by `n00b_in_heap()`
    // or similar. The purpose here is to be able to use the same
    // underlying arena code for low-level accounting, much of which
    // is used directly or indirectly by the garbage collector itself.

    uint32_t collection_enabled : 1; // GC'd heap.
    uint32_t grow : 1;               // Last collect left the arena dense
                                     // (live > 25% of capacity), so the next
                                     // out-of-memory collect should double the
                                     // to-space.  Recomputed every collect in
                                     // n00b_collection_cleanup.

#if defined(N00B_GC_STATS)
    struct timespec collect_start_time;
    uint32_t        collect_count;
#endif
};

/**
 * @brief Determine the mmap record kind for an address within an arena.
 * @param arena Arena to query.
 * @param addr  Address to classify.
 * @return      The mmap record kind.
 */
static inline n00b_mmap_rec_kind_t
n00b_get_arena_addr_type(n00b_arena_t *arena, void *addr)
{
    if (addr && (void *)arena == addr) {
        return n00b_mmap_arena;
    }
    return arena->vtable.__system ? n00b_mmap_sys_segment : n00b_mmap_managed_segment;
}

/**
 * @brief Initialize an arena allocator.
 * @param arena Arena to initialize.
 *
 * @kw size           Initial segment size in bytes.
 * @kw use_gc         Enable garbage collection on this arena.
 * @kw no_map         Skip mmap registration.
 * @kw hidden         Hide from GC (GC treats contents as opaque data).
 * @kw __system       System arena — never traced by GC, not returned by n00b_in_heap().
 * @kw inline_headers Prepend inline headers to allocations.
 * @kw name           Debug name for the arena.
 *
 * @pre @p arena points to mmap'd memory of at least `sizeof(n00b_arena_t)` bytes.
 * @post Arena is ready for allocation via its vtable.
 */
extern void
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
};

/**
 * @brief Register a finalizer to run when @p obj is collected or freed.
 * @param obj       Object to attach the finalizer to. May be from any
 *                  allocator that flows through n00b_free or GC sweep;
 *                  the registry keys on @p obj directly, so allocators
 *                  without alloc metadata (e.g. the hidden system pool)
 *                  participate just as well as GC-tracked arenas.
 * @param fn        Finalizer callback.
 * @param user_data Opaque pointer passed to @p fn when invoked.
 */
extern void n00b_add_finalizer(void *obj, n00b_finalizer_t fn, void *user_data);

struct n00b_finalizer_info_t {
    n00b_finalizer_t   funcptr;
    void              *key;        // User pointer; primary lookup key
                                   // for n00b_free-driven release.
    n00b_inline_hdr_t *alloc_info; // GC tracking key for forwarding
                                   // during collection. Null when the
                                   // owning allocator has no alloc
                                   // metadata (e.g. system_pool); such
                                   // entries are never in any GC-
                                   // managed arena, so the GC sweep
                                   // skips them.
    void              *user_ptr;
};

#define n00b_new_arena(...)                                                                    \
    ({                                                                                         \
        uint64_t _sz     = n00b_page_align(sizeof(n00b_arena_t));                              \
        auto     _mmap_r = n00b_mmap(_sz, .kind = n00b_mmap_arena);                            \
        assert(n00b_result_is_ok(_mmap_r));                                                    \
        n00b_arena_t *result = n00b_result_get(_mmap_r);                                       \
        n00b_initialize_arena(result,                                                         \
                              .creation_loc = N00B_LOC_STRING() __VA_OPT__(, __VA_ARGS__));    \
        result;                                                                                \
    })

/**
 * @brief Register an arena segment with the mmap tracking subsystem.
 *
 * Called by arena.c after adding a new segment, and by gc.c after
 * swapping in the to-space segment during collection cleanup.
 *
 * @param start  Start address of the segment.
 * @param end    End address of the segment.
 * @param arena  Owning arena.
 * @param file   Debug name / source file (may be nullptr).
 */
extern void
n00b_register_arena_segment(void *start, void *end, n00b_arena_t *arena) _kargs
{
    const char *file = nullptr;
};

typedef struct n00b_arena_alloc_param_t {
    bool no_scan;
    bool mem_debug;
    bool mem_debug_taint;
} n00b_arena_alloc_param_t;

/**
 * @brief Zero an arena for reuse (intended for scratch arenas).
 *
 * If an arena ended up with multiple segments (due to running out of
 * room), zeroing results in replacing the existing segments with a
 * single segment that would have been big enough for the total
 * allocated size.

 * @param arena  Owning arena.
 */

extern void n00b_arena_reset(n00b_arena_t *arena);

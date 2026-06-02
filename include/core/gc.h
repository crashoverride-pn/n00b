/**
 * @file gc.h
 * @brief Garbage collector interface and supporting types.
 *
 * Implements a copying/compacting collector for @c n00b_arena_t heaps.
 * When an arena runs out of space and has @c collection_enabled set,
 * @c n00b_collect() copies live allocations to a new arena segment,
 * rewrites all pointers, and releases the old memory.
 *
 * The collector traces:
 *   - User-registered GC roots (@ref n00b_gc_register_root)
 *   - Thread stacks (all registered threads)
 *   - The @c argv / @c envp arrays in @c n00b_runtime_t
 *
 * Callers must hold the stop-the-world lock before invoking
 * @c n00b_collect().
 */
#pragma once

#include "n00b.h"
#include "core/alloc_mdata.h"
#include "adt/list.h"
#include "adt/dict_untyped.h"
#include "core/pool.h"
#include "core/arena.h"

// ============================================================================
// GC root type
// ============================================================================

/*
 * Maintainer note: `n00b_gc_root_t` was relocated to
 * `include/n00b.h` so ncc's `--ncc-auto-gc-roots` transform can
 * emit static tables of this type from arbitrary TUs that include
 * only `n00b.h`. The Doxygen lives with the definition there.
 */

// ============================================================================
// Public API
// ============================================================================

/**
 * @brief Run a copying collection on @p arena.
 *
 * All live allocations reachable from the root set are copied to a
 * fresh segment; stale memory is unmapped.
 *
 * @param arena  The arena to collect.
 * @pre The STW lock must be held by the caller.
 * @pre @p arena has `collection_enabled` set.
 * @post All live allocations in @p arena have been relocated; old
 *       segments are unmapped and pointers are rewritten.
 */
extern void n00b_collect(n00b_arena_t *arena);

/**
 * @brief Stop-the-world GC pass with leak-detection diagnostics
 *        enabled.
 *
 * Runs the normal collection cycle with @c rt->debug_leak_detect
 * temporarily set; any alive allocation in a metadata-bearing
 * pool whose @c gc_epoch is still stale after the mark phase is
 * a leak — the routine prints its @c file_name + @c tinfo +
 * @c alloc_len on stderr before returning the slot to its pool.
 *
 * Useful as an on-demand debug knob (e.g. wired into a daemon's
 * periodic health tick) to pinpoint the origin of pool
 * allocations that never get freed.
 */
extern void n00b_debug_find_leaks(void);

/**
 * @brief Register a memory range as a GC root.
 *
 * The collector will scan @p num_words pointer-sized words starting
 * at @p addr during every collection.  Use @ref n00b_gc_register_root
 * for the convenient macro interface.
 *
 * @param addr      Start address of the root region.
 * @param num_words Number of pointer-sized words to scan.
 * @pre Runtime must be initialized.
 * @pre @p addr must remain valid for the lifetime of the registration.
 */
extern void _n00b_gc_register_root(void *addr, size_t num_words);

/**
 * @brief Bulk-register an array of GC roots in one call.
 *
 * Init-time-only with respect to concurrent collection: callers
 * must invoke during process init or before any `n00b_collect()`
 * runs. Not thread-safe with concurrent collection.
 *
 * **Pre-`n00b_init` behavior:** ncc's `--ncc-auto-gc-roots`
 * transform emits a `[[gnu::constructor]]` gc-root registrar in
 * every libn00b TU with TU-scope pointer-bearing decls. Those fire
 * during dynamic-loader init, and on Mach-O the `__init_offsets`
 * table runs in LINK order (not constructor-priority order), so such
 * a registrar can be the first initializer to run — before
 * `n00b_init()`. This function therefore calls the idempotent
 * `n00b_early_init()` first, which stands up the memory subsystem
 * and `runtime->gc_roots`; registration is then always direct
 * (no defer-and-replay queue).
 *
 * @param roots Pointer to an array of n00b_gc_root_t entries.
 *              The array must outlive the process (typically a
 *              `static` table emitted by ncc's `--ncc-auto-gc-roots`
 *              transform).
 * @param count Number of entries in @p roots. Zero is a clean
 *              no-op; @p roots may be `nullptr` when @p count is
 *              zero.
 */
extern void n00b_gc_register_roots(const n00b_gc_root_t *roots,
                                   size_t                count);

/**
 * @brief Unregister a previously registered GC root.
 *
 * Removes the first root whose address matches @p addr.
 *
 * @param addr  The address originally passed to register.
 */
extern void _n00b_gc_unregister_root(void *addr);

/**
 * @brief Register a variable as a GC root.
 *
 * Takes the address of @p var and computes the number of
 * pointer-sized words from its size.
 *
 * @code
 *     int *my_ptr;
 *     n00b_gc_register_root(my_ptr);
 * @endcode
 */
#define n00b_gc_register_root(var)                                                             \
    _n00b_gc_register_root(&(var),                                                             \
                           (sizeof(var) + sizeof(void *) - 1) / sizeof(void *))

/**
 * @brief Unregister a variable previously registered as a GC root.
 */
#define n00b_gc_unregister_root(var) _n00b_gc_unregister_root(&(var))

// ============================================================================
// Constants
// ============================================================================

#define N00B_DEFAULT_GC_ARENA_SIZE (1 << 16) // 64 KiB for to-space initial
#define N00B_GC_WL_START_SIZE      256
#define N00B_TOO_FEW_ALLOCS        128

// ============================================================================
// Internal types (used by gc.c; exposed for arena.c helpers)
// ============================================================================

/**
 * @brief Work-list entry: a memory range that still needs scanning.
 *
 * `stride == 0` requests the legacy "every word in [0, num_words)" scan.
 * `stride > 0` requests a strided visit: words at indices
 * `offset, offset+stride, offset+2*stride, ...` while in
 * `[0, num_words)`.  Used by EVERY_OTHER (stride=2) and by GC clients
 * that want a struct-array pattern without a per-allocation callback.
 */
typedef struct {
    void     *start;
    uint64_t  num_words;
    uint64_t  stride;
    uint64_t  offset;
} n00b_gc_wl_item_t;

/**
 * @brief Per-collection state, stack-allocated by the collector entry point.
 */
typedef struct {
    n00b_arena_t                     *from_space;
    n00b_arena_t                     *to_space;
    n00b_pool_t                       work_pool;
    n00b_list_t(n00b_gc_wl_item_t *)  worklist;
    n00b_dict_untyped_t               memos;
    /* The runtime's gc_current_epoch value snapshotted at
     * collection start. The mark phase stamps this onto every
     * metadata-bearing alloc it reaches via the OOB record's
     * gc_epoch field; the post-mark sweep compares it back to
     * detect leaks (alloc still alive with a stale epoch). */
    uint64_t                          current_epoch;
} n00b_collect_t;

// ============================================================================
// Arena metric helpers (also used by arena.c)
// ============================================================================

/**
 * @brief Total bytes used across all segments of @p arena.
 * @param arena  Target arena.
 * @return       Byte count of live allocation space.
 */
static inline uint64_t
n00b_arena_used(n00b_arena_t *arena)
{
    uint64_t        sz      = 0;
    n00b_segment_t *segment = arena->current_segment;

    // The current (top) segment doesn't have last_addr set yet.
    segment->last_addr = atomic_load(&arena->next_alloc);

    while (segment) {
        sz     += (uint64_t)(segment->last_addr - (char *)&segment->mem[0]);
        segment = segment->next_segment;
    }

    return sz;
}

/**
 * @brief Total capacity (usable bytes) across all segments of @p arena.
 * @param arena  Target arena.
 * @return       Byte count of total segment capacity.
 */
static inline uint64_t
n00b_arena_size(n00b_arena_t *arena)
{
    uint64_t        sz      = 0;
    n00b_segment_t *segment = arena->current_segment;

    while (segment) {
        sz     += segment->size - sizeof(n00b_segment_t);
        segment = segment->next_segment;
    }

    return sz;
}

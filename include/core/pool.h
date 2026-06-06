/**
 * @file pool.h
 * @brief Fixed-size slab pool allocator.
 *
 * Provides fast allocation of small, fixed-size objects using
 * power-of-two size classes with lock-free free lists.
 */
#pragma once

#include "n00b.h"
#include "core/alloc_base.h"
#include "adt/llstack.h"
#include "core/align.h"

#define N00B_POST_ROUND_SHIFT 6
#define N00B_NUM_FREE_LISTS   4

typedef struct n00b_pool_page_t {
    struct n00b_pool_page_t *prev;
    struct n00b_pool_page_t *next;
    /* Page-aligned size of the underlying mmap, captured by
     * new_page_entry so pool_free's big-alloc path can munmap the
     * page when its single entry is freed. Without this, big-alloc
     * pool_free was only unlinking the page from page_table — the
     * memory stayed mapped until pool_destroy. Observed leak: any
     * pool client that n00b_free's a >N00B_NUM_FREE_LISTS-class
     * allocation gave back its slot in the free list but the page
     * remained mapped. */
    size_t                   mapped_size;
} n00b_pool_page_t;

typedef struct {
    unsigned int list_index;
} n00b_pool_entry_t;

static_assert(sizeof(n00b_pool_entry_t) <= N00B_ALIGN);

struct n00b_pool_t {
    n00b_base_allocator_t vtable;
    n00b_llstack_t        free_lists[N00B_NUM_FREE_LISTS];
    n00b_pool_page_t     *page_table;
    _Atomic uint32_t      lock;
    /* Diagnostics counters. Map = successful big_mmap (page table
     * grew), unmap = delete_one_page_entry's munmap. Used by callers
     * that need to verify alloc/free symmetry on the big-mmap fast
     * path. Always-on accounting so users don't need to recompile
     * libn00b to inspect them. */
    _Atomic uint64_t      big_map_count;
    _Atomic uint64_t      big_unmap_count;
};

typedef struct n00b_pool_t n00b_pool_t;

/**
 * @brief Initialize a pool allocator.
 * @param pool Pool structure to initialize.
 * @return     Allocator interface pointer for the pool.
 *
 * @kw __system          System pool — skip STW checks (internal only).
 * @kw inline_headers    Prepend inline headers to allocations.
 * @kw external_metadata Keep OOB metadata in a separate arena.
 * @kw hidden            Hide from GC.
 * @kw name              Debug name for the pool.
 *
 * @pre @p pool points to zeroed or uninitialized memory.
 * @post The returned allocator is ready for use.
 */
extern n00b_allocator_t *
n00b_pool_init(n00b_pool_t *pool) _kargs
{
    bool        __system          = false;
    bool        inline_headers    = false;
    bool        external_metadata = false;
    bool        hidden            = false;
    const char *name              = "pool";
};

/**
 * @brief Total bytes the pool has currently mapped from the kernel.
 *
 * Walks the pool's page_table under the pool lock, summing every page
 * entry's `mapped_size`. This counts every mmap region the pool owns
 * — both the small-slab pages backing the size-class freelists and
 * the per-allocation big-mmap pages handed out for requests larger
 * than the freelist classes — regardless of how many of the slots in
 * those pages are currently in use.
 *
 * Intended for diagnostics: pair with phys_footprint sampling to
 * attribute resident memory to specific pools. Cheap-ish but not
 * free; the lock is contended on the alloc/free fast path.
 */
extern uint64_t n00b_pool_mapped_bytes(n00b_pool_t *pool);

/**
 * @brief Cumulative count of big-mmap pages this pool has released
 *        back to the kernel (i.e. n00b_safe_munmap calls in
 *        @ref delete_one_page_entry).
 *
 * Pair with the corresponding alloc counter to verify that the
 * big-mmap fast path is symmetric — every allocation eventually
 * paired with a release.
 */
extern uint64_t n00b_pool_big_unmap_count(n00b_pool_t *pool);

/**
 * @brief Cumulative count of big-mmap pages this pool has mapped
 *        from the kernel (i.e. successful @ref big_mmap calls).
 */
extern uint64_t n00b_pool_big_map_count(n00b_pool_t *pool);

/**
 * @brief Usable byte count for a raw pool allocation.
 *
 * Given a pointer returned by a pool's zero_alloc, recover the number of
 * usable bytes (size class minus the entry header, or big-mmap region
 * minus its headers).  Used by the libc-malloc interposition layer
 * (`core/alloc_interpose.h`) to implement realloc()/malloc_usable_size()
 * without per-allocation side metadata.
 *
 * @pre @p ptr was returned by a pool (callers resolve ownership via
 *      @ref n00b_mem_get_allocator first).
 */
extern size_t n00b_pool_usable_size(void *ptr);

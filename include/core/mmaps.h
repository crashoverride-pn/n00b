/**
 * @file mmaps.h
 * @brief Memory-mapping registry and helpers.
 *
 * Wraps mmap/munmap with a global interval-tree registry that tracks
 * every mapped region, its kind, and its owning allocator.  Also
 * provides sub-range registration for individual allocations within
 * larger mappings.
 */
#pragma once

#include "n00b.h"
#include "core/alloc_base.h"
#include "core/rt_access.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc_mdata.h"
#include "core/align.h"
#include "core/atomic.h"
#include "core/macros.h"

#ifdef _WIN32
#include "core/platform.h"
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define MAP_PRIVATE 0x02
#define MAP_ANON    0x20
#define MAP_FAILED  ((void *)-1)
#else
#include <sys/mman.h>
#endif
#include <assert.h>

#define N00B_MPROT (PROT_READ | PROT_WRITE)
#define N00B_MFLAG (MAP_PRIVATE | MAP_ANON)

typedef enum n00b_mmap_rec_kind_t n00b_mmap_rec_kind_t;

typedef struct {
    uint64_t total_count;
    uint64_t total_bytes;
    uint64_t static_count;
    uint64_t static_bytes;
    uint64_t arena_count;
    uint64_t arena_bytes;
    uint64_t managed_segment_count;
    uint64_t managed_segment_bytes;
    uint64_t system_segment_count;
    uint64_t system_segment_bytes;
    uint64_t zero_page_count;
    uint64_t zero_page_bytes;
    uint64_t unmanaged_count;
    uint64_t unmanaged_bytes;
    uint64_t stack_count;
    uint64_t stack_bytes;
    uint64_t internal_count;
    uint64_t internal_bytes;
    uint64_t pool_count;
    uint64_t pool_bytes;
    uint64_t api_mmap_count;
    uint64_t api_mmap_bytes;
    uint64_t unknown_count;
    uint64_t unknown_bytes;
    uint64_t largest_bytes;
    uint64_t largest_kind;
    const char *largest_file;
    const char *largest_source_file;
    uint32_t largest_source_line;
    uint64_t largest_static_bytes;
    uint64_t largest_static_kind;
    const char *largest_static_file;
    const char *largest_static_source_file;
    uint32_t largest_static_source_line;
} n00b_mmap_registry_stats_t;

/**
 * @brief Look up an mmap record by address (internal — prefer n00b_mmap_by_address).
 * @param ctx  Mmap context to search.
 * @param addr Address to look up.
 * @return     Optional mmap info.
 */
extern n00b_option_t(n00b_mmap_info_t *) n00b_mmap_lookup(n00b_mmap_ctx_t *ctx, void *addr);

extern n00b_mmap_registry_stats_t n00b_mmap_registry_stats(void);

/**
 * @brief Register an mmap'd region in the global registry.
 * @param startp Start address of the mapping.
 * @param endp   End address (exclusive).
 * @param kind   Kind of mapping (arena, pool, etc.).
 *
 * @kw runtime          Runtime whose mmap context to use.
 * @kw file             Debug file name for this mapping.
 * @kw allocator        Allocator owning the mapping.
 * @kw binary_offset    Offset within a mapped binary file.
 * @kw slide            ASLR slide for the mapping.
 * @kw order_id         Insertion order identifier.
 * @kw perms            Known mapping permissions, if authoritative.
 * @kw definitely_unique If true, skip duplicate checks on insert.
 */
extern n00b_option_t(n00b_mmap_info_t *)
_n00b_mmap_register(void *startp, void *endp, n00b_mmap_rec_kind_t kind) _kargs
{
    n00b_runtime_t   *runtime           = n00b_get_runtime();
    const char       *file              = nullptr;
    const char       *source_file       = nullptr;
    uint32_t          source_line       = 0;
    n00b_allocator_t *allocator         = nullptr;
    uint64_t          binary_offset     = 0;
    intptr_t          slide             = 0;
    uint64_t          order_id          = 0;
    n00b_mmap_perms_t perms             = n00b_mmap_perms_unknown;
    bool              definitely_unique = true;
};

#define n00b_mmap_register(startp, endp, kind, ...)                                      \
    _n00b_mmap_register((startp),                                                        \
                        (endp),                                                          \
                        (kind),                                                          \
                        .source_file = __FILE__,                                         \
                        .source_line = __LINE__ __VA_OPT__(, __VA_ARGS__))

/**
 * @brief Register a page that backs an @ref n00b_pool_t allocator.
 *
 * @param startp    Start address of the page.
 * @param endp      End address of the page (exclusive).
 * @param allocator Owning pool allocator.
 * @param file      Caller location for diagnostics.
 *
 * Narrow internal entry point intended only for @ref new_page_entry
 * in pool.c. Unlike @ref n00b_mmap_register this does NOT short-
 * circuit when @c allocator->hidden is set — that's the point.
 * @ref n00b_mem_get_allocator can then resolve a pointer in the
 * page back to the owning hidden pool, which is what makes
 * @ref n00b_free work for hidden+metadata pools (rt->user_pool in
 * particular).
 *
 * The GC-scan path is unaffected: @ref n00b_mmap_is_gc_scannable
 * still keys off @c allocator->hidden / @c metadata_pool, so a
 * hidden pool's pages remain opaque to conservative scanning;
 * registering them here only enables address-to-allocator lookup.
 *
 * Kind is fixed at @c n00b_mmap_pool.
 */
extern n00b_option_t(n00b_mmap_info_t *)
_n00b_mmap_register_pool_page(void *startp,
                               void *endp,
                               n00b_allocator_t *allocator,
                               const char *file,
                               const char *source_file,
                               uint32_t source_line);

#define n00b_mmap_register_pool_page(startp, endp, allocator, file)                     \
    _n00b_mmap_register_pool_page((startp),                                             \
                                  (endp),                                               \
                                  (allocator),                                          \
                                  (file),                                               \
                                  __FILE__,                                             \
                                  __LINE__)

/**
 * @brief Async-signal-handler-safe lookup for SIGBUS / SIGSEGV
 *        handlers.  Pulls registry fields for a candidate faulting
 *        address without allocating or calling any n00b string /
 *        print machinery.
 */
extern void *
n00b_mmap_handler_lookup(uintptr_t addr,
                         uint64_t *out_start,
                         uint64_t *out_end,
                         uint32_t *out_kind,
                         const char **out_file,
                         const char **out_source_file,
                         uint32_t *out_source_line);


/**
 * @brief Unregister an mmap'd region.
 * @param start Start address of the mapping to remove.
 *
 * @kw runtime Runtime whose mmap context to use.
 */
extern void
n00b_mmap_unregister(void *start) _kargs
{
    n00b_runtime_t *runtime = n00b_get_runtime();
};

/**
 * @brief Allocate memory via mmap.  Use the n00b_mmap() macro.
 * @param sz  Number of bytes to map.
 * @param loc Source location string (auto-filled by macro).
 *
 * @kw allocator Allocator to associate with the mapping.
 * @kw kind      Mmap record kind (default n00b_mmap_api_mmap).
 * @kw name      Debug name for the mapping.
 *
 * @pre @p sz > 0.
 * @post On success, the mapped region is registered in the global mmap registry.
 */
// clang-format off
extern n00b_result_t(void *)
_n00b_mmap(size_t sz, char *loc) _kargs
{
    n00b_allocator_t    *allocator     = nullptr;
    n00b_mmap_rec_kind_t kind          = n00b_mmap_api_mmap;
    char                *name          = nullptr;
    /* When true, allocate the page but don't enter it in the mmap
     * tree. The caller is then responsible for registering (and
     * unregistering) the page itself — currently only @c pool.c
     * does so, via @ref n00b_mmap_register_pool_page paired with
     * @ref n00b_mmap_unregister at free time. The skip avoids the
     * implicit @ref n00b_mmap_register that would otherwise filter
     * by @c allocator->hidden, leaving the caller in full control
     * of which pages are visible to @ref n00b_mem_get_allocator. */
    bool                 skip_register = false;
};
// clang-format on

#define n00b_mmap(sz, ...) _n00b_mmap(sz, N00B_LOC_STRING() __VA_OPT__(, __VA_ARGS__))

/**
 * @brief Unmap a previously mmap'd region.
 * @param addr Start address to unmap.
 *
 * @kw runtime Runtime whose mmap context to use.
 *
 * @pre @p addr was returned by a prior n00b_mmap() call.
 * @post The mapping is removed from the global registry and memory is released.
 */
// clang-format off
extern n00b_result_t(int)
n00b_munmap(void *addr) _kargs
{
    n00b_runtime_t *runtime = n00b_get_runtime();
};
// clang-format on

/**
 * @brief Check whether a mapping is an arena segment.
 * @param map Mmap info to check.
 * @return    true if managed or system segment.
 */
static inline bool
n00b_mmap_is_arena_segment(n00b_mmap_info_t *map)
{
    switch (map->kind) {
    case n00b_mmap_managed_segment:
    case n00b_mmap_sys_segment:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Check whether a mapping is an arena root (not a segment).
 * @param map Mmap info to check.
 * @return    true if arena root.
 */
static inline bool
n00b_mmap_is_arena(n00b_mmap_info_t *map)
{
    switch (map->kind) {
    case n00b_mmap_arena:
        return true;
    default:
        return false;
    }
}

static inline n00b_mmap_rec_kind_t
n00b_mmap_get_kind(n00b_mmap_info_t *map)
{
    return map->kind;
}

/**
 * @brief Look up mmap info by address using the global registry.
 * @param addr Address to look up.
 * @return     Optional mmap info.
 *
 * @kw runtime Runtime whose mmap context to use.
 */
extern n00b_option_t(n00b_mmap_info_t *)
n00b_mmap_by_address(void *addr) _kargs
{
    n00b_runtime_t *runtime = n00b_get_runtime();
};

/**
 * @brief Look up a registered allocation/static-object sub-range by address.
 * @param addr Address to look up.
 * @return     Optional range descriptor covering @p addr.
 *
 * @kw runtime Runtime whose mmap context to use.
 */
extern n00b_option_t(n00b_alloc_range_t *)
n00b_mmap_range_by_address(void *addr) _kargs
{
    n00b_runtime_t *runtime = n00b_get_runtime();
};

typedef n00b_option_t(n00b_allocator_t *) n00b_allocator_opt_t;

/**
 * @brief Find the allocator owning an address.
 * @param addr Address to look up.
 * @return     Optional allocator pointer.
 *
 * @kw runtime Runtime whose mmap context to use.
 */
extern n00b_allocator_opt_t
n00b_mem_get_allocator(void *addr) _kargs
{
    n00b_runtime_t *runtime = n00b_get_runtime();
};

/**
 * @brief Check whether a mapping is GC-managed.
 * @param map Mmap info to check.
 * @return    true if managed segment, system segment, or pool.
 */
static inline bool
n00b_mmap_is_managed(n00b_mmap_info_t *map)
{
    if (!map) {
        return false;
    }
    switch (map->kind) {
    case n00b_mmap_managed_segment:
    case n00b_mmap_sys_segment:
    case n00b_mmap_pool:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Unmap a region, handling both registered and hidden pages.
 *
 * Tries n00b_munmap() first (removes the mmap record and unmaps).
 * If the region is not registered (e.g. hidden allocator pages),
 * falls back to raw munmap with the provided size.
 *
 * This is the canonical cleanup path for allocator implementations
 * that may operate in hidden mode.
 *
 * @param addr Address to unmap.
 * @param size Size of the mapping (used as fallback for hidden pages).
 */
static inline void
n00b_safe_munmap(void *addr, size_t size)
{
    bool use_registry = false;
    auto map_opt      = n00b_mmap_by_address(addr);

    if (n00b_option_is_set(map_opt)) {
        n00b_mmap_info_t *map = n00b_option_get(map_opt);
        uint64_t          lo  = (uint64_t)addr;
        uint64_t          hi  = lo + (uint64_t)size;

        use_registry = map->start == lo && map->end == hi && hi >= lo;
    }

    if (use_registry) {
        auto r = n00b_munmap(addr);
        if (n00b_result_is_ok(r)) {
            return;
        }
    }
#ifdef _WIN32
    VirtualFree(addr, 0, MEM_RELEASE);
#else
    munmap(addr, size);
#endif
}

/**
 * @brief Register a sub-range (individual allocation) within an existing mmap.
 * @param start Start address of the sub-range.
 * @param end   End address (exclusive) of the sub-range.
 * @param kind  Kind of sub-range.
 *
 * @kw allocator Allocator owning the sub-range.
 * @kw file      Debug file name.
 */
extern n00b_alloc_range_t *
n00b_mmap_register_range(void *start, void *end, n00b_mmap_rec_kind_t kind) _kargs
{
    n00b_allocator_t    *allocator = nullptr;
    const char          *file      = nullptr;
    n00b_gc_scan_kind_t  scan_kind = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_cb_t    scan_cb   = nullptr;
    void                *scan_user = nullptr;
    n00b_alloc_type_info_t tinfo    = 0;
    uint64_t             object_id = 0;
    const n00b_static_identity_t *identity = nullptr;
    uint32_t             flags     = 0;
};

/**
 * @brief Register a static object descriptor in the global mmap/range tree.
 * @param start Object start address.
 * @param len   Object size in bytes.
 * @param tinfo Runtime type hash for the object, or 0 when unknown.
 * @param loc   Source location string.
 *
 * @kw scan_kind GC scan shape for the object's words.
 * @kw scan_cb   Optional callback used when scan_kind == CALLBACK.
 * @kw scan_user Opaque callback data.
 * @kw object_id Stable generated-object identity, if available.
 * @kw identity  Portable source-semantic identity, if available.
 * @kw flags     Reserved descriptor flags for generated-code contracts.
 */
extern n00b_alloc_range_t *
_n00b_static_object_register(void *start,
                             size_t len,
                             n00b_alloc_type_info_t tinfo,
                             const char *loc) _kargs
{
    n00b_gc_scan_kind_t scan_kind = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_gc_scan_cb_t   scan_cb   = nullptr;
    void               *scan_user = nullptr;
    uint64_t            object_id = 0;
    const n00b_static_identity_t *identity = nullptr;
    uint32_t            flags     = 0;
};

#define n00b_static_object_register(start, len, tinfo, ...)                                   \
    _n00b_static_object_register((start),                                                     \
                                 (len),                                                       \
                                 (tinfo),                                                     \
                                 N00B_LOC_STRING() __VA_OPT__(, __VA_ARGS__))

/**
 * @brief Delete all sub-ranges overlapping [start, end).
 * @param ctx   Mmap context.
 * @param start Start of the range to clear.
 * @param end   End of the range to clear (exclusive).
 */
extern void n00b_mmap_delete_ranges(n00b_mmap_ctx_t *ctx, uint64_t start, uint64_t end);

#define n00b_global_mem_map(rt) (&(rt->mmaps))

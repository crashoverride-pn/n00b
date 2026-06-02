/**
 * @file alloc_base.h
 * @brief Foundational allocator and memory-mapping types.
 *
 * Leaf header defining the base allocator vtable and mmap record
 * structures used throughout the memory subsystem.  Has no internal
 * dependencies beyond `n00b.h`.
 *
 * This header exists to break the circular dependency chain that
 * previously ran through `runtime.h` -> `pool.h` -> `arena.h` ->
 * `alloc.h` -> `mmaps.h` -> `runtime.h`.  Every memory-subsystem
 * header that needs `n00b_base_allocator_t` or `n00b_mmap_info_t`
 * now includes this file instead of `runtime.h`.
 */
#pragma once

#include "n00b.h"

// ============================================================================
// Allocator function typedefs
// ============================================================================

typedef void *(*n00b_calloc_fn)(n00b_allocator_t *, size_t, void *);
typedef void (*n00b_free_fn)(n00b_allocator_t *, void *);
typedef void (*n00b_allocator_destroy_fn)(n00b_allocator_t *);

// ============================================================================
// Base allocator vtable
// ============================================================================

struct n00b_base_allocator_t {
    n00b_calloc_fn            zero_alloc;
    n00b_free_fn              free;
    n00b_allocator_destroy_fn destroy;
    const char               *debug_name;
    uint8_t                   add_inline_header : 1;
    uint8_t                   __system          : 1; // no STW check
    uint8_t                   hidden            : 1; // GC must consider it data.
    n00b_allocator_t         *metadata_pool;
    n00b_dict_untyped_t      *metadata;
};

// ============================================================================
// Memory-map record types
// ============================================================================

typedef enum n00b_mmap_rec_kind_t n00b_mmap_rec_kind_t;

enum n00b_mmap_perms_t : uint8_t {
    n00b_mmap_perms_unknown       = 0,
    n00b_mmap_perms_data_not_addr = 0,
    n00b_mmap_perms_ro            = 1,
    n00b_mmap_perms_no_access     = 2,
    n00b_mmap_perms_rw            = 4,
};

typedef enum n00b_mmap_perms_t n00b_mmap_perms_t;

enum n00b_mmap_rec_kind_t {
    n00b_mmap_static          = 1,
    n00b_mmap_arena           = 2,
    n00b_mmap_managed_segment = 4,
    n00b_mmap_sys_segment     = 8,
    n00b_mmap_zero_page       = 16,
    n00b_mmap_unmanaged       = 32,
    n00b_mmap_stack           = 64,
    n00b_mmap_internal        = 128,
    n00b_mmap_pool            = 256,
    n00b_mmap_api_mmap        = 512,
    n00b_mmap_type_mask       = 1023,
};

struct n00b_mmap_info_t {
    uint64_t                    start;
    uint64_t                    end;
    uint64_t                    binary_offset;
    uint64_t                    order_id;
    _Atomic(n00b_allocator_t *) allocator;
    intptr_t                    slide;
    const char                 *file;
    n00b_mmap_rec_kind_t        kind;
    n00b_mmap_perms_t           perms;
    void                       *tree_node; // back-pointer for O(1) delete (generic node ptr)
};

/**
 * @brief Sub-range record for headerless allocations and described static objects.
 *
 * Stored as a variant alternative alongside `n00b_mmap_info_t *` in the
 * unified mmap interval tree.  The range carries enough scan and identity
 * metadata for GC and memory-test APIs without requiring an inline allocation
 * header at the object's address.
 */
struct n00b_alloc_range_t {
    void                    *start;
    void                    *tree_node;
    n00b_alloc_type_info_t   tinfo;
    n00b_gc_scan_cb_t        scan_cb;
    void                    *scan_user;
    n00b_allocator_t        *allocator;
    const char              *file;
    const n00b_static_identity_t *identity;
    uint64_t                 object_id;
    uint64_t                 len;
    n00b_mmap_rec_kind_t     kind;
    n00b_gc_scan_kind_t      scan_kind;
    uint32_t                 flags;
    // Cached pointer-key hash for descriptor-backed static objects.
    // Zero is the "uncached" sentinel; the build-time helper writes a
    // nonzero value into the descriptor template for key-bearing static
    // objects, and static-range registration copies it here so
    // n00b_hash() can short-circuit on static-range hits. Runtime
    // recompute paths must NOT write back to this slot (the value is
    // build-time-authoritative for static objects). Placed at the end
    // of the struct to preserve existing field layout.
    n00b_uint128_t           cached_hash;
};

/**
 * @file rocs/map.h
 * @brief Low-level resident-image mapped access declarations for rocs.
 *
 * This header declares the WP-001 mapped access surface. Mapped views are
 * borrowed, read-only, resolver-aware handles over a resident marshal image;
 * callers must not cast them to ordinary n00b containers or pass mapped
 * internals to hot list/dict APIs.
 *
 * The resident-image contract is:
 * - @c image_base + (vaddr & 0xFFFFFFFF) resolves into the contiguous payload
 *   front after the marshal stream header.
 * - Trailing marshal metadata remains for shared marshal/unmarshal
 *   compatibility outside rocs, but rocs mapped readers never unmarshal shard
 *   images and do not apply or rewrite patch/scan records.
 * - Function-pointer patch slots may be zero in the payload front because code
 *   pointers are not meaningful in read-only resident images; ordinary pointer
 *   and static-data patch payload slots are preserved.
 * - While open, the resident image is registered with the runtime as findable
 *   but GC-opaque. The collector may classify pointers into the image, but it
 *   must not trace or rewrite image contents.
 * - Closing a map invalidates every borrowed shard/list/dict/slot/ref handle
 *   derived from it.
 */
#pragma once

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error domain for rocs mapped-image operations.
 *
 * Values are suitable for the error branch of @c n00b_result_t returns
 * from @c n00b_store_map_* functions.
 */
typedef enum : int32_t {
    N00B_STORE_MAP_OK              = 0,
    N00B_STORE_MAP_ERR_ARG         = -1,
    N00B_STORE_MAP_ERR_IO          = -2,
    N00B_STORE_MAP_ERR_BAD_MAGIC   = -3,
    N00B_STORE_MAP_ERR_BAD_VERSION = -4,
    N00B_STORE_MAP_ERR_BAD_LAYOUT  = -5,
    N00B_STORE_MAP_ERR_RANGE       = -6,
    N00B_STORE_MAP_ERR_SCHEMA      = -7,
    N00B_STORE_MAP_ERR_BACKING     = -8,
    N00B_STORE_MAP_ERR_CACHE       = -9,
} n00b_store_map_err_t;

/**
 * @brief Static diagnostic string for a mapped-image error code.
 *
 * @param err  A @c N00B_STORE_MAP_* code, usually from
 *             @c n00b_result_get_err.
 * @return A n00b string naming the code, or @c UNKNOWN for an
 *         unrecognized value.
 */
extern n00b_string_t *n00b_store_map_err_str(n00b_err_t err);

/**
 * @brief Residency backing choice for a sealed shard image.
 */
typedef enum : int32_t {
    N00B_STORE_IMAGE_AUTO,
    N00B_STORE_IMAGE_LOCAL_MMAP,
    N00B_STORE_IMAGE_CACHE_MMAP,
    N00B_STORE_IMAGE_PINNED_BUFFER,
} n00b_store_image_backing_t;

typedef struct n00b_vfs       n00b_vfs_t;
typedef struct n00b_vfs_cache n00b_vfs_cache_t;

/**
 * @brief Process residency policy for sealed shard images.
 *
 * These limits control in-process residency only. Durable shard
 * retention and VFS cache eviction are separate policies.
 */
typedef struct {
    n00b_store_image_backing_t preferred_backing;
    uint64_t                   max_resident_bytes;
    uint32_t                   max_resident_shards;
    uint64_t                   idle_ns;
    bool                       prefetch_pruned_shards;
    bool                       allow_direct_mmap;
} n00b_store_residency_policy_t;

typedef struct n00b_store_map_t       n00b_store_map_t;
typedef struct n00b_store_map_shard_t n00b_store_map_shard_t;
typedef struct n00b_store_map_list_t  n00b_store_map_list_t;
typedef struct n00b_store_map_dict_t  n00b_store_map_dict_t;
typedef struct n00b_store_map_slot_t  n00b_store_map_slot_t;
typedef struct n00b_store_map_ref_t   n00b_store_map_ref_t;

/**
 * @brief Entry returned by hash-based mapped dictionary lookup.
 *
 * The key and value slots are borrowed view handles tied to the owning
 * map or parent dictionary view.
 */
typedef struct {
    n00b_store_map_slot_t *key;
    n00b_store_map_slot_t *value;
    n00b_uint128_t         hv;
    uint64_t               bucket_index;
} n00b_store_map_dict_entry_t;

/**
 * @brief Open a local sealed shard image by path.
 *
 * @param path  Local path naming an immutable sealed shard image.
 * @kw populate   Hint that the implementation may pre-populate pages.
 * @kw allocator  Allocator for the map handle and derived view handles.
 * @return A result containing an owned map handle on success.
 */
extern n00b_result_t(n00b_store_map_t *)
n00b_store_map_open_local_file(n00b_string_t *path) _kargs
{
    bool              populate  = false;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Open a sealed shard image through VFS.
 *
 * WP-001 keeps this public entry point stable for callers, but durable VFS/S3
 * loading and cache-file residency are implemented in WP-005. Until then, the
 * implementation fails predictably instead of falling back to a local-only
 * interpretation of remote paths.
 *
 * @param vfs   VFS instance that owns the durable shard namespace.
 * @param path  VFS path naming an immutable sealed shard image.
 * @kw cache      Optional cache used for cache-file residency.
 * @kw policy     Optional residency policy; @c nullptr selects defaults.
 * @return In WP-001, a typed cache error. WP-005 will return an owned map
 *         handle on success once durable VFS/S3 residency is implemented.
 */
extern n00b_result_t(n00b_store_map_t *)
n00b_store_map_open_vfs(n00b_vfs_t *vfs, n00b_string_t *path) _kargs
{
    n00b_vfs_cache_t              *cache     = nullptr;
    n00b_store_residency_policy_t *policy    = nullptr;
};

/**
 * @brief Open a sealed shard image from a n00b byte buffer.
 *
 * The implementation copies @p image into an owned, non-moving resident backing
 * before validating it. The caller retains ownership of the source buffer.
 *
 * @param image  Buffer containing the complete immutable image bytes.
 * @kw allocator  Allocator for the map handle and derived view handles.
 * @return A result containing an owned map handle on success.
 */
extern n00b_result_t(n00b_store_map_t *)
n00b_store_map_open_buffer(n00b_buffer_t *image) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Close a mapped image.
 *
 * @param map  Map handle returned by a successful open call.
 * @return @c true on successful close, or a typed map error.
 */
extern n00b_result_t(bool)
n00b_store_map_close(n00b_store_map_t *map);

/**
 * @brief Borrow the shard root view from a mapped image.
 *
 * @param map  Open map handle.
 * @return Borrowed mapped shard view on success, or a typed map error.
 */
extern n00b_result_t(n00b_store_map_shard_t *)
n00b_store_map_root(n00b_store_map_t *map);

/**
 * @brief Read the shard identifier from a mapped shard view.
 *
 * @param shard  Borrowed mapped shard view.
 * @return Shard identifier stored in the mapped shard root, or a typed
 *         map error for an invalid or closed handle.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_shard_id(n00b_store_map_shard_t *shard);

/**
 * @brief Read the record count from a mapped shard view.
 *
 * @param shard  Borrowed mapped shard view.
 * @return Number of records in the shard, or a typed map error for an
 *         invalid or closed handle.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_shard_records_len(n00b_store_map_shard_t *shard);

/**
 * @brief Borrow the mapped records-list view from a shard.
 *
 * @param shard  Borrowed mapped shard view.
 * @return Borrowed records-list view on success.
 */
extern n00b_result_t(n00b_store_map_list_t *)
n00b_store_map_shard_records(n00b_store_map_shard_t *shard);

/**
 * @brief Borrow the mapped columns-dictionary view from a shard.
 *
 * Phase 3 shard-column dict views are pointer-key/pointer-value views. Future
 * mapped dict constructors for hash keys, postings, or packed scalar values
 * must carry explicit key/value widths because the typed dict store layout is
 * erased and does not store element sizes.
 *
 * @param shard  Borrowed mapped shard view.
 * @return Borrowed columns-dictionary view on success.
 */
extern n00b_result_t(n00b_store_map_dict_t *)
n00b_store_map_shard_columns(n00b_store_map_shard_t *shard);

/**
 * @brief Read the length of a mapped list view.
 *
 * @param list  Borrowed mapped list view.
 * @return Number of slots in the mapped list, or a typed map error for an
 *         invalid or closed handle.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_list_len(n00b_store_map_list_t *list);

/**
 * @brief Borrow a slot from a mapped list by ordinal.
 *
 * Missing ordinals return a successful none; malformed mapped bytes
 * return a typed map error.
 *
 * @param list     Borrowed mapped list view.
 * @param ordinal  Zero-based slot ordinal.
 * @return Result wrapping an optional borrowed slot view.
 */
extern n00b_result_t(n00b_option_t(n00b_store_map_slot_t *))
n00b_store_map_list_slot(n00b_store_map_list_t *list, uint64_t ordinal);

/**
 * @brief Resolve a pointer-like mapped slot into a mapped reference.
 *
 * @param slot  Borrowed mapped slot view.
 * @return Result wrapping an optional borrowed mapped reference.
 */
extern n00b_result_t(n00b_option_t(n00b_store_map_ref_t *))
n00b_store_map_slot_ref(n00b_store_map_slot_t *slot);

/**
 * @brief Find a mapped dictionary entry by 128-bit hash value.
 *
 * Missing entries return a successful none; malformed mapped bytes
 * return a typed map error. The implementation must resolve internal
 * dictionary pointers through the owning map resolver. Lookup is read-only:
 * it never calls ordinary @c n00b_dict_* APIs, never takes dict/list locks,
 * never writes bucket flags, ignores synchronization-only bucket flags, and
 * treats only @c N00B_HT_FLAG_DELETED as semantic state.
 *
 * @param dict  Borrowed mapped dictionary view.
 * @param hv    Hash value to probe.
 * @return Result wrapping an optional borrowed dictionary entry.
 */
extern n00b_result_t(n00b_option_t(n00b_store_map_dict_entry_t *))
n00b_store_map_dict_find_hv(n00b_store_map_dict_t *dict, n00b_uint128_t hv);

#ifdef __cplusplus
}
#endif

/**
 * @file internal/rocs/map.h
 * @brief Internal mapped-image helpers for rocs implementation/tests.
 *
 * These declarations expose focused resident-image diagnostics plus narrow
 * implementation helpers that keep mapped JSON access inside the rocs map
 * layer. They are not public data-access APIs: production callers outside rocs
 * internals must use the public borrowed view handles in <rocs/map.h>.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "parsers/json.h"
#include "rocs/map.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return the raw resident-image base address for a live map.
 *
 * Test/diagnostic-only. The returned address becomes invalid when the map is
 * closed and must not be used to read rocs data directly.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_resident_base_for_test(n00b_store_map_t *map);

/**
 * @brief Return the raw resident-image byte length for a live map.
 *
 * Test/diagnostic-only. This is the sealed image length, not necessarily the
 * page-aligned backing allocation length.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_resident_len_for_test(n00b_store_map_t *map);

typedef struct {
    uint64_t byte_len;
    uint64_t mapped_bytes;
    bool     local_mmap;
    bool     copy_mmap;
    bool     pinned_buffer;
} n00b_store_map_memory_stats_t;

/**
 * @brief Return cheap resident-image backing diagnostics for a live map.
 *
 * Intended for store health accounting. `byte_len` is the sealed image size;
 * `mapped_bytes` is the page-aligned mmap length when the backing is mmaped.
 */
extern n00b_result_t(n00b_store_map_memory_stats_t)
n00b_store_map_memory_stats(n00b_store_map_t *map);

/**
 * @brief Materialize one sealed mapped record as a hot JSON graph.
 *
 * @param shard Borrowed sealed mapped shard view.
 * @param ordinal Per-shard record ordinal.
 * @kw allocator Allocator for the returned hot JSON node graph.
 * @return Ok(node) on success, or a typed map error for invalid input, bad
 *         mapped layout, or out-of-range ordinal.
 *
 * This helper is intentionally internal. It resolves and range-checks mapped
 * bytes inside the rocs map layer, recursively copies JSON nodes using the JSON
 * variant selector as the sole kind discriminator, and never unmarshals the
 * sealed shard or exposes raw mapped JSON pointers to callers.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_store_map_shard_record_json_copy(n00b_store_map_shard_t *shard,
                                      uint64_t                ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Copy one sealed mapped record's stored JSON string verbatim.
 *
 * @param shard Borrowed sealed mapped shard view.
 * @param ordinal Per-shard record ordinal.
 * @kw allocator Allocator for the returned string copy.
 * @return Ok(string) on success, or a typed map error for invalid input, bad
 *         mapped layout, or out-of-range ordinal.
 *
 * Records are persisted as compact (`.pretty = false`) JSON strings. Unlike
 * @ref n00b_store_map_shard_record_json_copy this returns the stored bytes as
 * a fresh string WITHOUT parsing them into a node graph, so a caller that only
 * needs to re-serialize the record avoids the parse + re-encode round trip and
 * the associated GC-heap allocation. The returned string is a copy; it never
 * aliases the read-only mapped image.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_map_shard_record_json_string(n00b_store_map_shard_t *shard,
                                        uint64_t                ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

typedef struct n00b_store_map_posting_list_t n00b_store_map_posting_list_t;

extern n00b_result_t(n00b_store_map_posting_list_t *)
n00b_store_map_slot_posting_list(n00b_store_map_slot_t *slot);

extern n00b_result_t(n00b_store_postings_kind_t)
n00b_store_map_posting_list_kind(n00b_store_map_posting_list_t *postings);

extern n00b_result_t(uint64_t)
n00b_store_map_posting_list_len(n00b_store_map_posting_list_t *postings);

extern n00b_result_t(uint64_t)
n00b_store_map_posting_list_ordinal_at(n00b_store_map_posting_list_t *postings,
                                       uint64_t                       index);

extern n00b_result_t(bool)
n00b_store_map_posting_list_contains(n00b_store_map_posting_list_t *postings,
                                     uint64_t                       ordinal);

#ifdef __cplusplus
}
#endif

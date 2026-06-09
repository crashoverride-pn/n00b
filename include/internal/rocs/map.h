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

#ifdef __cplusplus
}
#endif

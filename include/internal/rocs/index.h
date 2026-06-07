/**
 * @file internal/rocs/index.h
 * @brief Internal record-view helpers for rocs planner/index integration.
 *
 * These declarations are internal to rocs. They construct and resolve opaque
 * shard-aware @c n00b_store_record_t handles for existing per-shard ordinals.
 * They do not expose a public hit/record API and never return raw mapped JSON
 * pointers to callers.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "parsers/json.h"
#include "rocs/index.h"
#include "rocs/map.h"
#include "rocs/shard.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Construct an opaque record view for one open hot-shard ordinal.
 *
 * @param shard Borrowed open hot shard.
 * @param ordinal Per-shard ordinal to resolve.
 * @kw allocator Allocator for the returned view handle.
 * @return Ok(record) on success, or a typed index error for invalid inputs,
 *         unreadable shard state, or out-of-range ordinal.
 *
 * The returned handle borrows @p shard and carries only shard-aware position
 * metadata. It does not copy or own the hot JSON record.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_hot_at(n00b_store_shard_t *shard,
                              uint64_t            ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an opaque record view for one sealed mapped-shard ordinal.
 *
 * @param shard Borrowed sealed mapped shard view.
 * @param ordinal Per-shard ordinal to resolve.
 * @kw allocator Allocator for the returned view handle.
 * @return Ok(record) on success, or a typed index error for invalid inputs,
 *         unreadable mapped state, or out-of-range ordinal.
 *
 * The returned handle borrows @p shard. It records no raw mapped JSON pointer;
 * mapped record bytes remain hidden behind the rocs mapped access layer.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_mapped_at(n00b_store_map_shard_t *shard,
                                 uint64_t                ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Resolve a record view to a hot JSON node for verification.
 *
 * @param record Borrowed opaque record view.
 * @kw allocator Allocator used when a sealed mapped record must be
 *               materialized as a hot JSON graph.
 * @return Ok(node) on success, or a typed index error for invalid state.
 *
 * Hot record views return the borrowed in-shard JSON node. Mapped record views
 * return a newly materialized hot JSON graph produced through internal rocs map
 * helpers. The function never returns a pointer into sealed mapped bytes.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_store_record_view_json(n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

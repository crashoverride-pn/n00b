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
 * @brief Construct an opaque hot-shard record view for an explicit durable
 *        position.
 *
 * @param shard Borrowed in-memory hot-path shard that owns the record list.
 *              The shard may be the current OPEN hot shard or a just-sealed
 *              in-memory shard already handed to a live cursor hit.
 * @param pos   Durable position copied from the store tail. @c pos.shard_id
 *              must match @p shard and @c pos.ordinal must be readable.
 * @kw allocator Allocator for the returned view handle.
 * @return Ok(record) on success, or a typed index error.
 *
 * Live query cursors use this helper so hot-tail hits report the durable store
 * generation captured by the authoritative scan rather than the legacy hot
 * posting generation. The returned handle borrows @p shard and remains an
 * in-memory hot-path view; it does not expose mapped storage, shard images, or
 * copy JSON. Callers must keep the containing cursor/hit lifetime inside the
 * borrowed shard lifetime.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_hot_pos(n00b_store_shard_t *shard,
                               n00b_store_pos_t    pos) _kargs
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
 * @brief Construct an opaque mapped record view with an explicit durable
 *        catalog position.
 *
 * @param shard Borrowed sealed mapped shard view.
 * @param pos Durable catalog position to attach to the returned record view.
 *            @c pos.shard_id must match @p shard and @c pos.ordinal must be
 *            readable in the mapped record list.
 * @kw allocator Allocator for the returned view handle.
 * @return Ok(record) on success, or a typed index error for invalid inputs,
 *         unreadable mapped state, shard mismatch, or out-of-range ordinal.
 *
 * Query snapshot hits use this helper so public record positions retain the
 * catalog generation captured by the snapshot boundary rather than deriving a
 * generation from the mapped shard's seal timestamp.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_mapped_pos(n00b_store_map_shard_t *shard,
                                  n00b_store_pos_t        pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an opaque record view backed by owned hot JSON.
 *
 * @param pos  Durable position copied into the returned record view.
 * @param json Owned materialized JSON graph for this record.
 * @kw allocator Allocator for the returned view handle.
 * @return Ok(record) on success, or a typed index error.
 *
 * The returned handle does not borrow a hot shard or mapped shard. Query
 * output uses this for hot-tail deliveries that must remain valid after view
 * close or hot-shard rotation.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_owned_json(n00b_store_pos_t   pos,
                                  n00b_json_node_t  *json) _kargs
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
 * Hot record views backed by OPEN or SEALED in-memory hot-path shards return
 * the borrowed in-shard JSON node. Mapped record views return a newly
 * materialized hot JSON graph produced through internal rocs map helpers. The
 * function never returns a pointer into sealed mapped bytes.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_store_record_view_json(n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Materialize a record view as a newly owned hot JSON graph.
 *
 * @param record Borrowed opaque record view.
 * @kw allocator Allocator for the returned JSON graph.
 * @return Ok(copied JSON) on success, or a typed index error.
 *
 * Hot, mapped, and already-owned record views all return a fresh recursive
 * JSON graph. The function never returns a raw pointer into mapped bytes and
 * never exposes shard/list/dict internals.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_store_record_view_json_copy(n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

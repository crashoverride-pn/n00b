/**
 * @file internal/rocs/query.h
 * @brief Internal read-only query view inspectors.
 *
 * This header is for rocs implementation modules and focused tests. It is not
 * included from public rocs headers and exposes no planner, catalog entry,
 * resident-map, cursor, hit, or record-materialization structs.
 */
#pragma once

#define N00B_ROCS_INTERNAL_QUERY_H 1

#include "adt/option.h"
#include "adt/result.h"
#include "rocs/query.h"

/**
 * @brief Copied sealed-shard metadata captured by a snapshot query view.
 *
 * String handles are owned by the query view allocation lifetime and are not
 * borrowed from the store catalog. This value is returned by copy from
 * inspectors so tests and later phases cannot mutate the view boundary list.
 */
typedef struct {
    uint64_t                         shard_id;
    uint64_t                         generation;
    uint64_t                         schema_generation;
    uint64_t                         record_count;
    uint64_t                         seal_ts;
    n00b_string_t                   *partition_key;
    n00b_string_t                   *object_path;
    uint64_t                         byte_len;
    n00b_option_t(n00b_string_t *)    etag;
} n00b_query_boundary_entry_t;

/**
 * @brief Internal snapshot cache counters for focused tests.
 *
 * The cache is an invisible, process-side implementation detail owned by a
 * query view. Entries contain copied immutable per-shard ordinal sets and
 * copied metadata only; they never own resident shard handles, mapped shard
 * handles, record views, raw mapped containers, or public hit handles.
 *
 * The internal cache contract is intentionally unwindowed: an entry represents
 * the complete per-shard result for one semantic filter shape against one
 * sealed-shard boundary. Cursor options `resume`, `as_of`, and `limit` are
 * applied after an ordset is read from or populated into the cache, so those
 * options are not part of the cache key.
 *
 * `entries` is the current number of cache ownership references retained by
 * the view. `evictions` counts ownership references dropped from the cache
 * under the internal FIFO bound. These counters are not allocator heap-free
 * byte counts; storage lifetime remains owned by the allocator/GC.
 */
typedef struct {
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t populates;
    uint64_t bypasses;
    uint64_t clears;
    uint64_t stale_rejects;
    uint64_t evictions;
    uint64_t max_entries;
    uint64_t entries;
    bool     disabled;
} n00b_query_cache_stats_t;

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Return the number of copied boundary entries in a view. */
extern n00b_result_t(uint64_t)
n00b_query_view_boundary_count(n00b_query_view_t *view);

/** @brief Return one copied boundary entry by durable-position order. */
extern n00b_result_t(n00b_option_t(n00b_query_boundary_entry_t))
n00b_query_view_boundary_entry_at(n00b_query_view_t *view, uint64_t index);

/** @brief Return the mode recorded on a view. */
extern n00b_result_t(n00b_query_mode_t)
n00b_query_view_mode(n00b_query_view_t *view);

/** @brief Return the hit limit recorded on a view. */
extern n00b_result_t(uint64_t)
n00b_query_view_limit(n00b_query_view_t *view);

/** @brief Return the copied resume position when one was supplied. */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_resume(n00b_query_view_t *view);

/** @brief Return the copied as-of position when one was supplied. */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_as_of(n00b_query_view_t *view);

/**
 * @brief Return the copied snapshot upper bound for a query view.
 *
 * @param view Borrowed query view.
 * @return Ok(some(position)) for the last durable sealed position included by
 *         the view's copied snapshot boundary, capped by the copied @c as_of
 *         position when one was supplied. Empty copied boundaries return
 *         Ok(none). Null input returns @c N00B_QUERY_ERR_ARG.
 *
 * This internal handoff helper uses only metadata copied into the view at
 * snapshot creation time. It never consults the current store catalog, never
 * acquires residents, and never exposes catalog entries, mapped shard handles,
 * resident handles, record views, raw containers, or public hit handles.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_snapshot_upper_bound(n00b_query_view_t *view);

/** @brief Report whether a view has been closed. */
extern n00b_result_t(bool)
n00b_query_view_is_closed(n00b_query_view_t *view);

/**
 * @brief Return the number of snapshot hits built for a cursor.
 *
 * @param cursor Borrowed open cursor.
 * @return Ok(count), @c N00B_QUERY_ERR_ARG for null/malformed input, or
 *         @c N00B_QUERY_ERR_CLOSED after cursor/view close.
 *
 * This internal handoff helper does not advance cursor state and does not
 * expose hit handles, record views, residents, mapped shard internals, or raw
 * containers.
 */
extern n00b_result_t(uint64_t)
n00b_query_cursor_hit_count(n00b_query_cursor_t *cursor);

/**
 * @brief Return one built hit's durable position by built-hit order.
 *
 * @param cursor Borrowed open cursor.
 * @param index  Zero-based built-hit index.
 * @return Ok(some(position)) when @p index names a built snapshot hit,
 *         Ok(none) when out of range, @c N00B_QUERY_ERR_ARG for
 *         null/malformed input, or @c N00B_QUERY_ERR_CLOSED after cursor/view
 *         close.
 *
 * This internal handoff helper is position-only. It does not advance cursor
 * state and does not expose hit handles, record views, residents, mapped shard
 * internals, or raw containers.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_cursor_hit_position_at(n00b_query_cursor_t *cursor,
                                  uint64_t             index);

/**
 * @brief Return read-only counters for the invisible process-side cache.
 *
 * @param view Borrowed query view.
 * @return Ok(stats), or @c N00B_QUERY_ERR_ARG for null input.
 *
 * This is an internal/test control only. It does not expose cache keys, ordinal
 * storage, resident handles, mapped shard internals, or public cache knobs.
 */
extern n00b_result_t(n00b_query_cache_stats_t)
n00b_query_cache_stats(n00b_query_view_t *view);

/**
 * @brief Drop all entries from a view-owned invisible cache.
 *
 * @param view Borrowed query view.
 * @return Ok(true) when entries were replaced by an empty process-side list,
 *         or @c N00B_QUERY_ERR_ARG for null input.
 *
 * This internal/test helper changes only future cache hit/miss behavior and
 * counters. It does not change query answers and cannot release or retain
 * resident pins because cache entries do not own residents.
 */
extern n00b_result_t(bool)
n00b_query_cache_clear(n00b_query_view_t *view);

/**
 * @brief Enable or disable cache lookup/population for focused tests.
 *
 * @param view Borrowed query view.
 * @param disabled If true, cursor construction bypasses the cache and runs the
 *                 existing planner path.
 * @return Ok(true), or @c N00B_QUERY_ERR_ARG for null input.
 *
 * This is an internal/test control only. It is not public API and must not be
 * used as a query feature knob.
 */
extern n00b_result_t(bool)
n00b_query_cache_set_disabled(n00b_query_view_t *view, bool disabled);

/**
 * @brief Set the internal FIFO cache-entry bound for a query view.
 *
 * @param view Borrowed query view.
 * @param max_entries Maximum retained cache entries. Zero keeps the cache
 *                    unbounded, which is the default Phase 3 behavior.
 * @return Ok(true), or @c N00B_QUERY_ERR_ARG for null input.
 *
 * Positive bounds retain at most @p max_entries cache ownership references.
 * Lowering the bound evicts oldest inserted entries immediately until
 * `entries <= max_entries`. Cache hits do not change FIFO order. Eviction
 * drops only cache-owned references to copied keys, copied ordinal sets, and
 * copied boundary metadata; cache entries never own resident pins.
 */
extern n00b_result_t(bool)
n00b_query_cache_set_max_entries(n00b_query_view_t *view,
                                 uint64_t           max_entries);

/**
 * @brief Corrupt one cached entry's metadata for stale-entry tests.
 *
 * @param view Borrowed query view.
 * @return Ok(true) when one entry was modified, Ok(false) when the cache is
 *         empty, or @c N00B_QUERY_ERR_ARG for null input.
 *
 * This narrow test-only helper forces metadata validation to reject an entry
 * as stale on the next lookup. It does not expose ordinal storage, mapped
 * shard internals, or resident handles.
 */
extern n00b_result_t(bool)
n00b_query_cache_test_corrupt_first_metadata(n00b_query_view_t *view);

#ifdef __cplusplus
}
#endif

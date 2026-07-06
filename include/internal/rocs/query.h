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
    // Hot (uncommitted) shard boundary. When true this boundary is NOT a sealed
    // mmap image (object_path is unset); its records live in the current hot
    // shard and are read via the hot-scan path (hot_tail_scan_after up to the
    // frozen hot_through) rather than the sealed plan. The hot shard's generation
    // is the newest, so this boundary sorts last (newest) and, under reverse
    // iteration, is delivered first — making SNAPSHOT queries hot-inclusive.
    bool                             is_hot;
    n00b_store_pos_t                 hot_through;
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

/**
 * @brief Internal live-tail diagnostics and durable scan progress.
 *
 * These counters are for focused tests and live cursor delivery. They expose
 * only scalar progress and copied durable positions; they do not expose commit
 * payloads, inboxes, subscription handles, catalog entries, residents, mapped
 * shards, record views, raw containers, or planner internals.
 */
typedef struct {
    bool             subscribed;
    bool             subscription_active;
    bool             has_inbox;
    uint32_t         inbox_limit;
    uint64_t         queued_wakeups;
    uint64_t         wakeups_drained;
    uint64_t         wakeup_full_observations;
    uint64_t         scans;
    uint64_t         observed_positions;
    uint64_t         matched_positions;
    uint64_t         pending_positions;
    bool             has_last_observed;
    n00b_store_pos_t last_observed;
} n00b_query_live_tail_stats_t;

/**
 * @brief Internal query-output diagnostics for focused tests.
 *
 * These counters expose only lifecycle and durable-position progress. They do
 * not expose inboxes, subscriptions, resident handles, mapped shards, record
 * views, raw containers, or public cache knobs.
 */
typedef struct {
    bool             configured;
    bool             started;
    bool             stop_requested;
    bool             closed;
    bool             joined;
    bool             has_thread;
    uint64_t         historical_positions;
    uint64_t         live_positions;
    uint64_t         delivered_messages;
    uint64_t         dropped_messages;
    uint64_t              subscriber_count;
    uint64_t              emitted_positions;
    uint64_t              limit;
    bool                  has_last_error;
    n00b_result_error_t   last_error;
    n00b_err_t            last_error_code;
    bool                  has_last_position;
    n00b_store_pos_t      last_position;
} n00b_query_output_stats_t;

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Return whether a query spec requests ranked execution. */
extern n00b_result_t(bool)
n00b_query_spec_ranked(n00b_query_t *query);

/** @brief Return the API result limit copied into a query spec. */
extern n00b_result_t(uint64_t)
n00b_query_spec_limit(n00b_query_t *query);

/** @brief Return the copied as-of boundary stored in a query spec. */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_spec_as_of(n00b_query_t *query);

/** @brief Return the copied group-by field count in a query spec. */
extern n00b_result_t(uint64_t)
n00b_query_spec_group_by_count(n00b_query_t *query);

/** @brief Return one copied group-by field handle by index. */
extern n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_query_spec_group_by_at(n00b_query_t *query, uint64_t index);

/** @brief Return the copied aggregate-spec count in a query spec. */
extern n00b_result_t(uint64_t)
n00b_query_spec_aggregate_count(n00b_query_t *query);

/** @brief Return one copied aggregate-spec handle by index. */
extern n00b_result_t(n00b_option_t(n00b_query_agg_spec_t *))
n00b_query_spec_aggregate_at(n00b_query_t *query, uint64_t index);

/** @brief Return the copied boost-spec count in a query spec. */
extern n00b_result_t(uint64_t)
n00b_query_spec_boost_count(n00b_query_t *query);

/** @brief Return one copied boost-spec handle by index. */
extern n00b_result_t(n00b_option_t(n00b_query_boost_t *))
n00b_query_spec_boost_at(n00b_query_t *query, uint64_t index);

/** @brief Return an aggregate spec's operation. */
extern n00b_result_t(n00b_query_agg_op_t)
n00b_query_agg_spec_op(n00b_query_agg_spec_t *spec);

/** @brief Return an aggregate spec's field handle, when present. */
extern n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_query_agg_spec_field(n00b_query_agg_spec_t *spec);

/** @brief Return an aggregate spec's optional output name. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_query_agg_spec_name(n00b_query_agg_spec_t *spec);

/** @brief Return a boost spec's field handle. */
extern n00b_result_t(n00b_filter_field_t *)
n00b_query_boost_spec_field(n00b_query_boost_t *spec);

/** @brief Return a boost spec's positive finite multiplier. */
extern n00b_result_t(double)
n00b_query_boost_spec_value(n00b_query_boost_t *spec);

/** @brief Report whether a finite query result has been closed. */
extern n00b_result_t(bool)
n00b_query_result_is_closed(n00b_query_result_t *result);

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
 * @brief Return the live view's historical start-after position.
 *
 * @param view Borrowed query view.
 * @return Ok(some(position)) when live mode was created with a resume
 *         boundary, Ok(none) when live history starts at the retained
 *         beginning or the view is not live, or @c N00B_QUERY_ERR_ARG for
 *         null input.
 *
 * This internal helper is position-only. It does not expose commit topics,
 * inboxes, catalog entries, resident handles, mapped shard internals, record
 * views, raw containers, or public hit handles.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_live_start_after(n00b_query_view_t *view);

/**
 * @brief Return the live view's captured historical upper boundary.
 *
 * @param view Borrowed query view.
 * @return Ok(some(position)) for the last durable sealed position captured by
 *         the live view's historical boundary, Ok(none) when no historical
 *         position was captured or the view is not live, or
 *         @c N00B_QUERY_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_live_historical_upper_bound(n00b_query_view_t *view);

/**
 * @brief Return the position after which later hot-tail scans should start.
 *
 * @param view Borrowed query view.
 * @return Ok(some(position)) for the captured cutover-after boundary, Ok(none)
 *         when the live view has no retained historical/resume boundary or the
 *         view is not live, or @c N00B_QUERY_ERR_ARG for null input.
 *
 * Initially this is the captured historical upper bound when present,
 * otherwise the supplied live resume boundary when present. Live-tail helpers
 * advance separate last-observed state after scanning durable store state past
 * this cutover.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_live_cutover_after(n00b_query_view_t *view);

/**
 * @brief Drain live-view commit wakeups without scanning store state.
 *
 * @param view Borrowed live query view.
 * @return Ok(count) for the number of bounded-inbox wakeup messages drained,
 *         @c N00B_QUERY_ERR_ARG for null input, @c N00B_QUERY_ERR_STATE for a
 *         non-live view, or @c N00B_QUERY_ERR_CLOSED after close.
 *
 * Wakeups are latency hints only. Draining or dropping them does not determine
 * result correctness; correctness comes from a later authoritative scan of
 * committed store/catalog state.
 */
extern n00b_result_t(uint64_t)
n00b_query_live_tail_drain_wakeups(n00b_query_view_t *view);

/**
 * @brief Run one nonblocking authoritative live-tail catch-up scan.
 *
 * @param view Borrowed live query view.
 * @return Ok(count) for copied matching durable positions appended to the
 *         view's internal pending-position queue, or a typed query error.
 *
 * The scan starts after the live cutover/last-observed durable position, uses
 * the same filter lowering, planner, and shard verification path as snapshot
 * execution, and advances last-observed over all newly committed durable
 * positions, including non-matches.
 */
extern n00b_result_t(uint64_t)
n00b_query_live_tail_scan_once(n00b_query_view_t *view);

/**
 * @brief Return internal live-tail counters and durable progress.
 *
 * @param view Borrowed live query view.
 * @return Ok(stats), @c N00B_QUERY_ERR_ARG for null input, or
 *         @c N00B_QUERY_ERR_STATE for a non-live view.
 */
extern n00b_result_t(n00b_query_live_tail_stats_t)
n00b_query_live_tail_stats(n00b_query_view_t *view);

/** @brief Return copied internal query-output counters. */
extern n00b_result_t(n00b_query_output_stats_t)
n00b_query_output_stats(n00b_query_view_t *view);

/** @brief Return copied pending live-tail match count. */
extern n00b_result_t(uint64_t)
n00b_query_live_tail_pending_count(n00b_query_view_t *view);

/**
 * @brief Return one copied pending live-tail match position.
 *
 * @param view Borrowed live query view.
 * @param index Zero-based pending-position index.
 * @return Ok(some(position)) when present, Ok(none) when out of range, or a
 *         typed query error.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_live_tail_pending_position_at(n00b_query_view_t *view,
                                         uint64_t           index);

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
 * @brief Report whether a live cursor is blocked in live-next wait state.
 *
 * @param cursor Borrowed cursor.
 * @return Ok(true) only while a live cursor is parked waiting for commit,
 *         close, or timed poll wakeup; Ok(false) otherwise, or a typed query
 *         error for invalid input/state.
 *
 * This test/synchronization helper exposes only cursor wait state. It does not
 * expose commit inboxes, condition variables, pending positions, hits, record
 * views, resident handles, or mapped storage.
 */
extern n00b_result_t(bool)
n00b_query_cursor_live_is_waiting(n00b_query_cursor_t *cursor);

/**
 * @brief Block until a live cursor enters live-next wait state or closes.
 *
 * @param cursor Borrowed live cursor.
 * @return Ok(true) when the cursor is waiting, Ok(false) when it closed before
 *         waiting, or a typed query error.
 *
 * Focused tests use this deterministic handshake before committing a record or
 * closing a cursor/view. It is internal-only and has no query-result effect.
 */
extern n00b_result_t(bool)
n00b_query_cursor_live_wait_until_waiting(n00b_query_cursor_t *cursor);

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

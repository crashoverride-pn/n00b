/**
 * @file rocs/query.h
 * @brief Public query-view declarations for rocs snapshot reads.
 *
 * Query views are process-side handles over a committed store boundary.
 * Snapshot cursors expose borrowed hit handles in deterministic durable
 * position order. The snapshot result cache is an invisible process-side
 * implementation detail; it does not add public cache API or change cursor
 * answers. Live delivery, ranking, aggregation, and owned result/conduit hits
 * are intentionally out of scope for WP-008.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "conduit/conduit_types.h"
#include "core/alloc.h"
#include "core/string.h"
#include "rocs/filter.h"
#include "rocs/store.h"

typedef struct n00b_query_view_t            n00b_query_view_t;
typedef struct n00b_query_cursor_t          n00b_query_cursor_t;
typedef struct n00b_query_hit_t             n00b_query_hit_t;
typedef struct n00b_query_retention_error_t n00b_query_retention_error_t;

/**
 * @brief Query delivery mode.
 *
 * WP-008 implements @ref N00B_QUERY_MODE_SNAPSHOT only.
 * @ref N00B_QUERY_MODE_LIVE is reserved for WP-009 and returns
 * @ref N00B_QUERY_ERR_UNSUPPORTED_MODE without creating a view.
 */
typedef enum : int32_t {
    N00B_QUERY_MODE_SNAPSHOT = 0,
    N00B_QUERY_MODE_LIVE     = 1,
} n00b_query_mode_t;

/**
 * @brief Query error domain.
 *
 * These codes classify query/view state and execution choices only. They do
 * not classify filter values, record values, JSON payloads, or cache state.
 */
typedef enum : int32_t {
    N00B_QUERY_OK                     = 0,
    N00B_QUERY_ERR_ARG                = -1,
    N00B_QUERY_ERR_CLOSED             = -2,
    N00B_QUERY_ERR_STATE              = -3,
    N00B_QUERY_ERR_SCHEMA             = -4,
    N00B_QUERY_ERR_RETENTION          = -5,
    N00B_QUERY_ERR_UNSUPPORTED_MODE   = -6,
    N00B_QUERY_ERR_UNSUPPORTED_FILTER = -7,
    N00B_QUERY_ERR_EXECUTION          = -8,
    N00B_QUERY_ERR_INTERNAL           = -9,
} n00b_query_err_t;

/**
 * @brief Boundary option that triggered a retention diagnostic.
 */
typedef enum : int32_t {
    N00B_QUERY_BOUNDARY_RESUME   = 1,
    N00B_QUERY_BOUNDARY_AS_OF    = 2,
    N00B_QUERY_BOUNDARY_SNAPSHOT = 3,
} n00b_query_boundary_kind_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for a query error code.
 *
 * @param err A @c N00B_QUERY_* error code.
 * @return A static rich string naming the code, or an unknown-error string
 *         for codes outside @ref n00b_query_err_t.
 */
extern n00b_string_t *n00b_query_err_str(n00b_err_t err);

/**
 * @brief Create a query view over a store and checked public filter.
 *
 * @param store  Borrowed open store. Null returns @ref N00B_QUERY_ERR_ARG.
 * @param filter Borrowed public filter predicate. Null returns
 *               @ref N00B_QUERY_ERR_ARG. Snapshot cursor construction later
 *               lowers this filter through the internal planner boundary.
 * @kw mode      Query mode. Defaults to @ref N00B_QUERY_MODE_SNAPSHOT.
 *               @ref N00B_QUERY_MODE_LIVE is a typed unsupported-mode error
 *               in Phase 1 and never falls back to snapshot mode.
 * @kw resume    Optional borrowed durable resume position. The position is
 *               copied by value into the view. It must still be retained by
 *               @p store; stale, dropped, missing, or out-of-range positions
 *               return a typed retention payload error carrying the current
 *               oldest-available boundary when known.
 * @kw as_of     Optional borrowed durable snapshot boundary. It is valid only
 *               for snapshot mode, is copied by value into the view, and must
 *               still be retained by @p store. If both @p resume and @p as_of
 *               are valid and @p resume sorts after @p as_of, creation
 *               succeeds with an empty snapshot boundary.
 * @kw out       Optional conduit output. Conduit delivery is unsupported in
 *               Phase 1; any non-null value returns
 *               @ref N00B_QUERY_ERR_UNSUPPORTED_MODE and does not create a
 *               view.
 * @kw limit     API-level cursor hit limit. Zero means unlimited. Positive
 *               values cap emitted snapshot hits.
 * @kw allocator Allocator for the view, copied boundary records, and any
 *               structured error payload.
 *
 * @return Ok(view) on successful snapshot-boundary capture, integer query
 *         errors for ordinary validation/state failures, or a
 *         @ref n00b_query_retention_error_t pointer payload for retained-away
 *         boundary failures.
 *
 * @post A successful view owns copied catalog metadata for the visible sealed
 *       snapshot boundary: shard id, generation, schema generation, record
 *       count, seal timestamp, partition key, object path, byte length, and
 *       optional etag. It does not retain catalog-entry pointers, mapped
 *       resident handles, planner state, cache state, raw mapped containers,
 *       or materialized records. Open cursors created from the view are owned
 *       by their public cursor handles and are invalidated by view close.
 * @post A successful view acquires one store active pin. Close it with
 *       @ref n00b_query_view_close to release that pin.
 */
extern n00b_result_t(n00b_query_view_t *)
n00b_query_view(n00b_store_t  *store,
                n00b_filter_t *filter) _kargs
{
    n00b_query_mode_t  mode      = N00B_QUERY_MODE_SNAPSHOT;
    n00b_store_pos_t  *resume    = nullptr;
    n00b_store_pos_t  *as_of     = nullptr;
    n00b_conduit_t    *out       = nullptr;
    uint64_t           limit     = 0;
    n00b_allocator_t  *allocator = nullptr;
};

/**
 * @brief Close a query view and release its store active pin.
 *
 * @param view Owned view returned by @ref n00b_query_view. Null returns
 *             @ref N00B_QUERY_ERR_ARG.
 * @return Ok(true) on the first close, Ok(false) on later closes, or a typed
 *         query error if the underlying store pin release reports impossible
 *         state.
 *
 * @post Close is idempotent. The first successful close releases exactly one
 *       store active pin. Later calls do not release again and cannot
 *       underflow the store pin count.
 * @post Close invalidates and closes every open cursor created from the view,
 *       invalidates borrowed cursor hits, releases cursor-held resident shard
 *       pins, and then releases the view's active store pin. It does not free
 *       the view graph immediately; the allocator/GC owns storage.
 */
extern n00b_result_t(bool)
n00b_query_view_close(n00b_query_view_t *view);

/**
 * @brief Create a deterministic snapshot cursor for a query view.
 *
 * @param view Borrowed open snapshot query view returned by
 *             @ref n00b_query_view. Null or closed views return typed query
 *             errors.
 * @kw allocator Allocator for the cursor, hit handles, resident handle list,
 *               planner scratch, and mapped record-view handles.
 *
 * @return Ok(cursor) on success, integer query errors for validation,
 *         lowering, planner, store, map, or execution failures, or a
 *         @ref n00b_query_retention_error_t pointer payload when a copied
 *         snapshot boundary shard is no longer retained and the store reports
 *         an oldest-available boundary.
 *
 * @pre WP-008 supports only snapshot views. Live mode and conduit output are
 *      unsupported and cannot be produced by @ref n00b_query_view in this
 *      work plan.
 * @post Cursor construction validates every copied Phase 1 boundary entry
 *       against the current store catalog before planning. Missing,
 *       retained-away, stale-generation, stale-schema, and incompatible
 *       metadata states fail with typed query results and release any resident
 *       handles acquired during construction.
 * @post Planning lowers the public filter through
 *       @c n00b_filter_lower_to_plan, plans sealed shards through
 *       @c n00b_plan_store_sealed, and intersects planner output with the
 *       copied snapshot boundary before constructing hits. Later commits after
 *       view creation are therefore excluded even if the planner sees them in
 *       the current catalog.
 * @post A view-owned, process-side cache may store copied per-shard ordinal
 *       sets for cacheable public filter shapes. Cache hits never expose
 *       resident handles, mapped shard internals, record views, raw mapped
 *       containers, or public hit handles, and cursor windowing is applied
 *       after cache lookup.
 * @post Cursor hits are emitted in increasing durable
 *       @c (generation, shard_id, ordinal) order. @c resume is enforced as
 *       strictly after the supplied position, @c as_of includes the supplied
 *       position and excludes later positions, and @c limit == 0 means
 *       unlimited.
 * @post Cursor-held resident shard handles pin mapped images until
 *       @ref n00b_query_cursor_close or view close. Returned hit and record
 *       handles are borrowed from the cursor/view lifetime and never expose
 *       raw mapped JSON/list/dict/buffer pointers.
 */
extern n00b_result_t(n00b_query_cursor_t *)
n00b_query_cursor(n00b_query_view_t *view) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Advance a snapshot cursor by one hit.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_cursor. Null returns
 *               @ref N00B_QUERY_ERR_ARG. Closed cursors and cursors whose view
 *               was closed return @ref N00B_QUERY_ERR_CLOSED.
 * @return Ok(some(hit)) for the next borrowed hit, Ok(none) at end of
 *         snapshot, or a typed query error.
 *
 * @post Advancing invalidates the previously returned borrowed hit, including
 *       when advancement reaches end-of-snapshot and returns none. The new hit
 *       remains valid until the next advance, cursor close, or view close.
 */
extern n00b_result_t(n00b_option_t(n00b_query_hit_t *))
n00b_query_cursor_next(n00b_query_cursor_t *cursor);

/**
 * @brief Return the last emitted durable cursor position.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_cursor.
 * @return Ok(none) before the first emitted hit, Ok(some(position)) after a
 *         hit has been emitted, including after end-of-snapshot until close,
 *         @ref N00B_QUERY_ERR_ARG for null, or @ref N00B_QUERY_ERR_CLOSED
 *         after cursor/view close.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_cursor_position(n00b_query_cursor_t *cursor);

/**
 * @brief Close a query cursor and release cursor-held resident pins.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_cursor. Null returns
 *               @ref N00B_QUERY_ERR_ARG.
 * @return Ok(true) on the first close, Ok(false) on later closes, or a typed
 *         query error if an underlying resident release reports impossible
 *         state.
 *
 * @post Close is idempotent. The first close invalidates borrowed hits and
 *       record views from the cursor and releases every resident shard handle
 *       exactly once. Later close calls do not release again.
 */
extern n00b_result_t(bool)
n00b_query_cursor_close(n00b_query_cursor_t *cursor);

/**
 * @brief Return the durable position for a borrowed query hit.
 *
 * @param hit Borrowed hit returned by @ref n00b_query_cursor_next.
 * @return Ok(position) while the hit is valid, @ref N00B_QUERY_ERR_ARG for
 *         null, or @ref N00B_QUERY_ERR_CLOSED after cursor advance, cursor
 *         close, or view close invalidates the borrowed hit.
 */
extern n00b_result_t(n00b_store_pos_t)
n00b_query_hit_pos(n00b_query_hit_t *hit);

/**
 * @brief Return the score for a borrowed query hit.
 *
 * @param hit Borrowed hit returned by @ref n00b_query_cursor_next.
 * @return Ok(score) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after invalidation.
 *
 * Cursor hits in WP-008 are unranked and always report @c 0.0.
 */
extern n00b_result_t(double)
n00b_query_hit_score(n00b_query_hit_t *hit);

/**
 * @brief Borrow the record-view handle for a query hit.
 *
 * @param hit Borrowed hit returned by @ref n00b_query_cursor_next.
 * @return Ok(record) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after invalidation.
 *
 * @post The returned @ref n00b_store_record_t pointer is borrowed from the
 *       cursor-held resident mapped image. It remains valid only until cursor
 *       advance, cursor close, or view close. It is an opaque shard-aware
 *       record view; callers must use record-view/materializer APIs and cannot
 *       access raw mapped containers through it.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_query_hit_record(n00b_query_hit_t *hit);

/**
 * @brief Return the query error code represented by a retention payload.
 *
 * @param error Structured retention payload extracted from an error result.
 * @return Ok(@ref N00B_QUERY_ERR_RETENTION), or
 *         @ref N00B_QUERY_ERR_ARG for null.
 */
extern n00b_result_t(n00b_query_err_t)
n00b_query_retention_error_code(n00b_query_retention_error_t *error);

/**
 * @brief Return which boundary option failed retention validation.
 *
 * @param error Structured retention payload extracted from an error result.
 * @return Ok(boundary kind), or @ref N00B_QUERY_ERR_ARG for null.
 */
extern n00b_result_t(n00b_query_boundary_kind_t)
n00b_query_retention_error_boundary(n00b_query_retention_error_t *error);

/**
 * @brief Return the requested position that failed validation.
 *
 * @param error Structured retention payload extracted from an error result.
 * @return Ok(position), or @ref N00B_QUERY_ERR_ARG for null.
 */
extern n00b_result_t(n00b_store_pos_t)
n00b_query_retention_error_requested(n00b_query_retention_error_t *error);

/**
 * @brief Return the current oldest retained boundary, when known.
 *
 * @param error Structured retention payload extracted from an error result.
 * @return Ok(some(position)) when the store reported an oldest available
 *         boundary, Ok(none) when the store had no retained sealed boundary,
 *         or @ref N00B_QUERY_ERR_ARG for null.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_retention_error_oldest_available(
    n00b_query_retention_error_t *error);

#ifdef __cplusplus
}
#endif

/**
 * @file rocs/query.h
 * @brief Public query-view declarations for rocs snapshot and live reads.
 *
 * Query views are process-side handles over a committed store boundary.
 * Snapshot cursors expose borrowed hit handles in deterministic durable
 * position order. Live cursors use the same handle type and deliver copied
 * historical matches first, then live matches discovered through the hot-tail
 * extension. The snapshot result cache is an invisible process-side
 * implementation detail; it does not add public cache API or change cursor
 * answers. Ranking and aggregation are snapshot-only. Live query conduit
 * output publishes owned hit deliveries through typed query-hit messages
 * without changing borrowed cursor-hit invalidation.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "conduit/topic.h"
#include "core/alloc.h"
#include "core/string.h"
#include "rocs/filter.h"
#include "rocs/store.h"

typedef struct n00b_query_view_t            n00b_query_view_t;
typedef struct n00b_query_cursor_t          n00b_query_cursor_t;
typedef struct n00b_query_hit_t             n00b_query_hit_t;
typedef struct n00b_query_retention_error_t n00b_query_retention_error_t;

N00B_CONDUIT_INBOX_IMPL(n00b_query_hit_t *);

typedef n00b_conduit_message_t(n00b_query_hit_t *) n00b_query_hit_msg_t;
typedef n00b_conduit_inbox_t(n00b_query_hit_t *)   n00b_query_hit_inbox_t;
typedef n00b_conduit_topic_t(n00b_query_hit_t *)   n00b_query_hit_topic_t;

/** @brief Pop one query-hit output message from an inbox. */
#define n00b_query_hit_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_query_hit_t *, inbox)

/** @brief Check whether a query-hit inbox has queued user messages. */
#define n00b_query_hit_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_query_hit_t *, inbox)

/** @brief Return the queued query-hit user-message count for an inbox. */
#define n00b_query_hit_inbox_msg_count(inbox) \
    n00b_conduit_inbox_msg_count(n00b_query_hit_t *, inbox)

/**
 * @brief Query delivery mode.
 *
 * @ref N00B_QUERY_MODE_SNAPSHOT observes committed state at view creation.
 * @ref N00B_QUERY_MODE_LIVE captures the same historical boundary and then
 * tails committed store state. Live cursor delivery is history first, then
 * live durable-position order; commit-topic messages are wakeup hints only.
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
    N00B_QUERY_ERR_INVALID_OPTION     = -10,
    N00B_QUERY_ERR_NOT_READY          = -11,
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
 *               @ref N00B_QUERY_MODE_LIVE creates a live view through this
 *               same object and never falls back to snapshot mode.
 * @kw resume    Optional borrowed durable resume position. The position is
 *               copied by value into the view. It must still be retained by
 *               @p store; stale, dropped, missing, or out-of-range positions
 *               return a typed retention payload error carrying the current
 *               oldest-available boundary when known.
 * @kw as_of     Optional borrowed durable snapshot boundary. It is valid only
 *               for snapshot mode, is copied by value into the view, and must
 *               still be retained by @p store. Supplying @p as_of with live
 *               mode returns @ref N00B_QUERY_ERR_INVALID_OPTION before any
 *               store pin is acquired. If both @p resume and @p as_of are
 *               valid and @p resume sorts after @p as_of, creation succeeds
 *               with an empty snapshot boundary.
 * @kw out       Optional conduit output. Snapshot output remains unsupported.
 *               Live output creates a view-owned typed query-hit topic on
 *               @p out. Callers attach subscribers through
 *               @ref n00b_query_view_output_topic and
 *               @ref n00b_query_hit_subscribe, then start publishing with
 *               @ref n00b_query_view_output_start so subscribers cannot miss
 *               the historical prefix.
 * @kw limit     API-level cursor hit limit. Zero means unlimited. Positive
 *               values cap emitted hits across historical and live delivery.
 * @kw allocator Allocator for the view, copied boundary records, and any
 *               structured error payload.
 *
 * @return Ok(view) on successful boundary capture, integer query errors for
 *         ordinary validation/state/option failures, or a
 *         @ref n00b_query_retention_error_t pointer payload for retained-away
 *         boundary failures.
 *
 * @post A successful view owns copied catalog metadata for the visible sealed
 *       historical boundary: shard id, generation, schema generation, record
 *       count, seal timestamp, partition key, object path, byte length, and
 *       optional etag. Live views additionally record internal wakeup/tail
 *       state used by live cursors. The view does not retain catalog-entry
 *       pointers, mapped resident handles, planner state, raw mapped
 *       containers, or materialized records. Snapshot views own an invisible
 *       process-side cache. Live views additionally subscribe to commit
 *       wakeups when the store provides a topic, but correctness comes from
 *       later authoritative store/catalog scans. Live views created with
 *       output own a typed process-side topic and an output producer that is
 *       started explicitly after subscribers attach. Open cursors created
 *       from the view are owned by their public cursor handles and are
 *       invalidated by view close.
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
 *       store active pin. Live views also cancel their internal commit
 *       subscription exactly once when one was configured. Later calls do not
 *       release again and cannot underflow the store pin count.
 * @post Close stops the output producer and closes the output topic when
 *       present, wakes any live cursor blocked in
 *       @ref n00b_query_cursor_next, invalidates and closes every open cursor
 *       created from the view, invalidates borrowed cursor hits, releases
 *       cursor-held resident shard pins, and then releases the view's active
 *       store pin. Already queued output messages remain valid until callers
 *       drop them with @ref n00b_query_hit_msg_drop or drain their inbox. A
 *       blocked live `next` observes close as terminal `Ok(none)`. Later
 *       explicit calls on a closed cursor/view still return closed-state
 *       errors. Close does not free the view graph immediately; the
 *       allocator/GC owns storage.
 */
extern n00b_result_t(bool)
n00b_query_view_close(n00b_query_view_t *view);

/**
 * @brief Allocate and initialize a typed query-hit output inbox.
 *
 * @param conduit Conduit instance whose allocator and notification domain own
 *                the inbox.
 * @kw backpressure Inbox backpressure policy. Defaults to drop-newest with a
 *                  bounded queue so slow subscribers cannot grow memory
 *                  without bound.
 * @kw limit        Maximum queued query-hit messages. Zero makes the selected
 *                  policy unbounded; the default is 1024.
 * @kw allocator    Optional inbox allocator. Defaults to the conduit allocator.
 *
 * @return Ok(inbox) on success, or @ref N00B_QUERY_ERR_ARG /
 *         @ref N00B_QUERY_ERR_INTERNAL for invalid input or allocation state.
 */
extern n00b_result_t(n00b_query_hit_inbox_t *)
n00b_query_hit_inbox_new(n00b_conduit_t *conduit) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_DROP_NEWEST;
    uint32_t                    limit        = 1024;
    n00b_allocator_t           *allocator    = nullptr;
};

/**
 * @brief Return the typed output topic owned by a live output view.
 *
 * @param view Query view created with live mode and non-null @c out.
 * @return Ok(topic) while the view is open and has output configured,
 *         @ref N00B_QUERY_ERR_ARG for null, @ref N00B_QUERY_ERR_STATE when
 *         output was not configured, or @ref N00B_QUERY_ERR_CLOSED after
 *         view close.
 *
 * @post The returned topic is process-side only. It is not embedded in
 *       marshalable shard state and carries only @c n00b_query_hit_t *
 *       payloads in typed messages.
 */
extern n00b_result_t(n00b_query_hit_topic_t *)
n00b_query_view_output_topic(n00b_query_view_t *view);

/**
 * @brief Subscribe a typed inbox to a query-hit output topic.
 *
 * @param topic Topic returned by @ref n00b_query_view_output_topic.
 * @param inbox Inbox returned by @ref n00b_query_hit_inbox_new.
 * @kw operations Conduit operation mask. Defaults to all operations.
 * @kw flags      Conduit subscription flags.
 * @kw timeout_ms Optional conduit timeout in milliseconds.
 *
 * @return Ok(subscription handle) on success, or a typed query error.
 */
extern n00b_result_t(n00b_conduit_sub_handle_t)
n00b_query_hit_subscribe(n00b_query_hit_topic_t *topic,
                         n00b_query_hit_inbox_t *inbox) _kargs
{
    uint32_t operations = N00B_CONDUIT_OP_ALL;
    uint32_t flags      = 0;
    uint32_t timeout_ms = 0;
};

/**
 * @brief Cancel a query-hit output subscription.
 *
 * @param topic Topic returned by @ref n00b_query_view_output_topic.
 * @param sub   Subscription handle returned by @ref n00b_query_hit_subscribe.
 *
 * @return Ok(true) when a subscription was requested for cancellation,
 *         Ok(false) for an invalid handle, or a typed query error.
 *
 * @post Cancellation stops future deliveries for the subscription. Messages
 *       already queued in the subscriber inbox remain valid and must still be
 *       dropped with @ref n00b_query_hit_msg_drop or
 *       @ref n00b_query_hit_inbox_drain.
 */
extern n00b_result_t(bool)
n00b_query_hit_unsubscribe(n00b_query_hit_topic_t   *topic,
                           n00b_conduit_sub_handle_t sub);

/**
 * @brief Start a live query output producer after subscribers are attached.
 *
 * @param view Live view created with non-null @c out.
 * @return Ok(true) when the producer starts, Ok(false) when it was already
 *         started, @ref N00B_QUERY_ERR_STATE when output is not configured or
 *         the mode is not live, or @ref N00B_QUERY_ERR_CLOSED after close.
 *
 * @post The producer publishes retained historical matches first and then
 *       live matches in durable-position order. The view's @c limit is a
 *       single ordered-prefix cap for both cursor and output surfaces; it is
 *       not split by subscriber count. Slow subscribers apply their inbox
 *       backpressure policy. Dropped or rejected messages release owned hits
 *       and resident pins through the same finalizer used by explicit drops.
 */
extern n00b_result_t(bool)
n00b_query_view_output_start(n00b_query_view_t *view);

/**
 * @brief Drop one query-hit output message and release its owned hit.
 *
 * @param msg Message popped from a @ref n00b_query_hit_inbox_t.
 * @return Ok(true) on drop, or @ref N00B_QUERY_ERR_ARG for null.
 *
 * @post Dropping invalidates the message payload hit. If the hit pinned a
 *       resident sealed shard, the pin is released exactly once.
 */
extern n00b_result_t(bool)
n00b_query_hit_msg_drop(n00b_query_hit_msg_t *msg);

/**
 * @brief Drain and drop all queued query-hit output messages in an inbox.
 *
 * @param inbox Query-hit inbox returned by @ref n00b_query_hit_inbox_new.
 * @return Ok(number of query-hit messages dropped), or
 *         @ref N00B_QUERY_ERR_ARG for null.
 *
 * @post Each drained message is dropped with
 *       @ref n00b_query_hit_msg_drop. System messages are also discarded.
 */
extern n00b_result_t(uint64_t)
n00b_query_hit_inbox_drain(n00b_query_hit_inbox_t *inbox);

/**
 * @brief Create a deterministic cursor for a query view.
 *
 * @param view Borrowed open query view returned by
 *             @ref n00b_query_view. Null or closed views return typed query
 *             errors.
 * @kw allocator Allocator for the cursor, hit handles, resident handle list,
 *               planner scratch, and mapped record-view handles.
 *
 * @return Ok(cursor) on snapshot or live success, integer query errors for
 *         validation, lowering, planner, store, map, or execution failures,
 *         or a
 *         @ref n00b_query_retention_error_t pointer payload when a copied
 *         snapshot boundary shard is no longer retained and the store reports
 *         an oldest-available boundary.
 *
 * @post Cursor construction validates every copied snapshot boundary entry
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
 * @post Snapshot cursor hits are emitted in increasing durable
 *       @c (generation, shard_id, ordinal) order. Live cursor construction
 *       builds the same historical prefix, then later @ref
 *       n00b_query_cursor_next calls scan committed store state after the
 *       captured cutover. Records committed during cursor construction or
 *       historical delivery are discovered by that live scan with no
 *       history/live duplicate by durable position. @c resume is enforced as
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
 * @brief Advance a cursor by one hit.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_cursor. Null returns
 *               @ref N00B_QUERY_ERR_ARG. Closed cursors and cursors whose view
 *               was closed return @ref N00B_QUERY_ERR_CLOSED.
 * @return Ok(some(hit)) for the next borrowed hit, Ok(none) at snapshot end
 *         or live terminal stop, or a typed query error. For live cursors this
 *         call blocks until a matching hit is available, the cursor/view is
 *         closed, or the configured limit is reached. Live Ok(none) never
 *         means "no hit yet".
 *
 * @post Advancing invalidates the previously returned borrowed hit, including
 *       when advancement reaches end/stop and returns none. The new hit
 *       remains valid until the next advance, cursor close, or view close.
 */
extern n00b_result_t(n00b_option_t(n00b_query_hit_t *))
n00b_query_cursor_next(n00b_query_cursor_t *cursor);

/**
 * @brief Return the last emitted durable cursor position.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_cursor.
 * @return Ok(none) before the first emitted hit, Ok(some(position)) after a
 *         hit has been emitted, including after snapshot end or live cutover
 *         until close, @ref N00B_QUERY_ERR_ARG for null, or
 *         @ref N00B_QUERY_ERR_CLOSED after cursor/view close.
 *
 * @post Returned positions are durable store positions suitable for
 *       @ref n00b_store_pos_encode and later @c resume use with
 *       @ref n00b_query_view while the referenced position remains retained
 *       and generation-compatible. A resume view starts strictly after the
 *       supplied position.
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
 * @post Close is idempotent. The first close wakes any blocked live `next`,
 *       invalidates borrowed hits and record views from the cursor, and
 *       releases every resident shard handle exactly once. A blocked live
 *       `next` observes cursor close as terminal `Ok(none)`. Later close
 *       calls do not release again.
 */
extern n00b_result_t(bool)
n00b_query_cursor_close(n00b_query_cursor_t *cursor);

/**
 * @brief Return the durable position for a query hit.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @return Ok(position) while the hit is valid, @ref N00B_QUERY_ERR_ARG for
 *         null, or @ref N00B_QUERY_ERR_CLOSED after cursor advance, cursor
 *         close, or view close invalidates a borrowed hit, or after
 *         @ref n00b_query_hit_msg_drop / @ref n00b_query_hit_inbox_drain
 *         releases an owned output hit.
 */
extern n00b_result_t(n00b_store_pos_t)
n00b_query_hit_pos(n00b_query_hit_t *hit);

/**
 * @brief Return the score for a query hit.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @return Ok(score) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after cursor invalidation or owned
 *         output-message drop.
 *
 * Cursor and output hits in WP-009 are unranked and always report @c 0.0.
 */
extern n00b_result_t(double)
n00b_query_hit_score(n00b_query_hit_t *hit);

/**
 * @brief Borrow the record-view handle for a query hit.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @return Ok(record) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after cursor invalidation or owned
 *         output-message drop.
 *
 * @post For cursor hits, the returned @ref n00b_store_record_t pointer is
 *       borrowed from the cursor-held resident mapped image and remains valid
 *       only until cursor advance, cursor close, or view close. For output
 *       hits, the record view is owned by the delivery message: sealed hits
 *       pin the resident shard and hot hits carry a materialized JSON copy, so
 *       the returned record remains valid across cursor/view close until the
 *       message is explicitly dropped or drained. In both cases this is an
 *       opaque shard-aware record view; callers must use record-view or
 *       materializer APIs and cannot access raw mapped containers through it.
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

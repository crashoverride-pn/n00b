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
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/variant.h"
#include "conduit/topic.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "rocs/filter.h"
#include "rocs/store.h"

typedef struct n00b_query_view_t            n00b_query_view_t;
typedef struct n00b_query_cursor_t          n00b_query_cursor_t;
typedef struct n00b_query_linear_cursor_t   n00b_query_linear_cursor_t;
// Cooperative-cancellation predicate for n00b_query_cursor (.cancel_cb). Polled
// during the scan; returning true aborts with N00B_QUERY_ERR_CANCELED. A typedef
// (not an inline function-pointer type) so it can be used as an _kargs kwarg.
typedef bool (*n00b_query_cancel_fn)(void *ctx);
typedef struct n00b_query_t                 n00b_query_t;
typedef struct n00b_query_result_t          n00b_query_result_t;
typedef struct n00b_query_hit_t             n00b_query_hit_t;
typedef struct n00b_query_agg_spec_t        n00b_query_agg_spec_t;
typedef struct n00b_query_agg_row_t         n00b_query_agg_row_t;
typedef struct n00b_query_group_key_t       n00b_query_group_key_t;
typedef struct n00b_query_note_t            n00b_query_note_t;
typedef struct n00b_query_boost_t           n00b_query_boost_t;
typedef struct n00b_query_retention_error_t n00b_query_retention_error_t;

/** @brief Distinct query-value payload used for a missing group/aggregate field. */
typedef struct {
    uint8_t reserved;
} n00b_query_missing_t;

/** @brief Distinct query-value payload used for JSON null. */
typedef struct {
    uint8_t reserved;
} n00b_query_null_t;

/**
 * @brief Variant-only scalar value returned by query rows, keys, and notes.
 *
 * The selector in this variant is the only value discriminator. A missing
 * group-by or aggregate field uses @ref n00b_query_missing_t and is therefore
 * distinct from JSON null, every string value including `"__missing__"`, and
 * every other user scalar. Query APIs never expose raw mapped JSON nodes,
 * dictionaries, lists, buffers, or manual public kind/union payloads.
 */
typedef n00b_variant_t(n00b_query_missing_t,
                       n00b_query_null_t,
                       bool,
                       int64_t,
                       uint64_t,
                       double,
                       n00b_string_t *,
                       n00b_buffer_t *) n00b_query_value_t;

/** @brief Ordered group-by field list used by query specs. */
typedef n00b_list_t(n00b_filter_field_t *) n00b_query_group_by_list_t;

/** @brief Ordered aggregate-spec list used by query specs. */
typedef n00b_list_t(n00b_query_agg_spec_t *) n00b_query_agg_spec_list_t;

/** @brief Ordered ranking boost list used by query specs. */
typedef n00b_list_t(n00b_query_boost_t *) n00b_query_boost_list_t;

/** @brief Result-owned hit-handle list returned by query results. */
typedef n00b_list_t(n00b_query_hit_t *) n00b_query_hit_list_t;

/** @brief Result-owned aggregate-row handle list returned by query results. */
typedef n00b_list_t(n00b_query_agg_row_t *) n00b_query_agg_row_list_t;

/** @brief Result-owned group-key entry handle list stored on aggregate rows. */
typedef n00b_list_t(n00b_query_group_key_t *) n00b_query_group_key_list_t;

/** @brief Ordered aggregate scalar values stored on aggregate rows. */
typedef n00b_list_t(n00b_query_value_t) n00b_query_value_list_t;

/** @brief Result-owned structured note handle list returned by query results. */
typedef n00b_list_t(n00b_query_note_t *) n00b_query_note_list_t;

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
 * @brief Snapshot aggregation operator.
 *
 * Aggregate specs execute only through finite snapshot @ref n00b_query_run
 * results. They are not live-updating and do not expose raw record payloads.
 */
typedef enum : int32_t {
    N00B_QUERY_AGG_COUNT = 1,
    N00B_QUERY_AGG_SUM   = 2,
    N00B_QUERY_AGG_MIN   = 3,
    N00B_QUERY_AGG_MAX   = 4,
    N00B_QUERY_AGG_AVG   = 5,
} n00b_query_agg_op_t;

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
    N00B_QUERY_ERR_RANGE              = -12,
    // The caller's cancel callback (n00b_query_cursor .cancel_cb) asked the scan
    // to stop — e.g. the client that requested a streaming query disconnected.
    // An expected, non-fatal early termination, not a failure.
    N00B_QUERY_ERR_CANCELED           = -13,
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
 * @param filter Borrowed public filter predicate, or null. A non-null filter
 *               is lowered through the internal planner boundary at snapshot
 *               cursor construction. Null requests an unfiltered scan: it is
 *               accepted only for @ref N00B_QUERY_MODE_SNAPSHOT (servable solely
 *               by @ref n00b_query_linear_cursor, which ignores the view filter)
 *               and returns @ref N00B_QUERY_ERR_ARG for live-mode views, since
 *               the indexed cursor and live delivery both intersect the filter.
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
 * @post A successful view acquires one store active pin. The pin prevents
 *       store close while the view is open; it does not retain sealed
 *       hot-shard arenas after they have been durably written. Close the view
 *       with @ref n00b_query_view_close to release the pin.
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
	bool               min_partition_bucket_enabled = false;
	uint64_t           min_partition_bucket = 0;
	// Exact-granularity time floor: sealed boundaries whose seal_ts predates
	// this are skipped at capture (a record is sealed at-or-after it is
	// observed). Complements the coarse partition-bucket gate. 0 = disabled.
	uint64_t           min_seal_ts_ns = 0;
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
    // Optional cooperative-cancellation hook. When set, the snapshot scan polls
    // cancel_cb(cancel_ctx) periodically while building a boundary's hits; if it
    // returns true, n00b_query_cursor_next aborts with N00B_QUERY_ERR_CANCELED.
    // Use it to stop an expensive query whose consumer has gone away (e.g. a
    // disconnected streaming HTTP client). cancel_ctx is borrowed.
    n00b_query_cancel_fn cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
    // Newest-first iteration: walk the snapshot from the highest (most recent)
    // durable (generation, shard_id, ordinal) down to the oldest, so a limited
    // query returns the most recent matches. Default false (ascending durable
    // order, required for resume-token pagination).
    bool                 reverse    = false;
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
 * @brief Enable streaming mode on a snapshot cursor.
 *
 * In streaming mode the cursor releases the prior boundary's resident shard(s)
 * and drops already-delivered hits before loading the next boundary, bounding
 * the resident working set (and thus RSS) regardless of the query limit. ONLY
 * safe when the consumer copies each hit's data out (e.g. via
 * @ref n00b_query_hit_json_copy) BEFORE calling @ref n00b_query_cursor_next
 * again — delivered hits and their borrowed record views are invalidated on the
 * next advance. Must not be used by callers that retain hits/records across
 * advances. Off by default.
 */
extern void
n00b_query_cursor_set_streaming(n00b_query_cursor_t *cursor, bool on);

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
 * @brief Create a bidirectional linear record cursor over a snapshot view.
 *
 * A linear cursor is a low-cost alternative to @ref n00b_query_cursor for
 * draining a store in durable-position order. It walks the view's already
 * captured sealed-shard boundary in seal order (ascending
 * @c (generation, shard_id) — the same order shards are sealed) and steps a
 * record ordinal within each sealed shard. Each step
 * (@ref n00b_query_linear_cursor_next / @ref n00b_query_linear_cursor_prev) is
 * O(1): it does not build a planner ordset, does not take a snapshot boundary
 * ordset scan, and does not run a per-step rwlock-protected catalog scan. It
 * reads the record straight off the read-only sealed-shard mmap image through
 * the rocs mapped-view API. This is the API egress drains want: index to any
 * record, then step forward or backward at very little cost.
 *
 * The cursor is unfiltered: it visits every record in the snapshot boundary,
 * unlike @ref n00b_query_cursor which intersects the view filter. The view's
 * @c resume and @c as_of window still bound the visited range, and the view
 * filter is ignored (a linear scan is the natural shape for "drain everything
 * after this watermark"). The captured boundary is hot-inclusive: for a
 * snapshot view without @c as_of it includes the frozen hot shard as the newest
 * boundary, so the linear cursor reads the current hot records too (via the
 * hot-scan path, since the hot shard has no sealed mmap image). With
 * @c .reverse the walk is newest-first, mirroring @ref n00b_query_cursor.
 *
 * @param view Borrowed open snapshot query view returned by
 *             @ref n00b_query_view. Null or closed views return typed query
 *             errors. Live-mode views return
 *             @ref N00B_QUERY_ERR_UNSUPPORTED_MODE.
 * @kw allocator Allocator for the cursor, hit handles, resident handle, and
 *               mapped record-view handles.
 * @kw reverse   Newest-first walk when true: next() drains the captured
 *               boundary from the highest (newest) durable position down, and
 *               prev() is its inverse. Default false (ascending durable order,
 *               oldest-first). Mirrors @ref n00b_query_cursor's .reverse.
 *
 * @return Ok(cursor) on success, integer query errors for validation/state
 *         failures, or a @ref n00b_query_retention_error_t pointer payload when
 *         a copied snapshot boundary shard is no longer retained.
 *
 * @post The cursor begins positioned before the first record; the first
 *       @ref n00b_query_linear_cursor_next yields the oldest in-window record.
 *       The cursor holds at most one resident sealed-shard pin at a time (the
 *       shard it is currently positioned in). That pin keeps the sealed-shard
 *       mmap image mapped so trim/retention/unload cannot reclaim it mid-walk;
 *       it is released and the next shard's pin acquired on a boundary crossing,
 *       and the final pin is released by @ref n00b_query_linear_cursor_close or
 *       view close. The cursor is owned by its handle and is invalidated by view
 *       close.
 */
extern n00b_result_t(n00b_query_linear_cursor_t *)
n00b_query_linear_cursor(n00b_query_view_t *view) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    // Newest-first walk when set: next() drains the captured boundary from the
    // highest (newest) durable position down. Mirrors n00b_query_cursor's
    // .reverse. Default false = ascending durable order (oldest-first).
    bool              reverse   = false;
};

/**
 * @brief Step a linear cursor forward by one record.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_linear_cursor. Null
 *               returns @ref N00B_QUERY_ERR_ARG. Closed cursors and cursors
 *               whose view was closed return @ref N00B_QUERY_ERR_CLOSED.
 * @return Ok(some(hit)) for the next borrowed hit in ascending durable
 *         @c (generation, shard_id, ordinal) order -- or, when the cursor was
 *         created with @c .reverse, in descending order (newest-first);
 *         Ok(none) at the end of the walk, or a typed query error.
 *
 * @post Advancing invalidates the previously returned borrowed hit, including
 *       when advancement reaches the end and returns none. The new hit remains
 *       valid until the next step, cursor close, or view close. The returned
 *       @ref n00b_query_hit_t serializes identically to a snapshot cursor hit
 *       (@ref n00b_query_hit_record, @ref n00b_query_hit_json_copy,
 *       @ref n00b_query_hit_pos). Stepping forward off the end and then back is
 *       defined: a @ref n00b_query_linear_cursor_prev after an end-of-range
 *       none re-yields the last record.
 */
extern n00b_result_t(n00b_option_t(n00b_query_hit_t *))
n00b_query_linear_cursor_next(n00b_query_linear_cursor_t *cursor);

/**
 * @brief Step a linear cursor backward by one record.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_linear_cursor. Null
 *               returns @ref N00B_QUERY_ERR_ARG. Closed cursors and cursors
 *               whose view was closed return @ref N00B_QUERY_ERR_CLOSED.
 * @return Ok(some(hit)) for the previous borrowed hit in descending durable
 *         order -- or, when the cursor was created with @c .reverse, in
 *         ascending order; Ok(none) at the beginning of the walk, or a typed
 *         query error.
 *
 * @post Advancing invalidates the previously returned borrowed hit. Stepping
 *       back off the start and then forward re-yields the first record.
 */
extern n00b_result_t(n00b_option_t(n00b_query_hit_t *))
n00b_query_linear_cursor_prev(n00b_query_linear_cursor_t *cursor);

/**
 * @brief Index a linear cursor to an arbitrary durable position cheaply.
 *
 * Positions the cursor so that the next @ref n00b_query_linear_cursor_next
 * yields the record strictly after @p pos and the next
 * @ref n00b_query_linear_cursor_prev yields the record at or before @p pos. This
 * matches the @c resume watermark semantics of @ref n00b_query_view: a seek
 * resumes strictly after the supplied position. The seek is O(log shards) over
 * the captured boundary list plus O(1) ordinal arithmetic; it never rescans
 * records or builds an ordset.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_linear_cursor.
 * @param pos    Durable position to seek to. It need not name an existing
 *               record; the cursor positions to the gap implied by ascending
 *               durable order. Positions outside the view window clamp to the
 *               window edge.
 * @return Ok(true) on success, @ref N00B_QUERY_ERR_ARG for null, or
 *         @ref N00B_QUERY_ERR_CLOSED after cursor/view close.
 *
 * @post Seeking releases any current resident pin and invalidates the current
 *       borrowed hit. The shard pin for the sought-to position is acquired
 *       lazily on the next step, not by the seek itself.
 */
extern n00b_result_t(bool)
n00b_query_linear_cursor_seek(n00b_query_linear_cursor_t *cursor,
                              n00b_store_pos_t            pos);

/**
 * @brief Return the durable position last emitted by a linear cursor.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_linear_cursor.
 * @return Ok(none) before the first emitted hit, Ok(some(position)) after a hit
 *         has been emitted, @ref N00B_QUERY_ERR_ARG for null, or
 *         @ref N00B_QUERY_ERR_CLOSED after cursor/view close.
 *
 * @post The returned position round-trips through @ref n00b_store_pos_encode /
 *       @ref n00b_store_pos_decode and is suitable as a @c resume position for a
 *       later @ref n00b_query_view or @ref n00b_query_linear_cursor_seek; a
 *       resume/seek from it starts strictly after the supplied position.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_linear_cursor_position(n00b_query_linear_cursor_t *cursor);

/**
 * @brief Close a linear cursor and release its resident shard pin.
 *
 * @param cursor Owned cursor returned by @ref n00b_query_linear_cursor. Null
 *               returns @ref N00B_QUERY_ERR_ARG.
 * @return Ok(true) on the first close, Ok(false) on later closes, or a typed
 *         query error if the underlying resident release reports impossible
 *         state.
 *
 * @post Close is idempotent. The first close invalidates the borrowed hit and
 *       record view from the cursor and releases the held resident shard pin
 *       exactly once.
 */
extern n00b_result_t(bool)
n00b_query_linear_cursor_close(n00b_query_linear_cursor_t *cursor);

/**
 * @brief Return the durable position for a query hit.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next,
 *            result-owned hit returned through @ref n00b_query_records, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @return Ok(position) while the hit is valid, @ref N00B_QUERY_ERR_ARG for
 *         null, or @ref N00B_QUERY_ERR_CLOSED after cursor advance, cursor
 *         close, or view close invalidates a borrowed hit, after
 *         @ref n00b_query_result_close invalidates a result-owned hit, or
 *         after @ref n00b_query_hit_msg_drop /
 *         @ref n00b_query_hit_inbox_drain releases an owned output hit.
 */
extern n00b_result_t(n00b_store_pos_t)
n00b_query_hit_pos(n00b_query_hit_t *hit);

/**
 * @brief Return the score for a query hit.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next,
 *            result-owned hit returned through @ref n00b_query_records, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @return Ok(score) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after cursor invalidation,
 *         result close, or owned output-message drop.
 *
 * Cursor and output hits are unranked and always report @c 0.0. Unranked
 * finite @ref n00b_query_run result hits also report @c 0.0. Ranked finite
 * result hits report the sum of each matched scoreable whole-token contains
 * term's
 * @c boost * (log((snapshot_record_count + 1) / (document_frequency + 1)) + 1).
 * Each distinct field/term contributes at most once per hit.
 */
extern n00b_result_t(double)
n00b_query_hit_score(n00b_query_hit_t *hit);

/**
 * @brief Borrow the record-view handle for a query hit.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next,
 *            result-owned hit returned through @ref n00b_query_records, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @return Ok(record) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after cursor invalidation,
 *         result close, or owned output-message drop.
 *
 * @post For cursor hits, the returned @ref n00b_store_record_t pointer is
 *       borrowed from cursor-owned delivery state and remains valid only until
 *       cursor advance, cursor close, or view close. Sealed cursor hits borrow
 *       from the cursor-held resident mapped image; current-hot cursor hits
 *       carry a materialized JSON copy so they do not pin sealed hot-shard
 *       arenas. For
 *       result-owned hits, the record view is owned by the finite result:
 *       sealed hits pin the resident shard and hot hits carry a materialized
 *       JSON copy, so the returned record remains valid across the temporary
 *       cursor/view used by @ref n00b_query_run and until
 *       @ref n00b_query_result_close. For output hits, the record view is
 *       owned by the delivery message and remains valid across cursor/view
 *       close until the message is explicitly dropped or drained. In all
 *       cases this is an opaque shard-aware record view; callers must use
 *       record-view or materializer APIs and cannot access raw mapped
 *       containers through it.
 */
extern n00b_result_t(n00b_store_record_t *)
n00b_query_hit_record(n00b_query_hit_t *hit);

/**
 * @brief Materialize a copied JSON graph for a query hit's record.
 *
 * @param hit Borrowed cursor hit returned by @ref n00b_query_cursor_next,
 *            result-owned hit returned through @ref n00b_query_records, or
 *            owned output hit carried by a @ref n00b_query_hit_msg_t.
 * @kw allocator Allocator for the returned JSON graph.
 * @return Ok(copied JSON) while the hit is valid, @ref N00B_QUERY_ERR_ARG for
 *         null, or @ref N00B_QUERY_ERR_CLOSED after cursor invalidation,
 *         result close, or owned output-message drop.
 *
 * @post The returned JSON graph is an owned recursive copy and never exposes
 *       raw mapped storage, shard internals, or the cursor's borrowed record
 *       view. It remains valid after cursor advance, cursor close, and view
 *       close according to the allocator lifetime.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_query_hit_json_copy(n00b_query_hit_t *hit) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Serialize a cursor hit's record as a compact JSON string.
 *
 * @param hit Borrowed cursor hit (see @ref n00b_query_hit_json_copy).
 * @kw allocator Allocator for the returned string.
 * @return Ok(string) while the hit is valid, @ref N00B_QUERY_ERR_ARG for null,
 *         or @ref N00B_QUERY_ERR_CLOSED after invalidation.
 *
 * For sealed mapped records this returns the stored compact JSON bytes verbatim
 * (no parse, no node graph, no re-encode). Prefer this over
 * @ref n00b_query_hit_json_copy + @ref n00b_json_encode when the consumer only
 * needs the serialized record (e.g. an NDJSON egress drain): it removes the
 * per-record parse/re-encode round trip and its GC-heap allocation.
 */
extern n00b_result_t(n00b_string_t *)
n00b_query_hit_json_string(n00b_query_hit_t *hit) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an aggregate spec for a snapshot aggregate query.
 *
 * @param op    Aggregate operation. Values outside @ref n00b_query_agg_op_t
 *              return @ref N00B_QUERY_ERR_INVALID_OPTION.
 * @param field Borrowed immutable filter-field handle. It may be null only for
 *              @ref N00B_QUERY_AGG_COUNT; other operations require a field.
 * @kw name     Optional borrowed result-column name retained by pointer.
 * @kw allocator Allocator for the aggregate spec object.
 *
 * @return Ok(spec) on success, or a typed query option/argument error.
 *
 * @post The returned spec is process-side and immutable by convention. It does
 *       not expose raw JSON/mapped data and performs no aggregation by itself.
 *       Passing the spec to @ref n00b_query_new inside @c aggregates stores the
 *       spec handle in a query-owned copy of the aggregate list.
 */
extern n00b_result_t(n00b_query_agg_spec_t *)
n00b_query_agg(n00b_query_agg_op_t  op,
               n00b_filter_field_t *field) _kargs
{
    n00b_string_t    *name      = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a ranking field boost spec.
 *
 * @param field Borrowed immutable filter-field handle. Null returns
 *              @ref N00B_QUERY_ERR_ARG.
 * @param boost Positive finite multiplier. Zero, negative, NaN, and infinity
 *              return @ref N00B_QUERY_ERR_INVALID_OPTION.
 * @kw allocator Allocator for the boost spec object.
 *
 * @return Ok(boost) on success, or a typed query option/argument error.
 *
 * @post Boost specs are copied by handle when passed to
 *       @ref n00b_query_new. In finite snapshot record results, a matching
 *       boost multiplies that field's score contribution. Boosts do not add
 *       live cursor scoring and remain unsupported with grouped/aggregate
 *       output in this phase.
 */
extern n00b_result_t(n00b_query_boost_t *)
n00b_query_boost(n00b_filter_field_t *field,
                 double               boost) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an immutable snapshot query spec.
 *
 * @param filter Borrowed public filter predicate. Null returns
 *               @ref N00B_QUERY_ERR_ARG.
 * @kw group_by   Optional borrowed list of group-by field handles. The list
 *                container is copied into query-owned storage; later caller
 *                mutations to the input list do not affect the query.
 * @kw aggregates Optional borrowed list of aggregate spec handles. The list
 *                container is copied into query-owned storage.
 * @kw ranked     Whether finite snapshot record results should be scored and
 *                sorted by relevance.
 * @kw boosts     Optional borrowed list of boost spec handles. The list
 *                container is copied into query-owned storage.
 * @kw as_of      Optional borrowed durable snapshot boundary copied by value
 *                into the query spec. Query execution passes it to snapshot
 *                view creation.
 * @kw limit      API-level result limit. Zero means unlimited. The default is
 *                the signed-off ranked-result design default.
 * @kw allocator  Allocator for the query spec and copied list containers.
 *
 * @return Ok(query) on success, or a typed query validation error.
 *
 * @post The query spec is store-independent and never enters live mode. It
 *       owns copied list containers but borrows the immutable filter, field,
 *       aggregate, boost, and name handles stored in those lists. Grouping,
 *       aggregation, and relevance-ranked record results execute in finite
 *       snapshot results. @c limit is applied after the documented result
 *       ordering; ranked limited results may use bounded top-N internals, but
 *       expose the same answers as full scoring and truncation.
 */
extern n00b_result_t(n00b_query_t *)
n00b_query_new(n00b_filter_t *filter) _kargs
{
    n00b_query_group_by_list_t  *group_by   = nullptr;
    n00b_query_agg_spec_list_t  *aggregates = nullptr;
    bool                         ranked     = false;
    n00b_query_boost_list_t     *boosts     = nullptr;
    n00b_store_pos_t            *as_of      = nullptr;
    uint64_t                     limit      = 100;
    n00b_allocator_t            *allocator  = nullptr;
};

/**
 * @brief Execute a finite snapshot query spec.
 *
 * @param store Borrowed open store. Null returns @ref N00B_QUERY_ERR_ARG.
 * @param query Query spec returned by @ref n00b_query_new. Null returns
 *              @ref N00B_QUERY_ERR_ARG.
 * @kw allocator Allocator for the result, result-owned hit handles, copied
 *               result-list containers, notes, rows, and resident pins.
 *
 * @return Ok(result) for a successful finite snapshot, including an empty
 *         result; integer typed query errors for validation/state/execution
 *         failures; or the existing structured retention payload when the
 *         copied snapshot boundary is no longer retained.
 *
 * @post This API is snapshot-only. It creates an internal snapshot view,
 *       drains it to a finite result, and closes the temporary cursor/view
 *       before returning. It never requests @ref N00B_QUERY_MODE_LIVE, never
 *       tails commits, and never starts live conduit output.
 * @post Plain ungrouped/unaggregated queries return result-owned hits that pin
 *       any required resident mapped shard until @ref n00b_query_result_close.
 *       Unranked record hits are returned in durable-position order.
 *       Grouped/aggregate queries return result-owned rows and structured
 *       notes; row/key/note values are copied scalar variants and do not expose
 *       raw mapped JSON/list/dict/buffer handles.
 * @post Aggregate rows are sorted by typed group-key tuple order. Missing
 *       group-by fields use @ref n00b_query_missing_t, JSON null uses
 *       @ref n00b_query_null_t, and both are distinct from every string value.
 *       Row aggregate values are ordered like the query's @c aggregates list.
 *       @c COUNT returns @c uint64_t, @c AVG returns @c double, @c SUM returns
 *       @c double when any numeric operand is floating-point and otherwise
 *       @c int64_t or @ref N00B_QUERY_ERR_RANGE on signed overflow. @c MIN and
 *       @c MAX compare numeric operands numerically, preserve the selected
 *       operand's variant type, and break numeric ties by durable position.
 *       Missing, null, boolean, string, and composite operands for numeric
 *       aggregates are skipped and recorded as structured notes. @c limit is
 *       applied after row ordering.
 * @post Queries with @c ranked == true or non-empty @c boosts and no grouped
 *       or aggregate output score result-owned hits using scoreable positive
 *       whole-token @c contains leaves. Scoreable terms use mapped
 *       document-frequency stats and retained snapshot record counts; term
 *       frequency is not stored or counted, and duplicate occurrences in one
 *       record do not increase score. Ranked record results sort by descending
 *       score with durable-position tie-breaks, then apply @c limit. Limited
 *       ranked runs are answer-equivalent to unbounded ranked execution on the
 *       same snapshot followed by truncation. Field boosts default to @c 1.0.
 *       Non-scoreable predicates still filter but do not fabricate score.
 *       Grouped/aggregate results combined with ranking or boosts return
 *       @ref N00B_QUERY_ERR_NOT_READY in this phase.
 */
extern n00b_result_t(n00b_query_result_t *)
n00b_query_run(n00b_store_t *store,
               n00b_query_t *query) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the finite item count in a query result.
 *
 * @param result Result returned by @ref n00b_query_run.
 * @return The result-owned row count for grouped/aggregate results, otherwise
 *         the result-owned record-hit count. Null or closed results return
 *         zero.
 */
extern uint64_t
n00b_query_count(n00b_query_result_t *result);

/**
 * @brief Copy the result-owned record-hit handles into a caller list.
 *
 * @param result Result returned by @ref n00b_query_run.
 * @kw allocator Allocator for the returned list container.
 *
 * @return Ok(list) containing result-owned @ref n00b_query_hit_t handles, or a
 *         typed query error for null/closed results.
 *
 * @post The returned list container is independent and may be mutated by the
 *       caller. The hit handles in it are still owned by @p result and remain
 *       valid only until @ref n00b_query_result_close.
 */
extern n00b_result_t(n00b_query_hit_list_t *)
n00b_query_records(n00b_query_result_t *result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Copy the result-owned aggregate rows into a caller list.
 *
 * @param result Result returned by @ref n00b_query_run.
 * @kw allocator Allocator for the returned list container.
 *
 * @return Ok(list) containing result-owned aggregate-row handles, or a typed
 *         query error for null/closed results. Plain record queries return an
 *         empty list.
 *
 * @post The returned list container is independent and may be mutated by the
 *       caller. The row handles in it are still owned by @p result and remain
 *       valid only until @ref n00b_query_result_close.
 */
extern n00b_result_t(n00b_query_agg_row_list_t *)
n00b_query_rows(n00b_query_result_t *result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Copy result-owned structured notes into a caller list.
 *
 * @param result Result returned by @ref n00b_query_run.
 * @kw allocator Allocator for the returned list container.
 *
 * @return Ok(list) containing result-owned structured notes, or a typed query
 *         error for null/closed results.
 *
 * @post Notes are structured opaque values, not stdout/stderr diagnostics.
 *       Returned note handles are owned by @p result and are invalidated by
 *       @ref n00b_query_result_close.
 */
extern n00b_result_t(n00b_query_note_list_t *)
n00b_query_result_notes(n00b_query_result_t *result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the number of group-key entries on an aggregate row.
 *
 * @param row Result-owned row handle returned through @ref n00b_query_rows.
 * @return Ok(count), @ref N00B_QUERY_ERR_ARG for null, or
 *         @ref N00B_QUERY_ERR_CLOSED after result close invalidates the row.
 */
extern n00b_result_t(uint64_t)
n00b_query_row_group_key_count(n00b_query_agg_row_t *row);

/**
 * @brief Borrow one group-key entry from an aggregate row.
 *
 * @param row   Result-owned row handle.
 * @param index Zero-based group-key ordinal matching the query spec
 *              @c group_by order.
 * @return Ok(some(key)) when present, Ok(none) out of range, or a typed
 *         argument/closed error.
 *
 * @post The key handle is owned by the row's result and remains valid only
 *       until @ref n00b_query_result_close.
 */
extern n00b_result_t(n00b_option_t(n00b_query_group_key_t *))
n00b_query_row_group_key_at(n00b_query_agg_row_t *row, uint64_t index);

/**
 * @brief Return the number of aggregate scalar values on a row.
 *
 * Values are ordered exactly as the query spec's @c aggregates list.
 */
extern n00b_result_t(uint64_t)
n00b_query_row_value_count(n00b_query_agg_row_t *row);

/**
 * @brief Return one aggregate scalar value by aggregate-list ordinal.
 *
 * @return Ok(some(value)) when present, Ok(none) out of range, or a typed
 *         argument/closed error. Empty numeric aggregates with no numeric
 *         operands return @ref n00b_query_missing_t values.
 */
extern n00b_result_t(n00b_option_t(n00b_query_value_t))
n00b_query_row_value_at(n00b_query_agg_row_t *row, uint64_t index);

/**
 * @brief Return the group-by field associated with a group-key entry.
 */
extern n00b_result_t(n00b_filter_field_t *)
n00b_query_group_key_field(n00b_query_group_key_t *key);

/**
 * @brief Return the copied scalar value associated with a group-key entry.
 *
 * Missing fields return a set @ref n00b_query_missing_t variant; JSON null
 * returns a set @ref n00b_query_null_t variant.
 */
extern n00b_result_t(n00b_query_value_t)
n00b_query_group_key_value(n00b_query_group_key_t *key);

/**
 * @brief Return the durable record position associated with a result note.
 */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_note_pos(n00b_query_note_t *note);

/**
 * @brief Return the aggregate spec associated with a result note, when any.
 */
extern n00b_result_t(n00b_option_t(n00b_query_agg_spec_t *))
n00b_query_note_aggregate(n00b_query_note_t *note);

/**
 * @brief Return the field associated with a result note, when any.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_query_note_field(n00b_query_note_t *note);

/**
 * @brief Return the copied scalar value associated with a result note.
 */
extern n00b_result_t(n00b_option_t(n00b_query_value_t))
n00b_query_note_value(n00b_query_note_t *note);

/**
 * @brief Return the structured note message.
 *
 * The returned string is result-owned and valid only until result close.
 */
extern n00b_result_t(n00b_string_t *)
n00b_query_note_message(n00b_query_note_t *note);

/**
 * @brief Close a finite query result and release result-owned resources.
 *
 * @param result Result returned by @ref n00b_query_run. Null returns
 *               @ref N00B_QUERY_ERR_ARG.
 * @return Ok(true) on the first close and Ok(false) on later closes, or a
 *         typed query error if resident release reports impossible state.
 *
 * @post Close is idempotent. The first close invalidates result-owned hits,
 *       rows, and notes, and releases every resident shard pin held by owned
 *       hits exactly once. Lists returned earlier by @ref n00b_query_records,
 *       @ref n00b_query_rows, or @ref n00b_query_result_notes keep their list
 *       containers, but the result-owned handles inside them are no longer
 *       valid after close.
 */
extern n00b_result_t(bool)
n00b_query_result_close(n00b_query_result_t *result);

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

/*
 * Running a plan against shards.
 *
 * Planning is separate and lives in plan.h: n00b_plan_build turns a predicate
 * tree into a plan tree without touching a shard. Everything here takes that
 * plan and produces ordinals, and every entry point takes a cancel callback
 * because every one of them can read an unbounded number of records.
 *
 * Who calls what:
 *
 *   query.c            cursors, ranking, pagination
 *     |
 *     |  filter -> predicate            filter.c
 *     |  n00b_plan_build(...)           plan.h    (no shard touched)
 *     |
 *     +-- hot tail, via store.c
 *     |     n00b_plan_exec_hot(plan, shard)
 *     |
 *     '-- sealed shards
 *           n00b_plan_store_sealed(store, predicate, indexes)
 *             |  builds one plan, then per catalog entry:
 *             |    n00b_plan_partition_filter   plan.h, skips shards by route
 *             '    n00b_plan_exec_mapped(plan, root)
 *
 * One plan serves every shard, because a plan carries no shard state. That is
 * what lets the sealed fan-out build once and execute many times.
 *
 * Executing a node:
 *
 *   INDEX_SCAN    probe the index, turn postings into an ordset. If the index
 *                 is unusable, fall back the way the node's recovery says.
 *   RECORD_SCAN   materialize each candidate, parse it, test the predicate.
 *   INTERSECT     resolve index children first, then run record scans against
 *                 the narrowed set. Stops early once the set is empty.
 *   UNION         combine children, stopping once the universe is reached.
 *   COMPLEMENT    resolve the child, then invert within its universe.
 *
 * n00b_plan_record_scan_* is the record-reading primitive the interpreter is
 * built on, exposed because tests and callers sometimes want it directly. A
 * null candidate set means the whole shard.
 */
#pragma once

#include "internal/rocs/plan.h"

#ifdef __cplusplus
extern "C" {
#endif

extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_record_scan_hot(n00b_store_shard_t     *shard,
                     n00b_plan_ordset_t    *candidates,
                     n00b_plan_predicate_t *residual) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Verify candidate ordinals against a residual over a sealed mapped shard.
 *
 * @param shard Sealed mapped shard view.
 * @param candidates Per-shard candidate ordinal set.
 * @param residual Residual predicate, or @c nullptr when candidates
 *                 are already exact.
 * @kw allocator Allocator for materialized record JSON and the returned set
 *               when verification is required.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(set) with verified ordinals, @c N00B_PLAN_ERR_ARG for invalid
 *         inputs, @c N00B_PLAN_ERR_STATE for unreadable mapped state, or
 *         @c N00B_PLAN_ERR_UNIVERSE if @p candidates does not match the mapped
 *         shard's record universe.
 *
 * Sealed records are resolved by ordinal through internal rocs map helpers.
 * Verification never unmarshals the sealed shard, never passes mapped
 * container internals to ordinary hot JSON/list/dict APIs, and never exposes
 * raw mapped JSON pointers.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_record_scan_mapped(n00b_store_map_shard_t *shard,
                        n00b_plan_ordset_t     *candidates,
                        n00b_plan_predicate_t  *residual) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

// Execute a plan against a shard. record_limit freezes a live scan at the
// store's published hot boundary. UINT64_MAX is the quiescent-shard fallback.
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_hot(n00b_plan_node_t   *plan,
                   n00b_store_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator    = nullptr;
    n00b_plan_cancel_fn  cancel_cb    = nullptr;
    void                *cancel_ctx   = nullptr;
    uint64_t             record_limit = UINT64_MAX;
};

extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_mapped(n00b_plan_node_t       *plan,
                      n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
    // Seal-time schema watermark (N00B_STORE_SCHEMA_DECLARED_SINCE_NS). A shard
    // sealed at or above it is trusted to have declared every currently-declared
    // indexed field, so a missing column for one answers exact-empty instead of
    // scanning. Zero -- the default -- disables the trust, so a caller that does
    // not pass the store's value gets today's scan and never a false negative.
    uint64_t             schema_declared_since_ns = 0;
};

// The sealed-store fan-out and its per-shard results. Planning happens once
// via n00b_plan_build; everything here runs it against shards.

/**
 * @brief Plan catalog-visible sealed shards for WP-008 snapshot fan-out.
 *
 * @param store Open store whose catalog-visible sealed shards are planned.
 * @param predicate Internal predicate tree.
 * @param indexes Process-side descriptor list. @c nullptr is treated
 *                as an empty list.
 * @kw allocator Allocator for the ordered result list, result objects, copied
 *               route-key strings, dispatch scratch, mapped materializations,
 *               and verified ordinal sets.
 * @kw cancel_cb Optional cooperative-cancellation predicate polled every 1024
 *               candidates during residual verification; returning true aborts
 *               with @c N00B_PLAN_ERR_CANCELED. Borrowed; may be nullptr.
 * @kw cancel_ctx Opaque context passed to @p cancel_cb. Borrowed.
 * @return Ok(result list) on success or a typed planner/store-derived error.
 *
 * The planner enumerates only the store catalog visibility boundary: retained
 * sealed entries currently present in the catalog. Dropped or stale shards are
 * absent because retention removes them from that boundary. Partition pruning
 * is conservative; false positives may remain, but unsupported, unsafe OR, and
 * NOT cases keep shards instead of risking false negatives. Resident maps are
 * acquired only after a shard survives pruning and are released before this
 * function returns on every success and error path.
 *
 * Result objects are internal handoff state for WP-008. They expose durable
 * identity/metadata and the verified per-shard ordinal set only; they never
 * expose resident handles, mapped shard handles, record-view handles, raw
 * mapped JSON pointers, public cursor types, or public query-hit types.
 */
extern n00b_result_t(n00b_plan_shard_result_list_t *)
n00b_plan_store_sealed(n00b_store_t          *store,
                       n00b_plan_predicate_t *predicate,
                       n00b_plan_index_list_t *indexes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan one catalog-visible sealed shard.
 *
 * This is the per-shard form used by streaming/lazy query cursors. It performs
 * the same mapped-shard validation, dispatch, residual verification, and
 * resident release as @ref n00b_plan_store_sealed, but does not walk or prune
 * the whole catalog.
 */
extern n00b_result_t(n00b_plan_shard_result_t *)
n00b_plan_catalog_entry_sealed(n00b_store_t               *store,
                               n00b_store_catalog_entry_t *entry,
                               n00b_plan_node_t           *plan) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

/**
 * @brief Return the number of per-shard results in an ordered result list.
 *
 * @param results Result list returned by @ref n00b_plan_store_sealed.
 * @return Ok(count), or @c N00B_PLAN_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_count(n00b_plan_shard_result_list_t *results);

/**
 * @brief Borrow one per-shard result by deterministic result-list ordinal.
 *
 * @param results Result list returned by @ref n00b_plan_store_sealed.
 * @param index Zero-based result ordinal.
 * @return Ok(some(result)) when present, Ok(none) when out of range, or
 *         @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_plan_shard_result_t *))
n00b_plan_shard_result_at(n00b_plan_shard_result_list_t *results,
                          uint64_t                       index);

/**
 * @brief Return the durable shard id copied from catalog metadata.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(shard id), or @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_shard_id(n00b_plan_shard_result_t *result);

/**
 * @brief Return the catalog generation copied for stale-result detection.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(store/catalog generation), or @c N00B_PLAN_ERR_ARG for null
 *         input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_generation(n00b_plan_shard_result_t *result);

/**
 * @brief Return the schema generation copied from catalog metadata.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(schema generation), or @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_schema_generation(n00b_plan_shard_result_t *result);

/**
 * @brief Return the shard record-count universe for this result.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(record count), or @c N00B_PLAN_ERR_ARG for null input.
 *
 * The returned count must match the universe carried by
 * @ref n00b_plan_shard_result_ordinals.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_record_count(n00b_plan_shard_result_t *result);

/**
 * @brief Return the sealed shard timestamp copied from catalog metadata.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(seal timestamp), or @c N00B_PLAN_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_plan_shard_result_seal_ts(n00b_plan_shard_result_t *result);

/**
 * @brief Borrow the copied catalog partition route key.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(route key), or @c N00B_PLAN_ERR_ARG / @c N00B_PLAN_ERR_STATE.
 */
extern n00b_result_t(n00b_string_t *)
n00b_plan_shard_result_partition_key(n00b_plan_shard_result_t *result);

/**
 * @brief Borrow the verified per-shard ordinal set.
 *
 * @param result Per-shard result returned by @ref n00b_plan_store_sealed.
 * @return Ok(ordinals), or @c N00B_PLAN_ERR_ARG / @c N00B_PLAN_ERR_STATE.
 *
 * The returned set is owned by the result object's allocator lifetime. WP-008
 * callers may inspect it with ordinal-set accessors and must not mutate it.
 */
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_shard_result_ordinals(n00b_plan_shard_result_t *result);

// Only in a build with N00B_DEBUG, which is where tests run: counting
// records costs a write on the scan path.
#ifdef N00B_DEBUG
// Records materialized and parsed since the last reset. Query cost is
// dominated by this, so it is the useful thing to assert a bound on.
extern uint64_t
n00b_plan_records_scanned(void);

extern void
n00b_plan_records_scanned_reset(void);

// Put the count back, so work done by a checker between a reset and a read
// does not land in what the test is measuring.
extern void
n00b_plan_records_scanned_set(uint64_t count);
#endif

#ifdef __cplusplus
}
#endif

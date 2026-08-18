/*
 * What eval.c implements: plan execution and the record scan it is built on.
 * Everything here reads records, so every entry point takes a cancel callback.
 * Building a plan is plan.c's job and lives in plan.h.
 */
#pragma once

#include "internal/rocs/plan.h"

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

// Execute a plan against a shard. Does every scan, index and record alike.
extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_hot(n00b_plan_node_t   *plan,
                   n00b_store_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

extern n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_exec_mapped(n00b_plan_node_t       *plan,
                      n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t    *allocator  = nullptr;
    n00b_plan_cancel_fn  cancel_cb  = nullptr;
    void                *cancel_ctx = nullptr;
};

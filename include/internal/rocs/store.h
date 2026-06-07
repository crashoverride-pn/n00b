/**
 * @file internal/rocs/store.h
 * @brief Internal store/catalog helpers for rocs implementation.
 *
 * These declarations expose the narrow store internals needed by rocs
 * implementation modules. They are not part of the public rocs API and must
 * not be included from <rocs/n00b_rocs.h>.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "parsers/json.h"
#include "rocs/store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return the current catalog-visible sealed shard count.
 *
 * @param store Open store whose catalog is being planned.
 * @return Ok(count) for an open store, or a typed store error.
 *
 * This is the planner visibility boundary: dropped and stale shards are absent
 * from this count because retention removes their catalog entries.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_visible_entry_count(n00b_store_t *store);

/**
 * @brief Borrow one catalog-visible sealed shard by deterministic catalog order.
 *
 * @param store Open store whose catalog is being planned.
 * @param index Zero-based catalog-visible entry index.
 * @return Ok(some(entry)) when present, Ok(none) for out-of-range, or a typed
 *         store error.
 *
 * Returned entries are borrowed from the store catalog. Callers must not retain
 * them across catalog mutation.
 */
extern n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_visible_entry_at(n00b_store_t *store, uint64_t index);

/**
 * @brief Borrow the store partition policy used by planner pruning.
 *
 * @param store Open store.
 * @return Ok(policy), or a typed store error.
 */
extern n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_for_plan(n00b_store_t *store);

/**
 * @brief Borrow the configured partition field when the policy has one.
 *
 * @param policy Partition policy returned by store open/configuration.
 * @return Ok(some(field)) for time/hash partition policies, Ok(none) for the
 *         default/no-partition policy, or a typed store error.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_partition_policy_field_for_plan(
    n00b_store_partition_policy_t *policy);

/**
 * @brief Compute the route key for one partition-field value.
 *
 * @param policy Partition policy returned by store open/configuration.
 * @param value  Borrowed JSON value for the partition field.
 * @kw allocator Allocator for non-default route strings and hash scratch.
 * @return Ok(route key). Values that would route to the store default bucket
 *         return @c default.
 *
 * This helper uses the same policy semantics as store ingest routing while
 * avoiding construction of temporary records in the planner.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_partition_route_value_for_plan(
    n00b_store_partition_policy_t *policy,
    n00b_json_node_t              *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#ifdef __cplusplus
}
#endif

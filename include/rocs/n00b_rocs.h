/**
 * @file rocs/n00b_rocs.h
 * @brief Public umbrella header for the rocs module.
 *
 * rocs is libn00b's retrieval-oriented columnar store module. This umbrella
 * exposes the module lifecycle symbols, the low-level mapped access
 * declarations, the hot shard root/lifecycle declarations, and the index
 * descriptor/posting-view declarations used by the store implementation.
 */
#pragma once

#include "n00b.h"

/**
 * @brief Public API version for headers under @c include/rocs.
 *
 * This value is bumped only for incompatible public-surface changes.
 */
#define N00B_ROCS_API_VERSION 1

/** @brief Phase 1 exports callable module lifecycle symbols. */
#define N00B_ROCS_CAP_MODULE_LIFECYCLE 0x00000001u

/** @brief Phase 1 exports the store-map declaration surface. */
#define N00B_ROCS_CAP_STORE_MAP_DECLS 0x00000002u

/** @brief WP-003 exports the store-shard declaration surface. */
#define N00B_ROCS_CAP_STORE_SHARD_DECLS 0x00000004u

/** @brief WP-004 exports the index/posting declaration surface. */
#define N00B_ROCS_CAP_STORE_INDEX_DECLS 0x00000008u

/** @brief WP-004 exports shared normalizer/hash declarations. */
#define N00B_ROCS_CAP_STORE_NORMALIZER_DECLS 0x00000010u

/** @brief WP-005 exports durable store/schema/policy declarations. */
#define N00B_ROCS_CAP_STORE_DECLS 0x00000020u

/** @brief WP-007 exports store-independent filter builder declarations. */
#define N00B_ROCS_CAP_FILTER_DECLS 0x00000040u

/** @brief WP-008 exports snapshot query view declarations. */
#define N00B_ROCS_CAP_QUERY_DECLS 0x00000080u

/** @brief Bitset of rocs capabilities exposed by this header set. */
#define N00B_ROCS_CAPABILITIES                                                     \
    (N00B_ROCS_CAP_MODULE_LIFECYCLE | N00B_ROCS_CAP_STORE_MAP_DECLS                \
     | N00B_ROCS_CAP_STORE_SHARD_DECLS | N00B_ROCS_CAP_STORE_INDEX_DECLS           \
     | N00B_ROCS_CAP_STORE_NORMALIZER_DECLS | N00B_ROCS_CAP_STORE_DECLS            \
     | N00B_ROCS_CAP_FILTER_DECLS | N00B_ROCS_CAP_QUERY_DECLS)

#include "rocs/shard.h"
#include "rocs/map.h"
#include "rocs/index.h"
#include "rocs/normalizer.h"
#include "rocs/store.h"
#include "rocs/filter.h"
#include "rocs/query.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the rocs module.
 *
 * WP-001 Phase 1 has no process-wide state to initialize. The symbol is
 * still exported so consumers and tests can establish the header/link
 * contract before mapped-image behavior lands.
 *
 * @post Calling this function more than once is harmless.
 */
extern void n00b_rocs_module_init(void);

/**
 * @brief Shut down the rocs module.
 *
 * WP-001 Phase 1 has no process-wide state to release.
 *
 * @post Calling this function more than once is harmless.
 */
extern void n00b_rocs_module_shutdown(void);

#ifdef __cplusplus
}
#endif

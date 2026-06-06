/**
 * @file rocs/n00b_rocs.h
 * @brief Public umbrella header for the rocs module.
 *
 * rocs is libn00b's retrieval-oriented columnar store module. WP-001
 * Phase 1 exposes the module lifecycle symbols and the low-level mapped
 * access declarations used by later WP-001 phases. The lifecycle hooks
 * are intentionally idempotent and side-effect-free in Phase 1.
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

/** @brief Bitset of rocs capabilities exposed by this header set. */
#define N00B_ROCS_CAPABILITIES                                                     \
    (N00B_ROCS_CAP_MODULE_LIFECYCLE | N00B_ROCS_CAP_STORE_MAP_DECLS)

#include "rocs/map.h"

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

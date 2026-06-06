/**
 * @file internal/rocs/map.h
 * @brief Internal diagnostics for rocs mapped-image tests.
 *
 * These declarations intentionally expose only resident-image address facts
 * needed by focused tests. They are not data-access APIs: production callers
 * must use the public borrowed view handles in <rocs/map.h>.
 */
#pragma once

#include "n00b.h"
#include "rocs/map.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return the raw resident-image base address for a live map.
 *
 * Test/diagnostic-only. The returned address becomes invalid when the map is
 * closed and must not be used to read rocs data directly.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_resident_base_for_test(n00b_store_map_t *map);

/**
 * @brief Return the raw resident-image byte length for a live map.
 *
 * Test/diagnostic-only. This is the sealed image length, not necessarily the
 * page-aligned backing allocation length.
 */
extern n00b_result_t(uint64_t)
n00b_store_map_resident_len_for_test(n00b_store_map_t *map);

#ifdef __cplusplus
}
#endif

/**
 * @file internal/rocs/normalizer.h
 * @brief Debug counters for the rocs normalizer.
 */
#pragma once

#include <stdint.h>

#ifdef N00B_DEBUG
// Normalized terms materialized by the text tokenizers since the last reset.
// Each one costs a string, a JSON node, a buffer, and the term itself.
extern uint64_t
n00b_store_normalize_terms_built(void);

// Calls to the streaming text key functions since the last reset: one per
// value tokenized without building terms.
extern uint64_t
n00b_store_normalize_key_streams(void);

extern void
n00b_store_normalize_counters_reset(void);
#endif

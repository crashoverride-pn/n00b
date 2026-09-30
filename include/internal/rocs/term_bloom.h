/**
 * @file internal/rocs/term_bloom.h
 * @brief Membership filter over one TERM field's column keys in one shard.
 *
 * A sealed shard's catalog entry carries one of these per summarized TERM
 * field, and the planner probes it before mapping the shard. A false positive
 * costs a map the query would have made anyway; a false negative would drop
 * matching records, so none is possible: every key added probes present.
 *
 * The filter is persisted, so its layout is fixed by this header and never by
 * the process. Bit @c i is bit <tt>(i & 7)</tt> of byte <tt>i >> 3</tt>, so the
 * bytes read the same on every host. Probes come from the key's own bits, which
 * are already a hash: with @c h1 the high 64 bits and @c h2 the low 64 bits
 * forced odd, probe @c j of @c k is <tt>(h1 + j * h2) mod nbits</tt>. @c nbits
 * is a multiple of 64, so an odd step is never zero modulo it.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

// Probes per key when the filter gets its full size. With
// N00B_STORE_TERM_BLOOM_MILLIBITS_PER_KEY this is the optimum for a 1% false
// positive rate.
#define N00B_STORE_TERM_BLOOM_K 7
// Bits per key, in thousandths, for a 1% false positive rate:
// -ln(0.01) / ln(2)^2 = 9.585.
#define N00B_STORE_TERM_BLOOM_MILLIBITS_PER_KEY UINT64_C(9586)
// Below 1 / ln(2) = 1.443 bits per key even the best k predicts a false
// positive rate over one half, and the field is left unsummarized.
#define N00B_STORE_TERM_BLOOM_MIN_MILLIBITS_PER_KEY UINT64_C(1443)
// Largest k a catalog may carry.
#define N00B_STORE_TERM_BLOOM_MAX_K 16

typedef struct {
    uint64_t nkeys; // distinct keys added
    uint64_t nbits; // multiple of 64; zero exactly when nkeys is zero
    uint32_t k;     // probes per key, 1 to N00B_STORE_TERM_BLOOM_MAX_K
    uint8_t *bits;  // nbits / 8 bytes
} n00b_store_term_bloom_t;

/**
 * @brief Choose the size of a filter over @p nkeys distinct keys.
 *
 * The filter gets N00B_STORE_TERM_BLOOM_MILLIBITS_PER_KEY bits per key, rounded
 * up to a multiple of 64, and N00B_STORE_TERM_BLOOM_K probes. When that passes
 * @p max_bytes it gets the whole 64-bit words within @p max_bytes instead, and
 * the k nearest ln(2) * nbits / nkeys. Zero keys need zero bits.
 *
 * @return False when no filter within @p max_bytes predicts a false positive
 *         rate of one half or less; the field should then go unsummarized.
 */
extern bool
n00b_store_term_bloom_size(uint64_t  nkeys,
                           uint64_t  max_bytes,
                           uint64_t *nbits,
                           uint32_t *k);

/**
 * @brief Allocate an empty filter of the given shape.
 *
 * @pre @p nbits is a multiple of 64, and @p k is 1 to
 *      N00B_STORE_TERM_BLOOM_MAX_K.
 */
extern n00b_store_term_bloom_t *
n00b_store_term_bloom_new(uint64_t nbits, uint32_t k) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

extern void
n00b_store_term_bloom_add(n00b_store_term_bloom_t *bloom, n00b_uint128_t key);

/**
 * @brief False only when @p key was never added.
 *
 * A filter with no bits holds no keys, so it answers false for every key.
 */
extern bool
n00b_store_term_bloom_may_contain(const n00b_store_term_bloom_t *bloom,
                                  n00b_uint128_t                 key);

#ifdef __cplusplus
}
#endif

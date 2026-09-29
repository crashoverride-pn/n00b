#include "internal/rocs/term_bloom.h"

#include <string.h>

#include "core/gc_map.h"

// Keeps the products below in 64 bits whatever cap the caller passes.
#define ROCS_TERM_BLOOM_MAX_BITS (UINT64_C(1) << 52)

bool
n00b_store_term_bloom_size(uint64_t  nkeys,
                           uint64_t  max_bytes,
                           uint64_t *nbits,
                           uint32_t *k)
{
    if (nkeys == 0) {
        *nbits = 0;
        *k     = N00B_STORE_TERM_BLOOM_K;
        return true;
    }
    uint64_t cap_bits = max_bytes > ROCS_TERM_BLOOM_MAX_BITS / 8
                          ? ROCS_TERM_BLOOM_MAX_BITS
                          : max_bytes / 8 * 64;
    uint64_t want = (nkeys * N00B_STORE_TERM_BLOOM_MILLIBITS_PER_KEY + 999)
                  / 1000;
    want = (want + 63) & ~UINT64_C(63);
    if (want <= cap_bits) {
        *nbits = want;
        *k     = N00B_STORE_TERM_BLOOM_K;
        return true;
    }

    if (cap_bits * 1000 < nkeys * N00B_STORE_TERM_BLOOM_MIN_MILLIBITS_PER_KEY) {
        return false;
    }
    // round(ln(2) * cap_bits / nkeys): at least 1 given the check above, and
    // at most N00B_STORE_TERM_BLOOM_K because cap_bits is under the 1% size.
    uint64_t best = (cap_bits * 693 + nkeys * 500) / (nkeys * 1000);
    *nbits = cap_bits;
    *k     = (uint32_t)best;
    return true;
}

n00b_store_term_bloom_t *
n00b_store_term_bloom_new(uint64_t nbits, uint32_t k) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_term_bloom_t *bloom = n00b_alloc_with_opts(
        n00b_store_term_bloom_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    bloom->nkeys = 0;
    bloom->nbits = nbits;
    bloom->k     = k;
    bloom->bits  = nullptr;
    if (nbits > 0) {
        bloom->bits = n00b_alloc_array_with_opts(
            uint8_t,
            nbits / 8,
            &(n00b_alloc_opts_t){.allocator = allocator,
                                 .scan_kind = N00B_GC_SCAN_KIND_NONE});
        memset(bloom->bits, 0, nbits / 8);
    }
    return bloom;
}

// First probe and the step between probes, both already reduced mod nbits.
static inline void
rocs_term_bloom_start(const n00b_store_term_bloom_t *bloom,
                      n00b_uint128_t                 key,
                      uint64_t                      *pos,
                      uint64_t                      *step)
{
    uint64_t h1 = (uint64_t)(key >> 64);
    uint64_t h2 = (uint64_t)key | 1;
    *pos        = h1 % bloom->nbits;
    *step       = h2 % bloom->nbits;
}

void
n00b_store_term_bloom_add(n00b_store_term_bloom_t *bloom, n00b_uint128_t key)
{
    bloom->nkeys++;
    if (bloom->nbits == 0) {
        return;
    }
    uint64_t pos;
    uint64_t step;
    rocs_term_bloom_start(bloom, key, &pos, &step);
    for (uint32_t j = 0; j < bloom->k; j++) {
        bloom->bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
        pos += step;
        if (pos >= bloom->nbits) {
            pos -= bloom->nbits;
        }
    }
}

bool
n00b_store_term_bloom_may_contain(const n00b_store_term_bloom_t *bloom,
                                  n00b_uint128_t                 key)
{
    if (bloom->nbits == 0) {
        return false;
    }
    uint64_t pos;
    uint64_t step;
    rocs_term_bloom_start(bloom, key, &pos, &step);
    for (uint32_t j = 0; j < bloom->k; j++) {
        if ((bloom->bits[pos >> 3] & (1u << (pos & 7))) == 0) {
            return false;
        }
        pos += step;
        if (pos >= bloom->nbits) {
            pos -= bloom->nbits;
        }
    }
    return true;
}

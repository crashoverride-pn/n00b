#include "adt/bloom.h"

#include "core/hash.h"
#include "util/assert.h"
#include "util/math.h"

#include <math.h>
#include <stdatomic.h>

static uint64_t
bloom_word_count(uint64_t bit_length)
{
    return (bit_length + 63u) / 64u;
}

static uint64_t
bloom_add_mod(uint64_t lhs, uint64_t rhs, uint64_t modulus)
{
    return lhs >= modulus - rhs ? lhs - (modulus - rhs) : lhs + rhs;
}

static uint64_t
bloom_hash_mod(n00b_hash_value_t value, uint64_t modulus)
{
    uint64_t rem = 0;

    // Avoid compiler-rt 128-bit division helpers on Windows link paths.
    for (int byte_ix = (int)sizeof(value) - 1; byte_ix >= 0; byte_ix--) {
        for (int bit = 0; bit < 8; bit++) {
            rem = bloom_add_mod(rem, rem, modulus);
        }
        uint64_t byte = (uint64_t)(uint8_t)(value >> (byte_ix * 8));
        rem = bloom_add_mod(rem, byte % modulus, modulus);
    }

    return rem;
}

n00b_bloom_t *
n00b_bloom_new() _kargs
{
    double            false_pct = 0.01;
    uint64_t          set_size  = 250000;
    uint32_t          num_hashes = 0;
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_bloom_t *bf = n00b_alloc_with_opts(
        n00b_bloom_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_bloom_init(bf,
                    .false_pct = false_pct,
                    .set_size = set_size,
                    .num_hashes = num_hashes,
                    .allocator = allocator);
    return bf;
}

void
n00b_bloom_init(n00b_bloom_t *bf) _kargs
{
    double            false_pct = 0.01;
    uint64_t          set_size  = 250000;
    uint32_t          num_hashes = 0;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bf == nullptr) {
        return;
    }
    if (false_pct <= 0.0 || false_pct >= 1.0) {
        n00b_require(false, "invalid Bloom filter false positive target");
    }

    if (set_size < N00B_BLOOM_MIN_EXPECTED_ITEMS) {
        set_size = N00B_BLOOM_MIN_EXPECTED_ITEMS;
    }

    double nfplog = -log(false_pct);
    double optlen = (double)set_size * nfplog / N00B_BLOOM_LOG2_SQ;
    uint64_t bit_length = n00b_round_up(64, (uint64_t)(optlen + 0.5));
    if (bit_length < 64) {
        bit_length = 64;
    }

    if (num_hashes == 0) {
        double opthash = nfplog / N00B_BLOOM_LOG2;
        num_hashes = (uint32_t)(opthash + 0.5);
        if (num_hashes == 0) {
            num_hashes = 1;
        }
    }

    bf->bit_length = bit_length;
    bf->word_length = bloom_word_count(bit_length);
    bf->num_hashes = num_hashes;
    bf->false_rate = false_pct;
    bf->allocator = allocator;
    bf->bitfield = n00b_alloc_array_with_opts(
        _Atomic(uint64_t),
        bf->word_length,
        &(n00b_alloc_opts_t){.allocator = allocator});
    memset(bf->bitfield, 0, bf->word_length * sizeof(_Atomic(uint64_t)));
}

static uint64_t
bloom_index_for_hash(n00b_hash_value_t hv, uint32_t ordinal, uint64_t bit_length)
{
    uint8_t material[sizeof(n00b_hash_value_t) + sizeof(uint32_t)] = {0};
    memcpy(material, &hv, sizeof(hv));
    memcpy(material + sizeof(hv), &ordinal, sizeof(ordinal));
    n00b_hash_value_t expanded = n00b_hash_raw(material, sizeof(material));
    return bloom_hash_mod(expanded, bit_length);
}

void
n00b_bloom_add(n00b_bloom_t *bf, void *obj)
{
    if (bf == nullptr || bf->bitfield == nullptr || bf->bit_length == 0) {
        return;
    }

    n00b_hash_value_t hv = n00b_hash(obj, nullptr);
    for (uint32_t i = 0; i < bf->num_hashes; i++) {
        uint64_t bit = bloom_index_for_hash(hv, i, bf->bit_length);
        atomic_fetch_or_explicit(&bf->bitfield[bit >> 6],
                                 1ull << (bit & 63u),
                                 memory_order_relaxed);
    }
}

bool
n00b_bloom_contains(n00b_bloom_t *bf, void *obj)
{
    if (bf == nullptr || bf->bitfield == nullptr || bf->bit_length == 0) {
        return false;
    }

    n00b_hash_value_t hv = n00b_hash(obj, nullptr);
    for (uint32_t i = 0; i < bf->num_hashes; i++) {
        uint64_t bit  = bloom_index_for_hash(hv, i, bf->bit_length);
        uint64_t word = atomic_load_explicit(&bf->bitfield[bit >> 6],
                                             memory_order_relaxed);
        if ((word & (1ull << (bit & 63u))) == 0) {
            return false;
        }
    }
    return true;
}

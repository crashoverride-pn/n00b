/**
 * @file bloom.h
 * @brief Simple thread-safe Bloom filter ADT.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"

#include <stdatomic.h>
#include <stdint.h>

#define N00B_BLOOM_MIN_EXPECTED_ITEMS 10u
#define N00B_BLOOM_LOG2               0.6931471805599453
#define N00B_BLOOM_LOG2_SQ            0.4804530139182014

typedef struct n00b_bloom_t {
    _Atomic(uint64_t) *bitfield;
    uint64_t           bit_length;
    uint64_t           word_length;
    uint32_t           num_hashes;
    double             false_rate;
    n00b_allocator_t  *allocator;
} n00b_bloom_t;

extern n00b_bloom_t *
n00b_bloom_new() _kargs
{
    double            false_pct = 0.01;
    uint64_t          set_size  = 250000;
    uint32_t          num_hashes = 0;
    n00b_allocator_t *allocator = nullptr;
};

extern void
n00b_bloom_init(n00b_bloom_t *bf) _kargs
{
    double            false_pct = 0.01;
    uint64_t          set_size  = 250000;
    uint32_t          num_hashes = 0;
    n00b_allocator_t *allocator = nullptr;
};

extern void n00b_bloom_add(n00b_bloom_t *bf, void *obj);
extern bool n00b_bloom_contains(n00b_bloom_t *bf, void *obj);

/**
 * @file align.h
 * @brief Memory alignment utilities.
 *
 * Helpers for page-aligned and power-of-two-aligned address arithmetic,
 * used throughout the allocator and mmap subsystems.
 */
#pragma once

#include <stdint.h>

#if !defined(N00B_ALIGN)
#define N00B_ALIGN 32
#endif

/** @brief Cached system page size (set during runtime init). */
extern size_t n00b_page_size;

/**
 * @brief Round an address down to the start of its page.
 * @param addr The address to align.
 * @return     The page-aligned address.
 */
static inline void *
n00b_align_to_page_start(void *addr)
{
    uint64_t power   = n00b_page_size;
    uint64_t modulus = power - 1;

    return (char *)(((uint64_t)addr) & ~modulus);
}

#if __has_include(<stdbit.h>)
#include <stdbit.h>
#else
// C23 semantics: 1 for 0 and 1, and 0 when the result does not fit. Only
// x - 1 >= 1 reaches the builtin, which is undefined at 0.
static inline unsigned long long
stdc_bit_ceil_ull(unsigned long long x)
{
    return x <= 1 ? 1 : 2ULL << (63 - __builtin_clzll(x - 1));
}

static inline unsigned long long
stdc_bit_floor_ull(unsigned long long x)
{
    return x == 0 ? 0 : 1ULL << (63 - __builtin_clzll(x));
}
#endif

#define n00b_align_closest_pow2_floor(value) stdc_bit_floor_ull((unsigned long long int)(value))
#define n00b_align_closest_pow2_ceil(value)  stdc_bit_ceil_ull((unsigned long long int)value)

/**
 * @brief Align @p n down to a multiple of @p base (must be power-of-two).
 * @param n    Value to align.
 * @param base Power-of-two alignment base.
 * @return     Aligned value.
 * @pre @p base is a power of two (asserted).
 */
static inline uint64_t
n00b_align_floor(uint64_t n, uint64_t base)
{
    assert(base > 0);
    uint64_t mask = base - 1;

    assert(!(base & mask));
    return n & ~mask;
}

/**
 * @brief Align @p n up to a multiple of @p base (must be power-of-two).
 * @param n    Value to align.
 * @param base Power-of-two alignment base.
 * @return     Aligned value.
 * @pre @p base is a power of two (asserted).
 */
static inline uint64_t
n00b_align_ceil(uint64_t n, uint64_t base)
{
    assert(base > 0);
    uint64_t mask = base - 1;

    assert(!(base & mask));

    return (n + mask) & ~mask;
}

/**
 * @brief Align @p n up to the next page boundary.
 * @param n Value to align.
 * @return  Page-aligned value.
 * @pre `n00b_page_size` has been initialized (set during runtime init).
 */
static inline uint64_t
n00b_page_align(uint64_t n)
{
    return n00b_align_ceil(n, n00b_page_size);
}

/**
 * @brief Align @p n up to the default allocation alignment (N00B_ALIGN).
 * @param n Value to align.
 * @return  Aligned value.
 */
static inline uint64_t
n00b_align(uint64_t n)
{
    return n00b_align_ceil(n, N00B_ALIGN);
}

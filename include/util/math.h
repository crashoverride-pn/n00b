/**
 * @file math.h
 * @brief Low-level integer math utilities.
 *
 * Count-leading-zeros, integer log2, power-of-10 floor, population
 * count, and general-purpose rounding.
 */
#pragma once
#include <stdint.h>

#if __has_include(<stdbit.h>)
#include <stdbit.h>
#else
// C23 semantics: a zero operand counts every bit of its type, and an 8- or
// 16-bit operand counts within its own width. Only nonzero values reach the
// builtins, which are undefined at 0.
static inline unsigned int
_n00b_leading_zeros(unsigned long long x, unsigned int width)
{
    if (width < 64) {
        x &= (1ULL << width) - 1;
    }
    return x == 0 ? width : (unsigned int)__builtin_clzll(x) - (64 - width);
}

static inline unsigned int
_n00b_trailing_zeros(unsigned long long x, unsigned int width)
{
    if (width < 64) {
        x &= (1ULL << width) - 1;
    }
    return x == 0 ? width : (unsigned int)__builtin_ctzll(x);
}

#define stdc_leading_zeros(x) \
    _n00b_leading_zeros((unsigned long long)(x), (unsigned int)(8 * sizeof(x)))
#define stdc_trailing_zeros(x) \
    _n00b_trailing_zeros((unsigned long long)(x), (unsigned int)(8 * sizeof(x)))
#define stdc_count_ones(x) _Generic((x), \
    unsigned long long: __builtin_popcountll, \
    unsigned long: __builtin_popcountl, \
    default: __builtin_popcount)(x)
#endif
/** @brief Count leading zeros in a 64-bit value. */
extern uint64_t n00b_clz(uint64_t value);

/**
 * @brief Compute floor(log2(n)) for a non-zero value.
 * @param n Value to compute log2 of.
 * @return  floor(log2(n)).
 * @pre @p n > 0 (undefined behavior if zero).
 */
static inline uint64_t
n00b_int_log2(uint64_t n)
{
    return 63 - stdc_leading_zeros(n);
}

/**
 * @brief Round @p to_round up to the nearest multiple of @p mod.
 * @param mod      Divisor to round to.
 * @param to_round Value to round.
 * @return         Rounded value.
 * @pre @p mod > 0.
 */
static inline uint64_t
n00b_round_up(uint64_t mod, uint64_t to_round)
{
    return (to_round + mod - 1) - (to_round % mod);
}

/**
 * @brief Convert a fraction to a percentage.
 * @param numerator   Numerator.
 * @param denominator Denominator.
 * @return            Percentage (0.0–100.0).
 */
static inline double
n00b_to_pct(uint64_t numerator, uint64_t denominator)
{
    return 100.0 * ((double)numerator) / ((double)denominator);
}

/**
 * @brief Compute the largest power of 10 <= @p n.
 * @param n Input value.
 * @return  Largest power of 10 that does not exceed @p n.
 */
static inline uint64_t
n00b_pow10_floor(uint64_t n)
{
    uint16_t result = 0;

    while (n) {
        if (!result) {
            result = 1;
        }
        else {
            result *= 10;
        }
        n /= 10;
    }

    return result;
}

#if __has_include(<stdbit.h>)
#include <stdbit.h>
static inline unsigned int
n00b_count_ones(uint64_t n)
{
    return stdc_count_ones_ull((unsigned long long)n);
}
#else
static inline unsigned int
n00b_count_ones(uint64_t n)
{
    return stdc_count_ones((unsigned long long)n);
}
#endif

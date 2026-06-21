#pragma once

/**
 * @file crypto/gf256.h
 * @brief Arithmetic over the finite field GF(2^8).
 *
 * A small, dependency-light primitive for byte-wise finite-field
 * math. The field is parameterized by its reducing (primitive)
 * polynomial and a generator element, so the same type expresses the
 * QR / Reed-Solomon standard field (`0x11D`, generator `2`) as well as
 * other GF(256) fields such as AES's (`0x11B`, generator `3`).
 *
 * # Symbol prefix
 *
 * `n00b_gf256_*` (lower-case symbols). Top-level utility namespace,
 * matching the `n00b_base64_*` precedent. The first consumer is the
 * Reed-Solomon encoder (`crypto/reed_solomon.h`), but this is a
 * general-purpose field and is not tied to it.
 *
 * # Value type, not a managed object
 *
 * An `n00b_gf256_t` is a plain ~768-byte value: two lookup tables plus
 * the two parameters that generated them. There is no heap
 * constructor, no allocator threading, and no save/load — the tables
 * are cheap derived data (a few hundred iterations), so a field is
 * meant to be embedded on the stack or inside another struct and built
 * with `n00b_gf256_init()`. Build one and pass it by pointer to the
 * arithmetic ops; rebuild rather than cache globally.
 *
 * # Arithmetic
 *
 * Addition and subtraction in GF(2^8) are both XOR. Multiplication,
 * division, inverse, and exponentiation go through exp/log tables and
 * are provided as `static inline` so tight inner loops (e.g. the
 * Reed-Solomon polynomial division) stay branch-light. `mul`/`div`
 * guard the zero operand; `div`/`inv` require a non-zero divisor.
 */

#include <stdint.h>

#include "util/assert.h"

/**
 * @brief A GF(2^8) field: exp/log tables plus the parameters that built
 *        them.
 *
 * @var n00b_gf256_t::exp
 *   Antilog table: `exp[i] == generator^i`. Doubled to 512 entries so
 *   `mul`/`div` can index `log[a] + log[b]` (max 509) without a modulo.
 * @var n00b_gf256_t::log
 *   Log table: `log[exp[i]] == i`. `log[0]` is undefined and unused
 *   (the arithmetic ops special-case a zero operand first).
 * @var n00b_gf256_t::primitive
 *   The reducing polynomial (9-bit value, e.g. `0x11D`).
 * @var n00b_gf256_t::generator
 *   The field generator used to build the tables (e.g. `2`).
 */
typedef struct {
    uint8_t  exp[512];
    uint8_t  log[256];
    uint16_t primitive;
    uint8_t  generator;
} n00b_gf256_t;

/**
 * @brief Populate a caller-provided field. Performs no allocation.
 *
 * Builds the exp/log tables for the field defined by @kw primitive and
 * @kw generator. The generator must be a primitive element of the field
 * (true for the documented defaults); supplying a non-primitive element
 * yields tables that are not a bijection and arithmetic results are then
 * undefined.
 *
 * @param gf  Field to initialize (caller-owned storage).
 * @kw primitive  Reducing polynomial (default `0x11D`, the QR / RS
 *                standard `x^8 + x^4 + x^3 + x^2 + 1`).
 * @kw generator  Field generator (default `2`).
 */
extern void
n00b_gf256_init(n00b_gf256_t *gf) _kargs
{
    uint16_t primitive = 0x11D;
    uint8_t  generator = 2;
};

/** @brief Field addition (== subtraction): XOR. Field-independent. */
static inline uint8_t
n00b_gf256_add(uint8_t a, uint8_t b)
{
    return a ^ b;
}

/** @brief Field subtraction (== addition): XOR. Field-independent. */
static inline uint8_t
n00b_gf256_sub(uint8_t a, uint8_t b)
{
    return a ^ b;
}

/** @brief Field multiplication. Returns 0 if either operand is 0. */
static inline uint8_t
n00b_gf256_mul(const n00b_gf256_t *gf, uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return gf->exp[gf->log[a] + gf->log[b]];
}

/**
 * @brief Field division `a / b`. Returns 0 if @p a is 0.
 *
 * Division by zero is undefined in a field and is treated as a fatal
 * caller error (always-on guard), not silently coerced to a value.
 */
static inline uint8_t
n00b_gf256_div(const n00b_gf256_t *gf, uint8_t a, uint8_t b)
{
    n00b_require(b != 0, "n00b_gf256_div: division by zero");
    if (a == 0) {
        return 0;
    }
    return gf->exp[gf->log[a] + 255 - gf->log[b]];
}

/**
 * @brief Multiplicative inverse of @p a.
 *
 * Zero has no inverse; passing 0 is a fatal caller error (always-on
 * guard) rather than a silently-wrong result.
 */
static inline uint8_t
n00b_gf256_inv(const n00b_gf256_t *gf, uint8_t a)
{
    n00b_require(a != 0, "n00b_gf256_inv: zero has no inverse");
    return gf->exp[255 - gf->log[a]];
}

/** @brief Exponentiation `a^n` (n may be negative). `0^0` is 1. */
static inline uint8_t
n00b_gf256_pow(const n00b_gf256_t *gf, uint8_t a, int32_t n)
{
    if (a == 0) {
        return n == 0 ? 1 : 0;
    }
    // 64-bit intermediate so large |n| can't overflow before the mod.
    int64_t l = ((int64_t)gf->log[a] * (int64_t)n) % 255;
    if (l < 0) {
        l += 255;
    }
    return gf->exp[(int32_t)l];
}

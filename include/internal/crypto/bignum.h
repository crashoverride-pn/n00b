#pragma once

/*
 * bignum.h — minimal non-negative big-integer arithmetic (WP-042).
 *
 * Extracted from rsa_pkcs1.c (schoolbook multiply + Knuth-style modular
 * reduction) so RSA and the P-384 ECDSA verifier share one tested bignum.
 * 32-bit little-endian word limbs; sized for 4096-bit RSA products (which also
 * covers P-384). NOT constant-time — only ever used on public values (public
 * keys, signatures, hashes). All scratch is caller-stack; no allocation.
 */

#include "n00b.h"

/* Product of two 128-word (4096-bit) operands is 256 words; +1 for shift
 * overflow scratch. */
#define N00B_BN_MAX_WORDS 257

typedef struct {
    uint32_t w[N00B_BN_MAX_WORDS];
    int      n; /* most-significant nonzero word index + 1 */
} n00b_bignum_t;

extern void n00b_bn_zero(n00b_bignum_t *a);
extern void n00b_bn_set_u32(n00b_bignum_t *a, uint32_t v);
extern bool n00b_bn_is_zero(const n00b_bignum_t *a);
extern void n00b_bn_normalize(n00b_bignum_t *a);
extern bool n00b_bn_eq(const n00b_bignum_t *a, const n00b_bignum_t *b);
extern int  n00b_bn_ge(const n00b_bignum_t *a, const n00b_bignum_t *b); /* a>=b */

/* Big-endian bytes -> bignum; returns -1 if it doesn't fit, else 0. */
extern int  n00b_bn_from_bytes(n00b_bignum_t *a, const uint8_t *b, size_t blen);
/* bignum -> exactly out_len big-endian bytes (left-zero-padded). */
extern void n00b_bn_to_bytes(const n00b_bignum_t *a, uint8_t *out, size_t out_len);

extern void n00b_bn_add(n00b_bignum_t *res, const n00b_bignum_t *a,
                        const n00b_bignum_t *b);
extern void n00b_bn_sub(n00b_bignum_t *res, const n00b_bignum_t *a,
                        const n00b_bignum_t *b); /* assumes a >= b */
extern void n00b_bn_mul(n00b_bignum_t *res, const n00b_bignum_t *a,
                        const n00b_bignum_t *b);
extern void n00b_bn_mod(n00b_bignum_t *res, const n00b_bignum_t *a,
                        const n00b_bignum_t *m);
extern void n00b_bn_mulmod(n00b_bignum_t *res, const n00b_bignum_t *a,
                           const n00b_bignum_t *b, const n00b_bignum_t *m);
extern void n00b_bn_powmod(n00b_bignum_t *res, const n00b_bignum_t *s,
                           const n00b_bignum_t *e, const n00b_bignum_t *n);

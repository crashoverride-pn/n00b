/*
 * bignum.c — shared non-negative bignum (WP-042). See bignum.h.
 * Verbatim extraction of the rsa_pkcs1.c schoolbook + Knuth-style reduction,
 * renamed n00b_bn_*, with memset replaced by loops and a few helpers added.
 */

#include "n00b.h"
#include "internal/crypto/bignum.h"

void
n00b_bn_zero(n00b_bignum_t *a)
{
    for (int i = 0; i < N00B_BN_MAX_WORDS; i++) {
        a->w[i] = 0;
    }
    a->n = 0;
}

void
n00b_bn_set_u32(n00b_bignum_t *a, uint32_t v)
{
    n00b_bn_zero(a);
    if (v != 0) {
        a->w[0] = v;
        a->n    = 1;
    }
}

bool
n00b_bn_is_zero(const n00b_bignum_t *a)
{
    return a->n == 0;
}

void
n00b_bn_normalize(n00b_bignum_t *a)
{
    while (a->n > 0 && a->w[a->n - 1] == 0) {
        a->n--;
    }
}

bool
n00b_bn_eq(const n00b_bignum_t *a, const n00b_bignum_t *b)
{
    if (a->n != b->n) {
        return false;
    }
    for (int i = 0; i < a->n; i++) {
        if (a->w[i] != b->w[i]) {
            return false;
        }
    }
    return true;
}

int
n00b_bn_ge(const n00b_bignum_t *a, const n00b_bignum_t *b)
{
    if (a->n != b->n) {
        return a->n > b->n;
    }
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->w[i] != b->w[i]) {
            return a->w[i] > b->w[i];
        }
    }
    return 1;
}

int
n00b_bn_from_bytes(n00b_bignum_t *a, const uint8_t *b, size_t blen)
{
    n00b_bn_zero(a);
    while (blen > 0 && b[0] == 0) {
        b++;
        blen--;
    }
    if (blen == 0) {
        return 0;
    }
    size_t needed_words = (blen + 3) / 4;
    if (needed_words > N00B_BN_MAX_WORDS) {
        return -1;
    }
    size_t i   = 0;
    size_t pos = blen;
    while (pos >= 4) {
        pos -= 4;
        a->w[i++] = ((uint32_t)b[pos] << 24) | ((uint32_t)b[pos + 1] << 16)
                  | ((uint32_t)b[pos + 2] << 8) | ((uint32_t)b[pos + 3]);
    }
    if (pos > 0) {
        uint32_t v = 0;
        for (size_t k = 0; k < pos; k++) {
            v = (v << 8) | (uint32_t)b[k];
        }
        a->w[i++] = v;
    }
    a->n = (int)i;
    n00b_bn_normalize(a);
    return 0;
}

void
n00b_bn_to_bytes(const n00b_bignum_t *a, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        out[i] = 0;
    }
    int total_bytes = a->n * 4;
    if ((size_t)total_bytes > out_len) {
        total_bytes = (int)out_len;
    }
    for (int i = 0; i < total_bytes; i++) {
        int     word_idx = i / 4;
        int     byte_idx = i % 4;
        uint8_t b        = (uint8_t)(a->w[word_idx] >> (byte_idx * 8));
        out[out_len - 1 - i] = b;
    }
}

void
n00b_bn_add(n00b_bignum_t *res, const n00b_bignum_t *a, const n00b_bignum_t *b)
{
    int      n     = (a->n > b->n) ? a->n : b->n;
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t av = (i < a->n) ? a->w[i] : 0;
        uint64_t bv = (i < b->n) ? b->w[i] : 0;
        uint64_t s  = av + bv + carry;
        res->w[i]   = (uint32_t)s;
        carry       = s >> 32;
    }
    if (carry && n < N00B_BN_MAX_WORDS) {
        res->w[n++] = (uint32_t)carry;
    }
    res->n = n;
    n00b_bn_normalize(res);
}

void
n00b_bn_sub(n00b_bignum_t *res, const n00b_bignum_t *a, const n00b_bignum_t *b)
{
    int64_t borrow = 0;
    int     n      = a->n;
    for (int i = 0; i < n; i++) {
        uint32_t bv = (i < b->n) ? b->w[i] : 0;
        int64_t  d  = (int64_t)a->w[i] - (int64_t)bv - borrow;
        if (d < 0) {
            d += 0x100000000LL;
            borrow = 1;
        }
        else {
            borrow = 0;
        }
        res->w[i] = (uint32_t)d;
    }
    res->n = n;
    n00b_bn_normalize(res);
}

void
n00b_bn_mul(n00b_bignum_t *res, const n00b_bignum_t *a, const n00b_bignum_t *b)
{
    int n = a->n + b->n + 1;
    if (n > N00B_BN_MAX_WORDS) {
        n = N00B_BN_MAX_WORDS;
    }
    n00b_bn_zero(res);
    for (int i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->n; j++) {
            int k = i + j;
            if (k >= N00B_BN_MAX_WORDS) {
                break;
            }
            uint64_t prod = (uint64_t)a->w[i] * (uint64_t)b->w[j]
                          + (uint64_t)res->w[k] + carry;
            res->w[k] = (uint32_t)prod;
            carry     = prod >> 32;
        }
        int k = i + b->n;
        while (carry && k < N00B_BN_MAX_WORDS) {
            uint64_t s = (uint64_t)res->w[k] + carry;
            res->w[k]  = (uint32_t)s;
            carry      = s >> 32;
            k++;
        }
    }
    res->n = n;
    n00b_bn_normalize(res);
}

void
n00b_bn_mod(n00b_bignum_t *res, const n00b_bignum_t *a, const n00b_bignum_t *m)
{
    if (m->n == 0) {
        n00b_bn_zero(res);
        return;
    }
    if (a->n < m->n) {
        *res = *a;
        return;
    }
    n00b_bignum_t r = *a;
    n00b_bn_normalize(&r);

    int shift      = (r.n - m->n) * 32;
    int total_bits = shift + 32;

    n00b_bignum_t shifted;
    for (int s = total_bits; s >= 0; s--) {
        n00b_bn_zero(&shifted);
        int word_off = s / 32;
        int bit_off  = s % 32;
        for (int i = 0; i < m->n; i++) {
            int      dst = i + word_off;
            uint64_t val = ((uint64_t)m->w[i]) << bit_off;
            if (dst >= N00B_BN_MAX_WORDS) {
                break;
            }
            uint64_t v0    = (uint64_t)shifted.w[dst] + (val & 0xFFFFFFFFULL);
            shifted.w[dst] = (uint32_t)v0;
            uint64_t carry = (v0 >> 32);
            if (dst + 1 < N00B_BN_MAX_WORDS) {
                uint64_t v1        = (uint64_t)shifted.w[dst + 1] + (val >> 32)
                              + carry;
                shifted.w[dst + 1] = (uint32_t)v1;
                carry              = (v1 >> 32);
                int k              = dst + 2;
                while (carry && k < N00B_BN_MAX_WORDS) {
                    uint64_t v    = (uint64_t)shifted.w[k] + carry;
                    shifted.w[k]  = (uint32_t)v;
                    carry         = (v >> 32);
                    k++;
                }
            }
        }
        shifted.n = m->n + word_off + 2;
        if (shifted.n > N00B_BN_MAX_WORDS) {
            shifted.n = N00B_BN_MAX_WORDS;
        }
        n00b_bn_normalize(&shifted);

        if (n00b_bn_ge(&r, &shifted)) {
            n00b_bignum_t tmp;
            n00b_bn_sub(&tmp, &r, &shifted);
            r = tmp;
        }
    }
    *res = r;
}

void
n00b_bn_mulmod(n00b_bignum_t *res, const n00b_bignum_t *a,
               const n00b_bignum_t *b, const n00b_bignum_t *m)
{
    n00b_bignum_t prod;
    n00b_bn_mul(&prod, a, b);
    n00b_bn_mod(res, &prod, m);
}

void
n00b_bn_powmod(n00b_bignum_t *res, const n00b_bignum_t *s,
               const n00b_bignum_t *e, const n00b_bignum_t *n)
{
    n00b_bn_set_u32(res, 1);
    n00b_bignum_t base = *s;
    n00b_bn_mod(&base, &base, n);

    int total_bits = e->n * 32;
    for (int i = 0; i < total_bits; i++) {
        int      word = i / 32;
        int      bit  = i % 32;
        uint32_t b    = (e->w[word] >> bit) & 1;
        if (b) {
            n00b_bignum_t t;
            n00b_bn_mulmod(&t, res, &base, n);
            *res = t;
        }
        n00b_bignum_t t2;
        n00b_bn_mulmod(&t2, &base, &base, n);
        base = t2;
    }
}

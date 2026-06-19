/*
 * ecdsa_p384.c — ECDSA verify on NIST P-384 (WP-042 Phase 3). See header.
 *
 * Affine point arithmetic over GF(p) using the shared bignum; modular inverse
 * via Fermat (a^(p-2)). Verify-only (public inputs) so non-constant-time is
 * fine. Curve y^2 = x^3 - 3x + b (a = p-3). On-curve validation of the public
 * point is not performed (CA-issued keys); a follow-up may add it.
 */

#include "n00b.h"

#include "core/buffer.h"
#include "internal/crypto/bignum.h"
#include "internal/crypto/ecdsa_p384.h"

/* NIST P-384 / secp384r1 parameters, big-endian, 48 bytes each. */
static const uint8_t P384_P[48] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff};
static const uint8_t P384_N[48] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xc7,0x63,0x4d,0x81,0xf4,0x37,0x2d,0xdf,0x58,0x1a,0x0d,0xb2,
    0x48,0xb0,0xa7,0x7a,0xec,0xec,0x19,0x6a,0xcc,0xc5,0x29,0x73};
static const uint8_t P384_GX[48] = {
    0xaa,0x87,0xca,0x22,0xbe,0x8b,0x05,0x37,0x8e,0xb1,0xc7,0x1e,
    0xf3,0x20,0xad,0x74,0x6e,0x1d,0x3b,0x62,0x8b,0xa7,0x9b,0x98,
    0x59,0xf7,0x41,0xe0,0x82,0x54,0x2a,0x38,0x55,0x02,0xf2,0x5d,
    0xbf,0x55,0x29,0x6c,0x3a,0x54,0x5e,0x38,0x72,0x76,0x0a,0xb7};
static const uint8_t P384_GY[48] = {
    0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,0x98,0xbf,
    0x92,0x92,0xdc,0x29,0xf8,0xf4,0x1d,0xbd,0x28,0x9a,0x14,0x7c,
    0xe9,0xda,0x31,0x13,0xb5,0xf0,0xb8,0xc0,0x0a,0x60,0xb1,0xce,
    0x1d,0x7e,0x81,0x9d,0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f};

typedef struct {
    n00b_bignum_t x;
    n00b_bignum_t y;
    bool          inf;
} ecp_t;

/* field ops mod p (operands already reduced < p) */
static void
fadd(n00b_bignum_t *r, const n00b_bignum_t *a, const n00b_bignum_t *b,
     const n00b_bignum_t *p)
{
    n00b_bignum_t t;
    n00b_bn_add(&t, a, b);
    if (n00b_bn_ge(&t, p)) {
        n00b_bn_sub(r, &t, p);
    }
    else {
        *r = t;
    }
}

static void
fsub(n00b_bignum_t *r, const n00b_bignum_t *a, const n00b_bignum_t *b,
     const n00b_bignum_t *p)
{
    if (n00b_bn_ge(a, b)) {
        n00b_bn_sub(r, a, b);
    }
    else {
        n00b_bignum_t t;
        n00b_bn_add(&t, a, p);
        n00b_bn_sub(r, &t, b);
    }
}

static void
fmul(n00b_bignum_t *r, const n00b_bignum_t *a, const n00b_bignum_t *b,
     const n00b_bignum_t *p)
{
    n00b_bn_mulmod(r, a, b, p);
}

/* r = a^-1 mod p (Fermat: a^(p-2)); p prime. */
static void
finv(n00b_bignum_t *r, const n00b_bignum_t *a, const n00b_bignum_t *p)
{
    n00b_bignum_t two;
    n00b_bignum_t pm2;
    n00b_bn_set_u32(&two, 2);
    n00b_bn_sub(&pm2, p, &two);
    n00b_bn_powmod(r, a, &pm2, p);
}

static void
ec_double(ecp_t *R, const ecp_t *P, const n00b_bignum_t *p,
          const n00b_bignum_t *a)
{
    if (P->inf || n00b_bn_is_zero(&P->y)) {
        R->inf = true;
        return;
    }
    n00b_bignum_t x2, num, den, dinv, lam, l2, t2x, rx, t, ry;
    fmul(&x2, &P->x, &P->x, p);   /* x^2 */
    fadd(&num, &x2, &x2, p);      /* 2x^2 */
    fadd(&num, &num, &x2, p);     /* 3x^2 */
    fadd(&num, &num, a, p);       /* 3x^2 + a */
    fadd(&den, &P->y, &P->y, p);  /* 2y */
    finv(&dinv, &den, p);
    fmul(&lam, &num, &dinv, p);
    fmul(&l2, &lam, &lam, p);
    fadd(&t2x, &P->x, &P->x, p);
    fsub(&rx, &l2, &t2x, p);      /* rx = lam^2 - 2x */
    fsub(&t, &P->x, &rx, p);
    fmul(&ry, &lam, &t, p);
    fsub(&ry, &ry, &P->y, p);     /* ry = lam(x-rx) - y */
    R->x   = rx;
    R->y   = ry;
    R->inf = false;
}

static void
ec_add(ecp_t *R, const ecp_t *P, const ecp_t *Q, const n00b_bignum_t *p,
       const n00b_bignum_t *a)
{
    if (P->inf) {
        *R = *Q;
        return;
    }
    if (Q->inf) {
        *R = *P;
        return;
    }
    if (n00b_bn_eq(&P->x, &Q->x)) {
        if (n00b_bn_eq(&P->y, &Q->y)) {
            ec_double(R, P, p, a);
        }
        else {
            R->inf = true;
        }
        return;
    }
    n00b_bignum_t dy, dx, dxi, lam, l2, rx, t, ry;
    fsub(&dy, &Q->y, &P->y, p);
    fsub(&dx, &Q->x, &P->x, p);
    finv(&dxi, &dx, p);
    fmul(&lam, &dy, &dxi, p);
    fmul(&l2, &lam, &lam, p);
    fsub(&rx, &l2, &P->x, p);
    fsub(&rx, &rx, &Q->x, p);     /* rx = lam^2 - Px - Qx */
    fsub(&t, &P->x, &rx, p);
    fmul(&ry, &lam, &t, p);
    fsub(&ry, &ry, &P->y, p);     /* ry = lam(Px-rx) - Py */
    R->x   = rx;
    R->y   = ry;
    R->inf = false;
}

/* R = k*P (double-and-add, MSB first). */
static void
ec_mul(ecp_t *R, const n00b_bignum_t *k, const ecp_t *P, const n00b_bignum_t *p,
       const n00b_bignum_t *a)
{
    R->inf = true;
    int bits = k->n * 32;
    for (int i = bits - 1; i >= 0; i--) {
        ecp_t tmp;
        ec_double(&tmp, R, p, a);
        *R = tmp;
        if ((k->w[i / 32] >> (i % 32)) & 1) {
            ecp_t t2;
            ec_add(&t2, R, P, p, a);
            *R = t2;
        }
    }
}

bool
n00b_ecdsa_p384_verify(n00b_buffer_t *pub_xy, n00b_buffer_t *hash,
                       n00b_buffer_t *r, n00b_buffer_t *s)
{
    if (pub_xy == NULL || hash == NULL || r == NULL || s == NULL) {
        return false;
    }
    if (n00b_buffer_len(pub_xy) != 96) {
        return false;
    }

    n00b_bignum_t p, n, gx, gy, a, three;
    n00b_bn_from_bytes(&p, P384_P, 48);
    n00b_bn_from_bytes(&n, P384_N, 48);
    n00b_bn_from_bytes(&gx, P384_GX, 48);
    n00b_bn_from_bytes(&gy, P384_GY, 48);
    n00b_bn_set_u32(&three, 3);
    n00b_bn_sub(&a, &p, &three); /* a = p - 3 */

    n00b_bignum_t qx, qy, e, rr, ss;
    n00b_bn_from_bytes(&qx, (uint8_t *)pub_xy->data, 48);
    n00b_bn_from_bytes(&qy, (uint8_t *)pub_xy->data + 48, 48);
    n00b_bn_from_bytes(&e, (uint8_t *)hash->data, (size_t)hash->byte_len);
    n00b_bn_from_bytes(&rr, (uint8_t *)r->data, (size_t)r->byte_len);
    n00b_bn_from_bytes(&ss, (uint8_t *)s->data, (size_t)s->byte_len);

    /* 1 <= r,s < n */
    if (n00b_bn_is_zero(&rr) || n00b_bn_ge(&rr, &n)) {
        return false;
    }
    if (n00b_bn_is_zero(&ss) || n00b_bn_ge(&ss, &n)) {
        return false;
    }

    n00b_bn_mod(&e, &e, &n);

    /* w = s^-1 mod n ; u1 = e*w ; u2 = r*w */
    n00b_bignum_t w, u1, u2, ntwo, nm2;
    n00b_bn_set_u32(&ntwo, 2);
    n00b_bn_sub(&nm2, &n, &ntwo);
    n00b_bn_powmod(&w, &ss, &nm2, &n);
    n00b_bn_mulmod(&u1, &e, &w, &n);
    n00b_bn_mulmod(&u2, &rr, &w, &n);

    /* R = u1*G + u2*Q */
    ecp_t G  = {.x = gx, .y = gy, .inf = false};
    ecp_t Q  = {.x = qx, .y = qy, .inf = false};
    ecp_t P1, P2, Rpt;
    ec_mul(&P1, &u1, &G, &p, &a);
    ec_mul(&P2, &u2, &Q, &p, &a);
    ec_add(&Rpt, &P1, &P2, &p, &a);
    if (Rpt.inf) {
        return false;
    }

    /* valid iff (R.x mod n) == r */
    n00b_bignum_t v;
    n00b_bn_mod(&v, &Rpt.x, &n);
    return n00b_bn_eq(&v, &rr);
}

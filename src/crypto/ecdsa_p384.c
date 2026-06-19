/*
 * ecdsa_p384.c — ECDSA verify on NIST P-384 (WP-042 Phase 3). See header.
 *
 * Jacobian projective point arithmetic over GF(p) using the shared bignum: a
 * point (X,Y,Z) represents affine (X/Z^2, Y/Z^3), Z==0 is the identity. This
 * keeps the whole scalar multiplication inversion-free; exactly one modular
 * inverse (Fermat, a^(p-2)) is taken at the very end to recover the affine
 * x-coordinate. (Affine arithmetic would take a full 384-bit modexp inside
 * every point double/add — ~1150 per verify — which is unusably slow.)
 * Verify-only (public inputs) so non-constant-time is fine. Curve
 * y^2 = x^3 - 3x + b, i.e. a = -3, which the doubling formula bakes in.
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
static const uint8_t P384_B[48] = {
    0xb3,0x31,0x2f,0xa7,0xe2,0x3e,0xe7,0xe4,0x98,0x8e,0x05,0x6b,
    0xe3,0xf8,0x2d,0x19,0x18,0x1d,0x9c,0x6e,0xfe,0x81,0x41,0x12,
    0x03,0x14,0x08,0x8f,0x50,0x13,0x87,0x5a,0xc6,0x56,0x39,0x8d,
    0x8a,0x2e,0xd1,0x9d,0x2a,0x85,0xc8,0xed,0xd3,0xec,0x2a,0xef};

/* Jacobian point (X,Y,Z) -> affine (X/Z^2, Y/Z^3); Z==0 is the identity. */
typedef struct {
    n00b_bignum_t X;
    n00b_bignum_t Y;
    n00b_bignum_t Z;
} jac_t;

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

static void
fsqr(n00b_bignum_t *r, const n00b_bignum_t *a, const n00b_bignum_t *p)
{
    n00b_bn_mulmod(r, a, a, p);
}

/* r = a^-1 mod p (Fermat: a^(p-2)); p prime. One call per verify. */
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
jac_set_identity(jac_t *R)
{
    n00b_bn_set_u32(&R->X, 1);
    n00b_bn_set_u32(&R->Y, 1);
    n00b_bn_zero(&R->Z); /* Z==0 marks the identity */
}

/* R = 2P, Jacobian doubling for a = -3 (EFD "dbl-2001-b"). */
static void
jac_double(jac_t *R, const jac_t *P, const n00b_bignum_t *p)
{
    if (n00b_bn_is_zero(&P->Z) || n00b_bn_is_zero(&P->Y)) {
        jac_set_identity(R);
        return;
    }
    n00b_bignum_t delta, gamma, beta, alpha, t1, t2, fourb, eightb, eg2;
    n00b_bignum_t x3, y3, z3;

    fsqr(&delta, &P->Z, p);          /* delta = Z^2 */
    fsqr(&gamma, &P->Y, p);          /* gamma = Y^2 */
    fmul(&beta, &P->X, &gamma, p);   /* beta  = X*gamma */
    fsub(&t1, &P->X, &delta, p);     /* X - delta */
    fadd(&t2, &P->X, &delta, p);     /* X + delta */
    fmul(&alpha, &t1, &t2, p);       /* (X-delta)(X+delta) */
    fadd(&t1, &alpha, &alpha, p);
    fadd(&alpha, &t1, &alpha, p);    /* alpha = 3*(X-delta)(X+delta) */

    fadd(&fourb, &beta, &beta, p);
    fadd(&fourb, &fourb, &fourb, p); /* 4*beta */
    fadd(&eightb, &fourb, &fourb, p);/* 8*beta */
    fsqr(&t1, &alpha, p);
    fsub(&x3, &t1, &eightb, p);      /* X3 = alpha^2 - 8*beta */

    fadd(&t1, &P->Y, &P->Z, p);
    fsqr(&t1, &t1, p);
    fsub(&t1, &t1, &gamma, p);
    fsub(&z3, &t1, &delta, p);       /* Z3 = (Y+Z)^2 - gamma - delta */

    fsub(&t1, &fourb, &x3, p);
    fmul(&y3, &alpha, &t1, p);       /* alpha*(4*beta - X3) */
    fsqr(&t2, &gamma, p);
    fadd(&t1, &t2, &t2, p);
    fadd(&t1, &t1, &t1, p);
    fadd(&eg2, &t1, &t1, p);         /* 8*gamma^2 */
    fsub(&y3, &y3, &eg2, p);         /* Y3 = alpha*(4*beta-X3) - 8*gamma^2 */

    R->X = x3;
    R->Y = y3;
    R->Z = z3;
}

/* R = P + Q, general Jacobian addition (EFD "add-2007-bl"). */
static void
jac_add(jac_t *R, const jac_t *P, const jac_t *Q, const n00b_bignum_t *p)
{
    if (n00b_bn_is_zero(&P->Z)) {
        *R = *Q;
        return;
    }
    if (n00b_bn_is_zero(&Q->Z)) {
        *R = *P;
        return;
    }
    n00b_bignum_t z1z1, z2z2, u1, u2, s1, s2, t1, t2;
    fsqr(&z1z1, &P->Z, p);
    fsqr(&z2z2, &Q->Z, p);
    fmul(&u1, &P->X, &z2z2, p);       /* U1 = X1*Z2^2 */
    fmul(&u2, &Q->X, &z1z1, p);       /* U2 = X2*Z1^2 */
    fmul(&t1, &Q->Z, &z2z2, p);
    fmul(&s1, &P->Y, &t1, p);         /* S1 = Y1*Z2^3 */
    fmul(&t1, &P->Z, &z1z1, p);
    fmul(&s2, &Q->Y, &t1, p);         /* S2 = Y2*Z1^3 */

    if (n00b_bn_eq(&u1, &u2)) {
        if (n00b_bn_eq(&s1, &s2)) {
            jac_double(R, P, p);      /* P == Q */
        }
        else {
            jac_set_identity(R);      /* P == -Q */
        }
        return;
    }

    n00b_bignum_t h, i, j, r, v, x3, y3, z3;
    fsub(&h, &u2, &u1, p);            /* H = U2 - U1 */
    fadd(&t1, &h, &h, p);
    fsqr(&i, &t1, p);                 /* I = (2H)^2 */
    fmul(&j, &h, &i, p);             /* J = H*I */
    fsub(&t1, &s2, &s1, p);
    fadd(&r, &t1, &t1, p);            /* r = 2*(S2 - S1) */
    fmul(&v, &u1, &i, p);            /* V = U1*I */

    fsqr(&t1, &r, p);
    fsub(&t1, &t1, &j, p);
    fadd(&t2, &v, &v, p);
    fsub(&x3, &t1, &t2, p);          /* X3 = r^2 - J - 2V */

    fsub(&t1, &v, &x3, p);
    fmul(&y3, &r, &t1, p);
    fmul(&t1, &s1, &j, p);
    fadd(&t1, &t1, &t1, p);
    fsub(&y3, &y3, &t1, p);          /* Y3 = r*(V-X3) - 2*S1*J */

    fadd(&t1, &P->Z, &Q->Z, p);
    fsqr(&t1, &t1, p);
    fsub(&t1, &t1, &z1z1, p);
    fsub(&t1, &t1, &z2z2, p);
    fmul(&z3, &t1, &h, p);           /* Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H */

    R->X = x3;
    R->Y = y3;
    R->Z = z3;
}

/* R = k*P (double-and-add, MSB first); inversion-free. */
static void
jac_mul(jac_t *R, const n00b_bignum_t *k, const jac_t *P, const n00b_bignum_t *p)
{
    jac_set_identity(R);
    int bits = k->n * 32;
    for (int i = bits - 1; i >= 0; i--) {
        jac_t tmp;
        jac_double(&tmp, R, p);
        *R = tmp;
        if ((k->w[i / 32] >> (i % 32)) & 1) {
            jac_t t2;
            jac_add(&t2, R, P, p);
            *R = t2;
        }
    }
}

bool
n00b_ecdsa_p384_verify(n00b_buffer_t *pub_xy, n00b_buffer_t *hash,
                       n00b_buffer_t *r, n00b_buffer_t *s)
{
    if (pub_xy == nullptr || hash == nullptr || r == nullptr || s == nullptr) {
        return false;
    }
    if (n00b_buffer_len(pub_xy) != 96) {
        return false;
    }

    n00b_bignum_t p, n, gx, gy;
    n00b_bn_from_bytes(&p, P384_P, 48);
    n00b_bn_from_bytes(&n, P384_N, 48);
    n00b_bn_from_bytes(&gx, P384_GX, 48);
    n00b_bn_from_bytes(&gy, P384_GY, 48);

    n00b_bignum_t qx, qy, e, rr, ss;
    n00b_bn_from_bytes(&qx, (uint8_t *)pub_xy->data, 48);
    n00b_bn_from_bytes(&qy, (uint8_t *)pub_xy->data + 48, 48);
    n00b_bn_from_bytes(&e, (uint8_t *)hash->data, (size_t)hash->byte_len);
    n00b_bn_from_bytes(&rr, (uint8_t *)r->data, (size_t)r->byte_len);
    n00b_bn_from_bytes(&ss, (uint8_t *)s->data, (size_t)s->byte_len);

    /* public-key validation: Qx,Qy < p and Q on the curve
     * y^2 = x^3 - 3x + b (mod p). Rejects invalid-curve / garbage points. */
    if (n00b_bn_ge(&qx, &p) || n00b_bn_ge(&qy, &p)) {
        return false;
    }
    {
        n00b_bignum_t b384, y2, x2, x3, threex, rhs;
        n00b_bn_from_bytes(&b384, P384_B, 48);
        fmul(&y2, &qy, &qy, &p);
        fmul(&x2, &qx, &qx, &p);
        fmul(&x3, &x2, &qx, &p);
        fadd(&threex, &qx, &qx, &p);
        fadd(&threex, &threex, &qx, &p); /* 3x */
        fsub(&rhs, &x3, &threex, &p);    /* x^3 - 3x */
        fadd(&rhs, &rhs, &b384, &p);     /* + b */
        if (!n00b_bn_eq(&y2, &rhs)) {
            return false;
        }
    }

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

    /* R = u1*G + u2*Q (Jacobian; G and Q start affine with Z=1). */
    jac_t G = {.X = gx, .Y = gy};
    jac_t Q = {.X = qx, .Y = qy};
    n00b_bn_set_u32(&G.Z, 1);
    n00b_bn_set_u32(&Q.Z, 1);
    jac_t P1, P2, Rj;
    jac_mul(&P1, &u1, &G, &p);
    jac_mul(&P2, &u2, &Q, &p);
    jac_add(&Rj, &P1, &P2, &p);
    if (n00b_bn_is_zero(&Rj.Z)) {
        return false; /* point at infinity */
    }

    /* recover affine x = X / Z^2 (the one inversion), then check (x mod n)==r */
    n00b_bignum_t zinv, zinv2, xaff, v;
    finv(&zinv, &Rj.Z, &p);
    fsqr(&zinv2, &zinv, &p);
    fmul(&xaff, &Rj.X, &zinv2, &p);
    n00b_bn_mod(&v, &xaff, &n);
    return n00b_bn_eq(&v, &rr);
}

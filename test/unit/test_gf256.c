/** @file test/unit/test_gf256.c — GF(2^8) finite-field arithmetic.
 *
 *  Known-answer + algebraic-law coverage for include/crypto/gf256.h:
 *
 *    [1] Table sanity: exp[0]=1, exp[1]=2, exp[8]=0x1D for the standard
 *        field; exp/log are mutual inverses across all 255 non-zero
 *        elements.
 *    [2] Multiplication: identity/zero, two low-degree products with no
 *        reduction, and one product that exercises the reduction path.
 *    [3] Inverse / division: a * a^-1 == 1 for every non-zero element;
 *        division undoes multiplication.
 *    [4] Distributivity: a*(b^c) == a*b ^ a*c over a broad sample.
 *    [5] Parameterization: re-init with the AES field (0x11B, gen 3)
 *        and confirm a documented AES multiplication vector, proving
 *        the reducing polynomial actually drives the arithmetic.
 */

#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "crypto/gf256.h"

static void
test_table_sanity(void)
{
    n00b_gf256_t gf;
    n00b_gf256_init(&gf);

    assert(gf.exp[0] == 1);
    assert(gf.exp[1] == 2);
    assert(gf.exp[2] == 4);
    // 2^8 reduces by x^8+x^4+x^3+x^2+1 -> 0x1D.
    assert(gf.exp[8] == 0x1D);

    // exp and log invert each other over the multiplicative group.
    for (int i = 0; i < 255; i++) {
        uint8_t e = gf.exp[i];
        assert(gf.log[e] == (uint8_t)i);
    }
    for (int x = 1; x < 256; x++) {
        assert(gf.exp[gf.log[x]] == (uint8_t)x);
    }

    printf("  [PASS] table sanity\n");
}

static void
test_mul(void)
{
    n00b_gf256_t gf;
    n00b_gf256_init(&gf);

    for (int a = 0; a < 256; a++) {
        assert(n00b_gf256_mul(&gf, (uint8_t)a, 0) == 0);
        assert(n00b_gf256_mul(&gf, 0, (uint8_t)a) == 0);
        assert(n00b_gf256_mul(&gf, (uint8_t)a, 1) == (uint8_t)a);
        assert(n00b_gf256_mul(&gf, 1, (uint8_t)a) == (uint8_t)a);
    }

    // (x+1)(x^2+x+1) = x^3+1  ->  0x03 * 0x07 = 0x09  (no reduction).
    assert(n00b_gf256_mul(&gf, 0x03, 0x07) == 0x09);
    // 2^7 * 2 = 2^8 = 0x1D  (exercises the reduction path).
    assert(n00b_gf256_mul(&gf, 0x80, 0x02) == 0x1D);

    // Commutativity over the full table.
    for (int a = 0; a < 256; a++) {
        for (int b = 0; b < 256; b++) {
            assert(n00b_gf256_mul(&gf, (uint8_t)a, (uint8_t)b)
                   == n00b_gf256_mul(&gf, (uint8_t)b, (uint8_t)a));
        }
    }

    printf("  [PASS] multiplication\n");
}

static void
test_inv_div(void)
{
    n00b_gf256_t gf;
    n00b_gf256_init(&gf);

    for (int a = 1; a < 256; a++) {
        uint8_t inv = n00b_gf256_inv(&gf, (uint8_t)a);
        assert(n00b_gf256_mul(&gf, (uint8_t)a, inv) == 1);
    }

    assert(n00b_gf256_div(&gf, 0x09, 0x03) == 0x07);
    assert(n00b_gf256_div(&gf, 0x09, 0x07) == 0x03);
    assert(n00b_gf256_div(&gf, 0x00, 0x07) == 0x00);

    // div undoes mul for every non-zero divisor.
    for (int a = 0; a < 256; a++) {
        for (int b = 1; b < 256; b++) {
            uint8_t p = n00b_gf256_mul(&gf, (uint8_t)a, (uint8_t)b);
            assert(n00b_gf256_div(&gf, p, (uint8_t)b) == (uint8_t)a);
        }
    }

    printf("  [PASS] inverse / division\n");
}

static void
test_distributivity(void)
{
    n00b_gf256_t gf;
    n00b_gf256_init(&gf);

    for (int a = 0; a < 256; a++) {
        for (int b = 0; b < 256; b += 7) {
            for (int c = 0; c < 256; c += 13) {
                uint8_t lhs = n00b_gf256_mul(&gf,
                                             (uint8_t)a,
                                             n00b_gf256_add((uint8_t)b,
                                                            (uint8_t)c));
                uint8_t rhs = n00b_gf256_add(
                    n00b_gf256_mul(&gf, (uint8_t)a, (uint8_t)b),
                    n00b_gf256_mul(&gf, (uint8_t)a, (uint8_t)c));
                assert(lhs == rhs);
            }
        }
    }

    printf("  [PASS] distributivity\n");
}

static void
test_pow(void)
{
    n00b_gf256_t gf;
    n00b_gf256_init(&gf);

    assert(n00b_gf256_pow(&gf, 0x02, 0) == 0x01);
    assert(n00b_gf256_pow(&gf, 0x02, 1) == 0x02);
    assert(n00b_gf256_pow(&gf, 0x02, 8) == 0x1D);
    assert(n00b_gf256_pow(&gf, 0x00, 0) == 0x01);
    assert(n00b_gf256_pow(&gf, 0x00, 5) == 0x00);

    // a^-1 via pow agrees with the dedicated inverse.
    for (int a = 1; a < 256; a++) {
        assert(n00b_gf256_pow(&gf, (uint8_t)a, -1)
               == n00b_gf256_inv(&gf, (uint8_t)a));
    }

    printf("  [PASS] exponentiation\n");
}

static void
test_aes_field(void)
{
    // The AES field GF(2^8) uses x^8+x^4+x^3+x+1 (0x11B), generator 3.
    n00b_gf256_t gf;
    n00b_gf256_init(&gf, .primitive = 0x11B, .generator = 3);

    // Documented AES products (generator-independent, poly-dependent).
    assert(n00b_gf256_mul(&gf, 0x57, 0x83) == 0xC1);
    assert(n00b_gf256_mul(&gf, 0x57, 0x02) == 0xAE);  // xtime, no reduce
    assert(n00b_gf256_mul(&gf, 0x80, 0x02) == 0x1B);  // xtime, reduce

    printf("  [PASS] AES-field parameterization\n");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    test_table_sanity();
    test_mul();
    test_inv_div();
    test_distributivity();
    test_pow();
    test_aes_field();

    fprintf(stderr, "All GF(2^8) tests passed.\n");
    return 0;
}

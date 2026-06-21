/** @file test/unit/test_reed_solomon.c — Reed-Solomon encoder.
 *
 *  Coverage for include/crypto/reed_solomon.h:
 *
 *    [1] Known-answer: the canonical "HELLO WORLD" version-1-M QR data
 *        block (16 data codewords -> 10 ECC codewords) must reproduce
 *        the documented parity bytes. This pins the generator-root
 *        convention (consecutive roots from alpha^0).
 *    [2] Defining property: for any data block, the full codeword
 *        (data || ecc) evaluated at each generator root alpha^i
 *        (i = 0..ecc_len-1) is zero. This validates the encoder as a
 *        genuine RS code independent of any memorized output.
 *    [3] All-zero data yields all-zero parity.
 *    [4] Contract violations (null data, non-positive ecc_len,
 *        data_len + ecc_len > 255) return nullptr.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "crypto/gf256.h"
#include "crypto/reed_solomon.h"

static n00b_buffer_t *
buf_of(const uint8_t *bytes, int64_t len)
{
    return n00b_buffer_from_bytes((char *)bytes, len);
}

// Evaluate the codeword polynomial (highest-degree coefficient first) at
// `x` via Horner's method over the field.
static uint8_t
poly_eval(const n00b_gf256_t *gf, const uint8_t *coeffs, size_t n, uint8_t x)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc = n00b_gf256_add(n00b_gf256_mul(gf, acc, x), coeffs[i]);
    }
    return acc;
}

static void
test_hello_world_vector(void)
{
    // "HELLO WORLD", alphanumeric mode, QR version 1, ECC level M.
    static const uint8_t data[] = {
        32, 91, 11, 120, 209, 114, 220, 77,
        67, 64, 236, 17, 236, 17, 236, 17,
    };
    static const uint8_t expect_ecc[] = {
        196, 35, 39, 119, 235, 215, 231, 226, 93, 23,
    };

    n00b_result_t(n00b_buffer_t *) r = n00b_rs_encode(buf_of(data,
                                                             sizeof(data)),
                                                      10);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *ecc = n00b_result_get(r);
    assert(ecc->byte_len == sizeof(expect_ecc));
    assert(memcmp(ecc->data, expect_ecc, sizeof(expect_ecc)) == 0);

    printf("  [PASS] HELLO WORLD known-answer vector\n");
}

static void
test_codeword_roots_zero(void)
{
    n00b_gf256_t gf;
    n00b_gf256_init(&gf);

    static const uint8_t data[] = {
        0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xFF, 0x00, 0x7A,
    };

    for (int32_t ecc_len = 2; ecc_len <= 30; ecc_len++) {
        n00b_result_t(n00b_buffer_t *) r = n00b_rs_encode(buf_of(data,
                                                                 sizeof(data)),
                                                          ecc_len);
        assert(n00b_result_is_ok(r));
        n00b_buffer_t *ecc = n00b_result_get(r);
        assert((int32_t)ecc->byte_len == ecc_len);

        // Build the full codeword: data followed by the parity bytes.
        size_t   n        = sizeof(data) + (size_t)ecc_len;
        uint8_t *codeword = n00b_alloc_array_with_opts(
            uint8_t, n, &(n00b_alloc_opts_t){.no_scan = true});
        memcpy(codeword, data, sizeof(data));
        memcpy(codeword + sizeof(data), ecc->data, (size_t)ecc_len);

        // Every generator root must be a zero of the codeword.
        for (int32_t i = 0; i < ecc_len; i++) {
            uint8_t root = gf.exp[i];
            assert(poly_eval(&gf, codeword, n, root) == 0);
        }
    }

    printf("  [PASS] codeword vanishes at all generator roots\n");
}

static void
test_zero_data(void)
{
    static const uint8_t zeros[8] = {0};

    n00b_result_t(n00b_buffer_t *) r = n00b_rs_encode(buf_of(zeros,
                                                             sizeof(zeros)),
                                                      12);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *ecc = n00b_result_get(r);
    assert(ecc->byte_len == 12);
    for (size_t i = 0; i < ecc->byte_len; i++) {
        assert(((uint8_t *)ecc->data)[i] == 0);
    }

    printf("  [PASS] zero data -> zero parity\n");
}

static void
test_contract_violations(void)
{
    static const uint8_t data[4] = {1, 2, 3, 4};
    n00b_result_t(n00b_buffer_t *) r;

    r = n00b_rs_encode(nullptr, 4);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_RS_ERR_NULL_DATA);

    r = n00b_rs_encode(buf_of(data, sizeof(data)), 0);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_RS_ERR_BAD_ECC_LEN);

    r = n00b_rs_encode(buf_of(data, sizeof(data)), -1);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_RS_ERR_BAD_ECC_LEN);

    // data_len + ecc_len must be <= 255 (single-block limit).
    static uint8_t big[250] = {0};

    r = n00b_rs_encode(buf_of(big, sizeof(big)), 10);  // 260 > 255
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_RS_ERR_BLOCK_TOO_LARGE);

    r = n00b_rs_encode(buf_of(big, sizeof(big)), 5);   // 255, exactly fits
    assert(n00b_result_is_ok(r));

    // Every error code has a non-empty description.
    assert(n00b_rs_err_str(N00B_RS_ERR_NULL_DATA) != nullptr);
    assert(n00b_rs_err_str(N00B_RS_ERR_BAD_ECC_LEN) != nullptr);
    assert(n00b_rs_err_str(N00B_RS_ERR_BLOCK_TOO_LARGE) != nullptr);

    printf("  [PASS] contract violations return typed errors\n");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    test_hello_world_vector();
    test_codeword_roots_zero();
    test_zero_data();
    test_contract_violations();

    fprintf(stderr, "All Reed-Solomon encoder tests passed.\n");
    return 0;
}

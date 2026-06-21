/** @file test/unit/test_qr_codewords.c — QR data-encoding + ECC stage.
 *
 *  Validates _n00b_qr_make_codewords (internal/text/qrcode_internal.h):
 *
 *    [1] Full known-answer: "HELLO WORLD" at ECC level M selects
 *        version 1, alphanumeric mode, and produces the documented
 *        26-codeword stream (16 data + 10 ECC). This exercises mode
 *        selection, bit packing, padding, and (single-block) ECC end to
 *        end against an externally known vector.
 *    [2] Byte-mode selection + header packing: a lowercase URL selects
 *        byte mode; the first codeword encodes mode 0100 + the high bits
 *        of the character count.
 *    [3] Empty input -> N00B_QR_ERR_EMPTY_INPUT.
 *    [4] Oversized input -> N00B_QR_ERR_TOO_LARGE.
 *    [5] Multi-block structural check (v5-Q): correct version and total
 *        interleaved codeword length.
 *
 *  NOTE (disclosed gap): the multi-block *interleave order* is not
 *  checked against an external vector here; that is covered end-to-end
 *  by the matrix/reference test in the next slice. ECC correctness
 *  itself is exercised by [1] (same RS path) and the reed_solomon test.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/alloc.h"
#include "text/qrcode/qrcode.h"
#include "internal/text/qrcode_internal.h"

static void
test_hello_world_codewords(void)
{
    static const uint8_t expect[] = {
        // 16 data codewords
        32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17,
        // 10 ECC codewords
        196, 35, 39, 119, 235, 215, 231, 226, 93, 23,
    };

    n00b_result_t(n00b_qr_codeword_plan_t *) r =
        _n00b_qr_make_codewords(r"HELLO WORLD", N00B_QR_ECC_M);
    assert(n00b_result_is_ok(r));

    n00b_qr_codeword_plan_t *plan = n00b_result_get(r);
    assert(plan->version == 1);
    assert(plan->mode == N00B_QR_MODE_ALNUM);
    assert(plan->codewords->byte_len == sizeof(expect));
    assert(memcmp(plan->codewords->data, expect, sizeof(expect)) == 0);

    printf("  [PASS] HELLO WORLD v1-M codeword stream\n");
}

static void
test_byte_mode_header(void)
{
    // 23 bytes, contains lowercase + '/' => byte mode.
    n00b_result_t(n00b_qr_codeword_plan_t *) r =
        _n00b_qr_make_codewords(r"https://example.com/abc", N00B_QR_ECC_M);
    assert(n00b_result_is_ok(r));

    n00b_qr_codeword_plan_t *plan = n00b_result_get(r);
    assert(plan->mode == N00B_QR_MODE_BYTE);

    // First codeword: mode 0100, then top 4 bits of the 8-bit count.
    // count = 23 = 0001_0111, so byte = 0100_0001 = 0x41.
    uint8_t first = ((uint8_t *)plan->codewords->data)[0];
    assert(first == 0x41);

    printf("  [PASS] byte-mode selection + header packing\n");
}

static void
test_empty_input(void)
{
    n00b_result_t(n00b_qr_codeword_plan_t *) r =
        _n00b_qr_make_codewords(r"", N00B_QR_ECC_M);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QR_ERR_EMPTY_INPUT);

    printf("  [PASS] empty input rejected\n");
}

static void
test_too_large(void)
{
    // 300 bytes exceeds the v10 byte-mode capacity at every ECC level.
    char buf[301];
    for (int i = 0; i < 300; i++) {
        buf[i] = 'a';
    }
    buf[300] = '\0';

    n00b_result_t(n00b_qr_codeword_plan_t *) r =
        _n00b_qr_make_codewords(n00b_string_from_cstr(buf), N00B_QR_ECC_H);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QR_ERR_TOO_LARGE);

    printf("  [PASS] oversized input rejected\n");
}

static void
test_multiblock_structure(void)
{
    // ~50 lowercase bytes -> byte mode, needs ~52 data codewords, which
    // first fits at version 5 (v4-Q=48 data, v5-Q=62 data). v5-Q uses 4
    // blocks with 18 ECC codewords each: 62 data + 4*18 = 134 total.
    char buf[51];
    for (int i = 0; i < 50; i++) {
        buf[i] = 'x';
    }
    buf[50] = '\0';

    n00b_result_t(n00b_qr_codeword_plan_t *) r =
        _n00b_qr_make_codewords(n00b_string_from_cstr(buf), N00B_QR_ECC_Q);
    assert(n00b_result_is_ok(r));

    n00b_qr_codeword_plan_t *plan = n00b_result_get(r);
    assert(plan->version == 5);
    assert(plan->mode == N00B_QR_MODE_BYTE);
    assert(plan->codewords->byte_len == 134);

    printf("  [PASS] multi-block (v5-Q) version + length\n");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    test_hello_world_codewords();
    test_byte_mode_header();
    test_empty_input();
    test_too_large();
    test_multiblock_structure();

    fprintf(stderr, "All QR codeword-stage tests passed.\n");
    return 0;
}

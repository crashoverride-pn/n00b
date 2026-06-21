/** @file test/unit/test_qr_matrix.c — QR matrix round-trip self-decode.
 *
 *  Validates n00b_qr_encode by independently decoding the generated
 *  module matrix and checking it reproduces the (independently trusted)
 *  interleaved codeword stream from _n00b_qr_make_codewords.
 *
 *  The decoder here re-derives the function-module map from first
 *  principles (finders, timing, alignment, version + format reservation,
 *  dark module), reads the format information to recover the mask,
 *  unmasks, walks the same zigzag, and extracts the codeword bytes. It
 *  is deliberately independent of qrcode.c's internals so that a bug in
 *  placement, masking, format encoding, or interleave order is caught.
 *
 *  Coverage: v1 (no alignment / no version info), v2 (one alignment),
 *  v5-Q (multi-block), v8 (version info + 6 alignments + multi-block).
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

// Alignment-pattern centers, transcribed independently (cross-check vs.
// the encoder's own table).
static const uint8_t apos[10][3] = {
    {0, 0, 0}, {6, 18, 0}, {6, 22, 0}, {6, 26, 0}, {6, 30, 0},
    {6, 34, 0}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
};
static const uint8_t acnt[10] = {0, 2, 2, 2, 2, 2, 3, 3, 3, 3};

static uint8_t *
alloc_bytes(int32_t n)
{
    return n00b_alloc_array_with_opts(uint8_t, n,
                                      &(n00b_alloc_opts_t){.no_scan = true});
}

// Reconstruct the function-module map independently of qrcode.c.
static void
build_fn(int32_t version, int32_t size, uint8_t *fn)
{
    memset(fn, 0, (size_t)size * size);

    int32_t centers[3][2] = {{3, 3}, {3, size - 4}, {size - 4, 3}};
    for (int t = 0; t < 3; t++) {
        for (int dy = -4; dy <= 4; dy++) {
            for (int dx = -4; dx <= 4; dx++) {
                int r = centers[t][0] + dy, c = centers[t][1] + dx;
                if (r >= 0 && r < size && c >= 0 && c < size) {
                    fn[r * size + c] = 1;
                }
            }
        }
    }
    for (int i = 0; i < size; i++) {
        fn[6 * size + i] = 1;
        fn[i * size + 6] = 1;
    }
    int n = acnt[version - 1];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == n - 1)
                || (i == n - 1 && j == 0)) {
                continue;
            }
            int cr = apos[version - 1][i], cc = apos[version - 1][j];
            for (int dy = -2; dy <= 2; dy++) {
                for (int dx = -2; dx <= 2; dx++) {
                    fn[(cr + dy) * size + (cc + dx)] = 1;
                }
            }
        }
    }
    if (version >= 7) {
        for (int i = 0; i < 18; i++) {
            int a = size - 11 + (i % 3), b = i / 3;
            fn[b * size + a] = 1;
            fn[a * size + b] = 1;
        }
    }
    for (int i = 0; i <= 5; i++) {
        fn[i * size + 8] = 1;
    }
    fn[7 * size + 8] = 1;
    fn[8 * size + 8] = 1;
    fn[8 * size + 7] = 1;
    for (int i = 9; i < 15; i++) {
        fn[8 * size + (14 - i)] = 1;
    }
    for (int i = 0; i < 8; i++) {
        fn[8 * size + (size - 1 - i)] = 1;
    }
    for (int i = 8; i < 15; i++) {
        fn[(size - 15 + i) * size + 8] = 1;
    }
    fn[(size - 8) * size + 8] = 1;
}

// Read the format information (first copy) and recover the mask + ECC.
static void
read_format(const uint8_t *m, int32_t size, int32_t *mask, int32_t *ecc_fmt)
{
    int32_t bits = 0;
    for (int i = 0; i <= 5; i++) {
        bits |= (m[i * size + 8] & 1) << i;
    }
    bits |= (m[7 * size + 8] & 1) << 6;
    bits |= (m[8 * size + 8] & 1) << 7;
    bits |= (m[8 * size + 7] & 1) << 8;
    for (int i = 9; i < 15; i++) {
        bits |= (m[8 * size + (14 - i)] & 1) << i;
    }
    int32_t data = ((bits ^ 0x5412) >> 10) & 0x1F;
    *mask        = data & 0x7;
    *ecc_fmt     = (data >> 3) & 0x3;
}

static int
mask_cond(int mask, int r, int c)
{
    switch (mask) {
    case 0: return (r + c) % 2 == 0;
    case 1: return r % 2 == 0;
    case 2: return c % 3 == 0;
    case 3: return (r + c) % 3 == 0;
    case 4: return ((r / 2) + (c / 3)) % 2 == 0;
    case 5: return (r * c) % 2 + (r * c) % 3 == 0;
    case 6: return ((r * c) % 2 + (r * c) % 3) % 2 == 0;
    case 7: return ((r + c) % 2 + (r * c) % 3) % 2 == 0;
    default: return 0;
    }
}

// Walk the zigzag, unmask, and extract `outlen` codeword bytes.
static void
extract(const uint8_t *m, const uint8_t *fn, int32_t size, int mask,
        uint8_t *out, int32_t outlen)
{
    memset(out, 0, (size_t)outlen);
    int idx = 0;
    for (int right = size - 1; right >= 1; right -= 2) {
        if (right == 6) {
            right = 5;
        }
        for (int vert = 0; vert < size; vert++) {
            for (int j = 0; j < 2; j++) {
                int c  = right - j;
                int up = ((right + 1) & 2) == 0;
                int r  = up ? (size - 1 - vert) : vert;
                if (!fn[r * size + c]) {
                    int bit = m[r * size + c] & 1;
                    if (mask_cond(mask, r, c)) {
                        bit ^= 1;
                    }
                    if (idx < outlen * 8) {
                        out[idx >> 3] |= bit << (7 - (idx & 7));
                        idx++;
                    }
                }
            }
        }
    }
}

// Map the 2-bit format ECC code back to n00b_qr_ecc_t.
static n00b_qr_ecc_t
ecc_from_format(int32_t fmt)
{
    switch (fmt) {
    case 1: return N00B_QR_ECC_L;
    case 0: return N00B_QR_ECC_M;
    case 3: return N00B_QR_ECC_Q;
    default: return N00B_QR_ECC_H;  // 2
    }
}

static void
roundtrip(n00b_string_t *input, n00b_qr_ecc_t ecc, int32_t expect_version,
          const char *label)
{
    n00b_result_t(n00b_qr_codeword_plan_t *) cwr =
        _n00b_qr_make_codewords(input, ecc);
    assert(n00b_result_is_ok(cwr));
    n00b_qr_codeword_plan_t *plan = n00b_result_get(cwr);

    n00b_result_t(n00b_qr_t *) qrr = n00b_qr_encode(input, .ecc = ecc);
    assert(n00b_result_is_ok(qrr));
    n00b_qr_t *qr = n00b_result_get(qrr);

    assert(qr->version == expect_version);
    assert(qr->size == 4 * expect_version + 17);

    // Finder corners present (cheap structural sanity).
    assert(qr->modules[0] == 1);
    assert(qr->modules[3 * qr->size + 3] == 1);

    uint8_t *fn = alloc_bytes(qr->size * qr->size);
    build_fn(qr->version, qr->size, fn);

    int32_t mask, ecc_fmt;
    read_format(qr->modules, qr->size, &mask, &ecc_fmt);
    assert(mask == qr->mask);
    assert(ecc_from_format(ecc_fmt) == ecc);

    int32_t  outlen = (int32_t)plan->codewords->byte_len;
    uint8_t *out    = alloc_bytes(outlen);
    extract(qr->modules, fn, qr->size, mask, out, outlen);

    assert(memcmp(out, plan->codewords->data, (size_t)outlen) == 0);
    printf("  [PASS] round-trip %s (v%d, mask %d)\n", label, qr->version, mask);
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    // v1: alphanumeric, no alignment, no version info.
    roundtrip(r"HELLO WORLD", N00B_QR_ECC_M, 1, "HELLO WORLD");

    // v2: byte mode, one alignment pattern.
    roundtrip(r"https://example.com/abc", N00B_QR_ECC_M, 2, "short URL");

    // v5-Q: byte mode, multi-block interleave.
    {
        char buf[51];
        memset(buf, 'x', 50);
        buf[50] = '\0';
        roundtrip(n00b_string_from_cstr(buf), N00B_QR_ECC_Q, 5, "v5-Q");
    }

    // v8: byte mode, version information + 6 alignments + multi-block.
    {
        char buf[161];
        memset(buf, 'a', 160);
        buf[160] = '\0';
        roundtrip(n00b_string_from_cstr(buf), N00B_QR_ECC_L, 8, "v8");
    }

    fprintf(stderr, "All QR matrix round-trip tests passed.\n");
    return 0;
}

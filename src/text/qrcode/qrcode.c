// QR code generation. This translation unit currently implements the
// data-encoding + ECC-interleaving stage (see
// internal/text/qrcode_internal.h); matrix placement + masking + the
// renderer land in a later slice.
//
// Numeric tables (ECC block structure) are transcribed from the
// ISO/IEC 18004 error-correction characteristics for versions 1-10 and
// cross-checked: g1_blocks*g1_dcw + g2_blocks*g2_dcw equals the spec's
// data-codeword count, and (blocks*ecc_per_block + data) equals the
// per-version total codeword count.

#include "internal/text/qrcode_internal.h"

#include "core/buffer.h"
#include "core/alloc.h"
#include "core/string.h"
#include "crypto/reed_solomon.h"

#include "text/strings/theme.h"
#include "text/strings/text_style.h"
#include "text/strings/style_ops.h"
#include "display/render/plane.h"

#include "util/assert.h"

#include <string.h>

// --------------------------------------------------------------------
// Spec tables (versions 1-10)
// --------------------------------------------------------------------

typedef struct {
    uint8_t ecc_per_block;
    uint8_t g1_blocks;
    uint8_t g1_dcw;
    uint8_t g2_blocks;
    uint8_t g2_dcw;
} qr_ecc_block_t;

// Indexed [version-1][ecc level: L=0, M=1, Q=2, H=3].
static const qr_ecc_block_t qr_ecc_tbl[10][4] = {
    // v1
    {{7, 1, 19, 0, 0}, {10, 1, 16, 0, 0}, {13, 1, 13, 0, 0}, {17, 1, 9, 0, 0}},
    // v2
    {{10, 1, 34, 0, 0}, {16, 1, 28, 0, 0}, {22, 1, 22, 0, 0}, {28, 1, 16, 0, 0}},
    // v3
    {{15, 1, 55, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 17, 0, 0}, {22, 2, 13, 0, 0}},
    // v4
    {{20, 1, 80, 0, 0}, {18, 2, 32, 0, 0}, {26, 2, 24, 0, 0}, {16, 4, 9, 0, 0}},
    // v5
    {{26, 1, 108, 0, 0}, {24, 2, 43, 0, 0}, {18, 2, 15, 2, 16}, {22, 2, 11, 2, 12}},
    // v6
    {{18, 2, 68, 0, 0}, {16, 4, 27, 0, 0}, {24, 4, 19, 0, 0}, {28, 4, 15, 0, 0}},
    // v7
    {{20, 2, 78, 0, 0}, {18, 4, 31, 0, 0}, {18, 2, 14, 4, 15}, {26, 4, 13, 1, 14}},
    // v8
    {{24, 2, 97, 0, 0}, {22, 2, 38, 2, 39}, {22, 4, 18, 2, 19}, {26, 4, 14, 2, 15}},
    // v9
    {{30, 2, 116, 0, 0}, {22, 3, 36, 2, 37}, {20, 4, 16, 4, 17}, {24, 4, 12, 4, 13}},
    // v10
    {{18, 2, 68, 2, 69}, {26, 4, 43, 1, 44}, {24, 6, 19, 2, 20}, {28, 6, 15, 2, 16}},
};

#define QR_MAX_VERSION 10

// Total data codewords available for (version, ecc).
static int32_t
qr_total_data(int32_t version, n00b_qr_ecc_t ecc)
{
    const qr_ecc_block_t *t = &qr_ecc_tbl[version - 1][ecc];
    return (int32_t)t->g1_blocks * t->g1_dcw + (int32_t)t->g2_blocks * t->g2_dcw;
}

// Character-count-indicator width in bits. Versions 1-9 and 10 differ.
static int32_t
qr_count_bits(int32_t version, n00b_qr_mode_t mode)
{
    if (mode == N00B_QR_MODE_BYTE) {
        return version <= 9 ? 8 : 16;
    }
    return version <= 9 ? 9 : 11;  // alphanumeric
}

// QR alphanumeric value for a byte, or -1 if not in the set.
static int32_t
qr_alnum_value(uint8_t c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 10;
    }
    switch (c) {
    case ' ':
        return 36;
    case '$':
        return 37;
    case '%':
        return 38;
    case '*':
        return 39;
    case '+':
        return 40;
    case '-':
        return 41;
    case '.':
        return 42;
    case '/':
        return 43;
    case ':':
        return 44;
    default:
        return -1;
    }
}

// --------------------------------------------------------------------
// Bit writer (MSB-first into a byte buffer)
// --------------------------------------------------------------------

typedef struct {
    uint8_t *buf;
    size_t   bitpos;
} qr_bitw_t;

static void
qr_put_bits(qr_bitw_t *w, uint32_t value, int32_t nbits)
{
    for (int32_t i = nbits - 1; i >= 0; i--) {
        if ((value >> i) & 1u) {
            w->buf[w->bitpos >> 3] |= (uint8_t)(0x80u >> (w->bitpos & 7));
        }
        w->bitpos++;
    }
}

// --------------------------------------------------------------------
// Stage: data encoding + ECC interleaving
// --------------------------------------------------------------------

n00b_result_t(n00b_qr_codeword_plan_t *)
_n00b_qr_make_codewords(n00b_string_t *data, n00b_qr_ecc_t ecc) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (ecc < N00B_QR_ECC_L || ecc > N00B_QR_ECC_H) {
        return n00b_result_err(n00b_qr_codeword_plan_t *, N00B_QR_ERR_BAD_ECC);
    }
    if (data == nullptr || data->u8_bytes == 0) {
        return n00b_result_err(n00b_qr_codeword_plan_t *,
                               N00B_QR_ERR_EMPTY_INPUT);
    }

    const uint8_t *bytes  = (const uint8_t *)data->data;
    size_t         nbytes = data->u8_bytes;

    // Whole-string mode selection: alphanumeric if every byte qualifies.
    n00b_qr_mode_t mode = N00B_QR_MODE_ALNUM;
    for (size_t i = 0; i < nbytes; i++) {
        if (qr_alnum_value(bytes[i]) < 0) {
            mode = N00B_QR_MODE_BYTE;
            break;
        }
    }

    // Payload bit count is version-independent for these two modes.
    size_t payload_bits;
    if (mode == N00B_QR_MODE_BYTE) {
        payload_bits = nbytes * 8;
    }
    else {
        payload_bits = (nbytes / 2) * 11 + (nbytes % 2) * 6;
    }

    // Pick the smallest version whose data capacity holds the segment.
    int32_t version    = 0;
    int32_t total_data = 0;
    for (int32_t v = 1; v <= QR_MAX_VERSION; v++) {
        size_t need = 4 + (size_t)qr_count_bits(v, mode) + payload_bits;
        int32_t cap = qr_total_data(v, ecc);
        if (need <= (size_t)cap * 8) {
            version    = v;
            total_data = cap;
            break;
        }
    }
    if (version == 0) {
        return n00b_result_err(n00b_qr_codeword_plan_t *, N00B_QR_ERR_TOO_LARGE);
    }

    // --- Build the data codewords ---
    uint8_t *dcw = n00b_alloc_array_with_opts(
        uint8_t,
        total_data,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});

    qr_bitw_t w = {.buf = dcw, .bitpos = 0};

    // Mode indicator: alphanumeric 0010, byte 0100.
    qr_put_bits(&w, mode == N00B_QR_MODE_BYTE ? 0x4 : 0x2, 4);
    // Character count indicator.
    qr_put_bits(&w, (uint32_t)nbytes, qr_count_bits(version, mode));

    // Payload.
    if (mode == N00B_QR_MODE_BYTE) {
        for (size_t i = 0; i < nbytes; i++) {
            qr_put_bits(&w, bytes[i], 8);
        }
    }
    else {
        size_t i = 0;
        for (; i + 1 < nbytes; i += 2) {
            int32_t v = qr_alnum_value(bytes[i]) * 45 + qr_alnum_value(bytes[i + 1]);
            qr_put_bits(&w, (uint32_t)v, 11);
        }
        if (i < nbytes) {
            qr_put_bits(&w, (uint32_t)qr_alnum_value(bytes[i]), 6);
        }
    }

    // Terminator: up to four 0 bits, not past capacity. The buffer is
    // zero-filled, so we only need to advance the cursor.
    size_t cap_bits = (size_t)total_data * 8;
    size_t term     = cap_bits - w.bitpos;
    if (term > 4) {
        term = 4;
    }
    w.bitpos += term;
    // Pad to a byte boundary (zero bits, already present).
    if (w.bitpos & 7) {
        w.bitpos = (w.bitpos + 7) & ~(size_t)7;
    }
    // Pad bytes alternate 0xEC, 0x11 to fill the capacity.
    for (size_t b = w.bitpos >> 3; b < (size_t)total_data; b++) {
        dcw[b] = ((b - (w.bitpos >> 3)) & 1) ? 0x11 : 0xEC;
    }

    // --- ECC per block + interleave ---
    const qr_ecc_block_t *t           = &qr_ecc_tbl[version - 1][ecc];
    int32_t               nblocks     = t->g1_blocks + t->g2_blocks;
    int32_t               ecc_per_blk = t->ecc_per_block;

    // Per-block data slices (into dcw) and ECC byte arrays. v1-10 use at
    // most 8 blocks; 16 is a safe fixed upper bound.
    const uint8_t *blk_data[16];
    int32_t        blk_dlen[16];
    const uint8_t *blk_ecc[16];

    size_t off = 0;
    for (int32_t b = 0; b < nblocks; b++) {
        int32_t dlen = (b < t->g1_blocks) ? t->g1_dcw : t->g2_dcw;
        blk_data[b]  = dcw + off;
        blk_dlen[b]  = dlen;
        off += (size_t)dlen;

        n00b_buffer_t *src = n00b_buffer_from_bytes((char *)(dcw + (off - dlen)),
                                                    dlen);
        n00b_result_t(n00b_buffer_t *) er = n00b_rs_encode(src,
                                                           ecc_per_blk,
                                                           .allocator = allocator);
        // Block sizes are well within the 255-symbol RS limit, so this
        // is an internal invariant, not a user-facing failure.
        n00b_require(n00b_result_is_ok(er),
                     "qr: reed-solomon encode failed on a sized block");
        blk_ecc[b] = (const uint8_t *)n00b_result_get(er)->data;
    }

    int32_t max_dcw = t->g1_dcw > t->g2_dcw ? t->g1_dcw : t->g2_dcw;
    int32_t out_len = total_data + nblocks * ecc_per_blk;

    n00b_buffer_t *out = n00b_buffer_new((int64_t)out_len, .allocator = allocator);
    n00b_buffer_resize(out, (uint64_t)out_len);
    uint8_t *o   = (uint8_t *)out->data;
    int32_t  pos = 0;

    // Interleave data codewords column-major across blocks.
    for (int32_t i = 0; i < max_dcw; i++) {
        for (int32_t b = 0; b < nblocks; b++) {
            if (i < blk_dlen[b]) {
                o[pos++] = blk_data[b][i];
            }
        }
    }
    // Interleave ECC codewords column-major across blocks.
    for (int32_t i = 0; i < ecc_per_blk; i++) {
        for (int32_t b = 0; b < nblocks; b++) {
            o[pos++] = blk_ecc[b][i];
        }
    }

    n00b_qr_codeword_plan_t *plan = n00b_alloc(n00b_qr_codeword_plan_t,
                                               .allocator = allocator);
    plan->version   = version;
    plan->ecc       = ecc;
    plan->mode      = mode;
    plan->codewords = out;

    return n00b_result_ok(n00b_qr_codeword_plan_t *, plan);
}

// ====================================================================
// Matrix assembly
// ====================================================================

// Alignment-pattern center coordinates per version (v1 has none).
static const uint8_t qr_align_pos[10][3] = {
    {0, 0, 0},     // v1
    {6, 18, 0},    // v2
    {6, 22, 0},    // v3
    {6, 26, 0},    // v4
    {6, 30, 0},    // v5
    {6, 34, 0},    // v6
    {6, 22, 38},   // v7
    {6, 24, 42},   // v8
    {6, 26, 46},   // v9
    {6, 28, 50},   // v10
};
static const uint8_t qr_align_count[10] = {0, 2, 2, 2, 2, 2, 3, 3, 3, 3};

// ECC format-info 2-bit codes indexed by n00b_qr_ecc_t (L, M, Q, H).
static const uint8_t qr_ecc_format[4] = {1, 0, 3, 2};

typedef struct {
    int32_t  size;
    int32_t  version;
    uint8_t *mod;  // 1 = dark
    uint8_t *fn;   // 1 = function / reserved (skipped by data + masking)
} qr_canvas_t;

static inline int32_t
qr_idx(const qr_canvas_t *cv, int32_t r, int32_t c)
{
    return r * cv->size + c;
}

static inline void
qr_setf(qr_canvas_t *cv, int32_t r, int32_t c, int dark)
{
    cv->mod[qr_idx(cv, r, c)] = dark ? 1 : 0;
    cv->fn[qr_idx(cv, r, c)]  = 1;
}

static inline int32_t
qr_iabs(int32_t v)
{
    return v < 0 ? -v : v;
}

static inline int32_t
qr_max2(int32_t a, int32_t b)
{
    return a > b ? a : b;
}

// Finder pattern + surrounding separator, given the center module.
static void
qr_draw_finder(qr_canvas_t *cv, int32_t cr, int32_t cc)
{
    for (int32_t dy = -4; dy <= 4; dy++) {
        for (int32_t dx = -4; dx <= 4; dx++) {
            int32_t r = cr + dy, c = cc + dx;
            if (r < 0 || r >= cv->size || c < 0 || c >= cv->size) {
                continue;
            }
            int32_t dist = qr_max2(qr_iabs(dx), qr_iabs(dy));
            qr_setf(cv, r, c, dist != 2 && dist != 4);
        }
    }
}

// 5x5 alignment pattern centered at (cr, cc).
static void
qr_draw_alignment(qr_canvas_t *cv, int32_t cr, int32_t cc)
{
    for (int32_t dy = -2; dy <= 2; dy++) {
        for (int32_t dx = -2; dx <= 2; dx++) {
            int32_t dist = qr_max2(qr_iabs(dx), qr_iabs(dy));
            qr_setf(cv, cr + dy, cc + dx, dist != 1);
        }
    }
}

static void
qr_place_alignments(qr_canvas_t *cv)
{
    int32_t n = qr_align_count[cv->version - 1];
    for (int32_t i = 0; i < n; i++) {
        for (int32_t j = 0; j < n; j++) {
            // Skip the three centers that overlap finder patterns.
            if ((i == 0 && j == 0) || (i == 0 && j == n - 1)
                || (i == n - 1 && j == 0)) {
                continue;
            }
            qr_draw_alignment(cv,
                              qr_align_pos[cv->version - 1][i],
                              qr_align_pos[cv->version - 1][j]);
        }
    }
}

static void
qr_draw_timing(qr_canvas_t *cv)
{
    for (int32_t i = 0; i < cv->size; i++) {
        int dark = (i % 2) == 0;
        qr_setf(cv, 6, i, dark);
        qr_setf(cv, i, 6, dark);
    }
}

// 15-bit BCH(15,5) format information, masked with 0x5412.
static int32_t
qr_format_bits(n00b_qr_ecc_t ecc, int32_t mask)
{
    int32_t data = (qr_ecc_format[ecc] << 3) | mask;  // 5 bits
    int32_t rem  = data;
    for (int i = 0; i < 10; i++) {
        rem <<= 1;
        if (rem & 0x400) {
            rem ^= 0x537;
        }
    }
    return ((data << 10) | rem) ^ 0x5412;
}

// 18-bit BCH(18,6) version information (versions 7+).
static int32_t
qr_version_bits(int32_t version)
{
    int32_t rem = version;
    for (int i = 0; i < 12; i++) {
        rem <<= 1;
        if (rem & 0x1000) {
            rem ^= 0x1F25;
        }
    }
    return (version << 12) | rem;
}

static void
qr_draw_format(qr_canvas_t *cv, n00b_qr_ecc_t ecc, int32_t mask)
{
    int32_t bits = qr_format_bits(ecc, mask);
    int32_t size = cv->size;

    // First copy, around the top-left finder.
    for (int32_t i = 0; i <= 5; i++) {
        qr_setf(cv, i, 8, (bits >> i) & 1);
    }
    qr_setf(cv, 7, 8, (bits >> 6) & 1);
    qr_setf(cv, 8, 8, (bits >> 7) & 1);
    qr_setf(cv, 8, 7, (bits >> 8) & 1);
    for (int32_t i = 9; i < 15; i++) {
        qr_setf(cv, 8, 14 - i, (bits >> i) & 1);
    }

    // Second copy, split across top-right (row 8) and bottom-left (col 8).
    for (int32_t i = 0; i < 8; i++) {
        qr_setf(cv, 8, size - 1 - i, (bits >> i) & 1);
    }
    for (int32_t i = 8; i < 15; i++) {
        qr_setf(cv, size - 15 + i, 8, (bits >> i) & 1);
    }
    // Always-dark module.
    qr_setf(cv, size - 8, 8, 1);
}

static void
qr_draw_version(qr_canvas_t *cv)
{
    if (cv->version < 7) {
        return;
    }
    int32_t bits = qr_version_bits(cv->version);
    int32_t size = cv->size;
    for (int32_t i = 0; i < 18; i++) {
        int     bit = (bits >> i) & 1;
        int32_t a   = size - 11 + (i % 3);
        int32_t b   = i / 3;
        qr_setf(cv, b, a, bit);
        qr_setf(cv, a, b, bit);
    }
}

// Zigzag placement of the codeword bit stream; remainder positions stay 0.
static void
qr_place_data(qr_canvas_t *cv, const uint8_t *data, int32_t data_len)
{
    int32_t size = cv->size;
    int32_t i    = 0;  // bit cursor

    for (int32_t right = size - 1; right >= 1; right -= 2) {
        if (right == 6) {
            right = 5;  // skip the vertical timing column
        }
        for (int32_t vert = 0; vert < size; vert++) {
            for (int32_t j = 0; j < 2; j++) {
                int32_t c      = right - j;
                int     upward = ((right + 1) & 2) == 0;
                int32_t r      = upward ? (size - 1 - vert) : vert;
                if (!cv->fn[qr_idx(cv, r, c)]) {
                    int dark = 0;
                    if (i < data_len * 8) {
                        dark = (data[i >> 3] >> (7 - (i & 7))) & 1;
                        i++;
                    }
                    cv->mod[qr_idx(cv, r, c)] = (uint8_t)dark;
                }
            }
        }
    }
}

static int
qr_mask_cond(int32_t mask, int32_t r, int32_t c)
{
    switch (mask) {
    case 0:
        return (r + c) % 2 == 0;
    case 1:
        return r % 2 == 0;
    case 2:
        return c % 3 == 0;
    case 3:
        return (r + c) % 3 == 0;
    case 4:
        return ((r / 2) + (c / 3)) % 2 == 0;
    case 5:
        return (r * c) % 2 + (r * c) % 3 == 0;
    case 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0;
    case 7:
        return ((r + c) % 2 + (r * c) % 3) % 2 == 0;
    default:
        return 0;
    }
}

static void
qr_apply_mask(qr_canvas_t *cv, int32_t mask)
{
    for (int32_t r = 0; r < cv->size; r++) {
        for (int32_t c = 0; c < cv->size; c++) {
            if (!cv->fn[qr_idx(cv, r, c)] && qr_mask_cond(mask, r, c)) {
                cv->mod[qr_idx(cv, r, c)] ^= 1;
            }
        }
    }
}

// Rule-3 finder-like 11-module patterns (and their mirror).
static const uint8_t qr_r3a[11] = {1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0};
static const uint8_t qr_r3b[11] = {0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1};

static int
qr_r3_row(const uint8_t *m, int32_t size, int32_t r, int32_t c)
{
    int a = 1, b = 1;
    for (int k = 0; k < 11; k++) {
        uint8_t v = m[r * size + c + k];
        if (v != qr_r3a[k]) {
            a = 0;
        }
        if (v != qr_r3b[k]) {
            b = 0;
        }
    }
    return a || b;
}

static int
qr_r3_col(const uint8_t *m, int32_t size, int32_t r, int32_t c)
{
    int a = 1, b = 1;
    for (int k = 0; k < 11; k++) {
        uint8_t v = m[(r + k) * size + c];
        if (v != qr_r3a[k]) {
            a = 0;
        }
        if (v != qr_r3b[k]) {
            b = 0;
        }
    }
    return a || b;
}

static int32_t
qr_penalty(const qr_canvas_t *cv)
{
    int32_t        size  = cv->size;
    const uint8_t *m     = cv->mod;
    int32_t        score = 0;

    // Rule 1: runs of 5+ same-color modules, per row and column.
    for (int32_t r = 0; r < size; r++) {
        int run = 1;
        for (int32_t c = 1; c < size; c++) {
            if (m[r * size + c] == m[r * size + c - 1]) {
                if (++run == 5) {
                    score += 3;
                }
                else if (run > 5) {
                    score++;
                }
            }
            else {
                run = 1;
            }
        }
    }
    for (int32_t c = 0; c < size; c++) {
        int run = 1;
        for (int32_t r = 1; r < size; r++) {
            if (m[r * size + c] == m[(r - 1) * size + c]) {
                if (++run == 5) {
                    score += 3;
                }
                else if (run > 5) {
                    score++;
                }
            }
            else {
                run = 1;
            }
        }
    }

    // Rule 2: 2x2 blocks of one color.
    for (int32_t r = 0; r < size - 1; r++) {
        for (int32_t c = 0; c < size - 1; c++) {
            uint8_t v = m[r * size + c];
            if (v == m[r * size + c + 1] && v == m[(r + 1) * size + c]
                && v == m[(r + 1) * size + c + 1]) {
                score += 3;
            }
        }
    }

    // Rule 3: finder-like patterns in rows and columns.
    for (int32_t r = 0; r < size; r++) {
        for (int32_t c = 0; c <= size - 11; c++) {
            if (qr_r3_row(m, size, r, c)) {
                score += 40;
            }
        }
    }
    for (int32_t c = 0; c < size; c++) {
        for (int32_t r = 0; r <= size - 11; r++) {
            if (qr_r3_col(m, size, r, c)) {
                score += 40;
            }
        }
    }

    // Rule 4: deviation of dark-module proportion from 50%.
    int32_t dark = 0;
    for (int32_t k = 0; k < size * size; k++) {
        dark += m[k];
    }
    int32_t total   = size * size;
    int32_t percent = dark * 100 / total;
    int32_t low     = (percent / 5) * 5;
    int32_t dev     = qr_iabs(low - 50);
    int32_t dev2    = qr_iabs(low + 5 - 50);
    if (dev2 < dev) {
        dev = dev2;
    }
    score += (dev / 5) * 10;

    return score;
}

n00b_result_t(n00b_qr_t *)
n00b_qr_encode(n00b_string_t *data) _kargs
{
    n00b_qr_ecc_t     ecc       = N00B_QR_ECC_M;
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_result_t(n00b_qr_codeword_plan_t *) cwr =
        _n00b_qr_make_codewords(data, ecc, .allocator = allocator);
    if (n00b_result_is_err(cwr)) {
        return n00b_result_err(n00b_qr_t *, n00b_result_get_err(cwr));
    }
    n00b_qr_codeword_plan_t *plan    = n00b_result_get(cwr);
    int32_t                  version = plan->version;
    int32_t                  size    = 4 * version + 17;

    qr_canvas_t cv = {
        .size    = size,
        .version = version,
        .mod     = n00b_alloc_array_with_opts(
            uint8_t,
            size * size,
            &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true}),
        .fn = n00b_alloc_array_with_opts(
            uint8_t,
            size * size,
            &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true}),
    };

    qr_draw_timing(&cv);
    qr_draw_finder(&cv, 3, 3);
    qr_draw_finder(&cv, 3, size - 4);
    qr_draw_finder(&cv, size - 4, 3);
    qr_place_alignments(&cv);
    qr_draw_version(&cv);            // versions 7+ (mask-independent)
    qr_draw_format(&cv, ecc, 0);    // reserve format region + dark module
    qr_place_data(&cv, (const uint8_t *)plan->codewords->data,
                  (int32_t)plan->codewords->byte_len);

    // Choose the mask with the lowest penalty.
    int32_t best  = -1;
    int32_t bestp = 0;
    for (int32_t mask = 0; mask < 8; mask++) {
        qr_apply_mask(&cv, mask);
        qr_draw_format(&cv, ecc, mask);
        int32_t p = qr_penalty(&cv);
        if (best < 0 || p < bestp) {
            bestp = p;
            best  = mask;
        }
        qr_apply_mask(&cv, mask);  // undo (XOR is its own inverse)
    }
    qr_apply_mask(&cv, best);
    qr_draw_format(&cv, ecc, best);

    n00b_qr_t *qr = n00b_alloc(n00b_qr_t, .allocator = allocator);
    qr->version   = version;
    qr->size      = size;
    qr->ecc       = ecc;
    qr->mask      = best;
    qr->modules   = cv.mod;

    return n00b_result_ok(n00b_qr_t *, qr);
}

n00b_string_t *
n00b_qr_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_QR_OK:
        return r"ok";
    case N00B_QR_ERR_EMPTY_INPUT:
        return r"input string is empty";
    case N00B_QR_ERR_TOO_LARGE:
        return r"data does not fit in a version 1-10 QR at this ECC level";
    case N00B_QR_ERR_BAD_ECC:
        return r"invalid ECC level";
    default:
        return r"unknown QR error";
    }
}

// ====================================================================
// Rendering
// ====================================================================

// Module value at padded coordinate (r, c); the quiet zone reads light.
static int
qr_grid(const n00b_qr_t *qr, int32_t q, int32_t r, int32_t c)
{
    if (r < q || r >= q + qr->size || c < q || c >= q + qr->size) {
        return 0;
    }
    return qr->modules[(r - q) * qr->size + (c - q)] & 1;
}

n00b_plane_t *
n00b_qr_render(n00b_qr_t *qr) _kargs
{
    int64_t           quiet      = 4;
    bool              half_block = true;
    n00b_palette_ix_t dark       = N00B_PAL_TEXT_PRIMARY;
    n00b_palette_ix_t light      = N00B_PAL_BACKGROUND;
    n00b_allocator_t *allocator  = nullptr;
}
{
    int32_t q     = (int32_t)quiet;
    int32_t total = qr->size + 2 * q;

    n00b_plane_t *p = n00b_new_kargs(n00b_plane_t, plane, .allocator = allocator);

    if (half_block) {
        // Two module rows per cell via the upper-half-block glyph: the
        // foreground paints the top module, the background the bottom.
        // One cached style per (top, bottom) color combination.
        const n00b_codepoint_t upper_half = 0x2580;
        n00b_palette_ix_t      pal[2]     = {light, dark};

        n00b_text_style_t *style[2][2];
        for (int td = 0; td < 2; td++) {
            for (int bd = 0; bd < 2; bd++) {
                n00b_text_style_t *st = n00b_str_style_new();
                st->fg_palette_ix     = pal[td];
                st->bg_palette_ix     = pal[bd];
                style[td][bd]         = st;
            }
        }

        int32_t h = (total + 1) / 2;
        p->width  = total;
        p->height = h;

        for (int32_t cy = 0; cy < h; cy++) {
            int32_t top = cy * 2;
            int32_t bot = cy * 2 + 1;
            for (int32_t cx = 0; cx < total; cx++) {
                int td = qr_grid(qr, q, top, cx);
                int bd = (bot < total) ? qr_grid(qr, q, bot, cx) : 0;
                n00b_plane_fill_rect(p,
                                     cx,
                                     cy,
                                     1,
                                     1,
                                     .cp    = upper_half,
                                     .style = style[td][bd]);
            }
        }

        return p;
    }

    // Full-cell packing: each module is one cell, two columns wide for a
    // roughly square aspect. An opaque full-block glyph is colored via
    // the foreground palette (a space-only fill composites as transparent).
    const n00b_codepoint_t full_block = 0x2588;
    int32_t                mw         = 2;
    int32_t                w          = total * mw;
    int32_t                h          = total;

    n00b_text_style_t *dark_st = n00b_str_style_new();
    dark_st->fg_palette_ix     = dark;
    n00b_text_style_t *light_st = n00b_str_style_new();
    light_st->fg_palette_ix     = light;

    p->width  = w;
    p->height = h;

    n00b_plane_fill_rect(p, 0, 0, w, h, .cp = full_block, .style = light_st);

    for (int32_t mr = 0; mr < qr->size; mr++) {
        for (int32_t mc = 0; mc < qr->size; mc++) {
            if (qr->modules[mr * qr->size + mc] & 1) {
                n00b_plane_fill_rect(p,
                                     (mc + q) * mw,
                                     mr + q,
                                     mw,
                                     1,
                                     .cp    = full_block,
                                     .style = dark_st);
            }
        }
    }

    return p;
}

n00b_result_t(n00b_plane_t *)
n00b_qr_terminal(n00b_string_t *url) _kargs
{
    n00b_qr_ecc_t     ecc        = N00B_QR_ECC_M;
    int64_t           quiet      = 4;
    bool              half_block = true;
    n00b_palette_ix_t dark       = N00B_PAL_TEXT_PRIMARY;
    n00b_palette_ix_t light      = N00B_PAL_BACKGROUND;
    n00b_allocator_t *allocator  = nullptr;
}
{
    n00b_result_t(n00b_qr_t *) er = n00b_qr_encode(url,
                                                   .ecc       = ecc,
                                                   .allocator = allocator);
    if (n00b_result_is_err(er)) {
        return n00b_result_err(n00b_plane_t *, n00b_result_get_err(er));
    }

    n00b_plane_t *p = n00b_qr_render(n00b_result_get(er),
                                     .quiet      = quiet,
                                     .half_block = half_block,
                                     .dark       = dark,
                                     .light      = light,
                                     .allocator  = allocator);

    return n00b_result_ok(n00b_plane_t *, p);
}

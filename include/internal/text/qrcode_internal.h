#pragma once

/**
 * @file internal/text/qrcode_internal.h
 * @brief Internal QR pipeline stages shared between qrcode.c and tests.
 *
 * Not a public API. Exposes the data-encoding + ECC-interleaving stage
 * so it can be validated independently of matrix placement.
 */

#include <n00b.h>
#include "adt/result.h"
#include "text/qrcode/qrcode.h"

/** @brief QR encoding mode (subset supported by this implementation). */
typedef enum {
    N00B_QR_MODE_ALNUM = 0,
    N00B_QR_MODE_BYTE  = 1,
} n00b_qr_mode_t;

/**
 * @brief Result of the data-encoding + ECC-interleaving stage.
 *
 * @var n00b_qr_codeword_plan_t::version    Chosen version (1-10).
 * @var n00b_qr_codeword_plan_t::ecc        ECC level used.
 * @var n00b_qr_codeword_plan_t::mode       Encoding mode chosen.
 * @var n00b_qr_codeword_plan_t::codewords  Final interleaved data+ECC
 *                                          codeword byte sequence, in
 *                                          matrix-placement order
 *                                          (remainder bits not included).
 */
typedef struct {
    int32_t        version;
    n00b_qr_ecc_t  ecc;
    n00b_qr_mode_t mode;
    n00b_buffer_t *codewords;
} n00b_qr_codeword_plan_t;

/**
 * @brief Run data encoding + ECC + interleaving for @p data at @p ecc.
 *
 * Selects the mode and smallest fitting version (1-10), builds the
 * padded data codewords, computes Reed-Solomon ECC per block, and
 * interleaves data then ECC into the final codeword stream.
 *
 * @param data  Non-empty input string.
 * @param ecc   Error-correction level.
 * @kw allocator  Allocator (nullptr => runtime default).
 * @return ok with a #n00b_qr_codeword_plan_t, or err with a
 *         #n00b_qr_err_t code.
 */
extern n00b_result_t(n00b_qr_codeword_plan_t *)
_n00b_qr_make_codewords(n00b_string_t *data, n00b_qr_ecc_t ecc) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

#pragma once

/**
 * @file crypto/reed_solomon.h
 * @brief Reed-Solomon error-correction encoder over GF(2^8).
 *
 * Computes the parity (ECC) bytes for a single systematic Reed-Solomon
 * codeword over the finite field in `crypto/gf256.h`. This is the
 * encode side only — given `k` data bytes and a desired `ecc_len`, it
 * produces the `ecc_len` parity bytes such that the data followed by the
 * parity is a valid RS codeword. No decoder (syndrome / Berlekamp-Massey
 * / Chien-Forney) is provided; this exists to *generate* RS-coded data
 * (the immediate consumer is the QR generator), not to recover from
 * errors.
 *
 * # Symbol prefix
 *
 * `n00b_rs_*` (lower-case), top-level utility namespace alongside
 * `n00b_gf256_*` and `n00b_base64_*`.
 *
 * # Single-block contract
 *
 * A Reed-Solomon codeword over GF(2^8) is at most 255 symbols, so this
 * primitive encodes one block at a time: `data_len + ecc_len` must be
 * `<= 255`. Callers with more data than fits in one block (e.g. larger
 * QR versions) split it into blocks themselves and call this per block.
 *
 * # Generator polynomial
 *
 * Uses the conventional RS generator with consecutive roots starting at
 * `alpha^0`: `g(x) = prod_{i=0}^{ecc_len-1} (x - alpha^i)`. This is the
 * convention QR codes use; it is fixed (not a parameter) for now.
 *
 * # Allocator discipline
 *
 * `n00b_rs_encode` is allocating and accepts `.allocator = nullptr`
 * (runtime default), threaded through the result buffer and internal
 * scratch. The field may be supplied via `.field`; when omitted, a
 * standard GF(2^8) field (primitive `0x11D`, generator `2`) is built on
 * the stack for the call. Hot-loop callers that encode many blocks
 * should build one field and pass it in to avoid rebuilding the tables
 * per call.
 */

#include <n00b.h>
#include "adt/result.h"
#include <crypto/gf256.h>

/**
 * @brief Reed-Solomon encoder error codes (negative, errno-disjoint).
 */
typedef enum {
    N00B_RS_OK                  = 0,
    N00B_RS_ERR_NULL_DATA       = -1,  /**< @c data was nullptr. */
    N00B_RS_ERR_BAD_ECC_LEN     = -2,  /**< @c ecc_len <= 0 or > 255. */
    N00B_RS_ERR_BLOCK_TOO_LARGE = -3,  /**< data_len + ecc_len > 255. */
} n00b_rs_err_t;

/**
 * @brief Human-readable description of a Reed-Solomon error code.
 * @param err  A code from #n00b_rs_err_t.
 * @return A static styled string describing @p err.
 */
extern n00b_string_t *n00b_rs_err_str(n00b_err_t err);

/**
 * @brief Compute the Reed-Solomon parity bytes for one data block.
 *
 * @param data     The data symbols to encode (must be non-null).
 * @param ecc_len  Number of parity bytes to produce (`1 <= ecc_len`,
 *                 and `data->byte_len + ecc_len <= 255`).
 * @kw field       Field to compute in. `nullptr` => the standard QR / RS
 *                 field (`0x11D`, generator `2`), built for this call.
 * @kw allocator   Allocator for the result + scratch (`nullptr` =>
 *                 runtime default).
 * @return On success, ok with a new `n00b_buffer_t *` of exactly
 *         @p ecc_len parity bytes. On a contract violation, err with the
 *         corresponding #n00b_rs_err_t code.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_rs_encode(n00b_buffer_t *data, int32_t ecc_len) _kargs
{
    n00b_gf256_t     *field     = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

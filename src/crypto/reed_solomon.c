// Reed-Solomon encoder over GF(2^8). See include/crypto/reed_solomon.h
// for the API contract. Encoder only: produces the parity bytes for one
// systematic RS codeword via polynomial division by the generator.

#include <crypto/reed_solomon.h>

#include "core/buffer.h"
#include "core/alloc.h"

#include <string.h>

// Largest RS codeword over GF(2^8): 2^8 - 1 symbols.
#define RS_MAX_CODEWORD 255

// Build the degree-`ecc_len` generator polynomial:
//   g(x) = prod_{i=0}^{ecc_len-1} (x - alpha^i)
// Coefficients are stored highest-degree-first in `gen[0..ecc_len]`, and
// the polynomial is monic (gen[0] == 1). `gen` must have ecc_len+1 slots.
static void
rs_generator_poly(const n00b_gf256_t *gf, int32_t ecc_len, uint8_t *gen)
{
    gen[0]      = 1;  // g(x) = 1 to start (degree 0)
    int32_t len = 1;  // coefficients currently used

    for (int32_t i = 0; i < ecc_len; i++) {
        uint8_t a = gf->exp[i];  // root alpha^i

        // Multiply the current g by (x + a), in place, high index first
        // so each write only consumes not-yet-overwritten coefficients.
        // new[len]   = a * g[len-1]
        // new[j]     = g[j] + a * g[j-1]   (j = len-1 .. 1)
        // new[0]     = g[0]   (unchanged; stays 1)
        gen[len] = n00b_gf256_mul(gf, a, gen[len - 1]);
        for (int32_t j = len - 1; j >= 1; j--) {
            gen[j] = n00b_gf256_add(gen[j], n00b_gf256_mul(gf, a, gen[j - 1]));
        }
        len++;
    }
}

n00b_string_t *
n00b_rs_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_RS_OK:
        return r"ok";
    case N00B_RS_ERR_NULL_DATA:
        return r"data buffer was null";
    case N00B_RS_ERR_BAD_ECC_LEN:
        return r"ecc_len out of range (must be 1..255)";
    case N00B_RS_ERR_BLOCK_TOO_LARGE:
        return r"data_len + ecc_len exceeds the 255-symbol block limit";
    default:
        return r"unknown reed-solomon error";
    }
}

n00b_result_t(n00b_buffer_t *)
n00b_rs_encode(n00b_buffer_t *data, int32_t ecc_len) _kargs
{
    n00b_gf256_t     *field     = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (data == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_RS_ERR_NULL_DATA);
    }
    if (ecc_len <= 0 || ecc_len > RS_MAX_CODEWORD) {
        return n00b_result_err(n00b_buffer_t *, N00B_RS_ERR_BAD_ECC_LEN);
    }

    size_t data_len = data->byte_len;
    if (data_len + (size_t)ecc_len > RS_MAX_CODEWORD) {
        return n00b_result_err(n00b_buffer_t *, N00B_RS_ERR_BLOCK_TOO_LARGE);
    }

    // Use the caller's field, or build the standard one for this call.
    n00b_gf256_t        local_field;
    const n00b_gf256_t *gf = field;
    if (gf == nullptr) {
        n00b_gf256_init(&local_field);
        gf = &local_field;
    }

    uint8_t *gen = n00b_alloc_array_with_opts(
        uint8_t,
        ecc_len + 1,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});
    rs_generator_poly(gf, ecc_len, gen);

    // Working register: data followed by ecc_len zero bytes. The
    // allocator zero-fills, so the parity tail starts at zero.
    size_t   n    = data_len + (size_t)ecc_len;
    uint8_t *work = n00b_alloc_array_with_opts(
        uint8_t,
        n,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});
    if (data_len > 0) {
        memcpy(work, data->data, data_len);
    }

    // Synthetic division of (data << ecc_len) by the monic generator.
    // generator[0] == 1 consumes work[i] itself, so skip j == 0; the
    // remainder is left in the trailing ecc_len bytes.
    for (size_t i = 0; i < data_len; i++) {
        uint8_t coef = work[i];
        if (coef != 0) {
            for (int32_t j = 1; j <= ecc_len; j++) {
                work[i + j] = n00b_gf256_add(work[i + j],
                                             n00b_gf256_mul(gf, gen[j], coef));
            }
        }
    }

    n00b_buffer_t *out = n00b_buffer_new((int64_t)ecc_len,
                                         .allocator = allocator);
    n00b_buffer_resize(out, (uint64_t)ecc_len);
    memcpy(out->data, work + data_len, (size_t)ecc_len);

    return n00b_result_ok(n00b_buffer_t *, out);
}

/* src/util/base64.c — allocator-aware base64 wrapper around picotls.
 *
 * Implements the surface declared in include/util/base64.h:
 *   - n00b_base64_encode  (n00b_buffer_t *  -> n00b_string_t *)
 *   - n00b_base64_decode  (n00b_string_t *  -> n00b_buffer_t *)
 *
 * Both call into picotls's `ptls_base64_*` primitives
 * (subprojects/picotls/lib/pembase64.c) and thread the n00b
 * allocator forward through every internal allocation. picotls
 * itself owns no allocation: the encoder writes into a buffer the
 * caller sizes via `ptls_base64_howlong`, and the streaming
 * decoder accumulates into a `ptls_buffer_t` whose initial small-
 * buffer we provision from the n00b allocator (sized to the
 * worst-case decoded length so picotls never grows it via
 * realloc).
 *
 * Design notes:
 *
 * - We deliberately do NOT use n00b_buffer_from_bytes for the
 *   encoded scratch buffer: `n00b_buffer_from_bytes` copies the
 *   input bytes into a fresh buffer, which would double the
 *   allocation. Instead we allocate raw chars via
 *   `n00b_alloc_array_with_opts`, hand that pointer to
 *   `ptls_base64_encode`, and wrap the produced bytes in an
 *   `n00b_string_t *` via `n00b_string_from_raw` (which copies
 *   exactly once — same shape as dsse.c's original inline
 *   encoder used).
 *
 * - picotls writes a NUL terminator at position `howlong` and
 *   returns `howlong + 1` as the write length. We allocate
 *   `howlong + 1` bytes and pass `howlong` as the n00b string
 *   length so the NUL doesn't appear in `s->u8_bytes`.
 *
 * - The decoder's worst-case output length is `(text_len / 4) *
 *   3`. We pre-allocate that as the picotls scratch buffer so
 *   the streaming decoder never grows it. After the call, we
 *   copy the produced bytes into an n00b-owned `n00b_buffer_t *`
 *   and dispose the picotls buffer — the picotls buffer's
 *   `is_allocated` flag remains zero because we provisioned the
 *   initial capacity (so `ptls_buffer_dispose` is a no-op on
 *   the scratch storage, which lives in the n00b allocator and
 *   is GC-managed).
 */

#include <crypto/base64.h>

#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"

#include "picotls.h"
#include "picotls/pembase64.h"

#include <string.h>

n00b_result_t(n00b_string_t *)
n00b_base64_encode(n00b_buffer_t *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    size_t      data_len = 0;
    const char *data_ptr = nullptr;
    if (bytes != nullptr) {
        data_len = bytes->byte_len;
        data_ptr = bytes->data;
    }

    if (data_len == 0) {
        n00b_string_t *empty = n00b_string_empty(.allocator = allocator);
        return n00b_result_ok(n00b_string_t *, empty);
    }

    // picotls writes `howlong` base64 chars + 1 NUL = `howlong + 1`
    // bytes. Allocate room for both.
    size_t enc_len = ptls_base64_howlong(data_len);
    char  *scratch = n00b_alloc_array_with_opts(
        char,
        enc_len + 1,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    (void)ptls_base64_encode((const uint8_t *)data_ptr, data_len, scratch);

    // `n00b_string_from_raw` copies the bytes; pass `enc_len` so the
    // NUL picotls wrote at position `enc_len` is not counted in
    // u8_bytes (the string's own data will get its own NUL).
    n00b_string_t *out = n00b_string_from_raw(scratch,
                                              (int64_t)enc_len,
                                              .allocator = allocator);
    return n00b_result_ok(n00b_string_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_base64_decode(n00b_string_t *base64_text) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (base64_text == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_BASE64_ERR_NULL_INPUT);
    }

    // picotls's decoder requires a NUL-terminated input. n00b_string_t
    // is documented as NUL-terminated (see n00b_string_from_raw
    // post-condition), so `base64_text->data` is safe to read past
    // u8_bytes — but a defensive copy makes the contract local and
    // costs nothing at base64-frequency call sites.
    size_t text_len = base64_text->u8_bytes;
    if (text_len == 0) {
        return n00b_result_ok(n00b_buffer_t *,
                              n00b_buffer_from_bytes(nullptr,
                                                     0,
                                                     .allocator = allocator));
    }

    char *text_copy = n00b_alloc_array_with_opts(
        char,
        text_len + 1,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    memcpy(text_copy, base64_text->data, text_len);
    text_copy[text_len] = '\0';

    // Worst-case decoded length: floor(text_len / 4) * 3. picotls's
    // streaming decoder writes 1-3 bytes per 4 input chars. Pre-
    // allocate that as the scratch buffer's `smallbuf` so picotls
    // never calls realloc internally — the buffer's `is_allocated`
    // flag stays zero and `ptls_buffer_dispose` is a no-op on it.
    size_t scratch_cap = (text_len / 4) * 3;
    if (scratch_cap == 0) {
        // Short-input rejection (n00b-code-auditor W-5
        // informational). Valid RFC 4648 base64 is always a
        // multiple of 4 bytes (`=` padding tops up incomplete
        // groups), so a 1-, 2-, or 3-character input is
        // structurally invalid. The genuinely-empty case
        // (`text_len == 0`) is handled by the early return
        // above; reaching here means `text_len > 0` but
        // `text_len < 4`, which can't be padded back to a valid
        // sequence — decode-failed is the correct outcome.
        return n00b_result_err(n00b_buffer_t *,
                               N00B_BASE64_ERR_DECODE_FAILED);
    }
    uint8_t *scratch = (uint8_t *)n00b_alloc_array_with_opts(
        char,
        scratch_cap,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    ptls_buffer_t              pbuf;
    ptls_base64_decode_state_t state;
    ptls_buffer_init(&pbuf, scratch, scratch_cap);
    ptls_base64_decode_init(&state);

    int rc = ptls_base64_decode(text_copy, &state, &pbuf);

    // Bail on any error or unfinished state. The "complete" terminal
    // conditions are: status == DECODE_DONE, or DECODE_IN_PROGRESS
    // with nbc == 0 (a clean 4-char-aligned end without explicit
    // padding because the data length was already a multiple of 3).
    if (rc != 0
        || (state.status != PTLS_BASE64_DECODE_DONE
            && !(state.status == PTLS_BASE64_DECODE_IN_PROGRESS
                 && state.nbc == 0))) {
        ptls_buffer_dispose(&pbuf);
        return n00b_result_err(n00b_buffer_t *,
                               N00B_BASE64_ERR_DECODE_FAILED);
    }

    // Copy the produced bytes into an n00b-owned buffer. `pbuf.off`
    // is the number of bytes the decoder wrote into `pbuf.base`
    // (which == `scratch` because we sized it large enough that
    // picotls never reallocated). The buffer's contents live in
    // `scratch` (n00b-allocated, GC-managed), so we can either hand
    // `scratch` straight to `n00b_buffer_from_bytes` (which copies)
    // or trim it down. We hand it through n00b_buffer_from_bytes
    // for the canonical n00b_buffer_t shape with its own owned
    // payload — same convention dsse.c's inline decoder followed.
    size_t out_len = pbuf.off;
    n00b_buffer_t *out = n00b_buffer_from_bytes((char *)scratch,
                                                (int64_t)out_len,
                                                .allocator = allocator);
    ptls_buffer_dispose(&pbuf);
    return n00b_result_ok(n00b_buffer_t *, out);
}

// ---------------------------------------------------------------------------
// Error-code accessor (closes WA-1 from WP-002 Phase 1 audit per D-038
// part 2). Pure lookup; allocation-free; bodies are rich-string literals
// with process-lifetime storage.
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_base64_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_BASE64_ERR_DECODE_FAILED:
        return r"base64: decode failed (bad alphabet, padding, or truncation)";
    case N00B_BASE64_ERR_NULL_INPUT:
        return r"base64: null input string";
    default:
        return r"unknown base64 error code";
    }
}

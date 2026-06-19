#pragma once

/**
 * @file util/base64.h
 * @brief Allocator-aware base64 (RFC 4648) encode / decode utility.
 *
 * Thin n00b-shaped wrapper around picotls's `ptls_base64_*`
 * primitives in `subprojects/picotls/lib/pembase64.c`. The
 * picotls implementation handles the encoder padding-residue
 * cases and the streaming decoder state machine; this header
 * gives the rest of n00b an allocator-aware,
 * `n00b_result_t`-returning surface that takes / returns
 * `n00b_buffer_t *` and `n00b_string_t *` rather than raw
 * `(uint8_t *, size_t)` pairs.
 *
 * # Symbol prefix
 *
 * `n00b_base64_*` (lower-case symbols, `N00B_BASE64_*` for the
 * error-code macros) — top-level utility namespace, matching the
 * `n00b_json_*` precedent. These are NOT `n00b_attest_*` symbols
 * even though n00b_attest is the first consumer; libchalk's
 * `macos_wrap.c` consumes them too.
 *
 * # Allocator discipline
 *
 * Both entry points are allocating and accept `.allocator =
 * nullptr`. `nullptr` means "use the runtime default";
 * otherwise the allocator is threaded forward through every
 * internal allocation, including the per-call scratch buffer
 * the decoder uses to receive picotls's `ptls_buffer_t` output
 * before copying it into the n00b-owned `n00b_buffer_t *`.
 *
 * # Encoding scheme
 *
 * RFC 4648 base64 with the canonical `+` / `/` alphabet and
 * `=` padding. Decoder is lenient about surrounding whitespace
 * (skips leading and trailing blanks, including newlines)
 * matching picotls's RFC 7468-flavored decoder, but rejects any
 * non-alphabet byte inside the data — that surfaces as the
 * `N00B_BASE64_ERR_DECODE_FAILED` error code.
 */

#include <n00b.h>
#include "adt/result.h"

/**
 * @brief Error code returned when the decoder encounters a
 *        non-alphabet byte (other than padding `=` in the
 *        terminal positions) or a truncated input.
 *
 * Surfaces via the `_err` branch of the
 * `n00b_result_t(n00b_buffer_t *)` returned by
 * @ref n00b_base64_decode. Negative integer per the libn00b
 * convention (avoid collision with `errno`).
 */
#define N00B_BASE64_ERR_DECODE_FAILED (-3001)

/**
 * @brief Error code returned when @ref n00b_base64_decode is
 *        called with a null input string.
 */
#define N00B_BASE64_ERR_NULL_INPUT (-3002)

/**
 * @brief Base64-encode a byte buffer (RFC 4648, `+`/`/` alphabet,
 *        `=` padded).
 *
 * @param bytes  The bytes to encode. A null pointer is treated as
 *               an empty input and produces an empty
 *               `n00b_string_t *`. A non-null pointer is read
 *               from `bytes->data` for `bytes->byte_len` bytes;
 *               internal lengths above `SIZE_MAX/4 - 1` are out
 *               of practical reach and not specially guarded.
 *
 * @kw allocator Optional allocator (defaults to the runtime
 *               default); owns the returned string and is
 *               threaded through every internal allocation.
 *
 * @return `n00b_result_ok(n00b_string_t *, encoded)` on success.
 *         The returned string holds the base64 text (NUL
 *         terminated). Empty input yields an empty string.
 *
 * @details
 *
 * Sizes the output via `ptls_base64_howlong(bytes->byte_len)`,
 * allocates an n00b-managed buffer of that size, calls
 * `ptls_base64_encode` to fill it, and wraps the result in an
 * `n00b_string_t *` via `n00b_string_from_raw`. The encoder
 * cannot fail.
 *
 * @post The returned string's `data` is NUL-terminated and its
 *       `u8_bytes` equals the encoded length (the number of
 *       base64 characters, including any `=` padding, but not
 *       counting the terminating NUL).
 */
extern n00b_result_t(n00b_string_t *)
n00b_base64_encode(n00b_buffer_t *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Base64-decode a string (RFC 4648, `+`/`/` alphabet,
 *        `=` padded).
 *
 * @param base64_text  The base64 text to decode. Leading and
 *                     trailing whitespace (spaces, tabs, CR,
 *                     LF) is tolerated per RFC 7468 lax
 *                     semantics. A null pointer yields
 *                     `N00B_BASE64_ERR_NULL_INPUT`.
 *
 * @kw allocator Optional allocator (defaults to the runtime
 *               default); owns the returned buffer and is
 *               threaded through every internal allocation,
 *               including the picotls scratch buffer the
 *               decoder accumulates into.
 *
 * @return `n00b_result_ok(n00b_buffer_t *, decoded)` on success
 *         with the decoded bytes. Empty (zero-length) input
 *         yields a zero-length buffer. Malformed input (non-
 *         alphabet bytes, bad padding, mid-stream truncation)
 *         yields `n00b_result_err(n00b_buffer_t *,
 *         N00B_BASE64_ERR_DECODE_FAILED)`. A null pointer
 *         yields `N00B_BASE64_ERR_NULL_INPUT`.
 *
 * @details
 *
 * Drives picotls's streaming decoder
 * (`ptls_base64_decode_init` then `ptls_base64_decode`) against
 * a `ptls_buffer_t` instance the wrapper owns, then copies the
 * decoded bytes into an n00b-allocated `n00b_buffer_t *` so the
 * picotls buffer lifetime never escapes this function.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_base64_decode(n00b_string_t *base64_text) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Look up a human-readable string for an `N00B_BASE64_ERR_*`
 *        error code.
 *
 * @param err  Any `N00B_BASE64_ERR_*` code. Both currently defined
 *             codes (@ref N00B_BASE64_ERR_DECODE_FAILED and
 *             @ref N00B_BASE64_ERR_NULL_INPUT) are covered.
 *
 * @return A non-null `n00b_string_t *` containing a short
 *         description. The returned string is a rich-string
 *         literal with process-lifetime storage; the caller must
 *         NOT free it. Unknown codes return a documented fallback
 *         of the form `r"unknown base64 error code"` (the integer
 *         value itself is not formatted into the message — call
 *         sites that need the integer have it already).
 *
 * @details Pure lookup over a hard-coded table; allocates nothing,
 * never fails. Repeated calls with the same input return string
 * pointers whose `data` bytes are byte-identical.
 *
 * @note This accessor closes WA-1 from the WP-002 Phase 1 audit
 * (bundled with the n00b_attest equivalent at the Phase 3 audit
 * gate per D-038 part 2).
 */
extern n00b_string_t *
n00b_base64_err_str(n00b_err_t err);

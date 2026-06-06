/**
 * @file parse_num.h
 * @brief Libc-free numeric parsing.
 *
 * Locale-independent replacements for the strtol/strtoll/strtod family. Use
 * these — never the libc functions — anywhere the call may run on an n00b
 * off-libc worker thread: glibc's converters are locale-aware and dereference
 * the calling thread's TLS locale pointer, which is NULL on a thread created
 * via raw clone() (minimal TCB), so the libc call segfaults there. (The same
 * class of off-libc-worker libc-TLS trap motivated replacing snprintf("%g")
 * with n00b_fptostr in the QUIC metrics encoder.)
 *
 * Each parser comes in three input forms, selected automatically by the
 * n00b_parse_i64 / n00b_parse_f64 macros via _Generic on the first argument:
 *   - a raw byte span:    n00b_parse_i64(ptr, len)   // const char *, size_t
 *   - an n00b_buffer_t *: n00b_parse_i64(buf)
 *   - an n00b_string_t *: n00b_parse_i64(str)
 * The byte-span form exists because callers frequently hold borrowed,
 * already-bounded spans (HTTP/3 header values, a tokenizer's scratch buffer)
 * and parsing must not allocate; the buffer/string forms just read .data and
 * the length field and delegate to it.
 */
#pragma once

#include <stddef.h>
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"

/* Domain error codes for the parse results. Negative to avoid collision with
 * errno-valued results in a chain (§ 5.1); see n00b_parse_num_err_str. */
#define N00B_PARSE_ERR_NO_DIGITS (-1) /**< No digit was present.        */
#define N00B_PARSE_ERR_OVERFLOW  (-2) /**< Value is out of target range. */

/**
 * @brief Parse an optionally-signed base-10 integer from a byte span.
 *
 * Skips leading ASCII whitespace, accepts an optional '+'/'-' sign, then
 * consumes ASCII digits until the first non-digit or the end of the span.
 *
 * @return @c n00b_result_t(int64_t): ok(value); err(N00B_PARSE_ERR_NO_DIGITS)
 *         when no digit is present; err(N00B_PARSE_ERR_OVERFLOW) when the
 *         digits exceed the int64 range.
 */
extern n00b_result_t(int64_t) n00b_parse_i64_span(const char *s, size_t len);

/** @brief n00b_parse_i64_span over a buffer's bytes (null buffer -> no-digits). */
extern n00b_result_t(int64_t) n00b_parse_i64_buffer(n00b_buffer_t *b);

/** @brief n00b_parse_i64_span over a string's bytes (null string -> no-digits). */
extern n00b_result_t(int64_t) n00b_parse_i64_string(n00b_string_t *s);

/**
 * @brief Parse a base-10 floating-point number from a byte span, libc-free.
 *
 * Accepts the JSON number grammar: optional leading ASCII whitespace, optional
 * '+'/'-' sign, integer digits, optional fractional part, optional 'e'/'E'
 * exponent. (A leading '.' with no integer digit is accepted as 0.<frac>.)
 *
 * Accuracy: the common case — at most ~15 significant digits with a decimal
 * exponent in [-22, 22] — is computed via a single exact multiply/divide and
 * is correctly rounded (Clinger's fast path). Inputs outside that window (more
 * significant digits, or |exponent| > 22) are computed by chunked scaling and
 * may differ from a correctly-rounded result by a few ULP. A fully
 * correctly-rounded slow path would require either a large transcribed
 * power-of-ten table or a bignum, neither of which is in the tree.
 *
 * @return @c n00b_result_t(double): ok(value) (including signed zero /
 *         subnormals); err(N00B_PARSE_ERR_NO_DIGITS) when no digit is present;
 *         err(N00B_PARSE_ERR_OVERFLOW) when the magnitude overflows to
 *         infinity.
 */
extern n00b_result_t(double) n00b_parse_f64_span(const char *s, size_t len);

/** @brief n00b_parse_f64_span over a buffer's bytes (null buffer -> no-digits). */
extern n00b_result_t(double) n00b_parse_f64_buffer(n00b_buffer_t *b);

/** @brief n00b_parse_f64_span over a string's bytes (null string -> no-digits). */
extern n00b_result_t(double) n00b_parse_f64_string(n00b_string_t *s);

/**
 * @brief Human-readable description of a parse_num error code.
 * @param err One of the N00B_PARSE_ERR_* codes.
 * @return Process-lifetime rich string; a fallback for unknown codes.
 */
extern n00b_string_t *n00b_parse_num_err_str(n00b_err_t err);

/* Polymorphic entry points. The first argument selects the input form:
 *   n00b_parse_i64(ptr, len) -> span | n00b_parse_i64(buf) | n00b_parse_i64(str)
 * A bare `char[]` / `const char *` lands in the `default` (span) arm and
 * supplies its length as the second argument. */
#define n00b_parse_i64(src, ...)                       \
    _Generic((src),                                    \
        n00b_buffer_t *: n00b_parse_i64_buffer,        \
        n00b_string_t *: n00b_parse_i64_string,        \
        default:         n00b_parse_i64_span)((src)__VA_OPT__(, ) __VA_ARGS__)

#define n00b_parse_f64(src, ...)                       \
    _Generic((src),                                    \
        n00b_buffer_t *: n00b_parse_f64_buffer,        \
        n00b_string_t *: n00b_parse_f64_string,        \
        default:         n00b_parse_f64_span)((src)__VA_OPT__(, ) __VA_ARGS__)

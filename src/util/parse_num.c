/* src/util/parse_num.c — libc-free numeric parsing.
 *
 * Implements the surface declared in include/util/parse_num.h:
 *   - n00b_parse_i64_span / _buffer / _string  (base-10 integer)
 *   - n00b_parse_f64_span / _buffer / _string  (base-10 floating point)
 *   - n00b_parse_num_err_str                   (error-code accessor)
 *
 * # Why this exists
 *
 * glibc's strtol/strtoll/strtod are locale-aware: they read the calling
 * thread's TLS locale pointer (_NL_CURRENT). On an n00b off-libc worker
 * thread — created via raw clone() with a minimal TCB — that pointer is NULL,
 * so the libc call dereferences NULL and segfaults. Numeric values pulled off
 * the wire (HTTP/3 header values, JSON number tokens) are parsed on exactly
 * those worker threads, so they must never touch the libc converters. Same
 * class of off-libc-worker libc-TLS trap that motivated replacing
 * snprintf("%g") with n00b_fptostr in the QUIC metrics encoder.
 *
 * # Interface
 *
 * The core parsers take a (pointer, length) byte span: callers frequently
 * hold borrowed, already-bounded spans (header values, the JSON tokenizer's
 * number text) and parsing must not allocate. The _buffer / _string variants
 * just read .data and the length field and delegate. Failure is reported
 * through n00b_result_t with the negative N00B_PARSE_ERR_* domain codes (§ 5);
 * n00b_parse_num_err_str maps them to text.
 */

#include "n00b.h"
#include "util/parse_num.h"

n00b_result_t(int64_t)
n00b_parse_i64_span(const char *s, size_t len)
{
    size_t i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n'
                       || s[i] == '\r' || s[i] == '\v' || s[i] == '\f')) {
        i++;
    }

    bool neg = false;
    if (i < len && (s[i] == '+' || s[i] == '-')) {
        neg = (s[i] == '-');
        i++;
    }

    size_t         first_digit = i;
    uint64_t       acc         = 0;
    const uint64_t cap         = neg ? (uint64_t)INT64_MAX + 1u
                                     : (uint64_t)INT64_MAX;
    bool           overflow    = false;

    for (; i < len && s[i] >= '0' && s[i] <= '9'; i++) {
        uint64_t d = (uint64_t)(s[i] - '0');
        // First clause keeps acc*10+d from wrapping uint64; second clamps to
        // the signed range. Once overflow is known we keep consuming the
        // remaining digits (so the whole token is read) but the value is
        // discarded — the caller gets ERANGE regardless.
        if (acc > (UINT64_MAX - d) / 10u || acc * 10u + d > cap) {
            overflow = true;
            continue;
        }
        acc = acc * 10u + d;
    }

    if (i == first_digit) {
        return n00b_result_err(int64_t, N00B_PARSE_ERR_NO_DIGITS);
    }
    if (overflow) {
        return n00b_result_err(int64_t, N00B_PARSE_ERR_OVERFLOW);
    }
    return n00b_result_ok(int64_t, neg ? -(int64_t)acc : (int64_t)acc);
}

n00b_result_t(int64_t)
n00b_parse_i64_buffer(n00b_buffer_t *b)
{
    if (b == nullptr) {
        return n00b_result_err(int64_t, N00B_PARSE_ERR_NO_DIGITS);
    }
    return n00b_parse_i64_span(b->data, (size_t)b->byte_len);
}

n00b_result_t(int64_t)
n00b_parse_i64_string(n00b_string_t *s)
{
    if (s == nullptr) {
        return n00b_result_err(int64_t, N00B_PARSE_ERR_NO_DIGITS);
    }
    return n00b_parse_i64_span(s->data, s->u8_bytes);
}

/* Powers of ten that are exactly representable as doubles. 10^k = 2^k * 5^k;
 * 5^22 < 2^52, so 10^0..10^22 each fit in the 53-bit significand exactly.
 * 10^23 is the first power that is not exact, so the table stops at 22. */
static const double n00b_pow10_exact[] = {
    1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
    1e8,  1e9,  1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
    1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
};
#define N00B_POW10_EXACT_MAX 22

n00b_result_t(double)
n00b_parse_f64_span(const char *s, size_t len)
{
    size_t i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n'
                       || s[i] == '\r' || s[i] == '\v' || s[i] == '\f')) {
        i++;
    }

    bool neg = false;
    if (i < len && (s[i] == '+' || s[i] == '-')) {
        neg = (s[i] == '-');
        i++;
    }

    // Accumulate up to 19 significant digits into `mant`; `dec_exp` is the
    // power of ten by which `mant` must be scaled to recover the value.
    // Digits past the 19th are dropped (they cannot affect a double beyond a
    // sub-ULP that this bounded parser does not chase): integer digits past
    // the cap bump `dec_exp`, fractional ones are ignored.
    uint64_t mant       = 0;
    int      dec_exp    = 0;
    bool     any_digit  = false;
    bool     seen_dot   = false;

    for (; i < len; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            any_digit = true;
            if (mant < (UINT64_MAX - 9) / 10) {
                mant = mant * 10 + (uint64_t)(c - '0');
                if (seen_dot) {
                    dec_exp--;
                }
            }
            else if (!seen_dot) {
                dec_exp++; // integer digit beyond precision: keep magnitude
            }
        }
        else if (c == '.' && !seen_dot) {
            seen_dot = true;
        }
        else {
            break;
        }
    }

    if (!any_digit) {
        return n00b_result_err(double, N00B_PARSE_ERR_NO_DIGITS);
    }

    // Optional exponent.
    if (i < len && (s[i] == 'e' || s[i] == 'E')) {
        size_t  j      = i + 1;
        bool    eneg   = false;
        if (j < len && (s[j] == '+' || s[j] == '-')) {
            eneg = (s[j] == '-');
            j++;
        }
        bool exp_digit = false;
        int  ev        = 0;
        for (; j < len && s[j] >= '0' && s[j] <= '9'; j++) {
            exp_digit = true;
            if (ev < 100000) { // clamp; anything this large already over/underflows
                ev = ev * 10 + (s[j] - '0');
            }
        }
        if (exp_digit) {
            dec_exp += eneg ? -ev : ev;
        }
        // A bare 'e' with no exponent digits: leave i past the mantissa and
        // ignore the 'e' (matches the "consume what parses" contract).
    }

    if (mant == 0) {
        return n00b_result_ok(double, neg ? -0.0 : 0.0);
    }

    double value;
    // Clinger fast path: mantissa exactly representable and the scale is a
    // single exact power of ten -> one rounding, correctly rounded.
    if (mant <= (1ULL << 53)
        && dec_exp >= -N00B_POW10_EXACT_MAX
        && dec_exp <= N00B_POW10_EXACT_MAX) {
        value = (double)mant;
        if (dec_exp >= 0) {
            value *= n00b_pow10_exact[dec_exp];
        }
        else {
            value /= n00b_pow10_exact[-dec_exp];
        }
    }
    else {
        // Bounded fallback: scale by exact powers of ten in chunks of <=22.
        // Each step rounds, so the result may be a few ULP off for extreme
        // magnitudes; finite real-world JSON floats hit the fast path above.
        value = (double)mant;
        int e = dec_exp;
        while (e > 0) {
            int step = e > N00B_POW10_EXACT_MAX ? N00B_POW10_EXACT_MAX : e;
            value *= n00b_pow10_exact[step];
            e -= step;
        }
        while (e < 0) {
            int step = -e > N00B_POW10_EXACT_MAX ? N00B_POW10_EXACT_MAX : -e;
            value /= n00b_pow10_exact[step];
            e += step;
        }
    }

    if (__builtin_isinf(value)) {
        return n00b_result_err(double, N00B_PARSE_ERR_OVERFLOW);
    }
    return n00b_result_ok(double, neg ? -value : value);
}

n00b_result_t(double)
n00b_parse_f64_buffer(n00b_buffer_t *b)
{
    if (b == nullptr) {
        return n00b_result_err(double, N00B_PARSE_ERR_NO_DIGITS);
    }
    return n00b_parse_f64_span(b->data, (size_t)b->byte_len);
}

n00b_result_t(double)
n00b_parse_f64_string(n00b_string_t *s)
{
    if (s == nullptr) {
        return n00b_result_err(double, N00B_PARSE_ERR_NO_DIGITS);
    }
    return n00b_parse_f64_span(s->data, s->u8_bytes);
}

n00b_string_t *
n00b_parse_num_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_PARSE_ERR_NO_DIGITS:
        return r"no digits present";
    case N00B_PARSE_ERR_OVERFLOW:
        return r"value out of range";
    default:
        return r"unknown parse error";
    }
}

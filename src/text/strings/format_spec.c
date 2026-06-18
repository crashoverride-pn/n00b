#include "text/strings/format_spec.h"
#include "text/strings/fmt_numbers.h"
#include "text/strings/fp_format.h"
#include "text/strings/string_ops.h"
#include "text/unicode/encoding.h"
#include "internal/text/unicode/raw.h"
#include "core/alloc.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>

// ===================================================================
// Parser
// ===================================================================

n00b_format_spec_t
n00b_format_spec_parse(const char *spec, int spec_len)
{
    n00b_format_spec_t fs = {
        .type      = 0,
        .width     = -1,
        .precision = -1,
    };

    if (!spec || spec_len <= 0) {
        return fs;
    }

    int i = 0;

    // Parse flags.
    while (i < spec_len) {
        char c = spec[i];
        if (c == '-') {
            fs.left_align = true;
        }
        else if (c == '0') {
            fs.zero_pad = true;
        }
        else if (c == '+') {
            fs.sign_plus = true;
        }
        else if (c == ' ') {
            fs.sign_space = true;
        }
        else if (c == ',') {
            fs.commas = true;
        }
        else {
            break;
        }
        i++;
    }

    // Parse width.
    if (i < spec_len && isdigit((unsigned char)spec[i])) {
        int w = 0;
        while (i < spec_len && isdigit((unsigned char)spec[i])) {
            w = w * 10 + (spec[i] - '0');
            i++;
        }
        if (w > INT16_MAX) w = INT16_MAX;
        fs.width = (int16_t)w;
    }

    // Parse precision.
    if (i < spec_len && spec[i] == '.') {
        i++;
        int p = 0;
        while (i < spec_len && isdigit((unsigned char)spec[i])) {
            p = p * 10 + (spec[i] - '0');
            i++;
        }
        if (p > INT16_MAX) p = INT16_MAX;
        fs.precision = (int16_t)p;
    }

    // Parse type.
    if (i < spec_len) {
        char t = spec[i];
        switch (t) {
        case 'X': fs.upper = true; fs.type = 'x'; break;
        case 'E': fs.upper = true; fs.type = 'e'; break;
        case 'G': fs.upper = true; fs.type = 'g'; break;
        case 'B': fs.upper = true; fs.word = true; fs.type = 'b'; break;
        case 'T': fs.upper = true; fs.type = 'b'; break;
        case 'Y': fs.upper = true; fs.yn = true; fs.type = 'b'; break;
        case 'Q': fs.upper = true; fs.yn = true; fs.word = true; fs.type = 'b'; break;
        case 'b': fs.word = true; fs.type = 'b'; break;
        case 't': fs.type = 'b'; break;
        case 'y': fs.yn = true; fs.type = 'b'; break;
        case 'q': fs.yn = true; fs.word = true; fs.type = 'b'; break;
        case 'P': fs.upper = true; fs.type = 'p'; break;
        default:  fs.type = t; break;
        }
    }

    return fs;
}

// ===================================================================
// Padding helper
// ===================================================================

static n00b_string_t *
pad_string(const char *raw, int raw_len, int raw_cps,
           const n00b_format_spec_t *spec, n00b_allocator_t *allocator)
{
    int width = spec->width;
    if (width <= 0 || raw_cps >= width) {
        return n00b_string_from_raw(raw, raw_len, .allocator = allocator);
    }

    int  pad_count = width - raw_cps;
    char pad_char  = (spec->zero_pad && !spec->left_align) ? '0' : ' ';

    int   total_len = raw_len + pad_count;
    char *buf       = n00b_alloc_array(char, total_len + 1);

    if (spec->left_align) {
        memcpy(buf, raw, raw_len);
        memset(buf + raw_len, pad_char, pad_count);
    }
    else {
        // For zero-padding with a sign, keep sign at front.
        if (pad_char == '0' && raw_len > 0
            && (raw[0] == '-' || raw[0] == '+')) {
            buf[0] = raw[0];
            memset(buf + 1, '0', pad_count);
            memcpy(buf + 1 + pad_count, raw + 1, raw_len - 1);
        }
        else {
            memset(buf, pad_char, pad_count);
            memcpy(buf + pad_count, raw, raw_len);
        }
    }
    buf[total_len] = '\0';

    n00b_string_t *result = n00b_string_from_raw(buf, total_len, .allocator = allocator);
    n00b_free(buf);
    return result;
}

// ===================================================================
// Extended integer formatting
// ===================================================================

n00b_string_t *
n00b_str_fmt_int_ex(int64_t value, const n00b_format_spec_t *spec)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    char buf[80];
    int  len = 0;

    bool commas = spec->commas;

    if (spec->type == 'x') {
        // Hex.
        uint64_t uv = (uint64_t)value;
        const char *digits = spec->upper ? "0123456789ABCDEF"
                                         : "0123456789abcdef";
        if (uv == 0) {
            buf[0] = '0';
            len    = 1;
        }
        else {
            char tmp[20];
            int  ti = 0;
            while (uv) {
                tmp[ti++] = digits[uv & 0xF];
                uv >>= 4;
            }
            for (int j = ti - 1; j >= 0; j--) {
                buf[len++] = tmp[j];
            }
        }
    }
    else if (spec->type == 'o') {
        // Octal.
        uint64_t uv = (uint64_t)value;
        if (uv == 0) {
            buf[0] = '0';
            len    = 1;
        }
        else {
            char tmp[25];
            int  ti = 0;
            while (uv) {
                tmp[ti++] = '0' + (char)(uv & 7);
                uv >>= 3;
            }
            for (int j = ti - 1; j >= 0; j--) {
                buf[len++] = tmp[j];
            }
        }
    }
    else {
        // Decimal.
        n00b_string_t *s = n00b_fmt_int(value, .commas = commas, .allocator = allocator);
        // Apply sign flags.
        if (value >= 0 && spec->sign_plus) {
            char tmp[80];
            tmp[0] = '+';
            memcpy(tmp + 1, s->data, s->u8_bytes);
            return pad_string(tmp, (int)s->u8_bytes + 1,
                              (int)s->codepoints + 1, spec, allocator);
        }
        if (value >= 0 && spec->sign_space) {
            char tmp[80];
            tmp[0] = ' ';
            memcpy(tmp + 1, s->data, s->u8_bytes);
            return pad_string(tmp, (int)s->u8_bytes + 1,
                              (int)s->codepoints + 1, spec, allocator);
        }
        return pad_string(s->data, (int)s->u8_bytes,
                          (int)s->codepoints, spec, allocator);
    }

    buf[len] = '\0';
    return pad_string(buf, len, len, spec, allocator);
}

// ===================================================================
// Extended float formatting
// ===================================================================

n00b_string_t *
n00b_str_fmt_float_ex(double value, const n00b_format_spec_t *spec)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    char buf[128];
    int  len;

    // libc-free float formatting (n00b_fp_format_*): libc snprintf("%.*f"/"%.*e"
    // /"%.*g") descends through dtoa -> malloc, which traps on n00b off-libc
    // worker threads. The proper backend is Ryū (correctly rounded, malloc-free,
    // separate link); a weak Grisu2 fallback covers builds that drop it.
    if (spec->type == 'e') {
        int prec = spec->precision >= 0 ? spec->precision : 6;
        len      = n00b_fp_format_exp(value, prec, spec->upper, buf,
                                      sizeof(buf));
    }
    else if (spec->type == 'g') {
        int prec = spec->precision >= 0 ? spec->precision : 6;
        len      = n00b_fp_format_general(value, prec, spec->upper, buf,
                                          sizeof(buf));
    }
    else {
        // Fixed-point.
        if (spec->precision >= 0) {
            len = n00b_fp_format_fixed(value, spec->precision, buf,
                                       sizeof(buf));
        }
        else {
            // Shortest (default precision) via Grisu2.
            n00b_string_t *s = n00b_fmt_float(value,
                                              .allocator = allocator);
            return pad_string(s->data, (int)s->u8_bytes,
                              (int)s->codepoints, spec, allocator);
        }
    }

    if (len < 0) {
        len = 0;
    }

    int cps = (int)n00b_unicode_utf8_count_codepoints_raw(buf, len);
    return pad_string(buf, len, cps, spec, allocator);
}

// ===================================================================
// Extended string formatting
// ===================================================================

n00b_string_t *
n00b_str_fmt_string_ex(n00b_string_t *value, const n00b_format_spec_t *spec)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    const char *raw = value->data;
    int         len = (int)value->u8_bytes;
    int         cps = (int)value->codepoints;

    // Precision = max chars for strings.
    if (spec->precision >= 0 && cps > spec->precision) {
        // Truncate: find byte position of precision-th codepoint.
        int byte_pos = 0;
        int cp_count = 0;
        while (cp_count < spec->precision && byte_pos < len) {
            uint8_t b = (uint8_t)raw[byte_pos];
            if (b < 0x80) {
                byte_pos++;
            }
            else if ((b & 0xE0) == 0xC0) {
                byte_pos += 2;
            }
            else if ((b & 0xF0) == 0xE0) {
                byte_pos += 3;
            }
            else {
                byte_pos += 4;
            }
            cp_count++;
        }
        len = byte_pos;
        cps = cp_count;
    }

    return pad_string(raw, len, cps, spec, allocator);
}

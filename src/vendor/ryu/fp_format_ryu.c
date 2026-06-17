/* fp_format_ryu.c — STRONG n00b_fp_format_fixed/exp backed by Ryū.
 *
 * NOT upstream Ryū: this is the n00b adapter that maps n00b_fp_format_* onto
 * Ryū's correctly-rounded, malloc-free d2fixed/d2exp. Linked as the separate
 * `n00b_fpfmt_ryu` target; these STRONG definitions override the weak Grisu2
 * fallbacks in src/text/strings/fp_format.c when the library is linked.
 *
 * Specials (nan/inf) and upper-casing are normalized HERE so both backends emit
 * byte-identical output (Ryū itself writes "NaN"/"Infinity"); the digit content
 * is Ryū's. Ryū's buffered API is unbounded, so output is rendered into a
 * scratch sized for the double worst case (sign + 309 int digits + '.' + frac)
 * and bounds-checked before copy.
 */

#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>

#include "ryu/ryu.h"
#include "text/strings/fp_format.h"

#define N00B_RYU_SCRATCH 1100
// Leave room for sign + 309 integer digits + '.' + NUL on top of the fraction.
#define N00B_RYU_MAX_PREC (N00B_RYU_SCRATCH - 320)

// Identical to the fallback's special handling so the two backends match.
static int
ryu_special(double v, bool upper, char *buf, int bufsz)
{
    const char *s = nullptr;
    if (isnan(v)) {
        s = upper ? "NAN" : "nan";
    }
    else if (isinf(v)) {
        if (signbit(v)) {
            s = upper ? "-INF" : "-inf";
        }
        else {
            s = upper ? "INF" : "inf";
        }
    }
    if (s == nullptr) {
        return -1;
    }
    int n = (int)strlen(s);
    if (n + 1 > bufsz) {
        return -2;
    }
    memcpy(buf, s, n);
    buf[n] = '\0';
    return n;
}

int
n00b_fp_format_fixed(double value, int precision, char *buf, int bufsz)
{
    int sp = ryu_special(value, false, buf, bufsz);
    if (sp != -1) {
        return sp < 0 ? -1 : sp;
    }
    if (precision < 0) {
        precision = 0;
    }
    if (precision > N00B_RYU_MAX_PREC) {
        return -1;
    }

    char scratch[N00B_RYU_SCRATCH];
    int  len = d2fixed_buffered_n(value, (uint32_t)precision, scratch);
    if (len + 1 > bufsz) {
        return -1;
    }
    memcpy(buf, scratch, len);
    buf[len] = '\0';
    return len;
}

int
n00b_fp_format_exp(double value, int precision, bool upper, char *buf, int bufsz)
{
    int sp = ryu_special(value, upper, buf, bufsz);
    if (sp != -1) {
        return sp < 0 ? -1 : sp;
    }
    if (precision < 0) {
        precision = 6;
    }
    if (precision > N00B_RYU_MAX_PREC) {
        return -1;
    }

    char scratch[N00B_RYU_SCRATCH];
    int  len = d2exp_buffered_n(value, (uint32_t)precision, scratch);
    if (len + 1 > bufsz) {
        return -1;
    }
    memcpy(buf, scratch, len);
    buf[len] = '\0';

    if (upper) {
        for (int i = 0; i < len; i++) {
            if (buf[i] == 'e') {
                buf[i] = 'E';
                break;
            }
        }
    }
    return len;
}

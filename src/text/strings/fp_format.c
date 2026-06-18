/* fp_format.c — libc-free precision double formatting.
 *
 * WEAK Grisu2-shortest + decimal-round FALLBACK for n00b_fp_format_fixed/exp,
 * and the STRONG n00b_fp_format_general (printf %g) built on top of them.
 *
 * The proper, correctly-rounded backend is Ryū (src/vendor/ryu/, the
 * n00b_fpfmt_ryu link target): its STRONG n00b_fp_format_fixed/exp definitions
 * override the weak ones here when that library is linked. These fallbacks exist
 * only for size-constrained builds that drop the Ryū table; they are correct for
 * normal display precision but, beyond Grisu2's shortest significand, pad zeros
 * rather than emitting the exact binary tail (a deliberate approximation — see
 * fp_format.h). Neither path touches libc malloc/dtoa, so both are safe on
 * n00b off-libc worker threads.
 *
 * memcpy/memmove/memset and the signbit/isinf/isnan classifier macros are pure
 * (no malloc, no TSD), so they are safe here; only the libc *float* conversion
 * (dtoa -> malloc) is forbidden.
 */

#include <string.h>
#include <math.h>
#include <stdbool.h>

#include "text/strings/fptostr.h"
#include "text/strings/fp_format.h"

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

static inline bool
fp_is_neg(double v)
{
    return signbit(v);
}

// Emit a non-finite / signed special into buf; returns length, or -1 if it is a
// finite value (caller proceeds), or -2 on buffer overflow.
static int
fp_special(double v, bool upper, char *buf, int bufsz)
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

// Round the magnitude significand sig[0..n) (value = sig * 10^(dp - n), i.e. the
// decimal point sits dp digits from the left) to `frac` fractional digits.
// Writes the rounded digit run (no sign, no point) to digs and returns its
// length; *out_dp receives the (possibly carry-grown) decimal-point position.
// digs must hold at least dp + frac + 2 bytes.
static int
round_fixed_mag(const char *sig, int n, int dp, int frac, char *digs, int *out_dp)
{
    int keep = dp + frac; // significand digits at/above place 10^-frac

    if (keep <= 0) {
        // Whole significand is below the rounding place. It rounds up to one ulp
        // at 10^-frac only when the first dropped digit (sig[0], when keep == 0)
        // is >= 5; otherwise it rounds to zero. Represent +1ulp as the single
        // significand digit '1' whose place value is 10^-frac (decimal point
        // 1-frac digits from its left); zero as an empty significand (layout
        // then emits "0" + the fractional zeros).
        bool roundup = (keep == 0 && n > 0 && sig[0] >= '5');
        if (roundup) {
            digs[0] = '1';
            *out_dp = 1 - frac;
            return 1;
        }
        *out_dp = 0;
        return 0;
    }

    int take = keep < n ? keep : n; // real significand digits retained
    memcpy(digs, sig, take);
    if (keep > n) {
        memset(digs + take, '0', keep - n); // pad below shortest (approximation)
    }

    // Round half-up on the first dropped digit (only meaningful if keep < n).
    if (keep < n && sig[keep] >= '5') {
        int i = keep - 1;
        while (i >= 0 && digs[i] == '9') {
            digs[i] = '0';
            i--;
        }
        if (i < 0) {
            // Carried past the top: 999.. -> 1000.. ; shift right, grow dp.
            memmove(digs + 1, digs, keep);
            digs[0] = '1';
            *out_dp = dp + 1;
            return keep + 1;
        }
        digs[i]++;
    }

    *out_dp = dp;
    return keep;
}

// Lay out digs[0..len) with decimal point at dp into buf as fixed notation with
// exactly `frac` fractional digits. Returns length or -1 on overflow.
static int
layout_fixed(bool neg, const char *digs, int len, int dp, int frac, char *buf,
             int bufsz)
{
    int need = (neg ? 1 : 0) + (dp > 0 ? dp : 1) + (frac > 0 ? frac + 1 : 0) + 1;
    if (need > bufsz) {
        return -1;
    }

    int p = 0;
    if (neg) {
        buf[p++] = '-';
    }

    // integer part
    if (dp <= 0) {
        buf[p++] = '0';
    }
    else {
        memcpy(buf + p, digs, dp);
        p += dp;
    }

    if (frac > 0) {
        buf[p++] = '.';
        if (dp <= 0) {
            int lead = -dp; // zeros between point and first significant digit
            if (lead > frac) {
                lead = frac;
            }
            memset(buf + p, '0', lead);
            p += lead;
            int rest = frac - lead;
            int avail = len; // all digits are fractional when dp<=0
            int cp    = rest < avail ? rest : avail;
            memcpy(buf + p, digs, cp);
            p += cp;
            if (rest > cp) {
                memset(buf + p, '0', rest - cp);
                p += rest - cp;
            }
        }
        else {
            int avail = len - dp; // fractional digits present in digs
            if (avail < 0) {
                avail = 0;
            }
            int cp = frac < avail ? frac : avail;
            memcpy(buf + p, digs + dp, cp);
            p += cp;
            if (frac > cp) {
                memset(buf + p, '0', frac - cp);
                p += frac - cp;
            }
        }
    }

    buf[p] = '\0';
    return p;
}

// Round the magnitude significand to `sd` significant digits. Writes exactly sd
// digits to out and sets *exp10 to the base-10 exponent of the leading digit.
static void
round_sig_mag(const char *sig, int n, int K, int sd, char *out, int *exp10)
{
    int lead = K + n - 1; // exponent of sig[0]

    if (sd >= n) {
        memcpy(out, sig, n);
        memset(out + n, '0', sd - n);
        *exp10 = lead;
        return;
    }

    memcpy(out, sig, sd);
    if (sig[sd] >= '5') {
        int i = sd - 1;
        while (i >= 0 && out[i] == '9') {
            out[i] = '0';
            i--;
        }
        if (i < 0) {
            memmove(out + 1, out, sd - 1);
            out[0] = '1';
            *exp10 = lead + 1;
            return;
        }
        out[i]++;
    }
    *exp10 = lead;
}

static int
layout_exp(bool neg, const char *mant, int sd, int exp10, int frac, bool upper,
           char *buf, int bufsz)
{
    // mant has sd = frac + 1 significant digits: d.dddd e±XX
    int p = 0;
    if (neg) {
        if (p + 1 >= bufsz) {
            return -1;
        }
        buf[p++] = '-';
    }
    if (p + 1 >= bufsz) {
        return -1;
    }
    buf[p++] = mant[0];
    if (frac > 0) {
        if (p + 1 + frac >= bufsz) {
            return -1;
        }
        buf[p++] = '.';
        memcpy(buf + p, mant + 1, frac);
        p += frac;
    }
    if (p + 1 >= bufsz) {
        return -1;
    }
    buf[p++] = upper ? 'E' : 'e';

    int e = exp10;
    if (p + 1 >= bufsz) {
        return -1;
    }
    buf[p++] = e < 0 ? '-' : '+';
    if (e < 0) {
        e = -e;
    }
    // At least two exponent digits (printf convention).
    char ed[8];
    int  en = 0;
    if (e == 0) {
        ed[en++] = '0';
    }
    while (e > 0) {
        ed[en++] = (char)('0' + e % 10);
        e /= 10;
    }
    while (en < 2) {
        ed[en++] = '0';
    }
    if (p + en + 1 > bufsz) {
        return -1;
    }
    for (int i = en - 1; i >= 0; i--) {
        buf[p++] = ed[i];
    }
    buf[p] = '\0';
    return p;
}

// ---------------------------------------------------------------------------
// weak fallback entry points (overridden by the Ryū link target)
// ---------------------------------------------------------------------------

__attribute__((weak)) int
n00b_fp_format_fixed(double value, int precision, char *buf, int bufsz)
{
    int sp = fp_special(value, false, buf, bufsz);
    if (sp != -1) {
        return sp < 0 ? -1 : sp;
    }
    if (precision < 0) {
        precision = 0;
    }

    bool neg = fp_is_neg(value);
    char sig[18];
    int  K;
    int  n = n00b_fptostr_digits(value, sig, &K);

    if (n == 0) {
        // Zero.
        char digs[1] = {'0'};
        return layout_fixed(neg, digs, 0, 0, precision, buf, bufsz);
    }

    int  dp = n + K;
    char digs[160];
    if (dp + precision + 2 > (int)sizeof(digs)) {
        return -1;
    }
    int new_dp;
    int len = round_fixed_mag(sig, n, dp, precision, digs, &new_dp);
    return layout_fixed(neg, digs, len, new_dp, precision, buf, bufsz);
}

__attribute__((weak)) int
n00b_fp_format_exp(double value, int precision, bool upper, char *buf, int bufsz)
{
    int sp = fp_special(value, upper, buf, bufsz);
    if (sp != -1) {
        return sp < 0 ? -1 : sp;
    }
    if (precision < 0) {
        precision = 6;
    }

    bool neg = fp_is_neg(value);
    char sig[18];
    int  K;
    int  n = n00b_fptostr_digits(value, sig, &K);

    if (n == 0) {
        // Zero -> 0.000e+00
        char mant[160];
        if (precision + 1 > (int)sizeof(mant)) {
            return -1;
        }
        memset(mant, '0', precision + 1);
        return layout_exp(neg, mant, precision + 1, 0, precision, upper, buf,
                          bufsz);
    }

    int  sd = precision + 1;
    char mant[160];
    if (sd > (int)sizeof(mant)) {
        return -1;
    }
    int exp10;
    round_sig_mag(sig, n, K, sd, mant, &exp10);
    return layout_exp(neg, mant, sd, exp10, precision, upper, buf, bufsz);
}

// ---------------------------------------------------------------------------
// general (%g) — strong; built on whichever fixed/exp backend is linked.
// ---------------------------------------------------------------------------

int
n00b_fp_format_general(double value, int precision, bool upper, char *buf,
                       int bufsz)
{
    int sp = fp_special(value, upper, buf, bufsz);
    if (sp != -1) {
        return sp < 0 ? -1 : sp;
    }
    if (precision < 0) {
        precision = 6;
    }
    if (precision == 0) {
        precision = 1; // printf %g: P==0 treated as 1
    }

    // printf %g: let X be the decimal exponent of the value. Use scientific iff
    // X < -4 or X >= P; else fixed. Trailing zeros (and a trailing point) are
    // removed. Determine X from the rounded-to-P-significant-digits magnitude.
    bool neg = fp_is_neg(value);
    char sig[18];
    int  K;
    int  n = n00b_fptostr_digits(value, sig, &K);
    int  X = 0;
    if (n != 0) {
        char tmp[160];
        if (precision <= (int)sizeof(tmp)) {
            round_sig_mag(sig, n, K, precision, tmp, &X);
        }
        else {
            X = K + n - 1;
        }
    }

    int len;
    if (X < -4 || X >= precision) {
        // scientific with (P-1) fractional mantissa digits
        len = n00b_fp_format_exp(value, precision - 1, upper, buf, bufsz);
        if (len < 0) {
            return len;
        }
        // Trim trailing zeros in the mantissa (before 'e'/'E').
        int e = 0;
        while (e < len && buf[e] != 'e' && buf[e] != 'E') {
            e++;
        }
        if (e < len) {
            int last = e - 1;
            int dot  = -1;
            for (int i = 0; i < e; i++) {
                if (buf[i] == '.') {
                    dot = i;
                    break;
                }
            }
            if (dot >= 0) {
                while (last > dot && buf[last] == '0') {
                    last--;
                }
                if (last == dot) {
                    last--; // drop the point too
                }
                int tail = len - e;
                memmove(buf + last + 1, buf + e, tail);
                len = last + 1 + tail;
                buf[len] = '\0';
            }
        }
        return len;
    }

    // fixed with (P-1-X) fractional digits
    int frac = precision - 1 - X;
    if (frac < 0) {
        frac = 0;
    }
    len = n00b_fp_format_fixed(value, frac, buf, bufsz);
    if (len < 0) {
        return len;
    }
    // Trim trailing zeros (and a trailing point) if there is a point.
    int dot = -1;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '.') {
            dot = i;
            break;
        }
    }
    if (dot >= 0) {
        int last = len - 1;
        while (last > dot && buf[last] == '0') {
            last--;
        }
        if (last == dot) {
            last--;
        }
        len      = last + 1;
        buf[len] = '\0';
    }
    (void)neg;
    return len;
}

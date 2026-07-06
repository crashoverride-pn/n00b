/** @file core/time.c
 *  @brief Non-inline time helpers — currently just the ISO-8601 UTC
 *  formatter used by protocol envelopes (SKP ingestion `received_at`,
 *  AWS SigV4 `amz_date`, X.509 UTCTime) that need a deterministic
 *  textual stamp.
 *
 *  Inline helpers (timestamp capture, duration arithmetic, timespec
 *  comparison) stay in `include/core/time.h`.
 */

#include "n00b.h"
#include "core/time.h"
#include "core/string.h"

static size_t
n00b_format_iso8601_utc_buf(int64_t epoch_secs, char *out, size_t n)
{
    /* libc-free UTC breakdown + formatting.  gmtime_r/strftime were the
     * prior "single boundary for broken-down UTC time", but libc's lazy
     * timezone init (gmtsub -> gmt_init -> pthread_once -> notify_register)
     * touches pthread TSD, which an n00b off-libc worker thread (WP-001)
     * does not have — calling them there SIGTRAPs in pthread_self.  This
     * is the off-libc-safe replacement: pure integer arithmetic, no libc
     * calendar/format call, no TLS, and no heap allocation. */
    char buf[21];

    int64_t secs = epoch_secs;
    int64_t days = secs / 86400;
    int64_t rem  = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    int hh = (int)(rem / 3600);
    int mm = (int)((rem % 3600) / 60);
    int ss = (int)(rem % 60);

    /* Days since 1970-01-01 -> civil (year, month, day): Howard Hinnant's
     * days_from_civil inverse (public-domain), valid for the proleptic
     * Gregorian calendar across the full time_t range. */
    int64_t z   = days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;                                // [0,146096]
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0,399]
    int64_t y   = yoe + era * 400;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);         // [0,365]
    int64_t mp  = (5 * doy + 2) / 153;                            // [0,11]
    int64_t d   = doy - (153 * mp + 2) / 5 + 1;                   // [1,31]
    int64_t m   = mp < 10 ? mp + 3 : mp - 9;                      // [1,12]
    y += (m <= 2);

    /* Fixed layout: YYYY-MM-DDTHH:MM:SSZ (20 chars).  Year clamped to the
     * 4-digit field; negative/over-9999 years are out of scope for the
     * protocol stamps this serves. */
    if (y < 0) {
        y = 0;
    }
    if (y > 9999) {
        y = 9999;
    }
    buf[0]  = (char)('0' + (int)((y / 1000) % 10));
    buf[1]  = (char)('0' + (int)((y / 100) % 10));
    buf[2]  = (char)('0' + (int)((y / 10) % 10));
    buf[3]  = (char)('0' + (int)(y % 10));
    buf[4]  = '-';
    buf[5]  = (char)('0' + (int)((m / 10) % 10));
    buf[6]  = (char)('0' + (int)(m % 10));
    buf[7]  = '-';
    buf[8]  = (char)('0' + (int)((d / 10) % 10));
    buf[9]  = (char)('0' + (int)(d % 10));
    buf[10] = 'T';
    buf[11] = (char)('0' + (hh / 10));
    buf[12] = (char)('0' + (hh % 10));
    buf[13] = ':';
    buf[14] = (char)('0' + (mm / 10));
    buf[15] = (char)('0' + (mm % 10));
    buf[16] = ':';
    buf[17] = (char)('0' + (ss / 10));
    buf[18] = (char)('0' + (ss % 10));
    buf[19] = 'Z';
    buf[20] = '\0';

    if (n != 0 && out != nullptr) {
        size_t limit = n - 1;
        size_t len   = limit < 20 ? limit : 20;
        for (size_t i = 0; i < len; i++) {
            out[i] = buf[i];
        }
        out[len] = '\0';
    }
    return 20;
}

n00b_string_t *
n00b_iso8601_utc(n00b_duration_t *t)
{
    char buf[21];
    (void)n00b_format_iso8601_utc_buf(t ? (int64_t)t->tv_sec : (int64_t)0,
                                      buf,
                                      sizeof(buf));
    return n00b_string_from_raw(buf, 20);
}

/* Forward civil-date -> days-since-epoch (Howard Hinnant's days_from_civil,
 * public domain) — the inverse of the conversion in the formatter above. */
static int64_t
iso8601_days_from_civil(int64_t y, uint32_t m, uint32_t d)
{
    y -= m <= 2;
    int64_t  era = (y >= 0 ? y : y - 399) / 400;
    uint32_t yoe = (uint32_t)(y - era * 400);
    uint32_t doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static bool
iso8601_parse_fixed_u32(const char *data, size_t off, size_t n, uint32_t *out)
{
    uint32_t v = 0;
    for (size_t i = off; i < off + n; i++) {
        char c = data[i];
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10u + (uint32_t)(c - '0');
    }
    *out = v;
    return true;
}

static uint32_t
iso8601_month_days(uint32_t y, uint32_t m)
{
    static const uint32_t days[12] = {31, 28, 31, 30, 31, 30,
                                      31, 31, 30, 31, 30, 31};
    if (m == 2
        && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) {
        return 29;
    }
    return days[m - 1];
}

bool
n00b_iso8601_parse_ns(const char *data, size_t len, uint64_t *out_ns)
{
    /* Accepts `YYYY-MM-DDTHH:MM:SS[.fffffffff]Z` (RFC-3339 UTC — the exact
     * shape n00b_iso8601_utc emits, plus optional fractional seconds).
     * Allocation- and libc-free; safe on off-libc worker threads. */
    if (data == nullptr || out_ns == nullptr || len < 20) {
        return false;
    }
    if (data[4] != '-' || data[7] != '-' || data[10] != 'T'
        || data[13] != ':' || data[16] != ':') {
        return false;
    }
    uint32_t y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
    if (!iso8601_parse_fixed_u32(data, 0, 4, &y)
        || !iso8601_parse_fixed_u32(data, 5, 2, &mo)
        || !iso8601_parse_fixed_u32(data, 8, 2, &d)
        || !iso8601_parse_fixed_u32(data, 11, 2, &h)
        || !iso8601_parse_fixed_u32(data, 14, 2, &mi)
        || !iso8601_parse_fixed_u32(data, 17, 2, &sec)) {
        return false;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > iso8601_month_days(y, mo)
        || h > 23 || mi > 59 || sec > 60) {
        return false;
    }

    size_t   i       = 19;
    uint64_t frac_ns = 0;
    if (i < len && data[i] == '.') {
        i++;
        uint64_t scale  = 100000000ULL;
        size_t   digits = 0;
        while (i < len && data[i] >= '0' && data[i] <= '9') {
            if (digits < 9) {
                frac_ns += (uint64_t)(data[i] - '0') * scale;
                scale /= 10ULL;
            }
            digits++;
            i++;
        }
        if (digits == 0) {
            return false;
        }
    }
    if (i + 1 != len || data[i] != 'Z') {
        return false;
    }

    int64_t days = iso8601_days_from_civil((int64_t)y, mo, d);
    if (days < 0) {
        return false;
    }
    uint64_t epoch_s = (uint64_t)days * 86400ULL + (uint64_t)h * 3600ULL
                     + (uint64_t)mi * 60ULL + (uint64_t)sec;
    if (epoch_s > (UINT64_MAX - frac_ns) / 1000000000ULL) {
        return false;
    }
    *out_ns = epoch_s * 1000000000ULL + frac_ns;
    return true;
}

void
n00b_iso8601_utc_buf(int64_t epoch_secs, char *out, size_t n)
{
    /* Plain-C-ABI convenience wrapper over the allocation-free formatter,
     * for callers
     * that cannot include n00b's `_kargs` headers (e.g. clang-compiled
     * ObjC daemon code) and want a NUL-terminated C-string buffer. */
    (void)n00b_format_iso8601_utc_buf(epoch_secs, out, n);
}

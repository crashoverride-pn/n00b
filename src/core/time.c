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

void
n00b_iso8601_utc_buf(int64_t epoch_secs, char *out, size_t n)
{
    /* Plain-C-ABI convenience wrapper over the allocation-free formatter,
     * for callers
     * that cannot include n00b's `_kargs` headers (e.g. clang-compiled
     * ObjC daemon code) and want a NUL-terminated C-string buffer. */
    (void)n00b_format_iso8601_utc_buf(epoch_secs, out, n);
}

/**
 * @file time.h
 * @brief Time capture and comparison utilities.
 *
 * Provides nanosecond and microsecond timestamp helpers, duration
 * arithmetic, and timespec comparison used by futex waits and GC
 * statistics.
 */
#pragma once

#include <time.h> // IWYU pragma: keep
#ifndef _WIN32
#include <sys/time.h>
#else
#include "core/platform.h"
#endif

#define N00B_USEC_PER_SEC 1000000
#define N00B_NSEC_PER_SEC 1000000000
#define N00B_MS_PER_SEC   1000
#define N00B_NS_PER_MS    1000000

/**
 * @brief Capture the current wall-clock time.
 * @param output Duration structure to fill.
 */
static inline void
n00b_capture_timestamp(n00b_duration_t *output)
{
    clock_gettime(CLOCK_REALTIME, (struct timespec *)output);
}

/**
 * @brief Convert a duration to nanoseconds.
 * @param d Duration to convert.
 * @return  Total nanoseconds.
 */
static inline int64_t
n00b_ns_from_duration(n00b_duration_t *d)
{
    return d->tv_sec * N00B_NS_PER_SEC + d->tv_nsec;
}

/**
 * @brief Compute the nanosecond difference between two durations.
 * @param d1 First duration.
 * @param d2 Second duration.
 * @return   d1 - d2 in nanoseconds.
 */
static inline int64_t
n00b_ns_minus(n00b_duration_t *d1, n00b_duration_t *d2)
{
    int64_t ns1 = n00b_ns_from_duration(d1);
    int64_t ns2 = n00b_ns_from_duration(d2);

    return ns1 - ns2;
}

/**
 * @brief Get a monotonic nanosecond timestamp.
 * @return Current monotonic time in nanoseconds.
 */
static inline int64_t
n00b_ns_timestamp(void)
{
    n00b_duration_t d;
    clock_gettime(CLOCK_MONOTONIC, (void *)&d);

    return n00b_ns_from_duration(&d);
}

/**
 * @brief Get a wall-clock microsecond timestamp.
 * @return Current time in microseconds since the epoch.
 */
static inline int64_t
n00b_us_timestamp(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    // FILETIME is 100-ns intervals since 1601-01-01; convert to us since epoch.
    t -= 116444736000000000ULL;
    return (int64_t)(t / 10);
#else
    struct timeval tv;
    gettimeofday(&tv, nullptr);

    return tv.tv_sec * N00B_USEC_PER_SEC + tv.tv_usec;
#endif
}

/**
 * @brief Return true if @p t1 is strictly later than @p t2.
 * @param t1 First timespec.
 * @param t2 Second timespec.
 * @return   true if t1 > t2.
 */
static inline bool
n00b_timestamp_gt(struct timespec *t1,
                  struct timespec *t2)
{
    if (t1->tv_sec > t2->tv_sec) {
        return true;
    }
    if (t1->tv_sec < t2->tv_sec) {
        return false;
    }

    return t1->tv_nsec > t2->tv_nsec;
}

/**
 * @brief Compute the absolute difference between two timespecs.
 * @param t1     First timespec.
 * @param t2     Second timespec.
 * @param result Output: |t1 - t2|.
 */
static inline void
n00b_timestamp_diff(struct timespec *t1,
                    struct timespec *t2,
                    struct timespec *result)
{
    struct timespec *b, *l;

    if (n00b_timestamp_gt(t1, t2)) {
        b = t1;
        l = t2;
    }
    else {
        b = t2;
        l = t1;
    }
    result->tv_nsec = b->tv_nsec - l->tv_nsec;
    result->tv_sec  = b->tv_sec - l->tv_sec;

    if (result->tv_nsec < 0) {
        result->tv_nsec += N00B_NSEC_PER_SEC;
        result->tv_sec -= 1;
    }
}

/**
 * @brief Format a wall-clock timestamp as RFC-3339 / ISO-8601 UTC.
 *
 * Format is `YYYY-MM-DDTHH:MM:SSZ` (second precision). The `tv_nsec`
 * field of @p t is ignored — extend the API when a consumer needs
 * sub-second precision.
 *
 * @param t  Wall-clock timestamp (as produced by
 *           `n00b_capture_timestamp`). Must not be NULL.
 * @return   A newly-allocated n00b string. Never NULL.
 */
extern n00b_string_t *n00b_iso8601_utc(n00b_duration_t *t);

/**
 * @brief Plain-C-ABI ISO-8601 UTC formatter into a caller buffer.
 *
 * Convenience wrapper over @ref n00b_iso8601_utc for callers that cannot
 * include n00b's `_kargs` headers (e.g. clang-compiled ObjC daemon code)
 * and want a NUL-terminated C string.  Writes at most @p n-1 chars plus a
 * NUL.  libc-free — safe to call on n00b off-libc worker threads (unlike
 * libc gmtime/strftime).
 *
 * @param epoch_secs  Seconds since the Unix epoch (UTC).
 * @param out         Destination buffer (>= 21 bytes for full precision).
 * @param n           Size of @p out.
 */
extern void n00b_iso8601_utc_buf(int64_t epoch_secs, char *out, size_t n);

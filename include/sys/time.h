#pragma once

#ifdef _WIN32
#include "internal/win32_sockets.h"

#include <stdint.h>

#ifndef N00B_STRUCT_TIMEZONE_DEFINED
#define N00B_STRUCT_TIMEZONE_DEFINED 1
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
#endif

static inline int
n00b_win_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    if (tv) {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);

        uint64_t now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        now /= 10;
        now -= 11644473600000000ULL;

        tv->tv_sec  = (long)(now / 1000000ULL);
        tv->tv_usec = (long)(now % 1000000ULL);
    }

    if (tz) {
        tz->tz_minuteswest = 0;
        tz->tz_dsttime     = 0;
    }

    return 0;
}

#ifndef gettimeofday
#define gettimeofday(tv, tz) n00b_win_gettimeofday((tv), (tz))
#endif

#else
#include_next <sys/time.h>
#endif

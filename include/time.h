#pragma once

#include_next <time.h>

#ifdef _WIN32

__declspec(dllimport) void __attribute__((__stdcall__)) Sleep(unsigned long milliseconds);

[[n00b::nogc]]
static inline int
nanosleep(const struct timespec *req, struct timespec *rem)
{
    if (!req) {
        return 0;
    }

    unsigned long milliseconds =
        (unsigned long)(req->tv_sec * 1000 + (req->tv_nsec + 999999) / 1000000);
    Sleep(milliseconds);
    if (rem) {
        rem->tv_sec  = 0;
        rem->tv_nsec = 0;
    }
    return 0;
}

#endif

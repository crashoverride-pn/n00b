/**
 * @file random.h
 * @brief Cryptographic-quality pseudo-random number generation.
 *
 * On Linux, uses the getrandom(2) system call.  On macOS/arm64, uses
 * the raw getentropy(2) syscall so n00b-owned Mach workers do not cross
 * into pthread/TSD-dependent libc randomness.  Other BSDs use
 * arc4random_buf().  Convenience typed wrappers (n00b_rand8 .. n00b_rand64)
 * are generated via macro.
 */
#pragma once

#include <stdint.h>

// On Linux we are best off using the low-level interface to the
// system PRNG.  On other Unix systems, we fall back to
// `arc4random_buf()` which is widely available.

#if defined(__linux__)
#include <sys/random.h>
#include <stdlib.h> // for abort

static inline void
n00b_random_bytes(char *bufptr, size_t len)
{
    if (getrandom(bufptr, len, GRND_NONBLOCK) == -1) {
        abort();
    }
}
#elif defined(__APPLE__) && defined(__aarch64__)

#include "core/syscall.h"
#include <stddef.h>

static inline void
n00b_random_bytes(char *bufptr, size_t len)
{
    char  *cursor    = bufptr;
    size_t remaining = len;

    while (remaining != 0) {
        size_t chunk = remaining > 256u ? 256u : remaining;
        long rc = n00b_raw_getentropy(cursor, (unsigned long)chunk);
        if (rc != 0) {
            n00b_raw_exit(70);
        }

        cursor += chunk;
        remaining -= chunk;
    }
}
#elif defined(__APPLE__) || defined(BSD)

// IWYU Picks this up on the mac, but isn't wanted.
// IWYU pragma: no_include <_stdlib.h>
// for arc4random_buf
#include <stdlib.h> // IWYU pragma: keep
#define n00b_random_bytes(bufptr, len) arc4random_buf(bufptr, len)
#elif defined(_WIN32)
#include "core/platform.h"
#include <stdlib.h>

static inline void
n00b_random_bytes(char *bufptr, size_t len)
{
    if (!RtlGenRandom(bufptr, (ULONG)len)) {
        abort();
    }
}
#else
#error "Unsupported platform."
#endif

// clang-format off
#define N00B_DECLARE_RAND_FN(type_name, designator)        \
                                                           \
static inline type_name                                    \
n00b_rand##designator(void)                                \
{                                                          \
    type_name result;                                      \
                                                           \
    n00b_random_bytes((char *)&result, sizeof(type_name)); \
                                                           \
    return result;                                         \
}
// clang-format on

// Explicitly add the prototypes for the sake of grep, etc.
static inline uint64_t n00b_rand64(void);
static inline uint32_t n00b_rand32(void);
static inline uint16_t n00b_rand16(void);
static inline uint8_t  n00b_rand8(void);
static inline int64_t  n00b_rand_i64(void);
static inline int32_t  n00b_rand_i32(void);
static inline int16_t  n00b_rand_i16(void);
static inline int8_t   n00b_rand_i8(void);

N00B_DECLARE_RAND_FN(uint64_t, 64);
N00B_DECLARE_RAND_FN(int64_t, _i64);
N00B_DECLARE_RAND_FN(uint32_t, 32);
N00B_DECLARE_RAND_FN(int32_t, _i32);
N00B_DECLARE_RAND_FN(uint16_t, 16);
N00B_DECLARE_RAND_FN(int16_t, _i16);
N00B_DECLARE_RAND_FN(uint8_t, 8);
N00B_DECLARE_RAND_FN(int8_t, _i8);

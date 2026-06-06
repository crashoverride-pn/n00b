#pragma once

/**
 * @file core/alloc_interpose_shim.h
 * @brief Compile-time redirect of the libc malloc family to n00b's user pool.
 *
 * Force-included (meson `-include`) into the vendored QUIC libraries
 * (picoquic / picotls) and n00b's own QUIC glue. Those translation units
 * call the libc malloc family directly, and that traps on n00b off-libc
 * worker threads (libc's first-malloc-per-thread builds a cache via
 * pthread_self, which faults on a minimal TCB; macOS arm64 PAC). Redirecting
 * the calls at compile time to n00b_interposed_* routes every allocation into
 * n00b's non-moving, free-by-pointer user pool instead. See
 * core/alloc_interpose.h for the full rationale and the runtime API.
 *
 * Why compile-time rather than runtime interposition on macOS: dyld
 * `__DATA,__interpose` tables only take effect when they live in a *dylib*
 * (dyld never interposes the image that contains the table), so a table in
 * the statically-linked main executable cannot redirect statically-linked
 * picoquic. The compile-time shim sidesteps dyld entirely and is uniform
 * across platforms. (Linux additionally gets process-wide coverage from the
 * strong malloc symbols in libn00b.)
 */

/* This shim is force-included (meson `-include`) ahead of everything else in
 * the TU, including the TU's own feature-test-macro setup. The system headers
 * we pull in just below drag in glibc's <features.h>, which latches the
 * feature set permanently — so a vendored TU that defines e.g.
 * `_XOPEN_SOURCE 700` at its own top (picotls's cifra/random.c, to expose
 * O_CLOEXEC) would define it too late and lose those declarations. Under
 * `-std=c11` glibc sets __STRICT_ANSI__ and will NOT default to
 * _DEFAULT_SOURCE, so without help O_CLOEXEC / getaddrinfo / etc. vanish.
 * Establish the broad GNU feature set up front (superset of _XOPEN_SOURCE,
 * _POSIX_C_SOURCE, _DEFAULT_SOURCE; matches the `-D_GNU_SOURCE` picoquic's
 * build already passes on Linux) so those TUs still compile. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

/* Pull in the real prototypes FIRST, before the macros below, so the system
 * declarations are seen unmangled; the include guards then no-op any later
 * re-include from the shimmed TU. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__linux__)
#include <malloc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern void  *n00b_interposed_malloc(size_t);
extern void   n00b_interposed_free(void *);
extern void  *n00b_interposed_calloc(size_t, size_t);
extern void  *n00b_interposed_realloc(void *, size_t);
extern void  *n00b_interposed_reallocarray(void *, size_t, size_t);
extern char  *n00b_interposed_strdup(const char *);
extern char  *n00b_interposed_strndup(const char *, size_t);
extern int    n00b_interposed_posix_memalign(void **, size_t, size_t);
extern void  *n00b_interposed_aligned_alloc(size_t, size_t);
extern size_t n00b_interposed_malloc_usable_size(void *);

#ifdef __cplusplus
}
#endif

/* Function-like macros: they only fire on `name(...)` call syntax, so a bare
 * reference or struct member named `free`/`malloc` is left alone. */
#define malloc(n)              n00b_interposed_malloc(n)
#define free(p)                n00b_interposed_free(p)
#define calloc(c, n)           n00b_interposed_calloc((c), (n))
#define realloc(p, n)          n00b_interposed_realloc((p), (n))
#define reallocarray(p, c, n)  n00b_interposed_reallocarray((p), (c), (n))
#define strdup(s)              n00b_interposed_strdup(s)
#define strndup(s, n)          n00b_interposed_strndup((s), (n))
#define posix_memalign(m, a, s) n00b_interposed_posix_memalign((m), (a), (s))
#define aligned_alloc(a, s)    n00b_interposed_aligned_alloc((a), (s))
#define malloc_usable_size(p)  n00b_interposed_malloc_usable_size(p)
#if defined(__APPLE__)
#define malloc_size(p)         n00b_interposed_malloc_usable_size(p)
#endif

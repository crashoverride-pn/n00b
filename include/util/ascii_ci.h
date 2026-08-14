#pragma once

/**
 * @file util/ascii_ci.h
 * @brief Locale-independent ASCII case-insensitive string comparison.
 *
 * Houses @ref n00b_ascii_ci_eq / @ref n00b_ascii_ci_eq_n — the §2.10-clean
 * replacement for libc `strcasecmp()` / `strncasecmp()` at libn00b call
 * sites.
 *
 * # Why a dedicated helper
 *
 * glibc's `strcasecmp`/`strncasecmp` are locale-aware: they read
 * per-thread `LC_CTYPE` state through the thread's glibc
 * thread-control-block. n00b's worker-pool / off-libc worker threads
 * (`n00b_thread_spawn` -> raw `clone(2)`, see `src/core/thread.c`) are
 * deliberately created WITHOUT a normal glibc TCB, so any call into a
 * locale-aware libc function from such a thread reads uninitialized
 * TLS-backed state and crashes (confirmed root cause of a `SIGSEGV`
 * inside `strcasecmp` when `n00b_http_decompress()` — called from a
 * worker-pool thread — compared an HTTP `Content-Encoding` token).
 *
 * The tokens every current libn00b call site actually compares
 * case-insensitively (`Content-Encoding` values, header names, `Connection`
 * tokens, cookie domains, HTTP methods, ...) are all wire-format ASCII
 * per their respective RFCs — none of this is meant to be locale-sensitive
 * in the first place, so a plain byte-wise ASCII fold is not just safe,
 * it is the semantically correct comparison (a Turkish locale's
 * dotless/dotted 'i' handling, for example, must NOT apply to an HTTP
 * token).
 *
 * # Allocator discipline
 *
 * Pure, allocation-free comparisons over raw `const char *` — no
 * `n00b_string_t`, no `_kargs`, no allocator threading.
 */

#include <stddef.h>

/**
 * @brief ASCII case-insensitive equality, NUL-terminated strings.
 *
 * @param a  First string. `nullptr` compares equal only to another
 *           `nullptr` (mirrors two-null-pointer libc `strcasecmp`
 *           behavior only via this documented special case — libc's
 *           actual behavior on NULL is undefined; callers relying on
 *           NULL-safety should use this accessor specifically for it).
 * @param b  Second string.
 *
 * @return `true` iff the two strings are equal after folding ASCII
 *         `A`-`Z` to `a`-`z` byte-by-byte (non-ASCII bytes, including
 *         UTF-8 continuation bytes, compare literally/unfolded).
 */
extern bool
n00b_ascii_ci_eq(const char *a, const char *b);

/**
 * @brief ASCII case-insensitive equality over exactly @p n bytes.
 *
 * @param a  First buffer (need not be NUL-terminated).
 * @param b  Second buffer (need not be NUL-terminated).
 * @param n  Number of bytes to compare from each buffer.
 *
 * @return `true` iff the first @p n bytes of @p a and @p b are equal
 *         after folding ASCII `A`-`Z` to `a`-`z` byte-by-byte. Neither
 *         buffer is read past @p n bytes (embedded NULs do not
 *         terminate the comparison early, matching `strncasecmp`'s
 *         fixed-length shape rather than `strcasecmp`'s).
 */
extern bool
n00b_ascii_ci_eq_n(const char *a, const char *b, size_t n);

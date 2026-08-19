/* src/util/ascii_ci.c — locale-independent ASCII case-insensitive compare.
 *
 * Implements the surface declared in include/util/ascii_ci.h:
 *   - n00b_ascii_ci_eq    (NUL-terminated, strcasecmp-shaped)
 *   - n00b_ascii_ci_eq_n  (fixed-length, strncasecmp-shaped)
 *
 * Deliberately does NOT call libc's strcasecmp/strncasecmp, nor libc's
 * tolower()/toupper() (ctype.h's tolower is also locale-aware and reads
 * the same TLS-backed per-thread state on glibc) -- see the header
 * comment for why: n00b's off-libc worker threads have no glibc TCB, and
 * every current call site's tokens (HTTP header names/values, cookie
 * domains, methods) are wire-format ASCII where locale-sensitive folding
 * would be incorrect anyway.
 */

#include "util/ascii_ci.h"

static inline unsigned char
ascii_fold(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + ('a' - 'A')) : c;
}

bool
n00b_ascii_ci_eq(const char *a, const char *b) {
    if (a == b) {
        return true;
    }
    if (a == nullptr || b == nullptr) {
        return false;
    }
    while (*a != '\0' && *b != '\0') {
        if (ascii_fold((unsigned char)*a) != ascii_fold((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == *b;
}

bool
n00b_ascii_ci_eq_n(const char *a, const char *b, size_t n) {
    if (a == b || n == 0) {
        return true;
    }
    if (a == nullptr || b == nullptr) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (ascii_fold((unsigned char)a[i]) != ascii_fold((unsigned char)b[i])) {
            return false;
        }
    }
    return true;
}

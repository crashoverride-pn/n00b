#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "util/parse_num.h"

// n00b#467. The HTTP/1 and HTTP/3 Content-Length paths parse with
// n00b_parse_byte_count_span instead of strtoul/strtoull, because the libc
// converters read the calling thread's TLS locale pointer -- NULL on an n00b
// worker (raw clone(2), minimal zeroed TCB) -- and dereference it.
//
// The saturating behaviour below is not cosmetic. Those call sites gate a body
// against max_body_size, and the code this replaced got its rejection of an
// absurd length from strtoull OVERFLOWING inside a 24-byte scratch buffer. A
// parser that reported overflow as a plain error, and a caller that mapped any
// error to 0, would turn "refuse this body" into "admit this body". So the
// overflow case is pinned here explicitly.

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

static void
check_count(const char *lit, uint64_t expected, const char *what)
{
    uint64_t got = n00b_parse_byte_count_span(lit, strlen(lit));

    if (got != expected) {
        fprintf(stderr,
                "byte count mismatch (%s): input=\"%s\" got=%llu expected=%llu\n",
                what,
                lit,
                (unsigned long long)got,
                (unsigned long long)expected);
    }
    CHECK(got == expected);
}

static void
test_ordinary_lengths(void)
{
    check_count("0", 0, "zero");
    check_count("20", 20, "the value from the n00b#467 trace");
    check_count("1048576", 1048576, "a megabyte");
    check_count("9223372036854775807", INT64_MAX, "int64 max, still exact");

    printf("  [PASS] ordinary content lengths\n");
}

static void
test_span_is_honored_without_a_terminator(void)
{
    // The header value is borrowed from the middle of a receive buffer and is
    // NOT NUL-terminated. The old code copied it into scratch just to
    // terminate it; parsing the span directly is the reason that copy is gone,
    // so a parser that ran past `len` would be caught here.
    const char *raw = "Content-Length: 20\r\nHost: x\r\n";
    const char *val = raw + 16; // "20\r\nHost: x\r\n"

    CHECK(n00b_parse_byte_count_span(val, 2) == 20);

    // Trailing non-digits inside the span stop the parse rather than failing.
    CHECK(n00b_parse_byte_count_span(val, 6) == 20);

    printf("  [PASS] span length is honored without a terminator\n");
}

static void
test_overflow_saturates_so_caps_still_reject(void)
{
    // Twenty-eight digits: past int64, and past what the old 24-byte scratch
    // buffer could hold. It must come back as UINT64_MAX, not 0 -- a 0 here
    // would silently admit the body that max_body_size exists to refuse.
    const char *absurd = "9999999999999999999999999999";

    CHECK(n00b_parse_byte_count_span(absurd, strlen(absurd)) == UINT64_MAX);

    // One past int64 max is still an overflow for an int64-based parser, and
    // must saturate the same way rather than wrapping to something small.
    check_count("9223372036854775808", UINT64_MAX, "int64 max + 1");

    printf("  [PASS] overflow saturates so size caps still reject\n");
}

static void
test_unusable_values_are_zero(void)
{
    // strtoull returned 0 for each of these, and the call sites are written
    // around that; keep it, so this change is a crash fix and not a change in
    // how a malformed header is framed.
    check_count("", 0, "empty value");
    check_count("abc", 0, "no digits");
    check_count("-5", 0, "negative is not a count");

    printf("  [PASS] unusable values read as zero\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_parse_num:\n");
    test_ordinary_lengths();
    test_span_is_honored_without_a_terminator();
    test_overflow_saturates_so_caps_still_reject();
    test_unusable_values_are_zero();

    printf("All parse_num tests passed.\n");
    n00b_shutdown();
    return 0;
}

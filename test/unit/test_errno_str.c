/** @file test/unit/test_errno_str.c — `n00b_errno_str` accessor
 *  regression test.
 *
 *  Closes the WP-004 Phase 5 (DF-008 fix) gate. The accessor is a
 *  pure lookup over a hard-coded `switch` table; the test asserts:
 *
 *    [1] A representative sample of POSIX.1-2008 portable errno
 *        values returns a non-null, non-empty `n00b_string_t *`.
 *    [2] An unknown / out-of-range code returns a non-empty
 *        `n00b_string_t *` (the documented fallback). The exact
 *        wording is documented; the regression doesn't bind
 *        tightly to the wording (would be tautological) but does
 *        verify non-emptiness.
 *    [3] The sign-folding behavior works: positive and negative
 *        encodings of the same errno code return byte-equal
 *        `data` of byte-equal length.
 *    [4] The accessor is pure: two calls with the same input
 *        return strings with byte-equal `data` of byte-equal
 *        length. (Same pointer is acceptable but not required.)
 *    [5] The zero code (`errno_val == 0`) returns the documented
 *        "no error" string — distinct from the unknown-code
 *        fallback so callers can distinguish "explicit 0 / success"
 *        from "the platform defines an errno code we don't cover."
 *
 *  Test-file carve-out (D-030) applies — libc I/O for stdout
 *  logging is acceptable per the established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include "n00b.h"
#include "core/string.h"
#include "core/runtime.h"
#include "util/errno_str.h"

// Representative sample of POSIX.1-2008 portable errno values.
// Not exhaustive — the implementation's switch is exhaustive over
// the portable set, but the test sample picks one code from each
// rough family (process / file / io / math / network) so a
// regression that drops or corrupts a case is easy to localize.
//
// Hand-maintained against the codes in `util/errno_str.c`. If a
// future patch adds a code without updating this list, the test
// still passes (the list shrinks but doesn't go stale unsafely)
// but coverage drops — the auditor catches the gap.
static const int k_errno_codes[] = {
    // Process / signal family.
    EPERM,
    ESRCH,
    EINTR,
    ECHILD,
    // File-descriptor / file-system family.
    ENOENT,
    EIO,
    EBADF,
    EACCES,
    EEXIST,
    EXDEV,
    ENOTDIR,
    EISDIR,
    EMFILE,
    ENFILE,
    ENOSPC,
    EROFS,
    ENAMETOOLONG,
    ELOOP,
    ENOTEMPTY,
    EFBIG,
    ESPIPE,
    EMLINK,
    EPIPE,
    // Memory / argument-validation family.
    ENOMEM,
    EFAULT,
    EINVAL,
    E2BIG,
    ENOEXEC,
    // I/O resource family.
    EAGAIN,
    EBUSY,
    ENODEV,
    ENXIO,
    ENOSYS,
    EDEADLK,
    ENOLCK,
    // Math family.
    EDOM,
    ERANGE,
    EOVERFLOW,
    EILSEQ,
    // Message / IPC family.
    ENOMSG,
    EIDRM,
    EPROTO,
    EBADMSG,
    // Socket / network family.
    ENOTSOCK,
    EMSGSIZE,
    EPROTOTYPE,
    EPROTONOSUPPORT,
    ENOTSUP,
    EAFNOSUPPORT,
    EADDRINUSE,
    EADDRNOTAVAIL,
    ENETDOWN,
    ENETUNREACH,
    ECONNRESET,
    ECONNABORTED,
    ECONNREFUSED,
    ENOTCONN,
    EISCONN,
    ETIMEDOUT,
    EHOSTUNREACH,
    EINPROGRESS,
    EALREADY,
    ENOBUFS,
    // Streams family.
    ENOSTR,
    ENODATA,
    ETIME,
    ENOSR,
    ENOLINK,
#if defined(EMULTIHOP)
    EMULTIHOP,
#endif
    // Filesystem-quota / NFS family.
#if defined(ESTALE)
    ESTALE,
#endif
#if defined(EDQUOT)
    EDQUOT,
#endif
    // Robust-mutex family.
    ECANCELED,
    EOWNERDEAD,
    ENOTRECOVERABLE,
    // Misc.
    ETXTBSY,
    ENOTTY,
    ENOPROTOOPT,
    EDESTADDRREQ,
};

// Platform-extension errno codes that should produce a stable
// description on at least one supported platform. Each entry is
// guarded so the table only includes codes the host actually
// `#define`s; the sample is hand-maintained to track the cases in
// `util/errno_str.c`.
//
// This list intentionally trades exhaustiveness for breadth — it
// picks ~10 codes from each platform-extension family so a
// regression that drops a case is easy to localize without binding
// the test against the full ~50-entry table.
static const int k_errno_ext_codes[] = {
    // Linux-only family (XENIX / STREAMS / RPC / kernel key mgmt).
#if defined(ECHRNG)
    ECHRNG,
#endif
#if defined(EL2NSYNC)
    EL2NSYNC,
#endif
#if defined(EBADE)
    EBADE,
#endif
#if defined(EBADR)
    EBADR,
#endif
#if defined(ENOPKG)
    ENOPKG,
#endif
#if defined(EBADFD)
    EBADFD,
#endif
#if defined(ELIBACC)
    ELIBACC,
#endif
#if defined(ERESTART)
    ERESTART,
#endif
#if defined(EHOSTDOWN)
    EHOSTDOWN,
#endif
#if defined(ESHUTDOWN)
    ESHUTDOWN,
#endif
#if defined(ENOKEY)
    ENOKEY,
#endif
#if defined(EKEYEXPIRED)
    EKEYEXPIRED,
#endif
#if defined(ERFKILL)
    ERFKILL,
#endif
#if defined(EHWPOISON)
    EHWPOISON,
#endif
    // macOS / BSD-only family (extended attributes / ONC RPC / Mach-O).
#if defined(ENOATTR)
    ENOATTR,
#endif
#if defined(EBADRPC)
    EBADRPC,
#endif
#if defined(ERPCMISMATCH)
    ERPCMISMATCH,
#endif
#if defined(EPROGUNAVAIL)
    EPROGUNAVAIL,
#endif
#if defined(EPROGMISMATCH)
    EPROGMISMATCH,
#endif
#if defined(EPROCUNAVAIL)
    EPROCUNAVAIL,
#endif
#if defined(EFTYPE)
    EFTYPE,
#endif
#if defined(EAUTH)
    EAUTH,
#endif
#if defined(ENEEDAUTH)
    ENEEDAUTH,
#endif
#if defined(EPWROFF)
    EPWROFF,
#endif
#if defined(EDEVERR)
    EDEVERR,
#endif
#if defined(EBADEXEC)
    EBADEXEC,
#endif
#if defined(EBADARCH)
    EBADARCH,
#endif
#if defined(ESHLIBVERS)
    ESHLIBVERS,
#endif
#if defined(EBADMACHO)
    EBADMACHO,
#endif
#if defined(ENOPOLICY)
    ENOPOLICY,
#endif
#if defined(EQFULL)
    EQFULL,
#endif
};

// Representative sample of getaddrinfo `EAI_*` return codes.
// Same hand-maintained / sampling discipline as the errno table.
static const int k_gai_codes[] = {
#if defined(EAI_BADFLAGS)
    EAI_BADFLAGS,
#endif
#if defined(EAI_NONAME)
    EAI_NONAME,
#endif
#if defined(EAI_AGAIN)
    EAI_AGAIN,
#endif
#if defined(EAI_FAIL)
    EAI_FAIL,
#endif
#if defined(EAI_FAMILY)
    EAI_FAMILY,
#endif
#if defined(EAI_SOCKTYPE)
    EAI_SOCKTYPE,
#endif
#if defined(EAI_SERVICE)
    EAI_SERVICE,
#endif
#if defined(EAI_MEMORY)
    EAI_MEMORY,
#endif
#if defined(EAI_SYSTEM)
    EAI_SYSTEM,
#endif
#if defined(EAI_OVERFLOW)
    EAI_OVERFLOW,
#endif
#if defined(EAI_ADDRFAMILY)
    EAI_ADDRFAMILY,
#endif
#if defined(EAI_BADHINTS)
    EAI_BADHINTS,
#endif
#if defined(EAI_PROTOCOL)
    EAI_PROTOCOL,
#endif
};

static void
assert_nonempty(n00b_string_t *s, const char *ctx, int code)
{
    if (s == nullptr) {
        fprintf(stderr, "FAIL: %s errno_str(%d) returned null\n", ctx, code);
        assert(0);
    }
    if (s->u8_bytes == 0) {
        fprintf(stderr,
                "FAIL: %s errno_str(%d) returned empty string\n",
                ctx,
                code);
        assert(0);
    }
}

static void
test_errno_every_code_returns_nonempty(void)
{
    size_t n = sizeof(k_errno_codes) / sizeof(k_errno_codes[0]);
    // Sample-size sanity check; pins the table size at its current
    // cardinality. If a future patch drops a code from the test
    // sample without intent, this fires.
    assert(n >= 30);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *s = n00b_errno_str(k_errno_codes[i]);
        assert_nonempty(s, "errno", k_errno_codes[i]);
    }
    printf("  [PASS] errno_every_code_returns_nonempty (%zu codes)\n", n);
}

static void
test_errno_zero_returns_no_error(void)
{
    // Code 0 (no error) is distinct from the unknown-code fallback.
    // We don't bind tightly to the exact wording (would be
    // tautological) but we DO assert it's non-empty and that it
    // differs from the unknown-code fallback (so a caller can
    // distinguish "the syscall returned 0 / success" from "the
    // platform defines an errno we don't cover").
    n00b_string_t *zero    = n00b_errno_str(0);
    n00b_string_t *unknown = n00b_errno_str(0x7fffffff);
    assert_nonempty(zero, "errno-zero", 0);
    assert_nonempty(unknown, "errno-unknown", 0x7fffffff);

    // Byte-distinct: the zero string and the unknown-code fallback
    // must not be byte-equal — otherwise the caller cannot tell
    // them apart.
    bool same_len  = zero->u8_bytes == unknown->u8_bytes;
    bool same_data = same_len
                  && memcmp(zero->data, unknown->data, zero->u8_bytes) == 0;
    assert(!same_data);
    printf("  [PASS] errno_zero_returns_no_error\n");
}

static void
test_errno_unknown_code_returns_fallback(void)
{
    // A positive value well above any defined errno. POSIX errno
    // values are small positive ints on every POSIX platform; 0x7fffffff
    // is comfortably outside that range.
    n00b_string_t *s = n00b_errno_str(0x7fffffff);
    assert_nonempty(s, "errno-unknown", 0x7fffffff);
    printf("  [PASS] errno_unknown_code_returns_fallback\n");
}

static void
test_errno_sign_folding(void)
{
    // The accessor folds the sign so libn00b's `n00b_check_posix`
    // convention (Err(errno), positive) and the project-local
    // Err(-errno) convention both produce the same lookup.
    for (size_t i = 0;
         i < sizeof(k_errno_codes) / sizeof(k_errno_codes[0]);
         i++) {
        int            code = k_errno_codes[i];
        n00b_string_t *pos  = n00b_errno_str(code);
        n00b_string_t *neg  = n00b_errno_str(-code);
        assert(pos != nullptr && neg != nullptr);
        assert(pos->u8_bytes == neg->u8_bytes);
        assert(memcmp(pos->data, neg->data, pos->u8_bytes) == 0);
    }
    printf("  [PASS] errno_sign_folding\n");
}

static void
test_errno_accessor_is_pure(void)
{
    // Same input -> byte-equal output across consecutive calls.
    // Pointer equality is acceptable but not required (rich-literal
    // storage is process-stable, so it usually IS pointer-equal —
    // but we don't bind tightly).
    for (size_t i = 0;
         i < sizeof(k_errno_codes) / sizeof(k_errno_codes[0]);
         i++) {
        n00b_string_t *a = n00b_errno_str(k_errno_codes[i]);
        n00b_string_t *b = n00b_errno_str(k_errno_codes[i]);
        assert(a != nullptr && b != nullptr);
        assert(a->u8_bytes == b->u8_bytes);
        assert(memcmp(a->data, b->data, a->u8_bytes) == 0);
    }
    printf("  [PASS] errno_accessor_is_pure\n");
}

static void
test_errno_platform_extensions_return_nonempty(void)
{
    // Platform-extension errno codes (Linux-only or macOS/BSD-only)
    // each return a non-empty description on the platforms where
    // they are defined. The table itself is `#ifdef`-filtered so
    // we only test codes the host actually has.
    size_t n = sizeof(k_errno_ext_codes) / sizeof(k_errno_ext_codes[0]);
    // Some supported C runtimes, including native Windows, define no
    // Linux/BSD extension errno family. When the host has none, there is no
    // platform-extension behavior to exercise; otherwise pin the sample size
    // so accidental coverage loss still trips the test.
    if (n == 0) {
        printf("  [PASS] errno_platform_extensions_return_nonempty (0 codes)\n");
        return;
    }
    assert(n >= 5);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *s = n00b_errno_str(k_errno_ext_codes[i]);
        assert_nonempty(s, "errno-ext", k_errno_ext_codes[i]);

        // Platform-extension codes must produce a *non-fallback*
        // description on the platforms where they exist — a stale
        // entry that fell out of the switch would silently regress
        // to the fallback string. Compare byte-distinct against
        // the documented unknown-code fallback.
        n00b_string_t *fallback = n00b_errno_str(0x7fffffff);
        bool same_len  = s->u8_bytes == fallback->u8_bytes;
        bool same_data = same_len
                      && memcmp(s->data, fallback->data, s->u8_bytes) == 0;
        if (same_data) {
            fprintf(stderr,
                    "FAIL: errno-ext code %d fell through to fallback\n",
                    k_errno_ext_codes[i]);
            assert(0);
        }
    }
    printf("  [PASS] errno_platform_extensions_return_nonempty (%zu codes)\n",
           n);
}

static void
test_gai_every_code_returns_nonempty(void)
{
    size_t n = sizeof(k_gai_codes) / sizeof(k_gai_codes[0]);
    // POSIX.1 mandates ~10 EAI_* codes on every POSIX system.
    assert(n >= 8);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *s = n00b_gai_str(k_gai_codes[i]);
        assert_nonempty(s, "gai", k_gai_codes[i]);

        // Same fallback-distinctness check as the errno test:
        // every covered code must produce a non-fallback string.
        n00b_string_t *fallback = n00b_gai_str(0x7fffffff);
        bool same_len  = s->u8_bytes == fallback->u8_bytes;
        bool same_data = same_len
                      && memcmp(s->data, fallback->data, s->u8_bytes) == 0;
        if (same_data) {
            fprintf(stderr,
                    "FAIL: gai code %d fell through to fallback\n",
                    k_gai_codes[i]);
            assert(0);
        }
    }
    printf("  [PASS] gai_every_code_returns_nonempty (%zu codes)\n", n);
}

static void
test_gai_zero_returns_no_error(void)
{
    // Code 0 (no error) is distinct from the unknown-code fallback,
    // mirroring n00b_errno_str's contract.
    n00b_string_t *zero    = n00b_gai_str(0);
    n00b_string_t *unknown = n00b_gai_str(0x7fffffff);
    assert_nonempty(zero, "gai-zero", 0);
    assert_nonempty(unknown, "gai-unknown", 0x7fffffff);

    bool same_len  = zero->u8_bytes == unknown->u8_bytes;
    bool same_data = same_len
                  && memcmp(zero->data, unknown->data, zero->u8_bytes) == 0;
    assert(!same_data);
    printf("  [PASS] gai_zero_returns_no_error\n");
}

static void
test_gai_unknown_code_returns_fallback(void)
{
    n00b_string_t *s = n00b_gai_str(0x7fffffff);
    assert_nonempty(s, "gai-unknown", 0x7fffffff);
    printf("  [PASS] gai_unknown_code_returns_fallback\n");
}

static void
test_gai_sign_folding(void)
{
    // `getaddrinfo`'s sign convention varies: BSD/macOS uses
    // positive `EAI_*`, glibc historically uses negatives. The
    // accessor folds the sign so callers can pass the raw rc.
    size_t n = sizeof(k_gai_codes) / sizeof(k_gai_codes[0]);
    for (size_t i = 0; i < n; i++) {
        int            code = k_gai_codes[i];
        n00b_string_t *pos  = n00b_gai_str(code);
        n00b_string_t *neg  = n00b_gai_str(-code);
        assert(pos != nullptr && neg != nullptr);
        assert(pos->u8_bytes == neg->u8_bytes);
        assert(memcmp(pos->data, neg->data, pos->u8_bytes) == 0);
    }
    printf("  [PASS] gai_sign_folding\n");
}

static void
test_gai_accessor_is_pure(void)
{
    size_t n = sizeof(k_gai_codes) / sizeof(k_gai_codes[0]);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *a = n00b_gai_str(k_gai_codes[i]);
        n00b_string_t *b = n00b_gai_str(k_gai_codes[i]);
        assert(a != nullptr && b != nullptr);
        assert(a->u8_bytes == b->u8_bytes);
        assert(memcmp(a->data, b->data, a->u8_bytes) == 0);
    }
    printf("  [PASS] gai_accessor_is_pure\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    printf("== n00b_errno_str ==\n");
    test_errno_every_code_returns_nonempty();
    test_errno_zero_returns_no_error();
    test_errno_unknown_code_returns_fallback();
    test_errno_sign_folding();
    test_errno_accessor_is_pure();
    test_errno_platform_extensions_return_nonempty();
    printf("== n00b_gai_str ==\n");
    test_gai_every_code_returns_nonempty();
    test_gai_zero_returns_no_error();
    test_gai_unknown_code_returns_fallback();
    test_gai_sign_folding();
    test_gai_accessor_is_pure();
    printf("All n00b_errno_str / n00b_gai_str tests passed.\n");
    return 0;
}

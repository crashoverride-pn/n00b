/** @file test/unit/test_attest_err_str.c — `*_err_str` accessor
 *  regression test (WP-002 Phase 3).
 *
 *  Closes A-1 (D-031 carry-forward from WP-001) for the
 *  `n00b_attest_err_str` half + WA-1 (D-038 part 2) for the
 *  `n00b_base64_err_str` half. Both accessors are pure lookups
 *  over a hard-coded table; the test asserts:
 *
 *    [1] Every defined `N00B_ATTEST_ERR_*` code returns a non-null,
 *        non-empty `n00b_string_t *`.
 *    [2] Every defined `N00B_BASE64_ERR_*` code returns a non-null,
 *        non-empty `n00b_string_t *`.
 *    [3] An unknown code in each domain returns a non-empty
 *        `n00b_string_t *` (the documented fallback). The exact
 *        wording is documented; the regression doesn't bind tightly
 *        to the wording (would be tautological) but does verify
 *        non-emptiness.
 *    [4] The accessors are pure: two calls with the same input
 *        return strings with byte-equal `data` of byte-equal
 *        length. (Same pointer is acceptable but not required.)
 *
 *  Test-file carve-out (D-030) applies — libc I/O for stdout
 *  logging is acceptable per the established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/string.h"
#include "core/runtime.h"
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

// Every n00b_attest module-domain error code defined in the
// project. Maintained by hand against the codes declared in
// `n00b_attest_error.h` + `n00b_attest_signer.h`. If a future WP
// adds a code without updating this list, the test still passes
// (the list shrinks but doesn't go stale unsafely) but coverage
// drops — the auditor catches the gap.
static const n00b_err_t k_attest_codes[] = {
    // Statement domain.
    N00B_ATTEST_ERR_STMT_BAD_INPUT,
    N00B_ATTEST_ERR_STMT_MISSING_FIELD,
    N00B_ATTEST_ERR_STMT_BAD_JSON,
    N00B_ATTEST_ERR_STMT_WRONG_TYPE,
    // DSSE-envelope domain.
    N00B_ATTEST_ERR_DSSE_BAD_INPUT,
    N00B_ATTEST_ERR_DSSE_NO_PAYLOAD,
    N00B_ATTEST_ERR_DSSE_BAD_JSON,
    N00B_ATTEST_ERR_DSSE_WRONG_TYPE,
    N00B_ATTEST_ERR_DSSE_BAD_BASE64,
    // Signer domain.
    N00B_ATTEST_ERR_UNSUPPORTED_SCHEME,
    N00B_ATTEST_ERR_KEY_NOT_FOUND,
    N00B_ATTEST_ERR_PEM_PARSE_FAILED,
    N00B_ATTEST_ERR_DER_PARSE_FAILED,
    N00B_ATTEST_ERR_UNSUPPORTED_ALGORITHM,
    N00B_ATTEST_ERR_SIGN_FAILED,
    N00B_ATTEST_ERR_NOT_IMPLEMENTED,
    // Verifier domain (WP-003 Phase 2 per D-046).
    N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_SCHEME,
    N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND,
    N00B_ATTEST_ERR_VERIFIER_PEM_PARSE_FAILED,
    N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED,
    N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_ALGORITHM,
    // Verify check-path domain (WP-003 Phase 3 per D-047 W-1).
    N00B_ATTEST_ERR_VERIFY_BAD_SIG_LENGTH,
    N00B_ATTEST_ERR_VERIFY_BAD_INPUT,
    // OCI integration domain (WP-004 Phase 1 per D-051 OQ-6). Phase 1
    // declares four codes; Phase 2 adds `_OCI_MANIFEST_DIGEST_MISMATCH`
    // (-6002) for the manifest-upload cross-check between the
    // registry-reported `Docker-Content-Digest` and the locally-
    // computed digest. Slot -6002 was vacated by D-053 W-2's
    // retirement of unused Phase-1 codes. The remaining open slot
    // (-6006) and the -6007+ range are reserved for Phase 3/4 if
    // additional distinctions are needed.
    N00B_ATTEST_ERR_OCI_BAD_URL,
    N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH,
    N00B_ATTEST_ERR_OCI_HTTP_ERROR,
    N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED,
    N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND,
    // WP-004 Phase 3 (D-046 — phase introduces codes when it uses them).
    N00B_ATTEST_ERR_OCI_NO_MATCHING_REFERRER,
    N00B_ATTEST_ERR_OCI_BLOB_TOO_LARGE,
    N00B_ATTEST_ERR_OCI_BLOB_DIGEST_MISMATCH,
    N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX,
    // WP-004 Phase 4 (D-046 — phase introduces codes when it uses
    // them). Per-call size cap on `_list_referrers` pagination per
    // NFR-5.
    N00B_ATTEST_ERR_OCI_RESPONSE_TOO_LARGE,
    // Chalk integration domain (WP-005 Phase 1 per D-046 — phase
    // introduces codes when it uses them). One `_BAD_REGISTRY_HINT`
    // validation code, four IC-5 sentinels (`_NO_MARK`, `_NO_
    // ATTESTATION`, `_MALFORMED_ATTESTATION`, `_CODEC_LOOKUP_FAILED`),
    // three libchalk-dispatch passthroughs (`_INSERT_FAILED`,
    // `_EXTRACT_FAILED`, `_DELETE_FAILED`), and `_BAD_ENVELOPE` for
    // structurally malformed input envelopes.
    N00B_ATTEST_ERR_CHALK_BAD_REGISTRY_HINT,
    N00B_ATTEST_ERR_CHALK_NO_MARK,
    N00B_ATTEST_ERR_CHALK_NO_ATTESTATION,
    N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION,
    N00B_ATTEST_ERR_CHALK_CODEC_LOOKUP_FAILED,
    N00B_ATTEST_ERR_CHALK_INSERT_FAILED,
    N00B_ATTEST_ERR_CHALK_EXTRACT_FAILED,
    N00B_ATTEST_ERR_CHALK_DELETE_FAILED,
    N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE,
};

// Every base64-util code defined in the project.
static const n00b_err_t k_base64_codes[] = {
    N00B_BASE64_ERR_DECODE_FAILED,
    N00B_BASE64_ERR_NULL_INPUT,
};

static void
assert_nonempty(n00b_string_t *s, const char *ctx, n00b_err_t code)
{
    if (s == nullptr) {
        fprintf(stderr, "FAIL: %s err_str(%d) returned null\n", ctx, code);
        assert(0);
    }
    if (s->u8_bytes == 0) {
        fprintf(stderr,
                "FAIL: %s err_str(%d) returned empty string\n",
                ctx,
                code);
        assert(0);
    }
}

static void
test_attest_every_code_returns_nonempty(void)
{
    size_t n = sizeof(k_attest_codes) / sizeof(k_attest_codes[0]);
    // Expected post-WP-004-Phase-4 count: 33. Bumped from 16 by
    // D-046 (which authorized Phase 2 to introduce the first five
    // verifier-domain codes -5001..-5005, taking the count to 21);
    // bumped from 21 by D-047 W-1 (which authorized Phase 3 to
    // introduce the two runtime-check-path codes -5006/-5007
    // under the `_VERIFY_*` prefix, taking the count to 23);
    // bumped from 23 by D-051 OQ-6 to 27 (which authorized WP-004
    // Phase 1 to introduce four OCI-domain codes: -6001, -6003,
    // -6004, -6005); bumped from 27 by D-046 (phase introduces
    // codes when it uses them) for WP-004 Phase 2 to introduce
    // `_OCI_MANIFEST_DIGEST_MISMATCH` (-6002), taking the count
    // to 28; bumped from 28 by D-046 for WP-004 Phase 3 to introduce
    // `_OCI_NO_MATCHING_REFERRER` (-6006), `_OCI_BLOB_TOO_LARGE`
    // (-6007), `_OCI_BLOB_DIGEST_MISMATCH` (-6008), and
    // `_OCI_BAD_REFERRER_INDEX` (-6009), taking the count to 32;
    // bumped from 32 by D-046 for WP-004 Phase 4 to introduce
    // `_OCI_RESPONSE_TOO_LARGE` (-6010) for the per-call size cap
    // on `_list_referrers` pagination per NFR-5, taking the count
    // to 33; bumped from 33 by D-046 for WP-005 Phase 1 to introduce
    // nine chalk-integration codes (`_CHALK_BAD_REGISTRY_HINT`,
    // four IC-5 sentinels, three libchalk-dispatch passthroughs,
    // and `_CHALK_BAD_ENVELOPE`), taking the count to 42. If a
    // future WP adds a code without updating this list, the value
    // here drifts — a starting-point sanity check that pins the
    // table size at its current cardinality.
    assert(n == 42);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *s = n00b_attest_err_str(k_attest_codes[i]);
        assert_nonempty(s, "attest", k_attest_codes[i]);
    }
    printf("  [PASS] attest_every_code_returns_nonempty\n");
}

static void
test_attest_unknown_code_returns_fallback(void)
{
    // A code in the negative space not assigned to any domain.
    // `-9999` is outside the -1xxx / -2xxx / -4xxx ranges used so
    // far and is a stable "not in the table" value.
    n00b_string_t *s = n00b_attest_err_str(-9999);
    assert_nonempty(s, "attest-unknown", -9999);
    printf("  [PASS] attest_unknown_code_returns_fallback\n");
}

static void
test_attest_accessor_is_pure(void)
{
    // The accessor must be pure: same input → byte-equal output
    // across consecutive calls. Pointer equality is acceptable but
    // not required (the rich-literal storage is process-stable, so
    // it usually IS pointer-equal — but we don't bind tightly).
    for (size_t i = 0;
         i < sizeof(k_attest_codes) / sizeof(k_attest_codes[0]);
         i++) {
        n00b_string_t *a = n00b_attest_err_str(k_attest_codes[i]);
        n00b_string_t *b = n00b_attest_err_str(k_attest_codes[i]);
        assert(a != nullptr && b != nullptr);
        assert(a->u8_bytes == b->u8_bytes);
        assert(memcmp(a->data, b->data, a->u8_bytes) == 0);
    }
    printf("  [PASS] attest_accessor_is_pure\n");
}

static void
test_base64_every_code_returns_nonempty(void)
{
    size_t n = sizeof(k_base64_codes) / sizeof(k_base64_codes[0]);
    assert(n == 2);
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *s = n00b_base64_err_str(k_base64_codes[i]);
        assert_nonempty(s, "base64", k_base64_codes[i]);
    }
    printf("  [PASS] base64_every_code_returns_nonempty\n");
}

static void
test_base64_unknown_code_returns_fallback(void)
{
    n00b_string_t *s = n00b_base64_err_str(-9999);
    assert_nonempty(s, "base64-unknown", -9999);
    printf("  [PASS] base64_unknown_code_returns_fallback\n");
}

static void
test_base64_accessor_is_pure(void)
{
    for (size_t i = 0;
         i < sizeof(k_base64_codes) / sizeof(k_base64_codes[0]);
         i++) {
        n00b_string_t *a = n00b_base64_err_str(k_base64_codes[i]);
        n00b_string_t *b = n00b_base64_err_str(k_base64_codes[i]);
        assert(a != nullptr && b != nullptr);
        assert(a->u8_bytes == b->u8_bytes);
        assert(memcmp(a->data, b->data, a->u8_bytes) == 0);
    }
    printf("  [PASS] base64_accessor_is_pure\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest + n00b_base64 err_str ==\n");
    test_attest_every_code_returns_nonempty();
    test_attest_unknown_code_returns_fallback();
    test_attest_accessor_is_pure();
    test_base64_every_code_returns_nonempty();
    test_base64_unknown_code_returns_fallback();
    test_base64_accessor_is_pure();
    printf("All n00b_attest + n00b_base64 err_str tests passed.\n");
    return 0;
}

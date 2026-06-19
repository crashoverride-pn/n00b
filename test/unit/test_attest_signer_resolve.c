/** @file test/unit/test_attest_signer_resolve.c — signer resolver
 *  regression test (WP-002 Phase 2 cleanup pass).
 *
 *  Exercises `n00b_attest_signer_resolve` against a tempfile-
 *  fixture PKCS#8 PEM Ed25519 key and against the canonical error
 *  paths. The fixture is built from RFC 8032 §7.1 test vector #1
 *  (same seed `test_attest_monocypher_smoke` uses), so the
 *  expected pubkey + SPKI DER are well-known across the codebase.
 *
 *  Coverage table:
 *    [1] resolve(`file:///<tempfile>`) succeeds
 *    [2] returned pubkey-SPKI-DER matches expected 44-byte form
 *    [3] returned keyid = SHA-256(SPKI DER), full 32-byte hash
 *        hex-encoded (64 chars), per D-039 (resolves DF-003)
 *        — pre-computed expected hex baked in as a static fixture
 *        so the test is not a tautology against the implementation
 *        (D-039 is not yet logged; the orchestrator will log it
 *        after this dispatch returns clean — pre-stage the
 *        reference in source comments and the spec text)
 *    [4] resolve(`file:<tempfile>`) (FR-SM-1 strict form) succeeds
 *    [5] missing-file URI -> N00B_ATTEST_ERR_KEY_NOT_FOUND
 *    [6] malformed-PEM tempfile -> N00B_ATTEST_ERR_PEM_PARSE_FAILED
 *    [7] wrong-algorithm OID -> N00B_ATTEST_ERR_UNSUPPORTED_ALGORITHM
 *    [8] unsupported scheme `keychain://...` -> _ERR_UNSUPPORTED_SCHEME
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the
 *  tempfile setup and stdout logging is acceptable per the
 *  established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

#include "internal/attest/backends/file.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

// RFC 8032 §7.1 test vector #1 seed (32 bytes).
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// Expected Ed25519 public key for the seed (RFC 8032 §7.1).
static const uint8_t k_expected_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

// Expected SPKI DER (12-byte fixed Ed25519 prefix + 32-byte pubkey =
// 44 bytes total).
static const uint8_t k_expected_spki_prefix[12] = {
    0x30, 0x2A,
    0x30, 0x05,
    0x06, 0x03, 0x2B, 0x65, 0x70,
    0x03, 0x21,
    0x00,
};

// Pre-computed expected keyid for the RFC 8032 §7.1 vector #1 pubkey,
// per the D-039 (resolves DF-003) form (D-039 is not yet logged; the
// orchestrator will log it after this dispatch returns clean — pre-
// stage the reference in source comments and the spec text):
//   keyid = lowercase-hex(SHA-256(SPKI DER))
// where SPKI DER is the 12-byte k_expected_spki_prefix above
// concatenated with the 32-byte k_expected_pubkey (= 44 bytes total).
// Computed once at test-authoring time so this fixture is not a
// tautology against the implementation under test (a tautology would
// be "test recomputes the same SHA-256 the implementation computes,
// from the same input"). Baking the hex string here means a divergent
// implementation must explain the mismatch against a third-party-
// verifiable expected value.
//
// Reproducible via, e.g.:
//   python3 -c "import hashlib;\
//     prefix=bytes.fromhex('302a300506032b657003210' '0');\
//     pubkey=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a'\
//                          '0ee172f3daa62325af021a68f707511a');\
//     print(hashlib.sha256(prefix+pubkey).hexdigest())"
static const char k_expected_keyid_hex[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

// ---------------------------------------------------------------------------
// Tempfile + PEM build helpers (test-file carve-out).
// ---------------------------------------------------------------------------

// Build the 48-byte PrivateKeyInfo DER for a 32-byte Ed25519 seed:
//   30 2E 02 01 00 30 05 06 03 2B 65 70 04 22 04 20 <seed>
static void
build_ed25519_pkcs8_der(const uint8_t seed[32], uint8_t out[48])
{
    static const uint8_t k_prefix[16] = {
        0x30, 0x2E,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22,
        0x04, 0x20,
    };
    memcpy(out, k_prefix, 16);
    memcpy(out + 16, seed, 32);
}

// Write a PEM-armored DER blob into a freshly-created tempfile.
// Returns the heap-allocated path string (caller `free`s) on success;
// aborts on I/O failure.
static char *
write_pem_tempfile(const uint8_t *der, size_t der_len, const char *label)
{
    char  path_template[]    = "/tmp/n00b_attest_resolve_XXXXXX";
    char *path               = strdup(path_template);
    int   fd                 = mkstemp(path);
    assert(fd >= 0);

    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    // Encode DER bytes via n00b_base64_encode so the test exercises
    // the same code path the file-backend's PEM decoder will reverse.
    n00b_buffer_t *der_buf = n00b_buffer_from_bytes((char *)der,
                                                    (int64_t)der_len);
    auto enc_r = n00b_base64_encode(der_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *b64 = n00b_result_get(enc_r);

    fprintf(f, "-----BEGIN %s-----\n", label);
    // PEM wraps base64 at 64 chars per line (RFC 7468).
    size_t off = 0;
    while (off < b64->u8_bytes) {
        size_t take = b64->u8_bytes - off;
        if (take > 64) take = 64;
        fwrite(b64->data + off, 1, take, f);
        fputc('\n', f);
        off += take;
    }
    fprintf(f, "-----END %s-----\n", label);

    fclose(f);
    return path;
}

// ---------------------------------------------------------------------------
// Test cases.
// ---------------------------------------------------------------------------

static void
test_resolve_ok_file_triple_slash(void)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path = write_pem_tempfile(der, 48, "PRIVATE KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_signer_t *signer = n00b_result_get(r);
    assert(signer != nullptr);

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] resolve_ok_file_triple_slash\n");
}

static void
test_resolve_ok_file_strict(void)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path = write_pem_tempfile(der, 48, "PRIVATE KEY");

    // FR-SM-1 strict form: `file:<path>` (no double slash).
    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file:%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_signer_t *signer = n00b_result_get(r);
    assert(signer != nullptr);

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] resolve_ok_file_strict\n");
}

static void
test_resolve_pubkey_spki_der_matches(void)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path = write_pem_tempfile(der, 48, "PRIVATE KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_signer_t *signer = n00b_result_get(r);

    // Per architecture §6.1 the SPKI getter returns a raw
    // `n00b_buffer_t *` (no _kargs, no result wrapper) — the bytes
    // are pre-built at load time and stored on the signer state.
    n00b_buffer_t *spki = n00b_attest_signer_pubkey_spki_der(signer);
    assert(spki != nullptr);
    assert(spki->byte_len == 44);
    assert(memcmp(spki->data, k_expected_spki_prefix, 12) == 0);
    assert(memcmp(spki->data + 12, k_expected_pubkey, 32) == 0);

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] resolve_pubkey_spki_der_matches\n");
}

static void
test_resolve_keyid_matches_expected_spki_hash(void)
{
    // Coverage-table item [3]: assert the resolved signer's keyid
    // matches the pre-computed SHA-256(SPKI DER) hex string. The
    // expected value is k_expected_keyid_hex (baked in at test-
    // authoring time per D-039 (resolves DF-003); D-039 is not yet
    // logged — the orchestrator will log it after this dispatch
    // returns clean).
    //
    // The cast through the package-private file-backend state
    // struct mirrors the pattern in `test_attest_signer_release.c`
    // (the public surface does not expose a keyid getter at the
    // signer-handle level; the keyid is consumed only through the
    // envelope's `signatures[].keyid` field once Phase 3 wires
    // signing). The cast is safe because the file-backend struct's
    // first field is the `n00b_attest_signer` base per the
    // backends.h convention.
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path = write_pem_tempfile(der, 48, "PRIVATE KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_signer_t      *signer  = n00b_result_get(r);
    n00b_attest_signer_file_t *file_sg = (n00b_attest_signer_file_t *)signer;

    assert(file_sg->keyid != nullptr);
    assert(file_sg->keyid->u8_bytes == 64);
    // strlen of the expected fixture excludes the terminating NUL.
    assert(sizeof(k_expected_keyid_hex) - 1 == 64);
    if (memcmp(file_sg->keyid->data, k_expected_keyid_hex, 64) != 0) {
        // Verbose mismatch diagnostic — easier to triage than a
        // bare assertion failure when the form changes.
        fprintf(stderr,
                "FAIL: keyid mismatch\n"
                "  expected: %.64s\n"
                "  actual:   %.64s\n",
                k_expected_keyid_hex, file_sg->keyid->data);
        assert(0);
    }

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] resolve_keyid_matches_expected_spki_hash\n");
}

static void
test_resolve_unsupported_scheme(void)
{
    n00b_string_t *uri = n00b_string_from_cstr("keychain://foo");
    auto r = n00b_attest_signer_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_UNSUPPORTED_SCHEME);
    printf("  [PASS] resolve_unsupported_scheme\n");
}

static void
test_resolve_missing_file(void)
{
    n00b_string_t *uri = n00b_string_from_cstr(
        "file:///tmp/n00b_attest_does_not_exist_xyz_123");
    auto r = n00b_attest_signer_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_KEY_NOT_FOUND);
    printf("  [PASS] resolve_missing_file\n");
}

static void
test_resolve_malformed_pem(void)
{
    // Write a "PRIVATE KEY"-labeled PEM whose body isn't valid base64
    // (the picotls decoder will reject it).
    char  path_template[] = "/tmp/n00b_attest_malformed_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);
    fputs("-----BEGIN PRIVATE KEY-----\n", f);
    fputs("not-actually-base64-!!!\n", f);
    fputs("-----END PRIVATE KEY-----\n", f);
    fclose(f);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_PEM_PARSE_FAILED);

    unlink(path);
    free(path);
    printf("  [PASS] resolve_malformed_pem\n");
}

static void
test_resolve_wrong_algorithm(void)
{
    // Hand-craft a PKCS#8 DER carrying a NON-Ed25519 OID.
    // 1.3.101.113 (id-Ed448) is the closest sibling in the same
    // SubjectPublicKeyInfo family; we use it here purely as a
    // mismatch trigger — the file backend rejects every non-Ed25519
    // OID with N00B_ATTEST_ERR_UNSUPPORTED_ALGORITHM. The DER is
    // syntactically valid (the walk reaches the OID check), so
    // failure is the OID-mismatch path, not the DER-parse path.
    uint8_t der[48];
    static const uint8_t k_ed448_prefix[16] = {
        0x30, 0x2E,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2B, 0x65, 0x71,  // <- last byte changed: id-Ed448
        0x04, 0x22,
        0x04, 0x20,
    };
    memcpy(der, k_ed448_prefix, 16);
    memcpy(der + 16, k_seed, 32);

    char *path = write_pem_tempfile(der, 48, "PRIVATE KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_UNSUPPORTED_ALGORITHM);

    unlink(path);
    free(path);
    printf("  [PASS] resolve_wrong_algorithm\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    // Wire up the file backend's vtable + registration so the
    // resolver can find it. Per architecture §6.1 the in-tree
    // backends are registered during module-init; the host
    // (test binary) owns the call.
    n00b_attest_module_init();

    printf("== n00b_attest signer resolve ==\n");
    test_resolve_ok_file_triple_slash();
    test_resolve_ok_file_strict();
    test_resolve_pubkey_spki_der_matches();
    test_resolve_keyid_matches_expected_spki_hash();
    test_resolve_unsupported_scheme();
    test_resolve_missing_file();
    test_resolve_malformed_pem();
    test_resolve_wrong_algorithm();

    printf("All n00b_attest signer resolve tests passed.\n");
    return 0;
}

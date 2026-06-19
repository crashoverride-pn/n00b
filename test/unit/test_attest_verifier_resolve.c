/** @file test/unit/test_attest_verifier_resolve.c — verifier
 *  resolver regression test (WP-003 Phase 2).
 *
 *  Exercises `n00b_attest_verifier_resolve` against a tempfile-
 *  fixture SPKI PEM Ed25519 public key and against the canonical
 *  error paths. Mirrors the WP-002 Phase 2 `test_attest_signer_
 *  resolve.c` 7-test structure on the verifier side.
 *
 *  The fixture pubkey is the RFC 8032 §7.1 test vector #1 public
 *  key — derivable from the same seed the signer-side regression
 *  uses, so the keyid + SPKI DER are well-known across the
 *  codebase. The matching cross-WP keyid byte-equality invariant
 *  is gated separately in `test_attest_verifier_keyid.c`.
 *
 *  Coverage table:
 *    [1] resolve(`file:///<tempfile>`) succeeds; returned
 *        pubkey-SPKI-DER matches the 44-byte expected form;
 *        returned keyid matches the canonical D-039 hex.
 *    [2] resolve(`file:<tempfile>`) (FR-SM-1 strict form) succeeds
 *        with byte-identical results.
 *    [3] unsupported scheme `keychain://...` ->
 *        N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_SCHEME.
 *    [4] missing-file URI ->
 *        N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND.
 *    [5] malformed-PEM tempfile ->
 *        N00B_ATTEST_ERR_VERIFIER_PEM_PARSE_FAILED.
 *    [6] wrong-algorithm OID (id-Ed448 SPKI) ->
 *        N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_ALGORITHM.
 *    [7] release a verifier (no-op smoke — release-then-use is
 *        UB per the signer-side convention).
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

#include "internal/attest/verifier_backends/file.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

// Expected Ed25519 public key for the RFC 8032 §7.1 vector #1 seed
// — same fixture the signer-side resolve test uses.
static const uint8_t k_expected_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

// 12-byte fixed Ed25519 SPKI prefix — same constant the file
// backends bake in. Identical to the signer-side fixture so the
// keyid byte-equality invariant follows from "same SPKI DER bytes".
static const uint8_t k_expected_spki_prefix[12] = {
    0x30, 0x2A,
    0x30, 0x05,
    0x06, 0x03, 0x2B, 0x65, 0x70,
    0x03, 0x21,
    0x00,
};

// Canonical keyid hex per D-039 for the RFC 8032 §7.1 vector #1
// pubkey:
//   keyid = lowercase-hex(SHA-256(SPKI DER))
// SPKI DER = 12-byte prefix + 32-byte pubkey above.
// Reproducible via:
//   python3 -c "import hashlib;\
//     prefix=bytes.fromhex('302a300506032b657003210' '0');\
//     pubkey=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a'\
//                          '0ee172f3daa62325af021a68f707511a');\
//     print(hashlib.sha256(prefix+pubkey).hexdigest())"
// Baked in at test-authoring time — not a tautology against the
// implementation (a divergent verifier would have to explain the
// mismatch against this third-party-verifiable value).
static const char k_expected_keyid_hex[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

// ---------------------------------------------------------------------------
// Tempfile + PEM build helpers (test-file carve-out).
// ---------------------------------------------------------------------------

// Build the 44-byte SubjectPublicKeyInfo DER for the fixture
// pubkey (12-byte prefix + 32-byte raw pubkey).
static void
build_ed25519_spki_der(uint8_t out[44])
{
    memcpy(out, k_expected_spki_prefix, 12);
    memcpy(out + 12, k_expected_pubkey, 32);
}

// Write a PEM-armored DER blob into a freshly-created tempfile.
// Returns the heap-allocated path string (caller `free`s) on
// success; aborts on I/O failure. Mirrors the signer-side helper.
static char *
write_pem_tempfile(const uint8_t *der, size_t der_len, const char *label)
{
    char  path_template[]    = "/tmp/n00b_attest_vresolve_XXXXXX";
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
    uint8_t der[44];
    build_ed25519_spki_der(der);
    char *path = write_pem_tempfile(der, 44, "PUBLIC KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_verifier_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_verifier_t *verifier = n00b_result_get(r);
    assert(verifier != nullptr);

    // Per architecture §6.1 the SPKI getter returns a raw
    // `n00b_buffer_t *` (no _kargs, no result wrapper) — the bytes
    // are pre-built at load time and stored on the verifier state.
    n00b_buffer_t *spki = n00b_attest_verifier_pubkey_spki_der(verifier);
    assert(spki != nullptr);
    assert(spki->byte_len == 44);
    assert(memcmp(spki->data, k_expected_spki_prefix, 12) == 0);
    assert(memcmp(spki->data + 12, k_expected_pubkey, 32) == 0);

    n00b_string_t *kid = n00b_attest_verifier_keyid(verifier);
    assert(kid != nullptr);
    assert(kid->u8_bytes == 64);
    assert(sizeof(k_expected_keyid_hex) - 1 == 64);
    if (memcmp(kid->data, k_expected_keyid_hex, 64) != 0) {
        fprintf(stderr,
                "FAIL: verifier keyid mismatch (triple-slash form)\n"
                "  expected: %.64s\n"
                "  actual:   %.64s\n",
                k_expected_keyid_hex, kid->data);
        assert(0);
    }

    n00b_attest_verifier_release(verifier);
    unlink(path);
    free(path);
    printf("  [PASS] resolve_ok_file_triple_slash\n");
}

static void
test_resolve_ok_file_strict(void)
{
    uint8_t der[44];
    build_ed25519_spki_der(der);
    char *path = write_pem_tempfile(der, 44, "PUBLIC KEY");

    // FR-SM-1 strict form (mirrored on the verifier side):
    // `file:<path>` (no double slash).
    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file:%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_verifier_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_verifier_t *verifier = n00b_result_get(r);
    assert(verifier != nullptr);

    // Byte-identical results between the two URI forms.
    n00b_buffer_t *spki = n00b_attest_verifier_pubkey_spki_der(verifier);
    assert(spki != nullptr);
    assert(spki->byte_len == 44);
    assert(memcmp(spki->data, k_expected_spki_prefix, 12) == 0);
    assert(memcmp(spki->data + 12, k_expected_pubkey, 32) == 0);

    n00b_string_t *kid = n00b_attest_verifier_keyid(verifier);
    assert(kid != nullptr);
    assert(kid->u8_bytes == 64);
    assert(memcmp(kid->data, k_expected_keyid_hex, 64) == 0);

    n00b_attest_verifier_release(verifier);
    unlink(path);
    free(path);
    printf("  [PASS] resolve_ok_file_strict\n");
}

static void
test_resolve_unsupported_scheme(void)
{
    n00b_string_t *uri = n00b_string_from_cstr("keychain://foo");
    auto r = n00b_attest_verifier_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r)
           == N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_SCHEME);
    printf("  [PASS] resolve_unsupported_scheme\n");
}

static void
test_resolve_missing_file(void)
{
    n00b_string_t *uri = n00b_string_from_cstr(
        "file:///tmp/n00b_attest_verifier_does_not_exist_xyz_123");
    auto r = n00b_attest_verifier_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r)
           == N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND);
    printf("  [PASS] resolve_missing_file\n");
}

static void
test_resolve_malformed_pem(void)
{
    // Write a "PUBLIC KEY"-labeled PEM whose body isn't valid base64
    // (picotls's decoder will reject it).
    char  path_template[] = "/tmp/n00b_attest_vmalformed_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);
    fputs("-----BEGIN PUBLIC KEY-----\n", f);
    fputs("not-actually-base64-!!!\n", f);
    fputs("-----END PUBLIC KEY-----\n", f);
    fclose(f);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_verifier_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r)
           == N00B_ATTEST_ERR_VERIFIER_PEM_PARSE_FAILED);

    unlink(path);
    free(path);
    printf("  [PASS] resolve_malformed_pem\n");
}

static void
test_resolve_wrong_algorithm(void)
{
    // Hand-craft an SPKI DER carrying a NON-Ed25519 OID.
    // 1.3.101.113 (id-Ed448) is the closest sibling in the same
    // SubjectPublicKeyInfo family; we use it here purely as a
    // mismatch trigger — the file verifier backend rejects every
    // non-Ed25519 OID with
    // N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_ALGORITHM. The DER is
    // syntactically valid (the walk reaches the OID check), so
    // failure is the OID-mismatch path, not the DER-parse path.
    //
    // Shape (same length envelope as Ed25519 SPKI for simplicity):
    //   30 2A
    //     30 05 06 03 2B 65 71      <- last byte 0x71: id-Ed448
    //     03 21 00 <32 bytes>
    uint8_t der[44];
    static const uint8_t k_ed448_prefix[12] = {
        0x30, 0x2A,
        0x30, 0x05,
        0x06, 0x03, 0x2B, 0x65, 0x71,
        0x03, 0x21,
        0x00,
    };
    memcpy(der, k_ed448_prefix, 12);
    memcpy(der + 12, k_expected_pubkey, 32);

    char *path = write_pem_tempfile(der, 44, "PUBLIC KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_verifier_resolve(.ref = uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r)
           == N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_ALGORITHM);

    unlink(path);
    free(path);
    printf("  [PASS] resolve_wrong_algorithm\n");
}

static void
test_release_smoke(void)
{
    // Coverage-table item [7]: release a freshly-resolved verifier
    // and observe no fault. Release-then-use is UB per the signer-
    // side convention, so the test does not exercise post-release
    // calls (matches the signer-side `test_attest_signer_release.c`
    // shape).
    uint8_t der[44];
    build_ed25519_spki_der(der);
    char *path = write_pem_tempfile(der, 44, "PUBLIC KEY");

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_verifier_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_verifier_t *verifier = n00b_result_get(r);
    assert(verifier != nullptr);

    // Two releases on the same handle are NOT supported by the
    // public contract; the first release is the only one this
    // test exercises. A null release is documented as a no-op
    // (we test that separately below).
    n00b_attest_verifier_release(verifier);

    // Null-release no-op (signer-side convention).
    n00b_attest_verifier_release(nullptr);

    unlink(path);
    free(path);
    printf("  [PASS] release_smoke\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    // Wire up the verifier file backend's vtable + registration so
    // the resolver can find it. Per architecture §6.1 the in-tree
    // backends are registered during module-init; the host (test
    // binary) owns the call.
    n00b_attest_module_init();

    printf("== n00b_attest verifier resolve ==\n");
    test_resolve_ok_file_triple_slash();
    test_resolve_ok_file_strict();
    test_resolve_unsupported_scheme();
    test_resolve_missing_file();
    test_resolve_malformed_pem();
    test_resolve_wrong_algorithm();
    test_release_smoke();

    printf("All n00b_attest verifier resolve tests passed.\n");
    return 0;
}

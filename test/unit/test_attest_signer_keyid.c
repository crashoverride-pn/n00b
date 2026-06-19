/** @file test/unit/test_attest_signer_keyid.c — public keyid-getter
 *  regression test (WP-002 Phase 3).
 *
 *  Exercises `n00b_attest_signer_keyid` against the RFC 8032 §7.1
 *  vector #1 fixture. Asserts the returned string equals the
 *  canonical 64-hex value per D-039:
 *
 *    06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9
 *
 *  This is the lowercase-hex encoding of SHA-256 over the 44-byte
 *  SPKI DER (12-byte fixed Ed25519 prefix + 32-byte raw pubkey for
 *  the fixture seed), matching the cosign/sigstore convention.
 *
 *  Coverage:
 *    [1] keyid matches the pre-computed fixture (byte-equal).
 *    [2] Repeated calls return strings with byte-equal `data` and
 *        byte-equal length (the getter is allocation-free; same-
 *        pointer is acceptable but not required).
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the tempfile
 *  setup and stdout logging is acceptable per the established
 *  test-file precedent.
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
#include "core/runtime.h"
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

// RFC 8032 §7.1 test vector #1 seed (same fixture as resolve/release tests).
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// Canonical keyid for the RFC 8032 §7.1 vector #1 pubkey (D-039):
//   keyid = lowercase-hex(SHA-256(SPKI DER))
// SPKI DER = 12-byte fixed Ed25519 prefix + 32-byte raw pubkey.
// Reproducible via:
//   python3 -c "import hashlib;\
//     prefix=bytes.fromhex('302a300506032b657003210' '0');\
//     pubkey=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a'\
//                          '0ee172f3daa62325af021a68f707511a');\
//     print(hashlib.sha256(prefix+pubkey).hexdigest())"
static const char k_expected_keyid_hex[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

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

static char *
write_pem_tempfile(const uint8_t *der, size_t der_len)
{
    char  path_template[] = "/tmp/n00b_attest_keyid_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    n00b_buffer_t *der_buf = n00b_buffer_from_bytes((char *)der,
                                                    (int64_t)der_len);
    auto enc_r = n00b_base64_encode(der_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *b64 = n00b_result_get(enc_r);

    fprintf(f, "-----BEGIN PRIVATE KEY-----\n");
    size_t off = 0;
    while (off < b64->u8_bytes) {
        size_t take = b64->u8_bytes - off;
        if (take > 64) take = 64;
        fwrite(b64->data + off, 1, take, f);
        fputc('\n', f);
        off += take;
    }
    fprintf(f, "-----END PRIVATE KEY-----\n");
    fclose(f);
    return path;
}

static n00b_attest_signer_t *
resolve_fixture_signer(char **out_path)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path = write_pem_tempfile(der, 48);
    *out_path  = path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);
    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    return n00b_result_get(r);
}

static void
test_keyid_matches_expected(void)
{
    char *path;
    n00b_attest_signer_t *signer = resolve_fixture_signer(&path);

    n00b_string_t *kid = n00b_attest_signer_keyid(signer);
    assert(kid != nullptr);
    assert(kid->u8_bytes == 64);
    assert(sizeof(k_expected_keyid_hex) - 1 == 64);
    if (memcmp(kid->data, k_expected_keyid_hex, 64) != 0) {
        fprintf(stderr,
                "FAIL: keyid mismatch\n"
                "  expected: %.64s\n"
                "  actual:   %.64s\n",
                k_expected_keyid_hex, kid->data);
        assert(0);
    }

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] keyid_matches_expected\n");
}

static void
test_keyid_is_stable_across_calls(void)
{
    char *path;
    n00b_attest_signer_t *signer = resolve_fixture_signer(&path);

    n00b_string_t *a = n00b_attest_signer_keyid(signer);
    n00b_string_t *b = n00b_attest_signer_keyid(signer);
    assert(a != nullptr && b != nullptr);
    assert(a->u8_bytes == b->u8_bytes);
    assert(memcmp(a->data, b->data, a->u8_bytes) == 0);

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] keyid_is_stable_across_calls\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest signer keyid ==\n");
    test_keyid_matches_expected();
    test_keyid_is_stable_across_calls();
    printf("All n00b_attest signer keyid tests passed.\n");
    return 0;
}

/** @file test/unit/test_attest_verifier_keyid.c — cross-WP
 *  keyid-stability invariant test (WP-003 Phase 2).
 *
 *  **The single most important assertion at the WP-003 Phase 2
 *  gate.** Asserts that the keyid string the verifier derives
 *  for a given public key is byte-equal to the keyid string the
 *  signer derives for the SAME underlying key material.
 *
 *  Both keyids are defined as `lowercase-hex(SHA-256(SPKI DER))`
 *  per D-039. As long as:
 *
 *    1. Both backends construct the SAME 44-byte SPKI DER for
 *       the same Ed25519 pubkey (12-byte fixed prefix + 32-byte
 *       raw pubkey).
 *    2. Both backends feed it through the SAME SHA-256.
 *    3. Both backends lowercase-hex-encode the resulting digest.
 *
 *  ...the keyids will be byte-equal. Divergence at ANY of these
 *  three steps would make Phase 3's envelope-verify wrapper
 *  silently skip every signature (the wrapper filters
 *  `signatures[].keyid` by string match against the verifier's
 *  keyid).
 *
 *  Fixture: RFC 8032 §7.1 test vector #1.
 *    - Signer loads it from a PKCS#8 PEM file (the seed wrapped
 *      in the standard PrivateKeyInfo envelope).
 *    - Verifier loads it from an SPKI PEM file (the corresponding
 *      pubkey wrapped in the standard SubjectPublicKeyInfo
 *      envelope).
 *
 *  Both must produce keyid =
 *    06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9
 *
 *  Coverage:
 *    [1] signer-keyid byte-equals verifier-keyid (the gating
 *        invariant).
 *    [2] Both equal the canonical D-039 hex (third-party-
 *        verifiable fixture).
 *
 *  Test-file carve-out (D-030) applies — libc I/O for tempfile
 *  setup and stdout logging.
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

// RFC 8032 §7.1 test vector #1 seed (32 bytes) — same fixture
// used by `test_attest_signer_keyid.c` and
// `test_attest_signer_resolve.c`.
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// Matching pubkey (RFC 8032 §7.1).
static const uint8_t k_expected_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

// 12-byte fixed Ed25519 SPKI prefix.
static const uint8_t k_ed25519_spki_prefix[12] = {
    0x30, 0x2A,
    0x30, 0x05,
    0x06, 0x03, 0x2B, 0x65, 0x70,
    0x03, 0x21,
    0x00,
};

// Canonical keyid hex per D-039 — the third-party-verifiable
// expected value both backends MUST produce.
static const char k_expected_keyid_hex[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

// ---------------------------------------------------------------------------
// PEM build helpers (one PKCS#8 for the signer, one SPKI for the
// verifier — both derived from the same RFC 8032 §7.1 vector #1
// seed / pubkey).
// ---------------------------------------------------------------------------

// 48-byte PrivateKeyInfo DER for a 32-byte Ed25519 seed (same
// shape `test_attest_signer_keyid.c` builds).
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

// 44-byte SubjectPublicKeyInfo DER for the matching pubkey (same
// shape the file verifier backend caches at load time).
static void
build_ed25519_spki_der(uint8_t out[44])
{
    memcpy(out, k_ed25519_spki_prefix, 12);
    memcpy(out + 12, k_expected_pubkey, 32);
}

static char *
write_pem_tempfile(const char *prefix,
                   const uint8_t *der,
                   size_t der_len,
                   const char *label)
{
    char  path_template[64];
    snprintf(path_template, sizeof(path_template), "%sXXXXXX", prefix);
    char *path = strdup(path_template);
    int   fd   = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    n00b_buffer_t *der_buf = n00b_buffer_from_bytes((char *)der,
                                                    (int64_t)der_len);
    auto enc_r = n00b_base64_encode(der_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *b64 = n00b_result_get(enc_r);

    fprintf(f, "-----BEGIN %s-----\n", label);
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
// Tests.
// ---------------------------------------------------------------------------

static void
test_signer_verifier_keyid_byte_equal(void)
{
    // Build both PEMs from the same key material.
    uint8_t pkcs8[48];
    build_ed25519_pkcs8_der(k_seed, pkcs8);
    char *signer_path = write_pem_tempfile("/tmp/n00b_attest_vkid_sk_",
                                           pkcs8, 48, "PRIVATE KEY");

    uint8_t spki[44];
    build_ed25519_spki_der(spki);
    char *verifier_path = write_pem_tempfile("/tmp/n00b_attest_vkid_pk_",
                                             spki, 44, "PUBLIC KEY");

    // Resolve both sides.
    char uri_buf[256];

    snprintf(uri_buf, sizeof(uri_buf), "file://%s", signer_path);
    n00b_string_t *signer_uri = n00b_string_from_cstr(uri_buf);
    auto sr = n00b_attest_signer_resolve(.ref = signer_uri);
    ASSERT_OK(sr);
    n00b_attest_signer_t *signer = n00b_result_get(sr);
    assert(signer != nullptr);

    snprintf(uri_buf, sizeof(uri_buf), "file://%s", verifier_path);
    n00b_string_t *verifier_uri = n00b_string_from_cstr(uri_buf);
    auto vr = n00b_attest_verifier_resolve(.ref = verifier_uri);
    ASSERT_OK(vr);
    n00b_attest_verifier_t *verifier = n00b_result_get(vr);
    assert(verifier != nullptr);

    // The gating invariant: byte-equal keyids across the two
    // resolved handles for the same underlying key material
    // (D-039).
    n00b_string_t *signer_kid   = n00b_attest_signer_keyid(signer);
    n00b_string_t *verifier_kid = n00b_attest_verifier_keyid(verifier);
    assert(signer_kid != nullptr);
    assert(verifier_kid != nullptr);
    assert(signer_kid->u8_bytes == 64);
    assert(verifier_kid->u8_bytes == 64);

    if (signer_kid->u8_bytes != verifier_kid->u8_bytes
        || memcmp(signer_kid->data,
                  verifier_kid->data,
                  signer_kid->u8_bytes)
               != 0) {
        fprintf(stderr,
                "FAIL: cross-WP keyid byte-equality invariant violated\n"
                "  signer-keyid:   %.64s\n"
                "  verifier-keyid: %.64s\n",
                signer_kid->data, verifier_kid->data);
        assert(0);
    }

    // Belt-and-suspenders: both equal the canonical D-039 hex.
    // Without this assertion the test would pass for a divergent-
    // but-internally-consistent implementation (e.g., both
    // backends computing SHA-512 instead of SHA-256).
    assert(sizeof(k_expected_keyid_hex) - 1 == 64);
    if (memcmp(signer_kid->data, k_expected_keyid_hex, 64) != 0) {
        fprintf(stderr,
                "FAIL: signer keyid != canonical D-039 hex\n"
                "  expected: %.64s\n"
                "  actual:   %.64s\n",
                k_expected_keyid_hex, signer_kid->data);
        assert(0);
    }
    if (memcmp(verifier_kid->data, k_expected_keyid_hex, 64) != 0) {
        fprintf(stderr,
                "FAIL: verifier keyid != canonical D-039 hex\n"
                "  expected: %.64s\n"
                "  actual:   %.64s\n",
                k_expected_keyid_hex, verifier_kid->data);
        assert(0);
    }

    // Release both before exit (signer wipes the expanded sk
    // bytes via FR-SM-3; verifier release is a no-op-shaped
    // entry point for caller-uniform lifetime management).
    n00b_attest_signer_release(signer);
    n00b_attest_verifier_release(verifier);

    unlink(signer_path);
    unlink(verifier_path);
    free(signer_path);
    free(verifier_path);

    printf("  [PASS] signer_verifier_keyid_byte_equal\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest cross-WP keyid byte-equality ==\n");
    test_signer_verifier_keyid_byte_equal();
    printf("All n00b_attest verifier keyid tests passed.\n");
    return 0;
}

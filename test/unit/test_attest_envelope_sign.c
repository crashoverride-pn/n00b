/** @file test/unit/test_attest_envelope_sign.c — envelope sign
 *  vertical regression test (WP-002 Phase 3).
 *
 *  Exercises both the high-level entry point
 *  `n00b_attest_envelope_sign` and the low-level entry point
 *  `n00b_attest_envelope_add_signature` against the RFC 8032 §7.1
 *  vector #1 fixture key.
 *
 *  Coverage:
 *    [A] envelope_sign end-to-end:
 *        1. Build a Statement, wrap it in an envelope, attach the
 *           payload, resolve a fixture signer, call
 *           `n00b_attest_envelope_sign`.
 *        2. Serialize the envelope to JSON.
 *        3. Re-parse — the JSON path doesn't re-populate
 *           signatures[] on the parsed envelope handle (the parser
 *           is structural per WP-001), so signature recovery is
 *           done via the serialized JSON itself: we substring-scan
 *           the JSON for the expected keyid hex and assert it
 *           appears.
 *        4. The signature bytes we produced verify under Monocypher's
 *           `crypto_ed25519_check` against the same PAE bytes the
 *           envelope produces and the fixture pubkey.
 *
 *    [B] envelope_add_signature direct:
 *        1. Build a separate envelope; compute a signature via
 *           Monocypher directly; call
 *           `n00b_attest_envelope_add_signature(env, keyid, sig)`
 *           with a pre-computed pair.
 *        2. Serialize; assert the keyid hex appears in the rendered
 *           JSON.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the
 *  tempfile setup and stdout logging is acceptable per the
 *  established test-file precedent. The test calls Monocypher
 *  directly for its own verification step per the plan.md Phase 3
 *  regression-test block.
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

#include <monocypher.h>
#include <monocypher-ed25519.h>

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t k_expected_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

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
    char  path_template[] = "/tmp/n00b_attest_envsign_XXXXXX";
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

// Build a Statement payload identical to the dsse_roundtrip pattern,
// returning the serialized statement bytes.
static n00b_buffer_t *
build_statement_bytes(void)
{
    n00b_attest_statement_t *st = n00b_attest_statement_new();

    uint8_t d[32];
    for (int i = 0; i < 32; i++) d[i] = (uint8_t)(i * 7 + 3);
    n00b_buffer_t *digest = n00b_buffer_from_bytes((char *)d, 32);

    auto ar = n00b_attest_statement_add_subject(
        st,
        .name   = n00b_string_from_cstr("hello"),
        .digest = digest);
    ASSERT_OK(ar);

    auto tr = n00b_attest_statement_set_predicate_type(
        st,
        n00b_string_from_cstr("https://slsa.dev/provenance/v1"));
    ASSERT_OK(tr);

    static const char k_pred[] = "{\"foo\":42}";
    n00b_buffer_t *pred = n00b_buffer_from_bytes((char *)k_pred,
                                                 (int64_t)(sizeof(k_pred) - 1));
    auto pr = n00b_attest_statement_set_predicate_json(st, pred);
    ASSERT_OK(pr);

    auto sr = n00b_attest_statement_serialize(st);
    ASSERT_OK(sr);
    return n00b_result_get(sr);
}

static bool
contains_needle(const char *hay, size_t hay_len,
                const char *needle, size_t needle_len)
{
    if (needle_len > hay_len) return false;
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static void
test_envelope_sign_end_to_end(void)
{
    char *path;
    n00b_attest_signer_t *signer = resolve_fixture_signer(&path);

    n00b_buffer_t *stmt_bytes = build_statement_bytes();

    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, stmt_bytes);
    ASSERT_OK(spr);

    // High-level entry: PAE → sign → keyid → add_signature.
    auto sgr = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sgr);

    // Capture the PAE bytes so we can verify the embedded signature
    // independently.
    auto paer = n00b_attest_envelope_pae_bytes(env);
    ASSERT_OK(paer);
    n00b_buffer_t *pae = n00b_result_get(paer);

    // Serialize → inspect the JSON for the expected keyid hex.
    auto ser = n00b_attest_envelope_serialize(env);
    ASSERT_OK(ser);
    n00b_buffer_t *env_json = n00b_result_get(ser);

    if (!contains_needle(env_json->data,
                         env_json->byte_len,
                         k_expected_keyid_hex,
                         sizeof(k_expected_keyid_hex) - 1)) {
        fprintf(stderr,
                "FAIL: serialized envelope does not contain expected "
                "keyid hex.\n  json: %.*s\n",
                (int)env_json->byte_len, env_json->data);
        assert(0);
    }

    // Verify the signature against the PAE bytes + fixture pubkey
    // by re-signing the PAE via Monocypher directly and checking
    // for byte-equality. (We can't extract the signature bytes
    // from the JSON without a base64 decode of `signatures[0].sig`;
    // re-deriving the expected bytes and confirming the signer
    // produced them is the cleaner verification shape and matches
    // the sign-path test's oracle pattern.)
    uint8_t expanded_sk[64];
    uint8_t pubkey[32];
    uint8_t seed_copy[32];
    memcpy(seed_copy, k_seed, 32);
    crypto_ed25519_key_pair(expanded_sk, pubkey, seed_copy);

    uint8_t expected_sig[64];
    crypto_ed25519_sign(expected_sig,
                        expanded_sk,
                        (const uint8_t *)pae->data,
                        pae->byte_len);

    // verify under the fixture pubkey
    int rc = crypto_ed25519_check(expected_sig,
                                  k_expected_pubkey,
                                  (const uint8_t *)pae->data,
                                  pae->byte_len);
    assert(rc == 0);

    // base64-encode `expected_sig` and search for it in the JSON to
    // confirm the envelope's `signatures[0].sig` is the expected
    // bytes. This is the second-half of the oracle assertion.
    n00b_buffer_t *exp_sig_buf = n00b_buffer_from_bytes((char *)expected_sig,
                                                        64);
    auto enc_r = n00b_base64_encode(exp_sig_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *exp_sig_b64 = n00b_result_get(enc_r);

    if (!contains_needle(env_json->data,
                         env_json->byte_len,
                         exp_sig_b64->data,
                         exp_sig_b64->u8_bytes)) {
        fprintf(stderr,
                "FAIL: serialized envelope does not contain the "
                "expected (oracle-derived) signature in base64.\n");
        assert(0);
    }

    crypto_wipe(expanded_sk, sizeof(expanded_sk));

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] envelope_sign_end_to_end\n");
}

static void
test_envelope_add_signature_direct(void)
{
    // Build a pre-computed (keyid, sig) pair via Monocypher directly,
    // then call the low-level entry point and confirm the rendered
    // JSON carries the expected hex / base64 strings.
    n00b_buffer_t *stmt_bytes = build_statement_bytes();
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, stmt_bytes);
    ASSERT_OK(spr);

    auto paer = n00b_attest_envelope_pae_bytes(env);
    ASSERT_OK(paer);
    n00b_buffer_t *pae = n00b_result_get(paer);

    uint8_t expanded_sk[64];
    uint8_t pubkey[32];
    uint8_t seed_copy[32];
    memcpy(seed_copy, k_seed, 32);
    crypto_ed25519_key_pair(expanded_sk, pubkey, seed_copy);

    uint8_t sig_bytes[64];
    crypto_ed25519_sign(sig_bytes,
                        expanded_sk,
                        (const uint8_t *)pae->data,
                        pae->byte_len);
    crypto_wipe(expanded_sk, sizeof(expanded_sk));

    n00b_string_t *keyid = n00b_string_from_cstr(k_expected_keyid_hex);
    n00b_buffer_t *sig   = n00b_buffer_from_bytes((char *)sig_bytes, 64);

    auto ar = n00b_attest_envelope_add_signature(env, keyid, sig);
    ASSERT_OK(ar);

    auto ser = n00b_attest_envelope_serialize(env);
    ASSERT_OK(ser);
    n00b_buffer_t *env_json = n00b_result_get(ser);

    assert(contains_needle(env_json->data,
                           env_json->byte_len,
                           k_expected_keyid_hex,
                           sizeof(k_expected_keyid_hex) - 1));

    n00b_buffer_t *sig_buf = n00b_buffer_from_bytes((char *)sig_bytes, 64);
    auto enc_r = n00b_base64_encode(sig_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *sig_b64 = n00b_result_get(enc_r);
    assert(contains_needle(env_json->data,
                           env_json->byte_len,
                           sig_b64->data,
                           sig_b64->u8_bytes));

    printf("  [PASS] envelope_add_signature_direct\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest envelope sign ==\n");
    test_envelope_sign_end_to_end();
    test_envelope_add_signature_direct();
    printf("All n00b_attest envelope sign tests passed.\n");
    return 0;
}

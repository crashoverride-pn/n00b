/** @file test/unit/test_attest_cli_sign.c — `n00b-attest sign`
 *  verb regression test (WP-002 Phase 4).
 *
 *  Drives the **library-shaped core** of the `sign` verb
 *  (`n00b_attest_cli_sign`) end-to-end via in-memory buffers
 *  per the plan's library-API-first framing (WP-002 plan §727):
 *  the test does NOT spawn the `n00b-attest` binary, does NOT
 *  redirect stdin / stdout, and does NOT shell out. The binary's
 *  argv parsing + stdin / stdout / file binding is exercised by
 *  the build smoke (`./n00b-attest --help`); this test exercises
 *  the substrate the binary sits on.
 *
 *  Inputs:
 *    - A fixture in-toto Statement constructed via the
 *      Phase 2 / Phase 3 statement-build pattern, serialized to
 *      bytes. We feed the serialized bytes back into the verb
 *      core so the test exercises the parse + re-serialize +
 *      envelope + sign path verifiers will hit.
 *    - A fixture key URI pointing at a tempfile-written PEM
 *      built from the RFC 8032 §7.1 vector #1 seed (the same
 *      fixture every Phase 2 / Phase 3 test uses; the keyid for
 *      this seed is the D-039 canonical hex string).
 *
 *  Assertions:
 *    1. The output is a valid DSSE envelope (re-parses via
 *       `n00b_attest_envelope_parse` to a non-null handle).
 *    2. The output bytes carry the D-039 canonical keyid hex
 *       (`06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9`).
 *    3. The signature byte-string in the rendered envelope JSON
 *       equals the oracle signature: Monocypher's
 *       `crypto_ed25519_sign` over the same PAE bytes with the
 *       fixture-derived expanded secret key, base64-encoded. This
 *       is the same oracle pattern Phase 3's
 *       `test_attest_envelope_sign.c` uses.
 *    4. Monocypher's `crypto_ed25519_check` returns 0 (success)
 *       when called against the oracle-derived signature, the
 *       fixture pubkey, and the re-derived PAE bytes.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the
 *  tempfile setup and stdout logging is acceptable per the
 *  established test-file precedent. Monocypher is called
 *  directly for the verification oracle.
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

// RFC 8032 §7.1 test vector #1 (same as every Phase 2/3 test).
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

// D-039 canonical keyid for the RFC 8032 §7.1 vector #1 pubkey.
static const char k_expected_keyid_hex[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

// ---------------------------------------------------------------------------
// Fixture key tempfile.
// ---------------------------------------------------------------------------

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
    char  path_template[] = "/tmp/n00b_attest_cli_sign_XXXXXX";
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

// ---------------------------------------------------------------------------
// Fixture Statement bytes.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
build_statement_bytes(void)
{
    n00b_attest_statement_t *st = n00b_attest_statement_new();

    uint8_t d[32];
    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(i * 7 + 3);
    }
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
    n00b_buffer_t *pred = n00b_buffer_from_bytes(
        (char *)k_pred,
        (int64_t)(sizeof(k_pred) - 1));
    auto pr = n00b_attest_statement_set_predicate_json(st, pred);
    ASSERT_OK(pr);

    auto sr = n00b_attest_statement_serialize(st);
    ASSERT_OK(sr);
    return n00b_result_get(sr);
}

// ---------------------------------------------------------------------------
// Verification helpers.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Test cases.
// ---------------------------------------------------------------------------

static void
test_cli_sign_end_to_end(void)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *key_path = write_pem_tempfile(der, 48);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", key_path);
    n00b_string_t *key_uri = n00b_string_from_cstr(uri_buf);

    n00b_buffer_t *stmt_bytes = build_statement_bytes();

    // Drive the library-shaped verb core directly (NOT the binary).
    auto r = n00b_attest_cli_sign(stmt_bytes, key_uri);
    ASSERT_OK(r);
    n00b_buffer_t *env_json = n00b_result_get(r);
    assert(env_json != nullptr);
    assert(env_json->byte_len > 0);

    // Assertion 1: re-parses as a valid envelope.
    auto parse_r = n00b_attest_envelope_parse(env_json);
    ASSERT_OK(parse_r);
    n00b_attest_envelope_t *parsed_env = n00b_result_get(parse_r);
    assert(parsed_env != nullptr);

    // Assertion 2: D-039 canonical keyid appears verbatim in the
    // rendered JSON.
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

    // Assertion 3: PAE bytes from the re-parsed envelope feed the
    // oracle signature, and that oracle signature appears (base64-
    // encoded) in the rendered JSON.
    auto pae_r = n00b_attest_envelope_pae_bytes(parsed_env);
    ASSERT_OK(pae_r);
    n00b_buffer_t *pae = n00b_result_get(pae_r);

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
    crypto_wipe(expanded_sk, sizeof(expanded_sk));

    n00b_buffer_t *exp_sig_buf = n00b_buffer_from_bytes(
        (char *)expected_sig, 64);
    auto enc_r = n00b_base64_encode(exp_sig_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *exp_sig_b64 = n00b_result_get(enc_r);

    if (!contains_needle(env_json->data,
                         env_json->byte_len,
                         exp_sig_b64->data,
                         exp_sig_b64->u8_bytes)) {
        fprintf(stderr,
                "FAIL: serialized envelope does not contain the oracle-"
                "derived signature (base64).\n");
        assert(0);
    }

    // Assertion 4: Monocypher verifies the oracle signature against
    // the fixture pubkey + PAE bytes.
    int rc = crypto_ed25519_check(expected_sig,
                                  k_expected_pubkey,
                                  (const uint8_t *)pae->data,
                                  pae->byte_len);
    assert(rc == 0);

    unlink(key_path);
    free(key_path);
    printf("  [PASS] cli_sign_end_to_end\n");
}

static void
test_cli_sign_rejects_empty_statement(void)
{
    // Empty Statement input → STMT_BAD_INPUT before any signer work.
    n00b_buffer_t *empty = n00b_buffer_new(0);
    n00b_string_t *uri   = n00b_string_from_cstr("file:///dev/null");

    auto r = n00b_attest_cli_sign(empty, uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_STMT_BAD_INPUT);

    printf("  [PASS] cli_sign_rejects_empty_statement\n");
}

static void
test_cli_sign_rejects_missing_key(void)
{
    // Empty / null key URI → KEY_NOT_FOUND (the discovery chain is
    // empty in WP-002).
    n00b_buffer_t *stmt = build_statement_bytes();
    n00b_string_t *uri  = n00b_string_from_cstr("");

    auto r = n00b_attest_cli_sign(stmt, uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_KEY_NOT_FOUND);

    printf("  [PASS] cli_sign_rejects_missing_key\n");
}

static void
test_cli_sign_propagates_unsupported_scheme(void)
{
    // A non-file URI hits the resolver's UNSUPPORTED_SCHEME path
    // (the library's only registered backend in WP-002 is `file`).
    n00b_buffer_t *stmt = build_statement_bytes();
    n00b_string_t *uri  = n00b_string_from_cstr("keychain://nope");

    auto r = n00b_attest_cli_sign(stmt, uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_UNSUPPORTED_SCHEME);

    printf("  [PASS] cli_sign_propagates_unsupported_scheme\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest CLI sign verb ==\n");
    test_cli_sign_end_to_end();
    test_cli_sign_rejects_empty_statement();
    test_cli_sign_rejects_missing_key();
    test_cli_sign_propagates_unsupported_scheme();

    printf("All n00b_attest CLI sign tests passed.\n");
    return 0;
}

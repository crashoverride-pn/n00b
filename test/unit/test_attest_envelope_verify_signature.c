/** @file test/unit/test_attest_envelope_verify_signature.c — envelope
 *  verify-signature low-level wrapper regression test
 *  (WP-003 Phase 3).
 *
 *  Exercises `n00b_attest_envelope_verify_signature` — the dual of
 *  `n00b_attest_envelope_add_signature` on the verify side — across
 *  the canonical happy path + the four documented machinery /
 *  verdict edges.
 *
 *  Coverage (5 sub-cases):
 *    [1] Happy path: sign with key A, verify with matching verifier
 *        for key A at idx 0 → `Ok(true)`.
 *    [2] Wrong-key verifier: sign with key A, verify with verifier
 *        for a DIFFERENT keypair (key B) at idx 0 → `Ok(false)`
 *        (the crypto check is the Ok(false) verdict — keyid match
 *        is NOT checked at this low-level layer).
 *    [3] OOB index: 1-signature envelope, verify at idx 1 →
 *        `Err(N00B_ATTEST_ERR_DSSE_BAD_INPUT)`.
 *    [4] Null env / null verifier → `Err(_DSSE_BAD_INPUT)`.
 *    [5] Tampered payload: sign over payload A, then replace the
 *        envelope's payload with B between sign and verify (PAE
 *        bytes now differ from what was signed). Verify →
 *        `Ok(false)` (a verdict — the verify machinery ran
 *        correctly; the signature does not match the current
 *        payload). MUST NOT be `Err`.
 *
 *  Fixture keys:
 *    - Key A: RFC 8032 §7.1 test vector #1 (the canonical fixture
 *      used everywhere else in the suite). Seed is deterministic;
 *      keyid is the canonical D-039 hex.
 *    - Key B: RFC 8032 §7.1 test vector #2 — also a third-party-
 *      verifiable known-good keypair; seed is deterministic. Per
 *      DoD item 10 the wrong-key fixture must be reproducible
 *      byte-for-byte across runs; both vectors satisfy this.
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

// ---------------------------------------------------------------------------
// Deterministic fixture keypairs.
//
// Key A — RFC 8032 §7.1 test vector #1 (the canonical project
// fixture).  Key B — RFC 8032 §7.1 test vector #2 (a second
// third-party-verifiable known-good keypair). Both are hard-coded
// rather than generated at runtime so the test is reproducible
// byte-for-byte across runs (DoD item 10).
// ---------------------------------------------------------------------------

static const uint8_t k_seed_a[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// RFC 8032 §7.1 test vector #2 seed.
static const uint8_t k_seed_b[32] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};

// ---------------------------------------------------------------------------
// Tempfile + PEM build helpers.
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
write_pem_tempfile(const char *prefix, const uint8_t *der, size_t der_len)
{
    char path_template[64];
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
resolve_signer_for_seed(const uint8_t seed[32], char **out_path)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(seed, der);
    char *path = write_pem_tempfile("/tmp/n00b_attest_vsig_sk_", der, 48);
    *out_path  = path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);
    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    return n00b_result_get(r);
}

// We need a "PUBLIC KEY"-labeled PEM for the SPKI side; rather
// than parametrize `write_pem_tempfile` (which writes "PRIVATE
// KEY" for the PKCS#8 path), the pubkey PEM goes through this
// dedicated helper.
static char *
write_spki_pem_tempfile(n00b_buffer_t *spki)
{
    char  path_template[64];
    snprintf(path_template,
             sizeof(path_template),
             "/tmp/n00b_attest_vsig_pk_XXXXXX");
    char *path = strdup(path_template);
    int   fd   = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    auto enc_r = n00b_base64_encode(spki);
    ASSERT_OK(enc_r);
    n00b_string_t *b64 = n00b_result_get(enc_r);

    fprintf(f, "-----BEGIN PUBLIC KEY-----\n");
    size_t off = 0;
    while (off < b64->u8_bytes) {
        size_t take = b64->u8_bytes - off;
        if (take > 64) take = 64;
        fwrite(b64->data + off, 1, take, f);
        fputc('\n', f);
        off += take;
    }
    fprintf(f, "-----END PUBLIC KEY-----\n");
    fclose(f);
    return path;
}

static n00b_attest_verifier_t *
resolve_verifier_from_spki(n00b_buffer_t *spki, char **out_path)
{
    char *path = write_spki_pem_tempfile(spki);
    *out_path  = path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);
    auto r = n00b_attest_verifier_resolve(.ref = uri);
    ASSERT_OK(r);
    return n00b_result_get(r);
}

// ---------------------------------------------------------------------------
// Payload helpers.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
build_statement_bytes(uint8_t seed_byte)
{
    n00b_attest_statement_t *st = n00b_attest_statement_new();

    uint8_t d[32];
    for (int i = 0; i < 32; i++) d[i] = (uint8_t)(i * 7 + seed_byte);
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

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

static void
test_happy_path(void)
{
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a, &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload = build_statement_bytes(3);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);

    auto sg = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sg);

    auto vr = n00b_attest_envelope_verify_signature(env, 0, verifier);
    ASSERT_OK(vr);
    assert(n00b_result_get(vr) == true);

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_signature_happy_path\n");
}

static void
test_wrong_key_verifier(void)
{
    // Sign with key A; verify with verifier for key B. The
    // low-level wrapper does NOT keyid-match — it runs the crypto
    // check unconditionally and returns `Ok(false)` (verdict)
    // because the signature does not verify under key B's pubkey.
    char *sk_a_path;
    n00b_attest_signer_t *signer_a = resolve_signer_for_seed(k_seed_a,
                                                              &sk_a_path);
    char *sk_b_path;
    n00b_attest_signer_t *signer_b = resolve_signer_for_seed(k_seed_b,
                                                              &sk_b_path);

    char *pk_b_path;
    n00b_attest_verifier_t *verifier_b = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer_b),
        &pk_b_path);

    n00b_buffer_t *payload = build_statement_bytes(7);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);
    auto sg = n00b_attest_envelope_sign(env, signer_a);
    ASSERT_OK(sg);

    auto vr = n00b_attest_envelope_verify_signature(env, 0, verifier_b);
    ASSERT_OK(vr);
    assert(n00b_result_get(vr) == false);

    n00b_attest_verifier_release(verifier_b);
    n00b_attest_signer_release(signer_b);
    n00b_attest_signer_release(signer_a);
    unlink(pk_b_path);
    unlink(sk_b_path);
    unlink(sk_a_path);
    free(pk_b_path);
    free(sk_b_path);
    free(sk_a_path);
    printf("  [PASS] verify_signature_wrong_key_verifier\n");
}

static void
test_oob_index(void)
{
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a, &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload = build_statement_bytes(11);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);
    auto sg = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sg);

    // signature_count == 1; idx == 1 is OOB.
    assert(n00b_attest_envelope_signature_count(env) == 1);
    auto vr = n00b_attest_envelope_verify_signature(env, 1, verifier);
    assert(n00b_result_is_err(vr));
    assert(n00b_result_get_err(vr) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_signature_oob_index\n");
}

static void
test_null_inputs(void)
{
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a, &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload = build_statement_bytes(13);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);
    auto sg = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sg);

    // Null env.
    auto vr1 = n00b_attest_envelope_verify_signature(nullptr, 0, verifier);
    assert(n00b_result_is_err(vr1));
    assert(n00b_result_get_err(vr1) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    // Null verifier.
    auto vr2 = n00b_attest_envelope_verify_signature(env, 0, nullptr);
    assert(n00b_result_is_err(vr2));
    assert(n00b_result_get_err(vr2) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_signature_null_inputs\n");
}

static void
test_tampered_payload(void)
{
    // Build envelope with payload A; sign; then re-attach a
    // DIFFERENT payload (B). The signature is over PAE(A) but
    // verify now derives PAE(B). Crypto verdict: Ok(false).
    // **MUST NOT** be Err — the verify machinery ran correctly
    // and reached a definitive "no."
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a, &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload_a = build_statement_bytes(17);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr_a = n00b_attest_envelope_set_payload(env, payload_a);
    ASSERT_OK(spr_a);
    auto sg = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sg);

    // Swap the payload. `_set_payload` is documented BORROW
    // semantics (D-030 W-3): it overwrites the pointer with no
    // alloc, no copy. PAE bytes computed after this point reflect
    // payload B, not payload A.
    n00b_buffer_t *payload_b = build_statement_bytes(23);
    auto spr_b = n00b_attest_envelope_set_payload(env, payload_b);
    ASSERT_OK(spr_b);

    auto vr = n00b_attest_envelope_verify_signature(env, 0, verifier);
    ASSERT_OK(vr);  // verdict, not Err
    assert(n00b_result_get(vr) == false);

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_signature_tampered_payload\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest envelope verify-signature ==\n");
    test_happy_path();
    test_wrong_key_verifier();
    test_oob_index();
    test_null_inputs();
    test_tampered_payload();
    printf("All n00b_attest envelope verify-signature tests passed.\n");
    return 0;
}

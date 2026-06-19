/** @file test/unit/test_attest_envelope_verify.c — envelope verify
 *  high-level any-passes wrapper regression test (WP-003 Phase 3).
 *
 *  Exercises `n00b_attest_envelope_verify` — the dual of
 *  `n00b_attest_envelope_sign` on the verify side — across the
 *  five documented sub-cases. The **cross-WP round-trip
 *  integration** sub-case (sign → serialize → parse → verify) is
 *  the headline test: if it fails, either Phase 1's parser
 *  dropped data, Phase 2's verifier dropped state, or Phase 3's
 *  wrapper has a bug.
 *
 *  Coverage (5 sub-cases):
 *    [1] Multi-signature happy path: sign with key A AND key B
 *        (two `_envelope_sign` calls append two entries); verify
 *        with verifier for key A → `Ok(true)`. Key B's entry has
 *        non-matching keyid and is skipped silently per D-044 Q3;
 *        key A's entry verifies.
 *    [2] No keyid match: sign with key A; verify with verifier
 *        for key B → `Ok(false)` (the walk completes with no
 *        matching-keyid entry verifying).
 *    [3] Empty signatures: envelope with payload but no
 *        `_envelope_sign` call → `Ok(false)` (architecture §9
 *        FAIL_NO_SIGNATURES; modeled as a verdict).
 *    [4] **Cross-WP round-trip integration**: sign with key A;
 *        serialize to JSON; parse the JSON back into a new
 *        envelope (exercises Phase 1's reconstructed
 *        signatures[]); verify the parsed envelope with verifier
 *        for key A → `Ok(true)`. **Gating** test for "Phase 1 +
 *        Phase 2 + Phase 3 compose correctly through the wire
 *        format."
 *    [5] Null env / null verifier → `Err(_DSSE_BAD_INPUT)`.
 *
 *  Fixture keys:
 *    - Key A: RFC 8032 §7.1 test vector #1.
 *    - Key B: RFC 8032 §7.1 test vector #2. Both deterministic
 *      so the test is reproducible byte-for-byte (DoD item 10).
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
// Deterministic fixture keypairs (RFC 8032 §7.1 vectors #1 and #2).
// ---------------------------------------------------------------------------

static const uint8_t k_seed_a[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t k_seed_b[32] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};

// ---------------------------------------------------------------------------
// PEM helpers.
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
write_pkcs8_pem_tempfile(const uint8_t *der, size_t der_len)
{
    char  path_template[64];
    snprintf(path_template,
             sizeof(path_template),
             "/tmp/n00b_attest_venv_sk_XXXXXX");
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

static char *
write_spki_pem_tempfile(n00b_buffer_t *spki)
{
    char  path_template[64];
    snprintf(path_template,
             sizeof(path_template),
             "/tmp/n00b_attest_venv_pk_XXXXXX");
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

static n00b_attest_signer_t *
resolve_signer_for_seed(const uint8_t seed[32], char **out_path)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(seed, der);
    char *path = write_pkcs8_pem_tempfile(der, 48);
    *out_path  = path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);
    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    return n00b_result_get(r);
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
// Payload helper.
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
test_multi_sig_any_passes(void)
{
    // Sign the same envelope with key A and key B (two entries
    // appended). Resolve a verifier for key A. The walk skips
    // key B's entry (keyid mismatch — silent skip per D-044 Q3)
    // and verifies key A's entry — Ok(true).
    char *sk_a_path;
    n00b_attest_signer_t *signer_a = resolve_signer_for_seed(k_seed_a,
                                                              &sk_a_path);
    char *sk_b_path;
    n00b_attest_signer_t *signer_b = resolve_signer_for_seed(k_seed_b,
                                                              &sk_b_path);

    char *pk_a_path;
    n00b_attest_verifier_t *verifier_a = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer_a),
        &pk_a_path);

    n00b_buffer_t *payload = build_statement_bytes(31);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);

    auto sg_a = n00b_attest_envelope_sign(env, signer_a);
    ASSERT_OK(sg_a);
    auto sg_b = n00b_attest_envelope_sign(env, signer_b);
    ASSERT_OK(sg_b);
    assert(n00b_attest_envelope_signature_count(env) == 2);

    auto vr = n00b_attest_envelope_verify(env, verifier_a);
    ASSERT_OK(vr);
    assert(n00b_result_get(vr) == true);

    n00b_attest_verifier_release(verifier_a);
    n00b_attest_signer_release(signer_b);
    n00b_attest_signer_release(signer_a);
    unlink(pk_a_path);
    unlink(sk_b_path);
    unlink(sk_a_path);
    free(pk_a_path);
    free(sk_b_path);
    free(sk_a_path);
    printf("  [PASS] verify_multi_sig_any_passes\n");
}

static void
test_no_keyid_match(void)
{
    // Sign with key A; verify with verifier for key B. Walk
    // completes with no matching-keyid entry verifying — verdict
    // is Ok(false), NOT Err.
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

    n00b_buffer_t *payload = build_statement_bytes(37);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);
    auto sg = n00b_attest_envelope_sign(env, signer_a);
    ASSERT_OK(sg);

    auto vr = n00b_attest_envelope_verify(env, verifier_b);
    ASSERT_OK(vr);  // verdict, not Err
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
    printf("  [PASS] verify_no_keyid_match\n");
}

static void
test_empty_signatures(void)
{
    // Envelope with payload, NO _envelope_sign call. Walk sees
    // signature_count == 0; returns Ok(false) per architecture
    // §9 FAIL_NO_SIGNATURES.
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a,
                                                            &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload = build_statement_bytes(41);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);
    assert(n00b_attest_envelope_signature_count(env) == 0);

    auto vr = n00b_attest_envelope_verify(env, verifier);
    ASSERT_OK(vr);  // verdict, not Err
    assert(n00b_result_get(vr) == false);

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_empty_signatures\n");
}

static void
test_cross_wp_roundtrip(void)
{
    // **The gating cross-WP integration test.**
    //
    // Phase 1 + Phase 2 + Phase 3 compose correctly through the
    // wire format ONLY IF:
    //   - serialize emits signatures[] with the appended keyid+sig;
    //   - parse reconstructs signatures[] from the JSON (Phase 1
    //     DF-006 closure);
    //   - the verifier-side keyid matches the round-tripped keyid
    //     byte-equal (D-039 cross-WP invariant);
    //   - the round-tripped sig bytes match the in-memory ones
    //     byte-equal (Phase 1 base64 decode);
    //   - the round-tripped PAE bytes match the in-memory ones
    //     byte-equal (the same payload comes through).
    //
    // If this test fails, drill in via the four checks the prompt
    // describes (sig count; keyid byte-equality; sig byte-
    // equality; PAE byte-equality).
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a,
                                                            &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload = build_statement_bytes(43);
    n00b_attest_envelope_t *env_pre = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env_pre, payload);
    ASSERT_OK(spr);
    auto sg = n00b_attest_envelope_sign(env_pre, signer);
    ASSERT_OK(sg);
    assert(n00b_attest_envelope_signature_count(env_pre) == 1);

    // Serialize the envelope to JSON.
    auto ser = n00b_attest_envelope_serialize(env_pre);
    ASSERT_OK(ser);
    n00b_buffer_t *env_json = n00b_result_get(ser);

    // Parse it back. This exercises Phase 1's reconstructed
    // signatures[] (DF-006 closure).
    auto par = n00b_attest_envelope_parse(env_json);
    ASSERT_OK(par);
    n00b_attest_envelope_t *env_post = n00b_result_get(par);
    assert(n00b_attest_envelope_signature_count(env_post) == 1);

    // Verify against the parsed envelope.
    auto vr = n00b_attest_envelope_verify(env_post, verifier);
    ASSERT_OK(vr);
    if (n00b_result_get(vr) != true) {
        // Diagnostic dump per the prompt's drill-in checklist.
        fprintf(stderr,
                "FAIL: cross-WP round-trip verify produced Ok(false)\n");
        auto kid_pre_r = n00b_attest_envelope_get_signature_keyid(env_pre, 0);
        auto kid_post_r = n00b_attest_envelope_get_signature_keyid(env_post,
                                                                    0);
        auto sig_pre_r = n00b_attest_envelope_get_signature_sig(env_pre, 0);
        auto sig_post_r = n00b_attest_envelope_get_signature_sig(env_post,
                                                                  0);
        if (!n00b_result_is_err(kid_pre_r)
            && !n00b_result_is_err(kid_post_r)) {
            n00b_string_t *kp = n00b_result_get(kid_pre_r);
            n00b_string_t *kq = n00b_result_get(kid_post_r);
            fprintf(stderr,
                    "  keyid pre:  %.*s\n  keyid post: %.*s\n",
                    (int)kp->u8_bytes, kp->data,
                    (int)kq->u8_bytes, kq->data);
        }
        if (!n00b_result_is_err(sig_pre_r)
            && !n00b_result_is_err(sig_post_r)) {
            n00b_buffer_t *sp = n00b_result_get(sig_pre_r);
            n00b_buffer_t *sq = n00b_result_get(sig_post_r);
            fprintf(stderr,
                    "  sig-pre.len=%zu  sig-post.len=%zu\n",
                    (size_t)sp->byte_len, (size_t)sq->byte_len);
        }
        assert(0);
    }

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_cross_wp_roundtrip\n");
}

static void
test_null_inputs(void)
{
    char *sk_path;
    n00b_attest_signer_t *signer = resolve_signer_for_seed(k_seed_a,
                                                            &sk_path);
    char *pk_path;
    n00b_attest_verifier_t *verifier = resolve_verifier_from_spki(
        n00b_attest_signer_pubkey_spki_der(signer),
        &pk_path);

    n00b_buffer_t *payload = build_statement_bytes(47);
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);
    auto sg = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sg);

    // Null env.
    auto vr1 = n00b_attest_envelope_verify(nullptr, verifier);
    assert(n00b_result_is_err(vr1));
    assert(n00b_result_get_err(vr1) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    // Null verifier.
    auto vr2 = n00b_attest_envelope_verify(env, nullptr);
    assert(n00b_result_is_err(vr2));
    assert(n00b_result_get_err(vr2) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    n00b_attest_verifier_release(verifier);
    n00b_attest_signer_release(signer);
    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] verify_null_inputs\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest envelope verify (any-passes) ==\n");
    test_multi_sig_any_passes();
    test_no_keyid_match();
    test_empty_signatures();
    test_cross_wp_roundtrip();
    test_null_inputs();
    printf("All n00b_attest envelope verify tests passed.\n");
    return 0;
}

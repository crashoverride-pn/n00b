/** @file test/unit/test_attest_cli_verify.c — `n00b-attest verify`
 *  verb regression test (WP-003 Phase 4).
 *
 *  Drives the **library-shaped core** of the `verify` verb
 *  (`n00b_attest_cli_verify`) end-to-end via in-memory buffers
 *  per the WP-002 / WP-003 library-API-first framing: the test
 *  does NOT spawn the `n00b-attest` binary, does NOT redirect
 *  stdin / stdout, and does NOT shell out. The binary's argv
 *  parsing + stdin / file binding is exercised by the build smoke
 *  (`./n00b-attest --help` and the orchestrator's manual verify
 *  smoke); this test exercises the substrate the binary sits on.
 *
 *  Sub-cases (6):
 *    [1] **Happy path** — sign with the RFC 8032 §7.1 vector #1
 *        keypair via `_cli_sign`; write the matching SPKI PEM to
 *        a tempfile; call `_cli_verify(envelope_bytes,
 *        "file:///<tempfile>")` → assert `Ok(true)`.
 *    [2] **Wrong key** — sign with vector #1; verify with the
 *        vector #2 SPKI PEM → `Ok(false)`. The walk completes
 *        with no matching-keyid entry; the verdict is `Ok(false)`,
 *        NOT `Err`.
 *    [3] **Tampered envelope** — sign with vector #1; serialize;
 *        flip one byte in the base64 payload field of the JSON
 *        (parser still accepts; PAE differs from the bytes that
 *        were signed); call `_cli_verify` → `Ok(false)`.
 *    [4] **Round-trip integration** — sign with vector #1; pass
 *        the envelope JSON straight back to `_cli_verify` with
 *        the matching SPKI PEM → `Ok(true)`. **This is the cross-
 *        WP gating sub-case** — if it passes, the WP-003 CLI
 *        vertical (parse → resolve → verify → release, all
 *        through the library core) is wired correctly.
 *    [5] **Missing file** — `--key file:///<does-not-exist>` →
 *        `Err(N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND)`.
 *    [6] **Malformed envelope** — pass non-JSON bytes; expect
 *        `Err(_DSSE_BAD_JSON)`.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for tempfile
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
// PEM tempfile helpers (mirror of the Phase 2 / Phase 3 fixtures).
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
    char  path_template[] = "/tmp/n00b_attest_cliv_sk_XXXXXX";
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

static char *
write_spki_pem_tempfile(n00b_buffer_t *spki)
{
    char  path_template[] = "/tmp/n00b_attest_cliv_pk_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
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

// Resolve a temp signer for a seed, return SPKI DER + private-key
// PEM path. Used to build the matching SPKI PEM tempfile for the
// verifier side of each sub-case.
static n00b_buffer_t *
spki_der_for_seed(const uint8_t seed[32], char **out_sk_path)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(seed, der);
    char *path  = write_pkcs8_pem_tempfile(der, 48);
    *out_sk_path = path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_signer_t *s = n00b_result_get(r);

    n00b_buffer_t *spki = n00b_attest_signer_pubkey_spki_der(s);
    // Copy out to detach from the signer's lifetime — we will
    // release the signer next.
    n00b_buffer_t *copy = n00b_buffer_from_bytes(spki->data,
                                                 (int64_t)spki->byte_len);
    n00b_attest_signer_release(s);
    return copy;
}

// ---------------------------------------------------------------------------
// Statement fixture (mirror of `test_attest_cli_sign.c`).
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
    n00b_buffer_t *pred = n00b_buffer_from_bytes(
        (char *)k_pred,
        (int64_t)(sizeof(k_pred) - 1));
    auto pr = n00b_attest_statement_set_predicate_json(st, pred);
    ASSERT_OK(pr);

    auto sr = n00b_attest_statement_serialize(st);
    ASSERT_OK(sr);
    return n00b_result_get(sr);
}

// Build a signed envelope (via `_cli_sign`) for a given seed +
// statement byte; returns the envelope JSON bytes. The signer-side
// tempfile path is returned through `out_sk_path` so the caller
// can `unlink` it after the test.
static n00b_buffer_t *
build_signed_envelope(const uint8_t seed[32],
                      uint8_t       stmt_seed_byte,
                      char        **out_sk_path)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(seed, der);
    char *sk_path = write_pkcs8_pem_tempfile(der, 48);
    *out_sk_path  = sk_path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", sk_path);
    n00b_string_t *sk_uri = n00b_string_from_cstr(uri_buf);

    n00b_buffer_t *stmt = build_statement_bytes(stmt_seed_byte);
    auto sign_r = n00b_attest_cli_sign(stmt, sk_uri);
    ASSERT_OK(sign_r);
    return n00b_result_get(sign_r);
}

// ---------------------------------------------------------------------------
// Sub-cases.
// ---------------------------------------------------------------------------

static void
test_cli_verify_happy_path(void)
{
    char *sk_path;
    n00b_buffer_t *env_json = build_signed_envelope(k_seed_a, 17, &sk_path);

    // Build the matching SPKI PEM (key A pubkey).
    char *sk_path_for_spki;
    n00b_buffer_t *spki = spki_der_for_seed(k_seed_a, &sk_path_for_spki);
    char *pk_path = write_spki_pem_tempfile(spki);
    unlink(sk_path_for_spki);
    free(sk_path_for_spki);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", pk_path);
    n00b_string_t *pk_uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_cli_verify(env_json, pk_uri);
    ASSERT_OK(r);
    assert(n00b_result_get(r) == true);

    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] cli_verify_happy_path\n");
}

static void
test_cli_verify_wrong_key(void)
{
    // Sign with key A; verify with key B's pubkey. The walk
    // completes with no matching-keyid entry; verdict Ok(false).
    char *sk_path;
    n00b_buffer_t *env_json = build_signed_envelope(k_seed_a, 19, &sk_path);

    char *sk_path_for_spki;
    n00b_buffer_t *spki = spki_der_for_seed(k_seed_b, &sk_path_for_spki);
    char *pk_path = write_spki_pem_tempfile(spki);
    unlink(sk_path_for_spki);
    free(sk_path_for_spki);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", pk_path);
    n00b_string_t *pk_uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_cli_verify(env_json, pk_uri);
    ASSERT_OK(r);  // verdict, NOT Err
    assert(n00b_result_get(r) == false);

    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] cli_verify_wrong_key\n");
}

// Locate the `"payload":"<base64>"` field in the wire JSON and
// flip a single byte inside the base64 value. The result is still
// valid JSON and still parses through `_envelope_parse` (the
// base64 alphabet survives a single substitution by another
// base64 character), but the decoded payload bytes differ from
// the bytes that were signed — the PAE bytes the verifier
// re-derives no longer match the signature.
//
// Returns a fresh `n00b_buffer_t *` holding the tampered bytes.
static n00b_buffer_t *
tamper_envelope_payload(n00b_buffer_t *original)
{
    // Make a writable copy.
    n00b_buffer_t *tampered = n00b_buffer_from_bytes(
        original->data,
        (int64_t)original->byte_len);

    // Find the literal `"payload":"` substring.
    static const char k_needle[] = "\"payload\":\"";
    size_t            need_len  = sizeof(k_needle) - 1;
    size_t            hit       = SIZE_MAX;
    for (size_t i = 0; i + need_len <= (size_t)tampered->byte_len; i++) {
        if (memcmp(tampered->data + i, k_needle, need_len) == 0) {
            hit = i;
            break;
        }
    }
    assert(hit != SIZE_MAX);

    // Start of the base64 value: just past the closing quote of
    // the `"payload":` key + the opening quote of the value.
    size_t b64_start = hit + need_len;

    // Find the matching closing quote (end of base64 value).
    size_t b64_end = b64_start;
    while (b64_end < (size_t)tampered->byte_len
           && tampered->data[b64_end] != '"') {
        b64_end++;
    }
    assert(b64_end > b64_start);

    // Pick a byte inside the base64 value (mid-string), and flip
    // it to a different base64-alphabet character so the JSON +
    // base64 grammar still accept. The payload base64 is well
    // above 10 bytes for any non-empty in-toto Statement.
    size_t tamper_at = b64_start + (b64_end - b64_start) / 2;
    char   c         = tampered->data[tamper_at];

    char replacement;
    // Cycle within the base64 alphabet — pick the next char that
    // is provably different from `c` AND is itself valid base64.
    if (c >= 'A' && c <= 'Z') {
        replacement = (c == 'Z') ? 'A' : (char)(c + 1);
    }
    else if (c >= 'a' && c <= 'z') {
        replacement = (c == 'z') ? 'a' : (char)(c + 1);
    }
    else if (c >= '0' && c <= '9') {
        replacement = (c == '9') ? '0' : (char)(c + 1);
    }
    else if (c == '+') {
        replacement = '/';
    }
    else if (c == '/') {
        replacement = '+';
    }
    else if (c == '=') {
        // Padding — should not have landed here under our
        // mid-string pick, but be defensive: fall through to a
        // visibly-different alphabet char.
        replacement = 'A';
    }
    else {
        // Unexpected — bail loudly.
        fprintf(stderr,
                "tamper_envelope_payload: unexpected byte 0x%02x at %zu\n",
                (unsigned)(unsigned char)c, tamper_at);
        assert(0);
        return nullptr;
    }
    assert(replacement != c);
    tampered->data[tamper_at] = replacement;
    return tampered;
}

static void
test_cli_verify_tampered_payload(void)
{
    char *sk_path;
    n00b_buffer_t *env_json = build_signed_envelope(k_seed_a, 23, &sk_path);

    // Tamper one byte in the base64 payload value.
    n00b_buffer_t *tampered = tamper_envelope_payload(env_json);

    char *sk_path_for_spki;
    n00b_buffer_t *spki = spki_der_for_seed(k_seed_a, &sk_path_for_spki);
    char *pk_path = write_spki_pem_tempfile(spki);
    unlink(sk_path_for_spki);
    free(sk_path_for_spki);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", pk_path);
    n00b_string_t *pk_uri = n00b_string_from_cstr(uri_buf);

    // The parse succeeds (JSON valid, base64 valid); the verify
    // returns Ok(false) — the PAE bytes differ from those that
    // were signed.
    auto r = n00b_attest_cli_verify(tampered, pk_uri);
    ASSERT_OK(r);  // verdict, NOT Err
    assert(n00b_result_get(r) == false);

    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] cli_verify_tampered_payload\n");
}

static void
test_cli_verify_roundtrip_integration(void)
{
    // **The gating cross-WP integration sub-case.**
    //
    // _cli_sign produces an envelope JSON; we feed it straight
    // back through _cli_verify with the matching SPKI PEM. If
    // this passes the full CLI vertical (parse → resolve →
    // verify → release, all through the library cores) is wired
    // correctly.
    char *sk_path;
    n00b_buffer_t *env_json = build_signed_envelope(k_seed_a, 29, &sk_path);

    char *sk_path_for_spki;
    n00b_buffer_t *spki = spki_der_for_seed(k_seed_a, &sk_path_for_spki);
    char *pk_path = write_spki_pem_tempfile(spki);
    unlink(sk_path_for_spki);
    free(sk_path_for_spki);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", pk_path);
    n00b_string_t *pk_uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_cli_verify(env_json, pk_uri);
    if (n00b_result_is_err(r)) {
        fprintf(stderr,
                "FAIL: cross-WP roundtrip _cli_verify returned Err(%d)\n",
                n00b_result_get_err(r));
        assert(0);
    }
    if (n00b_result_get(r) != true) {
        fprintf(stderr,
                "FAIL: cross-WP roundtrip _cli_verify produced Ok(false)\n");
        assert(0);
    }

    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    printf("  [PASS] cli_verify_roundtrip_integration\n");
}

static void
test_cli_verify_missing_file(void)
{
    // Build a valid envelope so the parse step doesn't short-
    // circuit before the verifier-resolve step.
    char *sk_path;
    n00b_buffer_t *env_json = build_signed_envelope(k_seed_a, 31, &sk_path);

    n00b_string_t *uri = n00b_string_from_cstr(
        "file:///tmp/n00b_attest_cliv_does_not_exist_xyz_42");

    auto r = n00b_attest_cli_verify(env_json, uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND);

    unlink(sk_path);
    free(sk_path);
    printf("  [PASS] cli_verify_missing_file\n");
}

static void
test_cli_verify_malformed_envelope(void)
{
    // Non-JSON bytes → _envelope_parse returns _DSSE_BAD_JSON.
    static const char k_garbage[] = "this is not a JSON envelope";
    n00b_buffer_t *bytes = n00b_buffer_from_bytes(
        (char *)k_garbage,
        (int64_t)(sizeof(k_garbage) - 1));

    // Provide a syntactically-valid URI so the failure surfaces
    // strictly from the parse step (not the verifier-resolve step).
    char *sk_path_for_spki;
    n00b_buffer_t *spki = spki_der_for_seed(k_seed_a, &sk_path_for_spki);
    char *pk_path = write_spki_pem_tempfile(spki);
    unlink(sk_path_for_spki);
    free(sk_path_for_spki);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", pk_path);
    n00b_string_t *pk_uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_cli_verify(bytes, pk_uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_DSSE_BAD_JSON);

    unlink(pk_path);
    free(pk_path);
    printf("  [PASS] cli_verify_malformed_envelope\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest CLI verify verb ==\n");
    test_cli_verify_happy_path();
    test_cli_verify_wrong_key();
    test_cli_verify_tampered_payload();
    test_cli_verify_roundtrip_integration();
    test_cli_verify_missing_file();
    test_cli_verify_malformed_envelope();

    printf("All n00b_attest CLI verify tests passed.\n");
    return 0;
}

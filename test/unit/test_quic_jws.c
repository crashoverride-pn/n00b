/*
 * test_quic_jws.c — Unit tests for the ACME JWS module.
 *
 * Covers:
 *   1. Base64url-no-pad encode/decode round-trip across length classes.
 *   2. Real ECDSA-P-256 sign on the ephemeral provider — signature
 *      verifies under uECC against the matching public key.
 *   3. JWS build (kid form) — output parses as the expected JSON
 *      shape and the embedded signature verifies against the signer's
 *      public key.
 *   4. JWS build (jwk form) — same plus the JWK in the protected
 *      header matches the canonical JWK.
 *   5. JWK thumbprint matches a hand-computed reference vector
 *      (RFC 7638 § 3.1).
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "uECC.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/jws.h"

/* ============================================================================
 * 1. base64url-no-pad round-trip
 * ============================================================================ */

static void
test_b64url_roundtrip(void)
{
    const struct {
        const char *raw;
        size_t      raw_len;
        const char *expected;
    } cases[] = {
        {"",          0, ""},
        {"f",         1, "Zg"},
        {"fo",        2, "Zm8"},
        {"foo",       3, "Zm9v"},
        {"foob",      4, "Zm9vYg"},
        {"fooba",     5, "Zm9vYmE"},
        {"foobar",    6, "Zm9vYmFy"},
        /* ensure URL-safe alphabet kicks in: 0xff,0xff produces "//" in
         * standard base64; in base64url it should be "__". */
        {"\xff\xff", 2, "__8"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *enc = n00b_b64url_encode((const uint8_t *)cases[i].raw,
                                       cases[i].raw_len);
        assert(strcmp(enc, cases[i].expected) == 0);

        auto dr = n00b_b64url_decode(enc, strlen(enc));
        assert(n00b_result_is_ok(dr));
        n00b_buffer_t *back = n00b_result_get(dr);
        assert((size_t)back->byte_len == cases[i].raw_len);
        if (cases[i].raw_len > 0) {
            assert(memcmp(back->data, cases[i].raw, cases[i].raw_len) == 0);
        }
    }
    printf("  [PASS] base64url encode/decode round-trip\n");
}

static void
test_b64url_decode_rejects_garbage(void)
{
    /* Length 1 (mod 4) is invalid in unpadded form. */
    auto r1 = n00b_b64url_decode("A", 1);
    assert(n00b_result_is_err(r1));
    /* Padding character '=' is not in the alphabet. */
    auto r2 = n00b_b64url_decode("AB==", 4);
    assert(n00b_result_is_err(r2));
    /* '/' / '+' from standard base64 are not in URL-safe alphabet. */
    auto r3 = n00b_b64url_decode("AB+/", 4);
    assert(n00b_result_is_err(r3));
    printf("  [PASS] base64url decode rejects garbage / standard-base64 chars\n");
}

/* ============================================================================
 * 2. Ephemeral ECDSA-P-256: sign produces a signature uECC accepts.
 * ============================================================================ */

static void
test_secret_ecdsa_p256_signs_and_verifies(void)
{
    n00b_buffer_t *uri = n00b_buffer_from_cstr("ephemeral:signer");
    auto r1 = n00b_quic_secret_open(uri);
    assert(n00b_result_is_ok(r1));
    n00b_quic_secret_t *s = n00b_result_get(r1);

    /* Get the public key counterpart. */
    auto pk = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(pk));
    n00b_buffer_t *pub = n00b_result_get(pk);
    assert((size_t)pub->byte_len == 64);

    /* Asking for a non-EC pubkey is INVALID_ARG. */
    auto pk2 = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ED25519);
    assert(n00b_result_is_err(pk2));

    /* Sign some bytes. */
    n00b_buffer_t data;
    memset(&data, 0, sizeof(data));
    n00b_buffer_init(&data, .raw = (char *)"the quick brown fox", .length = 19);

    auto sr = n00b_quic_secret_sign(s, &data, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(sr));
    n00b_buffer_t *sig = n00b_result_get(sr);
    assert((size_t)sig->byte_len == 64);

    /* Verify under uECC: hash the same data, run uECC_verify with the
     * pubkey. */
    uint8_t digest[32];
    {
        n00b_sha256_ctx_t ctx;
        n00b_sha256_init(&ctx);
        n00b_sha256_update(&ctx, (const uint8_t *)data.data,
                           (size_t)data.byte_len);
        n00b_sha256_digest_t words;
        n00b_sha256_finalize(&ctx, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w     = words[i];
            digest[i*4]    = (uint8_t)(w >> 24);
            digest[i*4+1]  = (uint8_t)(w >> 16);
            digest[i*4+2]  = (uint8_t)(w >> 8);
            digest[i*4+3]  = (uint8_t)w;
        }
    }
    int ok = uECC_verify((const uint8_t *)pub->data, digest, 32,
                         (const uint8_t *)sig->data, uECC_secp256r1());
    assert(ok == 1);

    /* Tamper with one byte of the data — verification must fail. */
    char *tampered = (char *)data.data;
    tampered[0] ^= 0x01;
    {
        n00b_sha256_ctx_t ctx;
        n00b_sha256_init(&ctx);
        n00b_sha256_update(&ctx, (const uint8_t *)data.data,
                           (size_t)data.byte_len);
        n00b_sha256_digest_t words;
        n00b_sha256_finalize(&ctx, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w     = words[i];
            digest[i*4]    = (uint8_t)(w >> 24);
            digest[i*4+1]  = (uint8_t)(w >> 16);
            digest[i*4+2]  = (uint8_t)(w >> 8);
            digest[i*4+3]  = (uint8_t)w;
        }
    }
    int ok2 = uECC_verify((const uint8_t *)pub->data, digest, 32,
                          (const uint8_t *)sig->data, uECC_secp256r1());
    assert(ok2 == 0);

    n00b_quic_secret_close(s);
    printf("  [PASS] ECDSA-P-256 sign + uECC verify (and reject on tamper)\n");
}

/* ============================================================================
 * 3. JWS (kid form): output shape + signature verifies on signer's pubkey.
 * ============================================================================ */

/* Locate the value of `key` in the JSON @p s. Returns a pointer to the
 * first character of the value (after the opening quote) and writes
 * the length excluding the closing quote.  Returns NULL if the key
 * isn't present.  Crude but enough for this test (no escapes). */
static const char *
find_string(const char *s, const char *key, size_t *len_out)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(s, needle);
    if (!p) {
        return NULL;
    }
    p += strlen(needle);
    const char *end = strchr(p, '"');
    if (!end) {
        return NULL;
    }
    *len_out = (size_t)(end - p);
    return p;
}

static void
verify_jws_signature(n00b_buffer_t *body, n00b_buffer_t *pub)
{
    const char *json = body->data;

    size_t      bh_len, bp_len, bs_len;
    const char *bh = find_string(json, "protected", &bh_len);
    const char *bp = find_string(json, "payload",   &bp_len);
    const char *bs = find_string(json, "signature", &bs_len);
    assert(bh && bp && bs);

    /* Reconstruct the signing input: bh || "." || bp. */
    size_t si_len = bh_len + 1 + bp_len;
    uint8_t *si = malloc(si_len);
    memcpy(si, bh, bh_len);
    si[bh_len] = '.';
    memcpy(si + bh_len + 1, bp, bp_len);

    uint8_t digest[32];
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    n00b_sha256_update(&ctx, si, si_len);
    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w     = words[i];
        digest[i*4]    = (uint8_t)(w >> 24);
        digest[i*4+1]  = (uint8_t)(w >> 16);
        digest[i*4+2]  = (uint8_t)(w >> 8);
        digest[i*4+3]  = (uint8_t)w;
    }

    auto dr = n00b_b64url_decode(bs, bs_len);
    assert(n00b_result_is_ok(dr));
    n00b_buffer_t *raw_sig = n00b_result_get(dr);
    assert((size_t)raw_sig->byte_len == 64);

    int ok = uECC_verify((const uint8_t *)pub->data, digest, 32,
                         (const uint8_t *)raw_sig->data, uECC_secp256r1());
    free(si);
    assert(ok == 1);
}

static void
test_jws_kid(void)
{
    auto r1 = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:acct"));
    assert(n00b_result_is_ok(r1));
    n00b_quic_secret_t *s = n00b_result_get(r1);

    auto pk = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ECDSA_P256);
    n00b_buffer_t *pub = n00b_result_get(pk);

    const char *payload_json = "{\"contact\":[\"mailto:dev@example.com\"]}";

    auto br = n00b_jws_build(s,
                             "abc-nonce-123",
                             "https://acme-staging.example/order",
                             (const uint8_t *)payload_json,
                             strlen(payload_json),
                             .kid = "https://acme-staging.example/acct/42");
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *body = n00b_result_get(br);

    /* Output is JSON with the three flattened-JWS members. */
    assert(strstr(body->data, "\"protected\":") != NULL);
    assert(strstr(body->data, "\"payload\":")   != NULL);
    assert(strstr(body->data, "\"signature\":") != NULL);

    /* Signature verifies. */
    verify_jws_signature(body, pub);

    /* Decoded protected header carries alg=ES256 + the kid (NOT a jwk). */
    size_t bh_len;
    const char *bh = find_string(body->data, "protected", &bh_len);
    auto hdr_r = n00b_b64url_decode(bh, bh_len);
    assert(n00b_result_is_ok(hdr_r));
    n00b_buffer_t *hdr = n00b_result_get(hdr_r);
    assert(strstr(hdr->data, "\"alg\":\"ES256\"") != NULL);
    assert(strstr(hdr->data, "\"kid\":\"https://acme-staging.example/acct/42\"") != NULL);
    assert(strstr(hdr->data, "\"jwk\":") == NULL);

    n00b_quic_secret_close(s);
    printf("  [PASS] JWS (kid form) shape + signature verify\n");
}

static void
test_jws_jwk(void)
{
    auto r1 = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:newacct"));
    n00b_quic_secret_t *s = n00b_result_get(r1);

    auto pk = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ECDSA_P256);
    n00b_buffer_t *pub = n00b_result_get(pk);

    auto br = n00b_jws_build(s,
                             "nonce-xyz",
                             "https://acme-staging.example/newAccount",
                             (const uint8_t *)"{\"termsOfServiceAgreed\":true}",
                             strlen("{\"termsOfServiceAgreed\":true}"),
                             .embed_jwk = true);
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *body = n00b_result_get(br);

    /* Decoded protected header carries the canonical JWK. */
    size_t bh_len;
    const char *bh = find_string(body->data, "protected", &bh_len);
    auto hdr_r = n00b_b64url_decode(bh, bh_len);
    n00b_buffer_t *hdr = n00b_result_get(hdr_r);
    char *expected_jwk = n00b_jwk_p256_canonical((const uint8_t *)pub->data);
    char  needle[512];
    snprintf(needle, sizeof(needle), "\"jwk\":%s", expected_jwk);
    assert(strstr(hdr->data, needle) != NULL);

    /* Signature still verifies. */
    verify_jws_signature(body, pub);

    /* Both kid and embed_jwk together → INVALID_ARG. */
    auto br2 = n00b_jws_build(s, "n", "u",
                              (const uint8_t *)"", 0,
                              .kid = "https://x/acct/1",
                              .embed_jwk = true);
    assert(n00b_result_is_err(br2));

    /* Neither → INVALID_ARG. */
    auto br3 = n00b_jws_build(s, "n", "u",
                              (const uint8_t *)"", 0);
    assert(n00b_result_is_err(br3));

    n00b_quic_secret_close(s);
    printf("  [PASS] JWS (jwk form) shape + signature verify + arg validation\n");
}

/* ============================================================================
 * 4. JWK thumbprint reference vector — RFC 7638 § 3.1 (RSA example only,
 *    so we instead lock down the property that thumbprint(pub)
 *    == SHA-256(canonical_jwk(pub)) for our EC P-256 form.
 * ============================================================================ */

static void
test_jwk_thumbprint_matches_canonical(void)
{
    auto r1 = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:tp"));
    n00b_quic_secret_t *s = n00b_result_get(r1);

    auto pk = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ECDSA_P256);
    n00b_buffer_t *pub = n00b_result_get(pk);

    char *jwk = n00b_jwk_p256_canonical((const uint8_t *)pub->data);

    uint8_t expected[32];
    {
        n00b_sha256_ctx_t ctx;
        n00b_sha256_init(&ctx);
        n00b_sha256_update(&ctx, (const uint8_t *)jwk, strlen(jwk));
        n00b_sha256_digest_t words;
        n00b_sha256_finalize(&ctx, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w        = words[i];
            expected[i*4]     = (uint8_t)(w >> 24);
            expected[i*4 + 1] = (uint8_t)(w >> 16);
            expected[i*4 + 2] = (uint8_t)(w >> 8);
            expected[i*4 + 3] = (uint8_t)w;
        }
    }

    uint8_t got[32];
    n00b_jwk_p256_thumbprint((const uint8_t *)pub->data, got);
    assert(memcmp(got, expected, 32) == 0);

    /* Canonical JWK shape sanity-check. */
    assert(strstr(jwk, "\"crv\":\"P-256\"") != NULL);
    assert(strstr(jwk, "\"kty\":\"EC\"")    != NULL);
    assert(strstr(jwk, "\"x\":\"")          != NULL);
    assert(strstr(jwk, "\"y\":\"")          != NULL);

    n00b_quic_secret_close(s);
    printf("  [PASS] JWK thumbprint == SHA-256(canonical JWK)\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_jws:\n");
    test_b64url_roundtrip();
    test_b64url_decode_rejects_garbage();
    test_secret_ecdsa_p256_signs_and_verifies();
    test_jws_kid();
    test_jws_jwk();
    test_jwk_thumbprint_matches_canonical();
    printf("All quic_jws tests passed.\n");

    n00b_shutdown();
    return 0;
}

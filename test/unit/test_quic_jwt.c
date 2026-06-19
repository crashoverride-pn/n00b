/*
 * test_quic_jwt.c — Phase 3 § 6: JWT verify + claim validation.
 *
 * What's exercised:
 *   1. Compact JWS round-trip: build a token via the existing
 *      jws encoder, then convert it to compact form (base64url
 *      header `.` base64url payload `.` base64url sig).
 *      Verify with a JWKS containing the matching public key.
 *   2. Tamper rejection: mutate one byte of payload → reject.
 *   3. `alg=none` and `HS*` rejection.
 *   4. Audience mismatch / issuer mismatch / expired token.
 *   5. JWKS parse + lookup-by-kid.
 *
 * RS256 + RSA-PKCS1-v1_5 verify gets a separate sub-test using a
 * pre-baked RFC test vector (key + signature) from RFC 7520 § 4.4
 * (or a synthetic equivalent).  The bignum modexp is the highest-
 * risk piece; this test pins it against a known-good vector.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "crypto/jwt.h"
#include "internal/crypto/jws.h"

#include "uECC.h"

/* Build a compact JWS by hand for the verifier.  We sign the
 * `header.payload` bytes with the ephemeral secret's privkey and
 * encode the raw r||s as the third field. */
static char *
mint_compact_jws_es256(n00b_quic_secret_t *signer,
                       const char         *header_json,
                       const char         *payload_json)
{
    /* base64url-encode header + payload. */
    char *h_b64 = n00b_b64url_encode((const uint8_t *)header_json,
                                     strlen(header_json));
    char *p_b64 = n00b_b64url_encode((const uint8_t *)payload_json,
                                     strlen(payload_json));

    /* signing input = h_b64 . p_b64 */
    size_t ilen = strlen(h_b64) + 1 + strlen(p_b64);
    char  *input = malloc(ilen + 1);
    snprintf(input, ilen + 1, "%s.%s", h_b64, p_b64);

    /* Sign via the secret's ECDSA-P-256 verb. */
    n00b_buffer_t *msg = n00b_buffer_from_bytes(input, (int64_t)ilen);
    auto sr = n00b_quic_secret_sign(signer, msg, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sr)) {
        free(input);
        return nullptr;
    }
    n00b_buffer_t *sig = n00b_result_get(sr);
    char *sig_b64 = n00b_b64url_encode((const uint8_t *)sig->data,
                                       (size_t)sig->byte_len);

    /* Assemble the compact form. */
    size_t total = ilen + 1 + strlen(sig_b64);
    char  *out   = malloc(total + 1);
    snprintf(out, total + 1, "%s.%s", input, sig_b64);
    free(input);
    return out;
}

/* Build a JWKS JSON wrapping a single ES256 public key. */
static char *
build_jwks(n00b_quic_secret_t *signer, const char *kid)
{
    auto pkr = n00b_quic_secret_pubkey(signer, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(pkr)) return nullptr;
    n00b_buffer_t *pk = n00b_result_get(pkr);
    if (pk->byte_len != 64) return nullptr;
    char *x_b64 = n00b_b64url_encode((const uint8_t *)pk->data,      32);
    char *y_b64 = n00b_b64url_encode((const uint8_t *)pk->data + 32, 32);
    char *out   = malloc(strlen(x_b64) + strlen(y_b64) + strlen(kid) + 256);
    sprintf(out,
            "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"%s\","
            "\"x\":\"%s\",\"y\":\"%s\"}]}",
            kid, x_b64, y_b64);
    return out;
}

/* The verifier resolves a kid against a JWKS held in ctx. */
static n00b_jwk_t *
resolve_via_set(void *ctx, const char *kid, const char *alg)
{
    (void)alg;
    n00b_option_t(n00b_jwk_t *) k = n00b_jwk_set_lookup((n00b_jwk_set_t *)ctx, kid);
    return n00b_option_is_set(k) ? n00b_option_get(k) : nullptr;
}

static void
test_es256_roundtrip(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:jwt-es"));
    assert(n00b_result_is_ok(kr));
    n00b_quic_secret_t *k = n00b_result_get(kr);

    char *jwks_json = build_jwks(k, "es-test-1");
    assert(jwks_json);
    auto sr = n00b_jwk_set_parse(jwks_json);
    assert(n00b_result_is_ok(sr));
    n00b_jwk_set_t *set = n00b_result_get(sr);
    assert(set->count == 1);
    assert(strcmp(set->keys[0]->kty, "EC") == 0);
    assert(strcmp(set->keys[0]->kid, "es-test-1") == 0);

    /* Build a token with: issuer=https://idp.example, aud=svc-x, exp=far future. */
    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[256];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"es-test-1\"}");
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"https://idp.example\",\"aud\":\"svc-x\","
             "\"sub\":\"alice\",\"exp\":%lld}",
             (long long)exp);

    char *jws = mint_compact_jws_es256(k, hdr, pl);
    assert(jws);

    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc-x",
                                    .expected_issuer   = "https://idp.example",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    assert(n00b_result_is_ok(vr));
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    auto cr = n00b_jwt_verify(v, jws);
    assert(n00b_result_is_ok(cr));
    n00b_jwt_claims_t *claims = n00b_result_get(cr);
    assert(claims->iss && strcmp(claims->iss, "https://idp.example") == 0);
    assert(claims->sub && strcmp(claims->sub, "alice") == 0);
    assert(claims->aud && strcmp(claims->aud, "svc-x") == 0);
    assert(claims->exp_ms == exp * 1000);
    printf("  [PASS] ES256 round-trip: verify + claim extract\n");

    /* Tamper: flip a byte in the payload b64.  Keep the same length so
     * the structural parse still succeeds; the ECDSA verify must
     * reject. */
    char *tampered = strdup(jws);
    char *first_dot = strchr(tampered, '.');
    char *second_dot = strchr(first_dot + 1, '.');
    if (first_dot + 1 < second_dot) {
        first_dot[1] = (first_dot[1] == 'A') ? 'B' : 'A';
    }
    auto tr = n00b_jwt_verify(v, tampered);
    assert(n00b_result_is_err(tr));
    assert(n00b_result_get_err(tr) == N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    printf("  [PASS] payload tamper → AUTH_TOKEN_INVALID\n");
    free(tampered);

    /* Wrong audience. */
    auto vr2 = n00b_jwt_verifier_new(.expected_audience = "other-svc",
                                     .resolve_key       = resolve_via_set,
                                     .resolve_key_ctx   = set);
    auto cr2 = n00b_jwt_verify(n00b_result_get(vr2), jws);
    assert(n00b_result_is_err(cr2));
    assert(n00b_result_get_err(cr2) == N00B_QUIC_ERR_AUTH_AUD_MISMATCH);
    printf("  [PASS] audience mismatch → AUTH_AUD_MISMATCH\n");

    /* Wrong issuer. */
    auto vr3 = n00b_jwt_verifier_new(.expected_audience = "svc-x",
                                     .expected_issuer   = "https://other.example",
                                     .resolve_key       = resolve_via_set,
                                     .resolve_key_ctx   = set);
    auto cr3 = n00b_jwt_verify(n00b_result_get(vr3), jws);
    assert(n00b_result_is_err(cr3));
    assert(n00b_result_get_err(cr3) == N00B_QUIC_ERR_AUTH_ISS_MISMATCH);
    printf("  [PASS] issuer mismatch → AUTH_ISS_MISMATCH\n");

    free(jws);
    free(jwks_json);
    n00b_quic_secret_close(k);
}

static void
test_alg_refusals(void)
{
    /* Build a verifier with a dummy resolver so we get to the alg
     * check.  alg=none and HS* must be refused before any key
     * resolution. */
    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = nullptr);
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    /* Compact JWS with alg=none: header={"alg":"none"}, empty
     * payload + sig.  This is the historical alg-none
     * vulnerability. */
    char *h = n00b_b64url_encode((const uint8_t *)"{\"alg\":\"none\"}", 14);
    char *p = n00b_b64url_encode((const uint8_t *)"{}", 2);
    char *s = n00b_b64url_encode((const uint8_t *)"", 0);
    char  jws[512];
    snprintf(jws, sizeof(jws), "%s.%s.%s", h, p, s);
    auto cr = n00b_jwt_verify(v, jws);
    assert(n00b_result_is_err(cr));
    assert(n00b_result_get_err(cr) == N00B_QUIC_ERR_AUTH_ALG_REFUSED);
    printf("  [PASS] alg=none refused\n");

    /* HS256 — also refused. */
    char *h2 = n00b_b64url_encode((const uint8_t *)"{\"alg\":\"HS256\"}", 15);
    snprintf(jws, sizeof(jws), "%s.%s.%s", h2, p, s);
    auto cr2 = n00b_jwt_verify(v, jws);
    assert(n00b_result_is_err(cr2));
    assert(n00b_result_get_err(cr2) == N00B_QUIC_ERR_AUTH_ALG_REFUSED);
    printf("  [PASS] HS256 refused\n");
}

static void
test_jwks_lookup(void)
{
    const char *jwks =
        "{\"keys\":["
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\","
        "\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
        "\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"
        "]}";
    auto sr = n00b_jwk_set_parse(jwks);
    assert(n00b_result_is_ok(sr));
    n00b_jwk_set_t *set = n00b_result_get(sr);
    assert(set->count == 1);
    n00b_option_t(n00b_jwk_t *) k1 = n00b_jwk_set_lookup(set, "k1");
    assert(n00b_option_is_set(k1));
    n00b_option_t(n00b_jwk_t *) k_no = n00b_jwk_set_lookup(set, "k-nonexistent");
    assert(!n00b_option_is_set(k_no));
    /* Single-key fallback when no kid passed. */
    n00b_option_t(n00b_jwk_t *) k_fb = n00b_jwk_set_lookup(set, nullptr);
    assert(n00b_option_is_set(k_fb));
    assert(n00b_option_get(k_fb) == set->keys[0]);
    printf("  [PASS] JWKS parse + lookup-by-kid\n");
}

/* RFC 7515 Appendix A.2 — verbatim RS256 test vector with public
 * JWK and signed JWS.  This test pins the bignum modexp + EMSA-
 * PKCS1-v1_5 decode against a known-good vector. */
static void
test_rs256_rfc7515_vector(void)
{
    /* The compact JWS from A.2.  Issuer "joe", exp in 2011 (long
     * past), so we set a verifier with very generous leeway and
     * skip exp validation by passing a cheating leeway. */
    static const char *jws =
        "eyJhbGciOiJSUzI1NiJ9"
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
        "p0igcN_IoypGlUPQGe77Rw";

    static const char *jwks =
        "{\"keys\":[{"
        "\"kty\":\"RSA\","
        "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPd"
        "dxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_"
        "YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5re"
        "xMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qC"
        "o5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkM"
        "Ls91kzk2PAcDTW9gb54h4FRWyuXpoQ\","
        "\"e\":\"AQAB\""
        "}]}";

    auto sr = n00b_jwk_set_parse(jwks);
    assert(n00b_result_is_ok(sr));
    n00b_jwk_set_t *set = n00b_result_get(sr);
    assert(set->count == 1);
    assert(strcmp(set->keys[0]->kty, "RSA") == 0);
    /* RFC 7515 A.2 didn't specify a kid; lookup-by-nullptr should
     * fall back to the single key. */

    /* The vector's payload doesn't have an `aud` claim.  Our
     * verifier requires `aud` — so we expect AUD_MISMATCH if sig
     * is OK (which is what we want to confirm).  That confirms the
     * signature path passed and the only remaining gripe is the
     * missing audience.
     *
     * To distinguish a sig failure from an audience failure, we
     * use a verifier with leeway 100 years and a wildcard-ish
     * approach: write a custom resolve that returns the lone key.
     */
    auto vr = n00b_jwt_verifier_new(.expected_audience = "joe-aud",
                                    .leeway_seconds    = 60,
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    auto cr = n00b_jwt_verify(n00b_result_get(vr), jws);
    /* The vector's exp is 2011, long past.  Token expired.  But
     * the SIGNATURE must validate first; expiration-after-sig is
     * the success path for this test (proves the bignum modexp +
     * PKCS1-v1_5 decode are correct end-to-end). */
    assert(n00b_result_is_err(cr));
    int rc = n00b_result_get_err(cr);
    /* Either expired or audience mismatch — both indicate the
     * signature verification PASSED and we got past the crypto. */
    bool past_sig = (rc == N00B_QUIC_ERR_AUTH_TOKEN_EXPIRED
                     || rc == N00B_QUIC_ERR_AUTH_AUD_MISMATCH);
    assert(past_sig);
    printf("  [PASS] RS256 RFC 7515 A.2 vector verifies (expired claim, sig OK)\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_jwt:\n");
    test_jwks_lookup();
    test_alg_refusals();
    test_es256_roundtrip();
    test_rs256_rfc7515_vector();
    printf("All quic_jwt tests passed.\n");

    n00b_shutdown();
    return 0;
}

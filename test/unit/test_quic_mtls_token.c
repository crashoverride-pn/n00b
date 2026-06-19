/*
 * test_quic_mtls_token.c — Phase 3 § 9: RFC 8705 cnf.x5t#S256.
 *
 * Coverage:
 *   1. JWT with cnf.x5t#S256 → claims->has_cnf_x5t_s256 true,
 *      claims->cnf_x5t_s256 = decoded thumbprint.
 *   2. JWT WITHOUT cnf.x5t#S256 → claims->has_cnf_x5t_s256 false.
 *   3. n00b_mtls_token_verify with matching cert → ok.
 *   4. n00b_mtls_token_verify with mismatched cert → AUTH_MTLS_MISMATCH.
 *   5. n00b_mtls_token_verify with absent claim → AUTH_TOKEN_INVALID.
 *
 * Uses the existing test PKI fixture (quic_test_pki.h) for the
 * client cert DER.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "crypto/jwt.h"
#include "crypto/mtls_token.h"
#include "internal/crypto/jws.h"

#include "../fixtures/quic_test_pki.h"

static void
sha256_be(const uint8_t *m, size_t mlen, uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(m, mlen, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        out[i*4]     = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >> 8);
        out[i*4 + 3] = (uint8_t)w;
    }
}

/* Build a JWKS for a single ES256 key. */
static char *
build_jwks(n00b_quic_secret_t *signer, const char *kid)
{
    auto pkr = n00b_quic_secret_pubkey(signer, N00B_QUIC_SIG_ECDSA_P256);
    n00b_buffer_t *pk = n00b_result_get(pkr);
    char *x = n00b_b64url_encode((const uint8_t *)pk->data,      32);
    char *y = n00b_b64url_encode((const uint8_t *)pk->data + 32, 32);
    char *out = malloc(strlen(x) + strlen(y) + strlen(kid) + 256);
    sprintf(out,
            "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"%s\","
            "\"x\":\"%s\",\"y\":\"%s\"}]}",
            kid, x, y);
    return out;
}

/* Mint a compact JWS. */
static char *
mint_jws(n00b_quic_secret_t *signer, const char *hdr, const char *pl)
{
    char *h = n00b_b64url_encode((const uint8_t *)hdr, strlen(hdr));
    char *p = n00b_b64url_encode((const uint8_t *)pl,  strlen(pl));
    size_t ilen = strlen(h) + 1 + strlen(p);
    char  *input = malloc(ilen + 1);
    snprintf(input, ilen + 1, "%s.%s", h, p);
    n00b_buffer_t *msg = n00b_buffer_from_bytes(input, (int64_t)ilen);
    auto sr = n00b_quic_secret_sign(signer, msg, N00B_QUIC_SIG_ECDSA_P256);
    n00b_buffer_t *sig = n00b_result_get(sr);
    char *s = n00b_b64url_encode((const uint8_t *)sig->data,
                                 (size_t)sig->byte_len);
    size_t total = ilen + 1 + strlen(s);
    char  *out   = malloc(total + 1);
    snprintf(out, total + 1, "%s.%s", input, s);
    free(input);
    return out;
}

static n00b_jwk_t *
resolve_via_set(void *ctx, const char *kid, const char *alg)
{
    (void)alg;
    n00b_option_t(n00b_jwk_t *) k = n00b_jwk_set_lookup((n00b_jwk_set_t *)ctx, kid);
    return n00b_option_is_set(k) ? n00b_option_get(k) : nullptr;
}

/* Build a JWT with cnf.x5t#S256 set to the SHA-256 of the test cert. */
static char *
mint_token_with_cnf(n00b_quic_secret_t *k, const uint8_t *cert,
                    size_t cert_len, const char *kid)
{
    uint8_t fp[32];
    sha256_be(cert, cert_len, fp);
    char *fp_b64 = n00b_b64url_encode(fp, 32);

    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[512];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"%s\"}", kid);
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"https://idp.example\",\"aud\":\"svc-mtls\","
             "\"sub\":\"alice\",\"exp\":%lld,"
             "\"cnf\":{\"x5t#S256\":\"%s\"}}",
             (long long)exp, fp_b64);
    return mint_jws(k, hdr, pl);
}

static void
test_claims_extract_cnf(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:mtls-1"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks(k, "mtls-key-1");
    auto sr = n00b_jwk_set_parse(jwks);
    n00b_jwk_set_t *set = n00b_result_get(sr);

    char *jws = mint_token_with_cnf(k, n00b_quic_test_cert_der,
                                    n00b_quic_test_cert_der_len,
                                    "mtls-key-1");

    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc-mtls",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    auto cr = n00b_jwt_verify(n00b_result_get(vr), jws);
    assert(n00b_result_is_ok(cr));
    n00b_jwt_claims_t *claims = n00b_result_get(cr);
    assert(claims->has_cnf_x5t_s256);

    /* Computed thumbprint matches the cert's SHA-256. */
    uint8_t expected[32];
    sha256_be(n00b_quic_test_cert_der,
              n00b_quic_test_cert_der_len, expected);
    assert(memcmp(claims->cnf_x5t_s256, expected, 32) == 0);
    printf("  [PASS] JWT cnf.x5t#S256 surfaced as 32-byte thumbprint\n");

    free(jws); free(jwks);
    n00b_quic_secret_close(k);
}

static void
test_token_without_cnf(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:mtls-2"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks(k, "mtls-key-2");
    n00b_jwk_set_t *set = n00b_result_get(n00b_jwk_set_parse(jwks));

    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[256];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"mtls-key-2\"}");
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"https://idp.example\",\"aud\":\"svc-x\","
             "\"exp\":%lld}",
             (long long)exp);
    char *jws = mint_jws(k, hdr, pl);

    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc-x",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    auto cr = n00b_jwt_verify(n00b_result_get(vr), jws);
    n00b_jwt_claims_t *claims = n00b_result_get(cr);
    assert(claims->has_cnf_x5t_s256 == false);
    printf("  [PASS] JWT without cnf → has_cnf_x5t_s256 == false\n");

    free(jws); free(jwks);
    n00b_quic_secret_close(k);
}

static void
test_verify_match(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:mtls-3"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks(k, "mtls-key-3");
    n00b_jwk_set_t *set = n00b_result_get(n00b_jwk_set_parse(jwks));
    char *jws = mint_token_with_cnf(k, n00b_quic_test_cert_der,
                                    n00b_quic_test_cert_der_len,
                                    "mtls-key-3");
    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc-mtls",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    n00b_jwt_claims_t *claims = n00b_result_get(n00b_jwt_verify(
        n00b_result_get(vr), jws));

    auto mr = n00b_mtls_token_verify(claims, n00b_quic_test_cert_der,
                                     n00b_quic_test_cert_der_len);
    assert(n00b_result_is_ok(mr));
    printf("  [PASS] mtls_token_verify accepts matching client cert\n");

    free(jws); free(jwks);
    n00b_quic_secret_close(k);
}

static void
test_verify_mismatch(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:mtls-4"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks(k, "mtls-key-4");
    n00b_jwk_set_t *set = n00b_result_get(n00b_jwk_set_parse(jwks));
    char *jws = mint_token_with_cnf(k, n00b_quic_test_cert_der,
                                    n00b_quic_test_cert_der_len,
                                    "mtls-key-4");
    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc-mtls",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    n00b_jwt_claims_t *claims = n00b_result_get(n00b_jwt_verify(
        n00b_result_get(vr), jws));

    /* Mismatch: a totally different "cert" (just any byte string). */
    static const uint8_t bogus[] = "not the real cert bytes";
    auto mr = n00b_mtls_token_verify(claims, bogus, sizeof(bogus));
    assert(n00b_result_is_err(mr));
    assert(n00b_result_get_err(mr) == N00B_QUIC_ERR_AUTH_MTLS_MISMATCH);
    printf("  [PASS] mtls_token_verify rejects non-matching cert\n");

    free(jws); free(jwks);
    n00b_quic_secret_close(k);
}

static void
test_verify_absent_claim(void)
{
    /* Token without cnf — verifier must reject with TOKEN_INVALID. */
    n00b_jwt_claims_t empty = {0};
    static const uint8_t bytes[] = "anything";
    auto mr = n00b_mtls_token_verify(&empty, bytes, sizeof(bytes));
    assert(n00b_result_is_err(mr));
    assert(n00b_result_get_err(mr) == N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    printf("  [PASS] mtls_token_verify rejects token without cnf claim\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_mtls_token:\n");
    test_claims_extract_cnf();
    test_token_without_cnf();
    test_verify_match();
    test_verify_mismatch();
    test_verify_absent_claim();
    printf("All quic_mtls_token tests passed.\n");

    n00b_shutdown();
    return 0;
}

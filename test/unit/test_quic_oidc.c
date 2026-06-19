/*
 * test_quic_oidc.c — Phase 3 § 7: OIDC discovery + JWKS cache.
 *
 * Coverage:
 *
 *   1. n00b_oidc_open rejects http:// (must be HTTPS).
 *   2. n00b_oidc_open_with_jwks (synthetic) parses + caches a JWKS.
 *   3. n00b_oidc_get_key finds keys by kid; returns null for unknown.
 *   4. n00b_oidc_jwt_verifier produces a usable verifier wired to
 *      the OIDC handle's get_key.
 *   5. End-to-end: synthetic OIDC + an ES256 JWT minted from the
 *      matching private key → verify succeeds.
 *
 * The live-IdP test (Auth0/Okta/Keycloak) lives in the Phase 3.10
 * fixture suite; this file is offline-only.
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
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/secret.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"
#include "internal/crypto/jws.h"

/* Build a JWKS document containing one ES256 public key under @p kid. */
static char *
build_jwks_for(n00b_quic_secret_t *signer, const char *kid)
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

/* Build a compact JWS by hand (header + payload + signature). */
static char *
mint_jws(n00b_quic_secret_t *signer,
         const char         *header_json,
         const char         *payload_json)
{
    char *h = n00b_b64url_encode((const uint8_t *)header_json,
                                 strlen(header_json));
    char *p = n00b_b64url_encode((const uint8_t *)payload_json,
                                 strlen(payload_json));
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

static void
test_open_rejects_non_https(void)
{
    auto r = n00b_oidc_open("http://insecure.example/idp");
    assert(n00b_result_is_err(r));
    int code = n00b_result_get_err(r);
    assert(code == N00B_QUIC_ERR_INVALID_ARG);
    printf("  [PASS] n00b_oidc_open rejects http:// → INVALID_ARG\n");

    auto r2 = n00b_oidc_open(nullptr);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_QUIC_ERR_NULL_ARG);
    printf("  [PASS] n00b_oidc_open rejects nullptr → NULL_ARG\n");
}

static void
test_synthetic_open_lookup(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:oidc-1"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks_for(k, "oidc-key-1");

    auto or_ = n00b_oidc_open_with_jwks("https://idp.example", jwks);
    assert(n00b_result_is_ok(or_));
    n00b_oidc_t *o = n00b_result_get(or_);

    /* Lookup hits. */
    n00b_jwk_t *found = n00b_oidc_get_key(o, "oidc-key-1");
    assert(found != nullptr);
    assert(strcmp(found->kid, "oidc-key-1") == 0);

    /* Unknown kid: no refresh path (synthetic), so miss returns null. */
    n00b_jwk_t *missing = n00b_oidc_get_key(o, "no-such-kid");
    assert(missing == nullptr);
    printf("  [PASS] synthetic OIDC: get_key by kid (hit + miss)\n");

    n00b_oidc_close(o);
    n00b_quic_secret_close(k);
    free(jwks);
}

static void
test_oidc_verifier_roundtrip(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:oidc-2"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks_for(k, "oidc-key-2");

    auto or_ = n00b_oidc_open_with_jwks("https://idp.example", jwks);
    n00b_oidc_t *o = n00b_result_get(or_);

    /* Build a verifier that targets svc-x at this idp. */
    auto vr = n00b_oidc_jwt_verifier(o, "svc-x");
    assert(n00b_result_is_ok(vr));
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    /* Mint a JWT that should validate. */
    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[256];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"oidc-key-2\"}");
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"https://idp.example\",\"aud\":\"svc-x\","
             "\"sub\":\"bob\",\"exp\":%lld}",
             (long long)exp);
    char *jws = mint_jws(k, hdr, pl);

    auto cr = n00b_jwt_verify(v, jws);
    assert(n00b_result_is_ok(cr));
    n00b_jwt_claims_t *claims = n00b_result_get(cr);
    assert(strcmp(claims->iss, "https://idp.example") == 0);
    assert(strcmp(claims->aud, "svc-x") == 0);
    assert(strcmp(claims->sub, "bob") == 0);
    printf("  [PASS] OIDC-keyed JWT verifier: end-to-end ES256 round-trip\n");

    free(jws); free(jwks);
    n00b_oidc_close(o);
    n00b_quic_secret_close(k);
}

static void
test_oidc_close_idempotent(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:oidc-3"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks_for(k, "oidc-key-3");
    auto or_ = n00b_oidc_open_with_jwks("https://idp.example", jwks);
    n00b_oidc_t *o = n00b_result_get(or_);

    n00b_oidc_close(o);
    n00b_oidc_close(o);  /* double-close must be a no-op */

    /* get_key after close must return null cleanly (no crash). */
    assert(n00b_oidc_get_key(o, "oidc-key-3") == nullptr);
    printf("  [PASS] close is idempotent + post-close get_key safe\n");

    free(jwks);
    n00b_quic_secret_close(k);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_oidc:\n");
    test_open_rejects_non_https();
    test_synthetic_open_lookup();
    test_oidc_verifier_roundtrip();
    test_oidc_close_idempotent();
    printf("All quic_oidc tests passed.\n");

    n00b_shutdown();
    return 0;
}

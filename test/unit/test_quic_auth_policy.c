/*
 * test_quic_auth_policy.c — Phase 3 § 10: per-channel auth policy.
 *
 * Coverage:
 *   1. Empty policy passes any credentials (eval returns ok with
 *      claims=null).
 *   2. require_audience: missing token → TOKEN_MISSING; mismatch
 *      → AUD_MISMATCH; match → ok.
 *   3. require_issuer: mismatch → ISS_MISMATCH; match → ok.
 *   4. require_claim: missing → TOKEN_INVALID; mismatch →
 *      TOKEN_INVALID; match → ok.
 *   5. require_dpop: missing dpop_header → DPOP_FAILED; mismatch →
 *      DPOP_FAILED; valid → ok.
 *   6. require_mtls: thumbprint mismatch → MTLS_MISMATCH; match
 *      → ok.
 *   7. Stacked: aud + iss + claim + dpop + mtls all required, all
 *      satisfied → ok.
 *   8. set_policy / get_policy round-trip on a synthetic chan.
 *
 * The renewal hook is exercised only via "stored, never called"
 * (Phase 4 RPC drives it).
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
#include "net/quic/secret.h"
#include "crypto/jwt.h"
#include "crypto/dpop.h"
#include "net/quic/auth_policy.h"
#include "internal/crypto/jws.h"
#include "internal/net/quic/chan_internal.h"

#include "../fixtures/quic_test_pki.h"

/* ---- Test fixtures ---- */

static n00b_jwk_t *
resolve_via_set(void *ctx, const char *kid, const char *alg)
{
    (void)alg;
    n00b_option_t(n00b_jwk_t *) k = n00b_jwk_set_lookup((n00b_jwk_set_t *)ctx, kid);
    return n00b_option_is_set(k) ? n00b_option_get(k) : nullptr;
}

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

typedef struct {
    n00b_quic_secret_t  *k;
    n00b_jwk_set_t      *set;
    n00b_jwt_verifier_t *v;
    char                *jws;
    char                *jws_with_cnf;
    char                *jws_with_role;
    char                *jws_diff_iss;
} fixtures_t;

static void
build_fixtures(fixtures_t *f, const char *kid, const char *issuer,
               const char *aud)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:apol"));
    f->k = n00b_result_get(kr);
    char *jwks = build_jwks(f->k, kid);
    f->set = n00b_result_get(n00b_jwk_set_parse(jwks));
    free(jwks);

    auto vr = n00b_jwt_verifier_new(.expected_audience = aud,
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = f->set);
    f->v = n00b_result_get(vr);

    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[512];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"%s\"}", kid);

    /* Plain. */
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"%s\",\"aud\":\"%s\",\"sub\":\"alice\",\"exp\":%lld}",
             issuer, aud, (long long)exp);
    f->jws = mint_jws(f->k, hdr, pl);

    /* With cnf x5t#S256 over the test cert. */
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(n00b_quic_test_cert_der,
                         n00b_quic_test_cert_der_len, words);
        uint8_t fp[32];
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            fp[i*4]     = (uint8_t)(w >> 24);
            fp[i*4 + 1] = (uint8_t)(w >> 16);
            fp[i*4 + 2] = (uint8_t)(w >> 8);
            fp[i*4 + 3] = (uint8_t)w;
        }
        char *fp_b64 = n00b_b64url_encode(fp, 32);
        snprintf(pl, sizeof(pl),
                 "{\"iss\":\"%s\",\"aud\":\"%s\",\"sub\":\"alice\","
                 "\"exp\":%lld,\"cnf\":{\"x5t#S256\":\"%s\"}}",
                 issuer, aud, (long long)exp, fp_b64);
        f->jws_with_cnf = mint_jws(f->k, hdr, pl);
    }

    /* With a "role" claim. */
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"%s\",\"aud\":\"%s\",\"sub\":\"alice\","
             "\"exp\":%lld,\"role\":\"admin\"}",
             issuer, aud, (long long)exp);
    f->jws_with_role = mint_jws(f->k, hdr, pl);

    /* Different issuer. */
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"https://other.idp\",\"aud\":\"%s\","
             "\"sub\":\"alice\",\"exp\":%lld}",
             aud, (long long)exp);
    f->jws_diff_iss = mint_jws(f->k, hdr, pl);
}

/* ---- Tests ---- */

static void
test_empty_policy_passes(void)
{
    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_credentials_t creds = {0};
    auto r = n00b_quic_auth_policy_eval(p, &creds);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == nullptr);
    n00b_quic_auth_policy_close(p);
    printf("  [PASS] empty policy → ok with claims=null\n");
}

static void
test_require_audience(void)
{
    fixtures_t f;
    build_fixtures(&f, "k1", "https://idp.example", "svc-a");

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "svc-a");

    /* No token → TOKEN_MISSING. */
    n00b_quic_auth_credentials_t no_tok = {.jwt_verifier = f.v};
    auto r1 = n00b_quic_auth_policy_eval(p, &no_tok);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_QUIC_ERR_AUTH_TOKEN_MISSING);

    /* Match. */
    n00b_quic_auth_credentials_t ok = {.bearer_token = f.jws,
                                       .jwt_verifier = f.v};
    auto r2 = n00b_quic_auth_policy_eval(p, &ok);
    assert(n00b_result_is_ok(r2));

    /* Mismatch: build a fresh verifier expecting a different aud,
     * because the policy aud-check runs against the claims that
     * jwt_verify already validated.  If verifier-aud doesn't match
     * the token's aud, jwt_verify itself fails first.  We simulate
     * "policy expects different aud" by calling eval with policy
     * audience set differently. */
    n00b_quic_auth_policy_t *p2 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p2, "different-aud");
    auto r3 = n00b_quic_auth_policy_eval(p2, &ok);
    assert(n00b_result_is_err(r3));
    /* Either jwt_verifier rejected at AUD_MISMATCH (its own check)
     * or our explicit check did.  Both produce AUD_MISMATCH. */
    assert(n00b_result_get_err(r3) == N00B_QUIC_ERR_AUTH_AUD_MISMATCH);
    n00b_quic_auth_policy_close(p2);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] require_audience: missing → MISSING; match; mismatch → AUD_MISMATCH\n");
}

static void
test_require_issuer(void)
{
    fixtures_t f;
    build_fixtures(&f, "k2", "https://idp.example", "svc-b");

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_issuer(p, "https://idp.example");
    n00b_quic_auth_credentials_t ok = {.bearer_token = f.jws,
                                       .jwt_verifier = f.v};
    auto r1 = n00b_quic_auth_policy_eval(p, &ok);
    assert(n00b_result_is_ok(r1));

    /* Mismatch. */
    n00b_quic_auth_policy_t *p2 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_issuer(p2, "https://other.idp");
    auto r2 = n00b_quic_auth_policy_eval(p2, &ok);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_QUIC_ERR_AUTH_ISS_MISMATCH);
    n00b_quic_auth_policy_close(p2);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] require_issuer: match + mismatch\n");
}

static void
test_require_claim(void)
{
    fixtures_t f;
    build_fixtures(&f, "k3", "https://idp.example", "svc-c");

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_claim(p, "role", "admin");

    /* Missing claim (jws has no role). */
    n00b_quic_auth_credentials_t no_role = {.bearer_token = f.jws,
                                            .jwt_verifier = f.v};
    auto r1 = n00b_quic_auth_policy_eval(p, &no_role);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_QUIC_ERR_AUTH_TOKEN_INVALID);

    /* Has role=admin. */
    n00b_quic_auth_credentials_t with_role = {.bearer_token = f.jws_with_role,
                                              .jwt_verifier = f.v};
    auto r2 = n00b_quic_auth_policy_eval(p, &with_role);
    assert(n00b_result_is_ok(r2));

    /* Mismatch role. */
    n00b_quic_auth_policy_t *p2 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_claim(p2, "role", "user");
    auto r3 = n00b_quic_auth_policy_eval(p2, &with_role);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    n00b_quic_auth_policy_close(p2);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] require_claim: missing / match / mismatch\n");
}

static void
test_require_claim_contains(void)
{
    /* Build a token with `scope: "rpc:read rpc:write"`. */
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:apc"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks(k, "kc");
    n00b_jwk_set_t *set = n00b_result_get(n00b_jwk_set_parse(jwks));
    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[256];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"kc\"}");
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"i\",\"aud\":\"svc\",\"sub\":\"s\","
             "\"exp\":%lld,\"scope\":\"rpc:read rpc:write\"}",
             (long long)exp);
    char *jws = mint_jws(k, hdr, pl);

    /* Policy: require scope contains "rpc:write" → ok. */
    n00b_quic_auth_policy_t *p1 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_claim_contains(p1, "scope", "rpc:write");
    n00b_quic_auth_credentials_t creds = {.bearer_token = jws,
                                          .jwt_verifier = v};
    auto r1 = n00b_quic_auth_policy_eval(p1, &creds);
    assert(n00b_result_is_ok(r1));

    /* Policy: require scope contains "rpc:admin" → fail. */
    n00b_quic_auth_policy_t *p2 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_claim_contains(p2, "scope", "rpc:admin");
    auto r2 = n00b_quic_auth_policy_eval(p2, &creds);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_QUIC_ERR_AUTH_TOKEN_INVALID);

    /* Boundary: prefix-but-not-token must NOT match.  Token "rpc:read"
     * contains "rpc:re" as a substring but NOT as a complete token,
     * so contains_token must reject. */
    n00b_quic_auth_policy_t *p3 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_claim_contains(p3, "scope", "rpc:re");
    auto r3 = n00b_quic_auth_policy_eval(p3, &creds);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_QUIC_ERR_AUTH_TOKEN_INVALID);

    n00b_quic_auth_policy_close(p1);
    n00b_quic_auth_policy_close(p2);
    n00b_quic_auth_policy_close(p3);
    free(jws); free(jwks);
    n00b_quic_secret_close(k);
    printf("  [PASS] require_claim_contains: scope membership (token-aware)\n");
}

static void
test_require_dpop(void)
{
    fixtures_t f;
    build_fixtures(&f, "k4", "https://idp.example", "svc-d");

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_dpop(p);

    /* Missing dpop_header. */
    n00b_quic_auth_credentials_t no_dpop = {.bearer_token = f.jws,
                                            .jwt_verifier = f.v};
    auto r1 = n00b_quic_auth_policy_eval(p, &no_dpop);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_QUIC_ERR_AUTH_DPOP_FAILED);

    /* With a valid DPoP. */
    auto pr = n00b_dpop_create(f.k, "POST", "https://api/x");
    char *proof = n00b_result_get(pr);
    n00b_quic_auth_credentials_t with_dpop = {
        .bearer_token = f.jws,
        .jwt_verifier = f.v,
        .dpop_header  = proof,
        .htm          = "POST",
        .htu          = "https://api/x",
    };
    auto r2 = n00b_quic_auth_policy_eval(p, &with_dpop);
    assert(n00b_result_is_ok(r2));

    /* Wrong htu. */
    n00b_quic_auth_credentials_t bad_dpop = with_dpop;
    bad_dpop.htu = "https://api/y";
    auto r3 = n00b_quic_auth_policy_eval(p, &bad_dpop);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_QUIC_ERR_AUTH_DPOP_FAILED);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] require_dpop: missing / valid / wrong-htu\n");
}

static void
test_require_mtls(void)
{
    fixtures_t f;
    build_fixtures(&f, "k5", "https://idp.example", "svc-e");

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_mtls(p);

    /* Token doesn't carry cnf → mismatch. */
    n00b_quic_auth_credentials_t no_cnf = {
        .bearer_token  = f.jws,
        .jwt_verifier  = f.v,
        .peer_cert_der = n00b_quic_test_cert_der,
        .peer_cert_len = n00b_quic_test_cert_der_len,
    };
    auto r1 = n00b_quic_auth_policy_eval(p, &no_cnf);
    assert(n00b_result_is_err(r1));
    /* mtls_token_verify returns AUTH_TOKEN_INVALID for absent cnf;
     * the policy translates that one-for-one. */

    /* Token with cnf + matching cert. */
    n00b_quic_auth_credentials_t ok = {
        .bearer_token  = f.jws_with_cnf,
        .jwt_verifier  = f.v,
        .peer_cert_der = n00b_quic_test_cert_der,
        .peer_cert_len = n00b_quic_test_cert_der_len,
    };
    auto r2 = n00b_quic_auth_policy_eval(p, &ok);
    assert(n00b_result_is_ok(r2));

    /* Token with cnf + wrong cert. */
    static const uint8_t bogus[] = "definitely not the cert";
    n00b_quic_auth_credentials_t bad = ok;
    bad.peer_cert_der = bogus;
    bad.peer_cert_len = sizeof(bogus);
    auto r3 = n00b_quic_auth_policy_eval(p, &bad);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_QUIC_ERR_AUTH_MTLS_MISMATCH);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] require_mtls: cnf absent / match / mismatch\n");
}

static void
test_stacked_policy(void)
{
    fixtures_t f;
    build_fixtures(&f, "k6", "https://idp.example", "svc-f");

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "svc-f");
    n00b_quic_auth_policy_require_issuer(p, "https://idp.example");
    n00b_quic_auth_policy_require_dpop(p);
    n00b_quic_auth_policy_require_mtls(p);

    auto pr = n00b_dpop_create(f.k, "POST", "https://api/stacked");
    char *proof = n00b_result_get(pr);

    n00b_quic_auth_credentials_t creds = {
        .bearer_token  = f.jws_with_cnf,
        .jwt_verifier  = f.v,
        .dpop_header   = proof,
        .htm           = "POST",
        .htu           = "https://api/stacked",
        .peer_cert_der = n00b_quic_test_cert_der,
        .peer_cert_len = n00b_quic_test_cert_der_len,
    };
    auto r = n00b_quic_auth_policy_eval(p, &creds);
    assert(n00b_result_is_ok(r));
    n00b_jwt_claims_t *claims = n00b_result_get(r);
    assert(claims);
    assert(strcmp(claims->iss, "https://idp.example") == 0);
    assert(strcmp(claims->sub, "alice") == 0);
    assert(claims->has_cnf_x5t_s256);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] stacked: aud + iss + dpop + mtls all required → ok\n");
}

static void
test_chan_set_get_policy(void)
{
    /* Build a synthetic channel just enough to exercise set/get. */
    struct n00b_quic_chan c = {0};
    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "x");

    assert(n00b_quic_chan_get_policy(&c) == nullptr);
    n00b_quic_chan_set_policy(&c, p);
    assert(n00b_quic_chan_get_policy(&c) == p);
    n00b_quic_chan_set_policy(&c, nullptr);
    assert(n00b_quic_chan_get_policy(&c) == nullptr);

    n00b_quic_auth_policy_close(p);
    printf("  [PASS] chan_set_policy / chan_get_policy round-trip\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_auth_policy:\n");
    test_empty_policy_passes();
    test_require_audience();
    test_require_issuer();
    test_require_claim();
    test_require_claim_contains();
    test_require_dpop();
    test_require_mtls();
    test_stacked_policy();
    test_chan_set_get_policy();
    printf("All quic_auth_policy tests passed.\n");

    n00b_shutdown();
    return 0;
}

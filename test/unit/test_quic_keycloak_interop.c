/*
 * test_quic_keycloak_interop.c — Phase 3.10 manual interop test.
 *
 * Gated by `KEYCLOAK_ISSUER` (and friends) env vars.  Skipped
 * unless those are set — start the fixture via:
 *
 *   eval "$(bash test/fixtures/keycloak/start.sh)"
 *
 * What this exercises:
 *   1. n00b_oidc_open against a live Keycloak realm — discovers
 *      /.well-known/openid-configuration → JWKS.
 *   2. Mints an access token via the password-grant (curl).
 *      We don't ship password-grant in libn00b; this test reaches
 *      into the IdP via libcurl style HTTP fetched through our
 *      acme_http shim.
 *   3. Verifies the token via the OIDC handle + auth_policy_eval.
 *
 * Why not in CI: real Keycloak takes ~30-60s to come up and
 * needs Docker.  Per Phase 2's LE-staging precedent, real-IdP
 * interop is once-per-release manual.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "net/quic/jwt.h"
#include "net/quic/oidc.h"
#include "net/quic/auth_policy.h"
#include "net/http/http_client.h"

/* Fetch an access token from Keycloak via password-grant.  Returns
 * the bearer token string (heap; caller frees) or nullptr on
 * failure. */
static char *
fetch_token(const char *base_url, const char *realm,
            const char *client_id, const char *client_pw,
            const char *user, const char *user_pw)
{
    char url[1024];
    snprintf(url, sizeof(url),
             "%s/realms/%s/protocol/openid-connect/token",
             base_url, realm);
    char body[2048];
    snprintf(body, sizeof(body),
             "grant_type=password&client_id=%s&client_secret=%s"
             "&username=%s&password=%s",
             client_id, client_pw, user, user_pw);

    n00b_buffer_t *body_buf = n00b_buffer_from_bytes(body, (int64_t)strlen(body));
    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(url),
        .method       = n00b_string_from_cstr("POST"),
        .body         = body_buf,
        .content_type = n00b_string_from_cstr("application/x-www-form-urlencoded"),
        .prefer_h3    = false);
    if (!n00b_result_is_ok(r)) return nullptr;
    n00b_http_response_t *resp = n00b_result_get(r);
    int status = n00b_http_response_status(resp);
    if (status < 200 || status >= 300) return nullptr;
    n00b_buffer_t *rbody = n00b_http_response_body(resp);
    if (!rbody || rbody->byte_len == 0) return nullptr;

    /* Parse the JSON response and extract `access_token`. */
    const char *err = nullptr;
    n00b_json_node_t *root = n00b_json_parse(rbody->data,
                                             (size_t)rbody->byte_len,
                                             &err);
    if (!root || !n00b_json_is_object(root)) return nullptr;
    n00b_json_node_t *node = n00b_json_object_get_cstr(root, "access_token");
    const char       *tok  = n00b_json_as_cstr(node);
    return tok == nullptr ? nullptr : strdup(tok);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *issuer    = getenv("KEYCLOAK_ISSUER");
    const char *base_url  = getenv("KEYCLOAK_BASE_URL");
    const char *realm     = getenv("KEYCLOAK_REALM");
    const char *client    = getenv("KEYCLOAK_CLIENT_ID");
    const char *client_pw = getenv("KEYCLOAK_CLIENT_PW");
    const char *user      = getenv("KEYCLOAK_USER");
    const char *user_pw   = getenv("KEYCLOAK_USER_PW");

    if (!issuer || !base_url || !realm || !client || !client_pw
        || !user || !user_pw) {
        printf("[SKIP] Keycloak fixture env not set; "
               "run `eval \"$(bash test/fixtures/keycloak/start.sh)\"` first.\n");
        n00b_shutdown();
        return 0;
    }

    printf("test_quic_keycloak_interop (issuer=%s):\n", issuer);

    /* 1. Discover the IdP via OIDC. */
    auto or_ = n00b_oidc_open(issuer);
    assert(n00b_result_is_ok(or_));
    n00b_oidc_t *oidc = n00b_result_get(or_);
    printf("  [PASS] n00b_oidc_open discovered %s\n", issuer);

    /* 2. Fetch a real access token. */
    char *token = fetch_token(base_url, realm, client, client_pw,
                              user, user_pw);
    assert(token);
    printf("  [PASS] fetched access token (%zu bytes)\n", strlen(token));

    /* 3. Verify with a policy.  Keycloak's default audience is
     *    `account` for tokens minted via direct-access-grant; we
     *    don't customize the realm here. */
    auto vr = n00b_oidc_jwt_verifier(oidc, "account");
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "account");

    n00b_quic_auth_credentials_t creds = {.bearer_token = token,
                                          .jwt_verifier = v};
    auto r = n00b_quic_auth_policy_eval(p, &creds);
    if (!n00b_result_is_ok(r)) {
        fprintf(stderr, "policy_eval err=%d\n", n00b_result_get_err(r));
        assert(0);
    }
    n00b_jwt_claims_t *claims = n00b_result_get(r);
    assert(claims);
    /* Keycloak realm-issued tokens carry sub = the user id.  We
     * don't pin the exact value (it's generated). */
    assert(claims->sub && *claims->sub);
    printf("  [PASS] live Keycloak token verifies; sub=%s\n", claims->sub);

    n00b_quic_auth_policy_close(p);
    n00b_oidc_close(oidc);
    free(token);

    printf("All quic_keycloak_interop tests passed.\n");

    n00b_shutdown();
    return 0;
}

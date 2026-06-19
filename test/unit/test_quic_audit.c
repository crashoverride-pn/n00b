/*
 * test_quic_audit.c — Phase 3 § 10.2 + § 12: audit event fan-out
 * + JSONL sink + integration with auth_policy_eval.
 *
 * Coverage:
 *   1. Subscribe a counter; emit N events; verify count + last
 *      event payload.
 *   2. Unsubscribe stops further deliveries.
 *   3. event_to_json renders the expected fields.
 *   4. JSONL sink: open(path), emit events, close, then read the
 *      file back; verify line count + per-line JSON shape.
 *   5. auth_policy_eval emits ALLOW on success.
 *   6. auth_policy_eval emits DENY on failure with the right
 *      reason_code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "crypto/jwt.h"
#include "net/quic/auth_policy.h"
#include "net/quic/audit.h"
#include "internal/crypto/jws.h"

/* ---- Test helpers ---- */

typedef struct {
    int                        n_events;
    n00b_quic_audit_decision_t last_decision;
    n00b_quic_err_t            last_reason;
    char                       last_iss[256];
    char                       last_aud[256];
} sub_counter_t;

static void
counter_sub(const n00b_quic_audit_event_t *evt, void *ctx)
{
    sub_counter_t *c = ctx;
    c->n_events++;
    c->last_decision = evt->decision;
    c->last_reason   = evt->reason_code;
    if (evt->iss) snprintf(c->last_iss, sizeof(c->last_iss), "%s", evt->iss);
    else          c->last_iss[0] = '\0';
    if (evt->aud) snprintf(c->last_aud, sizeof(c->last_aud), "%s", evt->aud);
    else          c->last_aud[0] = '\0';
}

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

/* ---- Tests ---- */

static void
test_subscribe_and_emit(void)
{
    sub_counter_t counter = {0};
    int sub = n00b_quic_audit_subscribe(counter_sub, &counter);
    assert(sub > 0);

    n00b_quic_audit_event_t evt = {
        .timestamp_ms = 1234,
        .decision     = N00B_QUIC_AUDIT_ALLOW,
        .reason_code  = N00B_QUIC_OK,
        .iss          = "https://idp",
        .aud          = "svc",
    };
    n00b_quic_audit_emit(&evt);
    n00b_quic_audit_emit(&evt);
    assert(counter.n_events == 2);
    assert(counter.last_decision == N00B_QUIC_AUDIT_ALLOW);
    assert(strcmp(counter.last_iss, "https://idp") == 0);

    n00b_quic_audit_unsubscribe(sub);
    n00b_quic_audit_emit(&evt);
    assert(counter.n_events == 2);  /* no further deliveries */
    printf("  [PASS] subscribe / emit / unsubscribe\n");
}

static void
test_event_to_json(void)
{
    n00b_quic_audit_event_t evt = {
        .timestamp_ms = 9999,
        .decision     = N00B_QUIC_AUDIT_DENY,
        .reason_code  = N00B_QUIC_ERR_AUTH_AUD_MISMATCH,
        .iss          = "https://idp.example",
        .aud          = "wrong-svc",
        .htu          = "https://api/x",
    };
    char *json = n00b_quic_audit_event_to_json(&evt);
    assert(json);
    assert(strstr(json, "\"decision\":\"deny\"") != nullptr);
    assert(strstr(json, "\"reason\":\"audience claim mismatch\"") != nullptr);
    assert(strstr(json, "\"iss\":\"https://idp.example\"") != nullptr);
    assert(strstr(json, "\"aud\":\"wrong-svc\"") != nullptr);
    assert(strstr(json, "\"htu\":\"https://api/x\"") != nullptr);
    assert(strstr(json, "\"htm\":") == nullptr);  /* not set */
    printf("  [PASS] event_to_json shape\n");
}

static void
test_jsonl_sink(void)
{
    char path[] = "/tmp/n00b_audit_test_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);

    auto sr = n00b_quic_audit_jsonl_sink_open(path);
    assert(n00b_result_is_ok(sr));
    n00b_quic_audit_jsonl_sink_t *sink = n00b_result_get(sr);

    n00b_quic_audit_event_t evt = {
        .timestamp_ms = 1,
        .decision     = N00B_QUIC_AUDIT_ALLOW,
        .reason_code  = N00B_QUIC_OK,
        .sub          = "alice",
    };
    n00b_quic_audit_emit(&evt);
    evt.timestamp_ms = 2;
    evt.decision     = N00B_QUIC_AUDIT_DENY;
    evt.reason_code  = N00B_QUIC_ERR_AUTH_TOKEN_EXPIRED;
    n00b_quic_audit_emit(&evt);

    n00b_quic_audit_jsonl_sink_close(sink);

    /* Read the file back and check line count. */
    FILE *fp = fopen(path, "r");
    assert(fp);
    char line[2048];
    int  n_lines = 0;
    bool saw_allow = false, saw_deny = false;
    while (fgets(line, sizeof(line), fp)) {
        n_lines++;
        if (strstr(line, "\"decision\":\"allow\"")) saw_allow = true;
        if (strstr(line, "\"decision\":\"deny\""))  saw_deny  = true;
    }
    fclose(fp);
    assert(n_lines == 2);
    assert(saw_allow && saw_deny);
    unlink(path);
    printf("  [PASS] JSONL sink: 2 events, both lines present\n");
}

static void
test_auth_policy_emits(void)
{
    /* Build a simple policy + a JWT round-trip; eval an allow and
     * a deny.  Counter should record both. */
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:audit"));
    n00b_quic_secret_t *k = n00b_result_get(kr);
    char *jwks = build_jwks(k, "audit-key");
    n00b_jwk_set_t *set = n00b_result_get(n00b_jwk_set_parse(jwks));
    auto vr = n00b_jwt_verifier_new(.expected_audience = "svc",
                                    .resolve_key       = resolve_via_set,
                                    .resolve_key_ctx   = set);
    n00b_jwt_verifier_t *v = n00b_result_get(vr);

    int64_t exp = n00b_us_timestamp() / N00B_USEC_PER_SEC + 3600;
    char hdr[128], pl[256];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"audit-key\"}");
    snprintf(pl, sizeof(pl),
             "{\"iss\":\"i\",\"aud\":\"svc\",\"sub\":\"alice\",\"exp\":%lld}",
             (long long)exp);
    char *jws = mint_jws(k, hdr, pl);

    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p, "svc");

    sub_counter_t counter = {0};
    int sub = n00b_quic_audit_subscribe(counter_sub, &counter);

    n00b_quic_auth_credentials_t ok = {.bearer_token = jws,
                                       .jwt_verifier = v};
    auto r1 = n00b_quic_auth_policy_eval(p, &ok);
    assert(n00b_result_is_ok(r1));
    assert(counter.n_events == 1);
    assert(counter.last_decision == N00B_QUIC_AUDIT_ALLOW);
    assert(counter.last_reason == N00B_QUIC_OK);
    assert(strcmp(counter.last_aud, "svc") == 0);

    /* Mismatch: build a policy with a different aud → DENY. */
    n00b_quic_auth_policy_t *p2 = n00b_quic_auth_policy_new();
    n00b_quic_auth_policy_require_audience(p2, "different-svc");
    auto r2 = n00b_quic_auth_policy_eval(p2, &ok);
    assert(n00b_result_is_err(r2));
    assert(counter.n_events == 2);
    assert(counter.last_decision == N00B_QUIC_AUDIT_DENY);
    assert(counter.last_reason == N00B_QUIC_ERR_AUTH_AUD_MISMATCH);

    n00b_quic_audit_unsubscribe(sub);
    n00b_quic_auth_policy_close(p);
    n00b_quic_auth_policy_close(p2);
    free(jws); free(jwks);
    n00b_quic_secret_close(k);
    printf("  [PASS] auth_policy_eval emits allow/deny events\n");
}

static void
test_no_event_for_empty_policy(void)
{
    /* An empty (null) policy is a no-op; eval skips audit. */
    sub_counter_t counter = {0};
    int sub = n00b_quic_audit_subscribe(counter_sub, &counter);

    n00b_quic_auth_credentials_t empty = {0};
    auto r = n00b_quic_auth_policy_eval(nullptr, &empty);
    assert(n00b_result_is_ok(r));
    assert(counter.n_events == 0);

    n00b_quic_audit_unsubscribe(sub);
    printf("  [PASS] empty policy → no audit event\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_audit:\n");
    test_subscribe_and_emit();
    test_event_to_json();
    test_jsonl_sink();
    test_auth_policy_emits();
    test_no_event_for_empty_policy();
    printf("All quic_audit tests passed.\n");

    n00b_shutdown();
    return 0;
}

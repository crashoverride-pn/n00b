/*
 * test_quic_acme_orchestrator.c — Smoke test for the
 * `n00b_acme_acquire_certificate` high-level entry point.
 *
 * Coverage scope: argument validation + a sanity-check that the
 * orchestrator dispatches into the protocol layer when called with
 * a syntactically valid set of arguments.  **End-to-end cert
 * acquisition** (real ACME server, real HTTP-01 validation) is
 * deferred to the Phase 2 deployment playbook because HTTP-01
 * validation requires the test process to bind port 80, which is
 * privileged and hostile to CI.  See `~/dd/quic_2_progress.md`.
 *
 * The mock provider records call sequences without actually
 * provisioning anything; if used against a real ACME server the
 * server would time out validating, which is *expected* and what
 * the deferred playbook tests will exercise properly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "internal/net/http/http_url.h"
#include "crypto/secret.h"
#include "internal/crypto/acme.h"

/* ============================================================================
 * Mock challenge provider — records calls; returns OK from provision /
 * deprovision so the orchestrator advances.
 * ============================================================================ */

typedef struct {
    int  provision_calls;
    int  deprovision_calls;
    char last_identifier[256];
    char last_key_authz[256];
} mock_state_t;

static int
mock_provision(n00b_acme_challenge_provider_t *self,
               const n00b_acme_challenge_t    *ch,
               const char                     *identifier,
               const char                     *key_authz)
{
    (void)ch;
    mock_state_t *st = self->ctx;
    st->provision_calls++;
    snprintf(st->last_identifier, sizeof(st->last_identifier),
             "%s", identifier ? identifier : "");
    snprintf(st->last_key_authz, sizeof(st->last_key_authz),
             "%s", key_authz ? key_authz : "");
    return N00B_QUIC_OK;
}

static int
mock_deprovision(n00b_acme_challenge_provider_t *self,
                 const n00b_acme_challenge_t    *ch,
                 const char                     *identifier)
{
    (void)ch;
    (void)identifier;
    mock_state_t *st = self->ctx;
    st->deprovision_calls++;
    return N00B_QUIC_OK;
}

/* ============================================================================
 * Argument-validation tests (no network).
 * ============================================================================ */

static void
test_null_args(void)
{
    mock_state_t mock_ctx = {0};
    n00b_acme_challenge_provider_t mock = {
        .type        = "http-01",
        .provision   = mock_provision,
        .deprovision = mock_deprovision,
        .ctx         = &mock_ctx,
    };

    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:k"));
    n00b_quic_secret_t *k = n00b_result_get(kr);

    const char *names[] = {"x.example"};

    /* NULL directory URL. */
    {
        auto r = n00b_acme_acquire_certificate(NULL, k, k, names, 1, &mock);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);
    }
    /* NULL account_key. */
    {
        auto r = n00b_acme_acquire_certificate("https://x/dir", NULL, k,
                                               names, 1, &mock);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);
    }
    /* NULL cert_key. */
    {
        auto r = n00b_acme_acquire_certificate("https://x/dir", k, NULL,
                                               names, 1, &mock);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);
    }
    /* Zero names. */
    {
        auto r = n00b_acme_acquire_certificate("https://x/dir", k, k,
                                               names, 0, &mock);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);
    }
    /* NULL provider. */
    {
        auto r = n00b_acme_acquire_certificate("https://x/dir", k, k,
                                               names, 1, NULL);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);
    }
    /* Provider missing required hooks. */
    {
        n00b_acme_challenge_provider_t bad = {.type = "http-01"};
        auto r = n00b_acme_acquire_certificate("https://x/dir", k, k,
                                               names, 1, &bad);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);
    }
    /* No provision/deprovision calls happened — argument errors hit
     * before any IO. */
    assert(mock_ctx.provision_calls == 0);
    assert(mock_ctx.deprovision_calls == 0);

    n00b_quic_secret_close(k);
    printf("  [PASS] argument validation (NULL / zero-length / partial provider)\n");
}

/* ============================================================================
 * Bogus directory URL test.  The orchestrator should call into
 * acme_session_open which fails fast on a syntactically invalid URL.
 * ============================================================================ */

static void
test_bogus_directory(void)
{
    mock_state_t mock_ctx = {0};
    n00b_acme_challenge_provider_t mock = {
        .type        = "http-01",
        .provision   = mock_provision,
        .deprovision = mock_deprovision,
        .ctx         = &mock_ctx,
    };
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:k2"));
    n00b_quic_secret_t *k = n00b_result_get(kr);

    const char *names[] = {"x.example"};
    /* "ftp://" → the public HTTP dispatcher rejects with
     * N00B_HTTP_ERR_UNSUPPORTED_SCHEME (post Phase-6 chunk 11 cut-over;
     * the old acme_http path returned N00B_QUIC_ERR_INVALID_ARG).
     * Either negative code is acceptable. */
    auto r = n00b_acme_acquire_certificate("ftp://nope/", k, k,
                                           names, 1, &mock);
    assert(n00b_result_is_err(r));
    int err = (int)n00b_result_get_err(r);
    assert(err == N00B_HTTP_ERR_UNSUPPORTED_SCHEME
           || err == N00B_QUIC_ERR_INVALID_ARG);
    assert(mock_ctx.provision_calls == 0);

    n00b_quic_secret_close(k);
    printf("  [PASS] bogus directory URL → INVALID_ARG (provider untouched)\n");
}

/* ============================================================================ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_acme_orchestrator:\n");
    test_null_args();
    test_bogus_directory();
    printf("All quic_acme_orchestrator tests passed.\n");
    printf("(Live cert acquisition E2E deferred to Phase 2 deployment "
           "playbook — HTTP-01 validation needs port 80.)\n");

    n00b_shutdown();
    return 0;
}

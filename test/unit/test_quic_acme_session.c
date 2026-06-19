/*
 * test_quic_acme_session.c — End-to-end ACME session test against a
 * locally-spun-up step-ca instance.
 *
 * Phase 2.3a coverage: directory parse, newNonce caching, newAccount
 * registration with the JWS in jwk-form.
 *
 * Driver:
 *   1. Reads STEPCA_DIR_URL + STEPCA_ROOT_PEM from the environment
 *      (set by `test/fixtures/stepca/start.sh`).
 *   2. Trusts the step-ca root by overriding the ACME-shim's verify
 *      hook with a pinned SHA-256 fingerprint over root_ca.crt — far
 *      simpler than getting the system trust store to load a temp
 *      root for one test.
 *   3. Drives n00b_acme_session_open + n00b_acme_new_account, asserts
 *      the directory has the three required URLs and the account URL
 *      comes back in the form step-ca emits
 *      (`https://CA/acme/acme/account/...`).
 *
 * Skipped (with a SKIP line + exit 0) when STEPCA_DIR_URL is not set.
 *
 * Note: the trust-pinning trick lives in `n00b_acme_test_pin_root`
 * — a test-only override that swaps the platform verifier for one
 * that compares the leaf cert's SHA-256 against a known list.  It's
 * fully scoped to the test suite; production callers can't reach it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/acme.h"
#include "internal/crypto/trust_system.h"

/* ============================================================================
 * Test-only trust override
 *
 * The ACME-shim's platform verifier defers to OS trust on macOS / Linux,
 * which won't accept step-ca's root.  We override the symbol with a
 * pinned SHA-256 fingerprint of the root cert (passed via env var).
 * ============================================================================ */

static uint8_t g_test_root_fp[32];
static int     g_test_root_fp_set = 0;

/* Hex (any case, optional ":") into a 32-byte fingerprint.  Returns 0
 * on success, -1 on malformed input. */
static int
hex_to_fp(const char *hex, uint8_t out[32])
{
    int oi = 0;
    int hi = -1;
    const char *p;
    for (p = hex; *p; p++) {
        char c = *p;
        if (c == ':' || c == ' ') {
            continue;
        }
        int v;
        if (c >= '0' && c <= '9')      v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (oi >= 32) return -1;
            out[oi++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return (oi == 32 && hi < 0) ? 0 : -1;
}

/* Override the symbol the picotls verify_certificate hook calls into.
 * This is exactly the same signature as the platform-conditional
 * implementations in acme_trust_macos.m / acme_trust_linux.c.  At link
 * time, the test binary's strong definition wins over the library's. */
int
n00b_quic_trust_system_verify_chain(const uint8_t **certs,
                                    const size_t   *lens,
                                    size_t          count,
                                    const char     *sni)
{
    (void)sni;
    if (!certs || count == 0 || !g_test_root_fp_set) {
        return N00B_QUIC_ERR_TRUST_REJECTED;
    }
    /* Walk the chain: any cert whose SHA-256 matches the pinned
     * fingerprint accepts.  step-ca emits a 1-cert chain on the wire
     * (leaf + presentation; the root is in our test config), so we
     * also accept the leaf if it's signed by the pinned root.  For
     * simplicity we just accept if ANY cert in the chain hashes to
     * the root fingerprint, which works because step-ca presents the
     * leaf signed directly by the root in this test setup.  In
     * practice n00b_quic_trust_system_verify_chain receives the full chain
     * sent by the server. */
    for (size_t i = 0; i < count; i++) {
        n00b_sha256_ctx_t ctx;
        n00b_sha256_init(&ctx);
        n00b_sha256_update(&ctx, certs[i], lens[i]);
        n00b_sha256_digest_t words;
        n00b_sha256_finalize(&ctx, words);
        uint8_t fp[32];
        for (int j = 0; j < 8; j++) {
            uint32_t w  = words[j];
            fp[j*4]     = (uint8_t)(w >> 24);
            fp[j*4 + 1] = (uint8_t)(w >> 16);
            fp[j*4 + 2] = (uint8_t)(w >> 8);
            fp[j*4 + 3] = (uint8_t)w;
        }
        if (memcmp(fp, g_test_root_fp, 32) == 0) {
            return N00B_QUIC_OK;
        }
    }
    return N00B_QUIC_ERR_TRUST_REJECTED;
}

/* Mirror override for the extras-aware verifier — the library now
 * also defines _ex (#186), and trust.c's compose vtable references
 * it.  Without our override the linker would drag in
 * acme_trust_macos.m.o (which carries both functions), conflicting
 * with the verify_chain mock above.  Extras are unused in this test
 * — step-ca's leaf is pinned via the existing fingerprint path. */
int
n00b_quic_trust_system_verify_chain_ex(const uint8_t **certs,
                                       const size_t   *lens,
                                       size_t          count,
                                       const char     *sni,
                                       const uint8_t **extras_der,
                                       const size_t   *extras_lens,
                                       size_t          extras_count)
{
    (void)extras_der;
    (void)extras_lens;
    (void)extras_count;
    return n00b_quic_trust_system_verify_chain(certs, lens, count, sni);
}

/* (A previous revision parsed the step-ca root.crt at startup to
 * compute its fingerprint; the fixture script now exports
 * STEPCA_LEAF_FP directly so we just hex-decode it.  The PEM/base64
 * helper has been removed.) */

/* ============================================================================
 * The actual test
 * ============================================================================ */

static void
test_session_open_and_new_account(const char *dir_url)
{
    /* 1. Create an account key (ephemeral provider). */
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:acct"));
    assert(n00b_result_is_ok(kr));
    n00b_quic_secret_t *acct_key = n00b_result_get(kr);

    /* 2. Open the session — directory + newNonce GET. */
    auto sr = n00b_acme_session_open(dir_url, acct_key,
                                     .timeout_ms = 30000);
    if (!n00b_result_is_ok(sr)) {
        int err = (int)n00b_result_get_err(sr);
        fprintf(stderr,
                "[FAIL] acme_session_open returned %d (%s)\n", err,
                n00b_quic_err_str((n00b_quic_err_t)err));
        assert(false && "acme_session_open against step-ca failed");
    }
    n00b_acme_session_t *s = n00b_result_get(sr);

    const n00b_acme_directory_t *d = n00b_acme_session_directory(s);
    assert(d->new_nonce);
    assert(d->new_account);
    assert(d->new_order);
    assert(strstr(d->new_nonce,   "/acme/acme/new-nonce")  != NULL);
    assert(strstr(d->new_account, "/acme/acme/new-account") != NULL);
    assert(strstr(d->new_order,   "/acme/acme/new-order")   != NULL);
    printf("  [PASS] session_open + directory parse (newNonce/newAccount/newOrder)\n");

    /* 3. Register account.  step-ca's ACME provisioner is permissive
     * by default — no contact, no termsAgreed required. */
    auto ar = n00b_acme_new_account(s);
    if (!n00b_result_is_ok(ar)) {
        int err = (int)n00b_result_get_err(ar);
        fprintf(stderr,
                "[FAIL] acme_new_account returned %d (%s)\n", err,
                n00b_quic_err_str((n00b_quic_err_t)err));
        assert(false && "acme_new_account against step-ca failed");
    }
    n00b_acme_account_t *acct = n00b_result_get(ar);
    assert(acct->url);
    assert(strstr(acct->url, "/acme/acme/account/") != NULL);
    assert(acct->status);
    assert(strcmp(acct->status, "valid") == 0);
    printf("  [PASS] new_account → %s (status=%s)\n",
           acct->url, acct->status);

    /* 4. Place a new order for a single DNS identifier. */
    const char *names[] = {"test.example.com"};
    auto or_ = n00b_acme_new_order(s, names, 1);
    if (!n00b_result_is_ok(or_)) {
        int err = (int)n00b_result_get_err(or_);
        fprintf(stderr,
                "[FAIL] acme_new_order returned %d (%s)\n", err,
                n00b_quic_err_str((n00b_quic_err_t)err));
        assert(false && "acme_new_order against step-ca failed");
    }
    n00b_acme_order_t *order = n00b_result_get(or_);
    assert(order->url);
    assert(order->status);
    assert(order->finalize);
    /* Pre-validation, step-ca returns "pending". */
    assert(strcmp(order->status, "pending") == 0);
    assert(order->identifier_count == 1);
    assert(order->identifiers[0].type);
    assert(strcmp(order->identifiers[0].type, "dns") == 0);
    assert(strcmp(order->identifiers[0].value, "test.example.com") == 0);
    assert(order->authorization_count == 1);
    assert(order->authorizations[0]);
    printf("  [PASS] new_order → %s (status=pending, %zu authz)\n",
           order->url, order->authorization_count);

    /* 5. Fetch the authz (POST-as-GET).  Walk its challenges; we
     *    expect at least an HTTP-01 with a non-empty token. */
    auto azr = n00b_acme_get_authz(s, order->authorizations[0]);
    if (!n00b_result_is_ok(azr)) {
        int err = (int)n00b_result_get_err(azr);
        fprintf(stderr,
                "[FAIL] acme_get_authz returned %d (%s)\n", err,
                n00b_quic_err_str((n00b_quic_err_t)err));
        assert(false && "acme_get_authz against step-ca failed");
    }
    n00b_acme_authz_t *authz = n00b_result_get(azr);
    assert(authz->status);
    assert(strcmp(authz->status, "pending") == 0);
    assert(authz->identifier.value);
    assert(strcmp(authz->identifier.value, "test.example.com") == 0);
    assert(authz->challenge_count > 0);

    n00b_acme_challenge_t *http01 = NULL;
    for (size_t i = 0; i < authz->challenge_count; i++) {
        if (authz->challenges[i] && authz->challenges[i]->type
            && strcmp(authz->challenges[i]->type, "http-01") == 0) {
            http01 = authz->challenges[i];
            break;
        }
    }
    assert(http01 && "step-ca should expose an http-01 challenge by default");
    assert(http01->token && http01->token[0] != '\0');
    assert(http01->url);
    printf("  [PASS] get_authz → http-01 challenge %s (token len=%zu)\n",
           http01->url, strlen(http01->token));

    /* 6. Compute the key authorization string and sanity-check its
     *    shape: <token>.<43 base64url chars of SHA-256>. */
    char *ka = n00b_acme_http01_key_authz(s, http01->token);
    assert(ka);
    const char *dot = strchr(ka, '.');
    assert(dot);
    size_t left  = (size_t)(dot - ka);
    size_t right = strlen(dot + 1);
    assert(left == strlen(http01->token));
    assert(memcmp(ka, http01->token, left) == 0);
    /* base64url of 32 bytes (no padding) is 43 chars. */
    assert(right == 43);
    printf("  [PASS] http01_key_authz format = <token>.<43-byte-fp>\n");

    n00b_acme_session_close(s);
    n00b_quic_secret_close(acct_key);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *dir_url = getenv("STEPCA_DIR_URL");
    const char *leaf_fp = getenv("STEPCA_LEAF_FP");

    if (!dir_url || !*dir_url) {
        printf("Skipping quic_acme_session test: STEPCA_DIR_URL not set "
               "(run via test/fixtures/stepca/start.sh).\n");
        n00b_shutdown();
        return 0;
    }
    if (!leaf_fp || !*leaf_fp) {
        fprintf(stderr,
                "STEPCA_DIR_URL is set but STEPCA_LEAF_FP is not — "
                "cannot pin trust.\n");
        n00b_shutdown();
        return 1;
    }
    if (hex_to_fp(leaf_fp, g_test_root_fp) != 0) {
        fprintf(stderr, "Failed to parse STEPCA_LEAF_FP=%s\n", leaf_fp);
        n00b_shutdown();
        return 1;
    }
    g_test_root_fp_set = 1;

    printf("test_quic_acme_session (%s):\n", dir_url);
    test_session_open_and_new_account(dir_url);
    printf("All quic_acme_session tests passed.\n");

    n00b_shutdown();
    return 0;
}

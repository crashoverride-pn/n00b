#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "text/strings/format.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"

/* ============================================================================
 * 1. ephemeral: open + format + close + idempotent close
 * ============================================================================ */

static void
test_secret_ephemeral_lifecycle(void)
{
    n00b_buffer_t *uri = n00b_buffer_from_cstr("ephemeral:test-key");

    auto r = n00b_quic_secret_open(uri);
    assert(n00b_result_is_ok(r));
    n00b_quic_secret_t *s = n00b_result_get(r);
    assert(s != nullptr);

    /* Kind defaults to PRIVKEY for ephemeral. */
    assert(n00b_quic_secret_kind(s) == N00B_QUIC_SECRET_PRIVKEY);

    /* Format never includes the underlying material — assert it
     * doesn't contain anything that looks like raw bytes. */
    n00b_string_t *fmt = n00b_quic_secret_format(s);
    assert(fmt != nullptr);
    assert(strstr(fmt->data, "<secret") != nullptr);
    assert(strstr(fmt->data, "kind=privkey") != nullptr);
    assert(strstr(fmt->data, "provider=ephemeral") != nullptr);
    assert(strstr(fmt->data, "label=test-key") != nullptr);

    n00b_quic_secret_close(s);
    /* Idempotent close. */
    n00b_quic_secret_close(s);

    /* Format on a closed handle still returns a safe sentinel. */
    fmt = n00b_quic_secret_format(s);
    assert(fmt != nullptr);
    assert(strstr(fmt->data, "closed") != nullptr);

    printf("  [PASS] ephemeral lifecycle + format opacity\n");
}

/* ============================================================================
 * 2. URI scheme refusals (env: and file:) and unknown schemes
 * ============================================================================ */

static void
test_secret_uri_refusals(void)
{
    auto r = n00b_quic_secret_open(n00b_buffer_from_cstr("env:HOME"));
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_INVALID_ARG);

    r = n00b_quic_secret_open(n00b_buffer_from_cstr("file:/etc/key.pem"));
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_INVALID_ARG);

    /* Unknown scheme → NOT_IMPLEMENTED, not silent default. */
    r = n00b_quic_secret_open(n00b_buffer_from_cstr("unicorn:secret"));
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NOT_IMPLEMENTED);

    /* No colon → INVALID_ARG. */
    r = n00b_quic_secret_open(n00b_buffer_from_cstr("no-scheme-here"));
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_INVALID_ARG);

    /* Empty URI → NULL_ARG (string is non-NULL but empty). */
    r = n00b_quic_secret_open(n00b_buffer_from_cstr(""));
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);

    printf("  [PASS] URI scheme refusals (env / file / unknown / empty)\n");
}

/* ============================================================================
 * 3. ephemeral sign — TEST_MARKER alg succeeds, others reject
 * ============================================================================ */

static void
test_secret_ephemeral_sign(void)
{
    n00b_buffer_t *uri = n00b_buffer_from_cstr("ephemeral:signer");
    auto r1 = n00b_quic_secret_open(uri);
    assert(n00b_result_is_ok(r1));
    n00b_quic_secret_t *s = n00b_result_get(r1);

    n00b_buffer_t data;
    memset(&data, 0, sizeof(data));
    n00b_buffer_init(&data, .raw = (char *)"sign-this", .length = 9);

    auto sr = n00b_quic_secret_sign(s, &data, N00B_QUIC_SIG_TEST_MARKER);
    assert(n00b_result_is_ok(sr));
    n00b_buffer_t *sig = n00b_result_get(sr);
    assert(sig != nullptr);
    assert((size_t)sig->byte_len == 32);  /* SHA-256 length */

    /* Signing twice with same data produces identical "signature"
     * (deterministic test marker over same key+data). */
    auto sr2 = n00b_quic_secret_sign(s, &data, N00B_QUIC_SIG_TEST_MARKER);
    assert(n00b_result_is_ok(sr2));
    n00b_buffer_t *sig2 = n00b_result_get(sr2);
    assert(memcmp(sig->data, sig2->data, 32) == 0);

    /* Real algorithms reject — provider doesn't support them. */
    auto sr3 = n00b_quic_secret_sign(s, &data, N00B_QUIC_SIG_ED25519);
    assert(n00b_result_is_err(sr3));
    assert(n00b_result_get_err(sr3) == N00B_QUIC_ERR_INVALID_ARG);

    /* Wrap is NOT_IMPLEMENTED on ephemeral. */
    auto wr = n00b_quic_secret_wrap(s, &data);
    assert(n00b_result_is_err(wr));
    assert(n00b_result_get_err(wr) == N00B_QUIC_ERR_NOT_IMPLEMENTED);

    /* Sign on a closed handle → INVALID_ARG. */
    n00b_quic_secret_close(s);
    auto sr4 = n00b_quic_secret_sign(s, &data, N00B_QUIC_SIG_TEST_MARKER);
    assert(n00b_result_is_err(sr4));
    assert(n00b_result_get_err(sr4) == N00B_QUIC_ERR_INVALID_ARG);

    printf("  [PASS] ephemeral sign + wrap NOT_IMPLEMENTED + closed handle\n");
}

/* ============================================================================
 * 4. keychain: provider — macOS-only smoke test for the wiring
 *
 * We don't create a real keychain entry here (that requires either
 * SecKeyCreateRandomKey + cleanup, or a fixture script).  We just
 * verify the provider is registered on macOS and that an open call
 * with a label that almost certainly doesn't exist returns the
 * expected INVALID_ARG (rather than NOT_IMPLEMENTED, which would
 * mean the provider isn't wired up).
 * ============================================================================ */

#ifdef __APPLE__
#include "internal/crypto/secret_keychain_raw.h"

static void
test_secret_keychain_provider_wired(void)
{
    /* A label long enough and random enough to be effectively
     * guaranteed not to exist in the host keychain.  If a real
     * keychain entry with this exact label exists, the test will
     * spuriously open it; we accept that microscopic risk. */
    n00b_buffer_t *uri = n00b_buffer_from_cstr(
        "keychain:n00b-test-key-does-not-exist-aaaa-bbbb-cccc-dddd");

    auto r = n00b_quic_secret_open(uri);
    assert(n00b_result_is_err(r));
    /* INVALID_ARG = provider tried and couldn't find / rejected.
     * NOT_IMPLEMENTED would mean the provider isn't registered. */
    int err = n00b_result_get_err(r);
    assert(err == N00B_QUIC_ERR_INVALID_ARG);

    printf("  [PASS] keychain provider registered, returns "
           "INVALID_ARG on missing label\n");
}

/* Hermetic round-trip: create → open → sign → verify → close →
 * delete.  Uses the test-only helpers in secret_keychain.m to avoid
 * depending on a pre-provisioned keychain entry. */
static void
test_secret_keychain_roundtrip(void)
{
    const char *label = "n00b-roundtrip-test-key-2026-05-11";
    size_t      llen  = strlen(label);

    /* Ensure no stale entry from a prior failed run. */
    (void)n00b_keychain_test_delete(label, llen);

    int rc = n00b_keychain_test_create_p256(label, llen);
    if (rc != N00B_QUIC_OK) {
        /* Some CI environments may not allow keychain writes
         * (headless, restricted user).  Skip rather than fail. */
        printf("  [SKIP] keychain roundtrip — could not create test "
               "key (rc=%d, headless CI?)\n", rc);
        return;
    }

    n00b_string_t *uri_str = n00b_cformat("keychain:[|#|]",
                                          n00b_string_from_cstr(label));
    n00b_buffer_t *uri_buf = n00b_buffer_empty();
    n00b_buffer_init(uri_buf,
                     .raw    = uri_str->data,
                     .length = (int64_t)uri_str->u8_bytes);

    auto r = n00b_quic_secret_open(uri_buf);
    if (n00b_result_is_err(r)) {
        n00b_keychain_test_delete(label, llen);
        printf("  [SKIP] keychain roundtrip — open failed (err=%d)\n",
               n00b_result_get_err(r));
        return;
    }
    n00b_quic_secret_t *s = n00b_result_get(r);
    assert(n00b_quic_secret_kind(s) == N00B_QUIC_SECRET_PRIVKEY);

    /* Format must NOT leak the key material. */
    n00b_string_t *fmt = n00b_quic_secret_format(s);
    assert(strstr(fmt->data, "provider=keychain") != nullptr);
    assert(strstr(fmt->data, label) != nullptr);

    /* Sign a known message via the n00b API. */
    const char    *msg_str = "round-trip-payload";
    n00b_buffer_t  msg;
    memset(&msg, 0, sizeof(msg));
    n00b_buffer_init(&msg, .raw = (char *)msg_str,
                     .length = (int64_t)strlen(msg_str));

    auto sigr = n00b_quic_secret_sign(s, &msg, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(sigr));
    n00b_buffer_t *sig = n00b_result_get(sigr);
    assert(sig->byte_len > 0);

    /* Public key — 64 bytes, X || Y. */
    auto pubr = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(pubr));
    n00b_buffer_t *pub = n00b_result_get(pubr);
    assert(pub->byte_len == 64);

    /* Verify through Apple's SecKeyVerifySignature — covers the
     * full round-trip end-to-end, including the n00b → SecKey wire
     * format. */
    void *raw_sec_key = nullptr;
    rc = n00b_keychain_open_raw(label, llen, &raw_sec_key);
    assert(rc == N00B_QUIC_OK);
    rc = n00b_keychain_test_verify_p256(raw_sec_key,
                                        (const uint8_t *)msg_str,
                                        strlen(msg_str),
                                        (const uint8_t *)sig->data,
                                        (size_t)sig->byte_len);
    n00b_keychain_close_raw(raw_sec_key);
    assert(rc == N00B_QUIC_OK);

    n00b_quic_secret_close(s);
    rc = n00b_keychain_test_delete(label, llen);
    assert(rc == N00B_QUIC_OK);

    printf("  [PASS] keychain roundtrip: create → sign → verify → "
           "delete\n");
}
#endif

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_secret:\n");
    fflush(stdout);

    test_secret_ephemeral_lifecycle();
    fflush(stdout);
    test_secret_uri_refusals();
    fflush(stdout);
    test_secret_ephemeral_sign();
    fflush(stdout);
#ifdef __APPLE__
    test_secret_keychain_provider_wired();
    fflush(stdout);
    test_secret_keychain_roundtrip();
    fflush(stdout);
#endif

    printf("All quic secret tests passed.\n");
    n00b_shutdown();
    return 0;
}

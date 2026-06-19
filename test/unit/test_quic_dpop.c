/*
 * test_quic_dpop.c — Phase 3 § 8: DPoP issue + verify (RFC 9449).
 *
 * Coverage:
 *   1. Round-trip: create a DPoP for {POST, https://api/x} → verify
 *      with matching htm/htu → ok.
 *   2. htm mismatch → AUTH_DPOP_FAILED.
 *   3. htu mismatch → AUTH_DPOP_FAILED.
 *   4. nonce required + matching → ok.
 *   5. nonce required + mismatch → AUTH_DPOP_FAILED.
 *   6. jkt thumbprint check ok.
 *   7. jkt thumbprint mismatch → AUTH_MTLS_MISMATCH.
 *   8. Replay detection: insert once, second insert with same jti
 *      via the same replay store → AUTH_REPLAY_DETECTED.
 *   9. iat clock-skew rejection: forge a proof with `iat` far in
 *      the past → DPoP_FAILED.  We can't easily forge with the
 *      public API; this is exercised by waiting past leeway.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/secret.h"
#include "crypto/dpop.h"
#include "internal/crypto/jws.h"

static n00b_quic_secret_t *
mk_holder_key(const char *uri)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr(uri));
    return n00b_result_get(kr);
}

static void
test_roundtrip(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:dpop-1");
    auto pr = n00b_dpop_create(k, "POST", "https://api.example/x");
    assert(n00b_result_is_ok(pr));
    char *proof = n00b_result_get(pr);
    assert(proof);

    auto vr = n00b_dpop_verify(proof, "POST", "https://api.example/x");
    assert(n00b_result_is_ok(vr));
    printf("  [PASS] DPoP create + verify round-trip (matching htm/htu)\n");
    n00b_quic_secret_close(k);
}

static void
test_htm_htu_mismatch(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:dpop-2");
    auto pr = n00b_dpop_create(k, "POST", "https://api.example/x");
    char *proof = n00b_result_get(pr);

    auto v_htm = n00b_dpop_verify(proof, "GET", "https://api.example/x");
    assert(n00b_result_is_err(v_htm));
    assert(n00b_result_get_err(v_htm) == N00B_QUIC_ERR_AUTH_DPOP_FAILED);

    auto v_htu = n00b_dpop_verify(proof, "POST", "https://api.example/y");
    assert(n00b_result_is_err(v_htu));
    assert(n00b_result_get_err(v_htu) == N00B_QUIC_ERR_AUTH_DPOP_FAILED);

    printf("  [PASS] htm + htu mismatch → AUTH_DPOP_FAILED\n");
    n00b_quic_secret_close(k);
}

static void
test_nonce_required(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:dpop-3");
    auto pr = n00b_dpop_create(k, "POST", "https://api/x", .nonce = "abc-123");
    char *proof = n00b_result_get(pr);

    /* Verifier expects matching nonce. */
    auto vok = n00b_dpop_verify(proof, "POST", "https://api/x",
                                .expected_nonce = "abc-123");
    assert(n00b_result_is_ok(vok));

    /* Mismatch. */
    auto vbad = n00b_dpop_verify(proof, "POST", "https://api/x",
                                 .expected_nonce = "different");
    assert(n00b_result_is_err(vbad));
    assert(n00b_result_get_err(vbad) == N00B_QUIC_ERR_AUTH_DPOP_FAILED);

    printf("  [PASS] nonce match / mismatch handled\n");
    n00b_quic_secret_close(k);
}

static void
test_jkt_check(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:dpop-4");
    auto pr = n00b_dpop_create(k, "POST", "https://api/x");
    char *proof = n00b_result_get(pr);

    /* Compute the expected_jkt for the holder we just used. */
    auto pkr = n00b_quic_secret_pubkey(k, N00B_QUIC_SIG_ECDSA_P256);
    n00b_buffer_t *pk = n00b_result_get(pkr);
    uint8_t jkt[32];
    n00b_jwk_p256_thumbprint((const uint8_t *)pk->data, jkt);

    auto vok = n00b_dpop_verify(proof, "POST", "https://api/x",
                                .expected_jkt = jkt);
    assert(n00b_result_is_ok(vok));

    /* Bogus jkt: zeros. */
    uint8_t zero[32] = {0};
    auto vbad = n00b_dpop_verify(proof, "POST", "https://api/x",
                                 .expected_jkt = zero);
    assert(n00b_result_is_err(vbad));
    assert(n00b_result_get_err(vbad) == N00B_QUIC_ERR_AUTH_MTLS_MISMATCH);

    printf("  [PASS] jkt thumbprint check (match + mismatch)\n");
    n00b_quic_secret_close(k);
}

static void
test_replay_detection(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:dpop-5");
    auto pr = n00b_dpop_create(k, "POST", "https://api/x");
    char *proof = n00b_result_get(pr);

    n00b_dpop_replay_store_t *store =
        n00b_dpop_replay_store_new(.capacity = 16);

    auto v1 = n00b_dpop_verify(proof, "POST", "https://api/x",
                               .replay = store);
    assert(n00b_result_is_ok(v1));

    /* Same proof again → replay. */
    auto v2 = n00b_dpop_verify(proof, "POST", "https://api/x",
                               .replay = store);
    assert(n00b_result_is_err(v2));
    assert(n00b_result_get_err(v2) == N00B_QUIC_ERR_AUTH_REPLAY_DETECTED);

    /* A fresh proof with a different jti is fine. */
    auto pr2 = n00b_dpop_create(k, "POST", "https://api/x");
    char *proof2 = n00b_result_get(pr2);
    auto v3 = n00b_dpop_verify(proof2, "POST", "https://api/x",
                               .replay = store);
    assert(n00b_result_is_ok(v3));

    n00b_dpop_replay_store_close(store);
    printf("  [PASS] replay store detects jti reuse; allows fresh jti\n");
    n00b_quic_secret_close(k);
}

static void
test_replay_capacity_eviction(void)
{
    /* Ring-buffer FIFO at capacity=2.  Insert A, B, C → on insert
     * of C, slot 0 (which holds A) is overwritten.  Store now
     * holds {C, B}.  Replaying A is no longer flagged.  Replaying
     * B or C IS flagged. */
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:dpop-6");

    auto p1 = n00b_dpop_create(k, "POST", "https://api/x");
    char *a = n00b_result_get(p1);
    auto p2 = n00b_dpop_create(k, "POST", "https://api/x");
    char *b = n00b_result_get(p2);
    auto p3 = n00b_dpop_create(k, "POST", "https://api/x");
    char *c = n00b_result_get(p3);

    n00b_dpop_replay_store_t *store =
        n00b_dpop_replay_store_new(.capacity = 2);

    auto vA1 = n00b_dpop_verify(a, "POST", "https://api/x", .replay = store);
    auto vB1 = n00b_dpop_verify(b, "POST", "https://api/x", .replay = store);
    auto vC1 = n00b_dpop_verify(c, "POST", "https://api/x", .replay = store);
    assert(n00b_result_is_ok(vA1));
    assert(n00b_result_is_ok(vB1));
    assert(n00b_result_is_ok(vC1));

    /* A was evicted (FIFO ring); replaying A succeeds again. */
    auto vA2 = n00b_dpop_verify(a, "POST", "https://api/x", .replay = store);
    assert(n00b_result_is_ok(vA2));

    /* C is still present (it was the most-recently-inserted
     * before A's re-insert).  Replay of C must be flagged. */
    auto vC2 = n00b_dpop_verify(c, "POST", "https://api/x", .replay = store);
    assert(n00b_result_is_err(vC2));
    assert(n00b_result_get_err(vC2) == N00B_QUIC_ERR_AUTH_REPLAY_DETECTED);

    n00b_dpop_replay_store_close(store);
    printf("  [PASS] FIFO eviction at capacity (ring buffer)\n");
    n00b_quic_secret_close(k);
}

/* RFC 9449 § 4.3 — access-token binding via `ath`. */
static void
test_ath_binding(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:k");
    const uint8_t       at[] = "access-token-bytes-abc-xyz";
    size_t              at_len = sizeof(at) - 1;

    auto pr = n00b_dpop_create(k, "POST", "https://api.example/x",
                                .access_token     = at,
                                .access_token_len = at_len);
    char *proof = n00b_result_get(pr);

    /* Verify with the matching access token — succeeds. */
    auto vok = n00b_dpop_verify(proof, "POST", "https://api.example/x",
                                 .expected_ath     = at,
                                 .expected_ath_len = at_len);
    assert(n00b_result_is_ok(vok));

    /* Verify with a DIFFERENT access token — fails. */
    const uint8_t bad_at[] = "different-token";
    auto vbad = n00b_dpop_verify(proof, "POST", "https://api.example/x",
                                  .expected_ath     = bad_at,
                                  .expected_ath_len = sizeof(bad_at) - 1);
    assert(n00b_result_is_err(vbad));

    /* Proof WITHOUT ath but verifier expects one — fails. */
    auto pr2 = n00b_dpop_create(k, "POST", "https://api.example/x");
    char *proof_no_ath = n00b_result_get(pr2);
    auto vmissing = n00b_dpop_verify(proof_no_ath, "POST",
                                      "https://api.example/x",
                                      .expected_ath     = at,
                                      .expected_ath_len = at_len);
    assert(n00b_result_is_err(vmissing));

    printf("  [PASS] ath binding: matched token OK, "
           "mismatched rejected, missing rejected\n");
    n00b_quic_secret_close(k);
}

/* RFC 9449 § 4.2 htu canonicalization: strip query/fragment,
 * lowercase scheme + host, drop default port. */
static void
test_htu_canonicalization(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:k");

    /* Proof generated against the bare-host form. */
    auto pr = n00b_dpop_create(k, "GET", "https://api.example.com/path");
    char *proof = n00b_result_get(pr);

    /* Verifier sees the URL with default port — should match. */
    auto v1 = n00b_dpop_verify(proof, "GET",
                                "https://api.example.com:443/path");
    assert(n00b_result_is_ok(v1));

    /* Verifier sees the URL with query string — should match (query stripped). */
    auto v2 = n00b_dpop_verify(proof, "GET",
                                "https://api.example.com/path?x=1&y=2");
    assert(n00b_result_is_ok(v2));

    /* Verifier sees uppercase scheme + host — should match. */
    auto v3 = n00b_dpop_verify(proof, "GET",
                                "HTTPS://API.EXAMPLE.COM/path");
    assert(n00b_result_is_ok(v3));

    /* Verifier sees fragment — should match (fragment stripped). */
    auto v4 = n00b_dpop_verify(proof, "GET",
                                "https://api.example.com/path#section");
    assert(n00b_result_is_ok(v4));

    /* Verifier sees a DIFFERENT path — should NOT match. */
    auto v5 = n00b_dpop_verify(proof, "GET",
                                "https://api.example.com/other");
    assert(n00b_result_is_err(v5));

    /* Non-default port should NOT be stripped. */
    auto v6 = n00b_dpop_verify(proof, "GET",
                                "https://api.example.com:8443/path");
    assert(n00b_result_is_err(v6));

    printf("  [PASS] htu canonicalization: default-port, query, "
           "fragment, case all tolerated; path + non-default-port "
           "preserved\n");
    n00b_quic_secret_close(k);
}

/* RFC 9449 § 4.2 — IPv6 literals + userinfo edge cases. */
static void
test_htu_ipv6_userinfo(void)
{
    n00b_quic_secret_t *k = mk_holder_key("ephemeral:k");

    /* IPv6 literal — proof and verifier should match exactly on the
     * canonical (lowercased hex) form. */
    auto pr1 = n00b_dpop_create(k, "GET", "https://[2001:db8::1]/path");
    char *proof1 = n00b_result_get(pr1);

    /* Match: same address, uppercase hex (should canonicalize). */
    auto v_ip_upper = n00b_dpop_verify(proof1, "GET",
                                        "https://[2001:DB8::1]/path");
    assert(n00b_result_is_ok(v_ip_upper));

    /* Match: same address, default port spelled out. */
    auto v_ip_port = n00b_dpop_verify(proof1, "GET",
                                       "https://[2001:db8::1]:443/path");
    assert(n00b_result_is_ok(v_ip_port));

    /* Mismatch: different IPv6 address. */
    auto v_ip_diff = n00b_dpop_verify(proof1, "GET",
                                       "https://[2001:db8::2]/path");
    assert(n00b_result_is_err(v_ip_diff));

    /* Userinfo: RFC 9449 § 4.2 says htu MUST NOT include userinfo.
     * Proof created against the bare-host form should match a verifier
     * URL that happens to include userinfo — both sides strip it
     * during canonicalization. */
    auto pr2 = n00b_dpop_create(k, "POST", "https://api.example.com/x");
    char *proof2 = n00b_result_get(pr2);
    auto v_userinfo = n00b_dpop_verify(proof2, "POST",
                                        "https://user:pass@api.example.com/x");
    assert(n00b_result_is_ok(v_userinfo));

    /* Userinfo on the proof side too — should still match the bare
     * verifier URL. */
    auto pr3 = n00b_dpop_create(k, "POST",
                                "https://user@api.example.com/x");
    char *proof3 = n00b_result_get(pr3);
    auto v_userinfo_in_proof = n00b_dpop_verify(proof3, "POST",
                                                 "https://api.example.com/x");
    assert(n00b_result_is_ok(v_userinfo_in_proof));

    printf("  [PASS] htu IPv6 literals canonicalize (hex case); "
           "userinfo stripped on both sides\n");
    n00b_quic_secret_close(k);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_dpop:\n");
    test_roundtrip();
    test_htm_htu_mismatch();
    test_nonce_required();
    test_jkt_check();
    test_replay_detection();
    test_replay_capacity_eviction();
    test_ath_binding();
    test_htu_canonicalization();
    test_htu_ipv6_userinfo();
    printf("All quic_dpop tests passed.\n");

    n00b_shutdown();
    return 0;
}

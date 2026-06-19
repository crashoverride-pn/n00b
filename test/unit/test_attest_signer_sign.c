/** @file test/unit/test_attest_signer_sign.c — public sign path
 *  regression test (WP-002 Phase 3).
 *
 *  Exercises `n00b_attest_signer_sign` over the file backend
 *  against the RFC 8032 §7.1 vector #1 fixture key.
 *
 *  Coverage:
 *    [1] Sign succeeds and produces a 64-byte signature.
 *    [2] The produced signature verifies under Monocypher's
 *        `crypto_ed25519_check` against the fixture pubkey and
 *        the original message.
 *    [3] Ed25519 determinism: signing the same message twice
 *        produces byte-identical signature bytes (per
 *        RFC 8032's deterministic-nonce contract).
 *    [4] Byte-equality against an oracle: the test re-derives
 *        the expected signature by calling
 *        `crypto_ed25519_sign` directly on the same seed +
 *        message, and asserts byte-equality with the public-
 *        surface output. This catches an "implementation
 *        signs with the wrong key half" bug that determinism +
 *        verify alone might miss.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the
 *  tempfile setup and stdout logging is acceptable per the
 *  established test-file precedent. The test is allowed to call
 *  Monocypher directly for its own assertions per the plan.md
 *  Phase 3 regression-test block.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "core/gc.h"
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

#include <monocypher.h>
#include <monocypher-ed25519.h>

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

// RFC 8032 §7.1 test vector #1 seed.
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// Expected Ed25519 public key for the seed (RFC 8032 §7.1).
static const uint8_t k_expected_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

// Fixed test message — small but non-empty to exercise the real
// path. The DSSEv1 PAE prefix shape is the realistic input the
// envelope-sign vertical produces; using literal "DSSEv1 fixture
// bytes" as the message keeps the regression value-stable and
// recognizable in a hex dump.
static const char k_test_message[] = "DSSEv1 fixture bytes";

static void
build_ed25519_pkcs8_der(const uint8_t seed[32], uint8_t out[48])
{
    static const uint8_t k_prefix[16] = {
        0x30, 0x2E,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22,
        0x04, 0x20,
    };
    memcpy(out, k_prefix, 16);
    memcpy(out + 16, seed, 32);
}

static char *
write_pem_tempfile(const uint8_t *der, size_t der_len)
{
    char  path_template[] = "/tmp/n00b_attest_sign_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    n00b_buffer_t *der_buf = n00b_buffer_from_bytes((char *)der,
                                                    (int64_t)der_len);
    auto enc_r = n00b_base64_encode(der_buf);
    ASSERT_OK(enc_r);
    n00b_string_t *b64 = n00b_result_get(enc_r);

    fprintf(f, "-----BEGIN PRIVATE KEY-----\n");
    size_t off = 0;
    while (off < b64->u8_bytes) {
        size_t take = b64->u8_bytes - off;
        if (take > 64) take = 64;
        fwrite(b64->data + off, 1, take, f);
        fputc('\n', f);
        off += take;
    }
    fprintf(f, "-----END PRIVATE KEY-----\n");
    fclose(f);
    return path;
}

static n00b_attest_signer_t *
resolve_fixture_signer(char **out_path)
{
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path = write_pem_tempfile(der, 48);
    *out_path  = path;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);
    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    return n00b_result_get(r);
}

// Compute the oracle signature directly via Monocypher: derive the
// expanded sk from the seed (same path the file backend uses at
// load time) and call `crypto_ed25519_sign`. Caller owns nothing
// — all storage is stack-local.
static void
compute_oracle_signature(const uint8_t *msg,
                         size_t         msg_len,
                         uint8_t        out_sig[64])
{
    uint8_t expanded_sk[64];
    uint8_t pubkey[32];
    uint8_t seed_copy[32];
    memcpy(seed_copy, k_seed, 32);
    crypto_ed25519_key_pair(expanded_sk, pubkey, seed_copy);
    crypto_ed25519_sign(out_sig, expanded_sk, msg, msg_len);
    crypto_wipe(expanded_sk, sizeof(expanded_sk));
}

static void
test_sign_succeeds_and_verifies(void)
{
    char *path;
    n00b_attest_signer_t *signer = resolve_fixture_signer(&path);

    n00b_buffer_t *msg = n00b_buffer_from_bytes((char *)k_test_message,
                                                (int64_t)(sizeof(k_test_message) - 1));

    auto sr = n00b_attest_signer_sign(signer, msg);
    ASSERT_OK(sr);
    n00b_buffer_t *sig = n00b_result_get(sr);
    assert(sig != nullptr);
    assert(sig->byte_len == 64);

    // Verify under the known pubkey (the file backend stored the
    // pubkey internally; we cross-check against the RFC 8032 §7.1
    // expected pubkey here for the test's own assertion shape).
    int rc = crypto_ed25519_check((const uint8_t *)sig->data,
                                  k_expected_pubkey,
                                  (const uint8_t *)k_test_message,
                                  sizeof(k_test_message) - 1);
    if (rc != 0) {
        fprintf(stderr,
                "FAIL: crypto_ed25519_check returned %d (signature did "
                "not verify under the fixture pubkey)\n",
                rc);
        assert(0);
    }

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] sign_succeeds_and_verifies\n");
}

static void
test_sign_is_deterministic(void)
{
    char *path;
    n00b_attest_signer_t *signer = resolve_fixture_signer(&path);

    n00b_buffer_t *msg = n00b_buffer_from_bytes((char *)k_test_message,
                                                (int64_t)(sizeof(k_test_message) - 1));

    auto r1 = n00b_attest_signer_sign(signer, msg);
    ASSERT_OK(r1);
    auto r2 = n00b_attest_signer_sign(signer, msg);
    ASSERT_OK(r2);
    n00b_buffer_t *s1 = n00b_result_get(r1);
    n00b_buffer_t *s2 = n00b_result_get(r2);
    assert(s1->byte_len == 64 && s2->byte_len == 64);
    assert(memcmp(s1->data, s2->data, 64) == 0);

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] sign_is_deterministic\n");
}

// W-2 regression (`n00b-code-auditor` Phase 3 cleanup pass): when
// the caller resolves a signer with an explicit `.allocator =
// my_arena` but then calls sign WITHOUT specifying `.allocator`,
// the sign path must fall back to the signer's load-time allocator
// (== `my_arena`) for the signature-buffer allocation rather than
// silently routing the buffer through the runtime default.
//
// We assert two things:
//   1. The sign call succeeds (smoke check — the fallback is
//      structurally in place).
//   2. The arena's `used` byte count grows by at least 64 (the
//      signature buffer's payload size). This is the arena-
//      attribution check: if the fallback had failed and the
//      buffer landed in the runtime allocator, the arena's used
//      count would stay flat across the call.
static void
test_sign_allocator_fallback(void)
{
    // Build a dedicated arena and resolve a fresh signer pinned to
    // it via the resolve-time allocator. We repeat the PEM-fixture
    // setup inline (rather than reusing `resolve_fixture_signer`)
    // so we can thread `.allocator` through the resolve call.
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *path2 = write_pem_tempfile(der, 48);

    n00b_arena_t     *arena = n00b_new_arena(.size   = 1 << 20,
                                              .use_gc = true);
    n00b_allocator_t *alloc = (n00b_allocator_t *)arena;

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path2);
    n00b_string_t        *uri   = n00b_string_from_cstr(uri_buf);
    auto                  rr    = n00b_attest_signer_resolve(.ref       = uri,
                                                              .allocator = alloc);
    ASSERT_OK(rr);
    n00b_attest_signer_t *arena_signer = n00b_result_get(rr);

    n00b_buffer_t *msg = n00b_buffer_from_bytes(
        (char *)k_test_message,
        (int64_t)(sizeof(k_test_message) - 1));

    uint64_t before = n00b_arena_used(arena);

    // Note the deliberately missing `.allocator =` kwarg — this is
    // the precise call shape the fallback covers.
    auto sr = n00b_attest_signer_sign(arena_signer, msg);
    ASSERT_OK(sr);
    n00b_buffer_t *sig = n00b_result_get(sr);
    assert(sig != nullptr);
    assert(sig->byte_len == 64);

    uint64_t after = n00b_arena_used(arena);
    if (after < before + 64) {
        fprintf(stderr,
                "FAIL: arena used bytes did not grow by >= 64 across "
                "sign call (before=%llu after=%llu); the signature "
                "buffer likely did NOT land in the resolve-time "
                "arena — fallback path is broken.\n",
                (unsigned long long)before,
                (unsigned long long)after);
        assert(0);
    }

    n00b_attest_signer_release(arena_signer);
    unlink(path2);
    free(path2);
    printf("  [PASS] sign_allocator_fallback "
           "(arena grew %llu bytes across sign)\n",
           (unsigned long long)(after - before));
}

static void
test_sign_matches_oracle(void)
{
    char *path;
    n00b_attest_signer_t *signer = resolve_fixture_signer(&path);

    n00b_buffer_t *msg = n00b_buffer_from_bytes((char *)k_test_message,
                                                (int64_t)(sizeof(k_test_message) - 1));
    auto sr = n00b_attest_signer_sign(signer, msg);
    ASSERT_OK(sr);
    n00b_buffer_t *sig = n00b_result_get(sr);
    assert(sig->byte_len == 64);

    uint8_t oracle[64];
    compute_oracle_signature((const uint8_t *)k_test_message,
                             sizeof(k_test_message) - 1,
                             oracle);
    if (memcmp(sig->data, oracle, 64) != 0) {
        fprintf(stderr, "FAIL: signature byte-mismatch against oracle\n");
        for (int i = 0; i < 64; i++) {
            fprintf(stderr,
                    "  [%2d] api=%02x oracle=%02x %s\n",
                    i,
                    (unsigned char)sig->data[i],
                    oracle[i],
                    ((unsigned char)sig->data[i] == oracle[i]) ? "" : "<-- diff");
        }
        assert(0);
    }

    n00b_attest_signer_release(signer);
    unlink(path);
    free(path);
    printf("  [PASS] sign_matches_oracle\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest signer sign ==\n");
    test_sign_succeeds_and_verifies();
    test_sign_is_deterministic();
    test_sign_matches_oracle();
    test_sign_allocator_fallback();
    printf("All n00b_attest signer sign tests passed.\n");
    return 0;
}

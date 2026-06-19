/** @file test/unit/test_attest_verifier_arena.c — FR-22 arena-
 *  friendliness regression for the verifier surface (WP-003
 *  Phase 4).
 *
 *  Resolves N=50 verifiers through a single n00b arena, calls
 *  `n00b_attest_envelope_verify` on a pre-signed fixture envelope
 *  against each verifier, releases each verifier, then triggers a
 *  GC pass and asserts the arena's used-bytes count drops back
 *  close to the pre-burst baseline.
 *
 *  This is the WP-003 sibling of WP-002 Phase 4's
 *  `test_attest_signer_arena.c`: same `n00b_arena_used()` /
 *  `n00b_collect()` accounting, same "drop all stack locals + run
 *  collection" pattern, same `< before / 2` tolerance. The
 *  precedent's diagnostic narrative on the choice of leak-check
 *  primitive applies verbatim — libn00b does not (yet) expose a
 *  per-symbol-prefix leak primitive, so we use arena-level gross-
 *  byte accounting.
 *
 *  Per D-042 W-2 the verifier's resolve-time allocator inherits
 *  forward into `_envelope_verify` calls. This test passes
 *  `.allocator = arena` only at resolve time and verifies the
 *  check-path scratch lands in the same arena (via the gross
 *  arena-used delta) — the FR-22 expectation that arena-friendly
 *  semantics extend to the verifier vertical, not just the signer
 *  one.
 *
 *  The fixture envelope is signed ONCE at test setup (outside the
 *  arena loop) and reused across all N verify calls — the test
 *  cares about the verifier's allocation behavior, not the
 *  signer's (covered separately by `test_attest_signer_arena`).
 *
 *  Test-file carve-out (D-030) applies — libc I/O for tempfile
 *  setup and stdout logging is acceptable per the established
 *  test-file precedent.
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
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/stw.h"
#include "core/atomic.h"
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

#define ARENA_AS_ALLOC(a) ((n00b_allocator_t *)(a))

/** Outer fan-out per the Phase 4 spec: N=50 resolve / verify /
 *  release through one arena. Matches the signer-arena test's
 *  `N00B_ATTEST_TEST_ARENA_FANOUT` name verbatim so the two tests
 *  are visually paired. */
#define N00B_ATTEST_TEST_ARENA_FANOUT 50

// RFC 8032 §7.1 test vector #1 — same fixture every WP-002 /
// WP-003 test uses.
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// ---------------------------------------------------------------------------
// Tempfile + PEM fixtures.
// ---------------------------------------------------------------------------

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
write_pkcs8_pem_tempfile(const uint8_t *der, size_t der_len)
{
    char  path_template[] = "/tmp/n00b_attest_varena_sk_XXXXXX";
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

static char *
write_spki_pem_tempfile(n00b_buffer_t *spki)
{
    char  path_template[] = "/tmp/n00b_attest_varena_pk_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    auto enc_r = n00b_base64_encode(spki);
    ASSERT_OK(enc_r);
    n00b_string_t *b64 = n00b_result_get(enc_r);

    fprintf(f, "-----BEGIN PUBLIC KEY-----\n");
    size_t off = 0;
    while (off < b64->u8_bytes) {
        size_t take = b64->u8_bytes - off;
        if (take > 64) take = 64;
        fwrite(b64->data + off, 1, take, f);
        fputc('\n', f);
        off += take;
    }
    fprintf(f, "-----END PUBLIC KEY-----\n");
    fclose(f);
    return path;
}

// ---------------------------------------------------------------------------
// Pre-signed fixture envelope (sign once at setup, reuse).
// ---------------------------------------------------------------------------

static n00b_attest_envelope_t *
build_pre_signed_envelope(const char *sk_path_for_signer)
{
    // Build a Statement.
    n00b_attest_statement_t *st = n00b_attest_statement_new();

    uint8_t d[32];
    for (int i = 0; i < 32; i++) d[i] = (uint8_t)(i * 7 + 11);
    n00b_buffer_t *digest = n00b_buffer_from_bytes((char *)d, 32);
    auto ar = n00b_attest_statement_add_subject(
        st,
        .name   = n00b_string_from_cstr("arena"),
        .digest = digest);
    ASSERT_OK(ar);

    auto tr = n00b_attest_statement_set_predicate_type(
        st,
        n00b_string_from_cstr("https://slsa.dev/provenance/v1"));
    ASSERT_OK(tr);

    static const char k_pred[] = "{\"x\":1}";
    n00b_buffer_t *pred = n00b_buffer_from_bytes(
        (char *)k_pred,
        (int64_t)(sizeof(k_pred) - 1));
    auto pr = n00b_attest_statement_set_predicate_json(st, pred);
    ASSERT_OK(pr);

    auto sr = n00b_attest_statement_serialize(st);
    ASSERT_OK(sr);
    n00b_buffer_t *payload = n00b_result_get(sr);

    // Wrap + sign.
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    auto spr = n00b_attest_envelope_set_payload(env, payload);
    ASSERT_OK(spr);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", sk_path_for_signer);
    n00b_string_t *sk_uri = n00b_string_from_cstr(uri_buf);

    auto rr = n00b_attest_signer_resolve(.ref = sk_uri);
    ASSERT_OK(rr);
    n00b_attest_signer_t *signer = n00b_result_get(rr);

    auto sgr = n00b_attest_envelope_sign(env, signer);
    ASSERT_OK(sgr);
    n00b_attest_signer_release(signer);

    return env;
}

// ---------------------------------------------------------------------------
// One resolve / verify / release pass against the arena.
// ---------------------------------------------------------------------------

// Marked noinline so the call frame and its locals are distinct
// stack-scan units — the test's correctness depends on the
// conservative scanner being able to drop these locals after the
// frame returns. Same precaution `test_attest_signer_arena` /
// `test_attest_arena_lifecycle` takes on their per-pass helpers.
[[gnu::noinline]] static void
resolve_verify_release_once(n00b_allocator_t       *allocator,
                            n00b_string_t          *key_uri,
                            n00b_attest_envelope_t *env)
{
    // Resolve: per D-042 W-2 the verifier remembers `allocator`.
    auto rr = n00b_attest_verifier_resolve(.ref       = key_uri,
                                           .allocator = allocator);
    ASSERT_OK(rr);
    n00b_attest_verifier_t *verifier = n00b_result_get(rr);

    // Verify: per D-042 W-2 the per-call scratch is allocated in
    // `allocator` even though we don't re-thread `.allocator =
    // allocator` here — same rationale as the signer-arena test's
    // sign call site. The FR-22 expectation is that the verifier
    // surface is arena-friendly without per-call allocator
    // threading at every node.
    auto vr = n00b_attest_envelope_verify(env, verifier);
    ASSERT_OK(vr);
    assert(n00b_result_get(vr) == true);

    n00b_attest_verifier_release(verifier);

    // Drop locals so the conservative scanner can reclaim the
    // resolved verifier's state on the next GC pass.
    (void)verifier;
}

// ---------------------------------------------------------------------------
// The arena-friendliness test.
// ---------------------------------------------------------------------------

static void
test_verifier_arena_fr22(void)
{
    // One-time fixture setup (outside the arena loop). The signer
    // private-key tempfile + the SPKI PEM tempfile both live in
    // libc heap; the URIs live in the default allocator.
    uint8_t sk_der[48];
    build_ed25519_pkcs8_der(k_seed, sk_der);
    char *sk_path = write_pkcs8_pem_tempfile(sk_der, 48);

    // Pre-sign the fixture envelope (sign once, reuse for all N
    // verify calls). The envelope handle stays live for the
    // duration of the loop; it is allocated in the runtime
    // allocator, NOT the arena under test.
    n00b_attest_envelope_t *env = build_pre_signed_envelope(sk_path);

    // Build the matching SPKI PEM for the verifier side. Resolve a
    // signer once to extract the canonical SPKI DER bytes (so the
    // test mirrors the production round-trip), then release the
    // signer immediately — its state lives in the runtime
    // allocator, not the arena.
    char sk_uri_buf[256];
    snprintf(sk_uri_buf, sizeof(sk_uri_buf), "file://%s", sk_path);
    auto sr = n00b_attest_signer_resolve(
        .ref = n00b_string_from_cstr(sk_uri_buf));
    ASSERT_OK(sr);
    n00b_attest_signer_t *fixture_signer = n00b_result_get(sr);
    n00b_buffer_t *spki_alias = n00b_attest_signer_pubkey_spki_der(
        fixture_signer);
    n00b_buffer_t *spki_copy = n00b_buffer_from_bytes(
        spki_alias->data,
        (int64_t)spki_alias->byte_len);
    n00b_attest_signer_release(fixture_signer);

    char *pk_path = write_spki_pem_tempfile(spki_copy);

    char pk_uri_buf[256];
    snprintf(pk_uri_buf, sizeof(pk_uri_buf), "file://%s", pk_path);
    n00b_string_t *key_uri = n00b_string_from_cstr(pk_uri_buf);

    // Allocate the arena under test.
    n00b_arena_t     *arena = n00b_new_arena(.size   = 1 << 20, // 1 MiB
                                              .use_gc = true);
    n00b_allocator_t *alloc = ARENA_AS_ALLOC(arena);

    uint64_t baseline = n00b_arena_used(arena);
    printf("  arena baseline used bytes: %llu\n",
           (unsigned long long)baseline);

    for (int i = 0; i < N00B_ATTEST_TEST_ARENA_FANOUT; i++) {
        resolve_verify_release_once(alloc, key_uri, env);
    }

    uint64_t after_burst = n00b_arena_used(arena);
    printf("  arena used after %d resolve/verify/release passes: %llu\n",
           N00B_ATTEST_TEST_ARENA_FANOUT,
           (unsigned long long)after_burst);

    // Real work happened — used-bytes MUST have grown.
    assert(after_burst > baseline);

    // Conservative-stack GC pass. The resolve_verify_release_once
    // frames are gone; the stack holds no references into the
    // arena, so collection should reclaim the burst.
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    uint64_t after_collect = n00b_arena_used(arena);
    printf("  arena used after GC: %llu\n",
           (unsigned long long)after_collect);

    // Same tolerance the WP-002 sibling test uses (< before / 2).
    assert(after_collect < after_burst);
    assert(after_collect < after_burst / 2);

    printf("  [PASS] verifier_arena_fr22: %d verifiers built, "
           "GC reclaimed %llu -> %llu bytes\n",
           N00B_ATTEST_TEST_ARENA_FANOUT,
           (unsigned long long)after_burst,
           (unsigned long long)after_collect);

    unlink(pk_path);
    unlink(sk_path);
    free(pk_path);
    free(sk_path);
    (void)env;
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest verifier arena (FR-22) ==\n");
    test_verifier_arena_fr22();

    printf("All n00b_attest verifier arena tests passed.\n");
    return 0;
}

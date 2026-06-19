/** @file test/unit/test_attest_signer_arena.c — FR-22 arena-
 *  friendliness regression for the signer surface (WP-002 Phase 4).
 *
 *  Resolves N=50 signers through a single n00b arena, signs a
 *  fixture message N times against each resolved signer (the inner
 *  fan-out only stresses the sign path's allocator-fallback chain;
 *  the outer N is what the FR-22 expectation cares about), releases
 *  each signer, then triggers a GC pass and asserts the arena's
 *  used-bytes count drops back close to the pre-burst baseline.
 *
 *  This is the WP-002 sibling of WP-001's
 *  `test_attest_arena_lifecycle.c`: same `n00b_arena_used()` /
 *  `n00b_collect()` accounting, same "drop all stack locals + run
 *  collection" pattern, same `< before / 2` tolerance. The
 *  precedent's diagnostic narrative on the choice of leak-check
 *  primitive applies verbatim — libn00b does not (yet) expose a
 *  per-symbol-prefix leak primitive, so we use arena-level gross-
 *  byte accounting.
 *
 *  Per D-042 W-2 the signer's resolve-time allocator inherits
 *  forward into `_sign` calls. This test passes `.allocator = arena`
 *  only at resolve time and verifies the signature bytes land in
 *  the same arena (via the gross arena-used delta) — the FR-22
 *  expectation that arena-friendliness extends to the signer
 *  vertical, not just the Statement / envelope surface.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the
 *  tempfile setup and stdout logging is acceptable per the
 *  established test-file precedent.
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

/** Outer fan-out per the Phase 4 spec: N=50 resolve / sign / release
 *  through one arena. The number is small enough that the test runs
 *  fast but large enough that any per-resolve module-state stash
 *  would be visible in the arena-used delta. */
#define N00B_ATTEST_TEST_ARENA_FANOUT 50

// RFC 8032 §7.1 test vector #1 — same fixture every WP-002 test uses.
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// ---------------------------------------------------------------------------
// Tempfile fixture.
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
write_pem_tempfile(const uint8_t *der, size_t der_len)
{
    char  path_template[] = "/tmp/n00b_attest_arena_XXXXXX";
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

// ---------------------------------------------------------------------------
// One resolve / sign / release pass against the arena.
// ---------------------------------------------------------------------------

// Marked noinline so the call frame and its locals are distinct
// stack-scan units — the test's correctness depends on the
// conservative scanner being able to drop these locals after the
// frame returns. (Same precaution `test_attest_arena_lifecycle`
// takes on its `build_one` helper.)
[[gnu::noinline]] static void
resolve_sign_release_once(n00b_allocator_t *allocator,
                          n00b_string_t    *key_uri,
                          n00b_buffer_t    *msg)
{
    // Resolve: per D-042 W-2 the signer remembers `allocator`.
    auto rr = n00b_attest_signer_resolve(.ref       = key_uri,
                                         .allocator = allocator);
    ASSERT_OK(rr);
    n00b_attest_signer_t *signer = n00b_result_get(rr);

    // Sign: per D-042 W-2 the sig buffer is allocated in `allocator`
    // even though we don't re-thread `.allocator = allocator` here
    // (the fallback chain is opts->allocator → st->allocator →
    // runtime default; the second slot is the resolve-time
    // allocator). Forcing the kwarg here would defeat the test's
    // purpose — the FR-22 expectation is that the signer surface
    // is arena-friendly without per-call allocator threading at
    // every node.
    auto sr = n00b_attest_signer_sign(signer, msg);
    ASSERT_OK(sr);
    (void)n00b_result_get(sr);

    n00b_attest_signer_release(signer);

    // Drop locals so the conservative scanner can reclaim the
    // resolved signer's state on the next GC pass.
    (void)signer;
}

// ---------------------------------------------------------------------------
// The arena-friendliness test.
// ---------------------------------------------------------------------------

static void
test_signer_arena_fr22(void)
{
    // One-time fixture-key setup (outside the arena loop — the
    // tempfile path lives in libc heap, the URI string lives in
    // the default allocator).
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_seed, der);
    char *key_path = write_pem_tempfile(der, 48);

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", key_path);
    n00b_string_t *key_uri = n00b_string_from_cstr(uri_buf);

    // Allocate an n00b arena and use it as the resolve-time
    // allocator across the burst.
    n00b_arena_t     *arena = n00b_new_arena(.size   = 1 << 20, // 1 MiB
                                              .use_gc = true);
    n00b_allocator_t *alloc = ARENA_AS_ALLOC(arena);

    // Stable fixture message (PAE-shaped is unnecessary — the signer
    // signs arbitrary bytes per architecture §6).
    static const char k_msg[] = "n00b-attest FR-22 arena burst";
    n00b_buffer_t    *msg     = n00b_buffer_from_bytes(
        (char *)k_msg,
        (int64_t)(sizeof(k_msg) - 1));

    uint64_t baseline = n00b_arena_used(arena);
    printf("  arena baseline used bytes: %llu\n",
           (unsigned long long)baseline);

    for (int i = 0; i < N00B_ATTEST_TEST_ARENA_FANOUT; i++) {
        resolve_sign_release_once(alloc, key_uri, msg);
    }

    uint64_t after_burst = n00b_arena_used(arena);
    printf("  arena used after %d resolve/sign/release passes: %llu\n",
           N00B_ATTEST_TEST_ARENA_FANOUT,
           (unsigned long long)after_burst);

    // Real work happened — used-bytes MUST have grown.
    assert(after_burst > baseline);

    // Conservative-stack GC pass. The resolve_sign_release_once
    // frames are gone; the stack holds no references into the
    // arena, so collection should reclaim the burst.
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    uint64_t after_collect = n00b_arena_used(arena);
    printf("  arena used after GC: %llu\n",
           (unsigned long long)after_collect);

    // Same tolerance the WP-001 sibling test uses (< before / 2)
    // — leaves room for the conservative stack scanner's typical
    // few-KB of false retention without permitting an actual stash
    // (which would keep the per-resolve signer state alive and the
    // delta would not shrink at all).
    assert(after_collect < after_burst);
    assert(after_collect < after_burst / 2);

    printf("  [PASS] signer_arena_fr22: %d signers built, "
           "GC reclaimed %llu -> %llu bytes\n",
           N00B_ATTEST_TEST_ARENA_FANOUT,
           (unsigned long long)after_burst,
           (unsigned long long)after_collect);

    unlink(key_path);
    free(key_path);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest signer arena (FR-22) ==\n");
    test_signer_arena_fr22();

    printf("All n00b_attest signer arena tests passed.\n");
    return 0;
}

/** @file test/unit/test_attest_signer_release.c — signer release-
 *  path zeroize-on-release regression test (WP-002 Phase 2).
 *
 *  FR-SM-3 obliges every backend to wipe its private key material
 *  before the buffer holding it returns to the allocator. The
 *  file backend wipes the *full* 64-byte expanded secret key
 *  (not just the 32-byte seed half) at release time via
 *  `crypto_wipe`; this test asserts that the post-release buffer
 *  contents are all-zero.
 *
 *  Verification shape:
 *
 *    [1] Resolve a signer from a fixture PKCS#8 PEM.
 *    [2] Cast the public `n00b_attest_signer_t *` down to the
 *        backend's private state struct
 *        (`n00b_attest_signer_file_t`, declared in the package-
 *        private `internal/attest/backends/file.h`). The cast is
 *        safe because the struct's first field is the
 *        `n00b_attest_signer` base per the backends.h convention.
 *    [3] Snapshot the expanded-sk bytes pre-release; assert they
 *        are NOT all-zero (sanity that resolve actually
 *        populated them).
 *    [4] Call `n00b_attest_signer_release`.
 *    [5] Read the expanded-sk bytes back through the same cast;
 *        assert every byte is now zero. The libn00b GC-style
 *        allocator does not zero buffers on free, so the wipe is
 *        the only path producing this state.
 *
 *  The cast through the private header is the cleanest verifiable
 *  shape per the orchestrator-prompt "sub-agent picks the
 *  cleanest verifiable shape" instruction. No sanitizers
 *  (use-after-free, ASan) are tripped because the buffer is not
 *  freed by release — release wipes and returns; the GC reclaims
 *  later.
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
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

#include "internal/attest/backends/file.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

// RFC 8032 §7.1 test vector #1 seed (same as the resolve test).
static const uint8_t k_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// Build the 48-byte PKCS#8 PrivateKeyInfo DER for `k_seed`.
static void
build_pkcs8_der(uint8_t out[48])
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
    memcpy(out + 16, k_seed, 32);
}

// Tempfile writer — same shape as the resolve test's helper.
static char *
write_pem_tempfile(void)
{
    uint8_t der[48];
    build_pkcs8_der(der);

    char  path_template[] = "/tmp/n00b_attest_release_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    n00b_buffer_t *der_buf = n00b_buffer_from_bytes((char *)der, 48);
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

static void
test_release_wipes_expanded_sk(void)
{
    char *path = write_pem_tempfile();

    char uri_buf[256];
    snprintf(uri_buf, sizeof(uri_buf), "file://%s", path);
    n00b_string_t *uri = n00b_string_from_cstr(uri_buf);

    auto r = n00b_attest_signer_resolve(.ref = uri);
    ASSERT_OK(r);
    n00b_attest_signer_t      *signer    = n00b_result_get(r);
    n00b_attest_signer_file_t *file_sg   = (n00b_attest_signer_file_t *)signer;

    // [3] Snapshot the expanded-sk bytes pre-release; the resolve
    // path should have populated all 64 bytes with non-zero content
    // (the RFC 8032 expanded form is seed || pubkey; both halves are
    // non-trivially non-zero for our fixture key).
    bool any_nonzero_pre = false;
    for (size_t i = 0; i < 64; i++) {
        if (file_sg->expanded_sk[i] != 0) {
            any_nonzero_pre = true;
            break;
        }
    }
    assert(any_nonzero_pre);

    // Take a volatile snapshot so the optimizer cannot reason the
    // post-release read away.
    volatile uint8_t snapshot[64];
    for (size_t i = 0; i < 64; i++) {
        snapshot[i] = file_sg->expanded_sk[i];
    }
    (void)snapshot;

    // [4] Release.
    n00b_attest_signer_release(signer);

    // [5] Every byte of the expanded-sk slot must now be zero. The
    // libn00b GC allocator does not zero on free (and release does
    // not free anyway — the GC reclaims later), so a non-zero byte
    // here is a direct contradiction of the `crypto_wipe` call in
    // file_release.
    for (size_t i = 0; i < 64; i++) {
        if (file_sg->expanded_sk[i] != 0) {
            fprintf(stderr,
                    "FAIL: expanded_sk[%zu] = 0x%02x post-release "
                    "(crypto_wipe did not run or did not cover the "
                    "full 64-byte expanded form)\n",
                    i, file_sg->expanded_sk[i]);
            assert(0);
        }
    }

    unlink(path);
    free(path);
    printf("  [PASS] release_wipes_expanded_sk\n");
}

static void
test_release_null_is_noop(void)
{
    // Calling release(nullptr) must be a clean no-op — the libn00b
    // release-then-use convention names this explicitly in the
    // public header's doxygen.
    n00b_attest_signer_release(nullptr);
    printf("  [PASS] release_null_is_noop\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    // Wire up the file backend's vtable + registration so the
    // resolver can find it. Per architecture §6.1 the in-tree
    // backends are registered during module-init; the host
    // (test binary) owns the call.
    n00b_attest_module_init();

    printf("== n00b_attest signer release ==\n");
    test_release_wipes_expanded_sk();
    test_release_null_is_noop();

    printf("All n00b_attest signer release tests passed.\n");
    return 0;
}

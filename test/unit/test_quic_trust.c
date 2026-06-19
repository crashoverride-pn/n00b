#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"

/* Helper: compute SHA-256 of `data` as 32 big-endian bytes. */
static void
sha256_be(const void *data, size_t len, uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(data, len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i * 4]   = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >> 8);
        out[i*4 + 3] = (uint8_t)(w);
    }
}

/* ============================================================================
 * 1. Pinned-fingerprint accepts the pinned cert and rejects everything else
 * ============================================================================ */

static void
test_trust_pinned_accept_reject(void)
{
    /* Synthetic "cert" — not a real DER, but for fingerprint comparison
     * the framer treats it as opaque bytes which is exactly what the
     * pinned backend hashes. */
    static const uint8_t cert_a[] = "DER-encoded-cert-A";
    static const uint8_t cert_b[] = "DER-encoded-cert-B";

    uint8_t fp_a[32];
    sha256_be(cert_a, sizeof(cert_a) - 1, fp_a);

    n00b_quic_trust_t *t = n00b_quic_trust_pinned(fp_a);
    assert(t != nullptr);

    /* Verify against the pinned cert → accept. */
    const uint8_t *chain_a[] = { cert_a };
    size_t         lens_a[]  = { sizeof(cert_a) - 1 };
    auto r = n00b_quic_trust_verify(t, chain_a, lens_a, 1, "test.example");
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == true);

    /* Verify against a different cert → reject with TRUST_REJECTED. */
    const uint8_t *chain_b[] = { cert_b };
    size_t         lens_b[]  = { sizeof(cert_b) - 1 };
    r = n00b_quic_trust_verify(t, chain_b, lens_b, 1, "test.example");
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_TRUST_REJECTED);

    n00b_quic_trust_close(t);
    /* Idempotent close. */
    n00b_quic_trust_close(t);
    /* Verify after close → INVALID_ARG. */
    r = n00b_quic_trust_verify(t, chain_a, lens_a, 1, "test.example");
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_INVALID_ARG);

    printf("  [PASS] trust_pinned accept/reject + close idempotent\n");
}

/* ============================================================================
 * 2. system() returns a real handle; with_extra is still NOT_IMPLEMENTED.
 *
 * Phase 3 § 5.2 lit up the system trust backend (delegating to the
 * cross-platform OS-trust glue from Phase 2's ACME shim).
 * with_extra (corporate-PKI augmentation) is a documented follow-up.
 * ============================================================================ */

static void
test_trust_system_with_extra_status(void)
{
    auto sr = n00b_quic_trust_system();
    assert(n00b_result_is_ok(sr));
    n00b_quic_trust_t *sys = n00b_result_get(sr);
    assert(sys != nullptr);
    n00b_quic_trust_close(sys);

    /* with_extra: NULL chain → NULL_ARG. */
    auto wr_null = n00b_quic_trust_with_extra(nullptr, nullptr);
    assert(n00b_result_is_err(wr_null));
    assert(n00b_result_get_err(wr_null) == N00B_QUIC_ERR_NULL_ARG);

    /* Empty buffer → NULL_ARG. */
    n00b_buffer_t empty;
    memset(&empty, 0, sizeof(empty));
    n00b_buffer_init(&empty, .length = 0);
    auto wr_empty = n00b_quic_trust_with_extra(nullptr, &empty);
    assert(n00b_result_is_err(wr_empty));

    /* Garbage buffer (no PEM, doesn't start with 0x30) → PROTOCOL. */
    n00b_buffer_t garbage;
    memset(&garbage, 0, sizeof(garbage));
    n00b_buffer_init(&garbage, .raw = (char *)"not a cert",
                     .length = 10);
    auto wr_garb = n00b_quic_trust_with_extra(nullptr, &garbage);
    assert(n00b_result_is_err(wr_garb));
    assert(n00b_result_get_err(wr_garb) == N00B_QUIC_ERR_PROTOCOL);

    /* Real path: pass a minimal valid PEM block and verify the handle
     * comes back ok with the system+extras vtable.  We don't run an
     * actual chain verify here (that requires a peer cert that
     * chains to our extras anchor, which the per-test-fixture PKI
     * scripts produce — out of scope for this unit test).  */
    static const char minimal_pem[] =
        "-----BEGIN CERTIFICATE-----\n"
        /* 1-byte ASN.1 SEQUENCE (zero length).  d2i_X509 will reject
         * this as malformed, but our parser layer accepts any decoded
         * blob — the rejection happens at verify time, not parse
         * time.  This proves the parse / handle-build path. */
        "MAA=\n"
        "-----END CERTIFICATE-----\n";
    n00b_buffer_t one;
    memset(&one, 0, sizeof(one));
    n00b_buffer_init(&one, .raw = (char *)minimal_pem,
                     .length = (int64_t)(sizeof(minimal_pem) - 1));
    auto wr_one = n00b_quic_trust_with_extra(nullptr, &one);
    assert(n00b_result_is_ok(wr_one));
    n00b_quic_trust_t *t = n00b_result_get(wr_one);
    assert(t != nullptr);
    n00b_quic_trust_close(t);

    printf("  [PASS] trust_with_extra parses chain + builds handle\n");
}

/* ============================================================================
 * 3. Verify rejects null/empty input cleanly (no crash)
 * ============================================================================ */

static void
test_trust_null_args(void)
{
    uint8_t            zeros[32] = {0};
    n00b_quic_trust_t *t         = n00b_quic_trust_pinned(zeros);

    /* Null trust handle. */
    auto r = n00b_quic_trust_verify(nullptr, nullptr, nullptr, 0, nullptr);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NULL_ARG);

    /* Zero-count chain. */
    r = n00b_quic_trust_verify(t, nullptr, nullptr, 0, nullptr);
    assert(n00b_result_is_err(r));

    /* Chain with nullptr leaf. */
    const uint8_t *chain[] = { nullptr };
    size_t         lens[]  = { 0 };
    r = n00b_quic_trust_verify(t, chain, lens, 1, nullptr);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_TRUST_REJECTED);

    n00b_quic_trust_close(t);
    printf("  [PASS] trust verify null-arg behavior\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_trust:\n");
    fflush(stdout);

    test_trust_pinned_accept_reject();
    fflush(stdout);
    test_trust_system_with_extra_status();
    fflush(stdout);
    test_trust_null_args();
    fflush(stdout);

    printf("All quic trust tests passed.\n");
    n00b_shutdown();
    return 0;
}

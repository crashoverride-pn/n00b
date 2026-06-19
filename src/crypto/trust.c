/*
 * trust.c — Trust-store dispatch + the test-only pinned-fingerprint backend.
 *
 * The OS-native backends (Security.framework on macOS, OpenSSL default
 * verify paths on Linux) and the additive `n00b_quic_trust_with_extra`
 * land with picotls integration.  Until then those entry points return
 * NOT_IMPLEMENTED so callers see a clean error rather than a silent
 * trust-bypass.
 */

#define N00B_USE_INTERNAL_API
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/buffer.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"
#include "internal/crypto/trust_internal.h"
#include "internal/crypto/trust_system.h"  /* n00b_quic_trust_system_verify_chain
                                          * — cross-platform OS-trust glue
                                          * (originally scoped to the ACME
                                          * shim in Phase 2; reused verbatim
                                          * by the system backend after the
                                          * Phase 3 § 5 unification). */
#include "internal/crypto/cert_provisioner_common.h"
                                  /* n00b_certp_pem_all_certs_to_der —
                                   * multi-cert PEM/DER parser for the
                                   * extras chain in with_extra. */

/* ===========================================================================
 * SHA-256 helper — produce 32 raw big-endian bytes.
 *
 * `n00b_sha256_finalize` writes the result as a uint32_t[8] in *host*
 * byte order; for fingerprint comparison we want the canonical
 * big-endian byte sequence so the on-the-wire / on-disk
 * representation matches what other tools produce
 * (`openssl x509 -fingerprint -sha256`, etc.).
 * =========================================================================== */

static void
quic_sha256_be(const void *data, size_t len, uint8_t out[32])
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

/* ===========================================================================
 * Pinned-fingerprint backend
 * =========================================================================== */

typedef struct {
    uint8_t fingerprint[32];
} pinned_state_t;

static int
pinned_verify(void              *state,
              const uint8_t    **chain_der,
              const size_t      *chain_lens,
              size_t             count,
              const char        *sni)
{
    (void)sni;  /* pinned mode does no hostname checking */

    if (!state || !chain_der || !chain_lens || count == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (!chain_der[0] || chain_lens[0] == 0) {
        return N00B_QUIC_ERR_TRUST_REJECTED;
    }

    pinned_state_t *ps = state;

    uint8_t leaf_fp[32];
    quic_sha256_be(chain_der[0], chain_lens[0], leaf_fp);

    if (memcmp(leaf_fp, ps->fingerprint, 32) != 0) {
        return N00B_QUIC_ERR_TRUST_REJECTED;
    }
    return N00B_QUIC_OK;
}

static void
pinned_finalize(void *state)
{
    if (state) {
        memset(state, 0, sizeof(pinned_state_t));
    }
}

static const n00b_quic_trust_vtbl_t pinned_vtbl = {
    .verify_chain = pinned_verify,
    .finalize     = pinned_finalize,
    .name         = "pinned",
};

n00b_quic_trust_t *
n00b_quic_trust_pinned(const uint8_t fingerprint[32])
{
    n00b_allocator_t *alloc = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    n00b_quic_trust_t *t = n00b_alloc_with_opts(n00b_quic_trust_t,
                              &(n00b_alloc_opts_t){.allocator = alloc});

    pinned_state_t *ps = n00b_alloc_with_opts(pinned_state_t,
                              &(n00b_alloc_opts_t){.allocator = alloc, .no_scan = true});

    if (fingerprint) {
        memcpy(ps->fingerprint, fingerprint, 32);
    }

    t->vtbl          = &pinned_vtbl;
    t->backend_state = ps;
    t->purpose       = N00B_QUIC_TRUST_SERVER_AUTH;
    t->closed        = false;
    return t;
}

/* ===========================================================================
 * System trust backend
 *
 * Now delegates to the NATIVE backend (n00b_quic_trust_native, in
 * trust_native.c): the in-tree X.509 verifier against the system root store
 * shipped in pki/crayon-egress-roots.pem (extracted from the OS trust store).
 *
 * The previous implementation delegated to n00b_quic_trust_system_verify_chain
 * → SecTrust on macOS, which calls libsystem_malloc and TRAPS when the TLS
 * verify callback runs on an n00b worker thread (workers are not pthreads).
 * That broke crayon-gw egress. The "trust what the OS trusts" semantics are
 * preserved — the native default anchors ARE the OS root store — but no Apple
 * framework / libc allocation is on the verify path, so it is worker-safe.
 * The SecTrust glue (acme_trust_macos.m et al.) remains for the ACME shim;
 * it is simply no longer on the system-trust path.
 * =========================================================================== */

n00b_result_t(n00b_quic_trust_t *)
n00b_quic_trust_system(void)
{
    return n00b_quic_trust_native();
}

/* ===========================================================================
 * system+extras backend — OS trust store plus caller-provided anchors
 *
 * Layout: `backend_state` points to a `system_with_extras_state_t`
 * holding the additional anchor DERs (each in an n00b_buffer_t).  The
 * vtable's verify_chain dispatches to the extras-aware OS verifier,
 * which adds the extras to the trust evaluation (macOS:
 * SecTrustSetAnchorCertificates + AnchorCertificatesOnly=false;
 * Linux: X509_STORE_add_cert for each).
 * =========================================================================== */

typedef struct {
    /* Per-extra DER bytes (parsed from the caller's PEM/DER input
     * via n00b_certp_pem_all_certs_to_der). */
    n00b_list_t(n00b_buffer_t *) extras;
} system_with_extras_state_t;

static int
system_with_extras_verify(void              *state,
                          const uint8_t    **chain_der,
                          const size_t      *chain_lens,
                          size_t             count,
                          const char        *sni)
{
    system_with_extras_state_t *st = state;
    if (!st) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    size_t extras_count = (size_t)n00b_list_len(st->extras);
    if (extras_count == 0) {
        /* No extras → just call the base path. */
        return n00b_quic_trust_system_verify_chain(chain_der, chain_lens,
                                                   count, sni);
    }

    /* Build parallel arrays of DER pointers + lengths for the
     * extras-aware verifier.  Stack-allocate when small; otherwise
     * a transient allocation. */
    const uint8_t **e_der  = nullptr;
    size_t         *e_lens = nullptr;
    e_der  = n00b_alloc_array(const uint8_t *, extras_count);
    e_lens = n00b_alloc_array(size_t, extras_count);
    for (size_t i = 0; i < extras_count; i++) {
        n00b_buffer_t *b = n00b_list_get(st->extras, (int64_t)i);
        if (!b) {
            return N00B_QUIC_ERR_INVALID_ARG;
        }
        e_der[i]  = (const uint8_t *)b->data;
        e_lens[i] = (size_t)b->byte_len;
    }

    return n00b_quic_trust_system_verify_chain_ex(chain_der, chain_lens,
                                                  count, sni,
                                                  e_der, e_lens,
                                                  extras_count);
}

static const n00b_quic_trust_vtbl_t system_with_extras_vtbl = {
    .verify_chain = system_with_extras_verify,
    .finalize     = nullptr,   /* GC owns the state + list. */
    .name         = "system+extras",
};

/* ===========================================================================
 * with_extra: parse the chain + install the system+extras vtable.
 *
 * The `base` argument is currently unused — extras are always added
 * to the system store.  Once we ship non-system base backends (e.g.,
 * pinned-only-plus-extras) the dispatch will branch on
 * `base->vtbl->name`.  For Phase 3 this covers the common case
 * (corporate PKI on top of the OS trust).
 * =========================================================================== */

n00b_result_t(n00b_quic_trust_t *)
n00b_quic_trust_with_extra(n00b_quic_trust_t *base,
                           n00b_buffer_t     *ca_chain) _kargs
{
    n00b_quic_trust_purpose_t purpose = N00B_QUIC_TRUST_SERVER_AUTH;
}
{
    (void)base;  /* Phase 3: only system+extras supported. */

    if (!ca_chain || !ca_chain->data || ca_chain->byte_len == 0) {
        return n00b_result_err(n00b_quic_trust_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    n00b_result_t(n00b_list_t(n00b_buffer_t *)) pr =
        n00b_certp_pem_all_certs_to_der(ca_chain);
    if (n00b_result_is_err(pr)) {
        return n00b_result_err(n00b_quic_trust_t *,
                               n00b_result_get_err(pr));
    }

    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    system_with_extras_state_t *st = n00b_alloc_with_opts(
        system_with_extras_state_t,
        &(n00b_alloc_opts_t){.allocator = alloc});
    st->extras = n00b_result_get(pr);

    n00b_quic_trust_t *t = n00b_alloc_with_opts(n00b_quic_trust_t,
                              &(n00b_alloc_opts_t){.allocator = alloc});
    t->vtbl          = &system_with_extras_vtbl;
    t->backend_state = st;
    t->purpose       = purpose;
    t->closed        = false;
    return n00b_result_ok(n00b_quic_trust_t *, t);
}

/* ===========================================================================
 * Public entry points: verify + close
 * =========================================================================== */

n00b_result_t(bool)
n00b_quic_trust_verify(n00b_quic_trust_t *trust,
                       const uint8_t    **chain_der,
                       const size_t      *chain_lens,
                       size_t             count,
                       const char        *sni)
{
    if (!trust) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    if (trust->closed) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!trust->vtbl || !trust->vtbl->verify_chain) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NOT_IMPLEMENTED);
    }

    int rc = trust->vtbl->verify_chain(trust->backend_state,
                                       chain_der, chain_lens, count, sni);
    if (rc == N00B_QUIC_OK) {
        return n00b_result_ok(bool, true);
    }
    return n00b_result_err(bool, rc);
}

void
n00b_quic_trust_close(n00b_quic_trust_t *trust)
{
    if (!trust || trust->closed) {
        return;
    }
    if (trust->vtbl && trust->vtbl->finalize) {
        trust->vtbl->finalize(trust->backend_state);
    }
    trust->backend_state = nullptr;
    trust->closed        = true;
}

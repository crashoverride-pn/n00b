/*
 * picotls_verify.c — picotls verify_certificate adapter for n00b_quic_trust_t.
 *
 * One adapter per endpoint, allocated from the conduit pool.  picotls
 * calls `cb(...)` once per handshake; we marshal the DER iovec list to
 * the (ptr, len) array shape n00b_quic_trust_verify expects, then
 * delegate.
 *
 * picoquic's `picoquic_tls_set_verify_certificate_callback` accepts a
 * NULL free-fn (we pass NULL); the wrapping library will not call
 * libc free() on this struct at teardown.  See picoquic
 * `picoquic_dispose_verify_certificate_callback` — the explicit
 * `free(ctx->verify_certificate)` is commented out.  So conduit-pool
 * allocation is safe even though everything else picoquic owns is
 * malloc'd.
 */

#define N00B_USE_INTERNAL_API
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "picotls.h"
#include "picoquic.h"
#include "tls_api.h"  /* picoquic_tls_set_verify_certificate_callback */

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"
#include "internal/crypto/trust_internal.h"
#include "internal/crypto/picotls_verify.h"
#include "internal/crypto/picotls_certverify.h"

typedef struct {
    ptls_verify_certificate_t  super;
    n00b_quic_trust_t         *trust;
} n00b_quic_verify_t;

static int
verify_cb(ptls_verify_certificate_t *self_,
          ptls_t                    *tls,
          const char                *server_name,
          int                      (**verify_sign)(void *, uint16_t,
                                                  ptls_iovec_t,
                                                  ptls_iovec_t),
          void                     **verify_data,
          ptls_iovec_t              *certs,
          size_t                     num_certs)
{
    (void)tls;

    n00b_quic_verify_t *self = (n00b_quic_verify_t *)self_;
    if (!self || !self->trust) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    if (num_certs == 0) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    enum { K_STACK = 16 };
    const uint8_t *stack_ptrs[K_STACK];
    size_t         stack_lens[K_STACK];
    const uint8_t **ptrs = stack_ptrs;
    size_t         *lens = stack_lens;

    n00b_allocator_t *cp =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    if (num_certs > K_STACK) {
        ptrs = n00b_alloc_array_with_opts(const uint8_t *,
                                          (int64_t)num_certs,
                                          &(n00b_alloc_opts_t){
                                              .allocator = cp,
                                              .no_scan   = true,
                                          });
        lens = n00b_alloc_array_with_opts(size_t,
                                          (int64_t)num_certs,
                                          &(n00b_alloc_opts_t){
                                              .allocator = cp,
                                              .no_scan   = true,
                                          });
    }

    for (size_t i = 0; i < num_certs; i++) {
        ptrs[i] = certs[i].base;
        lens[i] = certs[i].len;
    }

    auto vr = n00b_quic_trust_verify(self->trust, ptrs, lens, num_certs,
                                     server_name);
    if (!n00b_result_is_ok(vr)) {
        /* Map the trust verdict to a TLS alert.  TRUST_REJECTED is the
         * normal "didn't validate" outcome → BAD_CERTIFICATE.
         * Anything else (NOT_IMPLEMENTED, INVALID_ARG) → INTERNAL_ERROR
         * so the caller sees a clear bug rather than a misleading
         * cert-rejection. */
        int code = n00b_result_get_err(vr);
        if (code == N00B_QUIC_ERR_TRUST_REJECTED) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        return PTLS_ALERT_INTERNAL_ERROR;
    }

    /* Chain validated.  Now install the CertificateVerify check —
     * picotls calls verify_sign later in the handshake to validate
     * the peer's proof-of-possession.  WITHOUT THIS STEP picotls
     * silently accepts any CertificateVerify (lib/picotls.c:3453-3458),
     * making the entire TLS authentication trivially bypassable.
     * Fail closed on parse / unsupported-algorithm. */
    int rc = n00b_picotls_install_verify_sign(verify_sign, verify_data,
                                              certs[0].base,
                                              certs[0].len);
    if (rc != 0) return rc;
    return 0;
}

int
n00b_quic_picotls_verify_install(picoquic_quic_t   *quic,
                                 n00b_quic_trust_t *trust)
{
    if (!quic || !trust) {
        return N00B_QUIC_ERR_NULL_ARG;
    }

    n00b_allocator_t *cp =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    n00b_quic_verify_t *v = n00b_alloc_with_opts(n00b_quic_verify_t,
                                &(n00b_alloc_opts_t){.allocator = cp});

    v->super.cb    = verify_cb;
    v->super.algos = n00b_picotls_supported_sig_algs;
    v->trust       = trust;

    /* free_fn = NULL: picoquic does not call libc free() on this slot
     * when the free fn is NULL (see tls_api.c).  Lifetime is the
     * endpoint's. */
    picoquic_tls_set_verify_certificate_callback(quic, &v->super, NULL);
    return 0;
}

int
n00b_quic_picotls_install_client_auth(picoquic_quic_t                    *quic,
                                      const uint8_t                      *cert_chain_der,
                                      const size_t                       *cert_chain_lens,
                                      size_t                              cert_chain_count,
                                      n00b_quic_secret_t                 *key,
                                      n00b_picotls_client_auth_storage_t *storage)
{
    if (!quic) return N00B_QUIC_ERR_NULL_ARG;
    ptls_context_t *ctx = (ptls_context_t *)quic->tls_master_ctx;
    if (!ctx) return N00B_QUIC_ERR_INVALID_ARG;
    int rc = n00b_picotls_install_client_auth(ctx,
                                              cert_chain_der,
                                              cert_chain_lens,
                                              cert_chain_count,
                                              key,
                                              storage);
    /* Map picotls alerts to n00b err codes for the caller. */
    return (rc == 0) ? N00B_QUIC_OK : N00B_QUIC_ERR_INVALID_ARG;
}

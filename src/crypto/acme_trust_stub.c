/*
 * acme_trust_stub.c — placeholder for platforms with no native trust
 * verifier wired up yet.
 *
 * Returning NOT_IMPLEMENTED keeps the QUIC handshake (and the ACME
 * HTTPS shim) from silently accepting any cert — connections that
 * need to verify simply do not come up on these platforms.  Replace
 * with a real backend when extending the matrix.
 */

#include <stdint.h>
#include <stddef.h>

#include "net/quic/quic_types.h"
#include "internal/crypto/trust_system.h"

int
n00b_quic_trust_system_verify_chain(const uint8_t **certs,
                                    const size_t   *lens,
                                    size_t          count,
                                    const char     *sni)
{
    (void)certs;
    (void)lens;
    (void)count;
    (void)sni;
    return N00B_QUIC_ERR_NOT_IMPLEMENTED;
}

int
n00b_quic_trust_system_verify_chain_ex(const uint8_t **certs,
                                       const size_t   *lens,
                                       size_t          count,
                                       const char     *sni,
                                       const uint8_t **extras_der,
                                       const size_t   *extras_lens,
                                       size_t          extras_count)
{
    (void)certs;
    (void)lens;
    (void)count;
    (void)sni;
    (void)extras_der;
    (void)extras_lens;
    (void)extras_count;
    return N00B_QUIC_ERR_NOT_IMPLEMENTED;
}

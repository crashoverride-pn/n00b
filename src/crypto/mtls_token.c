/*
 * mtls_token.c — RFC 8705 cnf.x5t#S256 thumbprint binding verifier.
 *
 * The pure verification logic.  See header for context on the
 * picotls/client-auth integration follow-up.
 */

#define N00B_USE_INTERNAL_API
#include <string.h>
#include <stdint.h>

#include "n00b.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/jwt.h"
#include "crypto/mtls_token.h"

n00b_result_t(bool)
n00b_mtls_token_verify(const n00b_jwt_claims_t *claims,
                       const uint8_t           *peer_cert_der,
                       size_t                   peer_cert_len)
{
    if (!claims || !peer_cert_der || peer_cert_len == 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    if (!claims->has_cnf_x5t_s256) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    }

    uint8_t actual[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(peer_cert_der, peer_cert_len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            actual[i*4]     = (uint8_t)(w >> 24);
            actual[i*4 + 1] = (uint8_t)(w >> 16);
            actual[i*4 + 2] = (uint8_t)(w >> 8);
            actual[i*4 + 3] = (uint8_t)w;
        }
    }

    /* Constant-time compare. */
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= actual[i] ^ claims->cnf_x5t_s256[i];
    }
    if (diff != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_MTLS_MISMATCH);
    }
    return n00b_result_ok(bool, true);
}

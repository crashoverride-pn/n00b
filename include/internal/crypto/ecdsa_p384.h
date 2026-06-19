#pragma once

/*
 * ecdsa_p384.h — ECDSA verify on NIST P-384 (secp384r1) (WP-042 Phase 3).
 *
 * Verify-only, so all inputs are public and constant-time is unnecessary; built
 * on the shared bignum (affine point arithmetic, field inverse via Fermat). This
 * fills the gap left by the vendored uECC (which has no P-384) so the verifier
 * can validate real ECDSA-P384 chains (e.g. GTS Root R4).
 */

#include "n00b.h"
#include "core/buffer.h"

/* Verify an ECDSA/P-384 signature. @p pub_xy is the 96-byte uncompressed public
 * point (X||Y, 48 bytes each, no 0x04 prefix); @p hash is the message digest
 * (typically SHA-384); @p r and @p s are the DER INTEGER content bytes of the
 * signature. Returns true iff valid. */
extern bool
n00b_ecdsa_p384_verify(n00b_buffer_t *pub_xy, n00b_buffer_t *hash,
                       n00b_buffer_t *r, n00b_buffer_t *s);

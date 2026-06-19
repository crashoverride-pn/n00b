/**
 * @file acme_csr.h
 * @internal
 * @brief PKCS#10 (RFC 2986) Certificate Signing Request builder.
 *
 * Scoped to the ACME path the rest of Phase 2 uses:
 *   - signing key is ECDSA-P-256 (a `n00b_quic_secret_t` privkey),
 *   - subject is empty (ACME relies on SAN, RFC 8555 § 7.4),
 *   - the CSR carries an `extensionRequest` attribute whose value is
 *     a single SubjectAltName extension listing one or more dNSName
 *     entries.
 *
 * The output is the DER-encoded `CertificationRequest`.  ACME's
 * finalize endpoint expects this DER body to be base64url-encoded
 * inside a JSON `{"csr":"..."}` object — that wrapping happens in
 * `acme.c`, not here.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "crypto/secret.h"

/**
 * @brief Build a DER-encoded PKCS#10 CSR for one or more DNS names.
 *
 * @param cert_key   Privkey secret that supports
 *                   @c N00B_QUIC_SIG_ECDSA_P256 (the cert's signing key).
 * @param dns_names  Array of DNS names to include in the SAN
 *                   extension; @p count > 0.
 * @param count      Number of names.
 *
 * @return Result: ok with a buffer holding the DER CSR; err on
 *         signing failure / argument errors.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_acme_build_csr(n00b_quic_secret_t *cert_key,
                    const char *const   *dns_names,
                    size_t               count);

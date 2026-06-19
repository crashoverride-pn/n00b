/**
 * @file cert_provisioner_common.h
 * @internal
 * @brief Shared helpers used by every cert-provisioner implementation.
 */
#pragma once

#include <stdint.h>
#include "n00b.h"
#include "core/buffer.h"
#include "internal/crypto/cert_provisioner.h"

/** @brief Read an entire file into a fresh buffer (conduit-pool-allocated). */
extern n00b_result_t(n00b_buffer_t *)
n00b_certp_load_file(const char *path);

/**
 * @brief Extract the DER body of the first PEM CERTIFICATE block.
 *
 * Returns the raw DER bytes (no PEM headers / footers / base64).
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_certp_pem_first_cert_to_der(n00b_buffer_t *pem);

/**
 * @brief Extract every CERTIFICATE block from a PEM buffer (or a
 *        single raw DER blob).
 *
 * Walks the buffer for `-----BEGIN CERTIFICATE-----` markers and
 * decodes each one into a DER `n00b_buffer_t *`.  If the buffer
 * holds no PEM markers but starts with `0x30` (ASN.1 SEQUENCE tag),
 * it is treated as a single DER blob and returned as one entry.
 *
 * Used by trust-anchor chain callers where the caller may pass
 * either form.
 *
 * @return Result with a list (length ≥ 1 on success).  err on
 *         malformed input or empty buffer.
 */
extern n00b_result_t(n00b_list_t(n00b_buffer_t *))
n00b_certp_pem_all_certs_to_der(n00b_buffer_t *pem);

/**
 * @brief Parse not_before / not_after (Unix-epoch ms) out of a DER
 *        X.509 v3 certificate's TBSCertificate.Validity field.
 *
 * Walks the outer SEQUENCE → TBSCertificate SEQUENCE; skips
 * version/serial/signature/issuer; reads the Validity SEQUENCE.
 * Accepts both UTCTime and GeneralizedTime.
 */
extern int
n00b_certp_parse_validity(const uint8_t *der, size_t der_len,
                          int64_t *not_before_ms,
                          int64_t *not_after_ms);

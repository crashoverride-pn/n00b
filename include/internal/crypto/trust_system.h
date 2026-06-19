/**
 * @file trust_system.h
 * @internal
 * @brief Cross-platform glue for OS-native trust verification.
 *
 * This is the shared backend used by both the QUIC handshake's
 * `n00b_quic_trust_system()` and the ACME HTTPS shim's `acme_tls.c`.
 * Originally shipped (under the name `acme_trust.h`) scoped to the
 * Phase 2 ACME path; Phase 3 § 5 unified the picotls verify-cert
 * bridge against this same routine, so the file/function names
 * dropped the "acme_" prefix to match the new reach.
 *
 * The implementation is platform-specific:
 *   - macOS: `acme_trust_macos.m` — Security.framework calls.
 *   - Linux: `acme_trust_linux.c` — dlopen libssl, X509_verify_cert.
 *   - Other: `acme_trust_stub.c` — returns NOT_IMPLEMENTED.
 *
 * (The implementation .c files keep their `acme_trust_*` names —
 * renaming them would be churn beyond the API rename's scope.
 * They're internal anyway; only meson.build references them.)
 *
 * @see ~/dd/quic_3.md § 5
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Verify a peer DER cert chain against the system trust store.
 *
 * Hostname-checked against @p sni.  No `--insecure` switch.
 *
 * @param certs  Array of DER-encoded certificate pointers.
 *               @p certs[0] is the leaf; @p certs[count-1] is closest
 *               to a trust anchor.
 * @param lens   Per-cert byte lengths.
 * @param count  Number of certs (must be ≥ 1).
 * @param sni    Server Name Indication from the TLS handshake.  May
 *               be nullptr to skip hostname checking (rare).
 *
 * @return @c N00B_QUIC_OK (0) on success; a negative
 *         @c n00b_quic_err_t on failure
 *         (e.g., @c N00B_QUIC_ERR_TRUST_REJECTED,
 *         @c N00B_QUIC_ERR_NOT_IMPLEMENTED).
 */
extern int
n00b_quic_trust_system_verify_chain(const uint8_t **certs,
                                    const size_t   *lens,
                                    size_t          count,
                                    const char     *sni);

/**
 * @brief Verify with extra trust anchors layered on top of the
 *        system store.
 *
 * Same contract as @ref n00b_quic_trust_system_verify_chain but each
 * of @p extras_count entries from @p extras_der / @p extras_lens is
 * added to the trust evaluation as an additional trusted anchor
 * (alongside whatever the OS store already trusts).  Used by
 * `n00b_quic_trust_with_extra` for corporate-PKI / internal-CA
 * augmentation.
 *
 * @param extras_der    Array of DER-encoded anchor certificates (may
 *                      be nullptr if @p extras_count is 0).
 * @param extras_lens   Per-anchor byte lengths.
 * @param extras_count  Number of extra anchors (0 = behaves exactly
 *                      like the non-_ex variant).
 *
 * Platforms that don't support extras (the stub backend) return
 * `N00B_QUIC_ERR_NOT_IMPLEMENTED` when @p extras_count > 0 and
 * delegate to the non-_ex path otherwise.
 */
extern int
n00b_quic_trust_system_verify_chain_ex(const uint8_t **certs,
                                       const size_t   *lens,
                                       size_t          count,
                                       const char     *sni,
                                       const uint8_t **extras_der,
                                       const size_t   *extras_lens,
                                       size_t          extras_count);

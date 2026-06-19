/**
 * @file picotls_certverify.h
 * @internal
 * @brief CertificateVerify (TLS 1.3 § 4.4.3) signature verification
 *        for the picotls handshake.
 *
 * picotls's `verify_certificate` callback has two outputs the chain
 * verifier MUST populate before returning ok:
 *
 *   - `*verify_sign`: the function picotls calls with (algo,
 *     signdata, signature) to validate the peer's CertificateVerify
 *     message.
 *   - `*verify_data`: opaque ctx passed back to `*verify_sign`.
 *
 * If the chain verifier leaves these unset, picotls's
 * `handle_certificate_verify` (lib/picotls.c:3453) takes the
 * `cb == NULL → ret = 0` branch and accepts ANY CertificateVerify,
 * including one signed with the wrong key.  That's a complete MITM
 * defeat — n00b's old `verify_cb` had this bug; this header is the
 * fix.
 *
 * Supported algorithms (must match picotls advertised list):
 *   - ECDSA P-256 SHA-256
 *   - RSA-PKCS1 SHA-256 (cert-chain only per RFC 8446 § 4.2.3; never
 *     selected for CertificateVerify in TLS 1.3)
 *   - RSA-PSS SHA-256 (rsa_pss_rsae_sha256)
 *
 * Unsupported algorithms fail closed — handshake terminates.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "picotls.h"

/**
 * @brief Install a verify_sign callback for the current handshake.
 *
 * Parses the leaf cert (`certs[0]`) to extract its SubjectPublicKeyInfo,
 * stashes a per-handshake context (pubkey + algorithm kind) in
 * `*verify_data`, and sets `*verify_sign` to a callback that uses the
 * extracted key to verify the peer's CertificateVerify signature.
 *
 * @param verify_sign  Out: picotls's per-handshake verify-sign slot.
 * @param verify_data  Out: opaque ctx passed back to *verify_sign.
 * @param leaf_der     Leaf cert DER bytes.
 * @param leaf_len     Length of leaf_der.
 *
 * @return 0 on success.  Non-zero PTLS_ALERT_* on failure.  Callers
 *         MUST propagate non-zero to picotls so the handshake aborts.
 */
extern int
n00b_picotls_install_verify_sign(int (**verify_sign)(void *, uint16_t,
                                                    ptls_iovec_t,
                                                    ptls_iovec_t),
                                 void          **verify_data,
                                 const uint8_t  *leaf_der,
                                 size_t          leaf_len);

/**
 * @brief Signature algorithms we can actually verify.
 *
 * Use this as the `algos` field of the `ptls_verify_certificate_t`
 * struct in both `picotls_verify.c` and `acme_tls.c`.  Trimming the
 * advertised list to what `n00b_picotls_install_verify_sign` can
 * handle ensures servers pick an algorithm we can verify; if a server
 * insists on something else, the handshake fails (closed).
 */
extern const uint16_t n00b_picotls_supported_sig_algs[];

/* ----------------------------------------------------------------- */
/* Client-side handshake signing (mTLS)                              */
/* ----------------------------------------------------------------- */

/* Forward decls — full types live in internal/net/quic/acme_tls.h
 * (cert_chain shape) and net/quic/secret.h (signing key handle). */
typedef struct n00b_quic_secret n00b_quic_secret_t;

/**
 * @brief Per-endpoint backing storage for an installed client-auth
 *        sign_certificate callback.
 *
 * picotls's `ptls_context_t::sign_certificate` is a pointer to a
 * struct that must outlive every `ptls_t` derived from the context.
 * This struct holds that storage along with the auth key pointer the
 * callback dereferences.  Allocate one per ptls_context_t that needs
 * client auth; pass its address to `n00b_picotls_install_client_auth`.
 */
struct n00b_picotls_client_auth_storage {
    ptls_sign_certificate_t  super;  /* installed into ctx.sign_certificate */
    n00b_quic_secret_t      *key;    /* signing key used by the callback */
    ptls_iovec_t            *cert_iovecs;
    size_t                   cert_iovec_count;
};
typedef struct n00b_picotls_client_auth_storage
    n00b_picotls_client_auth_storage_t;

/**
 * @brief Install client-side mTLS material on a `ptls_context_t`.
 *
 * After this call the context will respond to the peer's
 * CertificateRequest by:
 *   - Presenting @p cert_chain_der (leaf-first; each cert sized by
 *     `cert_chain_lens[i]`).  Bytes are borrowed — the caller must
 *     keep the underlying storage alive for the context's lifetime.
 *   - Signing CertificateVerify with @p key.  Today only
 *     ECDSA-P-256-SHA-256 is supported.
 *
 * @p storage MUST be a fresh struct whose lifetime spans the
 * `ptls_context_t`'s use.  This function overwrites @p storage's
 * fields and installs `&storage->super` as `ctx->sign_certificate`.
 *
 * @return 0 on success.  Non-zero PTLS_ALERT_* on validation failure.
 */
extern int
n00b_picotls_install_client_auth(ptls_context_t                     *ctx,
                                 const uint8_t                      *cert_chain_der,
                                 const size_t                       *cert_chain_lens,
                                 size_t                              cert_chain_count,
                                 n00b_quic_secret_t                 *key,
                                 n00b_picotls_client_auth_storage_t *storage);

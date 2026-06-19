/**
 * @file picotls_verify.h
 * @internal
 * @brief Bridge from `n00b_quic_trust_t` to picotls's verify_certificate.
 *
 * Phase 1 deferred OS-trust integration — the QUIC handshake used
 * picoquic's default verifier (which is `picoquic_set_null_verifier`
 * in the test scaffolding).  Phase 3 unifies the parallel paths
 * (Phase 2's ACME HTTPS verifier and Phase 1's null path) by routing
 * picotls's `verify_certificate` callback through whatever
 * `n00b_quic_trust_t` the endpoint was constructed with.
 *
 * The adapter is owned by the endpoint and lives in `conduit_pool`.
 * `picoquic_tls_set_verify_certificate_callback` accepts a NULL
 * free-fn — picoquic does NOT call libc `free()` on the cb when
 * free_fn is NULL — so pool allocation is safe.  (See tls_api.c
 * `picoquic_dispose_verify_certificate_callback` — the explicit
 * `free()` on `ctx->verify_certificate` is commented out.)
 *
 * @see ~/dd/quic_3.md § 5
 */
#pragma once

#include "picoquic.h"
#include "crypto/trust.h"

/**
 * @brief Install the trust→picotls verify-cert bridge on a picoquic ctx.
 *
 * Replaces any existing verify_certificate callback on
 * @p quic->tls_master_ctx.  Subsequent QUIC handshakes (both client-
 * verifying-server and server-verifying-client when client-auth is
 * enabled) delegate cert-chain validation to @p trust.
 *
 * @param quic   picoquic master context (`endpoint->quic`).
 * @param trust  Trust store to consult.  Borrowed; the caller must
 *               keep it alive for the lifetime of @p quic.
 *
 * @return 0 on success; a negative @c n00b_quic_err_t on failure.
 *
 * @pre  @p quic and @p trust are non-NULL.
 * @post On success, @p quic's TLS master ctx has a verify_certificate
 *       slot that, when invoked by picotls, calls
 *       @c n00b_quic_trust_verify against @p trust.
 */
extern int
n00b_quic_picotls_verify_install(picoquic_quic_t   *quic,
                                 n00b_quic_trust_t *trust);

/* Forward decl — full type in include/internal/net/quic/picotls_certverify.h.
 * Avoids leaking picotls into every caller of this header. */
typedef struct n00b_picotls_client_auth_storage
    n00b_picotls_client_auth_storage_t;
typedef struct n00b_quic_secret n00b_quic_secret_t;

/**
 * @brief Install client-side mTLS material on a picoquic master ctx.
 *
 * Mirrors the h1 path in `acme_tls.c`: after this call the picotls
 * context will respond to the server's CertificateRequest by
 * presenting @p cert_chain_der and signing CertificateVerify with
 * @p key.  Today only ECDSA-P-256-SHA-256 client keys are supported.
 *
 * @param quic        picoquic master context (endpoint->quic).
 * @param cert_chain_der  Leaf-first concatenated DER cert chain.
 *                        Borrowed; must outlive @p quic.
 * @param cert_chain_lens Per-cert byte counts.
 * @param cert_chain_count Number of certs in the chain.
 * @param key         Signing key handle.  Borrowed.
 * @param storage     Backing storage for the sign_certificate stub.
 *                    Lifetime must span @p quic's use.  Typically
 *                    embedded in the endpoint struct.
 *
 * @return 0 on success; non-zero on validation failure.
 */
extern int
n00b_quic_picotls_install_client_auth(picoquic_quic_t *quic,
                                      const uint8_t   *cert_chain_der,
                                      const size_t    *cert_chain_lens,
                                      size_t           cert_chain_count,
                                      n00b_quic_secret_t *key,
                                      n00b_picotls_client_auth_storage_t *storage);

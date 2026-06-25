/**
 * @file acme_tls.h
 * @internal
 * @brief Bytes-on-the-wire substrate for the ACME HTTPS shim.
 *
 * Exposes a single synchronous round-trip primitive: connect a TCP
 * socket to host:port, run a TLS-1.3 handshake (validating the peer
 * cert through `acme_trust_*.c`), send `request` over the encrypted
 * channel, drain the response until the peer closes, return the
 * raw HTTP/1.1 response bytes.
 *
 * Bypasses the n00b conduit machinery deliberately — see acme_http.h
 * for rationale.
 */
#pragma once

#include <stdint.h>
#include "n00b.h"
#include "core/buffer.h"
#include "crypto/trust.h"

/**
 * @brief One synchronous TLS round-trip.
 *
 * @param host        ASCII hostname; used for SNI + cert verification.
 * @param port        TCP port (typically 443).
 * @param request     Bytes to send after the handshake completes.
 *                    The buffer is borrowed; not retained past return.
 * @param response_out  Out-param: freshly allocated buffer holding the
 *                    raw HTTP/1.1 response bytes.  NULL on error.
 * @param timeout_ms  Hard wall-clock deadline for the entire round
 *                    trip (DNS + connect + handshake + I/O).
 *
 * @return N00B_QUIC_OK on success; a negative `n00b_quic_err_t`
 *         otherwise.
 */
extern int
n00b_acme_tls_round_trip(const char     *host,
                         uint16_t        port,
                         n00b_buffer_t  *request,
                         n00b_buffer_t **response_out,
                         int32_t         timeout_ms);

/* ----------------------------------------------------------------- */
/* Primitive ops (Phase 6 chunk 4 transport-wiring)                   */
/*                                                                   */
/* The round-trip primitive above is "open + send + read-until-EOF    */
/* + close" all in one — fine for the ACME shim that always sets     */
/* Connection: close, but it can't reuse a connection across HTTP    */
/* requests.  These primitives expose connect / send / recv / close  */
/* so the HTTP/1.1 round-trip in net/http/http_h1.c can reuse a      */
/* socket+TLS pair when the response advertises keep-alive.          */
/* ----------------------------------------------------------------- */

/** @brief Opaque TLS connection handle. */
typedef struct n00b_acme_tls_conn n00b_acme_tls_conn_t;

/* Forward decl — secret handle used for the mTLS client key. */
typedef struct n00b_quic_secret n00b_quic_secret_t;

/**
 * @brief mTLS client-side identity (cert + signing key).
 *
 * Pass to `n00b_acme_tls_connect_ex` to enable RFC 8705 / RFC 9325
 * client-authenticated TLS 1.3.  Both fields are required when
 * mutual auth is desired; either field NULL = handshake will not
 * present a client cert (server may still demand one, in which case
 * the handshake fails closed).
 *
 * `cert_chain_der` is leaf-first; each entry is a DER-encoded X.509
 * certificate.  `key` is the matching private-key secret handle.
 */
typedef struct {
    const uint8_t       *cert_chain_der;   /**< leaf-first, concat DER */
    const size_t        *cert_chain_lens;  /**< length per cert */
    size_t               cert_chain_count; /**< number of certs in the chain */
    n00b_quic_secret_t  *key;              /**< signing key for ClientVerify */
} n00b_acme_tls_client_auth_t;

/**
 * @brief Open a TCP socket + complete a TLS-1.3 handshake to
 *        @p host : @p port.
 *
 * On success, @p out_conn carries the live connection.  Caller
 * either calls `n00b_acme_tls_close()` to tear it down or hands
 * it to the connection pool.
 *
 * @return  N00B_QUIC_OK on success.  Negative `n00b_quic_err_t`
 *          on transport / handshake failure.
 */
extern int
n00b_acme_tls_connect(const char            *host,
                      uint16_t               port,
                      int32_t                timeout_ms,
                      n00b_acme_tls_conn_t **out_conn);

/**
 * @brief Like @c n00b_acme_tls_connect but with mTLS client material
 *        and an optional caller-supplied trust handle.
 *
 * When @p auth is non-NULL the handshake will respond to the server's
 * CertificateRequest by presenting @p auth->cert_chain_der and signing
 * CertificateVerify with @p auth->key.  Currently only ECDSA-P-256
 * client keys are supported.
 *
 * When @p auth is NULL the handshake will not present a client cert.
 *
 * @param host        ASCII hostname; used for SNI + cert verification.
 * @param port        TCP port (typically 443).
 * @param timeout_ms  Hard wall-clock deadline for connect + handshake.
 * @param auth        Optional mTLS client material; pass @c nullptr
 *                    for standard (server-only) TLS.
 * @param trust       Optional trust handle that overrides the default
 *                    system-trust verification path during the
 *                    handshake's `verify_certificate` callback.  When
 *                    @c nullptr (the default), the system trust store
 *                    is consulted via the same code path that has
 *                    always been used by this entry point — behavior
 *                    is byte-identical to the pre-trust-threading
 *                    form.  When non-@c nullptr, the cert-verify cb
 *                    dispatches through `n00b_quic_trust_verify` so
 *                    the caller's backend (pinned-fingerprint for
 *                    test fixtures, system+extras for corporate PKI,
 *                    etc.) decides the verdict.  The trust handle is
 *                    borrowed; it must outlive the connection (or any
 *                    subsequent pool-reuse window).
 * @param out_conn    Out: freshly opened TLS connection on success;
 *                    @c nullptr on error.
 *
 * @return  N00B_QUIC_OK on success.  Negative `n00b_quic_err_t` on
 *          transport / handshake failure (which includes "server
 *          demanded a client cert and we couldn't present one" and
 *          "the trust backend rejected the presented chain").
 */
extern int
n00b_acme_tls_connect_ex(const char                       *host,
                         uint16_t                          port,
                         int32_t                           timeout_ms,
                         const n00b_acme_tls_client_auth_t *auth,
                         n00b_quic_trust_t                *trust,
                         n00b_acme_tls_conn_t            **out_conn);

/**
 * @brief Send @p bytes over the encrypted channel.  Sends are
 *        synchronous from the caller's POV — returns when all
 *        bytes have been written or @p timeout_ms elapses.
 */
extern int
n00b_acme_tls_send(n00b_acme_tls_conn_t *conn,
                   n00b_buffer_t        *bytes,
                   int32_t               timeout_ms);

/**
 * @brief Receive up to @p max bytes of plaintext from the channel.
 *
 * Blocks up to @p timeout_ms waiting for at least one byte.
 * Returns immediately with whatever's been decoded — caller loops
 * until the message boundary is detected (Content-Length consumed
 * or chunked-body terminator).
 *
 * @param conn        Connection.
 * @param out_chunk   Out: freshly allocated buffer with decoded
 *                    plaintext bytes (may be 0-length on EOF).
 * @param peer_closed Out: true iff the peer FIN'd or sent
 *                    close_notify; the caller MUST close the
 *                    connection rather than pool it after this.
 * @param timeout_ms  Per-call deadline.
 *
 * @return  N00B_QUIC_OK on success (including 0-byte on peer
 *          close).  Negative on timeout / IO error.
 */
extern int
n00b_acme_tls_recv(n00b_acme_tls_conn_t  *conn,
                   size_t                 max,
                   n00b_buffer_t        **out_chunk,
                   bool                  *peer_closed,
                   int32_t                timeout_ms) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/** @brief Close the connection, releasing socket + TLS state. */
extern void
n00b_acme_tls_close(n00b_acme_tls_conn_t *conn);

/** @brief Heuristic: is the peer still alive on this connection?
 *
 * Performs a non-blocking peek.  Used by the connection pool when
 * acquiring an idle connection — if the heuristic says the peer
 * has gone away, the caller drops the connection and dials a
 * fresh one rather than risking a write to a half-closed socket. */
extern bool
n00b_acme_tls_alive(n00b_acme_tls_conn_t *conn);

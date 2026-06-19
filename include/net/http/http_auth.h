/**
 * @file http_auth.h
 * @brief HTTP authentication helper for the n00b HTTP client.
 *
 * Phase 6 chunk 10.  Bundles the three auth mechanisms n00b's QUIC
 * stack already supports — bearer JWT, DPoP, mTLS — into a single
 * struct the HTTP dispatcher (chunk 5) plumbs through to the
 * transports.
 *
 *   - **Bearer**:  `Authorization: Bearer <token>` injection.
 *   - **DPoP**:    Per-request proof generation via
 *                  `n00b_dpop_create()` (Phase 3 § 8); proof goes
 *                  in the `DPoP:` header alongside Bearer.
 *   - **mTLS**:    Client cert + key threaded into the transport's
 *                  TLS layer.  Chunk-10 captures the handle on
 *                  the struct; chunk-11 wires it through the
 *                  TCP+TLS path; chunk-12 wires it through QUIC.
 *
 *   - **Response verifier**: optional callback that runs on the
 *                  decoded response body / headers; lets callers
 *                  validate a JWS-signed response without baking
 *                  JWT verification into the dispatcher itself.
 *
 * The struct is heap-allocated and threaded through the dispatcher
 * via an `auth=` kwarg on `n00b_http_request`.  It is safe to share
 * across calls (the bearer token + DPoP key are immutable from the
 * helper's POV).
 *
 * @see ~/dd/quic_6.md § 4.2 + § 7 chunk 10.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "crypto/secret.h"
#include "crypto/trust.h"

/* Forward decls — h1 headers bag is internal-only at this revision. */
typedef struct n00b_http_h1_headers n00b_http_h1_headers_t;
typedef struct n00b_http_url        n00b_http_url_t;
typedef struct n00b_http_response   n00b_http_response_t;

/**
 * @brief Optional JWS-response verifier hook.
 *
 * Called after the dispatcher receives + decompresses a successful
 * response.  Implementations validate signature / claims and return
 * true to accept; false rejects the response (the dispatcher
 * replaces the body with an error).
 */
typedef bool (*n00b_http_response_verifier_fn)(
    n00b_http_response_t *resp,
    void                 *ctx);

struct n00b_http_auth {
    /** `Authorization: Bearer <token>` payload.  Optional. */
    n00b_buffer_t                  *bearer_token;
    /** Per-request DPoP proof signer.  Optional.  When set the
     *  dispatcher emits a `DPoP:` header derived from
     *  (method, absolute URL).  Pairs with `bearer_token`. */
    n00b_quic_secret_t             *dpop_signer;
    /** mTLS client signing key.  When set together with
     *  `mtls_cert_chain_der`, the h1 transport presents the chain at
     *  handshake time and signs CertificateVerify with this key.
     *  Today only ECDSA-P-256 keys are supported.  Required if
     *  `mtls_cert_chain_der` is non-NULL. */
    n00b_quic_secret_t             *mtls_key;
    /** mTLS client cert chain (DER, leaf-first, concatenated).  Each
     *  cert's length lives in `mtls_cert_chain_lens[i]`.  Required if
     *  `mtls_key` is non-NULL. */
    const uint8_t                  *mtls_cert_chain_der;
    /** Per-cert byte counts for `mtls_cert_chain_der`. */
    const size_t                   *mtls_cert_chain_lens;
    /** Number of certs in `mtls_cert_chain_der`. */
    size_t                          mtls_cert_chain_count;
    /** Response verifier + opaque ctx.  Both nullptr = no verify. */
    n00b_http_response_verifier_fn  response_verifier;
    void                           *response_verifier_ctx;
};
typedef struct n00b_http_auth n00b_http_auth_t;

/**
 * @brief Build a header bag carrying `Authorization` + `DPoP` per
 *        the auth struct, merged onto @p base if provided.
 *
 * Used by the dispatcher (chunk 5) before calling the transport's
 * request builder.  Operators rarely call this directly; the helper
 * is exposed for tests + advanced flows.
 *
 * @param auth   Auth helper (nullptr = no-op; returns @p base).
 * @param base   Optional caller-supplied headers; overlay applied
 *               last so caller-set values win.
 * @param method HTTP method ("GET", "POST", ...) — used as DPoP `htm`.
 * @param url    Parsed URL — origin + path used as DPoP `htu`.
 *
 * @kw allocator Default per-runtime conduit pool.
 *
 * @return  Heap-allocated header bag carrying the auth headers.  Even
 *          when @p auth is nullptr or @p base is nullptr the result is
 *          a fresh bag (possibly empty) so the caller can mutate it
 *          freely.
 */
extern n00b_http_h1_headers_t *
n00b_http_auth_apply(n00b_http_auth_t       *auth,
                     n00b_http_h1_headers_t *base,
                     const char             *method,
                     n00b_http_url_t        *url)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Run the response verifier (if set).  Returns true if the
 *        response is acceptable.
 */
extern bool
n00b_http_auth_verify_response(n00b_http_auth_t      *auth,
                               n00b_http_response_t  *resp);

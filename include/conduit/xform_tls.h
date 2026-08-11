/**
 * @file xform_tls.h
 * @brief Conduit-native TLS-1.3 client transport (two xforms / one ptls_t).
 *
 * TLS as a conduit pipeline stage instead of the raw, out-of-conduit
 * `acme_tls.c` path. Plaintext rides `n00b_write` / `n00b_read`; the
 * encrypt/decrypt happens under the hood and the conduit owns every buffer
 * across the boundary (so a worker thread never hands a movable GC pointer to
 * picotls — the acme_tls SIGSEGV class is impossible by construction).
 *
 * Shape (see doc/conduit-tls-xform-plan.md):
 *
 *   outbound:  app --n00b_write--> [write_topic] --[encrypt xform]--> tcp conn
 *   inbound:   tcp conn --> [decrypt xform] --> [read_topic] --n00b_read--> app
 *
 * Both xforms reference ONE `ptls_t` (the shared session below). The TLS
 * handshake is driven over the conduit IO during connect, before the plaintext
 * topics go live. Trust is delegated to `n00b_quic_trust_native()` (the same
 * worker-safe verifier the h1/h3 paths use); pass an explicit handle to
 * override.
 *
 * Built ALONGSIDE acme_tls.c; nothing in acme_tls is removed by this module.
 */
#pragma once

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/socket.h"
#include "conduit/topic.h"
#include "core/buffer.h"
#include "net/quic/quic_types.h" // n00b_quic_trust_t

// The n00b_buffer_t * topic machinery (message/inbox/subscription/topic) is
// already provided by N00B_CONDUIT_FULL_IMPL(n00b_buffer_t *) in fd_managed.h,
// reached transitively via conduit/socket.h above.

/**
 * @brief A live TLS client session bound to a conduit.
 *
 * Opaque to callers except through the accessors below. Owns the shared
 * `ptls_t`, the underlying TCP conduit connection, the two byte-transform
 * stages, and the plaintext read/write topics. Allocated from the conduit pool
 * (non-moving) so picotls never sees a relocatable pointer.
 */
typedef struct n00b_conduit_tls_t n00b_conduit_tls_t;

/**
 * @brief Open a TLS-1.3 client connection over the conduit and complete the
 *        handshake.
 *
 * Resolves + connects @p host:@p port via `n00b_conduit_conn_tcp`, drives the
 * picotls handshake over the conduit IO (verifying the peer chain through the
 * trust handle), and installs the encrypt/decrypt transform stages. On success
 * the returned session's plaintext topics are live: write requests with
 * `n00b_write(n00b_buffer_t *, n00b_conduit_tls_write_topic(s), buf)` and read
 * responses with `n00b_read(n00b_buffer_t *, n00b_conduit_tls_read_topic(s))`.
 *
 * @param c     Conduit to attach the session to.
 * @param io    Conduit IO backend driving the connection.
 * @param host  Server hostname (also the SNI / cert name).
 * @param port  Server port.
 * @kw trust    Optional trust handle; null uses `n00b_quic_trust_native()`.
 * @kw timeout_ms  Handshake deadline; <= 0 selects a sane default.
 * @kw allocator   Optional allocator; defaults to the conduit pool.
 * @kw proxy_host  When set, dial this host instead of @p host and perform
 *                 a plaintext `CONNECT host:port` tunnel exchange (RFC
 *                 9110 §9.3.6) before starting the TLS handshake. @p host
 *                 / @p port are unchanged as the SNI / cert name and the
 *                 CONNECT target — only the raw TCP dial target moves.
 *                 Null (the default) preserves today's direct-dial
 *                 behavior exactly.
 * @kw proxy_port  Port to dial on @kw proxy_host. Ignored if
 *                 @kw proxy_host is null.
 * @kw proxy_extra_headers  Optional extra header line(s) (each including
 *                 its own trailing CRLF, e.g. a `Proxy-Authorization:`
 *                 line) spliced verbatim into the CONNECT request.
 * @return Ok(session) once the handshake has completed, else a typed error.
 */
extern n00b_result_t(n00b_conduit_tls_t *)
n00b_conduit_tls_connect(n00b_conduit_t            *c,
                         n00b_conduit_io_backend_t *io,
                         n00b_string_t             *host,
                         uint16_t                   port) _kargs
{
    n00b_quic_trust_t *trust               = nullptr;
    int32_t            timeout_ms          = 0;
    n00b_allocator_t  *allocator           = nullptr;
    n00b_string_t     *proxy_host          = nullptr;
    uint16_t           proxy_port          = 0;
    n00b_string_t     *proxy_extra_headers = nullptr;
};

/**
 * @brief Write cleartext to the TLS session (the encrypt xform ciphers it onto
 *        the wire).
 *
 * Honors the conduit buffer-ownership contract: @p plaintext is COPIED into a
 * conduit-pool (non-moving) buffer that the conduit owns and frees once the
 * encrypt stage has consumed it.  The caller may mutate or drop @p plaintext
 * immediately on return — and, crucially, a moving GC can never relocate the
 * bytes out from under the encrypt worker, because the delivered copy is
 * pinned.  Prefer this over publishing directly to the write topic with a
 * caller-allocated (movable) buffer.
 */
extern n00b_result_t(bool)
n00b_conduit_tls_write(n00b_conduit_tls_t *s, n00b_buffer_t *plaintext);

/**
 * @brief Submit raw cleartext bytes to the TLS session.
 *
 * Copies @p len bytes directly into a conduit-pool pinned buffer and publishes
 * it to the encrypt stage. Return means the conduit accepted the pinned
 * plaintext chunk; socket delivery is driven asynchronously by the conduit IO
 * path. This is the streaming form for callers whose source bytes already live
 * in non-buffer storage such as mapped rocs shards.
 */
extern n00b_result_t(bool)
n00b_conduit_tls_submit_raw(n00b_conduit_tls_t *s, const void *data, size_t len);

/** @brief Plaintext write topic — lower-level handle. Anything published here
 *  MUST be a conduit-pool (pinned) buffer; use `n00b_conduit_tls_write` to get
 *  the copy-in ownership guarantee. */
extern n00b_conduit_topic_t(n00b_buffer_t *) *
n00b_conduit_tls_write_topic(n00b_conduit_tls_t *s);

/** @brief Plaintext read topic — the decrypt xform delivers cleartext here. */
extern n00b_conduit_topic_t(n00b_buffer_t *) *
n00b_conduit_tls_read_topic(n00b_conduit_tls_t *s);

/** @brief True once the handshake has completed and the plaintext topics are
 *  live. */
extern bool n00b_conduit_tls_is_ready(n00b_conduit_tls_t *s);

/**
 * @brief Send TLS close_notify, tear down the transform stages, free the
 *        ptls_t, and close the underlying connection. Idempotent.
 */
extern void n00b_conduit_tls_close(n00b_conduit_tls_t *s);

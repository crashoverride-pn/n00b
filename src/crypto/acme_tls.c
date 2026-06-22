/*
 * acme_tls.c — TCP connect + picotls TLS-1.3 client + bytes round-trip.
 *
 * Single public entry point: `n00b_acme_tls_round_trip`.  Internally:
 *
 *   1. Resolve host (getaddrinfo) and connect a TCP socket.
 *   2. Set the socket non-blocking and drive picotls's
 *      handshake/send/receive functions on top of a poll(2) loop.
 *   3. After the handshake completes, send the caller's request.
 *   4. Read until the peer closes (Connection: close per request).
 *   5. Hand the raw response bytes back as a freshly allocated buffer.
 *
 * Trust verification is delegated to `acme_trust_*.c` via the picotls
 * verify_certificate hook.  See trust_system.h.
 */

#define N00B_USE_INTERNAL_API
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "picotls.h"
#include "picotls/minicrypto.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "net/dns.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"
#include "internal/crypto/acme_tls.h"
#include "internal/crypto/trust_system.h"
#include "internal/crypto/picotls_certverify.h"
#include "crypto/secret.h"

/* ===========================================================================
 * Helpers
 * =========================================================================== */

static n00b_allocator_t *
tls_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

/* Monotonic milliseconds since some fixed origin. */
static int64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* picotls get_time callback. */
static uint64_t
get_time_cb(ptls_get_time_t *self)
{
    (void)self;
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static ptls_get_time_t the_get_time = {.cb = get_time_cb};

/* ===========================================================================
 * verify_certificate adapter
 *
 * picotls calls cb() during the handshake with the peer's DER chain.
 * We forward to acme_trust_verify_chain (platform-specific).
 * =========================================================================== */

typedef struct {
    ptls_verify_certificate_t super;
    const char               *server_name;  /* set per-handshake */
    /* Optional caller-supplied trust handle.  When non-NULL the cb
     * dispatches through `n00b_quic_trust_verify` instead of the
     * default system-trust path.  Borrowed pointer; the connection
     * struct that owns this `acme_verify_t` is responsible for not
     * outliving the trust handle. */
    n00b_quic_trust_t        *trust;
} acme_verify_t;

static int
acme_verify_cb(ptls_verify_certificate_t *self_,
               ptls_t                    *tls,
               const char                *server_name,
               int                      (**verify_sign)(void *, uint16_t,
                                                       ptls_iovec_t,
                                                       ptls_iovec_t),
               void                     **verify_data,
               ptls_iovec_t              *certs,
               size_t                     num_certs)
{
    (void)tls;

    if (num_certs == 0) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    /* picotls hands us back the verifier pointer we registered on the
     * ctx.  Recover it so we can route through any caller-supplied
     * trust handle.  Module-shared `the_verifier` has `trust = NULL`
     * (no behavior change for the default path); a per-call verifier
     * carries the trust pointer set up by `n00b_acme_tls_connect_ex`. */
    acme_verify_t *self = (acme_verify_t *)self_;

    /* Materialize a DER pointer array for the verifier. */
    enum { K_STACK = 16 };
    const uint8_t *stack_ptrs[K_STACK];
    size_t         stack_lens[K_STACK];
    const uint8_t **ptrs = stack_ptrs;
    size_t         *lens = stack_lens;

    if (num_certs > K_STACK) {
        ptrs = n00b_alloc_array_with_opts(const uint8_t *,
                                          (int64_t)num_certs,
                                          &(n00b_alloc_opts_t){
                                              .allocator = tls_alloc(),
                                              .no_scan   = true,
                                          });
        lens = n00b_alloc_array_with_opts(size_t,
                                          (int64_t)num_certs,
                                          &(n00b_alloc_opts_t){
                                              .allocator = tls_alloc(),
                                              .no_scan   = true,
                                          });
    }

    for (size_t i = 0; i < num_certs; i++) {
        ptrs[i] = certs[i].base;
        lens[i] = certs[i].len;
    }

    if (self && self->trust != nullptr) {
        /* Caller-supplied trust path — dispatch through the
         * `n00b_quic_trust_t` vtable.  Pinned-fingerprint, system,
         * system+extras, etc. all flow through the same entry point
         * the h3 path uses, so the two transports agree on the
         * verdict for any given trust handle. */
        n00b_result_t(bool) tr = n00b_quic_trust_verify(self->trust,
                                                       ptrs, lens,
                                                       num_certs,
                                                       server_name);
        if (n00b_result_is_err(tr)) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
    } else {
        /* Default path — native (libc-free) system trust via the trust
         * vtable, the same backend the h3 path uses. The previous direct
         * call to n00b_quic_trust_system_verify_chain went to SecTrust,
         * which calls libsystem_malloc and TRAPS when this verify callback
         * runs on an n00b worker thread (e.g. egress_worker_main during
         * credential refresh) — workers are not pthreads. The native
         * verifier has no Apple-framework / libc allocation, so it is
         * worker-safe. */
        n00b_result_t(n00b_quic_trust_t *) sr = n00b_quic_trust_native();
        if (n00b_result_is_err(sr)) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        n00b_result_t(bool) tr = n00b_quic_trust_verify(n00b_result_get(sr),
                                                        ptrs, lens, num_certs,
                                                        server_name);
        if (n00b_result_is_err(tr)) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
    }

    /* Install the CertificateVerify check.  picotls calls verify_sign
     * later in the handshake to validate the peer's proof-of-possession.
     * WITHOUT THIS STEP picotls silently accepts any CertificateVerify
     * (lib/picotls.c:3453-3458), making TLS authentication trivially
     * bypassable.  Fail closed on parse / unsupported-algorithm. */
    int vrc = n00b_picotls_install_verify_sign(verify_sign, verify_data,
                                               certs[0].base,
                                               certs[0].len);
    if (vrc != 0) return vrc;
    return 0;
}

/* picotls dereferences `verify_certificate->algos` without a NULL
 * check inside push_signature_algorithms (picotls.c:1995).  Use the
 * shared trimmed list from picotls_certverify — only algorithms we can
 * actually verify get offered, so servers don't pick one we'd be
 * forced to silently accept.
 *
 * The module-shared verifier carries `trust = NULL`, which selects the
 * default system-trust path in `acme_verify_cb`.  Calls that supply a
 * caller-side `n00b_quic_trust_t *` get a per-call verifier wired into
 * a per-call ptls_context_t (see `per_call_ctx_t` below); the
 * module-shared form is read-only and used only by the default
 * (system-trust) path. */
static acme_verify_t the_verifier = {
    .super       = {.cb = acme_verify_cb,
                    .algos = n00b_picotls_supported_sig_algs},
    .server_name = nullptr,
    .trust       = nullptr,
};

/* ===========================================================================
 * Per-runtime picotls base context
 *
 * Replaces the previous file-scope `the_ctx` global.  The base context
 * is a template: every connect call either uses it verbatim (for
 * unauthenticated clients) or makes a per-call shallow copy and
 * overlays mTLS material (certificates + sign_certificate) onto the
 * copy.  Either way the underlying picotls function pointers
 * (random_bytes / get_time / key_exchanges / cipher_suites /
 * verify_certificate) are stable for the runtime's lifetime.
 *
 * GC discipline: allocated from `n00b_runtime_t::system_pool`, which is
 * not a GC arena.  The pool's memory persists for the runtime's
 * lifetime and is not scanned by the collector, so:
 *   - The struct itself doesn't get moved, and its address remains
 *     stable for picotls's `tls->ctx` back-reference.
 *   - The struct doesn't hold any GC-tracked pointers (every field is
 *     either a function pointer into static minicrypto data or a
 *     pointer at file-scope storage like `the_verifier`).  Nothing in
 *     here needs `n00b_gc_register_root`.
 * The pointer on `n00b_runtime_t::acme_tls_state` is updated via
 * atomic CAS so concurrent first-callers don't race.
 * =========================================================================== */

struct n00b_acme_tls_state {
    ptls_context_t base_ctx;
};

static n00b_acme_tls_state_t *
get_base_state(void)
{
    n00b_runtime_t        *rt = n00b_get_runtime();
    n00b_acme_tls_state_t *s  = atomic_load_explicit(&rt->acme_tls_state,
                                                     memory_order_acquire);
    if (s) return s;

    n00b_allocator_t *sp = (n00b_allocator_t *)&rt->system_pool;
    n00b_acme_tls_state_t *fresh = n00b_alloc_with_opts(
        n00b_acme_tls_state_t,
        &(n00b_alloc_opts_t){.allocator = sp});
    memset(&fresh->base_ctx, 0, sizeof(fresh->base_ctx));
    fresh->base_ctx.random_bytes       = ptls_minicrypto_random_bytes;
    fresh->base_ctx.get_time           = &the_get_time;
    fresh->base_ctx.key_exchanges      = ptls_minicrypto_key_exchanges;
    fresh->base_ctx.cipher_suites      = ptls_minicrypto_cipher_suites;
    fresh->base_ctx.verify_certificate = &the_verifier.super;

    if (!atomic_compare_exchange_strong_explicit(
            &rt->acme_tls_state, &s, fresh,
            memory_order_acq_rel, memory_order_acquire)) {
        /* Lost the race; another thread published first.  fresh is
         * unreachable but lives in system_pool which is never GC'd, so
         * it's a small one-time leak — same shape as
         * `n00b_http_get_connection_pool`. */
        return s;
    }
    return fresh;
}

/* ===========================================================================
 * TCP connect with timeout
 * =========================================================================== */

static int
tcp_connect(const char *host, uint16_t port, int32_t timeout_ms,
            int *sock_out)
{
    /* Resolve without the libc resolver (getaddrinfo): this runs on n00b
     * worker threads, where getaddrinfo's internal libc malloc traps under the
     * off-libc runtime. n00b_dns_resolve_addrs uses n00b's own UDP resolver. */
    n00b_resolved_addr_t addrs[8];
    int                  naddr = n00b_dns_resolve_addrs(
        n00b_string_from_cstr(host), port, addrs,
        (int)(sizeof(addrs) / sizeof(addrs[0])));
    if (naddr <= 0) {
        fprintf(stderr,
                "[acme_tls] resolve(%s:%u) failed (no addresses)\n",
                host, (unsigned)port);
        return N00B_QUIC_ERR_BIND_FAILED;
    }

    int64_t deadline = now_ms() + timeout_ms;
    int     fd       = -1;
    int     rc       = N00B_QUIC_ERR_BIND_FAILED;
    int     last_errno  = 0;     /* errno snapshot from the last attempt */
    const char *last_phase = "init";

    for (int i = 0; i < naddr; i++) {
        fd = socket(addrs[i].ss.ss_family, SOCK_STREAM, 0);
        if (fd < 0) {
            last_errno = errno;
            last_phase = "socket";
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int cr = connect(fd, (struct sockaddr *)&addrs[i].ss, addrs[i].len);
        if (cr == 0) {
            rc = N00B_QUIC_OK;
            break;
        }
        if (errno != EINPROGRESS) {
            last_errno = errno;
            last_phase = "connect";
            close(fd);
            fd = -1;
            continue;
        }
        /* Wait for the socket to become writable. */
        int64_t now = now_ms();
        if (now >= deadline) {
            close(fd);
            fd = -1;
            rc = N00B_QUIC_ERR_TIMEOUT;
            last_phase = "deadline";
            continue;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int           pr  = poll(&pfd, 1, (int)(deadline - now));
        if (pr <= 0) {
            if (pr < 0) last_errno = errno;
            last_phase = (pr == 0) ? "poll-timeout" : "poll-error";
            close(fd);
            fd = -1;
            rc = (pr == 0) ? N00B_QUIC_ERR_TIMEOUT
                           : N00B_QUIC_ERR_BIND_FAILED;
            continue;
        }
        int       err     = 0;
        socklen_t err_len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0
            || err != 0) {
            last_errno = err ? err : errno;
            last_phase = "post-poll-so_error";
            close(fd);
            fd = -1;
            rc = N00B_QUIC_ERR_BIND_FAILED;
            continue;
        }
        rc = N00B_QUIC_OK;
        break;
    }

    if (rc == N00B_QUIC_OK) {
        *sock_out = fd;
    }
    else {
        fprintf(stderr,
                "[acme_tls] connect(%s:%u) failed: rc=%d phase=%s errno=%d (%s)\n",
                host, (unsigned)port, rc, last_phase,
                last_errno, last_errno ? strerror(last_errno) : "n/a");
    }
    return rc;
}

/* ===========================================================================
 * TLS round-trip
 * =========================================================================== */

/* Drain encbuf to the socket; non-blocking-safe. */
static int
flush_send(int sockfd, ptls_buffer_t *encbuf, int32_t timeout_ms)
{
    int64_t deadline = now_ms() + timeout_ms;
    while (encbuf->off > 0) {
        int64_t now = now_ms();
        if (now >= deadline) {
            return N00B_QUIC_ERR_TIMEOUT;
        }
        struct pollfd pfd = {.fd = sockfd, .events = POLLOUT};
        int           pr  = poll(&pfd, 1, (int)(deadline - now));
        if (pr <= 0) {
            return (pr == 0) ? N00B_QUIC_ERR_TIMEOUT : N00B_QUIC_ERR_PROTOCOL;
        }
        ssize_t w = send(sockfd, encbuf->base, encbuf->off, 0);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            return N00B_QUIC_ERR_PROTOCOL;
        }
        if ((size_t)w == encbuf->off) {
            encbuf->off = 0;
        } else {
            memmove(encbuf->base, encbuf->base + w, encbuf->off - (size_t)w);
            encbuf->off -= (size_t)w;
        }
    }
    return N00B_QUIC_OK;
}

/* =========================================================================
 * Connection-handle primitives
 *
 * The round-trip API above is "open + send + read-until-EOF + close"
 * fused; ACME directory + nonce flows want exactly that shape.  These
 * primitives split the operation so the public HTTP h1 path can keep
 * a connection open across requests for keep-alive pooling.
 * ========================================================================= */

/* Per-call picotls context.  Lives alongside the conn so its address
 * remains stable for the picotls `tls->ctx` back-reference.  Built
 * from `get_base_state()->base_ctx` with optional client-auth fields
 * overlaid via `n00b_picotls_install_client_auth` and/or a per-call
 * verifier that dispatches through a caller-supplied trust handle.
 *
 * The struct exists when ANY per-call override is needed (mTLS
 * material, caller-supplied trust, or both).  Connections with no
 * overrides alias the per-runtime base ctx directly with no per-call
 * allocation. */
typedef struct {
    ptls_context_t                     ctx;
    n00b_picotls_client_auth_storage_t auth_storage;
    /* Per-call verifier.  Populated only when the caller supplied a
     * trust handle to `n00b_acme_tls_connect_ex`.  Its address is
     * pinned by living inside the per-call ctx struct, so it remains
     * stable for the picotls ctx's `verify_certificate` field for the
     * connection's lifetime.  Per-connection state — preserves the
     * §10.9 invariant that the module-shared `the_verifier` carries
     * no caller-mutable per-call state. */
    acme_verify_t                      verifier;
} per_call_ctx_t;

struct n00b_acme_tls_conn {
    int            sockfd;
    ptls_t        *tls;
    bool           handshake_done;
    bool           peer_eof;
    ptls_buffer_t  encbuf;
    ptls_buffer_t  ptbuf;
    /* Backing storage for the picotls scratch buffers.  picotls
     * will realloc-grow these if needed; they stay allocated for
     * the conn's lifetime. */
    uint8_t        encbuf_storage[16384];
    uint8_t        ptbuf_storage[16384];
    /* Stash for plaintext bytes that arrived on a previous recv
     * but the caller hasn't drained yet. */
    n00b_buffer_t *recv_pending;
    size_t         recv_consumed;
    /* When the conn was opened with mTLS material, this holds the
     * per-call ptls_context_t whose lifetime must match the conn's.
     * nullptr for non-mTLS conns (which alias the per-runtime base
     * ctx directly). */
    per_call_ctx_t *pcctx;
};

static int
do_handshake_until_done(n00b_acme_tls_conn_t *c, int64_t deadline);
static int
flush_send(int sockfd, ptls_buffer_t *encbuf, int32_t timeout_ms);

/* Build a per-call ptls_context_t.  Called when the connection needs
 * to override at least one of:
 *   - the verify_certificate handle (caller-supplied trust)
 *   - the certificates / sign_certificate hooks (mTLS material)
 *
 * Returns NULL on allocation failure or when @p auth is non-NULL but
 * malformed.  When both @p auth and @p trust are NULL the caller is
 * expected to skip this path entirely and alias the base ctx
 * directly. */
static per_call_ctx_t *
build_per_call_ctx(const n00b_acme_tls_client_auth_t *auth,
                   n00b_quic_trust_t                 *trust)
{
    if (auth && (!auth->key || auth->cert_chain_count == 0
                 || !auth->cert_chain_der || !auth->cert_chain_lens)) {
        /* Caller passed mTLS material but it's malformed — refuse
         * rather than silently dropping it. */
        return nullptr;
    }
    n00b_acme_tls_state_t *base = get_base_state();
    if (!base) return nullptr;

    per_call_ctx_t *pcctx = n00b_alloc_with_opts(
        per_call_ctx_t,
        &(n00b_alloc_opts_t){.allocator = tls_alloc()});
    pcctx->ctx = base->base_ctx;                  /* shallow copy */

    if (trust != nullptr) {
        /* Populate the per-call verifier and point the per-call ctx
         * at it (overriding the module-shared `the_verifier` for this
         * connection only). */
        pcctx->verifier.super.cb    = acme_verify_cb;
        pcctx->verifier.super.algos = n00b_picotls_supported_sig_algs;
        pcctx->verifier.server_name = nullptr;
        pcctx->verifier.trust       = trust;
        pcctx->ctx.verify_certificate = &pcctx->verifier.super;
    }

    if (auth) {
        if (n00b_picotls_install_client_auth(&pcctx->ctx,
                                             auth->cert_chain_der,
                                             auth->cert_chain_lens,
                                             auth->cert_chain_count,
                                             auth->key,
                                             &pcctx->auth_storage) != 0) {
            return nullptr;
        }
    }
    return pcctx;
}

int
n00b_acme_tls_connect(const char            *host,
                      uint16_t               port,
                      int32_t                timeout_ms,
                      n00b_acme_tls_conn_t **out_conn)
{
    return n00b_acme_tls_connect_ex(host, port, timeout_ms, nullptr,
                                    nullptr, out_conn);
}

int
n00b_acme_tls_connect_ex(const char                       *host,
                         uint16_t                          port,
                         int32_t                           timeout_ms,
                         const n00b_acme_tls_client_auth_t *auth,
                         n00b_quic_trust_t                *trust,
                         n00b_acme_tls_conn_t            **out_conn)
{
    if (!host || !out_conn) return N00B_QUIC_ERR_NULL_ARG;
    *out_conn = nullptr;

    /* Resolve the picotls context.  Three cases:
     *   - any per-call override (mTLS auth and/or caller-supplied
     *     trust): build a per-call ctx that lives alongside the conn.
     *   - default path (no auth, no trust): alias the per-runtime
     *     base ctx with no per-call allocation.  The base ctx routes
     *     verify_certificate through the module-shared `the_verifier`
     *     which consults the OS trust store — byte-identical to the
     *     pre-trust-threading default. */
    per_call_ctx_t *pcctx = nullptr;
    ptls_context_t *ctx_for_new = nullptr;
    if (auth || trust) {
        pcctx = build_per_call_ctx(auth, trust);
        if (!pcctx) return N00B_QUIC_ERR_INVALID_ARG;
        ctx_for_new = &pcctx->ctx;
    } else {
        n00b_acme_tls_state_t *base = get_base_state();
        if (!base) {
            /* The per-runtime base picotls state should always be
             * available once the runtime is initialized.  If it
             * isn't, the runtime is in a bad state (post-shutdown
             * or pre-init) — not a missing-feature condition. */
            return N00B_QUIC_ERR_PROTOCOL;
        }
        ctx_for_new = &base->base_ctx;
    }

    int sockfd = -1;
    int rc     = tcp_connect(host, port, timeout_ms, &sockfd);
    if (rc != N00B_QUIC_OK) return rc;

    n00b_acme_tls_conn_t *c = n00b_alloc_with_opts(
        n00b_acme_tls_conn_t,
        &(n00b_alloc_opts_t){.allocator = tls_alloc()});
    c->sockfd = sockfd;
    c->pcctx  = pcctx;
    ptls_buffer_init(&c->encbuf, c->encbuf_storage,
                      sizeof(c->encbuf_storage));
    ptls_buffer_init(&c->ptbuf, c->ptbuf_storage,
                      sizeof(c->ptbuf_storage));
    c->tls = ptls_new(ctx_for_new, 0);
    if (!c->tls) {
        close(sockfd);
        return N00B_QUIC_ERR_PROTOCOL;
    }
    if (ptls_set_server_name(c->tls, host, 0) != 0) {
        ptls_free(c->tls);
        close(sockfd);
        return N00B_QUIC_ERR_PROTOCOL;
    }

    int64_t deadline = now_ms() + timeout_ms;

    /* Kick off ClientHello. */
    int phs_rc = ptls_handshake(c->tls, &c->encbuf,
                                 nullptr, nullptr, nullptr);
    if (phs_rc != PTLS_ERROR_IN_PROGRESS && phs_rc != 0) {
        ptls_free(c->tls);
        close(sockfd);
        return N00B_QUIC_ERR_HANDSHAKE;
    }

    rc = do_handshake_until_done(c, deadline);
    if (rc != N00B_QUIC_OK) {
        ptls_buffer_dispose(&c->encbuf);
        ptls_buffer_dispose(&c->ptbuf);
        ptls_free(c->tls);
        close(sockfd);
        return rc;
    }
    *out_conn = c;
    return N00B_QUIC_OK;
}

/* Drives the handshake to completion + flushes any pending records.
 * Stashes any post-handshake application data into c->recv_pending. */
static int
do_handshake_until_done(n00b_acme_tls_conn_t *c, int64_t deadline)
{
    while (!c->handshake_done) {
        int64_t now = now_ms();
        if (now >= deadline) return N00B_QUIC_ERR_TIMEOUT;

        if (c->encbuf.off > 0) {
            int srv = flush_send(c->sockfd, &c->encbuf,
                                  (int32_t)(deadline - now));
            if (srv != N00B_QUIC_OK) return srv;
        }

        struct pollfd pfd = {.fd = c->sockfd, .events = POLLIN};
        int           pr  = poll(&pfd, 1, (int)(deadline - now_ms()));
        if (pr < 0) {
            if (errno == EINTR) continue;
            return N00B_QUIC_ERR_PROTOCOL;
        }
        if (pr == 0) return N00B_QUIC_ERR_TIMEOUT;

        uint8_t buf[16384];
        ssize_t n = recv(c->sockfd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK
                || errno == EINTR) continue;
            return N00B_QUIC_ERR_PROTOCOL;
        }
        if (n == 0) return N00B_QUIC_ERR_HANDSHAKE;

        size_t consumed = 0;
        while (consumed < (size_t)n) {
            size_t insz = (size_t)n - consumed;
            int    phs_rc;
            if (!c->handshake_done) {
                phs_rc = ptls_handshake(c->tls, &c->encbuf,
                                         buf + consumed, &insz, nullptr);
                consumed += insz;
                if (phs_rc == 0) {
                    c->handshake_done = true;
                } else if (phs_rc == PTLS_ERROR_IN_PROGRESS) {
                    /* keep going */
                } else {
                    return (phs_rc == PTLS_ALERT_BAD_CERTIFICATE
                             || phs_rc == PTLS_ALERT_CERTIFICATE_UNKNOWN
                             || phs_rc == PTLS_ALERT_UNKNOWN_CA)
                            ? N00B_QUIC_ERR_TRUST_REJECTED
                            : N00B_QUIC_ERR_HANDSHAKE;
                }
            } else {
                /* Post-handshake app data — stash for the first recv. */
                int rr = ptls_receive(c->tls, &c->ptbuf,
                                       buf + consumed, &insz);
                consumed += insz;
                if (c->ptbuf.off > 0) {
                    n00b_buffer_t *piece = n00b_buffer_from_bytes(
                        (char *)c->ptbuf.base, (int64_t)c->ptbuf.off,
                        .allocator = tls_alloc());
                    if (!c->recv_pending) {
                        c->recv_pending = n00b_buffer_empty(
                            .allocator = tls_alloc());
                    }
                    n00b_buffer_concat(c->recv_pending, piece);
                    c->ptbuf.off = 0;
                }
                if (rr != 0 && rr != PTLS_ERROR_IN_PROGRESS) {
                    return N00B_QUIC_ERR_PROTOCOL;
                }
            }
        }
    }
    /* Flush any post-handshake-finished encrypted bytes. */
    if (c->encbuf.off > 0) {
        int64_t now = now_ms();
        if (now >= deadline) return N00B_QUIC_ERR_TIMEOUT;
        int srv = flush_send(c->sockfd, &c->encbuf,
                              (int32_t)(deadline - now));
        if (srv != N00B_QUIC_OK) return srv;
    }
    return N00B_QUIC_OK;
}

int
n00b_acme_tls_send(n00b_acme_tls_conn_t *c,
                   n00b_buffer_t        *bytes,
                   int32_t               timeout_ms)
{
    if (!c || !bytes) return N00B_QUIC_ERR_NULL_ARG;
    if (!c->handshake_done) return N00B_QUIC_ERR_PROTOCOL;
    int64_t deadline = now_ms() + timeout_ms;

    /* Own the plaintext for the duration of the encrypt. `bytes` is a
     * GC-managed n00b_buffer_t; handing its ->data straight to ptls_send let the
     * GC move/reclaim it out from under the AES-GCM encrypt on this (worker)
     * thread — the observed SIGSEGV in cifra xor_bb. Copy into a local picotls
     * buffer (non-GC, stack-backed; grows on the heap only if the payload
     * exceeds the inline storage) so the encryptor reads stable memory, then
     * dispose it on EVERY path so the owned copy can never leak. This is the
     * copy the conduit transport will eventually own; for now it lives here. */
    int sr;
    if (bytes->byte_len <= 0) {
        sr = ptls_send(c->tls, &c->encbuf, "", 0);
    }
    else {
        ptls_buffer_t pt;
        uint8_t       pt_storage[4096];
        ptls_buffer_init(&pt, pt_storage, sizeof(pt_storage));
        if (ptls_buffer__do_pushv(&pt, bytes->data, (size_t)bytes->byte_len)
            != 0) {
            ptls_buffer_dispose(&pt); /* frees any heap growth */
            return N00B_QUIC_ERR_PROTOCOL;
        }
        sr = ptls_send(c->tls, &c->encbuf, pt.base, pt.off);
        ptls_buffer_dispose(&pt); /* release the owned plaintext copy */
    }
    if (sr != 0) return N00B_QUIC_ERR_PROTOCOL;

    int64_t now = now_ms();
    if (now >= deadline) return N00B_QUIC_ERR_TIMEOUT;
    return flush_send(c->sockfd, &c->encbuf,
                       (int32_t)(deadline - now));
}

int
n00b_acme_tls_recv(n00b_acme_tls_conn_t  *c,
                   size_t                 max,
                   n00b_buffer_t        **out_chunk,
                   bool                  *peer_closed,
                   int32_t                timeout_ms)
{
    if (!c || !out_chunk) return N00B_QUIC_ERR_NULL_ARG;
    if (peer_closed) *peer_closed = false;
    *out_chunk = n00b_buffer_empty(.allocator = tls_alloc());

    /* If we already have stashed plaintext, hand back as much as
     * the caller asked for. */
    if (c->recv_pending) {
        size_t avail = (size_t)c->recv_pending->byte_len
                        - c->recv_consumed;
        if (avail > 0) {
            size_t give = avail < max ? avail : max;
            n00b_buffer_t *slice = n00b_buffer_from_bytes(
                c->recv_pending->data + c->recv_consumed,
                (int64_t)give, .allocator = tls_alloc());
            n00b_buffer_concat(*out_chunk, slice);
            c->recv_consumed += give;
            if (c->recv_consumed >= (size_t)c->recv_pending->byte_len) {
                c->recv_pending  = nullptr;
                c->recv_consumed = 0;
            }
            return N00B_QUIC_OK;
        }
        c->recv_pending  = nullptr;
        c->recv_consumed = 0;
    }

    if (c->peer_eof) {
        if (peer_closed) *peer_closed = true;
        return N00B_QUIC_OK;
    }

    int64_t deadline = now_ms() + timeout_ms;
    /* Wait + read one batch of encrypted bytes. */
    int64_t now = now_ms();
    if (now >= deadline) return N00B_QUIC_ERR_TIMEOUT;
    struct pollfd pfd = {.fd = c->sockfd, .events = POLLIN};
    int           pr  = poll(&pfd, 1, (int)(deadline - now));
    if (pr < 0) return N00B_QUIC_ERR_PROTOCOL;
    if (pr == 0) return N00B_QUIC_ERR_TIMEOUT;

    uint8_t buf[16384];
    ssize_t n = recv(c->sockfd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return N00B_QUIC_ERR_TIMEOUT;
        }
        return N00B_QUIC_ERR_PROTOCOL;
    }
    if (n == 0) {
        c->peer_eof = true;
        if (peer_closed) *peer_closed = true;
        return N00B_QUIC_OK;
    }

    size_t consumed = 0;
    while (consumed < (size_t)n) {
        size_t insz = (size_t)n - consumed;
        int rr = ptls_receive(c->tls, &c->ptbuf,
                               buf + consumed, &insz);
        consumed += insz;
        if (c->ptbuf.off > 0) {
            size_t available = c->ptbuf.off;
            size_t give = available < max ? available : max;
            n00b_buffer_t *piece = n00b_buffer_from_bytes(
                (char *)c->ptbuf.base, (int64_t)give,
                .allocator = tls_alloc());
            n00b_buffer_concat(*out_chunk, piece);
            if (give < available) {
                /* Stash the remainder for the next recv. */
                size_t left = available - give;
                if (!c->recv_pending) {
                    c->recv_pending = n00b_buffer_empty(
                        .allocator = tls_alloc());
                }
                n00b_buffer_t *rest = n00b_buffer_from_bytes(
                    (char *)c->ptbuf.base + give, (int64_t)left,
                    .allocator = tls_alloc());
                n00b_buffer_concat(c->recv_pending, rest);
            }
            c->ptbuf.off = 0;
            max -= give;
        }
        if (rr == 0 || rr == PTLS_ERROR_IN_PROGRESS) continue;
        if (rr == PTLS_ALERT_TO_PEER_ERROR(PTLS_ALERT_CLOSE_NOTIFY)) {
            c->peer_eof = true;
            if (peer_closed) *peer_closed = true;
            return N00B_QUIC_OK;
        }
        return N00B_QUIC_ERR_PROTOCOL;
    }
    return N00B_QUIC_OK;
}

void
n00b_acme_tls_close(n00b_acme_tls_conn_t *c)
{
    if (!c) return;
    if (c->encbuf.off > 0 && c->sockfd >= 0) {
        (void)flush_send(c->sockfd, &c->encbuf, 100);
    }
    ptls_buffer_dispose(&c->encbuf);
    ptls_buffer_dispose(&c->ptbuf);
    if (c->tls) ptls_free(c->tls);
    if (c->sockfd >= 0) close(c->sockfd);
    c->sockfd = -1;
    c->tls    = nullptr;
}

bool
n00b_acme_tls_alive(n00b_acme_tls_conn_t *c)
{
    if (!c || c->sockfd < 0 || c->peer_eof) return false;
    /* Non-blocking peek: if recv() returns 0 the peer FIN'd; if it
     * returns -1 with EAGAIN we have no data but the socket is OK. */
    char    peek[1];
    ssize_t r = recv(c->sockfd, peek, 1, MSG_PEEK | MSG_DONTWAIT);
    if (r == 0) return false;
    if (r > 0)  return true;          /* data waiting; peer alive */
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

/* =========================================================================
 * Original round-trip — refactored on top of the primitives.
 * ========================================================================= */

int
n00b_acme_tls_round_trip(const char     *host,
                         uint16_t        port,
                         n00b_buffer_t  *request,
                         n00b_buffer_t **response_out,
                         int32_t         timeout_ms)
{
    if (!host || !request || !response_out) {
        return N00B_QUIC_ERR_NULL_ARG;
    }
    *response_out = nullptr;

    n00b_acme_tls_conn_t *c = nullptr;
    int rc = n00b_acme_tls_connect(host, port, timeout_ms, &c);
    if (rc != N00B_QUIC_OK) return rc;

    int64_t deadline = now_ms() + timeout_ms;

    rc = n00b_acme_tls_send(c, request,
                             (int32_t)(deadline - now_ms()));
    if (rc != N00B_QUIC_OK) {
        n00b_acme_tls_close(c);
        return rc;
    }

    n00b_buffer_t *response = n00b_buffer_empty(.allocator = tls_alloc());
    while (true) {
        int64_t now = now_ms();
        if (now >= deadline) {
            n00b_acme_tls_close(c);
            return N00B_QUIC_ERR_TIMEOUT;
        }
        n00b_buffer_t *chunk = nullptr;
        bool           closed = false;
        rc = n00b_acme_tls_recv(c, 64 * 1024, &chunk, &closed,
                                 (int32_t)(deadline - now));
        if (rc != N00B_QUIC_OK) {
            n00b_acme_tls_close(c);
            return rc;
        }
        if (chunk && chunk->byte_len > 0) {
            n00b_buffer_concat(response, chunk);
        }
        if (closed) break;
    }
    n00b_acme_tls_close(c);
    *response_out = response;
    return N00B_QUIC_OK;
}


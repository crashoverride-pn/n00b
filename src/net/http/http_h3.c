/*
 * http_h3.c — HTTP/3 transport for the n00b HTTP client.
 *
 * Phase 6 chunks 3 + 4.  Single round-trip primitive over the
 * existing picoquic-backed QUIC + H3 stack, optionally backed by
 * the chunk-4 connection pool: when callers pass a `pool` kwarg we
 * try `acquire(origin, H3)` first and fall through to a fresh
 * endpoint + connection + h3 client only on miss.  Successful
 * round-trips return the (conduit, io, endpoint, conn, h3_client)
 * tuple to the pool so subsequent requests for the same origin
 * skip the QUIC handshake.
 *
 * Layout:
 *   §1   DNS resolution (getaddrinfo wrapper)
 *   §2   Round-trip driver
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/dns.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "net/quic/h3.h"
#include "net/quic/h3_types.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_h1.h"
#include "internal/net/http/http_h3.h"
#include "internal/net/http/http_pool.h"
#include "internal/crypto/picotls_certverify.h"
#include "internal/crypto/picotls_verify.h"
#include "internal/net/quic/endpoint_internal.h"
#include "net/http/http_auth.h"

/* ===========================================================================
 * §1   DNS resolution
 *
 * Resolves @p host to a single sockaddr_storage, preferring IPv4 to
 * keep the Phase-6 reach-set wide on networks where the local
 * IPv6 path is broken (Happy Eyeballs v2 is a deferred phase-7
 * candidate).  IPv6 literals from the URL parser bypass DNS entirely.
 * =========================================================================== */

static int
resolve_host(n00b_http_url_t        *url,
             struct sockaddr_storage *out,
             socklen_t              *outlen)
{
    memset(out, 0, sizeof(*out));

    if (url->is_ipv6_literal) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)out;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port   = htons(url->port);
        if (inet_pton(AF_INET6, url->host->data, &sa6->sin6_addr) != 1) {
            return -1;
        }
        *outlen = sizeof(*sa6);
        return 0;
    }

    /* IPv4 dotted-quad fast path — no DNS round-trip needed. */
    struct sockaddr_in sa4 = {0};
    if (inet_pton(AF_INET, url->host->data, &sa4.sin_addr) == 1) {
        sa4.sin_family = AF_INET;
        sa4.sin_port   = htons(url->port);
        memcpy(out, &sa4, sizeof(sa4));
        *outlen = sizeof(sa4);
        return 0;
    }

    /* Hostname → DNS, via n00b's libc-free UDP resolver. getaddrinfo's
     * internal libc malloc traps on n00b worker threads under the off-libc
     * runtime, so the system resolver cannot be used off the main thread. */
    n00b_resolved_addr_t addrs[8];
    int                  naddr = n00b_dns_resolve_addrs(
        url->host, url->port, addrs,
        (int)(sizeof(addrs) / sizeof(addrs[0])));
    if (naddr <= 0) {
        return -1;
    }
    /* Prefer IPv4 if present (see header comment). */
    int pick = 0;
    for (int i = 0; i < naddr; i++) {
        if (addrs[i].ss.ss_family == AF_INET) {
            pick = i;
            break;
        }
    }
    if ((size_t)addrs[pick].len > sizeof(*out)) {
        return -1;
    }
    memcpy(out, &addrs[pick].ss, addrs[pick].len);
    *outlen = addrs[pick].len;
    return 0;
}

/* ===========================================================================
 * §2   Round-trip driver
 *
 * Default path (no `pool` kwarg) builds a fresh conduit + endpoint
 * + connection + h3 client per call and tears them down at the end.
 * Pooled path (with `pool` kwarg) tries `acquire` first; on hit
 * reuses the cached tuple, on miss does the same fresh build but
 * `release`s the tuple back into the pool when the round-trip
 * completes cleanly.
 * =========================================================================== */

static n00b_h3_header_t *
build_extra_headers(n00b_http_h1_headers_t *extra,
                    const char             *content_type,
                    bool                    have_body,
                    size_t                 *n_out,
                    n00b_allocator_t       *allocator)
{
    /* Caller-supplied headers + an optional Content-Type when the
     * caller didn't supply one.  Content-Length is implicit in H3
     * (DATA-frame payload size); never emitted as a header. */
    size_t base = extra ? n00b_http_h1_headers_len(extra) : 0;
    bool   add_ct = have_body && content_type
                    && !(extra && n00b_http_h1_headers_get_cstr(
                                       extra, "content-type"));
    size_t total = base + (add_ct ? 1 : 0);
    if (total == 0) {
        *n_out = 0;
        return nullptr;
    }
    n00b_h3_header_t *out = n00b_alloc_array(n00b_h3_header_t, total,
                                              .allocator = allocator);
    size_t k = 0;
    if (add_ct) {
        out[k].name      = (const uint8_t *)"content-type";
        out[k].name_len  = strlen("content-type");
        out[k].value     = (const uint8_t *)content_type;
        out[k].value_len = strlen(content_type);
        k++;
    }
    for (size_t i = 0; i < base; i++) {
        const char *name;
        const char *value;
        if (!n00b_http_h1_headers_at(extra, i, &name, &value)) continue;
        out[k].name      = (const uint8_t *)name;
        out[k].name_len  = strlen(name);
        out[k].value     = (const uint8_t *)value;
        out[k].value_len = strlen(value);
        k++;
    }
    *n_out = k;
    return out;
}

/* ===========================================================================
 * Pool entry — keeps the (conduit, io, endpoint, conn, h3_client) tuple
 * alive across requests.  When a request completes cleanly (status > 0,
 * no transport error, conn still CONNECTED), the entry returns to the
 * pool.  Otherwise it gets closed via `h3_pool_entry_close` which tears
 * down all five components in reverse-construction order.
 * =========================================================================== */
typedef struct {
    n00b_conduit_t                     *c;
    n00b_conduit_io_backend_t          *io;
    n00b_quic_endpoint_t               *ep;
    n00b_quic_conn_t                   *conn;
    n00b_h3_client_t                   *h3;
    /* When this connection was opened with mTLS material, the
     * sign_certificate storage installed on the picoquic master ctx
     * lives here.  The picotls context keeps a raw pointer to
     * `&signer_storage->super`, so the storage's lifetime must match
     * the endpoint's — keeping it on the pool entry achieves that.
     * NULL for non-mTLS connections. */
    n00b_picotls_client_auth_storage_t *signer_storage;
} n00b_http_h3_pool_entry_t;

static void
h3_pool_entry_close(void *user_data)
{
    n00b_http_h3_pool_entry_t *e = (n00b_http_h3_pool_entry_t *)user_data;
    if (!e) return;
    if (e->h3)   n00b_h3_client_close(e->h3);
    if (e->conn) n00b_quic_close(e->conn, 0);
    if (e->ep)   n00b_quic_endpoint_close(e->ep);
    if (e->io)   n00b_conduit_io_destroy(e->io);
    if (e->c)    n00b_conduit_destroy(e->c);
}

n00b_result_t(n00b_h3_response_t *)
n00b_http_h3_round_trip(n00b_http_url_t *url)
    _kargs {
        const char                  *method       = "GET";
        n00b_buffer_t               *body         = nullptr;
        const char                  *content_type = nullptr;
        n00b_http_h1_headers_t      *extra        = nullptr;
        int32_t                      handshake_ms = 1500;
        int32_t                      await_ms     = 30000;
        n00b_quic_trust_t           *trust        = nullptr;
        n00b_http_connection_pool_t *pool         = nullptr;
        n00b_http_auth_t            *auth         = nullptr;
        /** Per-call response-body byte cap.  Default 0 = no cap.
         *  See @c http_h3.h prose above for the symmetry note. */
        uint64_t                     max_body_size = 0;
        n00b_allocator_t            *allocator    = nullptr;
    }
{
    if (!url) {
        return n00b_result_err(n00b_h3_response_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    n00b_allocator_t *a = allocator
        ? allocator
        : (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    /* mTLS active when the auth helper has BOTH a key AND a chain.
     * Same shape as h1's check. */
    bool mtls_active = auth && auth->mtls_key
                       && auth->mtls_cert_chain_der
                       && auth->mtls_cert_chain_count > 0
                       && auth->mtls_cert_chain_lens;

    /* Pool bucket key includes a per-auth subkey so two requests with
     * different mTLS identities don't share a pooled connection.
     * Matches the h1 path's `bucket_origin` shaping. */
    n00b_string_t *bucket_origin = url->origin;
    if (auth) {
        char auth_tag[40];
        snprintf(auth_tag, sizeof(auth_tag), "|auth=%p", (void *)auth);
        size_t orig_len = url->origin->u8_bytes;
        size_t tag_len  = strlen(auth_tag);
        char *buf = n00b_alloc_array(char, orig_len + tag_len + 1,
                                     .allocator = a);
        memcpy(buf, url->origin->data, orig_len);
        memcpy(buf + orig_len, auth_tag, tag_len);
        buf[orig_len + tag_len] = '\0';
        bucket_origin = n00b_string_from_raw(buf,
                                             (int64_t)(orig_len + tag_len),
                                             .allocator = a);
    }

    n00b_conduit_t            *c    = nullptr;
    n00b_conduit_io_backend_t *io   = nullptr;
    n00b_quic_endpoint_t      *ep   = nullptr;
    n00b_quic_conn_t          *conn = nullptr;
    n00b_h3_client_t          *h3   = nullptr;
    bool                       reused = false;
    /* When mTLS is active, this holds the sign_certificate storage
     * pinned on the picoquic master ctx.  Either freshly allocated
     * on the connect path or carried over from the acquired pool
     * entry on the reuse path. */
    n00b_picotls_client_auth_storage_t *signer_storage = nullptr;

    /* Try the pool first. */
    if (pool) {
        n00b_http_h3_pool_entry_t *e =
            (n00b_http_h3_pool_entry_t *)
            n00b_http_connection_pool_acquire(
                pool, bucket_origin, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H3);
        if (e) {
            /* Validate the pooled connection still looks alive. */
            n00b_quic_conn_state_t st = n00b_quic_conn_state(e->conn);
            if (st == N00B_QUIC_CONN_STATE_CONNECTED) {
                c    = e->c;
                io   = e->io;
                ep   = e->ep;
                conn = e->conn;
                h3   = e->h3;
                signer_storage = e->signer_storage;
                reused = true;
            } else {
                /* Stale — drop it. */
                h3_pool_entry_close(e);
            }
        }
    }

    if (!reused) {
        /* Resolve target. */
        struct sockaddr_storage dst;
        socklen_t               dstlen = 0;
        if (resolve_host(url, &dst, &dstlen) != 0) {
            return n00b_result_err(n00b_h3_response_t *,
                                   N00B_QUIC_ERR_BIND_FAILED);
        }

        auto cr = n00b_conduit_new();
        if (n00b_result_is_err(cr)) {
            return n00b_result_err(n00b_h3_response_t *,
                                   n00b_result_get_err(cr));
        }
        c = n00b_result_get(cr);

        auto ir = n00b_conduit_io_new_default(c);
        if (n00b_result_is_err(ir)) {
            n00b_conduit_destroy(c);
            return n00b_result_err(n00b_h3_response_t *,
                                   n00b_result_get_err(ir));
        }
        io = n00b_result_get(ir);

        /* Client endpoint with ALPN = "h3". */
        auto er = n00b_quic_endpoint_new(c, io,
                                         .alpn  = N00B_H3_ALPN,
                                         .trust = trust);
        if (n00b_result_is_err(er)) {
            int err = (int)n00b_result_get_err(er);
            n00b_conduit_io_destroy(io);
            n00b_conduit_destroy(c);
            return n00b_result_err(n00b_h3_response_t *, err);
        }
        ep = n00b_result_get(er);

        /* Install client-side mTLS material on the picoquic master ctx
         * BEFORE n00b_quic_connect — picotls reads the ctx during the
         * very first handshake flight, so the sign_certificate +
         * certificates fields must be set ahead of time.  The
         * signer_storage must outlive the picoquic ctx; we allocate
         * from conduit_pool and the pool entry pins it later so
         * pooled reuse keeps the storage alive. */
        if (mtls_active) {
            signer_storage = n00b_alloc_with_opts(
                n00b_picotls_client_auth_storage_t,
                &(n00b_alloc_opts_t){.allocator = a});
            int crc = n00b_quic_picotls_install_client_auth(
                ep->quic,
                auth->mtls_cert_chain_der,
                auth->mtls_cert_chain_lens,
                auth->mtls_cert_chain_count,
                auth->mtls_key,
                signer_storage);
            if (crc != N00B_QUIC_OK) {
                n00b_quic_endpoint_close(ep);
                n00b_conduit_io_destroy(io);
                n00b_conduit_destroy(c);
                return n00b_result_err(n00b_h3_response_t *, crc);
            }
        }

        auto rr = n00b_quic_connect(ep, (const struct sockaddr *)&dst,
                                    url->host);
        if (n00b_result_is_err(rr)) {
            int err = (int)n00b_result_get_err(rr);
            n00b_quic_endpoint_close(ep);
            n00b_conduit_io_destroy(io);
            n00b_conduit_destroy(c);
            return n00b_result_err(n00b_h3_response_t *, err);
        }
        conn = n00b_result_get(rr);

        /* Drive the handshake within the deadline. */
        int  iters     = (handshake_ms / 5) + 1;
        bool connected = false;
        bool hs_failed = false;
        for (int i = 0; i < iters; i++) {
            n00b_quic_endpoint_run_once(ep, 5);
            n00b_quic_conn_state_t st = n00b_quic_conn_state(conn);
            if (st == N00B_QUIC_CONN_STATE_CONNECTED) {
                connected = true;
                break;
            }
            if (st == N00B_QUIC_CONN_STATE_FAILED
                || st == N00B_QUIC_CONN_STATE_CLOSED) {
                hs_failed = true;
                break;
            }
        }
        if (!connected) {
            int err = hs_failed ? N00B_QUIC_ERR_HANDSHAKE
                                : N00B_QUIC_ERR_TIMEOUT;
            n00b_quic_close(conn, 0);
            n00b_quic_endpoint_close(ep);
            n00b_conduit_io_destroy(io);
            n00b_conduit_destroy(c);
            return n00b_result_err(n00b_h3_response_t *, err);
        }

        /* H3 client + initial drive iterations to flush SETTINGS. */
        auto hr = n00b_h3_client_new(conn);
        if (n00b_result_is_err(hr)) {
            int err = (int)n00b_result_get_err(hr);
            n00b_quic_close(conn, 0);
            n00b_quic_endpoint_close(ep);
            n00b_conduit_io_destroy(io);
            n00b_conduit_destroy(c);
            return n00b_result_err(n00b_h3_response_t *, err);
        }
        h3 = n00b_result_get(hr);
        for (int i = 0; i < 30; i++) {
            n00b_quic_endpoint_run_once(ep, 5);
            n00b_h3_client_drive(h3);
        }
    }

    /* Build authority + path for the request.  Authority is exactly
     * the form servers expect on the `:authority` pseudo-header:
     * `host[:port]`, with the port omitted when implicit and IPv6
     * hosts re-bracketed. */
    char authority[256];
    {
        bool needs_port = url->has_explicit_port && url->port != 443;
        if (url->is_ipv6_literal && needs_port) {
            snprintf(authority, sizeof(authority), "[%s]:%u",
                     url->host->data, (unsigned)url->port);
        } else if (url->is_ipv6_literal) {
            snprintf(authority, sizeof(authority), "[%s]",
                     url->host->data);
        } else if (needs_port) {
            snprintf(authority, sizeof(authority), "%s:%u",
                     url->host->data, (unsigned)url->port);
        } else {
            snprintf(authority, sizeof(authority), "%s",
                     url->host->data);
        }
    }

    char path_buf[2048];
    {
        const char *p = url->path && url->path->u8_bytes
                            ? url->path->data : "/";
        if (url->query && url->query->u8_bytes > 0) {
            snprintf(path_buf, sizeof(path_buf), "%s?%s",
                     p, url->query->data);
        } else {
            snprintf(path_buf, sizeof(path_buf), "%s", p);
        }
    }

    size_t            n_extra = 0;
    n00b_h3_header_t *xhdrs   = build_extra_headers(extra, content_type,
                                                     body != nullptr,
                                                     &n_extra, a);

    /* Helper-style cleanup pulled into a single block so both error
     * paths and the success path can pick "tear down" or "return to
     * pool" uniformly.  `signer_storage` is carried through so the
     * picotls ctx's pointer into it stays valid for the conn's
     * lifetime (including when reused from the pool). */
    n00b_http_h3_pool_entry_t entry_storage = {
        .c = c, .io = io, .ep = ep, .conn = conn, .h3 = h3,
        .signer_storage = signer_storage,
    };

    auto reqr = n00b_h3_client_request(
        h3,
        (n00b_h3_request_spec_t){
            .method    = method,
            .authority = authority,
            .path      = path_buf,
            .headers   = { .items = xhdrs, .count = n_extra },
            .body      = body ? (const uint8_t *)body->data : nullptr,
            .body_len  = body ? (size_t)body->byte_len : 0,
        });
    if (n00b_result_is_err(reqr)) {
        int err = (int)n00b_result_get_err(reqr);
        h3_pool_entry_close(&entry_storage);
        return n00b_result_err(n00b_h3_response_t *, err);
    }
    n00b_h3_request_t *req = n00b_result_get(reqr);

    auto respr = n00b_h3_request_await(req,
                                       .deadline_ms   = await_ms,
                                       .max_body_size = max_body_size);
    if (n00b_result_is_err(respr)) {
        int err = (int)n00b_result_get_err(respr);
        /* Mid-stream cap enforcement: the receive loop reset the
         * stream with `H3_EXCESSIVE_LOAD` before the body could
         * accumulate past the cap.  `n00b_h3_request_await` returned
         * `LOCAL_RESET`; the request flag tells us this was a cap
         * trip (vs. some other local reset).  Translate to the
         * HTTP-layer code so callers see identical semantics across
         * h1 and h3. */
        if (max_body_size > 0
            && err == N00B_QUIC_ERR_LOCAL_RESET
            && n00b_h3_request_body_cap_exceeded(req)) {
            h3_pool_entry_close(&entry_storage);
            return n00b_result_err(n00b_h3_response_t *,
                                    N00B_HTTP_ERR_RESPONSE_TOO_LARGE);
        }
        h3_pool_entry_close(&entry_storage);
        return n00b_result_err(n00b_h3_response_t *, err);
    }
    n00b_h3_response_t *resp = n00b_result_get(respr);

    /* Per-call response-body cap backstop (DF-014).  The mid-stream
     * guard inside `n00b_h3_request_await` is the primary enforcement
     * point — it resets the stream before the body grows past the cap
     * and surfaces `RESPONSE_TOO_LARGE` via the LOCAL_RESET path above.
     * This post-await check stays as a defensive backstop: if a future
     * change to the body-receive loop fails to trip the mid-stream
     * guard for some reason (frame batching, off-by-one, etc.), the
     * cap still fires here.  Cost is one comparison against an already-
     * materialized buffer length. */
    if (max_body_size > 0 && resp && resp->body
        && (uint64_t)resp->body->byte_len > max_body_size) {
        h3_pool_entry_close(&entry_storage);
        return n00b_result_err(n00b_h3_response_t *,
                                N00B_HTTP_ERR_RESPONSE_TOO_LARGE);
    }

    /* Decide: pool the connection, or close it.
     *
     * We require the QUIC conn to still be CONNECTED (no GOAWAY, no
     * idle-timer fired) and the response to look healthy.  If the pool
     * kwarg is null we always close; that matches how h1 handles the
     * no-pool case so callers get identical lifecycle semantics. */
    bool conn_alive = (n00b_quic_conn_state(conn)
                       == N00B_QUIC_CONN_STATE_CONNECTED);
    if (pool && conn_alive) {
        n00b_http_h3_pool_entry_t *e = n00b_alloc_with_opts(
            n00b_http_h3_pool_entry_t,
            &(n00b_alloc_opts_t){.allocator = a});
        *e = entry_storage;
        n00b_http_connection_pool_release(
            pool, bucket_origin, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H3,
            e, h3_pool_entry_close);
    } else {
        h3_pool_entry_close(&entry_storage);
    }

    return n00b_result_ok(n00b_h3_response_t *, resp);
}

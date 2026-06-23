/*
 * xform_tls.c — conduit-native TLS-1.3 client transport.
 *
 * Two transforms sharing one `ptls_t`, wired as ordinary conduit pipeline
 * stages so plaintext rides `n00b_write` / `n00b_read` and the conduit owns
 * every buffer across the encrypt/decrypt boundary:
 *
 *   outbound: app -> [write_topic] -> [encrypt xform] -> [ct topic]
 *                 -> [fd_writer] -> tcp fd
 *   inbound:  tcp fd -> [fd read_topic] -> [decrypt xform] -> [read_topic]
 *                 -> app
 *
 * The handshake is driven over the conduit IO during connect (subscribe a
 * temporary inbox to the fd read topic, submit handshake records with
 * `n00b_conduit_fd_write_submit`, pump `ptls_handshake` to completion) BEFORE
 * the two app-data xforms are installed — resolving the unidirectional
 * `T_in -> T_out` xform model against the bidirectional, stateful handshake.
 *
 * Why the acme_tls SIGSEGV class is gone here: acme_tls handed a caller's
 * GC-managed `n00b_buffer_t` straight to `ptls_send`, so the moving collector
 * could relocate the plaintext mid-encrypt on a worker thread.  Here the only
 * place plaintext meets the encryptor is the encrypt xform, which copies into
 * a picotls-owned buffer first — one copy site, always correct, instead of
 * every HTTPS caller having to remember.
 *
 * Built ALONGSIDE acme_tls.c; nothing in acme_tls is removed by this module.
 */

#define N00B_USE_INTERNAL_API
#include <sys/time.h>
#include <arpa/inet.h>

#include "picotls.h"
#include "picotls/minicrypto.h"

#include "n00b.h"
#include "conduit/xform_tls.h"
#include "conduit/conduit.h"
#include "conduit/socket.h"
#include "conduit/fd_managed.h"
#include "conduit/fd_writer.h"
#include "conduit/xform_types.h"
#include "conduit/topic.h"
#include "conduit/rw.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/mutex.h"
#include "core/condition.h"
#include "crypto/trust.h"
#include "net/dns.h"
#include "net/quic/quic_types.h"
#include "internal/crypto/picotls_certverify.h"

/* ===========================================================================
 * Helpers
 * =========================================================================== */

/* The conduit pool is non-moving and not scanned by the collector; picotls
 * therefore never sees a relocatable pointer, and any n00b buffer we keep on
 * the session is itself pinned (so it is not reclaimed even though the pool is
 * not traced).  Same allocator acme_tls uses. */
static n00b_allocator_t *
tls_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static int64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static uint64_t
tls_get_time_cb(ptls_get_time_t *self)
{
    (void)self;
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static ptls_get_time_t the_get_time = {.cb = tls_get_time_cb};

/* Resolve `host` to a dotted-quad IPv4 literal for the conduit TCP connect.
 * n00b_conduit_conn_tcp is AF_INET + inet_pton (numeric only — it does NOT do
 * name resolution), so the transport must resolve here and hand it the literal;
 * the hostname is still used for SNI + cert verification (ptls_set_server_name
 * below).  Resolution goes through n00b's own worker-safe UDP resolver, not
 * getaddrinfo (whose libc malloc traps on n00b worker threads) — the same
 * resolver acme_tls uses.  Literal IPv4 hosts (e.g. the loopback test's
 * "127.0.0.1") bypass DNS inside n00b_dns_resolve_addrs.  Returns nullptr if no
 * IPv4 address resolves (conn_tcp cannot use IPv6 results). */
static n00b_string_t *
tls_resolve_ipv4(n00b_string_t *host, uint16_t port, n00b_allocator_t *a)
{
    n00b_resolved_addr_t addrs[8];
    int n = n00b_dns_resolve_addrs(host, port, addrs,
                                   (int)(sizeof(addrs) / sizeof(addrs[0])));
    for (int i = 0; i < n; i++) {
        if (addrs[i].ss.ss_family != AF_INET) {
            continue;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)&addrs[i].ss;
        char                buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == nullptr) {
            continue;
        }
        return n00b_string_from_cstr(buf, .allocator = a);
    }
    return nullptr;
}

/* ===========================================================================
 * verify_certificate adapter (mirrors acme_tls's, kept local so this module
 * is self-contained and acme_tls is untouched)
 * =========================================================================== */

typedef struct {
    ptls_verify_certificate_t super;
    n00b_quic_trust_t        *trust; /* NULL => native system trust */
} tls_verify_t;

static int
tls_verify_cb(ptls_verify_certificate_t *self_,
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

    tls_verify_t *self = (tls_verify_t *)self_;

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

    n00b_quic_trust_t *trust = self ? self->trust : nullptr;
    if (trust == nullptr) {
        /* Default: native (libc-free) system trust — worker-safe, unlike
         * SecTrust which traps when this cb runs on an n00b worker thread. */
        n00b_result_t(n00b_quic_trust_t *) sr = n00b_quic_trust_native();
        if (n00b_result_is_err(sr)) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        trust = n00b_result_get(sr);
    }

    n00b_result_t(bool) tr = n00b_quic_trust_verify(trust, ptrs, lens,
                                                    num_certs, server_name);
    if (n00b_result_is_err(tr)) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    /* Install the CertificateVerify check — without it picotls silently
     * accepts any CertificateVerify, making auth trivially bypassable. */
    int vrc = n00b_picotls_install_verify_sign(verify_sign, verify_data,
                                               certs[0].base, certs[0].len);
    if (vrc != 0) return vrc;
    return 0;
}

/* ===========================================================================
 * Session
 * =========================================================================== */

struct n00b_conduit_tls_t {
    n00b_conduit_t            *conduit;
    n00b_conduit_io_backend_t *io;
    n00b_conduit_conn_t       *conn;
    n00b_conduit_fd_owner_t   *owner;
    n00b_string_t             *host;
    n00b_allocator_t          *allocator;

    /* picotls.  ctx + verifier are embedded so their addresses stay pinned
     * for the ptls_t's back-references for the session's lifetime. */
    ptls_context_t  ctx;
    tls_verify_t    verifier;
    ptls_t         *tls;

    /* Serializes ptls_send (encrypt worker) against ptls_receive (decrypt
     * worker) on the one shared ptls_t.  In steady-state TLS 1.3 the enc/dec
     * halves are independent, but a peer KeyUpdate request arrives on the recv
     * path and mutates send state, so the two cannot run unguarded. */
    n00b_mutex_t crypto_lock;

    /* Plaintext topics the app drives. write_topic is created explicitly here;
     * read_topic IS the decrypt xform's auto-created output topic. */
    n00b_conduit_topic_t(n00b_buffer_t *) *write_topic;
    n00b_conduit_topic_t(n00b_buffer_t *) *read_topic;

    n00b_conduit_filter_t(n00b_buffer_t *) *encrypt;
    n00b_conduit_filter_t(n00b_buffer_t *) *decrypt;
    n00b_conduit_filter_t(n00b_buffer_t *) *fdwriter;

    /* Post-handshake plaintext that arrived interleaved with the server's
     * Finished / NewSessionTicket records during connect; emitted by the
     * decrypt xform before any freshly-decrypted bytes. */
    n00b_buffer_t   *recv_pending;
    _Atomic(bool)    pending_emitted;

    _Atomic(bool) ready;
    _Atomic(bool) closed;
};

/* Per-xform cookie: a back-pointer to the shared session. */
typedef struct {
    n00b_conduit_tls_t *session;
} tls_link_state_t;

/* ===========================================================================
 * Encrypt xform: plaintext -> ptls_send -> ciphertext (-> fd_writer -> fd)
 * =========================================================================== */

static n00b_option_t(n00b_buffer_t *)
tls_encrypt_transform(n00b_conduit_filter_t(n00b_buffer_t *) *xf,
                      n00b_buffer_t *input)
{
    tls_link_state_t   *st = n00b_conduit_xform_cookie(n00b_buffer_t *,
                                                       n00b_buffer_t *, xf);
    n00b_conduit_tls_t *s  = st->session;

    if (!input || input->byte_len <= 0) {
        return n00b_option_none(n00b_buffer_t *);
    }

    /* Copy plaintext into picotls-owned storage BEFORE the encrypt so the
     * collector can never relocate it mid-AES-GCM on this worker thread.
     * This is the single copy site that retires the acme_tls crash class. */
    ptls_buffer_t pt;
    uint8_t       pt_storage[4096];
    ptls_buffer_init(&pt, pt_storage, sizeof(pt_storage));
    if (ptls_buffer__do_pushv(&pt, input->data, (size_t)input->byte_len) != 0) {
        ptls_buffer_dispose(&pt);
        return n00b_option_none(n00b_buffer_t *);
    }
    /* The plaintext is now in picotls-owned storage; release the conduit-owned
     * copy (delivered via n00b_conduit_tls_write) — "freed after delivered". */
    n00b_free(input);

    ptls_buffer_t enc;
    uint8_t       enc_storage[4096];
    ptls_buffer_init(&enc, enc_storage, sizeof(enc_storage));

    n00b_mutex_lock(&s->crypto_lock);
    int sr = ptls_send(s->tls, &enc, pt.base, pt.off);
    n00b_mutex_unlock(&s->crypto_lock);

    ptls_buffer_dispose(&pt);

    if (sr != 0 || enc.off == 0) {
        ptls_buffer_dispose(&enc);
        return n00b_option_none(n00b_buffer_t *);
    }

    /* Hand the ciphertext to the conduit (pool-owned); fd_writer copies it
     * again into the fd owner's write queue. */
    n00b_buffer_t *ct = n00b_buffer_from_bytes((char *)enc.base,
                                               (int64_t)enc.off,
                                               .allocator = tls_alloc());
    ptls_buffer_dispose(&enc);

    return n00b_option_set(n00b_buffer_t *, ct);
}

static n00b_string_t tls_encrypt_kind = {
    .data = "tls-encrypt", .u8_bytes = 11, .codepoints = 11, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(n00b_buffer_t *) tls_encrypt_ops = {
    .transform = tls_encrypt_transform,
    .kind      = &tls_encrypt_kind,
};

/* ===========================================================================
 * Decrypt xform: ciphertext -> ptls_receive -> plaintext (-> app)
 * =========================================================================== */

/* Emit the handshake-stashed plaintext exactly once, before any
 * freshly-decrypted bytes. */
static void
tls_decrypt_emit_pending(n00b_conduit_filter_t(n00b_buffer_t *) *xf,
                         n00b_conduit_tls_t                      *s)
{
    bool expected = false;
    if (!n00b_atomic_cas(&s->pending_emitted, &expected, true)) {
        return;
    }
    n00b_buffer_t *pend = s->recv_pending;
    s->recv_pending = nullptr;
    if (pend && pend->byte_len > 0) {
        n00b_conduit_filter_emit(n00b_buffer_t *, xf, pend);
    }
}

static n00b_option_t(n00b_buffer_t *)
tls_decrypt_transform(n00b_conduit_filter_t(n00b_buffer_t *) *xf,
                      n00b_buffer_t *input)
{
    tls_link_state_t   *st = n00b_conduit_xform_cookie(n00b_buffer_t *,
                                                       n00b_buffer_t *, xf);
    n00b_conduit_tls_t *s  = st->session;

    tls_decrypt_emit_pending(xf, s);

    if (!input || input->byte_len <= 0) {
        return n00b_option_none(n00b_buffer_t *);
    }

    const uint8_t *data = (const uint8_t *)input->data;
    size_t         len  = (size_t)input->byte_len;
    size_t         consumed = 0;

    ptls_buffer_t dec;
    uint8_t       dec_storage[16384];
    ptls_buffer_init(&dec, dec_storage, sizeof(dec_storage));

    bool peer_closed = false;
    bool proto_error = false;

    n00b_mutex_lock(&s->crypto_lock);
    while (consumed < len) {
        size_t insz = len - consumed;
        int    rr   = ptls_receive(s->tls, &dec, data + consumed, &insz);
        consumed += insz;

        if (dec.off > 0) {
            n00b_buffer_t *pt = n00b_buffer_from_bytes((char *)dec.base,
                                                       (int64_t)dec.off,
                                                       .allocator = tls_alloc());
            /* Emit while NOT holding the crypto lock would be nicer, but the
             * emit only touches the output topic (a different lock), and
             * keeping the decrypt strictly ordered is simpler and correct. */
            n00b_conduit_filter_emit(n00b_buffer_t *, xf, pt);
            dec.off = 0;
        }

        if (rr == 0 || rr == PTLS_ERROR_IN_PROGRESS) {
            continue;
        }
        if (rr == PTLS_ALERT_TO_PEER_ERROR(PTLS_ALERT_CLOSE_NOTIFY)) {
            peer_closed = true;
            break;
        }
        proto_error = true;
        break;
    }
    n00b_mutex_unlock(&s->crypto_lock);

    ptls_buffer_dispose(&dec);

    if (peer_closed || proto_error) {
        /* Half-close / error both surface to the app as EOF on the plaintext
         * read topic (TOPIC_CLOSED). */
        n00b_conduit_topic_close((n00b_conduit_topic_base_t *)xf->topic);
    }

    return n00b_option_none(n00b_buffer_t *);
}

static n00b_string_t tls_decrypt_kind = {
    .data = "tls-decrypt", .u8_bytes = 11, .codepoints = 11, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(n00b_buffer_t *) tls_decrypt_ops = {
    .transform = tls_decrypt_transform,
    .kind      = &tls_decrypt_kind,
};

/* ===========================================================================
 * Handshake driver (conduit-native, runs during connect)
 * =========================================================================== */

/* Push any post-handshake plaintext onto the session's recv_pending stash. */
static void
stash_pending(n00b_conduit_tls_t *s, const uint8_t *data, size_t len)
{
    if (len == 0) return;
    n00b_buffer_t *piece = n00b_buffer_from_bytes((char *)data, (int64_t)len,
                                                  .allocator = tls_alloc());
    if (!s->recv_pending) {
        s->recv_pending = n00b_buffer_empty(.allocator = tls_alloc());
    }
    n00b_buffer_concat(s->recv_pending, piece);
}

/* Feed one inbound ciphertext chunk through ptls during the handshake.
 * Drives ptls_handshake until done, then ptls_receive for any trailing app
 * data in the same chunk (stashed).  Returns an N00B_QUIC_* code. */
static int
hs_consume_chunk(n00b_conduit_tls_t *s, const uint8_t *data, size_t len,
                 bool *done, ptls_buffer_t *hs)
{
    size_t consumed = 0;
    while (consumed < len) {
        size_t insz = len - consumed;
        if (!*done) {
            int rc = ptls_handshake(s->tls, hs, data + consumed, &insz, nullptr);
            consumed += insz;
            if (hs->off > 0) {
                auto wr = n00b_conduit_fd_write_submit(s->owner, hs->base,
                                                       hs->off, nullptr, nullptr);
                hs->off = 0;
                if (n00b_result_is_err(wr)) return N00B_QUIC_ERR_PROTOCOL;
            }
            if (rc == 0) {
                *done = true;
            }
            else if (rc != PTLS_ERROR_IN_PROGRESS) {
                return (rc == PTLS_ALERT_BAD_CERTIFICATE
                        || rc == PTLS_ALERT_CERTIFICATE_UNKNOWN
                        || rc == PTLS_ALERT_UNKNOWN_CA)
                           ? N00B_QUIC_ERR_TRUST_REJECTED
                           : N00B_QUIC_ERR_HANDSHAKE;
            }
        }
        else {
            ptls_buffer_t pb;
            uint8_t       pb_storage[16384];
            ptls_buffer_init(&pb, pb_storage, sizeof(pb_storage));
            int rr = ptls_receive(s->tls, &pb, data + consumed, &insz);
            consumed += insz;
            if (pb.off > 0) {
                stash_pending(s, pb.base, pb.off);
            }
            ptls_buffer_dispose(&pb);
            if (rr != 0 && rr != PTLS_ERROR_IN_PROGRESS) {
                return N00B_QUIC_ERR_PROTOCOL;
            }
        }
    }
    return N00B_QUIC_OK;
}

static int
tls_conduit_handshake(n00b_conduit_tls_t *s, int64_t deadline)
{
    n00b_conduit_t *c = s->conduit;

    /* Subscribe a temporary inbox to the fd read topic.  This activates reads
     * on the managed fd (on_first_subscribe), so the ServerHello cannot be
     * lost between connect and our first poll. */
    auto read_topic = n00b_conduit_fd_read_topic_typed(s->owner);
    if (!read_topic) return N00B_QUIC_ERR_PROTOCOL;

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox = n00b_alloc_with_opts(
        n00b_conduit_inbox_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = tls_alloc()});
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    auto sub_r = n00b_conduit_read_async(n00b_buffer_t *, read_topic, inbox);
    if (n00b_result_is_err(sub_r)) return N00B_QUIC_ERR_PROTOCOL;
    n00b_conduit_sub_handle_t read_sub = n00b_result_get(sub_r).handle;

    /* Status inbox catches EOF / read errors during the handshake. */
    n00b_conduit_fd_status_inbox_t *status_inbox =
        n00b_conduit_fd_status_inbox_new(c);
    auto status_topic = n00b_conduit_fd_status_topic_typed(s->owner);
    n00b_conduit_sub_handle_t status_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    if (status_topic && status_inbox) {
        status_sub = n00b_conduit_fd_status_subscribe(status_topic,
                                                      status_inbox, .flags = 0);
    }

    ptls_buffer_t hs;
    uint8_t       hs_storage[16384];
    ptls_buffer_init(&hs, hs_storage, sizeof(hs_storage));

    int rc = N00B_QUIC_OK;

    /* Kick off ClientHello. */
    int phs = ptls_handshake(s->tls, &hs, nullptr, nullptr, nullptr);
    if (phs != PTLS_ERROR_IN_PROGRESS && phs != 0) {
        rc = N00B_QUIC_ERR_HANDSHAKE;
        goto cleanup;
    }
    if (hs.off > 0) {
        auto wr = n00b_conduit_fd_write_submit(s->owner, hs.base, hs.off,
                                               nullptr, nullptr);
        hs.off = 0;
        if (n00b_result_is_err(wr)) { rc = N00B_QUIC_ERR_PROTOCOL; goto cleanup; }
    }

    bool done = (phs == 0);
    while (!done) {
        if (now_ms() >= deadline) { rc = N00B_QUIC_ERR_TIMEOUT; goto cleanup; }

        /* Read errors are authoritative; surface them as handshake failure. */
        if (status_inbox) {
            n00b_conduit_fd_status_msg_t *m;
            while ((m = n00b_conduit_fd_status_inbox_pop(status_inbox))
                   != nullptr) {
                if (m->payload.status & N00B_CONDUIT_FD_ST_READ_ERR) {
                    rc = N00B_QUIC_ERR_HANDSHAKE;
                    goto cleanup;
                }
            }
        }

        auto msg = n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
        if (msg) {
            n00b_buffer_t *chunk = msg->payload;
            if (!chunk || chunk->byte_len == 0) {
                rc = N00B_QUIC_ERR_HANDSHAKE; /* EOF before Finished */
                goto cleanup;
            }
            rc = hs_consume_chunk(s, (const uint8_t *)chunk->data,
                                  (size_t)chunk->byte_len, &done, &hs);
            if (rc != N00B_QUIC_OK) goto cleanup;
            continue;
        }

        if (n00b_conduit_inbox_has_sys(inbox)) {
            n00b_conduit_sys_msg_t *sys = n00b_conduit_inbox_pop_sys(inbox);
            if (sys && sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
                rc = N00B_QUIC_ERR_HANDSHAKE; /* peer closed mid-handshake */
                goto cleanup;
            }
            continue;
        }

        n00b_condition_wait(&inbox->cv, .timeout_ms = 50, .auto_unlock = true);
    }

    /* Handshake done.  Drain any further chunks already delivered (trailing
     * NewSessionTicket / early app data) so nothing is stranded in this inbox
     * when we cancel the subscription. */
    {
        n00b_conduit_message_t(n00b_buffer_t *) *msg;
        while ((msg = n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox))
               != nullptr) {
            n00b_buffer_t *chunk = msg->payload;
            if (!chunk || chunk->byte_len == 0) continue;
            rc = hs_consume_chunk(s, (const uint8_t *)chunk->data,
                                  (size_t)chunk->byte_len, &done, &hs);
            if (rc != N00B_QUIC_OK) goto cleanup;
        }
    }

cleanup:
    ptls_buffer_dispose(&hs);
    if (read_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(read_sub);
    }
    if (status_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(status_sub);
    }
    return rc;
}

/* ===========================================================================
 * Wait for the non-blocking TCP connect to reach CONNECTED.
 * =========================================================================== */

static bool
tls_wait_connected(n00b_conduit_t *c, n00b_conduit_conn_t *conn,
                   int64_t deadline)
{
    int state = n00b_atomic_load(&conn->conn_state);
    if (state == N00B_CONDUIT_CONN_ST_CONNECTED) return true;
    if (state == N00B_CONDUIT_CONN_ST_ERROR
        || state == N00B_CONDUIT_CONN_ST_CLOSED) return false;

    auto status_opt = n00b_conduit_conn_status_topic(conn);
    n00b_conduit_sock_status_inbox_t *inbox = nullptr;
    n00b_conduit_sub_handle_t sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    if (n00b_option_is_set(status_opt)) {
        n00b_conduit_topic_base_t *st = n00b_option_get(status_opt);
        inbox = n00b_conduit_sock_status_inbox_new(c);
        sub = n00b_conduit_sock_status_subscribe(st, inbox,
                                                 .operations = N00B_CONDUIT_OP_ALL);
    }

    bool ok = false;
    while (now_ms() < deadline) {
        state = n00b_atomic_load(&conn->conn_state);
        if (state == N00B_CONDUIT_CONN_ST_CONNECTED) { ok = true; break; }
        if (state == N00B_CONDUIT_CONN_ST_ERROR
            || state == N00B_CONDUIT_CONN_ST_CLOSED) { ok = false; break; }
        if (inbox) {
            (void)n00b_conduit_sock_status_inbox_pop(inbox);
            n00b_condition_wait(&inbox->cv, .timeout_ms = 50,
                                .auto_unlock = true);
        }
    }

    if (sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(sub);
    }
    return ok;
}

/* ===========================================================================
 * Connect + teardown
 * =========================================================================== */

n00b_result_t(n00b_conduit_tls_t *)
n00b_conduit_tls_connect(n00b_conduit_t            *c,
                         n00b_conduit_io_backend_t *io,
                         n00b_string_t             *host,
                         uint16_t                   port) _kargs
{
    n00b_quic_trust_t *trust      = nullptr;
    int32_t            timeout_ms = 0;
    n00b_allocator_t  *allocator  = nullptr;
}
{
    if (!c || !io || !host) {
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    int32_t tmo = timeout_ms > 0 ? timeout_ms : 30000;
    n00b_allocator_t *a = allocator ? allocator : tls_alloc();
    int64_t deadline = now_ms() + tmo;

    /* 1. Resolve the hostname to a connectable IPv4 literal (conn_tcp does not
     * resolve names), then non-blocking TCP connect (fd_manage happens inside).
     * `host` stays the hostname for SNI + trust below. */
    n00b_string_t *connect_ip = tls_resolve_ipv4(host, port, a);
    if (!connect_ip) {
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_BIND_FAILED);
    }
    auto conn_r = n00b_conduit_conn_tcp(c, io, connect_ip, port);
    if (n00b_result_is_err(conn_r)) {
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_BIND_FAILED);
    }
    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);

    /* 2. Wait for CONNECTED. */
    if (!tls_wait_connected(c, conn, deadline)) {
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_TIMEOUT);
    }

    /* 3. The managed fd owner. */
    auto owner_opt = n00b_conduit_conn_fd_owner(conn);
    if (!n00b_option_is_set(owner_opt)) {
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    n00b_conduit_fd_owner_t *owner = n00b_option_get(owner_opt);

    /* 4. Session handle (pool-allocated, zeroed). */
    n00b_conduit_tls_t *s = n00b_alloc_with_opts(
        n00b_conduit_tls_t, &(n00b_alloc_opts_t){.allocator = a});
    s->conduit   = c;
    s->io        = io;
    s->conn      = conn;
    s->owner     = owner;
    s->host      = host;
    s->allocator = a;
    n00b_mutex_init(&s->crypto_lock);

    /* 5. picotls context + verifier. */
    s->ctx.random_bytes       = ptls_minicrypto_random_bytes;
    s->ctx.get_time           = &the_get_time;
    s->ctx.key_exchanges      = ptls_minicrypto_key_exchanges;
    s->ctx.cipher_suites      = ptls_minicrypto_cipher_suites;
    s->verifier.super.cb      = tls_verify_cb;
    s->verifier.super.algos   = n00b_picotls_supported_sig_algs;
    s->verifier.trust         = trust;
    s->ctx.verify_certificate = &s->verifier.super;

    /* 6. ptls_t + SNI. */
    s->tls = ptls_new(&s->ctx, 0);
    if (!s->tls) {
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    if (ptls_set_server_name(s->tls, host->data, 0) != 0) {
        ptls_free(s->tls);
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    /* 7. Drive the handshake over the conduit IO. */
    int hrc = tls_conduit_handshake(s, deadline);
    if (hrc != N00B_QUIC_OK) {
        ptls_free(s->tls);
        s->tls = nullptr;
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, hrc);
    }

    /* 8. Install the app-data pipeline.
     *
     *   outbound: write_topic -> encrypt -> ct -> fd_writer -> fd
     *   inbound:  fd read_topic -> decrypt -> read_topic -> app
     */

    /* 8a. Explicit plaintext write topic (the app's outbound entry point). */
    uint64_t wid = n00b_atomic_add(&c->next_xform_id, 1);
    s->write_topic = n00b_conduit_topic_init(n00b_buffer_t *, c,
                                             N00B_CONDUIT_URI_XFORM(wid));
    if (!s->write_topic) {
        ptls_free(s->tls);
        s->tls = nullptr;
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    /* 8b. Encrypt xform: upstream = write_topic; output = ciphertext topic. */
    auto enc_r = n00b_conduit_filter_new(n00b_buffer_t *, c, s->write_topic,
                                         &tls_encrypt_ops,
                                         sizeof(tls_link_state_t));
    if (n00b_result_is_err(enc_r)) {
        ptls_free(s->tls);
        s->tls = nullptr;
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    s->encrypt = n00b_result_get(enc_r);
    ((tls_link_state_t *)n00b_conduit_xform_cookie(n00b_buffer_t *,
                                                   n00b_buffer_t *,
                                                   s->encrypt))->session = s;

    /* 8c. fd_writer drains the ciphertext topic onto the fd.  Creating it
     * eager-subscribes to the ciphertext topic, which cascade-starts the
     * encrypt xform's worker. */
    auto fw_r = n00b_conduit_fd_writer_new(c, s->encrypt->topic, owner->fd,
                                           .consume = true);
    if (n00b_result_is_err(fw_r)) {
        ptls_free(s->tls);
        s->tls = nullptr;
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    s->fdwriter = n00b_result_get(fw_r);

    /* 8d. Decrypt xform: upstream = fd read_topic; output = plaintext read
     * topic (the app's inbound exit point). */
    auto read_topic = n00b_conduit_fd_read_topic_typed(owner);
    if (!read_topic) {
        ptls_free(s->tls);
        s->tls = nullptr;
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    auto dec_r = n00b_conduit_filter_new(n00b_buffer_t *, c, read_topic,
                                         &tls_decrypt_ops,
                                         sizeof(tls_link_state_t));
    if (n00b_result_is_err(dec_r)) {
        ptls_free(s->tls);
        s->tls = nullptr;
        n00b_conduit_conn_close(conn);
        return n00b_result_err(n00b_conduit_tls_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    s->decrypt = n00b_result_get(dec_r);
    ((tls_link_state_t *)n00b_conduit_xform_cookie(n00b_buffer_t *,
                                                   n00b_buffer_t *,
                                                   s->decrypt))->session = s;
    s->read_topic = s->decrypt->topic;

    n00b_atomic_store(&s->ready, true);
    return n00b_result_ok(n00b_conduit_tls_t *, s);
}

n00b_result_t(bool)
n00b_conduit_tls_write(n00b_conduit_tls_t *s, n00b_buffer_t *plaintext)
{
    if (!s || !plaintext) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    /* Copy-in: the conduit owns a pinned (pool) copy so a moving GC can never
     * relocate the bytes before the encrypt worker consumes them, and the
     * caller is free to reuse/drop `plaintext` immediately. The encrypt xform
     * frees this copy once it has ciphered it (conduit "freed after
     * delivered" ownership). */
    n00b_buffer_t *owned = n00b_buffer_copy(plaintext, .allocator = tls_alloc());
    return n00b_conduit_write(n00b_buffer_t *, s->write_topic, owned);
}

n00b_conduit_topic_t(n00b_buffer_t *) *
n00b_conduit_tls_write_topic(n00b_conduit_tls_t *s)
{
    return s ? s->write_topic : nullptr;
}

n00b_conduit_topic_t(n00b_buffer_t *) *
n00b_conduit_tls_read_topic(n00b_conduit_tls_t *s)
{
    return s ? s->read_topic : nullptr;
}

bool
n00b_conduit_tls_is_ready(n00b_conduit_tls_t *s)
{
    return s && n00b_atomic_load(&s->ready);
}

void
n00b_conduit_tls_close(n00b_conduit_tls_t *s)
{
    if (!s) return;
    bool expected = false;
    if (!n00b_atomic_cas(&s->closed, &expected, true)) {
        return; /* idempotent */
    }
    n00b_atomic_store(&s->ready, false);

    /* Best-effort close_notify: encrypt an empty close alert and submit it
     * directly to the fd, bypassing the encrypt worker (which we are about to
     * tear down).  Uses a local ptls buffer; guarded against the decrypt
     * worker by the crypto lock. */
    if (s->tls && s->owner) {
        ptls_buffer_t cn;
        uint8_t       cn_storage[256];
        ptls_buffer_init(&cn, cn_storage, sizeof(cn_storage));
        n00b_mutex_lock(&s->crypto_lock);
        int rc = ptls_send_alert(s->tls, &cn, PTLS_ALERT_LEVEL_WARNING,
                                 PTLS_ALERT_CLOSE_NOTIFY);
        n00b_mutex_unlock(&s->crypto_lock);
        if (rc == 0 && cn.off > 0) {
            (void)n00b_conduit_fd_write_submit(s->owner, cn.base, cn.off,
                                               nullptr, nullptr);
        }
        ptls_buffer_dispose(&cn);
    }

    if (s->tls) {
        ptls_free(s->tls);
        s->tls = nullptr;
    }
    if (s->conn) {
        n00b_conduit_conn_close(s->conn);
        s->conn = nullptr;
    }
}

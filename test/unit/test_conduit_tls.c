/*
 * test_conduit_tls.c — loopback round-trip + forced-GC no-dangle for the
 * conduit-native TLS transport (src/conduit/xform_tls.c).
 *
 * Unlike test_acme_tls_mtls.c (which bounces handshake bytes in memory), this
 * test drives the REAL transport over a REAL loopback TCP socket so the whole
 * conduit pipeline runs:
 *
 *   client: n00b_conduit_tls_connect -> write_topic -> [encrypt] -> ct
 *           -> [fd_writer] -> tcp fd
 *   server: a raw picotls echo server on a background n00b thread
 *   client: tcp fd -> [decrypt] -> read_topic
 *
 * Trust is pinned to the test cert's SHA-256, so the handshake completes
 * without a real CA chain (the server presents n00b_quic_test_cert_der).
 *
 * Two tests:
 *   1. round_trip — connect, write a request, read the echoed bytes back.
 *   2. forced_gc_no_dangle — a writer thread streams many freshly-allocated
 *      plaintext buffers through the encrypt xform while the main thread
 *      hammers n00b_collect().  This is the regression for the acme_tls
 *      SIGSEGV class: if the encryptor ever read a relocated GC buffer mid
 *      AES-GCM the process would crash and/or the echoed bytes would not
 *      match.  We assert byte-exact echoes and survival.
 */

#define N00B_USE_INTERNAL_API
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "picotls.h"
#include "picotls/minicrypto.h"
#include "uECC.h"

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/service.h"
#include "conduit/socket.h"
#include "conduit/xform_tls.h"
#include "conduit/rw.h"
#include "conduit/write.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/condition.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/stw.h"
#include "core/thread.h"
#include "crypto/trust.h"
#include "net/quic/quic_types.h"
#include "internal/crypto/picotls_certverify.h"

#include "../fixtures/quic_test_pki.h"

/* ====================================================================
 * Test PKI -> SHA-256 pin
 * ==================================================================== */

static void
test_cert_sha256(uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(n00b_quic_test_cert_der, n00b_quic_test_cert_der_len,
                     words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        out[i * 4]     = (uint8_t)(w >> 24);
        out[i * 4 + 1] = (uint8_t)(w >> 16);
        out[i * 4 + 2] = (uint8_t)(w >> 8);
        out[i * 4 + 3] = (uint8_t)w;
    }
}

/* ====================================================================
 * Server-side picotls signer (lifted from test_acme_tls_mtls.c so this
 * test stays self-contained).
 * ==================================================================== */

static void
extract_test_scalar(uint8_t out[32])
{
    memcpy(out, n00b_quic_test_key_der + 36, 32);
}

static size_t
ts_der_int_size(const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    return 1 + 1 + mag + (size_t)pad;
}

static size_t
ts_der_int_emit(uint8_t *out, const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(mag + (size_t)pad);
    size_t off = 2;
    if (pad) out[off++] = 0x00;
    memcpy(out + off, be + i, mag);
    return off + mag;
}

typedef struct {
    ptls_sign_certificate_t super;
    uint8_t                 priv[32];
} server_signer_t;

static int
server_sign_cb(ptls_sign_certificate_t *self_, ptls_t *tls,
               ptls_async_job_t **async, uint16_t *selected_algorithm,
               ptls_buffer_t *output, ptls_iovec_t input,
               const uint16_t *algorithms, size_t num_algorithms)
{
    (void)tls; (void)async;
    server_signer_t *s = (server_signer_t *)self_;

    bool es256 = false;
    for (size_t i = 0; i < num_algorithms; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
            es256 = true;
            break;
        }
    }
    if (!es256) return PTLS_ALERT_HANDSHAKE_FAILURE;
    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;

    uint8_t digest[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(input.base, input.len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            digest[i * 4]     = (uint8_t)(w >> 24);
            digest[i * 4 + 1] = (uint8_t)(w >> 16);
            digest[i * 4 + 2] = (uint8_t)(w >> 8);
            digest[i * 4 + 3] = (uint8_t)w;
        }
    }
    uint8_t raw[64];
    if (!uECC_sign(s->priv, digest, 32, raw, uECC_secp256r1())) {
        return PTLS_ERROR_LIBRARY;
    }
    size_t r_sz  = ts_der_int_size(raw, 32);
    size_t s_sz  = ts_der_int_size(raw + 32, 32);
    size_t inner = r_sz + s_sz;
    int rc = ptls_buffer_reserve(output, 2 + inner);
    if (rc != 0) return rc;
    output->base[output->off++] = 0x30;
    output->base[output->off++] = (uint8_t)inner;
    output->off += ts_der_int_emit(output->base + output->off, raw, 32);
    output->off += ts_der_int_emit(output->base + output->off, raw + 32, 32);
    return 0;
}

/* ====================================================================
 * Raw loopback picotls echo server (background thread, blocking socket).
 * ==================================================================== */

typedef struct {
    int               listen_fd;
    server_signer_t   signer;
    ptls_iovec_t      cert;
    ptls_context_t    ctx;
} echo_server_t;

static bool
send_all(int fd, const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, data + off, len - off, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += (size_t)w;
    }
    return true;
}

static void *
echo_server_main(void *arg)
{
    echo_server_t *srv = arg;

    int cfd = accept(srv->listen_fd, nullptr, nullptr);
    if (cfd < 0) return nullptr;

    ptls_t *tls = ptls_new(&srv->ctx, 1);
    if (!tls) { close(cfd); return nullptr; }

    uint8_t       buf[16384];
    ptls_buffer_t sbuf;
    uint8_t       sbuf_storage[16384];
    ptls_buffer_init(&sbuf, sbuf_storage, sizeof(sbuf_storage));

    bool done = false;
    while (!done) {
        ssize_t n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) goto cleanup;
        size_t consumed = 0;
        while (consumed < (size_t)n) {
            size_t insz = (size_t)n - consumed;
            int rc = ptls_handshake(tls, &sbuf, buf + consumed, &insz, nullptr);
            consumed += insz;
            if (sbuf.off > 0) {
                if (!send_all(cfd, sbuf.base, sbuf.off)) goto cleanup;
                sbuf.off = 0;
            }
            if (rc == 0) {
                done = true;
            }
            else if (rc != PTLS_ERROR_IN_PROGRESS) {
                goto cleanup;
            }
        }
    }

    /* Echo loop: decrypt inbound, re-encrypt the same bytes back. */
    ptls_buffer_t dec, enc;
    uint8_t       dec_storage[16384], enc_storage[16384];
    ptls_buffer_init(&dec, dec_storage, sizeof(dec_storage));
    ptls_buffer_init(&enc, enc_storage, sizeof(enc_storage));

    while (true) {
        ssize_t n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        size_t consumed = 0;
        while (consumed < (size_t)n) {
            size_t insz = (size_t)n - consumed;
            int rr = ptls_receive(tls, &dec, buf + consumed, &insz);
            consumed += insz;
            if (dec.off > 0) {
                if (ptls_send(tls, &enc, dec.base, dec.off) == 0
                    && enc.off > 0) {
                    if (!send_all(cfd, enc.base, enc.off)) goto echo_done;
                    enc.off = 0;
                }
                dec.off = 0;
            }
            if (rr == PTLS_ALERT_TO_PEER_ERROR(PTLS_ALERT_CLOSE_NOTIFY)) {
                goto echo_done;
            }
            if (rr != 0 && rr != PTLS_ERROR_IN_PROGRESS) {
                goto echo_done;
            }
        }
    }
echo_done:
    ptls_buffer_dispose(&dec);
    ptls_buffer_dispose(&enc);

cleanup:
    ptls_buffer_dispose(&sbuf);
    ptls_free(tls);
    close(cfd);
    return nullptr;
}

/* Bind a loopback listener on an ephemeral port; return fd, set *port. */
static int
start_listener(uint16_t *port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(fd, 4) == 0);

    struct sockaddr_in bound;
    socklen_t          blen = sizeof(bound);
    assert(getsockname(fd, (struct sockaddr *)&bound, &blen) == 0);
    *port_out = ntohs(bound.sin_port);
    return fd;
}

static n00b_thread_t *
spawn_echo_server(echo_server_t *srv)
{
    memset(srv, 0, sizeof(*srv));
    srv->listen_fd = -1; /* set by caller */

    srv->cert.base = (uint8_t *)n00b_quic_test_cert_der;
    srv->cert.len  = n00b_quic_test_cert_der_len;
    extract_test_scalar(srv->signer.priv);
    srv->signer.super.cb = server_sign_cb;

    srv->ctx.random_bytes       = ptls_minicrypto_random_bytes;
    srv->ctx.get_time           = &ptls_get_time;
    srv->ctx.key_exchanges      = ptls_minicrypto_key_exchanges;
    srv->ctx.cipher_suites      = ptls_minicrypto_cipher_suites;
    srv->ctx.certificates.list  = &srv->cert;
    srv->ctx.certificates.count = 1;
    srv->ctx.sign_certificate   = &srv->signer.super;
    return nullptr; /* spawned by caller after listen_fd is set */
}

/* ====================================================================
 * Conduit / IO bring-up (mirrors test_conduit_unix_socket.c).
 * ==================================================================== */

static n00b_conduit_io_backend_t *
make_io_via_service(n00b_conduit_t *c)
{
    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);
    assert(n00b_result_is_ok(n00b_conduit_service_start(svc)));

    int n = n00b_atomic_load(&svc->num_threads);
    for (int i = 0; i < n; i++) {
        n00b_conduit_svc_thread_t *t = svc->threads[i];
        if (t && t->role == N00B_CONDUIT_SVC_IO && t->io) {
            return t->io;
        }
    }
    assert(!"service did not spawn an IO thread");
    return nullptr;
}

/* Read exactly want_len plaintext bytes from the TLS read topic into out,
 * blocking on the inbox CV.  Returns true on success. */
static bool
read_exact(n00b_conduit_t *c, n00b_conduit_tls_t *s,
           n00b_conduit_sub_handle_t sub,
           n00b_conduit_inbox_t(n00b_buffer_t *) *inbox,
           n00b_buffer_t *acc, int64_t want_len, int budget_ms)
{
    (void)c; (void)s; (void)sub;
    int64_t spins = budget_ms / 5 + 1;
    while (acc->byte_len < want_len && spins-- > 0) {
        auto msg = n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
        if (msg) {
            if (msg->payload && msg->payload->byte_len > 0) {
                n00b_buffer_concat(acc, msg->payload);
            }
            continue;
        }
        if (n00b_conduit_inbox_has_sys(inbox)) {
            n00b_conduit_sys_msg_t *sys = n00b_conduit_inbox_pop_sys(inbox);
            if (sys && sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED) {
                break;
            }
            continue;
        }
        n00b_condition_wait(&inbox->cv, .timeout_ms = 5, .auto_unlock = true);
    }
    return acc->byte_len >= want_len;
}

/* ====================================================================
 * Test 1: round trip
 * ==================================================================== */

static void
test_round_trip(void)
{
    n00b_conduit_t            *c  = ({
        auto cr = n00b_conduit_new();
        assert(n00b_result_is_ok(cr));
        n00b_result_get(cr);
    });
    n00b_conduit_io_backend_t *io = make_io_via_service(c);

    echo_server_t srv;
    spawn_echo_server(&srv);
    uint16_t port = 0;
    srv.listen_fd = start_listener(&port);
    auto tr = n00b_thread_spawn(echo_server_main, &srv);
    assert(n00b_result_is_ok(tr));
    n00b_thread_t *server_thread = n00b_result_get(tr);

    uint8_t pin[32];
    test_cert_sha256(pin);
    n00b_quic_trust_t *trust = n00b_quic_trust_pinned(pin);
    assert(trust);

    auto cr = n00b_conduit_tls_connect(c, io,
                                       n00b_string_from_cstr("127.0.0.1"), port,
                                       .trust = trust, .timeout_ms = 5000);
    if (n00b_result_is_err(cr)) {
        fprintf(stderr, "  [FAIL] tls connect failed: %d\n",
                n00b_result_get_err(cr));
        abort();
    }
    n00b_conduit_tls_t *s = n00b_result_get(cr);
    assert(n00b_conduit_tls_is_ready(s));

    /* Subscribe to the plaintext read topic first (starts the decrypt
     * xform + activates fd reads), then write. */
    auto read_topic = n00b_conduit_tls_read_topic(s);
    assert(read_topic);
    /* The inbox embeds a CV/lock that the decrypt worker notifies across
     * threads; it MUST be pinned (conduit pool), never the movable default
     * arena, or a collection relocates it and corrupts its lock accounting. */
    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox = n00b_alloc_with_opts(
        n00b_conduit_inbox_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    auto sr = n00b_conduit_read_async(n00b_buffer_t *, read_topic, inbox);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_sub_handle_t sub = n00b_result_get(sr).handle;

    n00b_string_t *req = n00b_string_from_cstr("hello-conduit-tls");
    n00b_buffer_t *pt  = n00b_buffer_from_bytes(req->data,
                                                (int64_t)req->u8_bytes);
    auto wr = n00b_conduit_tls_write(s, pt);
    assert(n00b_result_is_ok(wr));

    n00b_buffer_t *acc = n00b_buffer_empty();
    bool ok = read_exact(c, s, sub, inbox, acc, (int64_t)req->u8_bytes, 5000);
    if (!ok) {
        fprintf(stderr, "  [FAIL] did not read %zu echoed bytes (got %lld)\n",
                req->u8_bytes, (long long)acc->byte_len);
        abort();
    }
    assert(acc->byte_len >= (int64_t)req->u8_bytes);
    assert(memcmp(acc->data, req->data, req->u8_bytes) == 0);

    n00b_conduit_sub_cancel(sub);
    n00b_conduit_tls_close(s);
    n00b_thread_join(server_thread);
    close(srv.listen_fd);

    /* This thread OWNS the conduit it created (with its service + IO worker
     * threads), so it must shut it down — otherwise those workers outlive the
     * test and n00b_shutdown()'s civil "wait for live_threads" never returns. */
    n00b_conduit_destroy(c);

    printf("  [PASS] round trip: wrote %zu bytes, echo matched\n",
           req->u8_bytes);
}

/* ====================================================================
 * Test 2: forced-GC no-dangle
 *
 * The acme_tls SIGSEGV class was the encryptor reading a relocated GC buffer
 * mid AES-GCM on a worker thread during a collection.  This test reproduces
 * that scenario directly: a writer thread streams freshly-allocated, movable
 * plaintext through the encrypt xform while the main thread forces
 * stop-the-world collections concurrently.  If the encrypt path ever handed
 * picotls a movable pointer, the process would crash and/or the echoed bytes
 * would not match.  We assert survival + byte-exact echoes across the
 * collections.
 *
 * The raw-recv() echo server is spawned with `.isolation = true`: it touches
 * no GC heap, so the GC must NOT conservatively scan its C stack (doing so
 * trips `base > top` in n00b_scan_thread_stacks when STW preemptively suspends
 * it deep in a syscall).  The writer DOES touch the GC heap, so it stays
 * non-isolated (its stack roots its in-flight buffers) and parks alive across
 * the collections so its teardown never races a STW pass.
 * ==================================================================== */

#define GC_TEST_ITERS  200
#define GC_TEST_MSGLEN 64

typedef struct {
    n00b_conduit_tls_t *s;
    _Atomic(bool)       done;
    _Atomic(bool)       exit_now;
    _Atomic(int)        sent;
} writer_ctx_t;

static void *
gc_writer_main(void *arg)
{
    writer_ctx_t *w = arg;
    for (int i = 0; i < GC_TEST_ITERS; i++) {
        /* Normal traceable plaintext (default arena) — the caller is supposed
         * to hand the conduit an ordinary GC buffer; n00b_conduit_tls_write
         * copies it into the conduit's non-traceable pool and owns it.
         * The bytes encode the iteration index so corruption is detectable. */
        char tmp[GC_TEST_MSGLEN];
        for (int b = 0; b < GC_TEST_MSGLEN; b++) {
            tmp[b] = (char)((i + b) & 0xff);
        }
        n00b_buffer_t *pt = n00b_buffer_from_bytes(tmp, (int64_t)GC_TEST_MSGLEN);
        auto wr = n00b_conduit_tls_write(w->s, pt);
        if (n00b_result_is_ok(wr)) {
            n00b_atomic_add(&w->sent, 1);
        }
    }
    n00b_atomic_store(&w->done, true);
    /* Park (alive + scannable) until main has finished forcing collections,
     * so this thread never tears down during a STW pass. */
    while (!n00b_atomic_load(&w->exit_now)) {
    }
    return nullptr;
}

static void
test_forced_gc_no_dangle(void)
{
    n00b_conduit_t            *c  = ({
        auto cr = n00b_conduit_new();
        assert(n00b_result_is_ok(cr));
        n00b_result_get(cr);
    });
    n00b_conduit_io_backend_t *io = make_io_via_service(c);

    echo_server_t srv;
    spawn_echo_server(&srv);
    uint16_t port = 0;
    srv.listen_fd = start_listener(&port);
    /* Isolated: the echo server does raw syscalls and touches no GC heap, so
     * the collector must skip its C stack (see test header). */
    auto tr = n00b_thread_spawn(echo_server_main, &srv);
    assert(n00b_result_is_ok(tr));
    n00b_thread_t *server_thread = n00b_result_get(tr);

    uint8_t pin[32];
    test_cert_sha256(pin);
    n00b_quic_trust_t *trust = n00b_quic_trust_pinned(pin);
    assert(trust);

    auto cr = n00b_conduit_tls_connect(c, io,
                                       n00b_string_from_cstr("127.0.0.1"), port,
                                       .trust = trust, .timeout_ms = 5000);
    assert(n00b_result_is_ok(cr));
    n00b_conduit_tls_t *s = n00b_result_get(cr);

    auto read_topic = n00b_conduit_tls_read_topic(s);
    /* The inbox embeds a CV/lock that the decrypt worker notifies across
     * threads; it MUST be pinned (conduit pool), never the movable default
     * arena, or a collection relocates it and corrupts its lock accounting. */
    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox = n00b_alloc_with_opts(
        n00b_conduit_inbox_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = c->allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    auto sr = n00b_conduit_read_async(n00b_buffer_t *, read_topic, inbox);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_sub_handle_t sub = n00b_result_get(sr).handle;

    /* Start the writer (streams movable plaintext through the encrypt worker),
     * then force collections concurrently. */
    writer_ctx_t w = {.s = s};
    n00b_atomic_store(&w.done, false);
    n00b_atomic_store(&w.exit_now, false);
    n00b_atomic_store(&w.sent, 0);
    auto wtr = n00b_thread_spawn(gc_writer_main, &w);
    assert(n00b_result_is_ok(wtr));
    n00b_thread_t *writer_thread = n00b_result_get(wtr);

    /* Let the writer fully come up + start sending before we force the first
     * collection (so a collect can't race the thread's bring-up). */
    while (n00b_atomic_load(&w.sent) == 0 && !n00b_atomic_load(&w.done)) {
    }

    n00b_arena_t *arena = n00b_get_runtime()->default_arena;
    int           collects = 0;
    /* Force collections concurrently with the writer, but YIELD between each so
     * the conduit workers get real CPU windows to drain.  A forced collect stops
     * the world for its whole duration (~ms); with NO gap the consumer worker
     * never gets scheduled, so it cannot drain delivered messages and the writer
     * eventually parks forever on backpressure (w.done never flips).  A 1ms gap
     * is ample for a drain pass.  The iteration cap converts a genuine stall into
     * a fast failure instead of an infinite loop. */
    int max_collects = GC_TEST_ITERS * 64 + 64;
    while (!n00b_atomic_load(&w.done) && collects < max_collects) {
        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();
        collects++;
        base_nanosleep_ns(1000000); // 1ms: let the conduit workers run + drain
    }
    /* A few more collects after the writer is done, to exercise relocation while
     * the pipeline drains the tail. */
    for (int k = 0; k < 16; k++) {
        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();
        collects++;
    }

    int total = GC_TEST_ITERS * GC_TEST_MSGLEN;
    n00b_buffer_t *acc = n00b_buffer_empty();
    bool ok = read_exact(c, s, sub, inbox, acc, total, 20000);
    if (!ok) {
        fprintf(stderr,
                "  [FAIL] forced-gc: read %lld of %d echoed bytes "
                "(sent=%d, collects=%d)\n",
                (long long)acc->byte_len, total,
                n00b_atomic_load(&w.sent), collects);
        abort();
    }

    /* Verify byte-exact reassembly: echoes are FIFO, so the stream is the
     * concatenation of every message in send order. */
    int idx = 0;
    for (int i = 0; i < GC_TEST_ITERS; i++) {
        for (int b = 0; b < GC_TEST_MSGLEN; b++) {
            uint8_t expect = (uint8_t)((i + b) & 0xff);
            if ((uint8_t)acc->data[idx] != expect) {
                fprintf(stderr,
                        "  [FAIL] forced-gc: byte %d corrupt: got %02x "
                        "want %02x (msg %d off %d)\n",
                        idx, (uint8_t)acc->data[idx], expect, i, b);
                abort();
            }
            idx++;
        }
    }

    /* Release the parked writer and join (no more collects will run). */
    n00b_atomic_store(&w.exit_now, true);
    n00b_thread_join(writer_thread);

    n00b_conduit_sub_cancel(sub);
    n00b_conduit_tls_close(s);
    n00b_thread_join(server_thread);
    close(srv.listen_fd);

    /* This thread OWNS the conduit it created (with its service + IO worker
     * threads), so it must shut it down — otherwise those workers outlive the
     * test and n00b_shutdown()'s civil "wait for live_threads" never returns. */
    n00b_conduit_destroy(c);

    printf("  [PASS] forced-gc no-dangle: %d msgs x %d bytes intact across "
           "%d forced collections\n",
           GC_TEST_ITERS, GC_TEST_MSGLEN, collects);
}

/* ==================================================================== */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt = {};
    n00b_init(&rt, argc, argv);

    printf("test_conduit_tls:\n");
    test_round_trip();
    test_forced_gc_no_dangle();
    printf("All test_conduit_tls tests passed.\n");

    n00b_shutdown();
    return 0;
}

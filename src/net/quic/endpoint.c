/*
 * endpoint.c — QUIC endpoint lifecycle.
 *
 * Phase 1 (this revision) ships create + close.  Recv → picoquic_incoming_packet
 * and picoquic_prepare_next_packet → send wiring lands in the next pass.
 */

#define N00B_USE_INTERNAL_API
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_interpose.h"
#include "core/runtime.h"
#include "core/random.h"
#include "core/time.h"
#include "core/data_lock.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/socket_udp.h"
#include "conduit/subscription.h"
#include "conduit/topic.h"
#include "conduit/publisher.h"
#include "conduit/message.h"
#include "net/quic/quic_types.h"
#include "net/quic/conn.h"
#include "net/quic/chan.h"
#include "net/quic/endpoint.h"
#include "net/quic/lb_cid.h"
#include "internal/net/quic/endpoint_internal.h"
#include "internal/net/quic/conn_internal.h"
#include "internal/net/quic/chan_internal.h"
#include "internal/crypto/picotls_sni.h"
#include "internal/crypto/picotls_verify.h"
#include "crypto/trust.h"

#include "picoquic.h"
#include "picotls.h"
#include "tls_api.h"  /* picoquic_set_private_key_from_file */
#if defined(__linux__)
#include "picoquic_crypto_provider_api.h"
#include "uECC.h"
#endif
#include "autoqlog.h" /* picoquic_set_qlog */
#include <stdlib.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define N00B_QLOG_MKDIR(path, mode) _mkdir(path)
#else
#define N00B_QLOG_MKDIR(path, mode) mkdir(path, mode)
#endif

#define N00B_PICO_ALLOC ((n00b_allocator_t *)&n00b_get_runtime()->user_pool)

#if defined(__linux__)
static void
n00b_quic_linux_random_bytes(void *buf, size_t len)
{
    n00b_random_bytes((char *)buf, len);
}

static int
n00b_quic_linux_uecc_random(uint8_t *dest, unsigned size)
{
    n00b_random_bytes((char *)dest, (size_t)size);
    return 1;
}

static void
n00b_quic_install_linux_random_provider(void)
{
    picoquic_tls_api_init();
    picoquic_register_crypto_random_provider_fn(n00b_quic_linux_random_bytes);
    uECC_set_rng(n00b_quic_linux_uecc_random);
}
#endif

/* ===========================================================================
 * Endpoint accept-default callback
 *
 * picoquic invokes this for events on any cnx that doesn't yet have a
 * per-cnx callback installed.  For server endpoints this means: a new
 * peer just sent us an Initial packet, picoquic created a new
 * `picoquic_cnx_t` for it, and is delivering the very first event on
 * it (typically `picoquic_callback_almost_ready` followed soon after
 * by stream events).
 *
 * Our job here:
 *   1. Wrap the new cnx as `n00b_quic_conn_t` via
 *      `_n00b_quic_conn_accept_internal` (which also installs the
 *      per-cnx `_n00b_quic_conn_default_callback`).
 *   2. Link the new conn into the endpoint's `accepted` list.
 *   3. Publish the new conn on the endpoint's accept topic.
 *   4. Forward this very event to the per-cnx callback so we don't
 *      drop the first event.
 *
 * Steps (1)-(3) are idempotent in the sense that we only do them once
 * per cnx — the lookup catches subsequent calls.  But subsequent
 * calls shouldn't happen anyway, because step (1) installs a per-cnx
 * callback that picoquic will use from now on.
 * =========================================================================== */

/* ===========================================================================
 * LB-CID callback (Phase 5 § 5.8)
 *
 * picoquic invokes this whenever it needs to mint a new connection ID
 * for a connection — once at connection start (server-issued local
 * CID) and on each path migration.  We replace its random CID with an
 * AES-128-encrypted `<server_id>||<nonce>` so that an LB-CID-aware
 * load balancer (Envoy / HAProxy QUIC LB) decoding the wire CID can
 * route follow-up packets to this exact replica regardless of
 * source-IP migration.
 *
 * On encode failure we leave the CID untouched: picoquic falls back
 * to its default random generation, the LB sees an unrecognized CID
 * and round-robins.  Better than refusing to bring up the connection.
 * =========================================================================== */
static void
endpoint_lb_cid_cb(picoquic_quic_t          *quic,
                   picoquic_connection_id_t  cnx_id_local,
                   picoquic_connection_id_t  cnx_id_remote,
                   void                     *cnx_id_cb_data,
                   picoquic_connection_id_t *cnx_id_returned)
{
    (void)quic;
    (void)cnx_id_local;
    (void)cnx_id_remote;
    n00b_quic_lb_cid_config_t *cfg
        = (n00b_quic_lb_cid_config_t *)cnx_id_cb_data;
    if (!cfg || !cnx_id_returned) {
        return;
    }
    uint8_t encoded[N00B_QUIC_LB_CID_LEN];
    auto er = n00b_quic_lb_cid_encode(cfg, encoded);
    if (!n00b_result_is_ok(er)) {
        return;  /* leaves cnx_id_returned as picoquic's default */
    }
    cnx_id_returned->id_len = N00B_QUIC_LB_CID_LEN;
    memcpy(cnx_id_returned->id, encoded, N00B_QUIC_LB_CID_LEN);
}

static int
default_stream_cb(picoquic_cnx_t              *cnx,
                  uint64_t                     stream_id,
                  uint8_t                     *bytes,
                  size_t                       length,
                  picoquic_call_back_event_t   event,
                  void                        *callback_ctx,
                  void                        *stream_ctx)
{
    n00b_quic_endpoint_t *ep = (n00b_quic_endpoint_t *)callback_ctx;
    if (!ep || ep->closed) {
        return 0;
    }

    /* Look up: have we wrapped this cnx already?  Linear scan over
     * the accepted list.  Server load patterns expect tens to hundreds
     * of live conns; linear scan is fine.  Promote to a dict if we
     * ever exceed 1k. */
    n00b_quic_conn_t *conn = nullptr;
    n00b_quic_conn_t *c;
    for (c = ep->accepted; c != nullptr;
         c = c->next_in_endpoint) {
        if (c->cnx == cnx) {
            conn = c;
            break;
        }
    }

    if (!conn) {
        conn = _n00b_quic_conn_accept_internal(ep, cnx);
        if (!conn) {
            return 0;
        }
        /* Link into the endpoint's accepted list (LIFO). */
        conn->next_in_endpoint = ep->accepted;
        ep->accepted = conn;

        /* Publish on the accept topic. */
        if (ep->accept_topic) {
            n00b_result_t(n00b_conduit_publisher_t *) pub_res =
                n00b_conduit_publish_try_claim(ep->accept_topic);
            if (n00b_result_is_ok(pub_res)) {
                n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

                n00b_quic_accept_msg_t *msg =
                    n00b_alloc_with_opts(
                        n00b_quic_accept_msg_t,
                        &(n00b_alloc_opts_t){
                            .allocator = ep->conduit
                                             ? ep->conduit->allocator
                                             : (n00b_allocator_t *)
                                                   &n00b_get_runtime()
                                                        ->conduit_pool,
                        });
                msg->header.type       = N00B_CONDUIT_MSG_USER;
                msg->header.topic      = ep->accept_topic;
                msg->header.generation =
                    n00b_conduit_topic_generation(ep->accept_topic);
                msg->header.epoch      =
                    n00b_conduit_topic_epoch(ep->accept_topic);
                msg->header.timestamp  = 0;
                msg->header.next       = nullptr;
                msg->payload.conn      = conn;

                n00b_conduit_topic_deliver_msg(
                    n00b_quic_accept_event_t,
                    (n00b_conduit_topic_t(n00b_quic_accept_event_t) *)
                        ep->accept_topic,
                    msg,
                    N00B_CONDUIT_OP_ALL);
                n00b_conduit_publish_yield(pub);
            }
        }
    }

    /* Forward this event to the per-cnx callback so we don't lose
     * the first event.  After this point, picoquic uses
     * `_n00b_quic_conn_default_callback` directly via
     * `picoquic_set_callback`, and this default cb won't be invoked
     * again for this cnx. */
    return _n00b_quic_conn_default_callback(cnx, stream_id, bytes, length,
                                            event, conn, stream_ctx);
}

/* ===========================================================================
 * Constructor
 * =========================================================================== */

n00b_result_t(n00b_quic_endpoint_t *)
n00b_quic_endpoint_new(n00b_conduit_t            *c,
                       n00b_conduit_io_backend_t *io) _kargs
{
    bool                   listen         = false;
    const char            *bind_host      = nullptr;
    uint16_t               bind_port      = 0;
    const char            *alpn           = nullptr;
    n00b_quic_trust_t     *trust          = nullptr;
    n00b_quic_secret_t    *cert           = nullptr;
    n00b_quic_secret_t    *key            = nullptr;
    n00b_string_t         *qlog_dir       = nullptr;
    const uint8_t         *cert_der_bytes = nullptr;
    size_t                 cert_der_len   = 0;
    const char            *key_pem_path   = nullptr;
    const uint8_t         *stateless_reset_secret      = nullptr;
    size_t                 stateless_reset_secret_len  = 0;
    const uint8_t         *addr_validation_token_key   = nullptr;
    size_t                 addr_validation_token_key_len = 0;
    n00b_quic_cert_store_t *cert_store    = nullptr;
    n00b_quic_metric_registry_t *metrics_registry = nullptr;
    n00b_quic_lb_cid_config_t   *lb_cid_config    = nullptr;
}
{
    n00b_allocator_scope_t pico_scope;

    if (!c || !io) {
        return n00b_result_err(n00b_quic_endpoint_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    /* picoquic/picotls call the libc malloc family directly, and that runs
     * on n00b off-libc worker threads where the first libc malloc would trap
     * (pthread_self on a minimal TCB).  Require the malloc family to be
     * interposed onto n00b's user pool before we touch any vendored code;
     * this turns a silent SIGTRAP into a clear, early error. */
    n00b_require_alloc_interposition(r"QUIC");

    /* Listen mode needs cert + key.  Phase 1 today supports the
     * test-only path: cert as DER bytes (set_tls_certificate_chain
     * works backend-agnostically) + key as a PEM file path
     * (minicrypto's key loader is file-only).  The secret_t-to-picotls
     * bridge ships with the auth/trust work in a follow-up. */
    if (listen) {
        bool have_test_path =
            (cert_der_bytes && cert_der_len > 0 && key_pem_path);
        if (!have_test_path) {
            (void)cert;
            (void)key;
            return n00b_result_err(n00b_quic_endpoint_t *,
                                   N00B_QUIC_ERR_NOT_IMPLEMENTED);
        }
    }
    /* qlog wiring happens after picoquic_create succeeds — see below. */

    /* Bind the UDP socket. */
    auto br = n00b_conduit_udp_bind(c, io, bind_host, bind_port);
    if (n00b_result_is_err(br)) {
        return n00b_result_err(n00b_quic_endpoint_t *,
                               N00B_QUIC_ERR_BIND_FAILED);
    }
    n00b_conduit_udp_t *udp = n00b_result_get(br);

    /* Allocate the endpoint handle from the conduit pool. */
    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    /* Forward decl — we want to register a finalizer that calls
     * the close path so GC reclaims the UDP fd + picoquic context
     * if the user drops the handle without explicit close.  The
     * finalizer is idempotent against `n00b_quic_endpoint_close`. */
    extern void _n00b_quic_endpoint_finalize(void *p);

    n00b_quic_endpoint_t *ep = n00b_alloc_with_opts(n00b_quic_endpoint_t,
                                  &(n00b_alloc_opts_t){
                                      .allocator      = alloc,
                                      .finalizer      = _n00b_quic_endpoint_finalize,
                                  });

    /* Per-endpoint mutex serializing all picoquic mutations
     * (run_once, chan_open / send / reset / stop_sending / close,
     * connect, conn_close).  picoquic isn't thread-safe; without
     * this lock, multi-threaded callers (e.g. the RPC test's three
     * concurrent client threads + driver thread) corrupt picoquic's
     * stream-id counter and ack state. */
    ep->lock = n00b_data_lock_new();

    /* Phase 5 § 5.1 — pre-wire metric handles when a registry is
     * supplied.  Stored on the endpoint for the chan/conn-level
     * helpers to look up.  When registry is nullptr, all helper
     * fetches return nullptr and increments are no-ops. */
    if (metrics_registry) {
        ep->metrics_registry = metrics_registry;
        n00b_list_t(n00b_buffer_t *) *kind_label = n00b_alloc(
            n00b_list_t(n00b_buffer_t *));
        *kind_label = n00b_list_new(n00b_buffer_t *);
        n00b_list_push(*kind_label, n00b_buffer_from_cstr("kind"));
        auto cr = n00b_quic_metric_counter(metrics_registry,
            "n00b_quic_chan_opens_total",
            "Total channels opened, by channel kind",
            .labels = kind_label);
        if (n00b_result_is_ok(cr)) ep->m_chan_opens_total = n00b_result_get(cr);
        auto gr = n00b_quic_metric_gauge(metrics_registry,
            "n00b_quic_chan_active",
            "Currently-active channels, by channel kind",
            .labels = kind_label);
        if (n00b_result_is_ok(gr)) ep->m_chan_active = n00b_result_get(gr);

        n00b_list_t(n00b_buffer_t *) *ep_label = n00b_alloc(
            n00b_list_t(n00b_buffer_t *));
        *ep_label = n00b_list_new(n00b_buffer_t *);
        n00b_list_push(*ep_label, n00b_buffer_from_cstr("endpoint"));
        auto er = n00b_quic_metric_gauge(metrics_registry,
            "n00b_quic_cert_expiry_seconds",
            "Seconds until the active cert expires; negative when expired",
            .labels = ep_label);
        if (n00b_result_is_ok(er)) ep->m_cert_expiry_seconds = n00b_result_get(er);
    }

    /* Default trust store: system OS-native verifier when caller
     * omits .trust=.  This is the Phase 3 reversal of Phase 1's
     * "no default" position; the design doc § 5.2 commits to a
     * safe-by-default trust path.  Callers who genuinely don't
     * want OS verification (e.g., tests with a self-signed cert
     * fixture) must pass `.trust = n00b_quic_trust_pinned(...)`
     * explicitly.
     *
     * If `n00b_quic_trust_system()` itself errors (e.g., on a
     * platform where the OS-trust glue isn't built), we propagate
     * that — better than silently constructing an endpoint that
     * can't verify anyone. */
    if (!trust) {
        auto tr = n00b_quic_trust_system();
        if (n00b_result_is_err(tr)) {
            n00b_conduit_udp_close(udp);
            return n00b_result_err(n00b_quic_endpoint_t *,
                                   n00b_result_get_err(tr));
        }
        trust = n00b_result_get(tr);
    }

    ep->conduit   = c;
    ep->io        = io;
    ep->udp       = udp;
    ep->trust     = trust;
    ep->cert      = cert;
    ep->key       = key;
    ep->is_server = listen;
    ep->closed    = false;
    ep->alpn      = nullptr;
    ep->sni_state = nullptr;
    if (alpn) {
        size_t alpn_len = strlen(alpn);
        ep->alpn = n00b_alloc_array_with_opts(char, alpn_len + 1,
                       &(n00b_alloc_opts_t){.allocator = alloc, .no_scan = true});
        memcpy(ep->alpn, alpn, alpn_len + 1);
    }

    /* Build the picoquic context.  Client-only at this revision: no
     * cert / key / cert_root files; ticket store off; default callback
     * is the no-op above.
     *
     * The stateless-reset secret seed is the caller-supplied bytes if
     * provided (multi-instance deployments share these across the LB
     * pool), otherwise we generate fresh CSPRNG entropy.  picoquic
     * does not expose a setter for this seed after create — rotation
     * requires endpoint replacement, which matches the design doc § 7
     * choice. */
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];
    if (stateless_reset_secret
        && stateless_reset_secret_len == sizeof(reset_seed)) {
        memcpy(reset_seed, stateless_reset_secret, sizeof(reset_seed));
    } else if (stateless_reset_secret
               && stateless_reset_secret_len != sizeof(reset_seed)) {
        n00b_conduit_udp_close(udp);
        return n00b_result_err(n00b_quic_endpoint_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    } else {
        n00b_random_bytes((char *)reset_seed, sizeof(reset_seed));
    }

    /* Address-validation token key — must be a multiple of 16; we
     * accept 16 or 32.  picoquic copies the bytes into its internal
     * state at create time. */
    if (addr_validation_token_key
        && addr_validation_token_key_len != 16
        && addr_validation_token_key_len != 32) {
        n00b_conduit_udp_close(udp);
        return n00b_result_err(n00b_quic_endpoint_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    }

    uint64_t now_us = (uint64_t)n00b_us_timestamp();

#if defined(__linux__)
    ep->pico_now_us = now_us;
    n00b_quic_install_linux_random_provider();
#endif

    picoquic_quic_t *quic = nullptr;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    quic = picoquic_create(
        /* max_nb_connections        */ 256,
        /* cert_file_name            */ nullptr,
        /* key_file_name             */ nullptr,
        /* cert_root_file_name       */ nullptr,
        /* default_alpn              */ alpn,
        /* default_callback_fn       */ default_stream_cb,
        /* default_callback_ctx      */ ep,
        /* cnx_id_callback           */ lb_cid_config ? endpoint_lb_cid_cb : nullptr,
        /* cnx_id_callback_data      */ lb_cid_config,
        /* reset_seed                */ reset_seed,
        /* current_time              */ now_us,
#if defined(__linux__)
        /* p_simulated_time          */ &ep->pico_now_us,
#else
        /* p_simulated_time          */ nullptr,
#endif
        /* ticket_file_name          */ nullptr,
        /* ticket_encryption_key     */ addr_validation_token_key,
        /* ticket_encryption_key_len */ addr_validation_token_key_len);
    n00b_allocator_scope_exit(&pico_scope);

    if (!quic) {
        n00b_conduit_udp_close(udp);
        return n00b_result_err(n00b_quic_endpoint_t *,
                               N00B_QUIC_ERR_HANDSHAKE);
    }

    /* Phase 5 § 5.8 — LB-CID requires the default CID length to be
     * exactly 16 bytes (one AES-128 block).  picoquic defaults to 8;
     * override before any cnx is created.  Stash the cfg on the
     * endpoint so it survives as long as the endpoint does (the
     * picoquic callback only borrows the pointer). */
    if (lb_cid_config) {
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        (void)picoquic_set_default_connection_id_length(
            quic, N00B_QUIC_LB_CID_LEN);
        n00b_allocator_scope_exit(&pico_scope);
    }

    /* RFC 9221 datagrams: advertise willingness to receive datagrams
     * up to ~64 KiB.  This MUST be set before any cnx is created
     * (transport params are populated at picoquic_create_cnx time).
     * A value of 0 means "we don't support datagrams" — picoquic's
     * default.  Setting any non-zero value enables the path; picoquic
     * negotiates the effective value with the peer. */
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    (void)picoquic_set_default_tp_value(quic,
                                        picoquic_tp_max_datagram_frame_size,
                                        65535);
    n00b_allocator_scope_exit(&pico_scope);

    /* qlog: opt-in via .qlog_dir.  Picoquic writes one .qlog file per
     * connection into this directory using QUIC qlog v0.3-ish JSON.
     * Useful with `qvis` (https://qvis.quictools.info/) for visual
     * handshake / loss analysis.  We `mkdir` it if it doesn't exist
     * so the user doesn't have to do it.  Failure to set up qlog
     * here is non-fatal — the rest of the endpoint still works.
     *
     * Per `quic_1.md § 11`: nullptr (default) is the production
     * setting; qlog is a debug knob that's off by default. */
    if (qlog_dir && qlog_dir->data && qlog_dir->u8_bytes > 0) {
        struct stat st;
        if (stat(qlog_dir->data, &st) != 0) {
            (void)N00B_QLOG_MKDIR(qlog_dir->data, 0755);
        }
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        (void)picoquic_set_qlog(quic, qlog_dir->data);
        n00b_allocator_scope_exit(&pico_scope);
    }

    /* Listen-mode: install the cert chain (in-memory iovec) + key (via
     * file path through minicrypto's PEM loader) into picoquic's TLS
     * context.
     *
     * picoquic takes ownership of the cert iovec list + individual
     * base pointers (it frees them with `free()` at teardown).
     * Allocators therefore use malloc/calloc here rather than the
     * conduit pool.
     *
     * The key file load happens inside picoquic_set_private_key_from_file
     * which dispatches to whichever backend is registered (minicrypto
     * for our Phase 1 build).  picotls reads, parses, then closes the
     * file; the caller does not need to keep it open. */
    if (listen) {
        /* picoquic takes ownership of `certs` + `cert_copy` and frees both
         * during `picoquic_master_tlscontext_free` (tls_api.c:
         * `free_certificates_list`). picoquic is built with the libc-malloc
         * interpose shim force-included, so that `free()` is
         * `n00b_interposed_free`, which recovers the user_pool base and
         * `n00b_free`s it. So we allocate from the same user pool via the
         * explicit n00b API (NOT n00b_alloc_with_opts, whose GC-heap pointers
         * the interposed free would mis-route to libc free → heap corruption). */
        ptls_iovec_t *certs = nullptr;
        uint8_t      *cert_copy = nullptr;
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        certs = (ptls_iovec_t *)n00b_interposed_calloc(1, sizeof(ptls_iovec_t));
        cert_copy = (uint8_t *)n00b_interposed_malloc(cert_der_len);
        n00b_allocator_scope_exit(&pico_scope);
        if (!certs || !cert_copy) {
            n00b_interposed_free(certs);
            n00b_interposed_free(cert_copy);
            pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
            picoquic_free(quic);
            n00b_allocator_scope_exit(&pico_scope);
            n00b_conduit_udp_close(udp);
            return n00b_result_err(n00b_quic_endpoint_t *,
                                   N00B_QUIC_ERR_HANDSHAKE);
        }
        memcpy(cert_copy, cert_der_bytes, cert_der_len);
        certs[0].base = cert_copy;
        certs[0].len  = cert_der_len;
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        picoquic_set_tls_certificate_chain(quic, certs, 1);
        n00b_allocator_scope_exit(&pico_scope);

        int kr = 0;
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        kr = picoquic_set_private_key_from_file(quic, key_pem_path);
        n00b_allocator_scope_exit(&pico_scope);
        if (kr != 0) {
            pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
            picoquic_free(quic);
            n00b_allocator_scope_exit(&pico_scope);
            n00b_conduit_udp_close(udp);
            return n00b_result_err(n00b_quic_endpoint_t *,
                                   N00B_QUIC_ERR_HANDSHAKE);
        }

        /* picoquic_create defaults to enforce_client_only=1 whenever
         * the cert/key file paths are NULL — which they are in our
         * code path because we install via in-memory APIs.  Without
         * this override the server returns SERVER_BUSY (transport
         * error code 0x02) on every Initial it receives.  See
         * quicctx.c:727 in upstream. */
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        picoquic_enforce_client_only(quic, 0);
        n00b_allocator_scope_exit(&pico_scope);
    }

    ep->quic = quic;

    /* Install the trust→picotls verify-cert bridge.  Replaces
     * picoquic's default verifier with one that delegates to
     * `ep->trust` (defaulted to system trust above).  This is what
     * makes a real client-side cert verification fire during the
     * QUIC handshake — Phase 1 had no working bridge so tests used
     * `picoquic_set_null_verifier`.  Tests that need to bypass
     * verification still can: pass `.trust = n00b_quic_trust_pinned(...)`
     * with a fingerprint that matches the test cert.
     *
     * For server endpoints the verifier only fires when client-auth
     * is enabled; with client-auth off (the Phase 1/2 default)
     * picotls never asks for a peer cert and the callback is
     * silent.  No-op for the server path. */
    int vr = 0;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    vr = n00b_quic_picotls_verify_install(quic, ep->trust);
    n00b_allocator_scope_exit(&pico_scope);
    if (vr != 0) {
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        picoquic_free(quic);
        n00b_allocator_scope_exit(&pico_scope);
        n00b_conduit_udp_close(udp);
        return n00b_result_err(n00b_quic_endpoint_t *,
                               N00B_QUIC_ERR_HANDSHAKE);
    }

    /* When a cert_store is supplied, install the SNI-routing
     * callbacks.  The cert_der_bytes / key_pem_path path above
     * (if also supplied) is used as a fallback for ClientHellos
     * whose SNI doesn't match any store entry. */
    if (cert_store) {
        int sr = 0;
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        sr = n00b_quic_picotls_sni_install(quic, cert_store,
                                           &ep->sni_state);
        n00b_allocator_scope_exit(&pico_scope);
        if (sr != 0) {
            pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
            picoquic_free(quic);
            n00b_allocator_scope_exit(&pico_scope);
            n00b_conduit_udp_close(udp);
            return n00b_result_err(n00b_quic_endpoint_t *,
                                   N00B_QUIC_ERR_HANDSHAKE);
        }
    }

    /* Subscribe to the UDP recv topic so received datagrams accumulate
     * in the endpoint's inbox.  run_once drains this on each pass. */
    ep->inbox = n00b_conduit_udp_inbox_new(c);
    n00b_conduit_topic_base_t *recv_topic = n00b_conduit_udp_recv_topic(udp);
    ep->recv_sub = n00b_conduit_udp_subscribe(recv_topic, ep->inbox,
                                              .operations = N00B_CONDUIT_OP_ALL);

    /* Outbound queued-send mailbox.  Producers off the I/O thread
     * call `n00b_quic_chan_send_queued`, which publishes here; the
     * I/O thread pops at the head of every `run_once`. */
    ep->outbound_topic = nullptr;
    ep->outbound_inbox = nullptr;
    ep->outbound_sub   = 0;
    {
        n00b_conduit_topic_t(n00b_quic_pending_send_t) *out_topic =
            n00b_conduit_topic_init(n00b_quic_pending_send_t,
                                    c,
                                    N00B_CONDUIT_URI_QUIC_OUTBOUND(udp->udp_id));
        if (out_topic) {
            ep->outbound_topic = (n00b_conduit_topic_base_t *)out_topic;
            ep->outbound_inbox = n00b_quic_pending_send_inbox_new(c);
            ep->outbound_sub   = n00b_quic_pending_send_subscribe(
                ep->outbound_topic, ep->outbound_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }
    }

    ep->rx_packets   = 0;
    ep->tx_packets   = 0;
    ep->accepted     = nullptr;
    ep->accept_topic = nullptr;

    /* Server endpoints expose an accept topic that publishes one
     * `n00b_quic_accept_event_t` per inbound connection.  Use the
     * UDP socket's id (which is unique within the conduit) as the
     * topic ID for stable lookup. */
    if (listen) {
        n00b_conduit_topic_t(n00b_quic_accept_event_t) *accept_topic =
            n00b_conduit_topic_init(n00b_quic_accept_event_t,
                                    c,
                                    N00B_CONDUIT_URI_QUIC_ACCEPT(udp->udp_id));
        if (accept_topic) {
            ep->accept_topic = (n00b_conduit_topic_base_t *)accept_topic;
        }
    }

    return n00b_result_ok(n00b_quic_endpoint_t *, ep);
}

/* ===========================================================================
 * Send drain — pump picoquic_prepare_next_packet until empty
 * =========================================================================== */

static int
endpoint_drain_send(n00b_quic_endpoint_t *ep)
{
    n00b_allocator_scope_t pico_scope;
    int sent = 0;

    /* Bounded loop guards against pathological cases where picoquic
     * hands us a packet whose sendto fails repeatedly; we cap at the
     * stream-budget ceiling × 4 (4 packets per stream is generous). */
    int budget = (int)(N00B_QUIC_DEFAULT_MAX_STREAMS_BIDI * 4);

    while (sent < budget) {
        uint8_t                 buf[1500];
        size_t                  send_len = 0;
        struct sockaddr_storage addr_to;
        struct sockaddr_storage addr_from;
        int                     if_index = 0;
        picoquic_connection_id_t log_cid = {0};
        picoquic_cnx_t          *cnx     = nullptr;

        memset(&addr_to,   0, sizeof(addr_to));
        memset(&addr_from, 0, sizeof(addr_from));

        uint64_t now = (uint64_t)n00b_us_timestamp();
#if defined(__linux__)
        ep->pico_now_us = now;
#endif
        int rc = 0;
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        rc = picoquic_prepare_next_packet(
            ep->quic, now, buf, sizeof(buf), &send_len,
            &addr_to, &addr_from, &if_index, &log_cid, &cnx);
        n00b_allocator_scope_exit(&pico_scope);

        if (rc != 0 || send_len == 0) {
            break;
        }

        socklen_t alen = (addr_to.ss_family == AF_INET)
            ? (socklen_t)sizeof(struct sockaddr_in)
            : (socklen_t)sizeof(struct sockaddr_in6);

        auto sr = n00b_conduit_udp_send(ep->udp,
                                        (const struct sockaddr *)&addr_to,
                                        alen, buf, send_len);
        if (n00b_result_is_err(sr)) {
            /* sendto failed — likely EAGAIN or peer unreachable.  Stop
             * draining; caller will retry on next run_once after the
             * write window opens. */
            break;
        }
        ep->tx_packets++;
        sent++;
    }
    return sent;
}

/* ===========================================================================
 * Run-once driver
 * =========================================================================== */

n00b_result_t(int)
n00b_quic_endpoint_run_once(n00b_quic_endpoint_t *ep, int timeout_ms)
{
    n00b_allocator_scope_t pico_scope;

    if (!ep || ep->closed || !ep->quic || !ep->udp) {
        return n00b_result_err(int, N00B_QUIC_ERR_INVALID_ARG);
    }

    /* Block in the IO backend until something is ready (or the timeout
     * elapses).  This delivers UDP datagrams onto our inbox via the
     * dispatch path.  Done OUTSIDE the picoquic lock so other threads
     * issuing chan_open / chan_send aren't blocked while we wait on
     * the kernel. */
    (void)n00b_conduit_io_poll(ep->io, timeout_ms);

    /* Take the picoquic lock for the rest of the function — every
     * call from here mutates picoquic state. */
    n00b_data_write_lock(ep->lock);

    /* Cache the local addr once; it does not change for the lifetime
     * of the endpoint.  picoquic wants this for path tracking. */
    struct sockaddr_storage local_addr;
    socklen_t               local_len = sizeof(local_addr);
    memset(&local_addr, 0, sizeof(local_addr));
    auto la_r = n00b_conduit_udp_local_addr(ep->udp,
                                            (struct sockaddr *)&local_addr,
                                            &local_len);
    bool have_local = n00b_result_is_ok(la_r);

    /* Drain the recv inbox into picoquic. */
    int got = 0;
    while (n00b_conduit_udp_inbox_has_messages(ep->inbox)) {
        n00b_conduit_udp_datagram_msg_t *msg =
            n00b_conduit_udp_inbox_pop(ep->inbox);
        if (!msg) {
            break;
        }
        if (msg->payload.bytes && msg->payload.len > 0) {
            uint64_t now = (uint64_t)n00b_us_timestamp();
#if defined(__linux__)
            ep->pico_now_us = now;
#endif
            pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
            picoquic_incoming_packet(
                ep->quic,
                msg->payload.bytes,
                msg->payload.len,
                (struct sockaddr *)&msg->payload.peer,
                have_local ? (struct sockaddr *)&local_addr : nullptr,
                /* if_index_to */ 0,
                /* received_ecn */ 0,
                now);
            n00b_allocator_scope_exit(&pico_scope);
            ep->rx_packets++;
            got++;
        }
    }

    /* Drain queued sends from any-thread producers (e.g. handler
     * dispatch threads).  All `picoquic_add_to_stream` calls happen
     * on this thread, serialized with packet preparation below. */
    if (ep->outbound_inbox) {
        while (n00b_quic_pending_send_inbox_has_messages(ep->outbound_inbox)) {
            n00b_quic_pending_send_msg_t *m =
                n00b_quic_pending_send_inbox_pop(ep->outbound_inbox);
            if (!m) {
                break;
            }
            n00b_quic_chan_t *chan = m->payload.chan;
            if (!chan || chan->closed) {
                continue;
            }
            (void)n00b_quic_chan_send(chan,
                                       m->payload.bytes,
                                       m->payload.len,
                                       .fin = m->payload.fin);
        }
    }

    /* Always drain send: incoming packets cause picoquic to schedule
     * outgoing packets, and so do timer-driven retransmits even when
     * no packet came in. */
    endpoint_drain_send(ep);

    n00b_data_unlock(ep->lock);
    return n00b_result_ok(int, got);
}

/* ===========================================================================
 * Stats accessor
 * =========================================================================== */

/* GC-time finalizer.  Idempotent against `n00b_quic_endpoint_close`. */
void
_n00b_quic_endpoint_finalize(void *p)
{
    n00b_quic_endpoint_close((n00b_quic_endpoint_t *)p);
}

/* Test-only accessor: returns the underlying picoquic_quic_t.  Public
 * code should never reach into picoquic directly through the endpoint;
 * this exists so that tests in `test/unit/test_quic_*.c` can configure
 * picoquic settings (e.g., disable cert verification) that the n00b
 * QUIC API doesn't yet expose.  When the relevant n00b API surface
 * lands, this stub goes away. */
struct st_picoquic_quic_t *
n00b_quic_test_endpoint_quic(n00b_quic_endpoint_t *ep)
{
    return ep ? (struct st_picoquic_quic_t *)ep->quic : nullptr;
}

n00b_option_t(n00b_conduit_topic_base_t *)
n00b_quic_endpoint_accept_topic(n00b_quic_endpoint_t *ep)
{
    if (!ep || ep->closed || !ep->accept_topic) {
        return n00b_option_none(n00b_conduit_topic_base_t *);
    }
    return n00b_option_set(n00b_conduit_topic_base_t *, ep->accept_topic);
}

n00b_quic_endpoint_stats_t
n00b_quic_endpoint_stats(n00b_quic_endpoint_t *ep)
{
    n00b_quic_endpoint_stats_t s = {0};
    if (ep && !ep->closed) {
        s.rx_packets = ep->rx_packets;
        s.tx_packets = ep->tx_packets;
    }
    return s;
}

/* ===========================================================================
 * Accessors
 * =========================================================================== */

uint16_t
n00b_quic_endpoint_local_port(n00b_quic_endpoint_t *ep)
{
    if (!ep || ep->closed || !ep->udp) {
        return 0;
    }
    struct sockaddr_storage ss;
    socklen_t               sslen = sizeof(ss);
    auto                    r     =
        n00b_conduit_udp_local_addr(ep->udp,
                                    (struct sockaddr *)&ss, &sslen);
    if (n00b_result_is_err(r) || ss.ss_family != AF_INET) {
        return 0;
    }
    return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

/* ===========================================================================
 * Hot-reload (cert + key swap)
 *
 * Wraps picoquic's per-quic-context cert/key setters.  Atomicity
 * caveats are documented in the header.
 * =========================================================================== */

n00b_result_t(bool)
n00b_quic_endpoint_reload_cert(n00b_quic_endpoint_t *ep,
                               n00b_quic_cert_reload_t reload)
{
    return n00b_quic_endpoint_reload_cert_raw(
        ep,
        .cert_der_bytes = reload.cert_der_bytes,
        .cert_der_len   = reload.cert_der_len,
        .key_pem_path   = reload.key_pem_path);
}

n00b_result_t(bool)
n00b_quic_endpoint_reload_cert_raw(n00b_quic_endpoint_t *ep) _kargs
{
    const uint8_t *cert_der_bytes = nullptr;
    size_t         cert_der_len   = 0;
    const char    *key_pem_path   = nullptr;
}
{
    n00b_allocator_scope_t pico_scope;

    if (!ep || ep->closed || !ep->is_server || !ep->quic) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!cert_der_bytes || cert_der_len == 0 || !key_pem_path) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }

    /* picoquic owns the iovec list + its base pointers and frees them with its
     * (shim-interposed) `free()` at teardown, which recovers the user_pool base
     * and n00b_frees it — so we allocate from the user pool via the explicit
     * n00b API, mirroring the initial-setup path in n00b_quic_endpoint_new. */
    ptls_iovec_t *certs = nullptr;
    uint8_t      *copy  = nullptr;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    certs = (ptls_iovec_t *)n00b_interposed_calloc(1, sizeof(ptls_iovec_t));
    copy  = (uint8_t *)n00b_interposed_malloc(cert_der_len);
    n00b_allocator_scope_exit(&pico_scope);
    if (!certs || !copy) {
        n00b_interposed_free(certs);
        n00b_interposed_free(copy);
        return n00b_result_err(bool, N00B_QUIC_ERR_HANDSHAKE);
    }
    memcpy(copy, cert_der_bytes, cert_der_len);
    certs[0].base = copy;
    certs[0].len  = cert_der_len;

    /* picoquic_set_tls_certificate_chain installs in place, replacing
     * any previously installed chain. */
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    picoquic_set_tls_certificate_chain(ep->quic, certs, 1);
    n00b_allocator_scope_exit(&pico_scope);

    int kr = 0;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    kr = picoquic_set_private_key_from_file(ep->quic, key_pem_path);
    n00b_allocator_scope_exit(&pico_scope);
    if (kr != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_HANDSHAKE);
    }

    return n00b_result_ok(bool, true);
}

/* ===========================================================================
 * Thread-safe queued send
 *
 * Producers off the I/O thread (e.g. RPC handler dispatch threads)
 * publish a `n00b_quic_pending_send_t` onto the endpoint's
 * `outbound_topic`; the I/O thread drains the matching inbox at the
 * head of every `run_once` and replays each message via
 * `n00b_quic_chan_send` (which is just a thin wrapper around
 * `picoquic_add_to_stream`).  This keeps every picoquic state
 * mutation on a single thread without blocking the producer.
 * =========================================================================== */

n00b_result_t(bool)
n00b_quic_chan_send_queued(n00b_quic_chan_t *chan,
                           const uint8_t   *bytes,
                           size_t           len) _kargs
{
    bool fin = false;
}
{
    if (!chan || chan->closed || !chan->conn || chan->conn->closed) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!bytes && len > 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }

    n00b_quic_endpoint_t *ep = chan->conn->endpoint;
    if (!ep || ep->closed || !ep->outbound_topic) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }

    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    /* Claim a publisher slot.  Topic policy is OPEN, so any thread
     * may claim — failures here are essentially "topic closed". */
    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(ep->outbound_topic);
    if (n00b_result_is_err(pub_res)) {
        return n00b_result_err(bool, N00B_QUIC_ERR_FLOW_BLOCKED);
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_quic_pending_send_msg_t *msg =
        n00b_alloc_with_opts(n00b_quic_pending_send_msg_t,
                             &(n00b_alloc_opts_t){.allocator = alloc});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = ep->outbound_topic;
    msg->header.generation = n00b_conduit_topic_generation(ep->outbound_topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(ep->outbound_topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    /* Copy bytes into a conduit-pool buffer; the producer's source
     * memory is borrowed only for the duration of this call. */
    uint8_t *copy = nullptr;
    if (len > 0) {
        copy = n00b_alloc_array_with_opts(uint8_t, (int64_t)len,
                   &(n00b_alloc_opts_t){
                       .allocator = alloc,
                       .no_scan   = true,
                   });
        memcpy(copy, bytes, len);
    }

    msg->payload.chan  = chan;
    msg->payload.bytes = copy;
    msg->payload.len   = len;
    msg->payload.fin   = fin;

    n00b_conduit_topic_deliver_msg(
        n00b_quic_pending_send_t,
        (n00b_conduit_topic_t(n00b_quic_pending_send_t) *)ep->outbound_topic,
        msg,
        N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_yield(pub);

    return n00b_result_ok(bool, true);
}

/* ===========================================================================
 * Close
 * =========================================================================== */

void
n00b_quic_endpoint_close(n00b_quic_endpoint_t *ep)
{
    n00b_allocator_scope_t pico_scope;

    if (!ep || ep->closed) {
        return;
    }
    ep->closed = true;

    /* Cancel the recv subscription before closing the UDP socket so
     * no more datagrams race onto the inbox during teardown. */
    if (ep->recv_sub != 0) {
        n00b_conduit_sub_cancel(ep->recv_sub);
        ep->recv_sub = 0;
    }
    if (ep->outbound_sub != 0) {
        n00b_conduit_sub_cancel(ep->outbound_sub);
        ep->outbound_sub = 0;
    }
    if (ep->outbound_topic) {
        n00b_conduit_topic_close(ep->outbound_topic);
        ep->outbound_topic = nullptr;
    }
    if (ep->quic) {
        /* On the CLIENT path, our n00b_quic_picotls_install_client_auth
         * may have set `tls_master_ctx->sign_certificate` to
         * conduit-pool-backed storage and `certificates.list` to a
         * conduit-pool-backed iovec array.  picoquic's teardown
         * unconditionally calls libc `free()` on both — which would
         * corrupt the heap.  Clear the slots before picoquic_free so
         * picoquic sees them as already disposed.
         *
         * Server endpoints don't go through this path: picoquic
         * itself populates sign_certificate + certificates from the
         * cert/key inputs and owns the malloc(), so leave them alone
         * for picoquic's teardown to free correctly. */
        if (!ep->is_server) {
            ptls_context_t *master =
                (ptls_context_t *)ep->quic->tls_master_ctx;
            if (master) {
                master->sign_certificate   = nullptr;
                master->certificates.list  = nullptr;
                master->certificates.count = 0;
            }
        }
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        picoquic_free(ep->quic);
        n00b_allocator_scope_exit(&pico_scope);
        ep->quic = nullptr;
    }
    if (ep->udp) {
        n00b_conduit_udp_close(ep->udp);
        ep->udp = nullptr;
    }
    /* Inbox and msg buffers are reachable from the conduit allocator
     * until the conduit itself is destroyed; nothing further to free
     * here. */
}

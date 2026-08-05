/**
 * @file endpoint.h
 * @brief QUIC endpoint — UDP socket + picoquic context.
 *
 * `n00b_quic_endpoint_t` pairs a UDP datagram socket (via the
 * conduit's UDP primitive) with a picoquic context.  An endpoint can
 * both initiate outbound connections (always) and accept inbound
 * connections (when constructed in listen mode).
 *
 * ### What this does today
 *
 * Phase 1 (this revision) ships endpoint **lifecycle** only — create
 * and close.  The recv → `picoquic_incoming_packet` → `picoquic_prepare_next_packet`
 * → send loop lands in the follow-up that wires up the per-channel
 * APIs.  An endpoint created today is a real `picoquic_quic_t` bound
 * to a real UDP socket; it just doesn't yet drive packets through
 * picoquic.
 *
 * ### Listen vs initiate
 *
 * - **Initiate-only** (default) — the endpoint can call
 *   `n00b_quic_connect` to open outbound connections.  No cert / key
 *   required.  Trust store optional (defaults to system).
 * - **Listen** (`.listen = true`) — the endpoint accepts inbound
 *   connections in addition to initiating.  Requires `cert` and `key`
 *   secret handles.  *Phase 1 does not yet ship listen mode*; the
 *   constructor returns @c N00B_QUIC_ERR_NOT_IMPLEMENTED until the
 *   secret-to-picotls bridge lands.
 *
 * ### Allocator discipline
 *
 * The endpoint and every long-lived object it owns (picoquic context,
 * UDP socket handle, etc.) live in the conduit pool.  Per
 * `docs/quic/allocator.md`.
 *
 * @see conn.h, chan.h, trust.h, secret.h
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/string.h"
#include "core/buffer.h"
#include "conduit/conduit.h"
#include "conduit/conduit_types.h"
#include "conduit/io.h"
#include "conduit/topic.h"
#include "conduit/inbox.h"
#include "conduit/subscription.h"
#include "conduit/message.h"
#include "conduit/publisher.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"
#include "net/quic/lb_cid.h"
#include "net/quic/metrics.h"
#include "crypto/secret.h"

/* ===========================================================================
 * Accept event — published once per server-accepted connection.
 *
 * The payload carries a borrowed pointer to the new connection.  The
 * subscriber owns the responsibility for whatever it does with the
 * conn (typically: walk channels and respond, or close).  The conn's
 * lifetime is bounded by the endpoint and by the connection's own
 * lifecycle — picoquic tears it down when the peer closes or the
 * idle timer expires.
 * =========================================================================== */

typedef struct {
    n00b_quic_conn_t *conn;
} n00b_quic_accept_event_t;

N00B_CONDUIT_FULL_IMPL(n00b_quic_accept_event_t);

/* ===========================================================================
 * Pending-send payload — queued from any thread, drained on the I/O thread.
 *
 * Producers off the endpoint's I/O thread MUST queue wire bytes via
 * `n00b_quic_chan_send_queued`.  The bytes are copied into the
 * conduit pool so the producer's source buffer is borrowed only for
 * the duration of the enqueue call.  The I/O thread pops the message
 * before its `endpoint_drain_send` step and replays it via the raw
 * `n00b_quic_chan_send` (which calls picoquic_add_to_stream); all
 * picoquic state mutation thus stays single-threaded.
 * =========================================================================== */

typedef struct {
    n00b_quic_chan_t *chan;       /**< Target channel; borrowed. */
    uint8_t          *bytes;      /**< Wire bytes (conduit-pool-owned copy). */
    size_t            len;        /**< Length of @c bytes. */
    bool              fin;        /**< FIN this direction after flush. */
} n00b_quic_pending_send_t;

N00B_CONDUIT_FULL_IMPL(n00b_quic_pending_send_t);

typedef n00b_conduit_message_t(n00b_quic_accept_event_t)
    n00b_quic_accept_msg_t;
typedef n00b_conduit_inbox_t(n00b_quic_accept_event_t)
    n00b_quic_accept_inbox_t;

typedef n00b_conduit_message_t(n00b_quic_pending_send_t)
    n00b_quic_pending_send_msg_t;
typedef n00b_conduit_inbox_t(n00b_quic_pending_send_t)
    n00b_quic_pending_send_inbox_t;

#define n00b_quic_pending_send_inbox_new(c)                                    \
    ({                                                                         \
        n00b_conduit_t *_c = (c);                                               \
        n00b_quic_pending_send_inbox_t *_inbox =                               \
            n00b_alloc_with_opts(n00b_quic_pending_send_inbox_t,                \
                &(n00b_alloc_opts_t){.allocator = _c->allocator});             \
        n00b_conduit_inbox_init(n00b_quic_pending_send_t,                      \
                                _inbox, _c, N00B_CONDUIT_BP_UNBOUNDED, 0);     \
        _inbox;                                                                \
    })

#define n00b_quic_pending_send_subscribe(topic, inbox, ...)                    \
    n00b_conduit_subscribe(n00b_quic_pending_send_t,                           \
                           (n00b_conduit_topic_t(n00b_quic_pending_send_t) *)(topic), \
                           inbox, __VA_ARGS__)

#define n00b_quic_pending_send_inbox_pop(inbox)                                \
    n00b_conduit_inbox_pop_msg(n00b_quic_pending_send_t, inbox)

#define n00b_quic_pending_send_inbox_has_messages(inbox)                       \
    n00b_conduit_inbox_has_msg(n00b_quic_pending_send_t, inbox)

/** @brief Convenience: create a typed inbox for accept events. */
#define n00b_quic_accept_inbox_new(c)                                          \
    ({                                                                         \
        n00b_conduit_t *_c = (c);                                               \
        n00b_quic_accept_inbox_t *_inbox =                                     \
            n00b_alloc_with_opts(n00b_quic_accept_inbox_t,                     \
                &(n00b_alloc_opts_t){.allocator = _c->allocator});             \
        n00b_conduit_inbox_init(n00b_quic_accept_event_t,                      \
                                _inbox, _c, N00B_CONDUIT_BP_UNBOUNDED, 0);     \
        _inbox;                                                                \
    })

#define n00b_quic_accept_subscribe(topic, inbox, ...)                          \
    n00b_conduit_subscribe(n00b_quic_accept_event_t,                           \
                           (n00b_conduit_topic_t(n00b_quic_accept_event_t) *)(topic), \
                           inbox, __VA_ARGS__)

#define n00b_quic_accept_inbox_pop(inbox)                                      \
    n00b_conduit_inbox_pop_msg(n00b_quic_accept_event_t, inbox)

#define n00b_quic_accept_inbox_has_messages(inbox)                             \
    n00b_conduit_inbox_has_msg(n00b_quic_accept_event_t, inbox)

#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

/**
 * @brief Create a QUIC endpoint backed by a UDP socket.
 *
 * Allocates a new endpoint, binds a UDP socket through the conduit's
 * UDP primitive, and creates a picoquic context wired to that socket.
 * The endpoint is the entry point for both outbound connections (via
 * @c n00b_quic_connect, follow-up) and accepted inbound connections
 * (via the topic returned from @c n00b_quic_endpoint_accept_topic,
 * follow-up).
 *
 * @param c   Conduit to register the endpoint's resources under.
 * @param io  IO backend for the UDP socket.
 *
 * @kw listen     Default: false.  Accept inbound connections in
 *                addition to initiating.  Requires @p cert and @p key.
 * @kw bind_host  Local bind address as a string (e.g., "127.0.0.1",
 *                "::").  Default: nullptr → IPv4 wildcard.
 * @kw bind_port  Local UDP port.  Default: 0 → ephemeral.
 * @kw alpn       NUL-terminated ALPN identifier (e.g., "n00b-echo/1").
 *                Default: nullptr → no ALPN advertised (rejected by most
 *                peers; set explicitly for production).
 * @kw trust      Trust store for verifying peer certs.  Default:
 *                nullptr → not yet supported (was: system store; that
 *                lands with picotls integration).
 * @kw cert       Server certificate handle.  Required if listen=true.
 * @kw key        Server private-key handle.  Required if listen=true.
 * @kw qlog_dir   Directory to write per-connection qlog files.
 *                Default: nullptr → disabled.  *Currently a no-op;
 *                qlog wiring lands with the qlog module.*
 * @kw lb_cid_config Optional QUIC LB-CID config
 *                (`include/quic/lb_cid.h`).  Default: nullptr →
 *                picoquic uses random CIDs.  Borrowed; must
 *                outlive the endpoint.  See
 *                [`security.md` § QUIC LB-CID](../../docs/quic/security.md)
 *                + Phase 5 § 5.8 for the deployment story.
 *
 * @return Result: ok with the new endpoint, or err on failure.
 *         @c N00B_QUIC_ERR_NOT_IMPLEMENTED for listen=true at this
 *         revision.
 *
 * @pre @p c and @p io are non-NULL and registered together.
 * @post On success the endpoint owns a UDP socket allocated from
 *       the conduit pool and a picoquic context with default
 *       transport parameters.
 */
extern n00b_result_t(n00b_quic_endpoint_t *)
    n00b_quic_endpoint_new(n00b_conduit_t            *c,
                           n00b_conduit_io_backend_t *io)
    _kargs {
        bool                   listen    = false;
        const char            *bind_host = nullptr;
        uint16_t               bind_port = 0;
        const char            *alpn      = nullptr;
        n00b_quic_trust_t     *trust     = nullptr;
        n00b_quic_secret_t    *cert      = nullptr;
        n00b_quic_secret_t    *key       = nullptr;
        n00b_string_t         *qlog_dir  = nullptr;
        /* Test-only path for listen mode: raw DER bytes for the cert
         * chain + a PEM file path for the private key.  The cert
         * is in-memory because picoquic_set_tls_certificate_chain
         * works backend-agnostically; the key goes through a path
         * because picotls's minicrypto backend's key loader is
         * file-only (no in-memory variant ships in minicrypto).  This
         * is awkward by design: the production path is the
         * secret_t-to-picotls sign-callback bridge, which lands when
         * the auth/trust work ships.  For Phase 1 this is the only
         * working path for listen=true; never call it from production
         * code. */
        const uint8_t         *cert_der_bytes = nullptr;
        size_t                 cert_der_len   = 0;
        const char            *key_pem_path   = nullptr;

        /*
         * Stateless-reset + address-validation token seeds (RFC 9000
         * § 10.3 / § 8.1.4).  When omitted, the endpoint generates
         * fresh random bytes from the OS CSPRNG at construction.
         *
         * For multi-instance deployments behind a load balancer,
         * callers should pull these from a `n00b_quic_sticky_secret_t`
         * shared across instances; see `include/quic/sticky_secret.h`
         * and `~/dd/quic_2.md` § 7.3.  picoquic only accepts these
         * seeds at create time — rotation requires endpoint
         * replacement.
         */
        const uint8_t         *stateless_reset_secret      = nullptr;  /* 32 bytes */
        size_t                 stateless_reset_secret_len  = 0;
        const uint8_t         *addr_validation_token_key   = nullptr;  /* 16 bytes */
        size_t                 addr_validation_token_key_len = 0;

        /*
         * SNI-keyed cert store (Phase 2 § 6).  When set, the
         * endpoint installs picotls's per-cnx callbacks
         * (on_client_hello / emit_certificate / sign_certificate)
         * to look up the cert per-cnx based on the ClientHello's
         * SNI extension.  Mutually compatible with cert_der_bytes /
         * key_pem_path: those install a fallback that the SNI
         * router consults when no cert_store entry matches.
         *
         * Borrowed; must outlive the endpoint.
         */
        struct n00b_quic_cert_store *cert_store = nullptr;

        /*
         * Phase 5 § 5.1 — optional metrics registry.  When set, the
         * endpoint registers `n00b_quic_chan_opens_total{kind}`,
         * `n00b_quic_chan_active{kind}`, and
         * `n00b_quic_cert_expiry_seconds{endpoint}` against the
         * registry, and updates them on chan open/close + cert
         * load.  When nullptr, no metric instrumentation is wired.
         *
         * Borrowed; must outlive the endpoint.
         */
        n00b_quic_metric_registry_t *metrics_registry = nullptr;

        /*
         * Phase 5 § 5.8 — optional QUIC LB-CID configuration
         * (draft-ietf-quic-load-balancers, block-cipher mode).
         * When set, every CID picoquic generates is replaced with a
         * 16-byte AES-128-encrypted `<server_id>||<nonce>` so that
         * an LB-CID-aware load balancer (Envoy / HAProxy with the
         * QUIC LB extension) can decode `server_id` from the wire
         * CID and route packets to the right backend replica
         * regardless of source-IP migrations.  All replicas must
         * share the same key; each replica gets a distinct
         * `server_id`.  See `include/quic/lb_cid.h` for the
         * helpers; the n00b_quic_lb_cid_config_t is borrowed
         * (must outlive the endpoint).
         *
         * When nullptr (default), picoquic uses its own
         * random-CID generator and the endpoint can sit behind a
         * standard L4 LB but won't survive multi-server CID
         * routing.
         */
        n00b_quic_lb_cid_config_t   *lb_cid_config    = nullptr;
    };

/**
 * @brief Drive one iteration of the endpoint's IO loop.
 *
 * Polls the conduit IO backend for up to @p timeout_ms, drains all
 * received UDP datagrams into picoquic via @c picoquic_incoming_packet,
 * then repeatedly calls @c picoquic_prepare_next_packet and sends each
 * resulting packet via the endpoint's UDP socket until picoquic has
 * nothing more to send.  Returns the number of inbound datagrams
 * processed in this iteration (0 if the poll timed out).
 *
 * Callers run this in their main loop:
 *
 * ```c
 * while (running) {
 *     n00b_quic_endpoint_run_once(ep, 100);
 * }
 * ```
 *
 * The endpoint's `picoquic_quic_t` is not thread-safe; @c run_once
 * therefore must be called from a single thread.  When picoquic is
 * idle (no pending recv, no pending send, no expiring timer),
 * @c run_once returns 0 quickly — there is no busy loop.
 *
 * @param ep         Endpoint handle.
 * @param timeout_ms Maximum time to block in @c io_poll, milliseconds.
 *                   0 = non-blocking poll; -1 = block indefinitely.
 *
 * @return Result of int: ok with the number of inbound datagrams
 *         processed; err on closed endpoint or invalid args.
 *
 * @pre @p ep is non-NULL and not closed.
 */
extern n00b_result_t(int)
n00b_quic_endpoint_run_once(n00b_quic_endpoint_t *ep, int timeout_ms);

/**
 * @brief Snapshot of endpoint-level packet counters.
 *
 * Useful for tests and operators verifying that bytes are flowing.
 * Does not include picoquic-internal stats; for those, use the
 * per-connection stats accessors.
 */
typedef struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
} n00b_quic_endpoint_stats_t;

extern n00b_quic_endpoint_stats_t
n00b_quic_endpoint_stats(n00b_quic_endpoint_t *ep);

/**
 * @brief Topic on which server endpoints publish accepted connections.
 *
 * Each new picoquic-accepted connection is wrapped as an
 * `n00b_quic_conn_t` and published once on this topic with payload
 * type `n00b_quic_accept_event_t`.  Subscribers can then walk
 * `n00b_quic_conn_first_chan` / `n00b_quic_chan_next_in_conn` to
 * discover incoming streams as they arrive.
 *
 * @param ep Endpoint handle.
 * @return `n00b_option_set(...)` with the topic when @p ep is in
 *         listen mode and not closed; `n00b_option_none(...)`
 *         otherwise. Callers MUST disambiguate via
 *         `n00b_option_is_set` (per §5.4 — no `nullptr`-as-absent
 *         sentinel).
 */
extern n00b_option_t(n00b_conduit_topic_base_t *)
n00b_quic_endpoint_accept_topic(n00b_quic_endpoint_t *ep);

/**
 * @brief Local UDP port the endpoint is bound to.
 *
 * After @c n00b_quic_endpoint_new, the OS may have assigned an
 * ephemeral port (when `bind_port = 0`).  This accessor surfaces the
 * actual bound port so tests and outbound-connect logic can reach the
 * endpoint.
 *
 * @param ep Endpoint handle.
 * @return Bound port in host byte order, or 0 if @p ep is NULL or
 *         not yet bound.
 */
extern uint16_t n00b_quic_endpoint_local_port(n00b_quic_endpoint_t *ep);

typedef struct {
    const uint8_t *cert_der_bytes;
    size_t         cert_der_len;
    const char    *key_pem_path;
} n00b_quic_cert_reload_t;

/**
 * @brief Hot-reload the server cert + key on a listening endpoint.
 *
 * Replaces the cert chain + signing key that picotls's
 * `sign_certificate` path uses for the *next* handshake.  Already-
 * completed handshakes are unaffected — their session keys were
 * derived from the old cert's signature on the handshake transcript
 * and persist for the lifetime of the connection.
 *
 * **Limitation (Phase 2 v1)**: a handshake that is in progress at
 * the exact moment of reload may observe a torn cert/key pair (the
 * Certificate message references the new chain while the
 * CertificateVerify is signed by the old key, or vice versa).  In
 * practice this race window is microseconds and renewals fire on
 * the order of weeks; clients retry on transient handshake
 * failures.  Per-cnx atomic swap via picotls's `on_client_hello`
 * hook is a Phase 2 follow-up.
 *
 * @param ep      Endpoint (must have been created with `listen=true`).
 * @param reload  New cert chain DER bytes and private-key PEM path.
 *
 * @return Result: ok(true) on success;
 *         err(@c N00B_QUIC_ERR_INVALID_ARG) on missing args or
 *         non-listening endpoint;
 *         err(@c N00B_QUIC_ERR_HANDSHAKE) if picoquic rejects the
 *         new key.
 */
extern n00b_result_t(bool)
n00b_quic_endpoint_reload_cert(n00b_quic_endpoint_t *ep,
                               n00b_quic_cert_reload_t reload);

/**
 * @brief Low-level cert reload API.
 *
 * Most callers should prefer `n00b_quic_endpoint_reload_cert` so the
 * required reload fields are grouped at the call site.
 */
extern n00b_result_t(bool)
n00b_quic_endpoint_reload_cert_raw(n00b_quic_endpoint_t *ep)
    _kargs {
        const uint8_t *cert_der_bytes = nullptr;
        size_t         cert_der_len   = 0;
        const char    *key_pem_path   = nullptr;
    };

/**
 * @brief Thread-safe enqueue of fully-prepped wire bytes for a channel.
 *
 * Producers may call this from any thread.  The bytes are not
 * interpreted; they are copied into a conduit-pool buffer and the
 * resulting `n00b_quic_pending_send_t` is published on the endpoint's
 * outbound topic.  The endpoint's I/O thread pops the message at the
 * head of its next `run_once` and replays it via `n00b_quic_chan_send`
 * (which invokes `picoquic_add_to_stream`).  All picoquic state
 * mutation thus happens on the I/O thread, even though arbitrary
 * worker threads produced the bytes.
 *
 * The producer's @p bytes buffer is borrowed for the duration of this
 * call only.  The function copies into conduit-pool storage before
 * returning, so the caller may free / let the GC reclaim its source
 * buffer immediately afterwards.
 *
 * @param chan    Target channel.  Must outlive the call; the I/O
 *                thread checks `chan->closed` before replaying.
 * @param bytes   Pre-encoded wire bytes (e.g., HTTP/3 frame payload).
 * @param len     Length of @p bytes.
 *
 * @kw fin    Default: false.  When true, FIN this direction after the
 *            queued bytes are flushed.
 *
 * @return Result of bool: ok(true) once enqueued; err on null inputs,
 *         a closed channel, or a closed outbound topic.
 *
 * @pre  @p chan was opened against the same endpoint that owns the
 *       outbound topic (i.e. `chan->conn->endpoint == ep`).
 * @post On ok, the bytes are durably scheduled for transmission; the
 *       call does **not** block waiting for the I/O thread to actually
 *       hand them to picoquic.
 */
extern n00b_result_t(bool)
n00b_quic_chan_send_queued(n00b_quic_chan_t *chan,
                           const uint8_t   *bytes,
                           size_t           len)
    _kargs {
        bool fin = false;
    };

/**
 * @brief Close the endpoint and release its picoquic + UDP resources.
 *
 * Idempotent.  After return, @p ep may not be dereferenced.  All
 * connections owned by this endpoint are torn down (Phase 1 today
 * has no live connections; this hook is the destination).
 *
 * @param ep Endpoint to close (may be NULL).
 */
extern void n00b_quic_endpoint_close(n00b_quic_endpoint_t *ep);

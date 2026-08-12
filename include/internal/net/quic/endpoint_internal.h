/**
 * @file endpoint_internal.h
 * @internal
 * @brief Internal layout of `n00b_quic_endpoint_t`.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "n00b.h"
#include "conduit/socket_udp.h"
#include "conduit/subscription.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"
#include "crypto/secret.h"

/* Forward decl — picoquic.h is large; consumers include it directly. */
typedef struct st_picoquic_quic_t picoquic_quic_t;

#include "conduit/conduit_types.h"
#include "conduit/topic.h"
#include "conduit/subscription.h"
#include "net/quic/endpoint.h"
#include "net/quic/metrics.h"

/* Opaque to consumers; full type via internal/quic/picotls_sni.h. */
typedef struct n00b_quic_sni_state n00b_quic_sni_state_t;

/**
 * @brief Endpoint handle internals.
 */
struct n00b_quic_endpoint {
    /* picoquic isn't thread-safe.  Every entry point that mutates
     * picoquic state — endpoint_run_once, chan_open / chan_send /
     * chan_reset / chan_stop_sending / chan_close, n00b_quic_connect
     * / n00b_quic_close — must hold this lock for the duration of
     * the picoquic call.  The rwlock supports recursion, so a
     * picoquic callback (default_stream_cb, etc.) firing while we
     * hold the lock can re-enter chan_send safely.
     *
     * The pointer is allocated lazily by endpoint_new; conn / chan
     * reach it via conn->endpoint->lock.  Borrowed; freed with the
     * endpoint. */
    n00b_rwlock_t                     *lock;

    n00b_conduit_t                    *conduit;
    n00b_conduit_io_backend_t         *io;
    n00b_conduit_udp_t                *udp;
    picoquic_quic_t                   *quic;     /**< picoquic context. */
    n00b_conduit_udp_datagram_inbox_t *inbox;    /**< Recv inbox. */
    n00b_conduit_sub_handle_t          recv_sub; /**< Recv subscription handle. */
    n00b_conduit_topic_base_t         *accept_topic;  /**< Server: published n00b_quic_conn_t* for each accepted cnx. */
    n00b_quic_conn_t                  *accepted;      /**< Head of intrusive list of server-side accepted conns. */
    n00b_quic_trust_t                 *trust;    /**< Borrowed; caller-owned. */
    n00b_quic_secret_t                *cert;     /**< Borrowed; caller-owned. */
    n00b_quic_secret_t                *key;      /**< Borrowed; caller-owned. */
    char                              *alpn;     /**< Owned copy of ALPN; nullptr if none. */
    uint64_t                           rx_packets; /**< Stats. */
    uint64_t                           tx_packets;
#if defined(__linux__)
    uint64_t                           pico_now_us;
#endif
    bool                               is_server;
    bool                               closed;

    /* Set by `n00b_quic_picotls_sni_install` when a cert_store is
     * wired in.  NULL otherwise.  Used by the conn-close hook to
     * find the side-table without introspecting picoquic's TLS ctx
     * (which can hold non-stub callbacks we'd misread). */
    n00b_quic_sni_state_t             *sni_state;

    /* Outbound queued-send mailbox.  Producer threads (e.g. handler
     * threads in the RPC server) call `n00b_quic_chan_send_queued`
     * which copies wire bytes into the conduit pool, claims a
     * publisher on `outbound_topic`, and writes a
     * `n00b_quic_pending_send_t` here.  The endpoint's I/O thread
     * drains `outbound_inbox` at the head of every `run_once` (just
     * before `endpoint_drain_send`) so that all
     * picoquic_add_to_stream calls are serialized with
     * picoquic_prepare_next_packet on the same thread. */
    n00b_conduit_topic_base_t         *outbound_topic;
    n00b_quic_pending_send_inbox_t    *outbound_inbox;
    n00b_conduit_sub_handle_t          outbound_sub;

    /* Phase 5 § 5.1 — optional metrics registry + pre-wired
     * counters/gauges.  When `metrics_registry == nullptr` the
     * helpers below are no-ops.  The atomic count array tracks
     * current chan-active values per kind so the gauge_set call
     * has a coherent value to publish (gauges are write-only at the
     * Prom API layer). */
    n00b_quic_metric_registry_t       *metrics_registry;
    n00b_quic_metric_counter_t        *m_chan_opens_total;
    n00b_quic_metric_gauge_t          *m_chan_active;
    n00b_quic_metric_gauge_t          *m_cert_expiry_seconds;
    _Atomic int64_t                    _chan_active_counts[3]; /* indexed by chan_kind */
};

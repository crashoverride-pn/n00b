/*
 * chan.c — Channel (single QUIC stream) wrapper.
 *
 * Phase 1 (this revision): open, send (with FIN), state, reset,
 * stop_sending, close.  Recv path lands with the per-cnx callback
 * fan-out work.
 */

#define N00B_USE_INTERNAL_API
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/data_lock.h"
#include "net/quic/quic_types.h"
#include "net/quic/chan.h"
#include "net/quic/conn.h"
#include "net/quic/metrics.h"
#include "internal/net/quic/chan_internal.h"
#include "internal/net/quic/conn_internal.h"
#include "internal/net/quic/endpoint_internal.h"
#include "internal/net/quic/metrics_internal.h"

#include "picoquic.h"
#include "picoquic_internal.h"  /* picoquic_find_stream + stream_head_t —
                                   see docs/net/quic/vendored.md
                                   "Internal header dependencies". */

#define N00B_PICO_ALLOC ((n00b_allocator_t *)&n00b_get_runtime()->user_pool)

/* Phase 5 § 5.1 — metrics helpers; no-ops when no registry attached. */
static void
chan_metrics_on_open(n00b_quic_chan_t *chan)
{
    if (!chan || !chan->conn || !chan->conn->endpoint
        || !chan->conn->endpoint->metrics_registry) return;
    n00b_quic_endpoint_t *ep = chan->conn->endpoint;
    const char *kind_str =
        (chan->kind == N00B_QUIC_CHAN_BYTES) ? "bytes" :
        (chan->kind == N00B_QUIC_CHAN_DGRAM) ? "dgram" : "framed";
    n00b_list_t(n00b_buffer_t *) *lv = n00b_alloc(
        n00b_list_t(n00b_buffer_t *));
    *lv = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(*lv, n00b_buffer_from_cstr(kind_str));
    if (ep->m_chan_opens_total) {
        n00b_quic_metric_counter_inc(ep->m_chan_opens_total, 1,
            .label_values = lv);
    }
    if (ep->m_chan_active) {
        int64_t now = atomic_fetch_add(&ep->_chan_active_counts[(int)chan->kind], 1)
                      + 1;
        n00b_quic_metric_gauge_set(ep->m_chan_active, (double)now,
            .label_values = lv);
    }
}

static void
chan_metrics_on_close(n00b_quic_chan_t *chan)
{
    if (!chan || !chan->conn || !chan->conn->endpoint
        || !chan->conn->endpoint->metrics_registry) return;
    n00b_quic_endpoint_t *ep = chan->conn->endpoint;
    if (!ep->m_chan_active) return;
    const char *kind_str =
        (chan->kind == N00B_QUIC_CHAN_BYTES) ? "bytes" :
        (chan->kind == N00B_QUIC_CHAN_DGRAM) ? "dgram" : "framed";
    n00b_list_t(n00b_buffer_t *) *lv = n00b_alloc(
        n00b_list_t(n00b_buffer_t *));
    *lv = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(*lv, n00b_buffer_from_cstr(kind_str));
    int64_t now = atomic_fetch_sub(&ep->_chan_active_counts[(int)chan->kind], 1)
                  - 1;
    if (now < 0) now = 0;
    n00b_quic_metric_gauge_set(ep->m_chan_active, (double)now,
        .label_values = lv);
}

/* GC-time finalizer for channels.  Idempotent against
 * `n00b_quic_chan_close`.  Safe even if the owning conn / endpoint
 * has already been finalized — `n00b_quic_chan_close` checks
 * `chan->conn->cnx` and `chan->conn->closed` before touching
 * picoquic. */
void
_n00b_quic_chan_finalize(void *p)
{
    n00b_quic_chan_close((n00b_quic_chan_t *)p);
}

/* ===========================================================================
 * Open
 * =========================================================================== */

n00b_result_t(n00b_quic_chan_t *)
n00b_quic_chan_open(n00b_quic_conn_t *conn) _kargs
{
    n00b_quic_chan_kind_t kind     = N00B_QUIC_CHAN_FRAMED;
    bool                  bidi     = true;
    bool                  zero_rtt = false;
}
{
    n00b_allocator_scope_t pico_scope;

    if (!conn || conn->closed || !conn->cnx) {
        return n00b_result_err(n00b_quic_chan_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    }
    if (kind == N00B_QUIC_CHAN_DGRAM) {
        /* RFC 9221 datagrams have no per-channel demux header on the
         * wire, so a connection has at most one DGRAM channel.
         * Subsequent opens return the same handle (idempotent). */
        (void)bidi;
        (void)zero_rtt;
        return n00b_result_ok(n00b_quic_chan_t *,
                              _n00b_quic_conn_dgram_chan(conn));
    }
    /* zero_rtt is forward-compat surface; today it's a no-op. */
    (void)zero_rtt;

    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    extern void _n00b_quic_chan_finalize(void *p);

    n00b_quic_chan_t *chan = n00b_alloc_with_opts(n00b_quic_chan_t,
                                &(n00b_alloc_opts_t){
                                    .allocator = alloc,
                                    .finalizer = _n00b_quic_chan_finalize,
                                });

    chan->conn         = conn;
    chan->next_in_conn = nullptr;
    chan->kind         = kind;
    chan->bidi         = bidi;
    chan->state        = N00B_QUIC_CHAN_STATE_OPEN;
    chan->bytes_sent     = 0;
    chan->bytes_received = 0;
    chan->app_err_local  = 0;
    chan->app_err_peer   = 0;
    chan->recv_buf       = nullptr;
    chan->sent_fin       = false;
    chan->recv_fin       = false;
    chan->closed         = false;
    chan->last_activity_ns = (uint64_t)n00b_ns_timestamp();

    /* Take the picoquic lock for the stream-id allocation +
     * eager-create.  Two concurrent chan_open calls without this
     * lock observe the same "next stream id" peek and then race
     * inside picoquic_add_to_stream — the loser's stream gets a
     * stale id and is silently dropped on the wire. */
    n00b_data_write_lock(conn->endpoint->lock);
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    chan->stream_id =
        picoquic_get_next_local_stream_id(conn->cnx,
                                         /*is_unidir*/ bidi ? 0 : 1);
    n00b_allocator_scope_exit(&pico_scope);

    /* picoquic_get_next_local_stream_id is a peek — it does not advance
     * the counter.  The counter advances when the stream is actually
     * created via picoquic_add_to_stream (or _with_ctx).  We open the
     * stream eagerly with a zero-byte add so two consecutive
     * chan_open calls get distinct stream IDs.  This is the canonical
     * picoquic pattern (see quicctx.c stream-id counter increment in
     * picoquic_create_stream). */
    int rc = 0;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    rc = picoquic_add_to_stream(conn->cnx, chan->stream_id,
                                nullptr, 0, /*set_fin*/ 0);
    n00b_allocator_scope_exit(&pico_scope);
    n00b_data_unlock(conn->endpoint->lock);
    if (rc != 0) {
        return n00b_result_err(n00b_quic_chan_t *,
                               N00B_QUIC_ERR_PROTOCOL);
    }

    /* Register on the connection's channel list so the per-cnx callback
     * can route inbound stream events to us by stream ID. */
    _n00b_quic_conn_register_chan(conn, chan);

    chan_metrics_on_open(chan);
    return n00b_result_ok(n00b_quic_chan_t *, chan);
}

/* ===========================================================================
 * Accessors
 * =========================================================================== */

uint64_t
n00b_quic_chan_id(n00b_quic_chan_t *chan)
{
    return (chan && !chan->closed) ? chan->stream_id : UINT64_MAX;
}

n00b_quic_chan_kind_t
n00b_quic_chan_kind(n00b_quic_chan_t *chan)
{
    return chan ? chan->kind : N00B_QUIC_CHAN_FRAMED;
}

n00b_quic_chan_state_t
n00b_quic_chan_state(n00b_quic_chan_t *chan)
{
    return chan ? chan->state : N00B_QUIC_CHAN_STATE_CLOSED;
}

n00b_quic_conn_t *
n00b_quic_chan_conn(n00b_quic_chan_t *chan)
{
    return chan ? chan->conn : nullptr;
}

n00b_quic_stream_stats_t
n00b_quic_chan_stats(n00b_quic_chan_t *chan)
{
    n00b_quic_stream_stats_t s = {0};
    if (!chan) return s;
    s.bytes_sent       = chan->bytes_sent;
    s.bytes_received   = chan->bytes_received;
    s.last_activity_ns = chan->last_activity_ns;
    s.app_err_local    = chan->app_err_local;
    s.app_err_peer     = chan->app_err_peer;
    s.state            = (uint8_t)chan->state;
    s.kind             = (uint8_t)chan->kind;
    s.bidi             = chan->bidi ? 1 : 0;

    /* Per-stream send / recv windows + bytes_in_flight come from
     * picoquic's stream_head_t (an internal-header type).
     *
     *   send_window     = maxdata_remote - sent_offset
     *     (peer's flow-control limit minus what we've already sent)
     *   recv_window     = maxdata_local  - consumed_offset
     *     (our flow-control limit minus what the app has consumed)
     *   bytes_in_flight = sent_offset - sack_list cumulative ack
     *     (sent bytes the peer hasn't yet acked)
     *
     * Lookup goes through picoquic_find_stream(); returns NULL if
     * picoquic has already torn down the stream (post-close /
     * post-reset), in which case the stats stay zero. */
    if (chan->conn && !chan->conn->closed && chan->conn->cnx
        && !chan->closed) {
        picoquic_stream_head_t *st =
            picoquic_find_stream(chan->conn->cnx, chan->stream_id);
        if (st) {
            s.send_window = (st->maxdata_remote > st->sent_offset)
                                ? (st->maxdata_remote - st->sent_offset)
                                : 0;
            s.recv_window = (st->maxdata_local > st->consumed_offset)
                                ? (st->maxdata_local - st->consumed_offset)
                                : 0;
            /* bytes_in_flight: cumulative-acked offset is the high
             * end of the sack_list's first (lowest-offset) range,
             * which represents the contiguous prefix acked so far.
             * Anything between that and sent_offset is in flight. */
            uint64_t acked_to = picoquic_sack_list_first(&st->sack_list);
            if (acked_to == UINT64_MAX) {
                acked_to = 0;
            }
            else {
                acked_to += 1;
            }
            s.bytes_acked     = acked_to;
            s.bytes_in_flight = (st->sent_offset > acked_to)
                                    ? (st->sent_offset - acked_to)
                                    : 0;
        }
    }

    /* write_blocked_us: requires a write-blocked timestamp we don't
     * track yet; cumulative write-blocked duration sits on the chan
     * struct as a future addition.  Field stays 0 until then. */
    s.write_blocked_us = 0;
    return s;
}

n00b_quic_chan_t *
n00b_quic_chan_next_in_conn(n00b_quic_chan_t *chan)
{
    return chan ? chan->next_in_conn : nullptr;
}

/* ===========================================================================
 * Server-side accept (internal): wrap a peer-initiated stream.
 *
 * Unlike chan_open, we do NOT call picoquic_add_to_stream to reserve
 * the ID — the stream already exists in picoquic because the peer
 * sent a STREAM frame.  We just allocate our wrapper, infer bidi
 * from the stream-ID parity (RFC 9000 §2.1), and register on the
 * conn's channel list.
 * =========================================================================== */

n00b_quic_chan_t *
_n00b_quic_chan_accept_internal(n00b_quic_conn_t *conn, uint64_t stream_id)
{
    if (!conn || conn->closed) {
        return nullptr;
    }
    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    extern void _n00b_quic_chan_finalize(void *p);

    n00b_quic_chan_t *chan = n00b_alloc_with_opts(n00b_quic_chan_t,
                                &(n00b_alloc_opts_t){
                                    .allocator = alloc,
                                    .finalizer = _n00b_quic_chan_finalize,
                                });

    /* RFC 9000 §2.1: stream-ID bit 1 distinguishes uni (1) from bidi
     * (0).  Bit 0 distinguishes server-initiated (1) from
     * client-initiated (0). */
    bool bidi = (stream_id & 0x2u) == 0;

    chan->conn         = conn;
    chan->next_in_conn = nullptr;
    chan->stream_id    = stream_id;
    chan->kind         = N00B_QUIC_CHAN_FRAMED;
    chan->bidi         = bidi;
    chan->state        = N00B_QUIC_CHAN_STATE_OPEN;
    chan->bytes_sent   = 0;
    chan->bytes_received = 0;
    chan->app_err_local  = 0;
    chan->app_err_peer   = 0;
    chan->recv_buf       = nullptr;
    chan->sent_fin       = false;
    chan->recv_fin       = false;
    chan->closed         = false;
    chan->last_activity_ns = (uint64_t)n00b_ns_timestamp();

    _n00b_quic_conn_register_chan(conn, chan);
    return chan;
}

/* ===========================================================================
 * Send
 * =========================================================================== */

n00b_result_t(size_t)
n00b_quic_chan_send(n00b_quic_chan_t *chan,
                    const uint8_t    *payload,
                    size_t            len) _kargs
{
    bool fin = false;
}
{
    n00b_allocator_scope_t pico_scope;

    if (!chan || chan->closed || !chan->conn || chan->conn->closed ||
        !chan->conn->cnx) {
        return n00b_result_err(size_t, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (chan->state == N00B_QUIC_CHAN_STATE_LOCAL_RESET ||
        chan->state == N00B_QUIC_CHAN_STATE_PEER_RESET ||
        chan->state == N00B_QUIC_CHAN_STATE_CLOSED) {
        return n00b_result_err(size_t, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (chan->sent_fin) {
        /* Already finned this direction; can't send more. */
        return n00b_result_err(size_t, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!payload && len > 0) {
        return n00b_result_err(size_t, N00B_QUIC_ERR_NULL_ARG);
    }

    /* DGRAM path: one datagram per send call.  FIN is meaningless for
     * datagrams (no logical EOF — they're fire-and-forget); ignore. */
    if (chan->kind == N00B_QUIC_CHAN_DGRAM) {
        (void)fin;
        n00b_data_write_lock(chan->conn->endpoint->lock);
        int drc = 0;
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        drc = picoquic_queue_datagram_frame(chan->conn->cnx, len, payload);
        n00b_allocator_scope_exit(&pico_scope);
        n00b_data_unlock(chan->conn->endpoint->lock);
        if (drc != 0) {
            /* picoquic returns PICOQUIC_ERROR_DATAGRAM_TOO_LONG when
             * the payload exceeds the negotiated frame size, or other
             * errors when datagrams aren't negotiated. */
            return n00b_result_err(size_t, N00B_QUIC_ERR_FRAME_TOO_LARGE);
        }
        chan->bytes_sent       += len;
        chan->last_activity_ns  = (uint64_t)n00b_ns_timestamp();
        return n00b_result_ok(size_t, len);
    }

    n00b_data_write_lock(chan->conn->endpoint->lock);
    int rc = 0;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    rc = picoquic_add_to_stream(chan->conn->cnx,
                                chan->stream_id,
                                payload,
                                len,
                                fin ? 1 : 0);
    n00b_allocator_scope_exit(&pico_scope);
    n00b_data_unlock(chan->conn->endpoint->lock);
    if (rc != 0) {
        return n00b_result_err(size_t, N00B_QUIC_ERR_FLOW_BLOCKED);
    }

    chan->bytes_sent       += len;
    chan->last_activity_ns  = (uint64_t)n00b_ns_timestamp();
    if (fin) {
        chan->sent_fin = true;
        /* If we were OPEN, we're now SEND_HALF_CLOSED.  If we were
         * RECV_HALF_CLOSED already, finning closes the channel. */
        if (chan->state == N00B_QUIC_CHAN_STATE_RECV_HALF_CLOSED) {
            chan->state = N00B_QUIC_CHAN_STATE_CLOSED;
        } else {
            chan->state = N00B_QUIC_CHAN_STATE_SEND_HALF_CLOSED;
        }
    }
    return n00b_result_ok(size_t, len);
}

/* ===========================================================================
 * Recv — internal append + public pull
 * =========================================================================== */

void
_n00b_quic_chan_append_recv(n00b_quic_chan_t *chan,
                            const uint8_t    *bytes,
                            size_t            len)
{
    if (!chan || len == 0) {
        return;
    }
    if (!chan->recv_buf) {
        n00b_allocator_t *alloc =
            (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
        chan->recv_buf = n00b_buffer_empty(.allocator = alloc);
    }
    size_t old = chan->recv_buf->byte_len;
    n00b_buffer_resize(chan->recv_buf, old + len);
    if (bytes) {
        memcpy(chan->recv_buf->data + old, bytes, len);
    } else {
        memset(chan->recv_buf->data + old, 0, len);
    }
    chan->bytes_received   += len;
    chan->last_activity_ns  = (uint64_t)n00b_ns_timestamp();
}

n00b_result_t(size_t)
n00b_quic_chan_recv(n00b_quic_chan_t *chan, uint8_t *out, size_t max)
{
    if (!chan || chan->closed) {
        return n00b_result_err(size_t, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (chan->kind == N00B_QUIC_CHAN_DGRAM) {
        /* DGRAM is atomic — bytes can't be flattened into a stream.
         * Caller must use n00b_quic_chan_recv_dgram. */
        return n00b_result_err(size_t, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (max == 0) {
        return n00b_result_ok(size_t, 0);
    }
    if (!out) {
        return n00b_result_err(size_t, N00B_QUIC_ERR_NULL_ARG);
    }
    if (!chan->recv_buf || chan->recv_buf->byte_len == 0) {
        return n00b_result_ok(size_t, 0);
    }

    size_t have = chan->recv_buf->byte_len;
    size_t n    = have < max ? have : max;
    memcpy(out, chan->recv_buf->data, n);

    /* Shift the remaining bytes down.  The recv buffer is small in
     * practice (per-stream); a memmove on every recv is fine. */
    if (have > n) {
        memmove(chan->recv_buf->data, chan->recv_buf->data + n, have - n);
    }
    n00b_buffer_resize(chan->recv_buf, have - n);
    return n00b_result_ok(size_t, n);
}

bool
n00b_quic_chan_has_data(n00b_quic_chan_t *chan)
{
    return chan && !chan->closed
           && chan->recv_buf && chan->recv_buf->byte_len > 0;
}

/* ===========================================================================
 * Datagram recv path
 *
 * Datagrams are atomic — each picoquic_callback_datagram delivery is
 * one whole payload.  We allocate a buffer with a copy of the bytes
 * (the picoquic callback's pointer is borrowed, valid only for the
 * duration of the call) and push it onto the channel's dgram queue.
 * The application drains via n00b_quic_chan_recv_dgram.
 * =========================================================================== */

void
_n00b_quic_chan_push_dgram(n00b_quic_chan_t *chan,
                           const uint8_t    *bytes,
                           size_t            len)
{
    if (!chan || chan->kind != N00B_QUIC_CHAN_DGRAM
        || !chan->dgram_queue_inited) {
        return;
    }
    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)bytes,
                                                (int64_t)len,
                                                .allocator = alloc);
    n00b_list_push(chan->dgram_recv_queue, buf);
    chan->bytes_received   += len;
    chan->last_activity_ns  = (uint64_t)n00b_ns_timestamp();
}

n00b_result_t(n00b_option_t(n00b_buffer_t *))
n00b_quic_chan_recv_dgram(n00b_quic_chan_t *chan)
{
    if (!chan || chan->closed || chan->kind != N00B_QUIC_CHAN_DGRAM
        || !chan->dgram_queue_inited) {
        return n00b_result_err(n00b_option_t(n00b_buffer_t *),
                               N00B_QUIC_ERR_INVALID_ARG);
    }
    if (n00b_list_len(chan->dgram_recv_queue) == 0) {
        return n00b_result_ok(n00b_option_t(n00b_buffer_t *),
                              n00b_option_none(n00b_buffer_t *));
    }
    n00b_option_t(n00b_buffer_t *) popped =
        n00b_list_pop(n00b_buffer_t *, chan->dgram_recv_queue);
    return n00b_result_ok(n00b_option_t(n00b_buffer_t *), popped);
}

bool
n00b_quic_chan_recv_fin(n00b_quic_chan_t *chan)
{
    return chan && chan->recv_fin;
}

/* ===========================================================================
 * Reset / stop_sending / close
 * =========================================================================== */

n00b_result_t(bool)
n00b_quic_chan_reset(n00b_quic_chan_t *chan, uint64_t app_err)
{
    n00b_allocator_scope_t pico_scope;

    if (!chan || chan->closed || !chan->conn || !chan->conn->cnx) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_data_write_lock(chan->conn->endpoint->lock);
    int rc = 0;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    rc = picoquic_reset_stream(chan->conn->cnx, chan->stream_id, app_err);
    n00b_allocator_scope_exit(&pico_scope);
    n00b_data_unlock(chan->conn->endpoint->lock);
    if (rc != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_PROTOCOL);
    }
    chan->app_err_local = app_err;
    chan->state         = N00B_QUIC_CHAN_STATE_LOCAL_RESET;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_quic_chan_stop_sending(n00b_quic_chan_t *chan, uint64_t app_err)
{
    n00b_allocator_scope_t pico_scope;

    if (!chan || chan->closed || !chan->conn || !chan->conn->cnx) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_data_write_lock(chan->conn->endpoint->lock);
    int rc = 0;
    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    rc = picoquic_stop_sending(chan->conn->cnx, chan->stream_id, app_err);
    n00b_allocator_scope_exit(&pico_scope);
    n00b_data_unlock(chan->conn->endpoint->lock);
    if (rc != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_PROTOCOL);
    }
    return n00b_result_ok(bool, true);
}

void
n00b_quic_chan_close(n00b_quic_chan_t *chan)
{
    n00b_allocator_scope_t pico_scope;

    if (!chan || chan->closed) {
        return;
    }
    /* Send FIN if we haven't already; ignore failures (the connection
     * may have been torn down underneath us). */
    if (!chan->sent_fin && chan->conn && !chan->conn->closed && chan->conn->cnx) {
        n00b_data_write_lock(chan->conn->endpoint->lock);
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        (void)picoquic_add_to_stream(chan->conn->cnx, chan->stream_id,
                                     nullptr, 0, /*set_fin=*/1);
        n00b_allocator_scope_exit(&pico_scope);
        n00b_data_unlock(chan->conn->endpoint->lock);
        chan->sent_fin = true;
    }
    chan->closed = true;
    if (chan->state != N00B_QUIC_CHAN_STATE_LOCAL_RESET &&
        chan->state != N00B_QUIC_CHAN_STATE_PEER_RESET) {
        chan->state = N00B_QUIC_CHAN_STATE_CLOSED;
    }
    chan_metrics_on_close(chan);
}

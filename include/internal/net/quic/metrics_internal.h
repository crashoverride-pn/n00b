/**
 * @file metrics_internal.h
 * @internal
 * @brief Layout of the metric registry + listener internals.
 *
 * Phase 5 § 5.1.  Visible only to `src/quic/metrics.c` and
 * `src/quic/metrics_encode.c`.
 */
#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/variant.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "conduit/conduit.h"
#include "conduit/socket.h"
#include "net/quic/metrics.h"

/* One label-tuple's worth of state.  Lookup is linear in the
 * tuple list (typical: 1-10 tuples per metric); append-on-first-
 * observation. */
typedef struct {
    n00b_list_t(n00b_buffer_t *)  *values;        /* may be nullptr (unlabeled). */
    _Atomic uint64_t               counter_u64;   /* counter slot */
    _Atomic uint64_t               gauge_bits;    /* gauge slot (double via bit_cast) */
    /* Histogram per-bucket counters; buckets[i] holds the count of
     * observations in (-inf, upper_bounds[i]].  Final entry is +Inf. */
    _Atomic uint64_t              *hist_buckets;
    _Atomic uint64_t               hist_count;
    _Atomic uint64_t               hist_sum_bits; /* double via bit_cast */
} n00b_quic_metric_tuple_t;

struct n00b_quic_metric_counter {
    n00b_quic_metric_registry_t           *registry;
    char                                  *name;
    char                                  *help;
    n00b_list_t(n00b_buffer_t *)          *label_names;  /* owned; nullable */
    n00b_list_t(n00b_quic_metric_tuple_t *) *tuples;
    n00b_rwlock_t                         *lock;         /* tuples list mutation */
};

struct n00b_quic_metric_gauge {
    n00b_quic_metric_registry_t           *registry;
    char                                  *name;
    char                                  *help;
    n00b_list_t(n00b_buffer_t *)          *label_names;  /* owned; nullable */
    n00b_list_t(n00b_quic_metric_tuple_t *) *tuples;
    n00b_rwlock_t                         *lock;
};

struct n00b_quic_metric_hist {
    n00b_quic_metric_registry_t           *registry;
    char                                  *name;
    char                                  *help;
    n00b_list_t(n00b_buffer_t *)          *label_names;  /* owned; nullable */
    n00b_list_t(n00b_quic_metric_tuple_t *) *tuples;
    n00b_rwlock_t                         *lock;
    /* Upper bounds; size = n_buckets.  Encoder inserts +Inf for
     * the implicit final bucket. */
    double                                *upper_bounds;
    size_t                                 n_buckets;
};

typedef n00b_variant_t(n00b_quic_metric_counter_t *,
                       n00b_quic_metric_gauge_t *,
                       n00b_quic_metric_hist_t *) n00b_quic_metric_entry_t;

struct n00b_quic_metric_registry {
    n00b_allocator_t                       *allocator;
    n00b_list_t(n00b_quic_metric_entry_t *) *entries;
    n00b_rwlock_t                          *lock;
};

/* ===========================================================================
 * Listener internals
 * =========================================================================== */

struct n00b_quic_metric_listener {
    n00b_quic_metric_registry_t      *registry;
    n00b_conduit_t                   *conduit;
    n00b_conduit_io_backend_t        *io;
    n00b_conduit_listener_t          *tcp_listener;
    n00b_conduit_sock_accept_inbox_t *accept_inbox;
    n00b_conduit_sub_handle_t         sub_handle;
    n00b_buffer_t                    *path;          /* match path; default "/metrics" */
    bool                              closed;
};

/* ===========================================================================
 * Internal helpers
 * =========================================================================== */

/**
 * @internal Render the registry into the Prom 0.0.4 text exposition
 *           format.  The caller-visible `n00b_quic_metrics_encode`
 *           wraps this; tests reach through to verify shape.
 */
extern void
_n00b_quic_metrics_render(n00b_quic_metric_registry_t *r,
                          n00b_buffer_t               *out);

/**
 * @internal Service one accepted TCP connection: read a bounded
 *           HTTP/1.1 request, match `GET <path>`, and write the
 *           response.  Closes the FD before returning.
 */
extern void
_n00b_quic_metrics_handle_conn(n00b_quic_metric_listener_t *l,
                               int                          client_fd);

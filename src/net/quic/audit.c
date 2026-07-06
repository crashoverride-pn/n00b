/*
 * audit.c — Phase 3 § 10.2 + § 12.  Auth-decision audit events.
 *
 * Subscriber list is process-global, mutex-protected.  Emits are
 * synchronous; each subscriber sees the event in the same order.
 */

#define N00B_USE_INTERNAL_API
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "core/mutex.h"
#include "adt/result.h"
#include "core/file.h"
#include "net/quic/quic_types.h"
#include "net/quic/audit.h"
#include "net/quic/metrics.h"

/* ===========================================================================
 * Allocator
 * =========================================================================== */

static n00b_allocator_t *
audit_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

/* ===========================================================================
 * Subscriber registry
 * =========================================================================== */

#define MAX_SUBS 64

typedef struct {
    n00b_quic_audit_subscriber_fn fn;
    void                         *ctx;
    int                           id;
    bool                          live;
} sub_t;

static sub_t            g_subs[MAX_SUBS];
static int              g_next_id = 1;
/* Lazy-initialized (atomic-flag-guarded) n00b_mutex.  All callers
 * are post-runtime; no pre-`n00b_init` access occurs. */
static n00b_mutex_t     g_mu;
static _Atomic uint32_t g_mu_inited;

static void
ensure_g_mu(void)
{
    uint32_t state = atomic_load(&g_mu_inited);
    if (state == 2) return;
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong(&g_mu_inited, &expected, 1)) {
        n00b_mutex_init(&g_mu);
        atomic_store(&g_mu_inited, 2);
        return;
    }
    while (atomic_load(&g_mu_inited) != 2) { /* tight spin */ }
}

int
n00b_quic_audit_subscribe(n00b_quic_audit_subscriber_fn fn, void *ctx)
{
    if (!fn) return -1;
    ensure_g_mu(); n00b_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_SUBS; i++) {
        if (!g_subs[i].live) {
            g_subs[i].fn   = fn;
            g_subs[i].ctx  = ctx;
            g_subs[i].id   = g_next_id++;
            g_subs[i].live = true;
            int id = g_subs[i].id;
            n00b_mutex_unlock(&g_mu);
            return id;
        }
    }
    n00b_mutex_unlock(&g_mu);
    return -1;
}

void
n00b_quic_audit_unsubscribe(int subscription_id)
{
    if (subscription_id <= 0) return;
    ensure_g_mu(); n00b_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_SUBS; i++) {
        if (g_subs[i].live && g_subs[i].id == subscription_id) {
            g_subs[i].live = false;
            g_subs[i].fn   = nullptr;
            g_subs[i].ctx  = nullptr;
            break;
        }
    }
    n00b_mutex_unlock(&g_mu);
}

/* Phase 5 § 5.1 — optional metrics counter for audit fan-out.
 * Set by n00b_quic_audit_attach_metrics; nullptr = no instrumentation. */
static n00b_quic_metric_counter_t *g_audit_events_total = nullptr;

void
n00b_quic_audit_emit(const n00b_quic_audit_event_t *evt)
{
    if (!evt) return;
    ensure_g_mu(); n00b_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_SUBS; i++) {
        if (g_subs[i].live && g_subs[i].fn) {
            g_subs[i].fn(evt, g_subs[i].ctx);
        }
    }
    n00b_quic_metric_counter_t *audit_ctr = g_audit_events_total;
    n00b_mutex_unlock(&g_mu);
    if (audit_ctr) {
        const char *decision_str =
            (evt->decision == N00B_QUIC_AUDIT_ALLOW) ? "allow" :
            (evt->decision == N00B_QUIC_AUDIT_DENY)  ? "deny"  : "other";
        n00b_list_t(n00b_buffer_t *) *lv = n00b_alloc(
            n00b_list_t(n00b_buffer_t *));
        *lv = n00b_list_new(n00b_buffer_t *);
        n00b_list_push(*lv, n00b_buffer_from_cstr(decision_str));
        n00b_quic_metric_counter_inc(audit_ctr, 1, .label_values = lv);
    }
}

void
n00b_quic_audit_attach_metrics(n00b_quic_metric_registry_t *r)
{
    if (!r) return;
    ensure_g_mu(); n00b_mutex_lock(&g_mu);
    if (!g_audit_events_total) {
        n00b_list_t(n00b_buffer_t *) *labels = n00b_alloc(
            n00b_list_t(n00b_buffer_t *));
        *labels = n00b_list_new(n00b_buffer_t *);
        n00b_list_push(*labels, n00b_buffer_from_cstr("decision"));
        auto cr = n00b_quic_metric_counter(r,
            "n00b_quic_audit_events_total",
            "Total audit events emitted, by decision",
            .labels = labels);
        if (n00b_result_is_ok(cr)) g_audit_events_total = n00b_result_get(cr);
    }
    n00b_mutex_unlock(&g_mu);
}

/* ===========================================================================
 * JSON rendering
 *
 * Hand-rolled rather than via the n00b JSON encoder because the
 * shape is fixed and we want minimal overhead on the hot path.
 * Subscribers that DON'T want JSON can format their own events
 * directly from the struct fields.
 * =========================================================================== */

/* Escape a string for embedding in a JSON string literal.  Returns
 * a heap-allocated NUL-terminated string. */
static char *
json_escape(const char *in)
{
    if (!in) return nullptr;
    size_t in_len = strlen(in);
    /* Worst case: every byte becomes \uXXXX (6 bytes), plus the
     * surrounding quotes — just allocate 6×.  Conduit pool. */
    size_t cap = in_len * 6 + 1;
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)cap,
        &(n00b_alloc_opts_t){.allocator = audit_alloc(),
                             .no_scan   = true});
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
        case '"':  out[oi++] = '\\'; out[oi++] = '"';  break;
        case '\\': out[oi++] = '\\'; out[oi++] = '\\'; break;
        case '\n': out[oi++] = '\\'; out[oi++] = 'n';  break;
        case '\r': out[oi++] = '\\'; out[oi++] = 'r';  break;
        case '\t': out[oi++] = '\\'; out[oi++] = 't';  break;
        default:
            if (c < 0x20) {
                oi += snprintf(out + oi, cap - oi, "\\u%04x", c);
            } else {
                out[oi++] = (char)c;
            }
        }
    }
    out[oi] = '\0';
    return out;
}

static const char *
decision_str(n00b_quic_audit_decision_t d)
{
    return d == N00B_QUIC_AUDIT_ALLOW ? "allow" : "deny";
}

char *
n00b_quic_audit_event_to_json(const n00b_quic_audit_event_t *evt)
{
    if (!evt) return nullptr;
    /* Build with a generous fixed buffer; events are small. */
    size_t cap = 2048;
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)cap,
        &(n00b_alloc_opts_t){.allocator = audit_alloc(),
                             .no_scan   = true});
    size_t off = 0;
    off += snprintf(out + off, cap - off,
                    "{\"ts_ms\":%lld,\"decision\":\"%s\",\"reason\":\"%s\"",
                    (long long)evt->timestamp_ms,
                    decision_str(evt->decision),
                    n00b_quic_err_str(evt->reason_code));
#define ADD_STR(KEY, VAL)                                                   \
    do {                                                                    \
        if ((VAL) && off < cap) {                                           \
            char *_esc = json_escape(VAL);                                  \
            off += snprintf(out + off, cap - off, ",\"" KEY "\":\"%s\"",    \
                            _esc ? _esc : "");                              \
        }                                                                   \
    } while (0)
    ADD_STR("iss", evt->iss);
    ADD_STR("sub", evt->sub);
    ADD_STR("aud", evt->aud);
    ADD_STR("jti", evt->jti);
    ADD_STR("htm", evt->htm);
    ADD_STR("htu", evt->htu);
    ADD_STR("policy_id", evt->policy_id);
    ADD_STR("peer_addr", evt->peer_addr);
#undef ADD_STR
    if (off < cap) {
        out[off++] = '}';
    }
    if (off < cap) {
        out[off] = '\0';
    } else {
        out[cap - 1] = '\0';
    }
    return out;
}

/* ===========================================================================
 * JSONL sink
 * =========================================================================== */

struct n00b_quic_audit_jsonl_sink {
    n00b_file_t   *file;      /* null once closed */
    int            sub_id;
    n00b_rwlock_t *lock;      /* serializes writes to the file */
};

static void
jsonl_emit(const n00b_quic_audit_event_t *evt, void *ctx)
{
    n00b_quic_audit_jsonl_sink_t *s = ctx;
    if (!s || !s->file) {
        return;
    }
    char *line = n00b_quic_audit_event_to_json(evt);
    if (!line) {
        return;
    }
    size_t line_len = strlen(line);
    /* Compose line + '\n' into a single buffer so one write call
     * delivers the whole record (no torn writes between subscribers). */
    n00b_buffer_t *out =
        n00b_buffer_empty(.allocator = audit_alloc());
    n00b_buffer_t *body = n00b_buffer_from_bytes(line, (int64_t)line_len,
                                                  .allocator = audit_alloc());
    n00b_buffer_concat(out, body);
    n00b_buffer_t *nl = n00b_buffer_from_bytes("\n", 1,
                                                .allocator = audit_alloc());
    n00b_buffer_concat(out, nl);

    n00b_data_write_lock(s->lock);
    if (s->file) {
        /* STREAM file write blocks until the conduit ACKs the write
         * (kernel has the bytes).  Note: there's no explicit fsync
         * here; previous VFS path called n00b_vfs_flush per line. */
        (void)n00b_file_write(s->file, out->data, (size_t)out->byte_len);
    }
    n00b_data_unlock(s->lock);
}

n00b_result_t(n00b_quic_audit_jsonl_sink_t *)
n00b_quic_audit_jsonl_sink_open(const char *path)
{
    if (!path) {
        return n00b_result_err(n00b_quic_audit_jsonl_sink_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    n00b_string_t *spath = n00b_string_from_cstr(path);
    auto           ofr   = n00b_file_open(spath,
        .mode = N00B_FILE_WRITE | N00B_FILE_CREATE | N00B_FILE_APPEND);
    if (n00b_result_is_err(ofr)) {
        return n00b_result_err(n00b_quic_audit_jsonl_sink_t *,
                               N00B_QUIC_ERR_BIND_FAILED);
    }
    n00b_file_t                  *file = n00b_result_get(ofr);
    n00b_quic_audit_jsonl_sink_t *s    =
        n00b_alloc_with_opts(n00b_quic_audit_jsonl_sink_t,
            &(n00b_alloc_opts_t){.allocator = audit_alloc()});
    s->file   = file;
    s->lock   = n00b_data_lock_new();
    s->sub_id = n00b_quic_audit_subscribe(jsonl_emit, s);
    if (s->sub_id < 0) {
        n00b_file_close(s->file);
        s->file = nullptr;
        return n00b_result_err(n00b_quic_audit_jsonl_sink_t *,
                               N00B_QUIC_ERR_HANDSHAKE);
    }
    return n00b_result_ok(n00b_quic_audit_jsonl_sink_t *, s);
}

void
n00b_quic_audit_jsonl_sink_close(n00b_quic_audit_jsonl_sink_t *s)
{
    if (!s) return;
    if (s->sub_id > 0) {
        n00b_quic_audit_unsubscribe(s->sub_id);
        s->sub_id = -1;
    }
    n00b_data_write_lock(s->lock);
    if (s->file) {
        n00b_file_close(s->file);
        s->file = nullptr;
    }
    n00b_data_unlock(s->lock);
}

/*
 * metrics_encode.c — Prometheus 0.0.4 text exposition format encoder.
 *
 * Phase 5 § 5.1.  Renders an `n00b_quic_metric_registry_t` snapshot
 * into the Prom text format (RFC-style content-type
 * `text/plain; version=0.0.4`).
 *
 * Encoding rules (per the Prom exposition format spec):
 *   - For each metric, emit `# HELP <name> <help>` and
 *     `# TYPE <name> <kind>` lines, then one or more sample lines.
 *   - Counter samples: `<name>{labels} <value>`.
 *   - Gauge samples: same shape; value is double.
 *   - Histogram samples: per-bucket `<name>_bucket{le="<ub>",...}`,
 *     plus `<name>_count{...}` and `<name>_sum{...}`, plus the
 *     `+Inf` bucket.
 *   - Label values are escaped: `\` → `\\`, `"` → `\"`, newline → `\n`.
 *   - Help text is escaped: `\` → `\\`, newline → `\n`.
 *   - Doubles are rendered with `%.17g` for round-trip; +Inf as
 *     `+Inf`, NaN as `NaN`.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/list.h"
#include "text/strings/fptostr.h"
#include "net/quic/metrics.h"
#include "internal/net/quic/metrics_internal.h"

/* ===========================================================================
 * Buffer append helpers
 * =========================================================================== */

static void
buf_append_bytes(n00b_buffer_t *b, const char *data, size_t len)
{
    size_t old = b->byte_len;
    n00b_buffer_resize(b, old + len);
    memcpy(b->data + old, data, len);
}

static void
buf_append_cstr(n00b_buffer_t *b, const char *s)
{
    buf_append_bytes(b, s, strlen(s));
}

static void
buf_append_help_escaped(n00b_buffer_t *b, const char *s)
{
    /* Per spec: HELP escapes `\` → `\\` and newline → `\n` only. */
    if (!s) return;
    const char *p;
    for (p = s; *p; p++) {
        char c = *p;
        if (c == '\\') {
            buf_append_bytes(b, "\\\\", 2);
        } else if (c == '\n') {
            buf_append_bytes(b, "\\n", 2);
        } else {
            buf_append_bytes(b, &c, 1);
        }
    }
}

static void
buf_append_label_value(n00b_buffer_t *b, const char *data, size_t len)
{
    /* Per spec: label values escape `\` → `\\`, `"` → `\"`, newline → `\n`. */
    for (size_t i = 0; i < len; i++) {
        char c = data[i];
        if (c == '\\') {
            buf_append_bytes(b, "\\\\", 2);
        } else if (c == '"') {
            buf_append_bytes(b, "\\\"", 2);
        } else if (c == '\n') {
            buf_append_bytes(b, "\\n", 2);
        } else {
            buf_append_bytes(b, &c, 1);
        }
    }
}

static void
buf_append_uint(n00b_buffer_t *b, uint64_t v)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    if (n > 0) buf_append_bytes(b, tmp, (size_t)n);
}

static void
buf_append_double(n00b_buffer_t *b, double v)
{
    // NB: libc snprintf("%g", ...) formats floats via dtoa(), which mallocs
    // INTERNALLY — that traps on n00b off-libc worker threads (the metrics
    // endpoint runs on one), and the compile-time malloc shim cannot redirect
    // libc-internal allocations. Use n00b's malloc-free formatter instead.
    // (Integer snprintf elsewhere in this file is fine: it never calls dtoa.)
    if (isnan(v)) {
        buf_append_bytes(b, "NaN", 3);
    } else if (isinf(v)) {
        buf_append_bytes(b, v > 0 ? "+Inf" : "-Inf", 4);
    } else {
        char tmp[24];
        int  n = n00b_fptostr(v, tmp);
        if (n > 0) {
            buf_append_bytes(b, tmp, (size_t)n);
        }
    }
}

/* ===========================================================================
 * Label-set rendering
 * =========================================================================== */

/* Render `{name1="v1",name2="v2",...}` (or empty if no labels).
 * Optionally appends an extra label `extra_name="<extra_val>"`
 * in front of the user's labels (used for histogram `le=`). */
static void
render_labels(n00b_buffer_t                *out,
              n00b_list_t(n00b_buffer_t *) *names,
              n00b_list_t(n00b_buffer_t *) *values,
              const char                   *extra_name,
              const char                   *extra_value)
{
    bool have_user = names && values && n00b_list_len(*names) > 0;
    if (!have_user && !extra_name) return;

    buf_append_bytes(out, "{", 1);
    bool need_comma = false;

    if (extra_name) {
        buf_append_cstr(out, extra_name);
        buf_append_bytes(out, "=\"", 2);
        if (extra_value) {
            buf_append_label_value(out, extra_value, strlen(extra_value));
        }
        buf_append_bytes(out, "\"", 1);
        need_comma = true;
    }

    if (have_user) {
        size_t n = (size_t)n00b_list_len(*names);
        for (size_t i = 0; i < n; i++) {
            n00b_buffer_t *nm = n00b_list_get(*names, i);
            n00b_buffer_t *vv = n00b_list_get(*values, i);
            if (need_comma) buf_append_bytes(out, ",", 1);
            buf_append_bytes(out, nm->data, nm->byte_len);
            buf_append_bytes(out, "=\"", 2);
            if (vv) buf_append_label_value(out, vv->data, vv->byte_len);
            buf_append_bytes(out, "\"", 1);
            need_comma = true;
        }
    }
    buf_append_bytes(out, "}", 1);
}

/* ===========================================================================
 * Per-kind renderers
 * =========================================================================== */

static void
render_counter(n00b_quic_metric_counter_t *c, n00b_buffer_t *out)
{
    buf_append_cstr(out, "# HELP ");
    buf_append_cstr(out, c->name);
    buf_append_bytes(out, " ", 1);
    buf_append_help_escaped(out, c->help);
    buf_append_bytes(out, "\n", 1);

    buf_append_cstr(out, "# TYPE ");
    buf_append_cstr(out, c->name);
    buf_append_cstr(out, " counter\n");

    n00b_data_read_lock(c->lock);
    if (!c->tuples) {
        /* Unlabeled metric with no observations yet: emit a zero
         * sample so scrapers see the metric exists. */
        if (!c->label_names || n00b_list_len(*c->label_names) == 0) {
            buf_append_cstr(out, c->name);
            buf_append_cstr(out, " 0\n");
        }
        n00b_data_unlock(c->lock);
        return;
    }
    size_t n = (size_t)n00b_list_len(*c->tuples);
    for (size_t i = 0; i < n; i++) {
        n00b_quic_metric_tuple_t *t = n00b_list_get(*c->tuples, i);
        buf_append_cstr(out, c->name);
        render_labels(out, c->label_names, t->values, nullptr, nullptr);
        buf_append_bytes(out, " ", 1);
        buf_append_uint(out, atomic_load(&t->counter_u64));
        buf_append_bytes(out, "\n", 1);
    }
    n00b_data_unlock(c->lock);
}

static void
render_gauge(n00b_quic_metric_gauge_t *g, n00b_buffer_t *out)
{
    buf_append_cstr(out, "# HELP ");
    buf_append_cstr(out, g->name);
    buf_append_bytes(out, " ", 1);
    buf_append_help_escaped(out, g->help);
    buf_append_bytes(out, "\n", 1);

    buf_append_cstr(out, "# TYPE ");
    buf_append_cstr(out, g->name);
    buf_append_cstr(out, " gauge\n");

    n00b_data_read_lock(g->lock);
    if (!g->tuples) {
        if (!g->label_names || n00b_list_len(*g->label_names) == 0) {
            buf_append_cstr(out, g->name);
            buf_append_cstr(out, " 0\n");
        }
        n00b_data_unlock(g->lock);
        return;
    }
    size_t n = (size_t)n00b_list_len(*g->tuples);
    for (size_t i = 0; i < n; i++) {
        n00b_quic_metric_tuple_t *t = n00b_list_get(*g->tuples, i);
        buf_append_cstr(out, g->name);
        render_labels(out, g->label_names, t->values, nullptr, nullptr);
        buf_append_bytes(out, " ", 1);
        uint64_t bits = atomic_load(&t->gauge_bits);
        double v;
        memcpy(&v, &bits, sizeof(v));
        buf_append_double(out, v);
        buf_append_bytes(out, "\n", 1);
    }
    n00b_data_unlock(g->lock);
}

static void
render_hist(n00b_quic_metric_hist_t *h, n00b_buffer_t *out)
{
    buf_append_cstr(out, "# HELP ");
    buf_append_cstr(out, h->name);
    buf_append_bytes(out, " ", 1);
    buf_append_help_escaped(out, h->help);
    buf_append_bytes(out, "\n", 1);

    buf_append_cstr(out, "# TYPE ");
    buf_append_cstr(out, h->name);
    buf_append_cstr(out, " histogram\n");

    n00b_data_read_lock(h->lock);
    if (!h->tuples) {
        n00b_data_unlock(h->lock);
        return;
    }
    size_t nt = (size_t)n00b_list_len(*h->tuples);
    char le_buf[64];
    for (size_t i = 0; i < nt; i++) {
        n00b_quic_metric_tuple_t *t = n00b_list_get(*h->tuples, i);
        for (size_t b = 0; b < h->n_buckets; b++) {
            // n00b_fptostr (not libc snprintf): float snprintf mallocs via
            // dtoa internally, which traps on n00b off-libc workers.
            int le_n = n00b_fptostr(h->upper_bounds[b], le_buf);
            le_buf[(le_n > 0 && le_n < (int)sizeof(le_buf)) ? le_n : 0] = '\0';
            buf_append_cstr(out, h->name);
            buf_append_cstr(out, "_bucket");
            render_labels(out, h->label_names, t->values, "le", le_buf);
            buf_append_bytes(out, " ", 1);
            buf_append_uint(out, atomic_load(&t->hist_buckets[b]));
            buf_append_bytes(out, "\n", 1);
        }
        /* +Inf bucket. */
        buf_append_cstr(out, h->name);
        buf_append_cstr(out, "_bucket");
        render_labels(out, h->label_names, t->values, "le", "+Inf");
        buf_append_bytes(out, " ", 1);
        buf_append_uint(out, atomic_load(&t->hist_buckets[h->n_buckets]));
        buf_append_bytes(out, "\n", 1);
        /* _count and _sum. */
        buf_append_cstr(out, h->name);
        buf_append_cstr(out, "_count");
        render_labels(out, h->label_names, t->values, nullptr, nullptr);
        buf_append_bytes(out, " ", 1);
        buf_append_uint(out, atomic_load(&t->hist_count));
        buf_append_bytes(out, "\n", 1);

        buf_append_cstr(out, h->name);
        buf_append_cstr(out, "_sum");
        render_labels(out, h->label_names, t->values, nullptr, nullptr);
        buf_append_bytes(out, " ", 1);
        uint64_t bits = atomic_load(&t->hist_sum_bits);
        double v;
        memcpy(&v, &bits, sizeof(v));
        buf_append_double(out, v);
        buf_append_bytes(out, "\n", 1);
    }
    n00b_data_unlock(h->lock);
}

/* ===========================================================================
 * Top-level render
 * =========================================================================== */

void
_n00b_quic_metrics_render(n00b_quic_metric_registry_t *r, n00b_buffer_t *out)
{
    if (!r || !out) return;
    n00b_data_read_lock(r->lock);
    size_t n = (size_t)n00b_list_len(*r->entries);
    for (size_t i = 0; i < n; i++) {
        n00b_quic_metric_entry_t *e = n00b_list_get(*r->entries, i);
        switch (e->kind) {
        case N00B_QUIC_METRIC_COUNTER: render_counter(e->as.counter, out); break;
        case N00B_QUIC_METRIC_GAUGE:   render_gauge(e->as.gauge, out);     break;
        case N00B_QUIC_METRIC_HIST:    render_hist(e->as.hist, out);       break;
        }
    }
    n00b_data_unlock(r->lock);
}

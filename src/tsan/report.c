/*
 * Race reporting.
 *
 * Formatting happens by hand into a stack buffer and leaves through write(2).
 * n00b's own printing allocates, takes locks and is instrumented, so using it
 * from here would re-enter the detector from inside a report.
 */

#include "internal.h"

#include <string.h>
#include <unistd.h>

typedef struct {
    char  buf[1024];
    size_t len;
} out_t;

static void
emit(out_t *o, const char *s)
{
    size_t n = strlen(s);
    if (o->len + n >= sizeof(o->buf)) {
        n = sizeof(o->buf) - o->len - 1;
    }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
}

static void
emit_u64(out_t *o, uint64_t v)
{
    char tmp[24];
    int  i = 0;

    if (v == 0) {
        emit(o, "0");
        return;
    }
    while (v > 0 && i < (int)sizeof(tmp)) {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i-- > 0) {
        char one[2] = {tmp[i], '\0'};
        emit(o, one);
    }
}

static void
emit_hex(out_t *o, uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    char              tmp[19];
    int               i = 0;

    tmp[i++] = '0';
    tmp[i++] = 'x';

    int started = 0;
    for (int shift = 60; shift >= 0; shift -= 4) {
        int nib = (int)((v >> shift) & 0xf);
        if (nib != 0 || started || shift == 0) {
            started  = 1;
            tmp[i++] = digits[nib];
        }
    }
    tmp[i] = '\0';
    emit(o, tmp);
}

static void
flush(out_t *o)
{
    ssize_t ignored = write(2, o->buf, o->len);
    (void)ignored;
    o->len = 0;
}

void
n00b_tsan_trace_acquire(void    *addr,
                        uint32_t tid,
                        uint32_t src,
                        uint64_t before,
                        uint64_t after)
{
    out_t o = {.len = 0};
    emit(&o, "[acq] tid=");
    emit_u64(&o, tid);
    emit(&o, " learned tid");
    emit_u64(&o, src);
    emit(&o, " ");
    emit_u64(&o, before);
    emit(&o, "->");
    emit_u64(&o, after);
    emit(&o, " via sync addr=");
    emit_hex(&o, (uint64_t)(uintptr_t)addr);
    emit(&o, "\n");
    flush(&o);
}

void
n00b_tsan_trace_check(void               *addr,
                      bool                is_write,
                      n00b_tsan_thread_t *t,
                      n00b_tsan_cell_t   *cells)
{
    out_t o = {.len = 0};
    emit(&o, "[watch] ");
    emit(&o, is_write ? "W" : "R");
    emit(&o, " addr=");
    emit_hex(&o, (uint64_t)(uintptr_t)addr);
    emit(&o, " tid=");
    emit_u64(&o, t->tid);
    emit(&o, " epoch=");
    emit_u64(&o, t->epoch);
    emit(&o, " cells=[");
    for (int i = 0; i < N00B_TSAN_SHADOW_CELLS; i++) {
        n00b_tsan_cell_t c = cells[i];
        if (i) {
            emit(&o, " ");
        }
        emit(&o, "t");
        emit_u64(&o, N00B_TSAN_CELL_TID(c));
        emit(&o, "/e");
        emit_u64(&o, N00B_TSAN_CELL_EPOCH(c));
        emit(&o, N00B_TSAN_CELL_WRITE(c) ? "/W" : "/R");
    }
    emit(&o, "] myvc_of_cell_tids=[");
    n00b_tsan_vc_t *vc = (n00b_tsan_vc_t *)t->vc;
    for (int i = 0; i < N00B_TSAN_SHADOW_CELLS; i++) {
        if (i) {
            emit(&o, " ");
        }
        emit_u64(&o, vc->e[N00B_TSAN_CELL_TID(cells[i])]);
    }
    emit(&o, "]\n");
    flush(&o);
}

void
n00b_tsan_report_race(void            *addr,
                      size_t           size,
                      bool             is_write,
                      n00b_tsan_cell_t other,
                      void            *pc)
{
    n00b_tsan_state_t *st  = &n00b_tsan_state;
    uint64_t           seq = atomic_fetch_add_explicit(&st->races,
                                             1,
                                             memory_order_relaxed);

    if (!st->report_all && seq >= st->report_limit) {
        return;
    }

    n00b_tsan_thread_t *t = n00b_tsan_self();
    out_t               o = {.len = 0};

    emit(&o, "\n=== n00b tsan: data race #");
    emit_u64(&o, seq + 1);
    emit(&o, " ===\n  ");
    emit(&o, is_write ? "write" : "read");
    emit(&o, " of size ");
    emit_u64(&o, size);
    emit(&o, " at ");
    emit_hex(&o, (uint64_t)(uintptr_t)addr);
    emit(&o, "\n  by thread ");
    emit_u64(&o, t != nullptr ? t->tid : 0);
    emit(&o, " at epoch ");
    emit_u64(&o, t != nullptr ? t->epoch : 0);
    emit(&o, "\n  pc ");
    emit_hex(&o, (uint64_t)(uintptr_t)pc);

    emit(&o, "\n  races with a previous ");
    emit(&o, N00B_TSAN_CELL_WRITE(other) ? "write" : "read");
    emit(&o, " by thread ");
    emit_u64(&o, N00B_TSAN_CELL_TID(other));
    emit(&o, " at epoch ");
    emit_u64(&o, N00B_TSAN_CELL_EPOCH(other));
    emit(&o, "\n");

    if (t != nullptr && t->stack_len > 0) {
        uint32_t n = t->stack_len;
        if (n > N00B_TSAN_STACK_DEPTH) {
            n = N00B_TSAN_STACK_DEPTH;
        }
        emit(&o, "  stack (innermost first, symbolize with atos):\n");
        uint32_t shown = n > 12 ? 12 : n;
        for (uint32_t i = 0; i < shown; i++) {
            emit(&o, "    ");
            emit_hex(&o, (uint64_t)(uintptr_t)t->stack[n - 1 - i]);
            emit(&o, "\n");
        }
    }

    flush(&o);
}

void
n00b_tsan_report_summary(void)
{
    n00b_tsan_state_t *st = &n00b_tsan_state;
    out_t              o  = {.len = 0};

    uint64_t races = atomic_load_explicit(&st->races, memory_order_relaxed);

    emit(&o, "\n=== n00b tsan summary ===\n  races: ");
    emit_u64(&o, races);
    emit(&o, "\n  threads: ");
    emit_u64(&o, atomic_load_explicit(&st->next_tid, memory_order_relaxed));
    emit(&o, "\n  sync objects: ");
    emit_u64(&o, atomic_load_explicit(&st->sync_count, memory_order_relaxed));
    emit(&o, "\n  shadow regions: ");
    emit_u64(&o, atomic_load_explicit(&st->region_count, memory_order_relaxed));
    emit(&o, "\n  sync evictions: ");
    emit_u64(&o, atomic_load_explicit(&st->sync_evictions, memory_order_relaxed));
    emit(&o, "\n  sync misses: ");
    emit_u64(&o, atomic_load_explicit(&st->sync_misses, memory_order_relaxed));
    emit(&o, "\n  cell pairs examined: ");
    emit_u64(&o, atomic_load_explicit(&st->d_checks, memory_order_relaxed));
    emit(&o, "\n    same thread: ");
    emit_u64(&o, atomic_load_explicit(&st->d_same_tid, memory_order_relaxed));
    emit(&o, "\n    no byte overlap: ");
    emit_u64(&o, atomic_load_explicit(&st->d_no_overlap, memory_order_relaxed));
    emit(&o, "\n    read/read: ");
    emit_u64(&o, atomic_load_explicit(&st->d_read_read, memory_order_relaxed));
    emit(&o, "\n    both atomic: ");
    emit_u64(&o, atomic_load_explicit(&st->d_atomic, memory_order_relaxed));
    emit(&o, "\n    ordered (happens-before): ");
    emit_u64(&o, atomic_load_explicit(&st->d_hb, memory_order_relaxed));
    emit(&o, "\n  per thread (tid: epoch reads writes):\n");
    flush(&o);

    uint32_t n = atomic_load_explicit(&st->next_tid, memory_order_relaxed);
    for (uint32_t i = 0; i < n && i < N00B_TSAN_MAX_THREADS; i++) {
        n00b_tsan_thread_t *t = st->threads[i];
        if (t == nullptr) {
            continue;
        }
        emit(&o, "    ");
        emit_u64(&o, i);
        emit(&o, ": ");
        emit_u64(&o, t->epoch);
        emit(&o, " ");
        emit_u64(&o, t->n_reads);
        emit(&o, " ");
        emit_u64(&o, t->n_writes);
        emit(&o, "\n");
        flush(&o);
    }
}

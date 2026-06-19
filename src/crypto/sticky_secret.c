/*
 * sticky_secret.c — rotatable secret backed by the OS CSPRNG.
 *
 * Lock-free reads + write-side serialization come from the shared
 * `n00b_rcu_t` helper.  The sticky-secret-specific bits are: each
 * "view" is a `sticky_buf_t` carrying a pointer + length, and at
 * close time we walk current + graveyard to zero out plaintext key
 * bytes (security hygiene — avoid leaving secrets in memory).
 */

#define N00B_USE_INTERNAL_API
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/random.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/sticky_secret.h"
#include "internal/net/quic/rcu.h"

typedef struct {
    uint8_t *bytes;
    size_t   len;
} sticky_buf_t;

struct n00b_quic_sticky_secret {
    n00b_rcu_t buf_rcu;
    size_t     bytes_needed;
    bool       closed;
};

/* ===========================================================================
 * Allocator + helpers
 * =========================================================================== */

static n00b_allocator_t *
ss_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static sticky_buf_t *
make_buf(size_t len)
{
    sticky_buf_t *b = n00b_alloc_with_opts(sticky_buf_t,
        &(n00b_alloc_opts_t){.allocator = ss_alloc()});
    b->bytes = n00b_alloc_array_with_opts(uint8_t, (int64_t)len,
                                          &(n00b_alloc_opts_t){
                                              .allocator = ss_alloc(),
                                              .no_scan   = true,
                                          });
    b->len = len;
    n00b_random_bytes((char *)b->bytes, len);
    return b;
}

/* Per-view zero callback used at close time. */
static void
ss_zero_view(void *view, void *ctx)
{
    (void)ctx;
    sticky_buf_t *b = view;
    if (b && b->bytes) {
        memset(b->bytes, 0, b->len);
    }
}

/* ===========================================================================
 * Public API
 * =========================================================================== */

n00b_result_t(n00b_quic_sticky_secret_t *)
n00b_quic_sticky_secret_open(size_t bytes_needed)
{
    if (bytes_needed < 16 || bytes_needed > 64
        || (bytes_needed % 16) != 0) {
        return n00b_result_err(n00b_quic_sticky_secret_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_quic_sticky_secret_t *ss = n00b_alloc_with_opts(
        n00b_quic_sticky_secret_t,
        &(n00b_alloc_opts_t){.allocator = ss_alloc()});
    ss->bytes_needed = bytes_needed;
    ss->closed       = false;
    n00b_rcu_init(&ss->buf_rcu, make_buf(bytes_needed));
    return n00b_result_ok(n00b_quic_sticky_secret_t *, ss);
}

const uint8_t *
n00b_quic_sticky_secret_current(n00b_quic_sticky_secret_t *ss, size_t *out_len)
{
    if (!ss) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    sticky_buf_t *b = n00b_rcu_load(&ss->buf_rcu);
    if (!b) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    if (out_len) *out_len = b->len;
    return b->bytes;
}

n00b_result_t(bool)
n00b_quic_sticky_secret_rotate(n00b_quic_sticky_secret_t *ss)
{
    if (!ss || ss->closed) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    n00b_rcu_swap(&ss->buf_rcu, make_buf(ss->bytes_needed));
    return n00b_result_ok(bool, true);
}

void
n00b_quic_sticky_secret_close(n00b_quic_sticky_secret_t *ss)
{
    if (!ss || ss->closed) {
        return;
    }
    ss->closed = true;
    /* Zero plaintext key bytes across current + graveyard before
     * we release the mutex.  Conduit-pool teardown will reclaim
     * the structures themselves. */
    n00b_rcu_for_each_view(&ss->buf_rcu, ss_zero_view, nullptr);
    n00b_rcu_close(&ss->buf_rcu);
}

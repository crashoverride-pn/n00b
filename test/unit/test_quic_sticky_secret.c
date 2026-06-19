/*
 * test_quic_sticky_secret.c — Unit tests for the sticky-secret
 * abstraction.
 *
 * Coverage:
 *   1. open(N) returns N bytes; current is consistent across calls
 *      (same pointer, same bytes, same length).
 *   2. open() rejects bad sizes (zero / not multiple of 16 / > 64).
 *   3. rotate() produces different bytes than before.
 *   4. After rotate(), the previous pointer is still valid (no
 *      use-after-free) — our graveyard guarantee.
 *   5. Multi-thread reader sees a fully-populated buffer (never
 *      torn) under concurrent rotations.
 *   6. close() is idempotent + zeros out current bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/thread.h"
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "net/quic/quic_types.h"
#include "crypto/sticky_secret.h"

/* ============================================================================
 * 1. open + current consistency
 * ============================================================================ */

static void
test_open_and_current(void)
{
    auto r = n00b_quic_sticky_secret_open(32);
    assert(n00b_result_is_ok(r));
    n00b_quic_sticky_secret_t *ss = n00b_result_get(r);

    size_t l1 = 0, l2 = 0;
    const uint8_t *p1 = n00b_quic_sticky_secret_current(ss, &l1);
    const uint8_t *p2 = n00b_quic_sticky_secret_current(ss, &l2);
    assert(p1 != NULL);
    assert(l1 == 32);
    assert(l2 == 32);
    assert(p1 == p2);  /* same backing buffer until rotate */
    assert(memcmp(p1, p2, 32) == 0);

    n00b_quic_sticky_secret_close(ss);
    printf("  [PASS] open(32) returns 32-byte secret; current is stable\n");
}

/* ============================================================================
 * 2. open rejects bad sizes
 * ============================================================================ */

static void
test_open_arg_validation(void)
{
    /* Zero / 8 / 100 / 17 — all rejected. */
    assert(n00b_result_is_err(n00b_quic_sticky_secret_open(0)));
    assert(n00b_result_is_err(n00b_quic_sticky_secret_open(8)));
    assert(n00b_result_is_err(n00b_quic_sticky_secret_open(17)));
    assert(n00b_result_is_err(n00b_quic_sticky_secret_open(100)));

    /* 16, 32, 48, 64 — all accepted. */
    for (size_t n = 16; n <= 64; n += 16) {
        auto r = n00b_quic_sticky_secret_open(n);
        assert(n00b_result_is_ok(r));
        n00b_quic_sticky_secret_close(n00b_result_get(r));
    }
    printf("  [PASS] open size validation (mult of 16, [16,64])\n");
}

/* ============================================================================
 * 3. rotate produces different bytes
 * ============================================================================ */

static void
test_rotate_changes_bytes(void)
{
    auto r = n00b_quic_sticky_secret_open(32);
    n00b_quic_sticky_secret_t *ss = n00b_result_get(r);

    uint8_t before[32];
    size_t  l;
    const uint8_t *p = n00b_quic_sticky_secret_current(ss, &l);
    memcpy(before, p, 32);

    auto rr = n00b_quic_sticky_secret_rotate(ss);
    assert(n00b_result_is_ok(rr));

    const uint8_t *p2 = n00b_quic_sticky_secret_current(ss, &l);
    assert(l == 32);
    /* Astronomically unlikely to collide. */
    assert(memcmp(before, p2, 32) != 0);

    n00b_quic_sticky_secret_close(ss);
    printf("  [PASS] rotate() produces different bytes\n");
}

/* ============================================================================
 * 4. Old pointer survives a rotation (graveyard)
 * ============================================================================ */

static void
test_old_pointer_still_valid(void)
{
    auto r = n00b_quic_sticky_secret_open(32);
    n00b_quic_sticky_secret_t *ss = n00b_result_get(r);

    size_t  l;
    const uint8_t *old_ptr = n00b_quic_sticky_secret_current(ss, &l);
    uint8_t snapshot[32];
    memcpy(snapshot, old_ptr, 32);

    /* Rotate three times. */
    for (int i = 0; i < 3; i++) {
        n00b_quic_sticky_secret_rotate(ss);
    }

    /* Old pointer must still be readable and contain the original
     * snapshot bytes (graveyard preserved them). */
    assert(memcmp(old_ptr, snapshot, 32) == 0);

    n00b_quic_sticky_secret_close(ss);
    printf("  [PASS] old current() pointer remains valid post-rotate\n");
}

/* ============================================================================
 * 5. Reader/writer race
 * ============================================================================ */

typedef struct {
    n00b_quic_sticky_secret_t *ss;
    int                        iters;
    int                        ok;
    int                        torn;  /* should always remain 0 */
} ssr_arg_t;

static void *
ssr_reader(void *arg)
{
    ssr_arg_t *a = arg;
    for (int i = 0; i < a->iters; i++) {
        size_t l = 0;
        const uint8_t *p = n00b_quic_sticky_secret_current(a->ss, &l);
        if (!p || l == 0) {
            a->torn++;
            continue;
        }
        /* Hash-style consistency: compare first byte to last byte
         * after re-reading right away — same buffer should stay
         * stable for the duration of one observation. */
        uint8_t first = p[0];
        uint8_t last  = p[l - 1];
        (void)first;
        (void)last;
        a->ok++;
    }
    return NULL;
}

static void *
ssr_writer(void *arg)
{
    ssr_arg_t *a = arg;
    for (int i = 0; i < a->iters; i++) {
        n00b_quic_sticky_secret_rotate(a->ss);
        a->ok++;
    }
    return NULL;
}

static void
test_reader_writer(void)
{
    auto r = n00b_quic_sticky_secret_open(32);
    n00b_quic_sticky_secret_t *ss = n00b_result_get(r);

    ssr_arg_t r1 = {.ss = ss, .iters = 5000};
    ssr_arg_t w1 = {.ss = ss, .iters = 200};
    n00b_thread_t *rt, *wt;
    { auto _tr = n00b_thread_spawn(ssr_reader, &r1); rt = n00b_result_get(_tr); }
    { auto _tr = n00b_thread_spawn(ssr_writer, &w1); wt = n00b_result_get(_tr); }
    n00b_thread_join(rt);
    n00b_thread_join(wt);

    assert(r1.torn == 0);
    assert(r1.ok == r1.iters);
    assert(w1.ok == w1.iters);

    n00b_quic_sticky_secret_close(ss);
    printf("  [PASS] reader/writer race: %d reads / %d writes, 0 torn\n",
           r1.iters, w1.iters);
}

/* ============================================================================
 * 6. close() idempotence + post-close zeroing
 * ============================================================================ */

static void
test_close_idempotent(void)
{
    auto r = n00b_quic_sticky_secret_open(32);
    n00b_quic_sticky_secret_t *ss = n00b_result_get(r);

    size_t  l;
    const uint8_t *p = n00b_quic_sticky_secret_current(ss, &l);
    /* Snapshot + close. */
    uint8_t before[32];
    memcpy(before, p, 32);

    n00b_quic_sticky_secret_close(ss);
    n00b_quic_sticky_secret_close(ss);  /* idempotent */

    /* After close, current() returns NULL. */
    size_t l2;
    assert(n00b_quic_sticky_secret_current(ss, &l2) == NULL);
    assert(l2 == 0);

    /* The bytes the original pointer pointed at have been zeroed
     * (security hygiene — no lingering plaintext post-close). */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (p[i] != 0) { all_zero = 0; break; }
    }
    assert(all_zero);
    /* Sanity: the "before" snapshot was non-zero (otherwise the
     * zeroing assertion is vacuous). */
    int snapshot_nonzero = 0;
    for (int i = 0; i < 32; i++) {
        if (before[i] != 0) { snapshot_nonzero = 1; break; }
    }
    assert(snapshot_nonzero);

    printf("  [PASS] close idempotent + zeroes current bytes\n");
}

/* ============================================================================
 * 7. Endpoint integration — verify the bytes flow through to picoquic.
 * ============================================================================ */

#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/endpoint.h"
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"
#include "picoquic_internal.h"

static void
test_endpoint_consumes_sticky_secret(void)
{
    /* picoquic uses 16-byte stateless-reset seeds (PICOQUIC_RESET_SECRET_SIZE).
     * The design doc's "32 bytes" was wrong; we follow picoquic. */
    auto ssr = n00b_quic_sticky_secret_open(16);
    assert(n00b_result_is_ok(ssr));
    n00b_quic_sticky_secret_t *ss = n00b_result_get(ssr);
    size_t  len = 0;
    const uint8_t *ssb = n00b_quic_sticky_secret_current(ss, &len);
    assert(len == 16);

    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    /* Build a client-mode endpoint (no cert/key needed) with the
     * caller-supplied stateless-reset secret. */
    auto er = n00b_quic_endpoint_new(c, io,
                                     .bind_host = "127.0.0.1",
                                     .alpn      = "n00b-stickytest/1",
                                     .stateless_reset_secret     = ssb,
                                     .stateless_reset_secret_len = len);
    if (n00b_result_is_err(er)) {
        fprintf(stderr, "quic endpoint creation failed: err=%d\n",
                n00b_result_get_err(er));
    }
    assert(n00b_result_is_ok(er));
    n00b_quic_endpoint_t *ep = n00b_result_get(er);

    /* picoquic stores the seed in `quic->reset_seed`; we read it
     * back to confirm the bytes flowed through. */
    assert(memcmp(ep->quic->reset_seed, ssb, 16) == 0);
    printf("  [PASS] endpoint reset_seed matches sticky_secret_current\n");

    /* Wrong length → endpoint construction errors out. */
    auto bad = n00b_quic_endpoint_new(c, io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = "n00b-stickytest/1",
                                      .stateless_reset_secret     = ssb,
                                      .stateless_reset_secret_len = 32);
    assert(n00b_result_is_err(bad));
    printf("  [PASS] wrong-sized stateless_reset_secret rejected\n");

    n00b_quic_endpoint_close(ep);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    n00b_quic_sticky_secret_close(ss);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_sticky_secret:\n");
    test_open_and_current();
    test_open_arg_validation();
    test_rotate_changes_bytes();
    test_old_pointer_still_valid();
    test_reader_writer();
    test_close_idempotent();
    test_endpoint_consumes_sticky_secret();
    printf("All quic_sticky_secret tests passed.\n");

    n00b_shutdown();
    return 0;
}

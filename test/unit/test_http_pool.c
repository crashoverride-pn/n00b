/*
 * test_http_pool.c — Phase 6 chunk 4 unit tests.
 *
 * Coverage:
 *   - acquire on empty pool → miss
 *   - release + acquire → hit; correct transport scoping
 *   - per-origin cap eviction (LRU within bucket)
 *   - global cap eviction (LRU across buckets)
 *   - idle-timeout reaping
 *   - lifetime-cap reaping
 *   - close evicts everything via close-fn
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/thread.h"
#include "core/stw.h"
#include "internal/net/http/http_pool.h"

/* The "connection" we pool is just a tagged int the close-fn
 * counts so tests can verify how many entries got reaped. */
static int g_close_count = 0;

static void
test_close(void *u)
{
    (void)u;
    g_close_count++;
}

static n00b_string_t *
S(const char *cstr)
{
    return n00b_string_from_cstr(cstr);
}

#define TAG(n) ((void *)(uintptr_t)(n))

static void
reset_count(void)
{
    g_close_count = 0;
}

static void
test_empty_acquire(void)
{
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new();
    void *u = n00b_http_connection_pool_acquire(p, S("https://example.com"),
                                       N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == nullptr);
    assert(n00b_http_connection_pool_stats(p).acquire_misses == 1);
    assert(n00b_http_connection_pool_stats(p).acquire_hits == 0);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] empty pool → acquire miss\n");
}

static void
test_basic_release_acquire(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new();
    n00b_http_connection_pool_release(p, S("https://example.com"),
                            N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(7),
                            test_close);
    assert(n00b_http_connection_pool_stats(p).idle_count == 1);

    void *u = n00b_http_connection_pool_acquire(p, S("https://example.com"),
                                       N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == TAG(7));
    assert(n00b_http_connection_pool_stats(p).idle_count == 0);
    assert(n00b_http_connection_pool_stats(p).acquire_hits == 1);
    /* close-fn is NOT invoked on acquire — the caller now owns the entry. */
    assert(g_close_count == 0);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] release → acquire returns the same user_data\n");
}

static void
test_transport_scoping(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new();
    n00b_http_connection_pool_release(p, S("https://example.com"),
                            N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(1),
                            test_close);
    /* Different transport → miss. */
    void *u = n00b_http_connection_pool_acquire(p, S("https://example.com"),
                                       N00B_HTTP_CONNECTION_POOL_TRANSPORT_H3);
    assert(u == nullptr);
    /* Same transport → hit. */
    u = n00b_http_connection_pool_acquire(p, S("https://example.com"),
                                 N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == TAG(1));
    n00b_http_connection_pool_close(p);
    printf("  [PASS] h1 entry doesn't satisfy h3 acquire\n");
}

static void
test_origin_scoping(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new();
    n00b_http_connection_pool_release(p, S("https://a.example.com"),
                            N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(1),
                            test_close);
    /* Different origin → miss. */
    void *u = n00b_http_connection_pool_acquire(p, S("https://b.example.com"),
                                       N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == nullptr);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] origin scoping enforced\n");
}

static void
test_per_origin_cap(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new(.max_per_origin = 2,
                                              .max_total_idle = 100);
    n00b_string_t *o = S("https://example.com");

    n00b_http_connection_pool_release(p, o, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(1), test_close);
    n00b_http_connection_pool_release(p, o, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(2), test_close);
    /* Third release evicts the LRU (TAG(1) since we just bumped TAG(2) MRU). */
    n00b_http_connection_pool_release(p, o, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(3), test_close);
    assert(g_close_count == 1);
    assert(n00b_http_connection_pool_stats(p).idle_count == 2);
    assert(n00b_http_connection_pool_stats(p).evict_cap_per_origin == 1);

    /* MRU now: TAG(3) at head, TAG(2) at tail. */
    void *u = n00b_http_connection_pool_acquire(p, o, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == TAG(3));
    u = n00b_http_connection_pool_acquire(p, o, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == TAG(2));
    n00b_http_connection_pool_close(p);
    printf("  [PASS] per-origin cap evicts LRU within bucket\n");
}

static void
test_global_cap(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new(.max_total_idle = 2,
                                              .max_per_origin = 100);
    n00b_http_connection_pool_release(p, S("https://a"), N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1,
                            TAG(1), test_close);
    n00b_http_connection_pool_release(p, S("https://b"), N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1,
                            TAG(2), test_close);
    n00b_http_connection_pool_release(p, S("https://c"), N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1,
                            TAG(3), test_close);
    /* TAG(1) (oldest) evicted. */
    assert(g_close_count == 1);
    assert(n00b_http_connection_pool_stats(p).evict_cap_total == 1);
    assert(n00b_http_connection_pool_stats(p).idle_count == 2);
    /* a's bucket should now be empty. */
    void *u = n00b_http_connection_pool_acquire(p, S("https://a"),
                                       N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
    assert(u == nullptr);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] global cap evicts global-LRU across buckets\n");
}

static void
test_idle_timeout_reap(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new(.idle_timeout_ms = 1000,
                                              .lifetime_ms = 0);
    n00b_http_connection_pool_set_now_for_test(p, 1000);
    n00b_http_connection_pool_release(p, S("https://example.com"),
                            N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(1), test_close);
    /* 999 ms after admit: no reap. */
    n00b_http_connection_pool_reap(p, 1999);
    assert(g_close_count == 0);
    assert(n00b_http_connection_pool_stats(p).idle_count == 1);
    /* 1000 ms after admit: reap. */
    n00b_http_connection_pool_reap(p, 2000);
    assert(g_close_count == 1);
    assert(n00b_http_connection_pool_stats(p).evict_idle_timeout == 1);
    assert(n00b_http_connection_pool_stats(p).idle_count == 0);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] idle-timeout reap fires at threshold\n");
}

static void
test_lifetime_reap(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new(.idle_timeout_ms = 0,
                                              .lifetime_ms = 5000);
    n00b_http_connection_pool_set_now_for_test(p, 0);
    n00b_http_connection_pool_release(p, S("https://example.com"),
                            N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(1), test_close);
    n00b_http_connection_pool_reap(p, 4999);
    assert(g_close_count == 0);
    n00b_http_connection_pool_reap(p, 5000);
    assert(g_close_count == 1);
    assert(n00b_http_connection_pool_stats(p).evict_lifetime == 1);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] lifetime cap reap fires at threshold\n");
}

static void
test_close_drops_everything(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new();
    n00b_http_connection_pool_release(p, S("https://a"), N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1,
                            TAG(1), test_close);
    n00b_http_connection_pool_release(p, S("https://b"), N00B_HTTP_CONNECTION_POOL_TRANSPORT_H3,
                            TAG(2), test_close);
    n00b_http_connection_pool_release(p, S("https://a"), N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1,
                            TAG(3), test_close);
    n00b_http_connection_pool_close(p);
    assert(g_close_count == 3);
    /* Idempotent — close again on the now-drained pool is OK. */
    n00b_http_connection_pool_close(p);
    assert(g_close_count == 3);
    printf("  [PASS] close() invokes close-fn for every entry; idempotent\n");
}

static void
test_release_with_null_close_fn(void)
{
    /* Defensive: a null close_fn would be a programming bug.  Instead
     * of crashing, the pool refuses admission so no orphan entries
     * survive. */
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new();
    n00b_http_connection_pool_release(p, S("https://example.com"),
                            N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1, TAG(1), nullptr);
    assert(n00b_http_connection_pool_stats(p).idle_count == 0);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] release with null close_fn is dropped, not admitted\n");
}

/* --------------------------------------------------------------- *
 * Concurrency smoke: hammer acquire/release/stats from N threads.  *
 * Each worker calls n00b_thread_checkin() per iter so STW can     *
 * make progress while the loops run.                              *
 * --------------------------------------------------------------- */

#define STRESS_THREADS 4
#define STRESS_ITERS   500

static void *
stress_worker(void *arg)
{
    n00b_http_connection_pool_t *p = (n00b_http_connection_pool_t *)arg;
    for (int i = 0; i < STRESS_ITERS; i++) {
        n00b_string_t *origin =
            (i % 2 == 0) ? S("https://a.example.com")
                         : S("https://b.example.com");
        void *u = n00b_http_connection_pool_acquire(
            p, origin, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1);
        if (!u) {
            n00b_http_connection_pool_release(
                p, origin, N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1,
                TAG(i + 1), test_close);
        }
        (void)n00b_http_connection_pool_stats(p);
    }
    return nullptr;
}

static void
test_concurrent_stress(void)
{
    reset_count();
    n00b_http_connection_pool_t *p = n00b_http_connection_pool_new(
        .max_total_idle = 32,
        .max_per_origin = 16);

    n00b_thread_t *threads[STRESS_THREADS];
    for (int i = 0; i < STRESS_THREADS; i++) {
        auto tr = n00b_thread_spawn(stress_worker, p);
        threads[i] = n00b_result_get(tr);
    }
    for (int i = 0; i < STRESS_THREADS; i++) {
        (void)n00b_thread_join(threads[i]);
    }

    n00b_http_connection_pool_stats_t st = n00b_http_connection_pool_stats(p);
    size_t expected = (size_t)STRESS_THREADS * (size_t)STRESS_ITERS;
    assert(st.acquire_hits + st.acquire_misses == expected);
    n00b_http_connection_pool_close(p);
    printf("  [PASS] concurrent acquire/release across %d threads x %d iters "
           "(hits=%zu, misses=%zu, evictions=%zu)\n",
           STRESS_THREADS, STRESS_ITERS,
           st.acquire_hits, st.acquire_misses,
           st.evict_cap_total + st.evict_cap_per_origin);
}


int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_pool:\n");
    test_empty_acquire();
    test_basic_release_acquire();
    test_transport_scoping();
    test_origin_scoping();
    test_per_origin_cap();
    test_global_cap();
    test_idle_timeout_reap();
    test_lifetime_reap();
    test_close_drops_everything();
    test_release_with_null_close_fn();
    test_concurrent_stress();
    printf("All test_http_pool tests passed.\n");

    n00b_shutdown();
    return 0;
}

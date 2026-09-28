/* test/unit/test_pool_page_cache.c - the released big-page cache in pool.c.
 *
 * A freed big pool page is parked, still mapped, and handed back out to the
 * next big allocation of exactly its size. This checks the contract through
 * the counters in n00b_pool_global_stats():
 *
 *   default mode   exact-size reuse returns zeroed memory; a full size class
 *                  refuses; a .page_cache = false pool never parks but may
 *                  take a parked page, which stays usable; drain unmaps; a
 *                  parked page survives one collection and is unmapped by the
 *                  second.
 *   "disabled"     N00B_POOL_PAGE_CACHE_MB=0 turns the cache off.
 *   "cap"          N00B_POOL_PAGE_CACHE_MB=2 accepts a put that lands exactly
 *                  on the cap and refuses one that would pass it.
 *
 * Every mode drains the cache first, so the counters start from a cache
 * holding nothing.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/align.h"
#include "core/gc.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "util/assert.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

#define MB (1024ull * 1024ull)

static uint8_t *
big_alloc(n00b_allocator_t *alloc, size_t n)
{
    uint8_t *p = n00b_alloc_array_with_opts(uint8_t,
                                            n,
                                            &(n00b_alloc_opts_t){
                                                .allocator = alloc,
                                                .no_scan   = true,
                                            });
    CHECK(p != nullptr);
    return p;
}

static bool
all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return false;
        }
    }
    return true;
}

// A request that maps exactly `mapped` bytes once the pool adds its page and
// entry headers, which are far smaller than half a page.
static size_t
request_for_mapped(uint64_t mapped)
{
    return (size_t)(mapped - n00b_page_size / 2);
}

static void
test_exact_reuse_is_zeroed(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "page_cache_reuse");
    size_t            n     = request_for_mapped(MB + 3 * n00b_page_size);

    n00b_pool_global_stats_t s0 = n00b_pool_global_stats();
    uint8_t                 *p  = big_alloc(alloc, n);
    memset(p, 0xa5, n);
    n00b_free_from_allocator(alloc, p);

    n00b_pool_global_stats_t s1 = n00b_pool_global_stats();
    CHECK(s1.page_cache_parked == s0.page_cache_parked + 1);
    CHECK(s1.page_cache_bytes == s0.page_cache_bytes + MB + 3 * n00b_page_size);

    uint8_t                 *q  = big_alloc(alloc, n);
    n00b_pool_global_stats_t s2 = n00b_pool_global_stats();
    CHECK(q == p);
    CHECK(s2.page_cache_hits == s1.page_cache_hits + 1);
    CHECK(s2.page_cache_bytes == s0.page_cache_bytes);
    CHECK(all_zero(q, n));

    n00b_free_from_allocator(alloc, q);
    n00b_allocator_destroy(alloc);
    n00b_pool_page_cache_drain();
    printf("  [PASS] exact_reuse_is_zeroed\n");
}

// Five sizes in one power-of-two class: the class holds four, so the fifth
// release is unmapped, and only the four parked sizes are hits on the way
// back.
static void
test_full_class_refuses(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "page_cache_class");
    uint8_t          *p[5];
    size_t            n[5];
    uint64_t          parked_bytes = 0;

    for (int i = 0; i < 5; i++) {
        n[i] = request_for_mapped(MB + (uint64_t)(i + 1) * n00b_page_size);
        p[i] = big_alloc(alloc, n[i]);
    }

    n00b_pool_global_stats_t s0 = n00b_pool_global_stats();
    CHECK(s0.page_cache_bytes == 0);

    for (int i = 0; i < 5; i++) {
        n00b_free_from_allocator(alloc, p[i]);
        if (i < 4) {
            parked_bytes += MB + (uint64_t)(i + 1) * n00b_page_size;
        }
    }

    n00b_pool_global_stats_t s1 = n00b_pool_global_stats();
    CHECK(s1.page_cache_parked == s0.page_cache_parked + 4);
    CHECK(s1.page_cache_bytes == parked_bytes);

    for (int i = 0; i < 5; i++) {
        p[i] = big_alloc(alloc, n[i]);
    }

    n00b_pool_global_stats_t s2 = n00b_pool_global_stats();
    CHECK(s2.page_cache_hits == s1.page_cache_hits + 4);
    CHECK(s2.page_cache_misses == s1.page_cache_misses + 1);
    CHECK(s2.page_cache_bytes == 0);

    for (int i = 0; i < 5; i++) {
        n00b_free_from_allocator(alloc, p[i]);
    }
    n00b_allocator_destroy(alloc);
    n00b_pool_page_cache_drain();
    printf("  [PASS] full_class_refuses\n");
}

// A .page_cache = false pool unmaps its big frees. It may still take a page
// another pool parked, and that page comes back zeroed and writable.
static void
test_opt_out_pool(void)
{
    n00b_pool_t       caching;
    n00b_pool_t       direct;
    n00b_allocator_t *ca = n00b_pool_init(&caching, .name = "page_cache_on");
    n00b_allocator_t *da = n00b_pool_init(&direct,
                                          .name       = "page_cache_off",
                                          .page_cache = false);
    size_t            n  = request_for_mapped(2 * MB + 5 * n00b_page_size);

    CHECK(caching.page_cache);
    CHECK(!direct.page_cache);

    n00b_pool_global_stats_t s0 = n00b_pool_global_stats();
    uint8_t                 *d  = big_alloc(da, n);
    memset(d, 0x5a, n);
    n00b_free_from_allocator(da, d);

    n00b_pool_global_stats_t s1 = n00b_pool_global_stats();
    CHECK(s1.page_cache_parked == s0.page_cache_parked);
    CHECK(s1.page_cache_bytes == s0.page_cache_bytes);

    uint8_t *c = big_alloc(ca, n);
    memset(c, 0xc3, n);
    n00b_free_from_allocator(ca, c);

    n00b_pool_global_stats_t s2 = n00b_pool_global_stats();
    CHECK(s2.page_cache_parked == s1.page_cache_parked + 1);
    CHECK(s2.page_cache_bytes == s1.page_cache_bytes + 2 * MB + 5 * n00b_page_size);

    d = big_alloc(da, n);
    n00b_pool_global_stats_t s3 = n00b_pool_global_stats();
    CHECK(d == c);
    CHECK(s3.page_cache_hits == s2.page_cache_hits + 1);
    CHECK(s3.page_cache_bytes == s1.page_cache_bytes);
    CHECK(all_zero(d, n));
    memset(d, 0x77, n);
    CHECK(d[0] == 0x77 && d[n - 1] == 0x77);
    n00b_free_from_allocator(da, d);

    n00b_pool_global_stats_t s4 = n00b_pool_global_stats();
    CHECK(s4.page_cache_parked == s3.page_cache_parked);
    CHECK(s4.page_cache_bytes == s1.page_cache_bytes);

    // Drain unmaps what the caching pool parks; the next allocation of that
    // size is a fresh, zeroed mapping.
    c = big_alloc(ca, n);
    n00b_free_from_allocator(ca, c);
    CHECK(n00b_pool_global_stats().page_cache_bytes
          == s1.page_cache_bytes + 2 * MB + 5 * n00b_page_size);
    CHECK(n00b_pool_page_cache_drain() >= 2 * MB + 5 * n00b_page_size);
    CHECK(n00b_pool_global_stats().page_cache_bytes == 0);

    n00b_pool_global_stats_t s5 = n00b_pool_global_stats();
    c                           = big_alloc(ca, n);
    CHECK(n00b_pool_global_stats().page_cache_misses == s5.page_cache_misses + 1);
    CHECK(all_zero(c, n));
    n00b_free_from_allocator(ca, c);

    n00b_allocator_destroy(ca);
    n00b_allocator_destroy(da);
    n00b_pool_page_cache_drain();
    printf("  [PASS] opt_out_pool\n");
}

// Each collection advances the cache's generation, and a page parked before
// the previous collection is unmapped when the next one restarts the world.
// The collector's own work pool may park pages meanwhile, so this follows two
// pages of sizes nothing else maps through hits on this thread.
static void
test_ages_out_across_collections(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc  = n00b_pool_init(&pool, .name = "page_cache_age");
    n00b_arena_t     *arena  = n00b_new_arena(.size = 1 << 20, .use_gc = true);
    size_t            a_n    = request_for_mapped(MB + 9 * n00b_page_size);
    size_t            b_n    = request_for_mapped(MB + 11 * n00b_page_size);
    uint8_t          *a      = big_alloc(alloc, a_n);
    uint8_t          *b      = big_alloc(alloc, b_n);
    uint64_t          parked = n00b_pool_global_stats().page_cache_parked;

    n00b_free_from_allocator(alloc, a);
    n00b_free_from_allocator(alloc, b);
    CHECK(n00b_pool_global_stats().page_cache_parked == parked + 2);

    // One collection: a is still parked. Releasing it again parks it in the
    // new generation, while b stays in the old one.
    n00b_collect(arena);
    uint64_t hits = n00b_pool_global_stats().page_cache_hits;
    a             = big_alloc(alloc, a_n);
    CHECK(n00b_pool_global_stats().page_cache_hits == hits + 1);
    n00b_free_from_allocator(alloc, a);

    // Second collection: b, parked two generations back, is unmapped, and a,
    // parked one generation back, stays.
    uint64_t evicted = n00b_pool_global_stats().page_cache_evicted;
    n00b_collect(arena);
    CHECK(n00b_pool_global_stats().page_cache_evicted >= evicted + 1);

    hits = n00b_pool_global_stats().page_cache_hits;
    b    = big_alloc(alloc, b_n);
    CHECK(n00b_pool_global_stats().page_cache_hits == hits);
    CHECK(all_zero(b, b_n));
    a = big_alloc(alloc, a_n);
    CHECK(n00b_pool_global_stats().page_cache_hits == hits + 1);

    n00b_free_from_allocator(alloc, a);
    n00b_free_from_allocator(alloc, b);
    n00b_allocator_destroy(alloc);
    n00b_pool_page_cache_drain();
    printf("  [PASS] ages_out_across_collections\n");
}

static void
test_disabled(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "page_cache_disabled");
    size_t            n     = request_for_mapped(MB + 7 * n00b_page_size);

    n00b_pool_global_stats_t s0 = n00b_pool_global_stats();
    CHECK(s0.page_cache_cap_bytes == 0);
    CHECK(s0.page_cache_bytes == 0);

    for (int round = 0; round < 3; round++) {
        uint8_t *p = big_alloc(alloc, n);
        CHECK(all_zero(p, n));
        memset(p, 0x3c, n);
        n00b_free_from_allocator(alloc, p);
    }

    n00b_pool_global_stats_t s1 = n00b_pool_global_stats();
    CHECK(s1.page_cache_parked == s0.page_cache_parked);
    CHECK(s1.page_cache_hits == s0.page_cache_hits);
    CHECK(s1.page_cache_bytes == 0);

    n00b_allocator_destroy(alloc);
    printf("  [PASS] disabled\n");
}

// Cap of 2 MB: two 1 MB parks land exactly on it and are accepted; a third
// release would pass it and is unmapped; once a parked page is taken back the
// same release fits. The small page is 20 OS pages so that no slab chunk,
// which every pool maps at 64K, can take it from the cache mid-test.
static void
test_cap_boundary(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "page_cache_cap");
    size_t            one   = request_for_mapped(MB);
    size_t            small = request_for_mapped(20 * n00b_page_size);

    n00b_pool_global_stats_t s0 = n00b_pool_global_stats();
    CHECK(s0.page_cache_cap_bytes == 2 * MB);
    CHECK(s0.page_cache_bytes == 0);

    uint8_t *a = big_alloc(alloc, one);
    uint8_t *b = big_alloc(alloc, one);
    uint8_t *c = big_alloc(alloc, small);

    n00b_free_from_allocator(alloc, a);
    n00b_free_from_allocator(alloc, b);
    n00b_pool_global_stats_t s1 = n00b_pool_global_stats();
    CHECK(s1.page_cache_parked == s0.page_cache_parked + 2);
    CHECK(s1.page_cache_bytes == 2 * MB);

    n00b_free_from_allocator(alloc, c);
    n00b_pool_global_stats_t s2 = n00b_pool_global_stats();
    CHECK(s2.page_cache_parked == s1.page_cache_parked);
    CHECK(s2.page_cache_bytes == 2 * MB);

    a = big_alloc(alloc, one);
    CHECK(n00b_pool_global_stats().page_cache_bytes == MB);
    c = big_alloc(alloc, small);
    n00b_free_from_allocator(alloc, c);
    n00b_pool_global_stats_t s3 = n00b_pool_global_stats();
    CHECK(s3.page_cache_parked == s2.page_cache_parked + 1);
    CHECK(s3.page_cache_bytes == MB + 20 * n00b_page_size);

    n00b_free_from_allocator(alloc, a);
    n00b_allocator_destroy(alloc);
    n00b_pool_page_cache_drain();
    printf("  [PASS] cap_boundary\n");
}

int
main(int argc, char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "default";

    // Fallback for direct runs; meson sets these in the test environment.
    if (strcmp(mode, "disabled") == 0) {
        setenv("N00B_POOL_PAGE_CACHE_MB", "0", 1);
    }
    else if (strcmp(mode, "cap") == 0) {
        setenv("N00B_POOL_PAGE_CACHE_MB", "2", 1);
    }
    else {
        unsetenv("N00B_POOL_PAGE_CACHE_MB");
    }

    n00b_init_simple(argc, argv);
    n00b_pool_page_cache_drain();

    if (strcmp(mode, "disabled") == 0) {
        test_disabled();
    }
    else if (strcmp(mode, "cap") == 0) {
        test_cap_boundary();
    }
    else {
#if defined(_WIN32)
        // The cache is off by default on Windows.
        CHECK(n00b_pool_global_stats().page_cache_cap_bytes == 0);
        printf("  [SKIP] default-mode cases (cache off on Windows)\n");
#else
        test_exact_reuse_is_zeroed();
        test_full_class_refuses();
        test_opt_out_pool();
        test_ages_out_across_collections();
#endif
    }

    printf("test_pool_page_cache %s OK\n", mode);
    return 0;
}

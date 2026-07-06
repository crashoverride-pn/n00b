#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/alloc_mdata.h"
#include "core/pool.h"
#include "core/align.h"

// ============================================================================
// 1. Init — pool_init returns non-null allocator with correct debug_name
// ============================================================================

static void
test_init(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "test_pool");

    assert(alloc != nullptr);
    assert(strcmp(alloc->debug_name, "test_pool") == 0);

    printf("  [PASS] init\n");
}

// ============================================================================
// 2. Small alloc — allocate 32-byte object; aligned and usable
// ============================================================================

static void
test_small_alloc(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool);

    void *p = n00b_alloc_array_with_opts(uint8_t, 32, &(n00b_alloc_opts_t){.allocator = alloc});

    assert(p != nullptr);
    assert(((uintptr_t)p & (N00B_ALIGN - 1)) == 0);

    // Write and read back
    memset(p, 0xAB, 32);
    assert(((uint8_t *)p)[0] == 0xAB);
    assert(((uint8_t *)p)[31] == 0xAB);

    n00b_free(p);
    printf("  [PASS] small_alloc\n");
}

// ============================================================================
// 3. Size classes — allocs of sizes 64, 128, 256, 512 succeed
// ============================================================================

static void
test_size_classes(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool);

    int sizes[] = {64, 128, 256, 512};

    for (int i = 0; i < 4; i++) {
        void *p = n00b_alloc_array_with_opts(uint8_t, sizes[i], &(n00b_alloc_opts_t){.allocator = alloc});
        assert(p != nullptr);
        assert(((uintptr_t)p & (N00B_ALIGN - 1)) == 0);

        // Verify usable by writing
        memset(p, (uint8_t)(i + 1), sizes[i]);
        assert(((uint8_t *)p)[0] == (uint8_t)(i + 1));
        assert(((uint8_t *)p)[sizes[i] - 1] == (uint8_t)(i + 1));

        n00b_free(p);
    }

    printf("  [PASS] size_classes\n");
}

// ============================================================================
// 4. Free recycle — alloc, free, alloc again; second may reuse freed slot
// ============================================================================

static void
test_free_recycle(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool);

    void *p1 = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p1 != nullptr);

    n00b_free(p1);

    void *p2 = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p2 != nullptr);

    // The second allocation should be valid regardless of whether
    // it reused the same slot
    memset(p2, 0xCD, 64);
    assert(((uint8_t *)p2)[0] == 0xCD);

    n00b_free(p2);
    printf("  [PASS] free_recycle\n");
}

// ============================================================================
// 5. Many allocs — 100 allocations all return distinct pointers
// ============================================================================

static void
test_many_allocs(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool);

    void *ptrs[100];

    for (int i = 0; i < 100; i++) {
        ptrs[i] = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
        assert(ptrs[i] != nullptr);
    }

    // All should be distinct
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            assert(ptrs[i] != ptrs[j]);
        }
    }

    for (int i = 0; i < 100; i++) {
        n00b_free(ptrs[i]);
    }

    printf("  [PASS] many_allocs\n");
}

// ============================================================================
// 6. Inline header — pool allocs with inline_headers have valid guard
// ============================================================================

static void
test_inline_header(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .inline_headers = true);

    void *p = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);

    n00b_option_t(n00b_inline_hdr_t *) opt = n00b_inline_alloc_header(p);
    assert(n00b_option_is_set(opt));

    n00b_inline_hdr_t *hdr = n00b_option_get(opt);
    assert(hdr->guard == n00b_gc_guard);

    n00b_free(p);
    printf("  [PASS] inline_header\n");
}

// ============================================================================
// 7. Alignment — all pool allocations are N00B_ALIGN aligned
// ============================================================================

static void
test_alignment(void)
{
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool);

    for (int i = 0; i < 50; i++) {
        void *p = n00b_alloc_array_with_opts(uint8_t, 48 + i, &(n00b_alloc_opts_t){.allocator = alloc});
        assert(p != nullptr);
        assert(((uintptr_t)p & (N00B_ALIGN - 1)) == 0);
        n00b_free(p);
    }

    printf("  [PASS] alignment\n");
}

// ============================================================================
// 8. Known allocator free — hidden/system pools are not discoverable
// ============================================================================

static void
test_known_allocator_free_system_hidden(void)
{
    n00b_pool_global_stats_t before = n00b_pool_global_stats();
    n00b_pool_t      pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool,
                                             .__system = true,
                                             .hidden   = true,
                                             .name     = "test_gc_work_pool");

    void *p1 = n00b_alloc_array_with_opts(uint8_t,
                                          64,
                                          &(n00b_alloc_opts_t){
                                              .allocator = alloc,
                                              .no_scan   = true});
    assert(p1 != nullptr);
    assert(!n00b_option_is_set(n00b_mem_get_allocator(p1)));

    n00b_pool_global_stats_t during = n00b_pool_global_stats();
    assert(during.live_system_pool_count >= before.live_system_pool_count + 1);
    assert(during.live_system_mapped_bytes >= before.live_system_mapped_bytes + n00b_page_size);
    assert(during.diagnostic_page_count >= before.diagnostic_page_count + 1);

    uint64_t    page_start = 0;
    uint64_t    page_end = 0;
    const char *page_name = nullptr;
    bool        registered = true;
    assert(n00b_pool_diagnostic_lookup_page((uintptr_t)((uintptr_t)p1 & ~(n00b_page_size - 1)),
                                            &page_start,
                                            &page_end,
                                            &page_name,
                                            nullptr,
                                            &registered));
    assert(page_start != 0);
    assert(page_end > page_start);
    assert(page_name != nullptr && strcmp(page_name, "test_gc_work_pool") == 0);
    assert(!registered);

    n00b_free_from_allocator(alloc, p1);

    void *p2 = n00b_alloc_array_with_opts(uint8_t,
                                          64,
                                          &(n00b_alloc_opts_t){
                                              .allocator = alloc,
                                              .no_scan   = true});
    assert(p2 == p1);

    n00b_free_from_allocator(alloc, p2);
    n00b_allocator_destroy(alloc);

    n00b_pool_global_stats_t after = n00b_pool_global_stats();
    assert(after.live_system_pool_count <= during.live_system_pool_count - 1);
    assert(after.diagnostic_page_count <= during.diagnostic_page_count - 1);

    printf("  [PASS] known_allocator_free_system_hidden\n");
}

// ============================================================================
// 9. Per-pool refcount — .pool_refcount forces OOB; ref/unref balance; last
//    unref reclaims via the on_last_unref hook.
// ============================================================================

static int  g_pool_unref_hook_calls = 0;
static void *g_pool_unref_hook_ctx  = nullptr;

static void
pool_unref_hook(void *ctx)
{
    g_pool_unref_hook_calls++;
    g_pool_unref_hook_ctx = ctx;
}

static void
test_pool_refcount(void)
{
    static n00b_pool_t pool; // static: survives the on_last_unref teardown path
    n00b_allocator_t  *alloc = n00b_pool_init(&pool,
                                              .pool_refcount = true,
                                              .name          = "rc_pool");
    assert(alloc != nullptr);

    // .pool_refcount is orthogonal to the metadata strategy: it must NOT force
    // OOB on (no kwargs requested it here) and must NOT reserve a flex tail.
    assert(pool.vtable.metadata_pool == nullptr);
    assert(pool.vtable.oob_extra_size == 0);
    assert(pool.pool_refcounted);
    assert(atomic_load(&pool.pool_refs) == 1);

    int marker = 42;
    n00b_pool_set_unref_cb(&pool, pool_unref_hook, &marker);

    // Allocations still work normally.
    void *p = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);
    memset(p, 0x5A, 64);

    // ref then unref: net zero, no reclaim.
    n00b_pool_ref(&pool);
    assert(atomic_load(&pool.pool_refs) == 2);
    n00b_pool_unref(&pool);
    assert(atomic_load(&pool.pool_refs) == 1);
    assert(g_pool_unref_hook_calls == 0);

    // Last unref fires the hook exactly once with our ctx.
    n00b_pool_unref(&pool);
    assert(g_pool_unref_hook_calls == 1);
    assert(g_pool_unref_hook_ctx == &marker);

    printf("  [PASS] pool_refcount\n");
}

// ============================================================================
// 10. Per-pool refcount default reclaim — no hook installed → last unref calls
//     n00b_allocator_destroy (pool memory is released; we just exercise the path).
// ============================================================================

static void
test_pool_refcount_default_destroy(void)
{
    static n00b_pool_t pool;
    n00b_allocator_t  *alloc = n00b_pool_init(&pool,
                                              .pool_refcount = true,
                                              .name          = "rc_pool_default");
    assert(alloc != nullptr);

    void *p = n00b_alloc_array_with_opts(uint8_t, 128, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);

    // No hook: last unref must route to n00b_allocator_destroy without crashing.
    n00b_pool_unref(&pool);

    printf("  [PASS] pool_refcount_default_destroy\n");
}

// ============================================================================
// 11. Non-refcounted pools are unaffected — ref/unref are no-ops, the pool is
//     not reclaimed, and OOB is NOT forced on (caller's choice still honored).
// ============================================================================

static void
test_refcount_noop_on_plain_pool(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "plain_pool");
    assert(alloc != nullptr);
    assert(!pool.pool_refcounted);
    assert(pool.vtable.oob_extra_size == 0);

    void *p = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);

    // No-ops: must not reclaim or fault.
    n00b_pool_ref(&pool);
    n00b_pool_unref(&pool);
    n00b_alloc_ref(p);
    n00b_alloc_unref(p);

    // Pool still usable after the no-op ref/unref.
    void *p2 = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p2 != nullptr);

    n00b_free(p);
    n00b_free(p2);
    printf("  [PASS] refcount_noop_on_plain_pool\n");
}

// ============================================================================
// 12. Per-alloc refcount — .alloc_refcount reserves a flex tail; ref/unref
//     balance; last unref returns the alloc to the pool (slot recycles).
// ============================================================================

static void
test_alloc_refcount(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool,
                                             .alloc_refcount = true,
                                             .name           = "alloc_rc_pool");
    assert(alloc != nullptr);
    // .alloc_refcount forces OOB + reserves a uint32_t flex tail.
    assert(pool.vtable.metadata_pool != nullptr);
    assert(pool.vtable.oob_extra_size == sizeof(uint32_t));

    void *p = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);

    // Fresh alloc == exactly 1 ref (zero-filled biased counter). The flex tail
    // accessor resolves to non-null for an alloc-refcounted pool.
    assert(n00b_alloc_extra(p) != nullptr);

    // ref then unref: still alive, slot not recycled.
    n00b_alloc_ref(p);   // refs: 1 -> 2
    n00b_alloc_unref(p); // refs: 2 -> 1

    // Last unref returns p to the pool. We assert the behavioral guarantee
    // (a subsequent same-size alloc succeeds and is usable), not the exact slot
    // address — freelist reuse order is an implementation detail.
    n00b_alloc_unref(p); // refs: 1 -> 0 -> freed
    void *p2 = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p2 != nullptr);
    memset(p2, 0x3C, 64);
    assert(((uint8_t *)p2)[63] == 0x3C);

    n00b_alloc_unref(p2); // clean up via the refcount path too
    printf("  [PASS] alloc_refcount\n");
}

// ============================================================================
// 13. Per-alloc refcount survives metadata compaction — the OOB flex tail (and
//     thus the counter) must be carried across an n00b_allocator_compact_metadata
//     rebuild, which reallocates every OOB record.
// ============================================================================

static void
test_alloc_refcount_survives_compaction(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool,
                                             .alloc_refcount = true,
                                             .name           = "alloc_rc_compact");
    assert(alloc != nullptr);

    void *a = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    void *b = n00b_alloc_array_with_opts(uint8_t, 64, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(a != nullptr && b != nullptr);

    // a: refs 1 -> 3 (stored counter 0 -> 2). b stays at 1 ref (stored 0).
    n00b_alloc_ref(a);
    n00b_alloc_ref(a);

    uint32_t a_before = *(uint32_t *)n00b_alloc_extra(a);
    uint32_t b_before = *(uint32_t *)n00b_alloc_extra(b);
    assert(a_before == 2);
    assert(b_before == 0);

    // Rebuild the metadata arena wholesale; every OOB record is reallocated.
    n00b_allocator_compact_metadata(alloc);

    // Records relocated — re-resolve and confirm the flex-tail counters survived.
    uint32_t a_after = *(uint32_t *)n00b_alloc_extra(a);
    uint32_t b_after = *(uint32_t *)n00b_alloc_extra(b);
    assert(a_after == a_before);
    assert(b_after == b_before);

    // The refcount lifecycle still works on the post-compaction records.
    n00b_alloc_unref(a); // 3 -> 2
    n00b_alloc_unref(a); // 2 -> 1
    n00b_alloc_unref(a); // 1 -> 0 -> freed
    n00b_alloc_unref(b); // 1 -> 0 -> freed

    printf("  [PASS] alloc_refcount_survives_compaction\n");
}

// ============================================================================
// Big-free quarantine (env N00B_POOL_BIG_QUARANTINE; see pool.c).
//
// main() sets the env var before n00b_init so the lazily-latched capacity
// sees it (the latch happens at the first big free process-wide). The
// default-off behavior needs no dedicated case here: every other test binary
// in the suite runs with the env unset, exercising the disabled path.
// ============================================================================

// Anything above the largest slab class allocates page-granular ("big").
#define QUAR_BIG_SZ (64 * 1024)

static void
test_quarantine_find_hit_and_miss(void)
{
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "quar_pool");

    void *p = n00b_alloc_array_with_opts(
        uint8_t, QUAR_BIG_SZ, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);
    uintptr_t inside  = (uintptr_t)p + QUAR_BIG_SZ / 2;
    uintptr_t outside = (uintptr_t)p + (uintptr_t)QUAR_BIG_SZ * 8;

    // Live allocation: not quarantined.
    assert(!n00b_option_is_set(n00b_pool_quarantine_find(inside)));

    n00b_free(p);

    // Freed big page is parked: an interior address attributes to it.
    n00b_option_t(n00b_pool_quarantine_hit_t) opt =
        n00b_pool_quarantine_find(inside);
    assert(n00b_option_is_set(opt));
    n00b_pool_quarantine_hit_t hit = n00b_option_get(opt);
    assert(hit.start <= (uintptr_t)p);
    assert(inside < hit.start + hit.size);
    assert(hit.frees[0] != nullptr); // freeing call stack captured
    assert(hit.pool_name != nullptr && strcmp(hit.pool_name, "quar_pool") == 0);

    // Unrelated address: no attribution.
    assert(!n00b_option_is_set(n00b_pool_quarantine_find(outside)));

    printf("  [PASS] quarantine_find_hit_and_miss\n");
}

static void
test_guard_page_per_alloc(void)
{
    // main() sets N00B_POOL_PAGE_PER_ALLOC to a filter matching only pools
    // named *guardpool*. A slab-class (32-byte) allocation from a matching
    // pool must route through the single-entry page path — proven by the
    // freed allocation landing in the big-free quarantine, which only sees
    // page-granular frees. A non-matching pool's small alloc must NOT.
    n00b_pool_t       gpool;
    n00b_allocator_t *galloc = n00b_pool_init(&gpool, .name = "guardpool_a");
    void *gp = n00b_alloc_array_with_opts(
        uint8_t, 32, &(n00b_alloc_opts_t){.allocator = galloc});
    assert(gp != nullptr);
    n00b_free(gp);
    assert(n00b_option_is_set(n00b_pool_quarantine_find((uintptr_t)gp)));

    n00b_pool_t       ppool;
    n00b_allocator_t *palloc = n00b_pool_init(&ppool, .name = "plainpool_a");
    void *pp = n00b_alloc_array_with_opts(
        uint8_t, 32, &(n00b_alloc_opts_t){.allocator = palloc});
    assert(pp != nullptr);
    n00b_free(pp);
    assert(!n00b_option_is_set(n00b_pool_quarantine_find((uintptr_t)pp)));

    printf("  [PASS] guard_page_per_alloc\n");
}

static void
test_quarantine_uaf_faults(void)
{
    // Parent allocates + frees a big page (now parked PROT_NONE), then a
    // forked child touches it: the touch must fault (raw SIGSEGV/SIGBUS, or
    // n00b's crash handler exiting 128+sig) instead of silently reading
    // freed memory. The child does no pool/lock work at all, so runtime
    // fork-safety is not in play.
    n00b_pool_t       pool;
    n00b_allocator_t *alloc = n00b_pool_init(&pool, .name = "quar_uaf");

    void *p = n00b_alloc_array_with_opts(
        uint8_t, QUAR_BIG_SZ, &(n00b_alloc_opts_t){.allocator = alloc});
    assert(p != nullptr);
    n00b_free(p);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 2);
        }
        *(volatile char *)p; // must fault: page is parked PROT_NONE
        _exit(0);            // reached only if the quarantine failed
    }

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    bool died = (WIFSIGNALED(status)
                 && (WTERMSIG(status) == SIGSEGV
                     || WTERMSIG(status) == SIGBUS))
                || (WIFEXITED(status)
                    && (WEXITSTATUS(status) == 128 + SIGSEGV
                        || WEXITSTATUS(status) == 128 + SIGBUS));
    assert(died);

    printf("  [PASS] quarantine_uaf_faults\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    // Must precede n00b_init: the quarantine capacity latches process-wide
    // at the FIRST big free, and init itself can free big pages. The guard
    // filter latches at the first pool alloc; "guardpool" scopes page-per-
    // alloc to this file's dedicated test pool so the rest of the suite's
    // pools stay slab-backed.
    setenv("N00B_POOL_BIG_QUARANTINE", "64", 1);
    setenv("N00B_POOL_PAGE_PER_ALLOC", "guardpool", 1);

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running pool alloc tests...\n");

    test_init();
    test_small_alloc();
    test_size_classes();
    test_free_recycle();
    test_many_allocs();
    test_inline_header();
    test_alignment();
    test_known_allocator_free_system_hidden();
    test_pool_refcount();
    test_pool_refcount_default_destroy();
    test_refcount_noop_on_plain_pool();
    test_alloc_refcount();
    test_alloc_refcount_survives_compaction();
    test_quarantine_find_hit_and_miss();
    test_guard_page_per_alloc();
    test_quarantine_uaf_faults();

    printf("All pool alloc tests passed.\n");
    return 0;
}

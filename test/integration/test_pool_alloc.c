#include <stdio.h>
#include <assert.h>
#include <string.h>

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

    n00b_free_from_allocator(alloc, p1);

    void *p2 = n00b_alloc_array_with_opts(uint8_t,
                                          64,
                                          &(n00b_alloc_opts_t){
                                              .allocator = alloc,
                                              .no_scan   = true});
    assert(p2 == p1);

    n00b_free_from_allocator(alloc, p2);
    n00b_allocator_destroy(alloc);

    printf("  [PASS] known_allocator_free_system_hidden\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
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

    printf("All pool alloc tests passed.\n");
    return 0;
}

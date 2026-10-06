// Self-test for libc malloc-family interposition.
//
// Two things are verified:
//   1. The interposed allocator entry points are functional after n00b_init.
//   2. The shim routes allocations into the thread's current allocator when
//      that allocator opts in with .libc_backing, otherwise into the
//      registered non-moving user_pool. We
//      call the n00b_interposed_* entry points DIRECTLY because
//      the portable QUIC/picotls mechanism is a compile-time redirect to these
//      functions; on macOS, dyld interpose tables do not interpose the image
//      that contains the table, so bare malloc() in this executable is not a
//      useful proof of shim behavior.

#include "n00b/alloc_interpose.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_interpose.h"
#include "core/runtime.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/arena.h"

static void
check_owned(void *p, n00b_allocator_t *expected)
{
    n00b_allocator_opt_t a = n00b_mem_get_allocator(p);
    assert(n00b_option_is_set(a));
    assert(n00b_option_get(a) == expected);
}

// Churn more distinct big allocations through user_pool than the interposer's
// range table holds, then free one after shutdown the way a libc atexit handler
// releases its state. The free must be dropped, never handed to libc.
static int
free_after_shutdown(void)
{
    enum { CHURN = 70000 };
    size_t base = 128 * 1024;

    for (size_t i = 0; i < CHURN; i++) {
        void *p = n00b_interposed_malloc(base + i * n00b_page_size);
        assert(p != nullptr);
        n00b_interposed_free(p);
    }
    // Hold the largest churned mapping and give `late` the same size, so it
    // fits no hole the churn left behind and the kernel maps it next to
    // `hold`, outside every range seen so far. Only the first and last page
    // of each is written.
    size_t big  = base + CHURN * n00b_page_size;
    void  *hold = n00b_interposed_malloc(big);
    void  *late = n00b_interposed_malloc(big);
    assert(hold != nullptr && late != nullptr);
    n00b_interposed_free(hold);

    n00b_shutdown();
    n00b_interposed_free(late);
    assert(n00b_interposed_malloc_usable_size(late) == 0);
    assert(n00b_interposed_realloc(late, 64) == nullptr);
    printf("  [PASS] free_after_shutdown\n");
    return 0;
}

int
main(int argc, char **argv)
{
    bool exit_mode = argc > 1 && strcmp(argv[1], "--free-after-shutdown") == 0;
    if (exit_mode) {
        // Each churned page must come back from the kernel at a fresh range,
        // not out of the released-page cache, which would zero it whole.
        setenv("N00B_POOL_PAGE_CACHE_MB", "0", 1);
    }

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    if (exit_mode) {
        return free_after_shutdown();
    }
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(rt != nullptr);
    setbuf(stdout, NULL);
    printf("Running alloc interposition tests...\n");

    // 1. Install mechanism is detectable.
    assert(n00b_alloc_interposition_active());
    printf("  [PASS] interposition_active\n");

    // 2. malloc routes into the registered non-moving user_pool when no
    //    current allocator is pushed; counter advances; usable size OK.
    n00b_allocator_t *default_alloc = (n00b_allocator_t *)&rt->user_pool;
    uint64_t h0 = n00b_alloc_interpose_hits();
    void    *p  = n00b_interposed_malloc(100);
    assert(p != nullptr);
    assert(n00b_alloc_interpose_hits() > h0);
    check_owned(p, default_alloc);
    memset(p, 0xAB, 100);
    assert(n00b_interposed_malloc_usable_size(p) >= 100);
    n00b_interposed_free(p);
    printf("  [PASS] malloc_routes_to_user_pool\n");

    // 3. calloc zeroes.
    unsigned char *z = n00b_interposed_calloc(64, 4);
    assert(z != nullptr);
    check_owned(z, default_alloc);
    for (int i = 0; i < 256; i++) {
        assert(z[i] == 0);
    }
    n00b_interposed_free(z);
    printf("  [PASS] calloc_zeroes\n");

    // 4. realloc preserves contents and grows.
    char *s = n00b_interposed_malloc(16);
    assert(s != nullptr);
    memcpy(s, "0123456789abcde", 16);
    char *s2 = n00b_interposed_realloc(s, 4096);
    assert(s2 != nullptr);
    assert(memcmp(s2, "0123456789abcde", 16) == 0);
    check_owned(s2, default_alloc);
    n00b_interposed_free(s2);
    printf("  [PASS] realloc_preserves\n");

    // 5. strdup.
    char *d = n00b_interposed_strdup("hello, interposed world");
    assert(d != nullptr && strcmp(d, "hello, interposed world") == 0);
    check_owned(d, default_alloc);
    n00b_interposed_free(d);
    printf("  [PASS] strdup\n");

    // 6. aligned_alloc + posix_memalign across alignments. The returned
    //    pointer must satisfy the alignment, live in the default allocator, be
    //    writable, and free correctly (base recovered from n00b metadata).
    for (size_t align = 16; align <= 4096; align <<= 1) {
        void *ap = n00b_interposed_aligned_alloc(align, align * 2);
        assert(ap != nullptr);
        assert(((uintptr_t)ap & (align - 1)) == 0);
        check_owned(ap, default_alloc);
        memset(ap, 0x5A, align * 2);
        n00b_interposed_free(ap);

        void *mp = nullptr;
        int   rc = n00b_interposed_posix_memalign(&mp, align, 200);
        assert(rc == 0 && mp != nullptr);
        assert(((uintptr_t)mp & (align - 1)) == 0);
        check_owned(mp, default_alloc);
        memset(mp, 0x33, 200);
        n00b_interposed_free(mp);
    }
    printf("  [PASS] aligned_alloc + posix_memalign\n");

    // 7. free(NULL) / realloc(NULL, n) edge cases.
    n00b_interposed_free(nullptr);
    void *r0 = n00b_interposed_realloc(nullptr, 32);
    assert(r0 != nullptr);
    check_owned(r0, default_alloc);
    n00b_interposed_free(r0);
    printf("  [PASS] null_edge_cases\n");

    // 8. A pushed .libc_backing pool wins, here a hidden pool with inline
    //    headers and no external metadata.
    n00b_pool_t scoped_pool;
    n00b_allocator_t *scoped_alloc =
        n00b_pool_init(&scoped_pool,
                       .hidden            = true,
                       .inline_headers    = true,
                       .external_metadata = false,
                       .libc_backing      = true,
                       .name              = "interpose_scoped_inline");
    n00b_allocator_t *prev_alloc = n00b_push_current_allocator(scoped_alloc);
    void             *sp         = n00b_interposed_malloc(128);
    assert(sp != nullptr);
    check_owned(sp, scoped_alloc);
    memset(sp, 0xC7, 128);
    n00b_interposed_free(sp);

    void *sap = n00b_interposed_aligned_alloc(4096, 8192);
    assert(sap != nullptr);
    assert(((uintptr_t)sap & 4095) == 0);
    check_owned(sap, scoped_alloc);
    memset(sap, 0xD1, 8192);
    n00b_interposed_free(sap);
    n00b_restore_current_allocator(prev_alloc);
    n00b_allocator_destroy(scoped_alloc);
    printf("  [PASS] current_allocator_routes_to_inline_pool\n");

    // 9. Allocators reclaimed wholesale never receive libc memory: a hidden
    //    scratch arena that is reset per batch, a hidden pool without the
    //    opt-in, and the moving GC arena all fall back to user_pool.
    n00b_arena_t *scratch = n00b_new_arena(.use_gc         = false,
                                           .hidden         = true,
                                           .inline_headers = true,
                                           .name           = "interpose_scratch");
    prev_alloc = n00b_push_current_allocator((n00b_allocator_t *)scratch);
    char *kept = n00b_interposed_strdup("libc state outlives the batch");
    n00b_restore_current_allocator(prev_alloc);
    n00b_arena_reset(scratch);
    assert(strcmp(kept, "libc state outlives the batch") == 0);
    check_owned(kept, default_alloc);
    n00b_interposed_free(kept);
#if defined(__linux__)
    // glibc allocates the FILE through the interposed malloc, so it has to
    // survive a reset of the arena that was current when fopen ran.
    prev_alloc    = n00b_push_current_allocator((n00b_allocator_t *)scratch);
    FILE *devnull = fopen("/dev/null", "r");
    n00b_restore_current_allocator(prev_alloc);
    assert(devnull != nullptr);
    n00b_arena_reset(scratch);
    assert(fclose(devnull) == 0);
#endif
    n00b_allocator_destroy((n00b_allocator_t *)scratch);

    n00b_pool_t       plain_pool;
    n00b_allocator_t *plain_alloc =
        n00b_pool_init(&plain_pool, .hidden = true, .name = "interpose_plain_hidden");
    prev_alloc = n00b_push_current_allocator(plain_alloc);
    void *hp   = n00b_interposed_malloc(64);
    n00b_restore_current_allocator(prev_alloc);
    check_owned(hp, default_alloc);
    n00b_interposed_free(hp);
    n00b_allocator_destroy(plain_alloc);

    prev_alloc = n00b_push_current_allocator(n00b_default_allocator());
    void *gp   = n00b_interposed_malloc(64);
    n00b_restore_current_allocator(prev_alloc);
    check_owned(gp, default_alloc);
    n00b_interposed_free(gp);
    printf("  [PASS] scratch_allocators_fall_back_to_user_pool\n");

    // 10. Forgetting a page validates its slot. The range is never touched:
    //     a free inside it is dropped while it is recorded, and would reach
    //     libc free(), which aborts, once it is not.
    char    *fake  = (char *)((uintptr_t)1 << 40);
    char    *fake2 = fake + (1 << 20);
    uint32_t slot  = n00b_alloc_interpose_note_pages(fake, fake + 4096);
    assert(slot != 0);
    n00b_alloc_interpose_forget_pages(4096001, fake); // no chunk maps this slot
    n00b_alloc_interpose_forget_pages(slot, fake2);   // records another page
    n00b_interposed_free(fake + 128);

    n00b_alloc_interpose_forget_pages(slot, fake);
    n00b_alloc_interpose_forget_pages(slot, fake); // already retired
    uint32_t a = n00b_alloc_interpose_note_pages(fake, fake + 4096);
    uint32_t b = n00b_alloc_interpose_note_pages(fake2, fake2 + 4096);
    assert(a != 0 && b != 0 && a != b);
    n00b_interposed_free(fake + 128);
    n00b_interposed_free(fake2 + 128);
    n00b_alloc_interpose_forget_pages(a, fake);
    n00b_alloc_interpose_forget_pages(b, fake2);
    printf("  [PASS] forget_validates_slot\n");

    // 11. require() must not abort when interposition is active.
    n00b_require_alloc_interposition(r"alloc_interpose self-test");
    printf("  [PASS] require_ok\n");

    printf("All alloc interposition tests passed.\n");
    n00b_shutdown();
    return 0;
}

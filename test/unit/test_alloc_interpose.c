// Self-test for libc malloc-family interposition.
//
// Two things are verified:
//   1. The interposed allocator entry points are functional after n00b_init.
//   2. The shim routes allocations into n00b's current/default allocator with
//      correct
//      semantics. We call the n00b_interposed_* entry points DIRECTLY because
//      the portable QUIC/picotls mechanism is a compile-time redirect to these
//      functions; on macOS, dyld interpose tables do not interpose the image
//      that contains the table, so bare malloc() in this executable is not a
//      useful proof of shim behavior.

#include "n00b/alloc_interpose.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_interpose.h"
#include "core/runtime.h"
#include "core/mmaps.h"
#include "core/pool.h"

static void
check_owned(void *p, n00b_allocator_t *expected)
{
    n00b_allocator_opt_t a = n00b_mem_get_allocator(p);
    assert(n00b_option_is_set(a));
    assert(n00b_option_get(a) == expected);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    setbuf(stdout, NULL);
    printf("Running alloc interposition tests...\n");

    // 1. Install mechanism is detectable.
    assert(n00b_alloc_interposition_active());
    printf("  [PASS] interposition_active\n");

    // 2. malloc routes into the default allocator when no current allocator
    //    is pushed; counter advances; usable size OK.
    n00b_allocator_t *default_alloc = n00b_default_allocator();
    uint64_t h0 = n00b_alloc_interpose_hits();
    void    *p  = n00b_interposed_malloc(100);
    assert(p != nullptr);
    assert(n00b_alloc_interpose_hits() > h0);
    check_owned(p, default_alloc);
    memset(p, 0xAB, 100);
    assert(n00b_interposed_malloc_usable_size(p) >= 100);
    n00b_interposed_free(p);
    printf("  [PASS] malloc_routes_to_default_allocator\n");

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

    // 8. Pushed allocators win, including inline-header/no-external-metadata
    //    pools used to isolate picotls session allocations.
    n00b_pool_t scoped_pool;
    n00b_allocator_t *scoped_alloc =
        n00b_pool_init(&scoped_pool,
                       .hidden            = true,
                       .inline_headers    = true,
                       .external_metadata = false,
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

    // 9. require() must not abort when interposition is active.
    n00b_require_alloc_interposition(r"alloc_interpose self-test");
    printf("  [PASS] require_ok\n");

    printf("All alloc interposition tests passed.\n");
    return 0;
}

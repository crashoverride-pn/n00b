#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/hash.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/static_objects.h"

// Test fixtures for D-066 (Phase 3a): verify that n00b_hash() reads the
// cached_hash slot from n00b_alloc_range_t for descriptor-backed static
// objects, and that the runtime recompute path for static-range hits
// does NOT mutate that slot.

#define STATIC_HASH_A_TINFO UINT64_C(0x5354484153480001)
#define STATIC_HASH_B_TINFO UINT64_C(0x5354484153480002)
#define STATIC_HASH_A_ID    UINT64_C(0x5348413001)
#define STATIC_HASH_B_ID    UINT64_C(0x5348423002)

// 128-bit cached hash for object A. The literal is built as
// ((hi << 64) | lo) because _BitInt(128) is a plain integer type and
// 128-bit integer constants are not directly expressible in source.
#define STATIC_HASH_A_HI UINT64_C(0xDEADBEEFCAFEBABE)
#define STATIC_HASH_A_LO UINT64_C(0x0123456789ABCDEF)
#define STATIC_HASH_A_VALUE                                                 \
    ((((n00b_uint128_t)STATIC_HASH_A_HI) << 64)                             \
     | (n00b_uint128_t)STATIC_HASH_A_LO)

static uint64_t static_hash_object_a[4];
static uint64_t static_hash_object_b[4];

// Object A: descriptor with an explicit non-zero cached hash.
N00B_STATIC_OBJECT_DESCRIPTOR_WITH_HASH(n00b_test_static_hash_a_desc,
                                        &static_hash_object_a,
                                        sizeof(static_hash_object_a),
                                        STATIC_HASH_A_TINFO,
                                        N00B_STATIC_OBJECT_F_MUTABLE,
                                        N00B_GC_SCAN_KIND_NONE,
                                        nullptr,
                                        nullptr,
                                        STATIC_HASH_A_ID,
                                        STATIC_HASH_A_VALUE);

// Object B: descriptor with the default cached_hash (zero / "uncached").
N00B_STATIC_OBJECT_DESCRIPTOR_FOR(n00b_test_static_hash_b_desc,
                                  static_hash_object_b,
                                  STATIC_HASH_B_TINFO,
                                  N00B_STATIC_OBJECT_F_MUTABLE,
                                  N00B_GC_SCAN_KIND_NONE,
                                  nullptr,
                                  nullptr,
                                  STATIC_HASH_B_ID);

static n00b_alloc_range_t *
lookup_range(void *addr)
{
    auto opt = n00b_mmap_range_by_address(addr);
    assert(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static void
test_cached_hash_read_path(void)
{
    n00b_alloc_range_t *range_a = lookup_range(&static_hash_object_a[0]);
    assert(range_a->kind == n00b_mmap_static);
    assert(range_a->object_id == STATIC_HASH_A_ID);
    assert(range_a->tinfo == STATIC_HASH_A_TINFO);

    // The descriptor's cached_hash should have been copied into the
    // runtime range record during static-range registration.
    assert(range_a->cached_hash == STATIC_HASH_A_VALUE);

    // n00b_hash() must return the cached value verbatim.
    n00b_uint128_t observed = n00b_hash(&static_hash_object_a[0], nullptr);
    assert(observed == STATIC_HASH_A_VALUE);

    printf("  [PASS] static_hash_cached_read_path\n");
}

static void
test_uncached_recompute_path(void)
{
    n00b_alloc_range_t *range_b = lookup_range(&static_hash_object_b[0]);
    assert(range_b->kind == n00b_mmap_static);
    assert(range_b->object_id == STATIC_HASH_B_ID);
    assert(range_b->tinfo == STATIC_HASH_B_TINFO);

    // Object B has no descriptor-supplied cached hash; the runtime
    // range record's cached_hash must be the "uncached" sentinel.
    assert(range_b->cached_hash == (n00b_uint128_t)0);

    // n00b_hash() falls through to recompute via n00b_hash_word (no
    // vtable for this synthetic tinfo). The result must be non-zero
    // for the pointer we pass.
    n00b_uint128_t observed = n00b_hash(&static_hash_object_b[0], nullptr);
    assert(observed != (n00b_uint128_t)0);

    // The recompute must equal the explicit n00b_hash_word value for
    // the same pointer (no vtable / caller-supplied fn means
    // n00b_hash() uses n00b_hash_word as the default).
    n00b_uint128_t expected = n00b_hash_word(&static_hash_object_b[0]);
    assert(observed == expected);

    // Sanity: the recompute must differ from object A's cached hash so
    // we know we did not accidentally pick up the wrong slot.
    assert(observed != STATIC_HASH_A_VALUE);

    // Critically, the recompute must NOT cache-back to the static
    // range record. The cached_hash slot must remain zero so the next
    // build-time helper write (Phase 3b) is unambiguous.
    n00b_alloc_range_t *range_b_after = lookup_range(&static_hash_object_b[0]);
    assert(range_b_after == range_b);
    assert(range_b_after->cached_hash == (n00b_uint128_t)0);

    // Calling n00b_hash() again must still recompute and still not
    // mutate the slot.
    n00b_uint128_t observed_again = n00b_hash(&static_hash_object_b[0],
                                              nullptr);
    assert(observed_again == observed);
    assert(range_b_after->cached_hash == (n00b_uint128_t)0);

    printf("  [PASS] static_hash_uncached_recompute_path\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running static-hash tests...\n");

    test_cached_hash_read_path();
    test_uncached_recompute_path();

    printf("All static-hash tests passed.\n");
    n00b_shutdown();
    return 0;
}

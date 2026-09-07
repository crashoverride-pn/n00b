#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/hash.h"

// ============================================================================
// 1. Determinism — same input produces same output across calls
// ============================================================================

static void
test_determinism(void)
{
    uint64_t       val = 0xDEADBEEF;
    n00b_uint128_t h1  = n00b_hash_word((void *)(uintptr_t)val);
    n00b_uint128_t h2  = n00b_hash_word((void *)(uintptr_t)val);

    assert(h1 == h2);

    n00b_uint128_t h3 = n00b_hash_cstring("hello world");
    n00b_uint128_t h4 = n00b_hash_cstring("hello world");

    assert(h3 == h4);

    printf("  [PASS] determinism\n");
}

// ============================================================================
// 2. Word distinct — different word inputs produce different hashes
// ============================================================================

static void
test_word_distinct(void)
{
    n00b_uint128_t h1 = n00b_hash_word((void *)1UL);
    n00b_uint128_t h2 = n00b_hash_word((void *)2UL);
    n00b_uint128_t h3 = n00b_hash_word((void *)3UL);
    n00b_uint128_t h4 = n00b_hash_word((void *)0xFFFFFFFFUL);

    assert(h1 != h2);
    assert(h1 != h3);
    assert(h1 != h4);
    assert(h2 != h3);
    assert(h2 != h4);
    assert(h3 != h4);

    printf("  [PASS] word_distinct\n");
}

// ============================================================================
// 3. C-string distinct — different strings produce different hashes
// ============================================================================

static void
test_cstring_distinct(void)
{
    n00b_uint128_t h1 = n00b_hash_cstring("alpha");
    n00b_uint128_t h2 = n00b_hash_cstring("beta");
    n00b_uint128_t h3 = n00b_hash_cstring("gamma");
    n00b_uint128_t h4 = n00b_hash_cstring("");

    assert(h1 != h2);
    assert(h1 != h3);
    assert(h1 != h4);
    assert(h2 != h3);
    assert(h2 != h4);
    assert(h3 != h4);

    printf("  [PASS] cstring_distinct\n");
}

// ============================================================================
// 4. C-string content — identical strings at different addresses hash equal
// ============================================================================

static void
test_cstring_content(void)
{
    char buf1[64];
    char buf2[64];

    strcpy(buf1, "same content here");
    strcpy(buf2, "same content here");

    // Ensure different addresses
    assert((void *)buf1 != (void *)buf2);

    n00b_uint128_t h1 = n00b_hash_cstring(buf1);
    n00b_uint128_t h2 = n00b_hash_cstring(buf2);

    assert(h1 == h2);

    printf("  [PASS] cstring_content\n");
}

// ============================================================================
// 5. Distribution — 1000 sequential ints; no bucket > 3x average across 64
// ============================================================================

static void
test_distribution(void)
{
    const int num_values  = 1000;
    const int num_buckets = 64;
    int       buckets[64] = {};

    for (int i = 0; i < num_values; i++) {
        n00b_uint128_t h   = n00b_hash_word((void *)(uintptr_t)i);
        uint64_t       low = (uint64_t)h;
        int            bix = low % num_buckets;
        buckets[bix]++;
    }

    double avg       = (double)num_values / num_buckets;
    int    threshold = (int)(avg * 3.0);

    for (int i = 0; i < num_buckets; i++) {
        assert(buckets[i] <= threshold);
    }

    printf("  [PASS] distribution\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running hash tests...\n");

    test_determinism();
    test_word_distinct();
    test_cstring_distinct();
    test_cstring_content();
    test_distribution();

    printf("All hash tests passed.\n");
    n00b_shutdown();
    return 0;
}

#include "test_unicode_helpers.h"
#include "logic/clpfd_domain.h"

// ============================================================================
// Construction
// ============================================================================

TEST(test_interval_basic)
{
    n00b_csp_domain_t d = n00b_csp_dom_range(1, 10);

    ASSERT_EQ(n00b_csp_dom_min(&d), 1);
    ASSERT_EQ(n00b_csp_dom_max(&d), 10);
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 10);
    ASSERT(!n00b_csp_dom_is_empty(&d));
    ASSERT(!n00b_csp_dom_is_singleton(&d));
    ASSERT(n00b_csp_dom_contains(&d, 1));
    ASSERT(n00b_csp_dom_contains(&d, 5));
    ASSERT(n00b_csp_dom_contains(&d, 10));
    ASSERT(!n00b_csp_dom_contains(&d, 0));
    ASSERT(!n00b_csp_dom_contains(&d, 11));

    n00b_csp_dom_free(&d);
}

TEST(test_singleton)
{
    n00b_csp_domain_t d = n00b_csp_dom_singleton(42);

    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 1);
    ASSERT(n00b_csp_dom_is_singleton(&d));
    ASSERT_EQ(n00b_csp_dom_min(&d), 42);
    ASSERT_EQ(n00b_csp_dom_max(&d), 42);
    ASSERT(n00b_csp_dom_contains(&d, 42));
    ASSERT(!n00b_csp_dom_contains(&d, 41));

    n00b_csp_dom_free(&d);
}

TEST(test_empty)
{
    n00b_csp_domain_t d = n00b_csp_dom_empty();

    ASSERT(n00b_csp_dom_is_empty(&d));
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 0);
    ASSERT(!n00b_csp_dom_contains(&d, 0));

    n00b_csp_dom_free(&d);

    // Invalid range should also be empty.
    n00b_csp_domain_t d2 = n00b_csp_dom_range(10, 5);
    ASSERT(n00b_csp_dom_is_empty(&d2));
    n00b_csp_dom_free(&d2);
}

// ============================================================================
// from_values construction
// ============================================================================

TEST(test_from_values_contiguous)
{
    int64_t vals[] = {3, 1, 2, 4, 5};
    n00b_csp_domain_t d = n00b_csp_dom_from_values(vals, 5);

    // Should be promoted to interval.
    ASSERT(n00b_variant_is_type(d, n00b_csp_dom_interval_t));
    ASSERT_EQ(n00b_csp_dom_min(&d), 1);
    ASSERT_EQ(n00b_csp_dom_max(&d), 5);
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 5);

    n00b_csp_dom_free(&d);
}

TEST(test_from_values_sparse)
{
    int64_t vals[] = {1, 5, 3};
    n00b_csp_domain_t d = n00b_csp_dom_from_values(vals, 3);

    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 3);
    ASSERT(n00b_csp_dom_contains(&d, 1));
    ASSERT(n00b_csp_dom_contains(&d, 3));
    ASSERT(n00b_csp_dom_contains(&d, 5));
    ASSERT(!n00b_csp_dom_contains(&d, 2));
    ASSERT(!n00b_csp_dom_contains(&d, 4));

    n00b_csp_dom_free(&d);
}

TEST(test_from_values_dedup)
{
    int64_t vals[] = {3, 1, 3, 1, 5, 5};
    n00b_csp_domain_t d = n00b_csp_dom_from_values(vals, 6);

    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 3);

    n00b_csp_dom_free(&d);
}

// ============================================================================
// Clone
// ============================================================================

TEST(test_clone)
{
    n00b_csp_domain_t d = n00b_csp_dom_range(1, 100);
    n00b_csp_domain_t c = n00b_csp_dom_clone(&d);

    ASSERT_EQ(n00b_csp_dom_min(&c), 1);
    ASSERT_EQ(n00b_csp_dom_max(&c), 100);

    n00b_csp_dom_free(&d);
    n00b_csp_dom_free(&c);

    // Clone a sparse domain.
    int64_t vals[] = {10, 20, 30};
    d = n00b_csp_dom_from_values(vals, 3);
    c = n00b_csp_dom_clone(&d);

    ASSERT_EQ((int64_t)n00b_csp_dom_size(&c), 3);
    ASSERT(n00b_csp_dom_contains(&c, 20));

    n00b_csp_dom_free(&d);
    n00b_csp_dom_free(&c);
}

// ============================================================================
// Intersection
// ============================================================================

TEST(test_intersect_intervals)
{
    n00b_csp_domain_t a = n00b_csp_dom_range(1, 10);
    n00b_csp_domain_t b = n00b_csp_dom_range(5, 15);
    bool changed = n00b_csp_dom_intersect(&a, &b);

    ASSERT(changed);
    ASSERT_EQ(n00b_csp_dom_min(&a), 5);
    ASSERT_EQ(n00b_csp_dom_max(&a), 10);

    n00b_csp_dom_free(&a);
    n00b_csp_dom_free(&b);
}

TEST(test_intersect_disjoint)
{
    n00b_csp_domain_t a = n00b_csp_dom_range(1, 5);
    n00b_csp_domain_t b = n00b_csp_dom_range(10, 20);
    bool changed = n00b_csp_dom_intersect(&a, &b);

    ASSERT(changed);
    ASSERT(n00b_csp_dom_is_empty(&a));

    n00b_csp_dom_free(&a);
    n00b_csp_dom_free(&b);
}

TEST(test_intersect_no_change)
{
    n00b_csp_domain_t a = n00b_csp_dom_range(3, 7);
    n00b_csp_domain_t b = n00b_csp_dom_range(1, 10);
    bool changed = n00b_csp_dom_intersect(&a, &b);

    ASSERT(!changed);
    ASSERT_EQ(n00b_csp_dom_min(&a), 3);
    ASSERT_EQ(n00b_csp_dom_max(&a), 7);

    n00b_csp_dom_free(&a);
    n00b_csp_dom_free(&b);
}

// ============================================================================
// Remove value
// ============================================================================

TEST(test_remove_value)
{
    n00b_csp_domain_t d = n00b_csp_dom_range(1, 5);

    // Remove from endpoint.
    ASSERT(n00b_csp_dom_remove_value(&d, 1));
    ASSERT_EQ(n00b_csp_dom_min(&d), 2);

    // Remove from other endpoint.
    ASSERT(n00b_csp_dom_remove_value(&d, 5));
    ASSERT_EQ(n00b_csp_dom_max(&d), 4);

    // Remove from middle (promotes to bitset).
    ASSERT(n00b_csp_dom_remove_value(&d, 3));
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 2);
    ASSERT(n00b_csp_dom_contains(&d, 2));
    ASSERT(n00b_csp_dom_contains(&d, 4));
    ASSERT(!n00b_csp_dom_contains(&d, 3));

    // Remove non-existent.
    ASSERT(!n00b_csp_dom_remove_value(&d, 99));

    n00b_csp_dom_free(&d);
}

TEST(test_remove_to_empty)
{
    n00b_csp_domain_t d = n00b_csp_dom_singleton(42);

    ASSERT(n00b_csp_dom_remove_value(&d, 42));
    ASSERT(n00b_csp_dom_is_empty(&d));

    n00b_csp_dom_free(&d);
}

// ============================================================================
// Restrict min/max
// ============================================================================

TEST(test_restrict_min)
{
    n00b_csp_domain_t d = n00b_csp_dom_range(1, 10);

    ASSERT(n00b_csp_dom_restrict_min(&d, 5));
    ASSERT_EQ(n00b_csp_dom_min(&d), 5);
    ASSERT_EQ(n00b_csp_dom_max(&d), 10);

    ASSERT(!n00b_csp_dom_restrict_min(&d, 3));

    ASSERT(n00b_csp_dom_restrict_min(&d, 11));
    ASSERT(n00b_csp_dom_is_empty(&d));

    n00b_csp_dom_free(&d);
}

TEST(test_restrict_max)
{
    n00b_csp_domain_t d = n00b_csp_dom_range(1, 10);

    ASSERT(n00b_csp_dom_restrict_max(&d, 7));
    ASSERT_EQ(n00b_csp_dom_min(&d), 1);
    ASSERT_EQ(n00b_csp_dom_max(&d), 7);

    ASSERT(!n00b_csp_dom_restrict_max(&d, 10));

    ASSERT(n00b_csp_dom_restrict_max(&d, 0));
    ASSERT(n00b_csp_dom_is_empty(&d));

    n00b_csp_dom_free(&d);
}

// ============================================================================
// Bitset-specific tests
// ============================================================================

TEST(test_bitset_intersect)
{
    // Create two bitset domains that overlap partially.
    int64_t a_vals[] = {1, 3, 5, 7};
    int64_t b_vals[] = {3, 5, 8, 10};

    n00b_csp_domain_t a = n00b_csp_dom_from_values(a_vals, 4);
    n00b_csp_domain_t b = n00b_csp_dom_from_values(b_vals, 4);

    bool changed = n00b_csp_dom_intersect(&a, &b);

    ASSERT(changed);
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&a), 2);
    ASSERT(n00b_csp_dom_contains(&a, 3));
    ASSERT(n00b_csp_dom_contains(&a, 5));
    ASSERT(!n00b_csp_dom_contains(&a, 1));

    n00b_csp_dom_free(&a);
    n00b_csp_dom_free(&b);
}

TEST(test_bitset_restrict)
{
    int64_t vals[] = {2, 4, 6, 8, 10};
    n00b_csp_domain_t d = n00b_csp_dom_from_values(vals, 5);

    ASSERT(n00b_csp_dom_restrict_min(&d, 5));
    ASSERT_EQ(n00b_csp_dom_min(&d), 6);
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 3);

    ASSERT(n00b_csp_dom_restrict_max(&d, 9));
    ASSERT_EQ(n00b_csp_dom_max(&d), 8);
    ASSERT_EQ((int64_t)n00b_csp_dom_size(&d), 2);

    n00b_csp_dom_free(&d);
}

// ============================================================================
// Test runner
// ============================================================================

static void
run_tests(void)
{
    RUN_TEST(test_interval_basic);
    RUN_TEST(test_singleton);
    RUN_TEST(test_empty);
    RUN_TEST(test_from_values_contiguous);
    RUN_TEST(test_from_values_sparse);
    RUN_TEST(test_from_values_dedup);
    RUN_TEST(test_clone);
    RUN_TEST(test_intersect_intervals);
    RUN_TEST(test_intersect_disjoint);
    RUN_TEST(test_intersect_no_change);
    RUN_TEST(test_remove_value);
    RUN_TEST(test_remove_to_empty);
    RUN_TEST(test_restrict_min);
    RUN_TEST(test_restrict_max);
    RUN_TEST(test_bitset_intersect);
    RUN_TEST(test_bitset_restrict);
}

TEST_MAIN()

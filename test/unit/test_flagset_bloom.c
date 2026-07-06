#include "n00b.h"
#include "adt/bloom.h"
#include "adt/flagset.h"
#include "core/runtime.h"
#include "util/assert.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static void
test_flagset_lock_defaults(void)
{
    n00b_flagset_t *locked = n00b_flagset_new(.length = 2);
    CHECK(locked->lock != nullptr);

    n00b_flagset_t *private = n00b_flagset_new(.length = 2, .locked = false);
    CHECK(private->lock == nullptr);

    n00b_flagset_set_index(locked, 1, true);
    n00b_flagset_set_index(private, 1, true);
    CHECK(n00b_flagset_index(locked, 1));
    CHECK(n00b_flagset_index(private, 1));
    CHECK(n00b_flagset_test_and_set_index(locked, 1, true));
    CHECK(!n00b_flagset_test_and_set_index(locked, 3, true));
    CHECK(n00b_flagset_index(locked, 3));
    CHECK(n00b_flagset_test_and_set_index(locked, 3, false));
    CHECK(!n00b_flagset_index(locked, 3));
}

static void
test_flagset_resize_and_index(void)
{
    n00b_flagset_t *flags = n00b_flagset_new(.length = 3);
    CHECK(n00b_flagset_len(flags) == 3);
    CHECK(!n00b_flagset_index(flags, 1));

    n00b_flagset_set_index(flags, 1, true);
    CHECK(n00b_flagset_index(flags, 1));
    CHECK(n00b_flagset_index(flags, -2));

    CHECK(!n00b_flagset_index(flags, 130));
    CHECK(n00b_flagset_len(flags) == 3);

    n00b_flagset_set_index(flags, 130, true);
    CHECK(n00b_flagset_len(flags) == 131);
    CHECK(n00b_flagset_index(flags, 130));
    CHECK(n00b_flagset_count(flags) == 2);

    n00b_flagset_set_index(flags, 130, false);
    CHECK(!n00b_flagset_index(flags, 130));
    CHECK(n00b_flagset_count(flags) == 1);
}

static void
test_flagset_set_operations(void)
{
    n00b_flagset_t *a = n00b_flagset_new(.length = 8);
    n00b_flagset_t *b = n00b_flagset_new(.length = 72);
    n00b_flagset_set_index(a, 1, true);
    n00b_flagset_set_index(a, 7, true);
    n00b_flagset_set_index(b, 7, true);
    n00b_flagset_set_index(b, 70, true);

    n00b_flagset_t *sum = n00b_flagset_add(a, b);
    CHECK(n00b_flagset_index(sum, 1));
    CHECK(n00b_flagset_index(sum, 7));
    CHECK(n00b_flagset_index(sum, 70));
    CHECK(n00b_flagset_count(sum) == 3);

    n00b_flagset_t *intersection = n00b_flagset_test(a, b);
    CHECK(!n00b_flagset_index(intersection, 1));
    CHECK(n00b_flagset_index(intersection, 7));
    CHECK(!n00b_flagset_index(intersection, 70));
    CHECK(n00b_flagset_count(intersection) == 1);

    n00b_flagset_t *diff = n00b_flagset_sub(sum, b);
    CHECK(n00b_flagset_index(diff, 1));
    CHECK(!n00b_flagset_index(diff, 7));
    CHECK(!n00b_flagset_index(diff, 70));

    n00b_flagset_t *xor_set = n00b_flagset_xor(a, b);
    CHECK(n00b_flagset_index(xor_set, 1));
    CHECK(!n00b_flagset_index(xor_set, 7));
    CHECK(n00b_flagset_index(xor_set, 70));

    n00b_flagset_t *copy = n00b_flagset_copy(a);
    CHECK(n00b_flagset_eq(a, copy));
    CHECK(!n00b_flagset_eq(a, b));
}

static void
test_flagset_next_set_and_invert(void)
{
    n00b_flagset_t *flags = n00b_flagset_new(.length = 10);
    n00b_flagset_set_index(flags, 2, true);
    n00b_flagset_set_index(flags, 9, true);

    uint64_t ix = 0;
    CHECK(n00b_flagset_next_set(flags, 0, &ix));
    CHECK(ix == 2);
    CHECK(n00b_flagset_next_set(flags, 3, &ix));
    CHECK(ix == 9);
    CHECK(!n00b_flagset_next_set(flags, 10, &ix));

    n00b_flagset_t *inverted = n00b_flagset_invert(flags);
    CHECK(n00b_flagset_len(inverted) == 10);
    CHECK(!n00b_flagset_index(inverted, 2));
    CHECK(!n00b_flagset_index(inverted, 9));
    CHECK(n00b_flagset_count(inverted) == 8);
}

static void
test_bloom_basic_membership(void)
{
    n00b_bloom_t *bloom = n00b_bloom_new(.set_size = 32,
                                         .false_pct = 0.001);
    n00b_string_t *alpha = r"alpha";
    n00b_string_t *beta  = r"beta";

    CHECK(!n00b_bloom_contains(bloom, alpha));
    n00b_bloom_add(bloom, alpha);
    n00b_bloom_add(bloom, beta);
    CHECK(n00b_bloom_contains(bloom, alpha));
    CHECK(n00b_bloom_contains(bloom, beta));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_flagset_lock_defaults();
    test_flagset_resize_and_index();
    test_flagset_set_operations();
    test_flagset_next_set_and_invert();
    test_bloom_basic_membership();

    n00b_shutdown();
    return 0;
}

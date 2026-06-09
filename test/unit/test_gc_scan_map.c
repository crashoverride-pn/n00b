#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/gc_map.h"

// ============================================================================
// Test fixture: a bitmap built on the caller's stack.
// ============================================================================

#define MK_MAP(name, num)                                              \
    uint64_t name##_bits[(((num) + 63) >> 6)] = {0};                   \
    n00b_gc_map_t name = {                                             \
        .user_ptr  = NULL,                                             \
        .num_words = (num),                                            \
        .bitmap    = name##_bits,                                      \
    }

// ============================================================================
// 1. mark / unmark / is_set
// ============================================================================

static void
test_mark_unmark_single(void)
{
    MK_MAP(m, 128);

    assert(!n00b_gc_map_is_set(&m, 7));
    n00b_gc_map_mark(&m, 7);
    assert(n00b_gc_map_is_set(&m, 7));
    n00b_gc_map_unmark(&m, 7);
    assert(!n00b_gc_map_is_set(&m, 7));

    // word-boundary cases.
    n00b_gc_map_mark(&m, 63);
    n00b_gc_map_mark(&m, 64);
    n00b_gc_map_mark(&m, 65);
    assert(n00b_gc_map_is_set(&m, 63));
    assert(n00b_gc_map_is_set(&m, 64));
    assert(n00b_gc_map_is_set(&m, 65));
    assert(!n00b_gc_map_is_set(&m, 62));
    assert(!n00b_gc_map_is_set(&m, 66));

    printf("  [PASS] mark_unmark_single\n");
}

// ============================================================================
// 2. mark_range — basic case
// ============================================================================

static void
test_mark_range_basic(void)
{
    MK_MAP(m, 64);

    n00b_gc_map_mark_range(&m, 5, 20);

    for (uint64_t i = 0; i < 5; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 5; i < 25; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 25; i < 64; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }

    printf("  [PASS] mark_range_basic\n");
}

// ============================================================================
// 3. mark_range — word-aligned full-word range
// ============================================================================

static void
test_mark_range_aligned(void)
{
    MK_MAP(m, 192);

    n00b_gc_map_mark_range(&m, 64, 64);

    // Bits 0..63 clear, 64..127 set, 128..191 clear.
    for (uint64_t i = 0; i < 64; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 64; i < 128; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 128; i < 192; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }

    // Bitmap word #1 should be all-ones.
    assert(m_bits[1] == UINT64_MAX);
    assert(m_bits[0] == 0);
    assert(m_bits[2] == 0);

    printf("  [PASS] mark_range_aligned\n");
}

// ============================================================================
// 4. mark_range — straddling a word boundary
// ============================================================================

static void
test_mark_range_straddling(void)
{
    MK_MAP(m, 128);

    n00b_gc_map_mark_range(&m, 60, 10);

    for (uint64_t i = 0; i < 60; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 60; i < 70; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 70; i < 128; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }

    printf("  [PASS] mark_range_straddling\n");
}

// ============================================================================
// 5. unmark_range — mirror of mark_range
// ============================================================================

static void
test_unmark_range(void)
{
    MK_MAP(m, 128);

    n00b_gc_map_mark_all(&m);
    n00b_gc_map_unmark_range(&m, 10, 20);

    for (uint64_t i = 0; i < 10; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 10; i < 30; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }
    for (uint64_t i = 30; i < 128; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }

    printf("  [PASS] unmark_range\n");
}

// ============================================================================
// 6. mark_all on a non-64-multiple length — out-of-range bits stay zero
// ============================================================================

static void
test_mark_all_then_unmark(void)
{
    MK_MAP(m, 70);

    n00b_gc_map_mark_all(&m);

    // Bits 0..69 set.
    for (uint64_t i = 0; i < 70; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }

    // Bits 70..127 (the high half of bitmap word 1, beyond num_words)
    // must remain zero — the collector relies on that to avoid spurious
    // pointer visits past the end of the allocation.
    uint64_t expected_word1 = (UINT64_C(1) << (70 - 64)) - 1; // bits 0..5 set
    assert(m_bits[0] == UINT64_MAX);
    assert(m_bits[1] == expected_word1);

    n00b_gc_map_unmark_all(&m);
    for (uint64_t i = 0; i < 70; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }
    assert(m_bits[0] == 0);
    assert(m_bits[1] == 0);

    printf("  [PASS] mark_all_then_unmark\n");
}

// ============================================================================
// 7. mark_stride
// ============================================================================

static void
test_mark_stride(void)
{
    MK_MAP(m, 64);

    n00b_gc_map_mark_stride(&m, 0, 4, 8);

    for (uint64_t i = 0; i < 64; ++i) {
        bool expected = (i < 32) && (i % 4 == 0);
        assert(n00b_gc_map_is_set(&m, i) == expected);
    }

    printf("  [PASS] mark_stride\n");
}

// ============================================================================
// 8. mark_every_other from offset 0
// ============================================================================

static void
test_mark_every_other(void)
{
    MK_MAP(m, 16);

    n00b_gc_map_mark_every_other(&m, 0);

    for (uint64_t i = 0; i < 16; ++i) {
        bool expected = (i % 2 == 0);
        assert(n00b_gc_map_is_set(&m, i) == expected);
    }

    printf("  [PASS] mark_every_other\n");
}

// ============================================================================
// 9. mark_every_other from offset 1
// ============================================================================

static void
test_mark_every_other_offset_1(void)
{
    MK_MAP(m, 16);

    n00b_gc_map_mark_every_other(&m, 1);

    for (uint64_t i = 0; i < 16; ++i) {
        bool expected = (i % 2 == 1);
        assert(n00b_gc_map_is_set(&m, i) == expected);
    }

    printf("  [PASS] mark_every_other_offset_1\n");
}

// ============================================================================
// 10. word_count rounding
// ============================================================================

static void
test_bitmap_size_calc(void)
{
    assert(n00b_gc_map_word_count(0)   == 0);
    assert(n00b_gc_map_word_count(1)   == 1);
    assert(n00b_gc_map_word_count(63)  == 1);
    assert(n00b_gc_map_word_count(64)  == 1);
    assert(n00b_gc_map_word_count(65)  == 2);
    assert(n00b_gc_map_word_count(70)  == 2);
    assert(n00b_gc_map_word_count(128) == 2);
    assert(n00b_gc_map_word_count(129) == 3);

    printf("  [PASS] bitmap_size_calc\n");
}

// ============================================================================
// 11. cb_all — every bit in [0, num_words) set
// ============================================================================

static void
test_cb_all(void)
{
    MK_MAP(m, 70);

    n00b_gc_scan_cb_all(&m, NULL);

    for (uint64_t i = 0; i < 70; ++i) {
        assert(n00b_gc_map_is_set(&m, i));
    }
    // Out-of-range bits in the trailing partial word stay zero.
    uint64_t expected_word1 = (UINT64_C(1) << (70 - 64)) - 1;
    assert(m_bits[1] == expected_word1);

    printf("  [PASS] cb_all\n");
}

// ============================================================================
// 12. cb_none — nothing set
// ============================================================================

static void
test_cb_none(void)
{
    MK_MAP(m, 64);

    n00b_gc_scan_cb_none(&m, NULL);

    for (uint64_t i = 0; i < 64; ++i) {
        assert(!n00b_gc_map_is_set(&m, i));
    }
    assert(m_bits[0] == 0);

    printf("  [PASS] cb_none\n");
}

// ============================================================================
// 13. cb_every_other — bits 0, 2, 4, …
// ============================================================================

static void
test_cb_every_other(void)
{
    MK_MAP(m, 16);

    n00b_gc_scan_cb_every_other(&m, NULL);

    for (uint64_t i = 0; i < 16; ++i) {
        bool expected = (i % 2 == 0);
        assert(n00b_gc_map_is_set(&m, i) == expected);
    }

    printf("  [PASS] cb_every_other\n");
}

// ============================================================================
// 14. cb_struct_field — {stride=4, offset=2, count=8} → {2,6,10,14,…,30}
// ============================================================================

static void
test_cb_struct_field(void)
{
    MK_MAP(m, 64);

    n00b_gc_struct_array_t desc = {.stride = 4, .offset = 2, .count = 8};
    n00b_gc_scan_cb_struct_field(&m, &desc);

    uint64_t expected_bits[] = {2, 6, 10, 14, 18, 22, 26, 30};
    for (uint64_t i = 0; i < 64; ++i) {
        bool expected = false;
        for (size_t e = 0; e < sizeof(expected_bits) / sizeof(expected_bits[0]); ++e) {
            if (expected_bits[e] == i) {
                expected = true;
                break;
            }
        }
        assert(n00b_gc_map_is_set(&m, i) == expected);
    }

    printf("  [PASS] cb_struct_field\n");
}

// ============================================================================
// 15. cb_struct_layout — stride=5, offsets={1,4}, count=3
//     → {1,4,6,9,11,14}
// ============================================================================

static void
test_cb_struct_layout(void)
{
    MK_MAP(m, 16);
    uint64_t offsets[] = {1, 4};
    n00b_gc_struct_layout_t desc = {
        .stride       = 5,
        .count        = 3,
        .offset_count = 2,
        .offsets      = offsets,
    };

    n00b_gc_scan_cb_struct_layout(&m, &desc);

    for (uint64_t i = 0; i < 16; i++) {
        bool expected = i == 1 || i == 4 || i == 6 || i == 9 || i == 11 || i == 14;
        assert(n00b_gc_map_is_set(&m, i) == expected);
    }

    printf("  [PASS] cb_struct_layout\n");
}

// ============================================================================
// Discriminated-union (n00b_variant_t) scan: the value word is a heap pointer
// only when the element's selector names a pointer alternative.
// ============================================================================

static void
test_cb_variant(void)
{
    static const uint64_t PTR_HASH = 0xABCDEF0123456789ULL;
    uint64_t              ptr_hashes[] = {PTR_HASH};
    n00b_gc_variant_field_t var        = {
               .selector_offset = 0,
               .value_offset    = 1,
               .ptr_hash_count  = 1,
               .ptr_hashes      = ptr_hashes,
    };
    n00b_gc_struct_layout_t layout = {
        .stride        = 2,
        .count         = 1,
        .offset_count  = 0,
        .offsets       = NULL,
        .variant_count = 1,
        .variants      = &var,
    };

    // Pointer alternative active -> value word (1) marked; selector never is.
    {
        uint64_t obj[2] = {PTR_HASH, 0x1234};
        MK_MAP(m, 2);
        m.user_ptr = obj;
        n00b_gc_scan_cb_type_layout(&m, &layout);
        assert(!n00b_gc_map_is_set(&m, 0));
        assert(n00b_gc_map_is_set(&m, 1));
    }

    // Scalar alternative active (selector not in table) -> value not marked.
    {
        uint64_t obj[2] = {0x999, 0x1234};
        MK_MAP(m, 2);
        m.user_ptr = obj;
        n00b_gc_scan_cb_type_layout(&m, &layout);
        assert(!n00b_gc_map_is_set(&m, 1));
    }

    // Unset variant (selector == 0) -> value not marked.
    {
        uint64_t obj[2] = {0, 0x1234};
        MK_MAP(m, 2);
        m.user_ptr = obj;
        n00b_gc_scan_cb_type_layout(&m, &layout);
        assert(!n00b_gc_map_is_set(&m, 1));
    }

    printf("  [PASS] cb_variant\n");
}

static void
test_cb_variant_embedded_and_array(void)
{
    static const uint64_t PTR_HASH = 0xABCDEF0123456789ULL;
    uint64_t              ptr_hashes[] = {PTR_HASH};
    // Element: word 0 = head (unconditional ptr), word 1 = selector,
    // word 2 = variant value.
    n00b_gc_variant_field_t var = {
        .selector_offset = 1,
        .value_offset    = 2,
        .ptr_hash_count  = 1,
        .ptr_hashes      = ptr_hashes,
    };
    uint64_t                flat[] = {0};
    n00b_gc_struct_layout_t layout = {
        .stride        = 3,
        .count         = 1,
        .offset_count  = 1,
        .offsets       = flat,
        .variant_count = 1,
        .variants      = &var,
    };

    // Two elements: element 0 has the pointer alternative active, element 1 is
    // unset. The element count is derived from the allocation length.
    uint64_t obj[6] = {
        0xAAAA, PTR_HASH, 0xBBBB, // elem 0: head, selector=ptr, value
        0xCCCC, 0x0,      0xDDDD, // elem 1: head, selector=unset, value
    };
    MK_MAP(m, 6);
    m.user_ptr = obj;
    n00b_gc_scan_cb_type_layout(&m, &layout);

    // elem 0: head (0) and value (2) marked; selector (1) not.
    assert(n00b_gc_map_is_set(&m, 0));
    assert(!n00b_gc_map_is_set(&m, 1));
    assert(n00b_gc_map_is_set(&m, 2));
    // elem 1: head (3) marked; value (5) not (selector unset); selector (4) not.
    assert(n00b_gc_map_is_set(&m, 3));
    assert(!n00b_gc_map_is_set(&m, 4));
    assert(!n00b_gc_map_is_set(&m, 5));

    printf("  [PASS] cb_variant_embedded_and_array\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("Running gc_scan_map tests...\n");

    test_mark_unmark_single();
    test_mark_range_basic();
    test_mark_range_aligned();
    test_mark_range_straddling();
    test_unmark_range();
    test_mark_all_then_unmark();
    test_mark_stride();
    test_mark_every_other();
    test_mark_every_other_offset_1();
    test_bitmap_size_calc();
    test_cb_all();
    test_cb_none();
    test_cb_every_other();
    test_cb_struct_field();
    test_cb_struct_layout();
    test_cb_variant();
    test_cb_variant_embedded_and_array();

    printf("All gc_scan_map tests passed.\n");
    return 0;
}

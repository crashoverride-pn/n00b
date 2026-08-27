#include "test_unicode_helpers.h"
#include "text/unicode/casemap.h"
#include "text/unicode/encoding.h"

TEST(test_simple_toupper)
{
    ASSERT_EQ(n00b_unicode_toupper_cp('a'), 'A');
    ASSERT_EQ(n00b_unicode_toupper_cp('z'), 'Z');
    ASSERT_EQ(n00b_unicode_toupper_cp('A'), 'A');
    ASSERT_EQ(n00b_unicode_toupper_cp('0'), '0');
    ASSERT_EQ(n00b_unicode_toupper_cp(0x00E9), 0x00C9); // é → É
}

TEST(test_simple_tolower)
{
    ASSERT_EQ(n00b_unicode_tolower_cp('A'), 'a');
    ASSERT_EQ(n00b_unicode_tolower_cp('Z'), 'z');
    ASSERT_EQ(n00b_unicode_tolower_cp('a'), 'a');
    ASSERT_EQ(n00b_unicode_tolower_cp(0x00C9), 0x00E9); // É → é
}

TEST(test_simple_totitle)
{
    ASSERT_EQ(n00b_unicode_totitle_cp('a'), 'A');
    ASSERT_EQ(n00b_unicode_totitle_cp('A'), 'A');
}

TEST(test_casefold_simple)
{
    ASSERT_EQ(n00b_unicode_casefold_cp('A'), 'a');
    ASSERT_EQ(n00b_unicode_casefold_cp('a'), 'a');
    ASSERT_EQ(n00b_unicode_casefold_cp(0x00C9), 0x00E9);
}

TEST(test_full_uppercase)
{
    n00b_string_t *upper = n00b_unicode_toupper(r"hello", .allocator = nullptr);
    ASSERT_STR_EQ(upper->data, "HELLO");
}

TEST(test_full_lowercase)
{
    n00b_string_t *lower = n00b_unicode_tolower(r"HELLO", .allocator = nullptr);
    ASSERT_STR_EQ(lower->data, "hello");
}

TEST(test_full_casefold)
{
    n00b_string_t *folded
        = n00b_unicode_casefold(r"Hello World", .allocator = nullptr);
    ASSERT_STR_EQ(folded->data, "hello world");
}

TEST(test_full_casefold_ascii_already_folded)
{
    // Fast path: all-ASCII, no uppercase.
    n00b_string_t *folded
        = n00b_unicode_casefold(r"already folded 123", .allocator = nullptr);
    ASSERT_STR_EQ(folded->data, "already folded 123");
    ASSERT_EQ(folded->u8_bytes, 18);
}

TEST(test_full_casefold_empty)
{
    n00b_string_t *folded = n00b_unicode_casefold_raw(nullptr, "", 0);
    ASSERT_EQ(folded->u8_bytes, 0);
    ASSERT_STR_EQ(folded->data, "");
}

TEST(test_full_casefold_sharp_s_multi_cp)
{
    // ß (U+00DF) full-folds to "ss" (multi-codepoint full-table entry) mixed
    // with ASCII in one string. Codepoints expand 6 → 7, but byte length
    // stays 7 == 7 (2-byte ß → 2x 1-byte s); byte-length *growth* is covered
    // by test_full_casefold_output_grows.
    n00b_string_t *folded
        = n00b_unicode_casefold(r"Stra\xC3\x9Fe", .allocator = nullptr);
    ASSERT_STR_EQ(folded->data, "strasse");
    ASSERT_EQ(folded->u8_bytes, 7);
    ASSERT_EQ(folded->codepoints, 7);
}

TEST(test_full_casefold_non_ascii_one_to_one)
{
    // É (U+00C9) → é (U+00E9): count==1 full-table entry on the non-ASCII
    // path, with ASCII uppercase folded in the same pass.
    n00b_string_t *folded
        = n00b_unicode_casefold(r"CAF\xC3\x89", .allocator = nullptr);
    ASSERT_STR_EQ(folded->data, "caf\xC3\xA9");
    ASSERT_EQ(folded->u8_bytes, 5);
}

TEST(test_full_casefold_output_grows)
{
    // Folded byte length exceeds the input byte length -- the case the old
    // 12x worst-case buffer existed for, and the one the measure pass must
    // size exactly (undersizing here is a heap overflow in the write pass).
    // İ (U+0130, 2 bytes) → i + U+0307 (3 bytes).
    n00b_string_t *dotted_i
        = n00b_unicode_casefold(r"\xC4\xB0", .allocator = nullptr);
    ASSERT_STR_EQ(dotted_i->data, "i\xCC\x87");
    ASSERT_EQ(dotted_i->u8_bytes, 3);
    ASSERT_EQ(dotted_i->codepoints, 2);

    // ΐ (U+0390, 2 bytes) → ι + U+0308 + U+0301 (6 bytes): 3x growth.
    n00b_string_t *iota
        = n00b_unicode_casefold(r"\xCE\x90", .allocator = nullptr);
    ASSERT_STR_EQ(iota->data, "\xCE\xB9\xCC\x88\xCC\x81");
    ASSERT_EQ(iota->u8_bytes, 6);
    ASSERT_EQ(iota->codepoints, 3);
}

TEST(test_full_casefold_four_byte_cp)
{
    // Deseret 𐐀 (U+10400) → 𐐨 (U+10428): 4-byte codepoint on both sides,
    // filling the measure pass's 4-byte temp buffer exactly.
    n00b_string_t *folded
        = n00b_unicode_casefold(r"\xF0\x90\x90\x80", .allocator = nullptr);
    ASSERT_STR_EQ(folded->data, "\xF0\x90\x90\xA8");
    ASSERT_EQ(folded->u8_bytes, 4);
    ASSERT_EQ(folded->codepoints, 1);
}

TEST(test_full_casefold_invalid_utf8_truncates)
{
    // Truncated 2-byte sequence after valid ASCII: both fold passes must
    // stop at the same byte (the exact-size buffer is only correct if the
    // measure and write passes handle decode errors identically).
    n00b_string_t *folded = n00b_unicode_casefold_raw(nullptr, "AB\xC3", 3);
    ASSERT_STR_EQ(folded->data, "ab");
    ASSERT_EQ(folded->u8_bytes, 2);
}

TEST(test_casecmp)
{
    ASSERT_EQ(n00b_unicode_casecmp(r"Hello", r"hello"), 0);
    ASSERT(n00b_unicode_casecmp(r"apple", r"BANANA") < 0);
}

TEST(test_sharp_s_uppercase)
{
    // ß (U+00DF) → "SS" when uppercased
    n00b_string_t *upper = n00b_unicode_toupper(r"\xC3\x9F", .allocator = nullptr);
    ASSERT_STR_EQ(upper->data, "SS");
}

static void
run_tests(void)
{
    RUN_TEST(test_simple_toupper);
    RUN_TEST(test_simple_tolower);
    RUN_TEST(test_simple_totitle);
    RUN_TEST(test_casefold_simple);
    RUN_TEST(test_full_uppercase);
    RUN_TEST(test_full_lowercase);
    RUN_TEST(test_full_casefold);
    RUN_TEST(test_full_casefold_ascii_already_folded);
    RUN_TEST(test_full_casefold_empty);
    RUN_TEST(test_full_casefold_sharp_s_multi_cp);
    RUN_TEST(test_full_casefold_non_ascii_one_to_one);
    RUN_TEST(test_full_casefold_output_grows);
    RUN_TEST(test_full_casefold_four_byte_cp);
    RUN_TEST(test_full_casefold_invalid_utf8_truncates);
    RUN_TEST(test_casecmp);
    RUN_TEST(test_sharp_s_uppercase);
}

TEST_MAIN()

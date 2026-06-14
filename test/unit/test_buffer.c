#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"

// ============================================================================
// 1. Construction -- empty, sized, from-bytes
// ============================================================================

static void
test_construction(void)
{
    // Empty buffer.
    n00b_buffer_t *empty = n00b_buffer_empty();
    assert(empty != nullptr);
    assert(n00b_buffer_len(empty) == 0);
    assert(empty->alloc_len >= N00B_EMPTY_BUFFER_ALLOC);
    n00b_buffer_free(empty);

    // Sized buffer.
    n00b_buffer_t *sized = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(sized, .length = 64);
    assert(n00b_buffer_len(sized) == 64);
    assert(sized->alloc_len >= 64);
    n00b_buffer_free(sized);

    // From bytes.
    char data[] = "hello";
    n00b_buffer_t *from = n00b_buffer_from_bytes(data, 5);
    assert(n00b_buffer_len(from) == 5);
    assert(memcmp(from->data, "hello", 5) == 0);
    n00b_buffer_free(from);

    printf("  [PASS] construction\n");
}

// ============================================================================
// 2. Len
// ============================================================================

static void
test_len(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("abcdef", 6);
    assert(n00b_buffer_len(buf) == 6);
    n00b_buffer_free(buf);

    n00b_buffer_t *empty = n00b_buffer_empty();
    assert(n00b_buffer_len(empty) == 0);
    n00b_buffer_free(empty);

    printf("  [PASS] len\n");
}

// ============================================================================
// 3. Resize -- grow (data preserved), shrink
// ============================================================================

static void
test_resize(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("abc", 3);

    // Grow.
    n00b_buffer_resize(buf, 10);
    assert(n00b_buffer_len(buf) == 10);
    assert(memcmp(buf->data, "abc", 3) == 0);
    // New bytes should be zero.
    for (int i = 3; i < 10; i++) {
        assert(buf->data[i] == 0);
    }

    // Shrink.
    n00b_buffer_resize(buf, 2);
    assert(n00b_buffer_len(buf) == 2);
    assert(buf->data[0] == 'a');
    assert(buf->data[1] == 'b');

    n00b_buffer_free(buf);
    printf("  [PASS] resize\n");
}

// ============================================================================
// 4. Add -- concatenate two buffers
// ============================================================================

static void
test_add(void)
{
    n00b_buffer_t *a = n00b_buffer_from_bytes("hello", 5);
    n00b_buffer_t *b = n00b_buffer_from_bytes("world", 5);

    n00b_buffer_t *c = n00b_buffer_add(a, b);
    assert(n00b_buffer_len(c) == 10);
    assert(memcmp(c->data, "helloworld", 10) == 0);

    // Originals unchanged.
    assert(n00b_buffer_len(a) == 5);
    assert(n00b_buffer_len(b) == 5);

    // Null handling.
    assert(n00b_buffer_add(nullptr, b) == b);
    assert(n00b_buffer_add(a, nullptr) == a);

    n00b_buffer_free(a);
    n00b_buffer_free(b);
    n00b_buffer_free(c);

    printf("  [PASS] add\n");
}

// ============================================================================
// 5. Get/Set index -- valid, OOB, negative
// ============================================================================

static void
test_get_set_index(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("ABCD", 4);

    // Valid get.
    n00b_result_t(uint8_t) r = n00b_buffer_get_index(buf, 0);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 'A');

    r = n00b_buffer_get_index(buf, 3);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 'D');

    // Negative indexing.
    r = n00b_buffer_get_index(buf, -1);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 'D');

    r = n00b_buffer_get_index(buf, -4);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 'A');

    // OOB.
    r = n00b_buffer_get_index(buf, 4);
    assert(n00b_result_is_err(r));

    r = n00b_buffer_get_index(buf, -5);
    assert(n00b_result_is_err(r));

    // Valid set.
    n00b_result_t(bool) sr = n00b_buffer_set_index(buf, 1, 'X');
    assert(n00b_result_is_ok(sr));

    r = n00b_buffer_get_index(buf, 1);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 'X');

    // OOB set.
    sr = n00b_buffer_set_index(buf, 100, 'Z');
    assert(n00b_result_is_err(sr));

    n00b_buffer_free(buf);
    printf("  [PASS] get/set index\n");
}

// ============================================================================
// 6. Get/Set slice
// ============================================================================

static void
test_get_set_slice(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("abcdef", 6);

    // Get slice [1, 4) -> "bcd"
    n00b_buffer_t *s = n00b_buffer_get_slice(buf, 1, 4);
    assert(n00b_buffer_len(s) == 3);
    assert(memcmp(s->data, "bcd", 3) == 0);
    n00b_buffer_free(s);

    // Negative end: [0, -1) means [0, 6) -> "abcdef"
    s = n00b_buffer_get_slice(buf, 0, -1);
    assert(n00b_buffer_len(s) == 6);
    assert(memcmp(s->data, "abcdef", 6) == 0);
    n00b_buffer_free(s);

    // Empty slice.
    s = n00b_buffer_get_slice(buf, 3, 3);
    assert(n00b_buffer_len(s) == 0);
    n00b_buffer_free(s);

    // Set slice: replace "bcd" with "XY"
    n00b_buffer_t *repl = n00b_buffer_from_bytes("XY", 2);
    n00b_result_t(bool) r = n00b_buffer_set_slice(buf, 1, 4, .val = repl);
    assert(n00b_result_is_ok(r));
    // Now buf = "aXYef" (5 bytes)
    assert(n00b_buffer_len(buf) == 5);
    assert(memcmp(buf->data, "aXYef", 5) == 0);
    n00b_buffer_free(repl);

    n00b_buffer_free(buf);
    printf("  [PASS] get/set slice\n");
}

// ============================================================================
// 7. Find
// ============================================================================

static void
test_find(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("hello world hello", 17);
    n00b_buffer_t *sub = n00b_buffer_from_bytes("world", 5);

    // Found.
    n00b_option_t(int64_t) r = n00b_buffer_find(buf, sub);
    assert(n00b_option_is_set(r));
    assert(n00b_option_get(r) == 6);

    // Not found.
    n00b_buffer_t *missing = n00b_buffer_from_bytes("xyz", 3);
    r = n00b_buffer_find(buf, missing);
    assert(!n00b_option_is_set(r));
    n00b_buffer_free(missing);

    // With start offset.
    n00b_buffer_t *hello = n00b_buffer_from_bytes("hello", 5);
    r = n00b_buffer_find(buf, hello, .start = n00b_option_set(size_t, 1));
    assert(n00b_option_is_set(r));
    assert(n00b_option_get(r) == 12);
    n00b_buffer_free(hello);

    // Empty sub always found at start.
    n00b_buffer_t *empty = n00b_buffer_empty();
    r = n00b_buffer_find(buf, empty);
    assert(n00b_option_is_set(r));
    assert(n00b_option_get(r) == 0);
    n00b_buffer_free(empty);

    n00b_buffer_free(buf);
    n00b_buffer_free(sub);

    printf("  [PASS] find\n");
}

// ============================================================================
// 8. Copy -- deep copy independence
// ============================================================================

static void
test_copy(void)
{
    n00b_buffer_t *orig = n00b_buffer_from_bytes("original", 8);
    n00b_buffer_t *cpy  = n00b_buffer_copy(orig);

    assert(n00b_buffer_len(cpy) == 8);
    assert(memcmp(cpy->data, "original", 8) == 0);

    // Mutate copy, original unchanged.
    n00b_buffer_set_index(cpy, 0, 'X');
    n00b_result_t(uint8_t) r = n00b_buffer_get_index(orig, 0);
    assert(n00b_result_get(r) == 'o');

    r = n00b_buffer_get_index(cpy, 0);
    assert(n00b_result_get(r) == 'X');

    n00b_buffer_free(orig);
    n00b_buffer_free(cpy);

    printf("  [PASS] copy\n");
}

// ============================================================================
// 9. Hex init -- hex string -> buffer -> verify bytes
// ============================================================================

static void
test_hex_init(void)
{
    // Create a mock n00b_string_t with hex data.
    n00b_string_t *hex_str = n00b_string_from_raw("deadbeef", 8);

    n00b_buffer_t *buf = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(buf, .hex = hex_str);

    assert(n00b_buffer_len(buf) == 4);
    assert((uint8_t)buf->data[0] == 0xde);
    assert((uint8_t)buf->data[1] == 0xad);
    assert((uint8_t)buf->data[2] == 0xbe);
    assert((uint8_t)buf->data[3] == 0xef);

    n00b_buffer_free(buf);

    printf("  [PASS] hex init\n");
}

// ============================================================================
// 10. To hex string
// ============================================================================

static void
test_to_hex_str(void)
{
    char bytes[] = { (char)0xde, (char)0xad, (char)0xbe, (char)0xef };
    n00b_buffer_t *buf = n00b_buffer_from_bytes(bytes, 4);

    n00b_string_t *hex = n00b_buffer_to_hex_str(buf);
    assert(hex->u8_bytes == 8);
    assert(memcmp(hex->data, "deadbeef", 8) == 0);

    n00b_buffer_free(buf);
    // hex string memory will be cleaned up by GC / allocator.

    printf("  [PASS] to hex string\n");
}

// ============================================================================
// 11. To string
// ============================================================================

static void
test_to_string(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("test string", 11);
    n00b_string_t *s = n00b_buffer_to_string(buf);

    assert(s->u8_bytes == 11);
    assert(memcmp(s->data, "test string", 11) == 0);

    n00b_buffer_free(buf);

    printf("  [PASS] to string\n");
}

// ============================================================================
// 12. From codepoint -- ASCII and multi-byte
// ============================================================================

static void
test_from_codepoint(void)
{
    // ASCII 'A' -> 1 byte.
    n00b_buffer_t *a = n00b_buffer_from_codepoint('A');
    assert(n00b_buffer_len(a) == 1);
    assert(a->data[0] == 'A');
    n00b_buffer_free(a);

    // Euro sign U+20AC -> 3 bytes: 0xE2 0x82 0xAC.
    n00b_buffer_t *euro = n00b_buffer_from_codepoint(0x20AC);
    assert(n00b_buffer_len(euro) == 3);
    assert((uint8_t)euro->data[0] == 0xE2);
    assert((uint8_t)euro->data[1] == 0x82);
    assert((uint8_t)euro->data[2] == 0xAC);
    n00b_buffer_free(euro);

    // Emoji U+1F600 -> 4 bytes: 0xF0 0x9F 0x98 0x80.
    n00b_buffer_t *emoji = n00b_buffer_from_codepoint(0x1F600);
    assert(n00b_buffer_len(emoji) == 4);
    assert((uint8_t)emoji->data[0] == 0xF0);
    assert((uint8_t)emoji->data[1] == 0x9F);
    assert((uint8_t)emoji->data[2] == 0x98);
    assert((uint8_t)emoji->data[3] == 0x80);
    n00b_buffer_free(emoji);

    printf("  [PASS] from codepoint\n");
}

// ============================================================================
// 13. Join -- multiple buffers with separator
// ============================================================================

static void
test_join(void)
{
    n00b_buffer_t *a = n00b_buffer_from_bytes("one", 3);
    n00b_buffer_t *b = n00b_buffer_from_bytes("two", 3);
    n00b_buffer_t *c = n00b_buffer_from_bytes("three", 5);
    n00b_buffer_t *sep = n00b_buffer_from_bytes(",", 1);

    n00b_buffer_t *raw_items[] = { a, b, c };
    n00b_array_t(n00b_buffer_t *) items = n00b_array_checked_ptr(n00b_buffer_t *, 3, raw_items);
    items.len = 3;
    n00b_buffer_t *result = n00b_buffer_join(items, sep);

    assert(n00b_buffer_len(result) == 13); // "one,two,three"
    assert(memcmp(result->data, "one,two,three", 13) == 0);

    // Without separator.
    n00b_buffer_t *no_sep = n00b_buffer_join(items, nullptr);
    assert(n00b_buffer_len(no_sep) == 11); // "onetwothree"
    assert(memcmp(no_sep->data, "onetwothree", 11) == 0);

    n00b_buffer_free(a);
    n00b_buffer_free(b);
    n00b_buffer_free(c);
    n00b_buffer_free(sep);
    n00b_buffer_free(result);
    n00b_buffer_free(no_sep);

    printf("  [PASS] join\n");
}

// ============================================================================
// 14. Free -- verify cleanup
// ============================================================================

static void
test_free(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("data", 4);
    assert(buf->data != nullptr);
    n00b_rwlock_t *lock = buf->lock;
    assert(lock != nullptr);
    assert(n00b_buffer_len(buf) == 4);

    n00b_buffer_free(buf);
    assert(buf->data == nullptr);
    assert(buf->byte_len == 0);
    assert(buf->alloc_len == 0);
    assert(buf->lock == nullptr);

    // Free nullptr is safe.
    n00b_buffer_free(nullptr);

    printf("  [PASS] free\n");
}

// ============================================================================
// 15. To C -- raw pointer access
// ============================================================================

static void
test_to_c(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes("raw", 3);
    int64_t        len = 0;
    char          *p   = n00b_buffer_to_c(buf, &len);

    assert(len == 3);
    assert(p == buf->data);
    assert(memcmp(p, "raw", 3) == 0);

    // nullptr len_ptr is fine.
    char *p2 = n00b_buffer_to_c(buf, nullptr);
    assert(p2 == buf->data);

    n00b_buffer_free(buf);

    printf("  [PASS] to c\n");
}

// ============================================================================
// 16. From C string -- convenience wrapper
// ============================================================================

static void
test_from_cstr(void)
{
    n00b_buffer_t *buf = n00b_buffer_from_cstr("hello world");
    assert(n00b_buffer_len(buf) == 11);
    assert(memcmp(buf->data, "hello world", 11) == 0);

    n00b_buffer_t *empty = n00b_buffer_from_cstr("");
    assert(n00b_buffer_len(empty) == 0);

    n00b_buffer_free(buf);
    n00b_buffer_free(empty);

    printf("  [PASS] from_cstr\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running buffer tests...\n");

    test_construction();
    test_len();
    test_resize();
    test_add();
    test_get_set_index();
    test_get_set_slice();
    test_find();
    test_copy();
    test_hex_init();
    test_to_hex_str();
    test_to_string();
    test_from_codepoint();
    test_join();
    test_free();
    test_to_c();
    test_from_cstr();

    printf("All buffer tests passed.\n");
    n00b_shutdown();
    return 0;
}

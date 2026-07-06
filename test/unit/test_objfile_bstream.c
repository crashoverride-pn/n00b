#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/bstream.h"

// ============================================================================
// Helper: create a stream from raw bytes
// ============================================================================

static n00b_bstream_t *
make_stream(const void *data, size_t len)
{
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)data, len);
    return n00b_bstream_new(buf);
}

// ============================================================================
// Construction
// ============================================================================

static void
test_construction(void)
{
    uint8_t data[] = {1, 2, 3, 4};
    n00b_bstream_t *s = make_stream(data, 4);

    assert(s != nullptr);
    assert(n00b_bstream_pos(s) == 0);
    assert(n00b_bstream_remaining(s) == 4);
    assert(n00b_bstream_can_read(s, 4));
    assert(!n00b_bstream_can_read(s, 5));

    printf("  [PASS] construction\n");
}

// ============================================================================
// Read u8
// ============================================================================

static void
test_read_u8(void)
{
    uint8_t data[] = {0x42, 0xFF, 0x00};
    n00b_bstream_t *s = make_stream(data, 3);

    auto r1 = n00b_bstream_read_u8(s);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_get(r1) == 0x42);
    assert(n00b_bstream_pos(s) == 1);

    auto r2 = n00b_bstream_read_u8(s);
    assert(n00b_result_get(r2) == 0xFF);

    auto r3 = n00b_bstream_read_u8(s);
    assert(n00b_result_get(r3) == 0x00);

    // Past end.
    auto r4 = n00b_bstream_read_u8(s);
    assert(n00b_result_is_err(r4));

    printf("  [PASS] read_u8\n");
}

// ============================================================================
// Read u16/u32/u64 (native endian)
// ============================================================================

static void
test_read_multibyte(void)
{
    // Write known little-endian values.
    uint8_t data[14];
    uint16_t v16 = 0x1234;
    uint32_t v32 = 0xDEADBEEF;
    uint64_t v64 = 0x0102030405060708ULL;

    memcpy(data + 0, &v16, 2);
    memcpy(data + 2, &v32, 4);
    memcpy(data + 6, &v64, 8);

    n00b_bstream_t *s = make_stream(data, 14);

    auto r16 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_ok(r16));
    assert(n00b_result_get(r16) == v16);

    auto r32 = n00b_bstream_read_u32(s);
    assert(n00b_result_is_ok(r32));
    assert(n00b_result_get(r32) == v32);

    auto r64 = n00b_bstream_read_u64(s);
    assert(n00b_result_is_ok(r64));
    assert(n00b_result_get(r64) == v64);

    assert(n00b_bstream_pos(s) == 14);
    assert(n00b_bstream_remaining(s) == 0);

    printf("  [PASS] read_multibyte\n");
}

// ============================================================================
// Endian swap
// ============================================================================

static void
test_endian_swap(void)
{
    // Store 0x0102 in big-endian byte order.
    uint8_t data[] = {0x01, 0x02};
    n00b_bstream_t *s = make_stream(data, 2);

    // Read without swap (host endian).
    auto r1 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_ok(r1));
    uint16_t native_val = n00b_result_get(r1);

    // Reset and read with big-endian setting.
    auto reset_r = n00b_bstream_setpos(s, 0);
    assert(n00b_result_is_ok(reset_r));
    n00b_bstream_set_endian(s, N00B_ENDIAN_BIG);

    auto r2 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_ok(r2));
    uint16_t be_val = n00b_result_get(r2);

    // On a little-endian host, big-endian read of {0x01, 0x02} = 0x0102.
    // On a big-endian host, same bytes, no swap needed, also 0x0102.
    assert(be_val == 0x0102);

    printf("  [PASS] endian_swap\n");
    (void)native_val;
}

// ============================================================================
// Bounds checking
// ============================================================================

static void
test_bounds(void)
{
    uint8_t data[] = {0x42};
    n00b_bstream_t *s = make_stream(data, 1);

    // Can read 1 byte.
    assert(n00b_bstream_can_read(s, 1));

    // Cannot read 2 bytes.
    auto r16 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_err(r16));
    assert(n00b_result_get_err(r16) == N00B_ERR_OUT_OF_BOUNDS);

    // setpos past end.
    auto sp = n00b_bstream_setpos(s, 100);
    assert(n00b_result_is_err(sp));

    // advance past end.
    auto reset_r = n00b_bstream_setpos(s, 0);
    assert(n00b_result_is_ok(reset_r));
    auto adv = n00b_bstream_advance(s, 2);
    assert(n00b_result_is_err(adv));

    printf("  [PASS] bounds\n");
}

// ============================================================================
// Position and advance
// ============================================================================

static void
test_position(void)
{
    uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};
    n00b_bstream_t *s = make_stream(data, 8);

    assert(n00b_bstream_pos(s) == 0);

    auto adv_r = n00b_bstream_advance(s, 3);
    assert(n00b_result_is_ok(adv_r));
    assert(n00b_bstream_pos(s) == 3);
    assert(n00b_bstream_remaining(s) == 5);

    auto set_r = n00b_bstream_setpos(s, 0);
    assert(n00b_result_is_ok(set_r));
    assert(n00b_bstream_pos(s) == 0);

    printf("  [PASS] position\n");
}

// ============================================================================
// Align
// ============================================================================

static void
test_align(void)
{
    uint8_t data[16] = {};
    n00b_bstream_t *s = make_stream(data, 16);

    auto set_r = n00b_bstream_setpos(s, 3);
    assert(n00b_result_is_ok(set_r));
    auto r = n00b_bstream_align(s, 4);
    assert(n00b_result_is_ok(r));
    assert(n00b_bstream_pos(s) == 4);

    // Already aligned — no movement.
    r = n00b_bstream_align(s, 4);
    assert(n00b_result_is_ok(r));
    assert(n00b_bstream_pos(s) == 4);

    printf("  [PASS] align\n");
}

// ============================================================================
// Read bytes
// ============================================================================

static void
test_read_bytes(void)
{
    uint8_t data[] = {0xCA, 0xFE, 0xBA, 0xBE};
    n00b_bstream_t *s = make_stream(data, 4);

    auto r = n00b_bstream_read_bytes(s, 2);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *got = n00b_result_get(r);
    assert(n00b_buffer_len(got) == 2);
    assert((uint8_t)got->data[0] == 0xCA);
    assert((uint8_t)got->data[1] == 0xFE);

    assert(n00b_bstream_pos(s) == 2);
    n00b_buffer_free(got);

    printf("  [PASS] read_bytes\n");
}

// ============================================================================
// Read cstring
// ============================================================================

static void
test_read_cstring(void)
{
    const char data[] = "hello\0world\0";
    n00b_bstream_t *s = make_stream(data, sizeof(data) - 1); // 12 bytes

    auto r1 = n00b_bstream_read_cstring(s);
    assert(n00b_result_is_ok(r1));
    n00b_string_t *str1 = n00b_result_get(r1);
    assert(str1->u8_bytes == 5);
    assert(memcmp(str1->data, "hello", 5) == 0);

    auto r2 = n00b_bstream_read_cstring(s);
    assert(n00b_result_is_ok(r2));
    n00b_string_t *str2 = n00b_result_get(r2);
    assert(str2->u8_bytes == 5);
    assert(memcmp(str2->data, "world", 5) == 0);

    printf("  [PASS] read_cstring\n");
}

// ============================================================================
// LEB128
// ============================================================================

static void
test_uleb128(void)
{
    // Encode 624485 = 0xE5 0x8E 0x26 in ULEB128.
    uint8_t data[] = {0xE5, 0x8E, 0x26};
    n00b_bstream_t *s = make_stream(data, 3);

    auto r = n00b_bstream_read_uleb128(s);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 624485);

    printf("  [PASS] uleb128\n");
}

static void
test_sleb128(void)
{
    // Encode -123456 in SLEB128 = 0xC0 0xBB 0x78
    uint8_t data[] = {0xC0, 0xBB, 0x78};
    n00b_bstream_t *s = make_stream(data, 3);

    auto r = n00b_bstream_read_sleb128(s);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == -123456);

    printf("  [PASS] sleb128\n");
}

// ============================================================================
// Peek
// ============================================================================

static void
test_peek(void)
{
    uint8_t data[] = {0x11, 0x22, 0x33, 0x44};
    n00b_bstream_t *s = make_stream(data, 4);

    auto r = n00b_bstream_peek_u8(s, 2);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == 0x33);

    // Peek should not advance.
    assert(n00b_bstream_pos(s) == 0);

    // Peek out of bounds.
    auto r2 = n00b_bstream_peek_u8(s, 100);
    assert(n00b_result_is_err(r2));

    printf("  [PASS] peek\n");
}

// ============================================================================
// Raw access
// ============================================================================

static void
test_raw(void)
{
    uint8_t data[] = {0xAA, 0xBB, 0xCC};
    n00b_bstream_t *s = make_stream(data, 3);

    const uint8_t *p = n00b_bstream_raw(s);
    assert(p != nullptr);
    assert(p[0] == 0xAA);

    auto adv_r = n00b_bstream_advance(s, 1);
    assert(n00b_result_is_ok(adv_r));
    p = n00b_bstream_raw(s);
    assert(p[0] == 0xBB);

    auto r = n00b_bstream_raw_at(s, 2);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r)[0] == 0xCC);

    printf("  [PASS] raw\n");
}

// ============================================================================
// Signed reads
// ============================================================================

static void
test_signed_reads(void)
{
    int8_t  i8  = -42;
    int16_t i16 = -1234;
    int32_t i32 = -100000;
    int64_t i64 = -9999999999LL;

    uint8_t data[15];
    memcpy(data + 0, &i8, 1);
    memcpy(data + 1, &i16, 2);
    memcpy(data + 3, &i32, 4);
    memcpy(data + 7, &i64, 8);

    n00b_bstream_t *s = make_stream(data, 15);

    auto r8 = n00b_bstream_read_i8(s);
    assert(n00b_result_is_ok(r8));
    assert(n00b_result_get(r8) == -42);

    auto r16 = n00b_bstream_read_i16(s);
    assert(n00b_result_is_ok(r16));
    assert(n00b_result_get(r16) == -1234);

    auto r32 = n00b_bstream_read_i32(s);
    assert(n00b_result_is_ok(r32));
    assert(n00b_result_get(r32) == -100000);

    auto r64 = n00b_bstream_read_i64(s);
    assert(n00b_result_is_ok(r64));
    assert(n00b_result_get(r64) == -9999999999LL);

    printf("  [PASS] signed_reads\n");
}

// ============================================================================
// File I/O
// ============================================================================

static void
test_file_io(void)
{
    // Read /usr/bin/true which should exist on macOS and Linux.
    auto r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_ok(r)) {
        n00b_bstream_t *s = n00b_result_get(r);
        assert(s != nullptr);
        assert(n00b_bstream_remaining(s) > 0);
        printf("  [PASS] file_io\n");
    }
    else {
        printf("  [SKIP] file_io (file not found)\n");
    }

    // Non-existent file.
    auto r2 = n00b_bstream_from_file("/nonexistent/path/to/file");
    assert(n00b_result_is_err(r2));

    printf("  [PASS] file_io_error\n");
}

// ============================================================================
// Peek multi-byte variants
// ============================================================================

static void
test_peek_multibyte(void)
{
    uint8_t data[16];
    uint16_t v16 = 0x1234;
    uint32_t v32 = 0xDEADBEEF;
    uint64_t v64 = 0x0102030405060708ULL;
    memcpy(data + 0, &v16, 2);
    memcpy(data + 2, &v32, 4);
    memcpy(data + 6, &v64, 8);

    n00b_bstream_t *s = make_stream(data, 14);

    // Peek u16 at offset 0.
    auto r16 = n00b_bstream_peek_u16(s, 0);
    assert(n00b_result_is_ok(r16));
    assert(n00b_result_get(r16) == 0x1234);
    assert(n00b_bstream_pos(s) == 0);  // Position unchanged.

    // Peek u32 at offset 2.
    auto r32 = n00b_bstream_peek_u32(s, 2);
    assert(n00b_result_is_ok(r32));
    assert(n00b_result_get(r32) == 0xDEADBEEF);
    assert(n00b_bstream_pos(s) == 0);

    // Peek u64 at offset 6.
    auto r64 = n00b_bstream_peek_u64(s, 6);
    assert(n00b_result_is_ok(r64));
    assert(n00b_result_get(r64) == 0x0102030405060708ULL);
    assert(n00b_bstream_pos(s) == 0);

    // Out of bounds for each.
    auto e16 = n00b_bstream_peek_u16(s, 13);
    assert(n00b_result_is_err(e16));
    auto e32 = n00b_bstream_peek_u32(s, 11);
    assert(n00b_result_is_err(e32));
    auto e64 = n00b_bstream_peek_u64(s, 7);
    assert(n00b_result_is_err(e64));

    printf("  [PASS] peek_multibyte\n");
}

static void
test_peek_bytes(void)
{
    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    n00b_bstream_t *s = make_stream(data, 5);

    // Peek 3 bytes at offset 1.
    auto r = n00b_bstream_peek_bytes(s, 1, 3);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(n00b_buffer_len(buf) == 3);
    assert((uint8_t)buf->data[0] == 0xBB);
    assert((uint8_t)buf->data[1] == 0xCC);
    assert((uint8_t)buf->data[2] == 0xDD);
    assert(n00b_bstream_pos(s) == 0);

    // Out of bounds.
    auto e = n00b_bstream_peek_bytes(s, 3, 5);
    assert(n00b_result_is_err(e));

    printf("  [PASS] peek_bytes\n");
}

static void
test_peek_cstring(void)
{
    uint8_t data[] = {'h', 'i', '\0', 'b', 'y', 'e', '\0'};
    n00b_bstream_t *s = make_stream(data, 7);

    // Peek cstring at offset 0 → "hi"
    auto r = n00b_bstream_peek_cstring(s, 0);
    assert(n00b_result_is_ok(r));
    n00b_string_t *str = n00b_result_get(r);
    assert(strcmp(str->data, "hi") == 0);
    assert(n00b_bstream_pos(s) == 0);

    // Peek cstring at offset 3 → "bye"
    auto r2 = n00b_bstream_peek_cstring(s, 3);
    assert(n00b_result_is_ok(r2));
    str = n00b_result_get(r2);
    assert(strcmp(str->data, "bye") == 0);
    assert(n00b_bstream_pos(s) == 0);

    printf("  [PASS] peek_cstring\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running stream tests...\n");

    test_construction();
    test_read_u8();
    test_read_multibyte();
    test_endian_swap();
    test_bounds();
    test_position();
    test_align();
    test_read_bytes();
    test_read_cstring();
    test_uleb128();
    test_sleb128();
    test_peek();
    test_raw();
    test_signed_reads();
    test_file_io();
    test_peek_multibyte();
    test_peek_bytes();
    test_peek_cstring();

    printf("All stream tests passed.\n");
    return 0;
}

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/writer.h"
#include "compiler/objfile/bstream.h"

// ============================================================================
// Test: construction
// ============================================================================

static void
test_construction(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    assert(w != nullptr);
    assert(n00b_writer_pos(w) == 0);

    printf("  [PASS] construction\n");
}

// ============================================================================
// Test: write and read back integers
// ============================================================================

static void
test_write_integers(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_u8(w, 0x42);
    n00b_writer_write_u16(w, 0x1234);
    n00b_writer_write_u32(w, 0xDEADBEEF);
    n00b_writer_write_u64(w, 0x0102030405060708ULL);

    assert(n00b_writer_pos(w) == 1 + 2 + 4 + 8);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r8 = n00b_bstream_read_u8(s);
    assert(n00b_result_is_ok(r8));
    assert(n00b_result_get(r8) == 0x42);

    auto r16 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_ok(r16));
    assert(n00b_result_get(r16) == 0x1234);

    auto r32 = n00b_bstream_read_u32(s);
    assert(n00b_result_is_ok(r32));
    assert(n00b_result_get(r32) == 0xDEADBEEF);

    auto r64 = n00b_bstream_read_u64(s);
    assert(n00b_result_is_ok(r64));
    assert(n00b_result_get(r64) == 0x0102030405060708ULL);

    printf("  [PASS] write_integers\n");
}

// ============================================================================
// Test: write signed integers
// ============================================================================

static void
test_write_signed(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_i8(w, -42);
    n00b_writer_write_i16(w, -1234);
    n00b_writer_write_i32(w, -100000);
    n00b_writer_write_i64(w, -9999999999LL);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

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

    printf("  [PASS] write_signed\n");
}

// ============================================================================
// Test: endian swap
// ============================================================================

static void
test_endian_swap(void)
{
    // Write big-endian, read big-endian.
    n00b_writer_t *w = n00b_writer_new(64);
    n00b_writer_set_endian(w, N00B_ENDIAN_BIG);

    n00b_writer_write_u16(w, 0x0102);
    n00b_writer_write_u32(w, 0x01020304);
    n00b_writer_write_u64(w, 0x0102030405060708ULL);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);
    n00b_bstream_set_endian(s, N00B_ENDIAN_BIG);

    auto r16 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_ok(r16));
    assert(n00b_result_get(r16) == 0x0102);

    auto r32 = n00b_bstream_read_u32(s);
    assert(n00b_result_is_ok(r32));
    assert(n00b_result_get(r32) == 0x01020304);

    auto r64 = n00b_bstream_read_u64(s);
    assert(n00b_result_is_ok(r64));
    assert(n00b_result_get(r64) == 0x0102030405060708ULL);

    printf("  [PASS] endian_swap\n");
}

// ============================================================================
// Test: write_cstring
// ============================================================================

static void
test_write_cstring(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_cstring(w, "hello");
    n00b_writer_write_cstring(w, "world");

    assert(n00b_writer_pos(w) == 12); // 5+1 + 5+1

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r1 = n00b_bstream_read_cstring(s);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_get(r1)->u8_bytes == 5);
    assert(memcmp(n00b_result_get(r1)->data, "hello", 5) == 0);

    auto r2 = n00b_bstream_read_cstring(s);
    assert(n00b_result_is_ok(r2));
    assert(memcmp(n00b_result_get(r2)->data, "world", 5) == 0);

    printf("  [PASS] write_cstring\n");
}

// ============================================================================
// Test: write_zeros
// ============================================================================

static void
test_write_zeros(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_u8(w, 0xFF);
    n00b_writer_write_zeros(w, 4);
    n00b_writer_write_u8(w, 0xAA);

    assert(n00b_writer_pos(w) == 6);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    assert((uint8_t)buf->data[0] == 0xFF);
    assert((uint8_t)buf->data[1] == 0x00);
    assert((uint8_t)buf->data[2] == 0x00);
    assert((uint8_t)buf->data[3] == 0x00);
    assert((uint8_t)buf->data[4] == 0x00);
    assert((uint8_t)buf->data[5] == 0xAA);

    printf("  [PASS] write_zeros\n");
}

// ============================================================================
// Test: write_buffer
// ============================================================================

static void
test_write_buffer(void)
{
    uint8_t data[] = {0xCA, 0xFE, 0xBA, 0xBE};
    n00b_buffer_t *src = n00b_buffer_from_bytes((char *)data, 4);

    n00b_writer_t *w = n00b_writer_new(64);
    n00b_writer_write_buffer(w, src);

    assert(n00b_writer_pos(w) == 4);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    assert((uint8_t)buf->data[0] == 0xCA);
    assert((uint8_t)buf->data[1] == 0xFE);
    assert((uint8_t)buf->data[2] == 0xBA);
    assert((uint8_t)buf->data[3] == 0xBE);

    printf("  [PASS] write_buffer\n");
}

// ============================================================================
// Test: align
// ============================================================================

static void
test_align(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_u8(w, 0x11);   // pos = 1
    n00b_writer_align(w, 4);         // pos = 4
    assert(n00b_writer_pos(w) == 4);

    // Already aligned — no change.
    n00b_writer_align(w, 4);
    assert(n00b_writer_pos(w) == 4);

    n00b_writer_write_u8(w, 0x22);   // pos = 5
    n00b_writer_align(w, 8);         // pos = 8
    assert(n00b_writer_pos(w) == 8);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    // Verify zero padding.
    assert((uint8_t)buf->data[0] == 0x11);
    assert((uint8_t)buf->data[1] == 0x00);
    assert((uint8_t)buf->data[2] == 0x00);
    assert((uint8_t)buf->data[3] == 0x00);
    assert((uint8_t)buf->data[4] == 0x22);
    assert((uint8_t)buf->data[5] == 0x00);
    assert((uint8_t)buf->data[6] == 0x00);
    assert((uint8_t)buf->data[7] == 0x00);

    printf("  [PASS] align\n");
}

// ============================================================================
// Test: patch operations (no cursor movement)
// ============================================================================

static void
test_patch(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    // Write some data.
    n00b_writer_write_zeros(w, 16);
    size_t saved_pos = n00b_writer_pos(w);
    assert(saved_pos == 16);

    // Patch at various offsets — should not move cursor.
    n00b_writer_patch_u16(w, 0, 0xABCD);
    assert(n00b_writer_pos(w) == saved_pos);

    n00b_writer_patch_u32(w, 4, 0x12345678);
    assert(n00b_writer_pos(w) == saved_pos);

    n00b_writer_patch_u64(w, 8, 0xDEADC0DE00112233ULL);
    assert(n00b_writer_pos(w) == saved_pos);

    // Read back.
    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r16 = n00b_bstream_read_u16(s);
    assert(n00b_result_is_ok(r16));
    assert(n00b_result_get(r16) == 0xABCD);

    // Skip 2 zero bytes.
    n00b_bstream_advance(s, 2);

    auto r32 = n00b_bstream_read_u32(s);
    assert(n00b_result_is_ok(r32));
    assert(n00b_result_get(r32) == 0x12345678);

    auto r64 = n00b_bstream_read_u64(s);
    assert(n00b_result_is_ok(r64));
    assert(n00b_result_get(r64) == 0xDEADC0DE00112233ULL);

    printf("  [PASS] patch\n");
}

// ============================================================================
// Test: patch_i64
// ============================================================================

static void
test_patch_i64(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_zeros(w, 8);
    n00b_writer_patch_i64(w, 0, -42);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_bstream_read_i64(s);
    assert(n00b_result_is_ok(r));
    assert(n00b_result_get(r) == -42);

    printf("  [PASS] patch_i64\n");
}

// ============================================================================
// Test: finalize truncates to pos
// ============================================================================

static void
test_finalize_truncates(void)
{
    n00b_writer_t *w = n00b_writer_new(4096);

    n00b_writer_write_u32(w, 0x11223344);
    n00b_writer_write_u32(w, 0x55667788);

    assert(n00b_writer_pos(w) == 8);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    // Buffer should be truncated to 8 bytes, not 4096.
    assert(n00b_buffer_len(buf) == 8);

    printf("  [PASS] finalize_truncates\n");
}

// ============================================================================
// Test: buffer growth
// ============================================================================

static void
test_growth(void)
{
    n00b_writer_t *w = n00b_writer_new(4);

    // Write more than initial capacity.
    for (int i = 0; i < 256; i++) {
        n00b_writer_write_u8(w, (uint8_t)i);
    }

    assert(n00b_writer_pos(w) == 256);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    assert(n00b_buffer_len(buf) == 256);

    for (int i = 0; i < 256; i++) {
        assert((uint8_t)buf->data[i] == (uint8_t)i);
    }

    printf("  [PASS] growth\n");
}

// ============================================================================
// Test: setpos and overwrite
// ============================================================================

static void
test_setpos(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_u32(w, 0xAAAAAAAA);
    n00b_writer_write_u32(w, 0xBBBBBBBB);
    assert(n00b_writer_pos(w) == 8);

    // Seek back and overwrite.
    n00b_writer_setpos(w, 0);
    n00b_writer_write_u32(w, 0xCCCCCCCC);
    assert(n00b_writer_pos(w) == 4);

    // Seek to end.
    n00b_writer_setpos(w, 8);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r1 = n00b_bstream_read_u32(s);
    assert(n00b_result_get(r1) == 0xCCCCCCCC);

    auto r2 = n00b_bstream_read_u32(s);
    assert(n00b_result_get(r2) == 0xBBBBBBBB);

    printf("  [PASS] setpos\n");
}

// ============================================================================
// Test: ULEB128 round-trip
// ============================================================================

static void
test_uleb128(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_uleb128(w, 0);
    n00b_writer_write_uleb128(w, 127);
    n00b_writer_write_uleb128(w, 128);
    n00b_writer_write_uleb128(w, 624485);
    n00b_writer_write_uleb128(w, 0xFFFFFFFFFFFFFFFFULL);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r0 = n00b_bstream_read_uleb128(s);
    assert(n00b_result_is_ok(r0));
    assert(n00b_result_get(r0) == 0);

    auto r1 = n00b_bstream_read_uleb128(s);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_get(r1) == 127);

    auto r2 = n00b_bstream_read_uleb128(s);
    assert(n00b_result_is_ok(r2));
    assert(n00b_result_get(r2) == 128);

    auto r3 = n00b_bstream_read_uleb128(s);
    assert(n00b_result_is_ok(r3));
    assert(n00b_result_get(r3) == 624485);

    auto r4 = n00b_bstream_read_uleb128(s);
    assert(n00b_result_is_ok(r4));
    assert(n00b_result_get(r4) == 0xFFFFFFFFFFFFFFFFULL);

    printf("  [PASS] uleb128\n");
}

// ============================================================================
// Test: SLEB128 round-trip
// ============================================================================

static void
test_sleb128(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_sleb128(w, 0);
    n00b_writer_write_sleb128(w, 63);
    n00b_writer_write_sleb128(w, -1);
    n00b_writer_write_sleb128(w, -123456);
    n00b_writer_write_sleb128(w, 624485);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r0 = n00b_bstream_read_sleb128(s);
    assert(n00b_result_is_ok(r0));
    assert(n00b_result_get(r0) == 0);

    auto r1 = n00b_bstream_read_sleb128(s);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_get(r1) == 63);

    auto r2 = n00b_bstream_read_sleb128(s);
    assert(n00b_result_is_ok(r2));
    assert(n00b_result_get(r2) == -1);

    auto r3 = n00b_bstream_read_sleb128(s);
    assert(n00b_result_is_ok(r3));
    assert(n00b_result_get(r3) == -123456);

    auto r4 = n00b_bstream_read_sleb128(s);
    assert(n00b_result_is_ok(r4));
    assert(n00b_result_get(r4) == 624485);

    printf("  [PASS] sleb128\n");
}

// ============================================================================
// Test: strtab builder
// ============================================================================

static void
test_strtab(void)
{
    n00b_strtab_builder_t *sb = n00b_strtab_builder_new();

    // Empty string always at 0.
    uint32_t off0 = n00b_strtab_builder_add(sb, "");
    assert(off0 == 0);

    uint32_t off1 = n00b_strtab_builder_add(sb, ".text");
    assert(off1 == 1);

    uint32_t off2 = n00b_strtab_builder_add(sb, ".data");
    assert(off2 == 7); // 1 + 5 + 1

    uint32_t off3 = n00b_strtab_builder_add(sb, ".bss");
    assert(off3 == 13); // 7 + 5 + 1

    // Deduplication: adding ".text" again should return same offset.
    uint32_t off4 = n00b_strtab_builder_add(sb, ".text");
    assert(off4 == off1);

    // Verify size.
    assert(n00b_strtab_builder_size(sb) == 18); // 1 + 6 + 6 + 5

    // Write to writer and verify content.
    n00b_writer_t *w = n00b_writer_new(64);
    n00b_strtab_builder_write(sb, w);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    assert(n00b_buffer_len(buf) == 18);
    assert(buf->data[0] == '\0');
    assert(memcmp(buf->data + 1, ".text", 5) == 0);
    assert(buf->data[6] == '\0');
    assert(memcmp(buf->data + 7, ".data", 5) == 0);
    assert(buf->data[12] == '\0');
    assert(memcmp(buf->data + 13, ".bss", 4) == 0);
    assert(buf->data[17] == '\0');

    printf("  [PASS] strtab\n");
}

// ============================================================================
// Test: strtab with NULL
// ============================================================================

static void
test_strtab_null(void)
{
    n00b_strtab_builder_t *sb = n00b_strtab_builder_new();

    uint32_t off = n00b_strtab_builder_add(sb, nullptr);
    assert(off == 0);

    printf("  [PASS] strtab_null\n");
}

// ============================================================================
// Test: write_bytes with raw data
// ============================================================================

static void
test_write_bytes(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    n00b_writer_write_bytes(w, data, sizeof(data));

    assert(n00b_writer_pos(w) == 5);

    n00b_buffer_t *buf = n00b_writer_finalize(w);

    for (int i = 0; i < 5; i++) {
        assert((uint8_t)buf->data[i] == (uint8_t)(i + 1));
    }

    printf("  [PASS] write_bytes\n");
}

// ============================================================================
// Test: null buffer write is no-op
// ============================================================================

static void
test_write_null_buffer(void)
{
    n00b_writer_t *w = n00b_writer_new(64);

    n00b_writer_write_buffer(w, nullptr);
    assert(n00b_writer_pos(w) == 0);

    printf("  [PASS] write_null_buffer\n");
}

static void
test_has_error(void)
{
    // A fresh writer should have no error.
    n00b_writer_t *w = n00b_writer_new(64);
    assert(n00b_writer_has_error(w) == false);

    // Normal writes should not trigger an error.
    n00b_writer_write_u32(w, 0x12345678);
    assert(n00b_writer_has_error(w) == false);

    n00b_buffer_t *buf = n00b_writer_finalize(w);
    assert(buf != nullptr);

    printf("  [PASS] has_error\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running writer tests...\n");

    test_construction();
    test_write_integers();
    test_write_signed();
    test_endian_swap();
    test_write_cstring();
    test_write_zeros();
    test_write_buffer();
    test_align();
    test_patch();
    test_patch_i64();
    test_finalize_truncates();
    test_growth();
    test_setpos();
    test_uleb128();
    test_sleb128();
    test_strtab();
    test_strtab_null();
    test_write_bytes();
    test_write_null_buffer();
    test_has_error();

    printf("All writer tests passed.\n");
    n00b_shutdown();
    return 0;
}

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/abstract.h"

// ============================================================================
// Detect ELF from magic bytes
// ============================================================================

static void
test_detect_elf(void)
{
    // Minimal ELF header (just magic + a few bytes).
    uint8_t elf_data[] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)elf_data, sizeof(elf_data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    n00b_format_t fmt = n00b_detect_format(s);
    assert(fmt == N00B_FMT_ELF);

    printf("  [PASS] detect_elf\n");
}

// ============================================================================
// Detect MachO from magic bytes
// ============================================================================

static void
test_detect_macho_64(void)
{
    // MachO 64-bit magic (little-endian host).
    uint32_t magic = 0xfeedfacf;
    char     data[8] = {};
    memcpy(data, &magic, 4);

    n00b_buffer_t *buf = n00b_buffer_from_bytes(data, sizeof(data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    n00b_format_t fmt = n00b_detect_format(s);
    assert(fmt == N00B_FMT_MACHO);

    printf("  [PASS] detect_macho_64\n");
}

static void
test_detect_macho_fat(void)
{
    uint32_t magic = 0xcafebabe;
    char     data[8] = {};
    memcpy(data, &magic, 4);

    n00b_buffer_t *buf = n00b_buffer_from_bytes(data, sizeof(data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    n00b_format_t fmt = n00b_detect_format(s);
    assert(fmt == N00B_FMT_MACHO);

    printf("  [PASS] detect_macho_fat\n");
}

// ============================================================================
// Detect unknown
// ============================================================================

static void
test_detect_unknown(void)
{
    char data[] = {0x00, 0x00, 0x00, 0x00};
    n00b_buffer_t *buf = n00b_buffer_from_bytes(data, sizeof(data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    n00b_format_t fmt = n00b_detect_format(s);
    assert(fmt == N00B_FMT_UNKNOWN);

    printf("  [PASS] detect_unknown\n");
}

// ============================================================================
// Detect too small
// ============================================================================

static void
test_detect_too_small(void)
{
    char data[] = {0x7f, 'E'};
    n00b_buffer_t *buf = n00b_buffer_from_bytes(data, 2);
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    n00b_format_t fmt = n00b_detect_format(s);
    assert(fmt == N00B_FMT_UNKNOWN);

    printf("  [PASS] detect_too_small\n");
}

// ============================================================================
// Detect does not modify stream position
// ============================================================================

static void
test_detect_preserves_pos(void)
{
    uint8_t elf_data[] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)elf_data, sizeof(elf_data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    // Advance the stream first.
    auto adv_r = n00b_bstream_advance(s, 2);
    assert(n00b_result_is_ok(adv_r));
    size_t before = n00b_bstream_pos(s);

    n00b_detect_format(s);

    // Position should be unchanged.
    assert(n00b_bstream_pos(s) == before);

    printf("  [PASS] detect_preserves_pos\n");
}

// ============================================================================
// Detect on a real binary (/usr/bin/true on macOS = MachO)
// ============================================================================

static void
test_detect_real_binary(void)
{
    auto r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_err(r)) {
        printf("  [SKIP] detect_real_binary (file not found)\n");
        return;
    }

    n00b_bstream_t *s  = n00b_result_get(r);
    n00b_format_t fmt = n00b_detect_format(s);

    // On macOS it's MachO, on Linux it's ELF.
    assert(fmt == N00B_FMT_MACHO || fmt == N00B_FMT_ELF);
    printf("  [PASS] detect_real_binary (format=%d)\n", fmt);
}

// ============================================================================
// Abstract accessors on a stub binary
// ============================================================================

static void
test_abstract_accessors(void)
{
    n00b_binary_t *b = n00b_alloc(n00b_binary_t);
    b->format        = N00B_FMT_ELF;
    b->arch          = N00B_ARCH_X86_64;
    b->entrypoint    = 0x401000;
    b->imagebase     = 0x400000;
    b->is_pie        = true;

    assert(n00b_binary_format(b) == N00B_FMT_ELF);
    assert(n00b_binary_arch(b) == N00B_ARCH_X86_64);
    assert(n00b_binary_entrypoint(b) == 0x401000);
    assert(n00b_binary_imagebase(b) == 0x400000);
    assert(n00b_binary_is_pie(b) == true);

    // Null safety.
    assert(n00b_binary_format(nullptr) == N00B_FMT_UNKNOWN);
    assert(n00b_binary_arch(nullptr) == N00B_ARCH_UNKNOWN);
    assert(n00b_binary_entrypoint(nullptr) == 0);

    printf("  [PASS] abstract_accessors\n");
}

// ============================================================================
// n00b_parse_file
// ============================================================================

static void
test_parse_file(void)
{
    auto r = n00b_parse_file("/usr/bin/true");

    if (n00b_result_is_ok(r)) {
        n00b_binary_t *b = n00b_result_get(r);
        assert(b != nullptr);
        assert(n00b_binary_format(b) == N00B_FMT_MACHO
               || n00b_binary_format(b) == N00B_FMT_ELF);
        printf("  [PASS] parse_file\n");
    }
    else {
        printf("  [SKIP] parse_file (/usr/bin/true not found)\n");
    }

    // Non-existent file.
    auto r2 = n00b_parse_file("/nonexistent/file");
    assert(n00b_result_is_err(r2));

    printf("  [PASS] parse_file_error\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running detect tests...\n");

    test_detect_elf();
    test_detect_macho_64();
    test_detect_macho_fat();
    test_detect_unknown();
    test_detect_too_small();
    test_detect_preserves_pos();
    test_detect_real_binary();
    test_abstract_accessors();
    test_parse_file();

    printf("All detect tests passed.\n");
    return 0;
}

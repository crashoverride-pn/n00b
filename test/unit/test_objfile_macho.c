#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"

#include "objfile_macho_casegen.h"

// ============================================================================
// Helper: write values at a byte pointer (native endian, x86/ARM = LE)
// ============================================================================

static void
put16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, 2);
}

static void
put32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

static void
put64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, 8);
}

// ============================================================================
// Helper: build a minimal synthetic Mach-O 64-bit binary
// ============================================================================

static n00b_buffer_t *
make_minimal_macho64(void)
{
    size_t total_size = 128;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;

    uint8_t *p = (uint8_t *)buf->data;

    // mach_header_64 (32 bytes)
    put32(p + 0, MH_MAGIC_64);
    put32(p + 4, CPU_TYPE_X86_64);
    put32(p + 8, CPU_SUBTYPE_X86_64_ALL);
    put32(p + 12, MH_EXECUTE);
    put32(p + 16, 1);           // ncmds
    put32(p + 20, 72);          // sizeofcmds
    put32(p + 24, MH_PIE | MH_DYLDLINK | MH_TWOLEVEL);
    // reserved = 0

    // LC_SEGMENT_64 (offset 32, 72 bytes)
    uint8_t *lc = p + 32;
    put32(lc + 0, LC_SEGMENT_64);
    put32(lc + 4, 72);
    memcpy(lc + 8, "__TEXT", 6);
    put64(lc + 24, 0x100000000ULL);  // vmaddr
    put64(lc + 32, total_size);       // vmsize
    put64(lc + 40, 0);                // fileoff
    put64(lc + 48, total_size);       // filesize
    put32(lc + 56, 5);                // maxprot (r-x)
    put32(lc + 60, 5);                // initprot
    // nsects = 0, flags = 0

    return buf;
}

// ============================================================================
// Helper: Mach-O 64 with symbol table
// ============================================================================

static n00b_buffer_t *
make_macho64_with_symtab(void)
{
    // Layout:
    //   [0]    mach_header_64          32 bytes
    //   [32]   LC_SEGMENT_64 __TEXT    72 bytes (0 sections)
    //   [104]  LC_SYMTAB               24 bytes
    //   [128]  string table            16 bytes: \0_main\0_helper\0
    //   [144]  nlist_64 entries        2 * 16 = 32 bytes
    //   Total: 176, round to 256

    size_t total_size = 256;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;

    uint8_t *p = (uint8_t *)buf->data;

    // mach_header_64
    put32(p + 0, MH_MAGIC_64);
    put32(p + 4, CPU_TYPE_X86_64);
    put32(p + 8, CPU_SUBTYPE_X86_64_ALL);
    put32(p + 12, MH_EXECUTE);
    put32(p + 16, 2);                    // ncmds
    put32(p + 20, 72 + 24);              // sizeofcmds
    put32(p + 24, MH_PIE);

    // LC_SEGMENT_64 __TEXT (offset 32)
    uint8_t *seg = p + 32;
    put32(seg + 0, LC_SEGMENT_64);
    put32(seg + 4, 72);
    memcpy(seg + 8, "__TEXT", 6);
    put64(seg + 24, 0x100000000ULL);
    put64(seg + 32, total_size);
    put64(seg + 40, 0);
    put64(seg + 48, total_size);
    put32(seg + 56, 5);
    put32(seg + 60, 5);

    // LC_SYMTAB (offset 104)
    uint8_t *lc = p + 104;
    put32(lc + 0, LC_SYMTAB);
    put32(lc + 4, 24);
    put32(lc + 8, 144);         // symoff
    put32(lc + 12, 2);          // nsyms
    put32(lc + 16, 128);        // stroff
    put32(lc + 20, 16);         // strsize

    // String table at 128: "\0_main\0_helper\0"
    //   0:\0  1:_main  7:\0  8:_helper  15:\0  (wait, "_helper" is 7 chars)
    //   Actually: \0 _ m a i n \0 _ h e l p e r \0
    //              0  1 2 3 4 5  6  7 8 9 10 11 12 13 14
    // That's 15 bytes but we allocated 16.
    uint8_t *str = p + 128;
    str[0] = '\0';
    memcpy(str + 1, "_main", 5);
    str[6] = '\0';
    memcpy(str + 7, "_helper", 7);
    str[14] = '\0';

    // nlist_64 entries at 144 (each 16 bytes)
    // struct nlist_64: n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8)

    // [0] _main: N_SECT | N_EXT, sect=1, value=0x100001000
    uint8_t *n0 = p + 144;
    put32(n0 + 0, 1);                      // n_strx -> "_main"
    n0[4] = N_SECT | N_EXT;                // n_type
    n0[5] = 1;                              // n_sect
    put16(n0 + 6, 0);                      // n_desc
    put64(n0 + 8, 0x100001000ULL);         // n_value

    // [1] _helper: N_SECT, sect=1, value=0x100001100
    uint8_t *n1 = p + 160;
    put32(n1 + 0, 7);                      // n_strx -> "_helper"
    n1[4] = N_SECT;                        // n_type
    n1[5] = 1;                              // n_sect
    put16(n1 + 6, 0);                      // n_desc
    put64(n1 + 8, 0x100001100ULL);         // n_value

    return buf;
}

// ============================================================================
// Helper: Mach-O 64 with dylib
// ============================================================================

static n00b_buffer_t *
make_macho64_with_dylib(void)
{
    // Layout:
    //   [0]    mach_header_64               32 bytes
    //   [32]   LC_SEGMENT_64 __TEXT          72 bytes
    //   [104]  LC_LOAD_DYLIB                 64 bytes (cmd=12, cmdsize=64)
    //          name_offset=24, then dylib path at +24
    //   Total: 168, round to 256

    size_t total_size = 256;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;

    uint8_t *p = (uint8_t *)buf->data;

    // mach_header_64
    put32(p + 0, MH_MAGIC_64);
    put32(p + 4, CPU_TYPE_X86_64);
    put32(p + 8, CPU_SUBTYPE_X86_64_ALL);
    put32(p + 12, MH_EXECUTE);
    put32(p + 16, 2);           // ncmds
    put32(p + 20, 72 + 64);     // sizeofcmds
    put32(p + 24, MH_PIE | MH_DYLDLINK | MH_TWOLEVEL);

    // LC_SEGMENT_64 __TEXT (offset 32)
    uint8_t *seg = p + 32;
    put32(seg + 0, LC_SEGMENT_64);
    put32(seg + 4, 72);
    memcpy(seg + 8, "__TEXT", 6);
    put64(seg + 24, 0x100000000ULL);
    put64(seg + 32, total_size);
    put64(seg + 40, 0);
    put64(seg + 48, total_size);
    put32(seg + 56, 5);
    put32(seg + 60, 5);

    // LC_LOAD_DYLIB (offset 104)
    // struct: cmd(4) cmdsize(4) name_offset(4) timestamp(4) current_version(4) compat_version(4)
    // then the dylib path string at cmd_start + name_offset
    uint8_t *dl = p + 104;
    put32(dl + 0, LC_LOAD_DYLIB);
    put32(dl + 4, 64);          // cmdsize
    put32(dl + 8, 24);          // name_offset (relative to cmd start)
    put32(dl + 12, 0);          // timestamp
    put32(dl + 16, 0x010000);   // current_version
    put32(dl + 20, 0x010000);   // compat_version

    // Dylib path at offset 104 + 24 = 128
    const char *dylib_path = "/usr/lib/libSystem.B.dylib";
    memcpy(dl + 24, dylib_path, strlen(dylib_path));

    return buf;
}

// ============================================================================
// Test: parse synthetic Mach-O 64
// ============================================================================

static void
test_parse_synthetic_macho64(void)
{
    n00b_buffer_t *buf = make_minimal_macho64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse(s);

    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);

    assert(fat->count == 1);

    n00b_macho_binary_t *bin = fat->binaries[0];

    assert(bin->header.magic == MH_MAGIC_64);
    assert(bin->header.cputype == (uint32_t)CPU_TYPE_X86_64);
    assert(bin->header.filetype == MH_EXECUTE);
    assert(bin->header.ncmds == 1);
    assert(bin->header.flags & MH_PIE);

    // Should have 1 segment.
    assert(bin->num_segments == 1);
    assert(strcmp(bin->segments[0].name, "__TEXT") == 0);
    assert(bin->segments[0].vmaddr == 0x100000000ULL);

    printf("  [PASS] parse_synthetic_macho64\n");
}

// ============================================================================
// Test: parse bad magic
// ============================================================================

static void
test_parse_bad_magic(void)
{
    uint8_t data[64] = {};

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)data, sizeof(data));
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse(s);

    // Should fail because magic doesn't match.
    assert(n00b_result_is_err(r));

    printf("  [PASS] parse_bad_magic\n");
}

// ============================================================================
// Test: null stream
// ============================================================================

static void
test_null_stream(void)
{
    auto r = n00b_macho_parse(nullptr);

    assert(n00b_result_is_err(r));

    printf("  [PASS] null_stream\n");
}

// ============================================================================
// Test: parse real binary (/usr/bin/true on macOS)
// ============================================================================

static void
test_parse_real_binary(void)
{
    auto stream_r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_err(stream_r)) {
        printf("  [SKIP] parse_real_binary (file not found)\n");
        return;
    }

    n00b_bstream_t *s = n00b_result_get(stream_r);

    // Check if it's MachO.
    if (n00b_buffer_len(s->buf) < 4) {
        printf("  [SKIP] parse_real_binary (file too small)\n");
        return;
    }

    uint32_t magic;
    memcpy(&magic, s->buf->data, 4);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64
        && magic != FAT_MAGIC && magic != FAT_CIGAM
        && magic != MH_MAGIC && magic != MH_CIGAM) {
        printf("  [SKIP] parse_real_binary (not MachO, probably Linux)\n");
        return;
    }

    auto r = n00b_macho_parse(s);

    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);

    assert(fat->count >= 1);

    // Use the first (or only) binary.
    n00b_macho_binary_t *bin = fat->binaries[0];

    // Header checks.
    assert(bin->header.magic == MH_MAGIC_64);
    assert(bin->header.filetype == MH_EXECUTE);
    assert(bin->header.ncmds > 0);

    // Should have segments.
    assert(bin->num_segments > 0);

    // Query API: __TEXT segment.
    n00b_option_t(n00b_macho_segment_t *) text_opt
        = n00b_macho_segment_by_name(bin, "__TEXT");
    assert(n00b_option_is_set(text_opt));
    n00b_macho_segment_t *text = n00b_option_get(text_opt);

    // Query API: __LINKEDIT segment.
    assert(n00b_macho_has_segment(bin, "__LINKEDIT"));

    // Query API: LC_SEGMENT_64 command.
    n00b_option_t(n00b_macho_command_t *) seg_cmd_opt
        = n00b_macho_command_by_type(bin, LC_SEGMENT_64);
    assert(n00b_option_is_set(seg_cmd_opt));

    // Should have some symbols.
    printf("    cputype: 0x%x, filetype: %u, ncmds: %u\n",
           bin->header.cputype, bin->header.filetype, bin->header.ncmds);
    printf("    segments: %u, symbols: %u\n",
           bin->num_segments, bin->num_symbols);
    printf("    dylibs: %u, bindings: %u, exports: %u\n",
           bin->num_dylibs, bin->num_bindings, bin->num_exports);

    if (bin->dylinker && bin->dylinker->u8_bytes > 0) {
        printf("    dylinker: %s\n", bin->dylinker->data);
    }

    // Query API: check for libSystem via substring match.
    if (bin->num_dylibs > 0) {
        n00b_option_t(n00b_macho_dylib_t *) libsys_opt
            = n00b_macho_dylib_by_name(bin, "libSystem");

        if (n00b_option_is_set(libsys_opt)) {
            n00b_macho_dylib_t *libsys = n00b_option_get(libsys_opt);
            printf("    libSystem found: %s\n", libsys->name->data);
        }
    }

    // Check sections within __TEXT segment.
    if (text->nsects > 0) {
        printf("    __TEXT has %u sections\n", text->nsects);
    }

    // Entrypoint check.
    if (n00b_macho_has_entrypoint(bin)) {
        printf("    entrypoint: 0x%llx\n", (unsigned long long)bin->entrypoint);
    }

    // Fat binary detection.
    if (fat->count > 1) {
        printf("    fat binary with %u architectures\n", fat->count);

        for (uint32_t i = 0; i < fat->count; i++) {
            printf("      arch[%u]: cputype=0x%x\n",
                   i, fat->binaries[i]->header.cputype);
        }
    }

    printf("  [PASS] parse_real_binary\n");
}

// ============================================================================
// Test: parse_single API
// ============================================================================

static void
test_parse_single(void)
{
    n00b_buffer_t *buf = make_minimal_macho64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);

    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    assert(bin->header.magic == MH_MAGIC_64);
    assert(bin->num_segments == 1);

    printf("  [PASS] parse_single\n");
}

// ============================================================================
// Test: symtab parsing
// ============================================================================

static void
test_symtab_parsing(void)
{
    n00b_buffer_t *buf = make_macho64_with_symtab();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    // Symbol parsing is lazy; materialize before reading num_symbols directly.
    n00b_macho_ensure_symbols(bin);
    assert(bin->num_symbols == 2);

    // [0] _main
    assert(strcmp(bin->symbols[0].name->data, "_main") == 0);
    assert((bin->symbols[0].type & N_TYPE) == N_SECT);
    assert(bin->symbols[0].type & N_EXT);
    assert(bin->symbols[0].value == 0x100001000ULL);

    // [1] _helper
    assert(strcmp(bin->symbols[1].name->data, "_helper") == 0);
    assert((bin->symbols[1].type & N_TYPE) == N_SECT);
    assert(bin->symbols[1].value == 0x100001100ULL);

    printf("  [PASS] symtab_parsing\n");
}

// ============================================================================
// Test: dylib parsing
// ============================================================================

static void
test_dylib_parsing(void)
{
    n00b_buffer_t *buf = make_macho64_with_dylib();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    assert(bin->num_dylibs >= 1);
    assert(strstr(bin->dylibs[0].name->data, "libSystem.B.dylib") != nullptr);

    printf("  [PASS] dylib_parsing\n");
}

// ============================================================================
// Test: segment_by_name query
// ============================================================================

static void
test_segment_by_name(void)
{
    n00b_buffer_t *buf = make_minimal_macho64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    n00b_option_t(n00b_macho_segment_t *) text_opt
        = n00b_macho_segment_by_name(bin, "__TEXT");
    assert(n00b_option_is_set(text_opt));
    n00b_macho_segment_t *text = n00b_option_get(text_opt);
    assert(text->vmaddr == 0x100000000ULL);

    assert(!n00b_option_is_set(n00b_macho_segment_by_name(bin, "__DATA")));

    printf("  [PASS] segment_by_name\n");
}

// ============================================================================
// Test: symbol_by_name query
// ============================================================================

static void
test_symbol_by_name(void)
{
    n00b_buffer_t *buf = make_macho64_with_symtab();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    n00b_option_t(n00b_macho_symbol_t *) main_opt
        = n00b_macho_symbol_by_name(bin, "_main");
    assert(n00b_option_is_set(main_opt));
    n00b_macho_symbol_t *main_sym = n00b_option_get(main_opt);
    assert(main_sym->value == 0x100001000ULL);

    n00b_option_t(n00b_macho_symbol_t *) helper_opt
        = n00b_macho_symbol_by_name(bin, "_helper");
    assert(n00b_option_is_set(helper_opt));
    n00b_macho_symbol_t *helper = n00b_option_get(helper_opt);
    assert(helper->value == 0x100001100ULL);

    printf("  [PASS] symbol_by_name\n");
}

// ============================================================================
// Test: dylib_by_name query (substring)
// ============================================================================

static void
test_dylib_by_name(void)
{
    n00b_buffer_t *buf = make_macho64_with_dylib();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    // Substring match.
    assert(n00b_option_is_set(n00b_macho_dylib_by_name(bin, "libSystem")));

    // Full path should also work.
    assert(n00b_option_is_set(
        n00b_macho_dylib_by_name(bin, "/usr/lib/libSystem.B.dylib")));

    // Non-existent.
    assert(!n00b_option_is_set(n00b_macho_dylib_by_name(bin, "libFoo")));

    printf("  [PASS] dylib_by_name\n");
}

// ============================================================================
// Test: command_by_type query
// ============================================================================

static void
test_command_by_type(void)
{
    n00b_buffer_t *buf = make_macho64_with_dylib();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    n00b_option_t(n00b_macho_command_t *) seg_opt
        = n00b_macho_command_by_type(bin, LC_SEGMENT_64);
    assert(n00b_option_is_set(seg_opt));
    n00b_macho_command_t *seg = n00b_option_get(seg_opt);
    assert(seg->cmd == LC_SEGMENT_64);

    n00b_option_t(n00b_macho_command_t *) dylib_opt
        = n00b_macho_command_by_type(bin, LC_LOAD_DYLIB);
    assert(n00b_option_is_set(dylib_opt));
    n00b_macho_command_t *dylib = n00b_option_get(dylib_opt);
    assert(dylib->cmd == LC_LOAD_DYLIB);

    printf("  [PASS] command_by_type\n");
}

// ============================================================================
// Test: not-found returns nullptr
// ============================================================================

static void
test_not_found_returns_null(void)
{
    n00b_buffer_t *buf = make_minimal_macho64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    assert(!n00b_option_is_set(n00b_macho_segment_by_name(bin, "__DATA")));
    assert(!n00b_option_is_set(
        n00b_macho_section_by_name(bin, "__TEXT", "__text")));
    assert(!n00b_option_is_set(n00b_macho_symbol_by_name(bin, "_nosuch")));
    assert(!n00b_option_is_set(n00b_macho_dylib_by_name(bin, "libFoo")));
    assert(!n00b_option_is_set(n00b_macho_export_by_name(bin, "_nosuch")));
    assert(!n00b_option_is_set(n00b_macho_binding_by_symbol(bin, "_nosuch")));
    assert(!n00b_option_is_set(
        n00b_macho_command_by_type(bin, LC_LOAD_DYLIB)));

    // Predicates.
    assert(n00b_macho_has_segment(bin, "__TEXT"));
    assert(!n00b_macho_has_segment(bin, "__DATA"));
    assert(!n00b_macho_has_dylib(bin, "libFoo"));
    assert(!n00b_macho_has_entrypoint(bin));

    // nullptr safety.
    assert(!n00b_option_is_set(n00b_macho_segment_by_name(nullptr, "__TEXT")));
    assert(!n00b_option_is_set(n00b_macho_symbol_by_name(nullptr, "_main")));
    assert(!n00b_macho_has_entrypoint(nullptr));
    assert(!n00b_option_is_set(
        n00b_macho_fat_by_cputype(nullptr, CPU_TYPE_X86_64)));

    printf("  [PASS] not_found_returns_null\n");
}

// ============================================================================
// Test: has_entrypoint on real binary
// ============================================================================

static void
test_has_entrypoint(void)
{
    auto stream_r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_err(stream_r)) {
        printf("  [SKIP] has_entrypoint (file not found)\n");
        return;
    }

    n00b_bstream_t *s = n00b_result_get(stream_r);

    if (n00b_buffer_len(s->buf) < 4) {
        printf("  [SKIP] has_entrypoint (file too small)\n");
        return;
    }

    uint32_t magic;
    memcpy(&magic, s->buf->data, 4);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64
        && magic != FAT_MAGIC && magic != FAT_CIGAM) {
        printf("  [SKIP] has_entrypoint (not MachO)\n");
        return;
    }

    auto r = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);
    n00b_macho_binary_t *bin = fat->binaries[0];

    // A real executable should have an entrypoint from LC_MAIN.
    assert(n00b_macho_has_entrypoint(bin));

    printf("  [PASS] has_entrypoint\n");
}

// ============================================================================
// Test: code signature parsing on real binary
// ============================================================================

static void
test_code_signature_real(void)
{
    auto stream_r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_err(stream_r)) {
        printf("  [SKIP] code_signature_real (file not found)\n");
        return;
    }

    n00b_bstream_t *s = n00b_result_get(stream_r);

    if (n00b_buffer_len(s->buf) < 4) {
        printf("  [SKIP] code_signature_real (file too small)\n");
        return;
    }

    uint32_t magic;
    memcpy(&magic, s->buf->data, 4);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64
        && magic != FAT_MAGIC && magic != FAT_CIGAM) {
        printf("  [SKIP] code_signature_real (not MachO)\n");
        return;
    }

    auto r = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);
    assert(fat->count >= 1);

    // Check each slice for code signature.
    bool found_codesig = false;

    for (uint32_t i = 0; i < fat->count; i++) {
        n00b_macho_binary_t *bin = fat->binaries[i];

        if (bin->code_signature == nullptr) {
            continue;
        }

        found_codesig = true;

        // Raw code signature data should exist.
        assert(bin->code_signature->data != nullptr);
        assert(bin->code_signature->datasize > 0);

        // Parsed code signature should exist.
        n00b_option_t(n00b_macho_code_signature_parsed_t *) csp_opt
            = n00b_macho_get_code_signature(bin);
        assert(n00b_option_is_set(csp_opt));
        n00b_macho_code_signature_parsed_t *csp = n00b_option_get(csp_opt);
        assert(csp->num_blobs > 0);

        // Code directory should be parsed.
        assert(csp->code_directory != nullptr);

        // /usr/bin/true has identifier "com.apple.true".
        n00b_option_t(n00b_string_t *) ident_opt
            = n00b_macho_codesign_identifier(bin);
        assert(n00b_option_is_set(ident_opt));
        n00b_string_t *ident = n00b_option_get(ident_opt);
        assert(strstr(ident->data, "com.apple.true") != nullptr);

        // Version should be >= 0x20000 (CodeDirectory v2).
        assert(csp->code_directory->version >= 0x20000);

        // Hash type should be SHA-1 or SHA-256.
        assert(csp->code_directory->hash_type == CS_HASHTYPE_SHA1
            || csp->code_directory->hash_type == CS_HASHTYPE_SHA256);

        // Page size should be a power of 2.
        assert(csp->code_directory->page_size > 0);
        assert((csp->code_directory->page_size
                & (csp->code_directory->page_size - 1)) == 0);
    }

    assert(found_codesig);
    printf("  [PASS] code_signature_real\n");
}

// ============================================================================
// Helper: write big-endian uint32_t
// ============================================================================

static void
put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

// ============================================================================
// Test: synthetic code signature parsing
// ============================================================================

static void
test_code_signature_synthetic(void)
{
    // Build a minimal MachO with an LC_CODE_SIGNATURE pointing to a
    // synthetic SuperBlob containing a CodeDirectory and entitlements.

    // Layout:
    //   [0..31]     mach_header_64
    //   [32..103]   LC_SEGMENT_64 (__TEXT, covers entire file)
    //   [104..115]  LC_CODE_SIGNATURE (dataoff=256, datasize=TBD)
    //   [256..]     SuperBlob data

    // CodeDirectory blob:
    //   magic(4) + length(4) + version(4) + flags(4) + hashOffset(4)
    //   + identOffset(4) + nSpecialSlots(4) + nCodeSlots(4)
    //   + codeLimit(4) + hashSize(1) + hashType(1) + platform(1)
    //   + pageSize(1) + spare2(4) = 44 bytes header
    //   Then identifier string "test.codesig\0" at offset 44 = 13 bytes
    //   Total CD blob = 57 bytes

    const char *ident_str = "test.codesig";
    size_t ident_len = strlen(ident_str);  // 12
    size_t cd_blob_size = 44 + ident_len + 1;  // 57

    // Entitlements blob:
    //   magic(4) + length(4) + xml data
    const char *ent_xml = "<plist><dict><key>test</key><true/></dict></plist>";
    size_t ent_xml_len = strlen(ent_xml);
    size_t ent_blob_size = 8 + ent_xml_len;

    // SuperBlob: magic(4) + length(4) + count(4) + 2 index entries (8 each)
    //   = 12 + 16 = 28 byte header
    //   Blob 0 (CodeDirectory) at offset 28
    //   Blob 1 (Entitlements)  at offset 28 + cd_blob_size
    size_t sb_header = 12 + 2 * 8;  // 28
    size_t sb_total  = sb_header + cd_blob_size + ent_blob_size;

    size_t cs_off = 256;
    size_t total_size = cs_off + sb_total;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;

    uint8_t *p = (uint8_t *)buf->data;

    // mach_header_64
    put32(p + 0, MH_MAGIC_64);
    put32(p + 4, CPU_TYPE_X86_64);
    put32(p + 8, CPU_SUBTYPE_X86_64_ALL);
    put32(p + 12, MH_EXECUTE);
    put32(p + 16, 2);           // ncmds
    put32(p + 20, 72 + 12);     // sizeofcmds (segment + codesig)
    put32(p + 24, MH_PIE);

    // LC_SEGMENT_64 [32..103]
    uint8_t *lc = p + 32;
    put32(lc + 0, LC_SEGMENT_64);
    put32(lc + 4, 72);          // cmdsize
    memcpy(lc + 8, "__TEXT", 6);
    put64(lc + 24, 0x100000000ULL);  // vmaddr
    put64(lc + 32, total_size);       // vmsize
    put64(lc + 40, 0);               // fileoff
    put64(lc + 48, total_size);       // filesize
    put32(lc + 56, 5);               // maxprot
    put32(lc + 60, 5);               // initprot
    put32(lc + 64, 0);               // nsects
    put32(lc + 68, 0);               // flags

    // LC_CODE_SIGNATURE [104..115]
    uint8_t *cs_lc = p + 104;
    put32(cs_lc + 0, LC_CODE_SIGNATURE);
    put32(cs_lc + 4, 16);            // cmdsize for linkedit_data_command
    put32(cs_lc + 8, (uint32_t)cs_off);   // dataoff
    put32(cs_lc + 12, (uint32_t)sb_total); // datasize

    // SuperBlob at cs_off
    uint8_t *sb = p + cs_off;
    put_be32(sb + 0, CSMAGIC_EMBEDDED_SIGNATURE);
    put_be32(sb + 4, (uint32_t)sb_total);
    put_be32(sb + 8, 2);  // count = 2 blobs

    // Blob index [0]: CodeDirectory at offset sb_header
    put_be32(sb + 12, CSSLOT_CODEDIRECTORY);
    put_be32(sb + 16, (uint32_t)sb_header);

    // Blob index [1]: Entitlements at offset sb_header + cd_blob_size
    put_be32(sb + 20, CSSLOT_ENTITLEMENTS);
    put_be32(sb + 24, (uint32_t)(sb_header + cd_blob_size));

    // CodeDirectory blob
    uint8_t *cd = sb + sb_header;
    put_be32(cd + 0, CSMAGIC_CODEDIRECTORY);
    put_be32(cd + 4, (uint32_t)cd_blob_size);
    put_be32(cd + 8, 0x20400);       // version
    put_be32(cd + 12, 0);            // flags
    put_be32(cd + 16, 0);            // hashOffset (unused in our test)
    put_be32(cd + 20, 44);           // identOffset
    put_be32(cd + 24, 0);            // nSpecialSlots
    put_be32(cd + 28, 0);            // nCodeSlots
    put_be32(cd + 32, 0);            // codeLimit
    cd[36] = 32;                     // hashSize (SHA256)
    cd[37] = CS_HASHTYPE_SHA256;     // hashType
    cd[38] = 0;                      // platform
    cd[39] = 12;                     // pageSize = 1 << 12 = 4096

    // Identifier string at CD offset 44
    memcpy(cd + 44, ident_str, ident_len + 1);

    // Entitlements blob
    uint8_t *ent = sb + sb_header + cd_blob_size;
    put_be32(ent + 0, CSMAGIC_EMBEDDED_ENTITLEMENTS);
    put_be32(ent + 4, (uint32_t)ent_blob_size);
    memcpy(ent + 8, ent_xml, ent_xml_len);

    // Parse
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    // Verify raw code signature
    assert(bin->code_signature != nullptr);
    assert(bin->code_signature->dataoff == cs_off);
    assert(bin->code_signature->datasize == sb_total);

    // Verify parsed code signature
    n00b_option_t(n00b_macho_code_signature_parsed_t *) csp_opt
        = n00b_macho_get_code_signature(bin);
    assert(n00b_option_is_set(csp_opt));
    n00b_macho_code_signature_parsed_t *csp = n00b_option_get(csp_opt);
    assert(csp->num_blobs == 2);

    // Verify code directory
    assert(csp->code_directory != nullptr);
    assert(csp->code_directory->version == 0x20400);
    assert(csp->code_directory->hash_type == CS_HASHTYPE_SHA256);
    assert(csp->code_directory->hash_size == 32);
    assert(csp->code_directory->page_size == 4096);

    // Verify identifier
    n00b_option_t(n00b_string_t *) id_opt = n00b_macho_codesign_identifier(bin);
    assert(n00b_option_is_set(id_opt));
    n00b_string_t *id = n00b_option_get(id_opt);
    assert(strcmp(id->data, "test.codesig") == 0);

    // Verify entitlements
    n00b_option_t(n00b_string_t *) ent_opt = n00b_macho_get_entitlements(bin);
    assert(n00b_option_is_set(ent_opt));
    n00b_string_t *ent_str = n00b_option_get(ent_opt);
    assert(strstr(ent_str->data, "<plist>") != nullptr);
    assert(strstr(ent_str->data, "test") != nullptr);

    // Verify query functions on binary without code sig return none
    n00b_macho_binary_t empty = {0};
    assert(!n00b_option_is_set(n00b_macho_get_code_signature(&empty)));
    assert(!n00b_option_is_set(n00b_macho_get_entitlements(&empty)));
    assert(!n00b_option_is_set(n00b_macho_codesign_identifier(&empty)));
    assert(!n00b_option_is_set(n00b_macho_codesign_team_id(&empty)));

    printf("  [PASS] code_signature_synthetic\n");
}

// ============================================================================
// Test: chained fixups parsing on real binary
// ============================================================================

static void
test_chained_fixups_real(void)
{
    // Use /usr/bin/grep which has real imports (unlike /usr/bin/true).
    auto stream_r = n00b_bstream_from_file("/usr/bin/grep");

    if (n00b_result_is_err(stream_r)) {
        printf("  [SKIP] chained_fixups_real (file not found)\n");
        return;
    }

    n00b_bstream_t *s = n00b_result_get(stream_r);

    if (n00b_buffer_len(s->buf) < 4) {
        printf("  [SKIP] chained_fixups_real (file too small)\n");
        return;
    }

    uint32_t magic;
    memcpy(&magic, s->buf->data, 4);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64
        && magic != FAT_MAGIC && magic != FAT_CIGAM) {
        printf("  [SKIP] chained_fixups_real (not MachO)\n");
        return;
    }

    auto r = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);
    assert(fat->count >= 1);

    bool found_chained = false;

    for (uint32_t i = 0; i < fat->count; i++) {
        n00b_macho_binary_t *bin = fat->binaries[i];

        if (bin->chained_fixups == nullptr) {
            continue;
        }

        found_chained = true;

        n00b_macho_chained_fixups_t *cf = bin->chained_fixups;
        assert(cf->imports_format == DYLD_CHAINED_IMPORT
            || cf->imports_format == DYLD_CHAINED_IMPORT_ADDEND
            || cf->imports_format == DYLD_CHAINED_IMPORT_ADDEND64);

        printf("    arch=0x%x: %u imports, %u bindings, %u rebases, "
               "%u exports\n",
               bin->header.cputype, cf->num_imports,
               bin->num_bindings, bin->num_rebases, bin->num_exports);

        // /usr/bin/grep should have imports.
        assert(cf->num_imports > 0);

        // Each import should have a symbol name.
        for (uint32_t j = 0; j < cf->num_imports; j++) {
            assert(cf->imports[j].symbol_name != nullptr);
            assert(cf->imports[j].symbol_name->data != nullptr);
        }

        // Chained fixups should produce bindings and/or rebases.
        assert(bin->num_bindings > 0 || bin->num_rebases > 0);

        // Exports should be parsed via LC_DYLD_EXPORTS_TRIE. Export parsing is
        // lazy; materialize before reading num_exports directly.
        n00b_macho_ensure_exports(bin);
        assert(bin->num_exports > 0);
    }

    if (!found_chained) {
        printf("  [SKIP] chained_fixups_real (no chained fixups in binary)\n");
        return;
    }

    printf("  [PASS] chained_fixups_real\n");
}

// ============================================================================
// Test: synthetic chained fixups
// ============================================================================

static void
test_chained_fixups_synthetic(void)
{
    // Build a minimal MachO with LC_DYLD_CHAINED_FIXUPS.
    //
    // Layout:
    //   [0..31]       mach_header_64
    //   [32..103]     LC_SEGMENT_64 (__TEXT, file 0..512, vm 0x100000000)
    //   [104..175]    LC_SEGMENT_64 (__DATA, file 512..1024, vm 0x100001000)
    //   [176..191]    LC_DYLD_CHAINED_FIXUPS (dataoff=1024, datasize=TBD)
    //   [512..1023]   __DATA segment content (contains fixup chains)
    //   [1024..]      Chained fixups data in __LINKEDIT

    // Fixup data layout:
    //   [0..27]   dyld_chained_fixups_header
    //   [28..39]  dyld_chained_starts_in_image (seg_count=2, offsets)
    //   [40..63]  dyld_chained_starts_in_segment for __DATA
    //   [64..67]  one DYLD_CHAINED_IMPORT entry
    //   [68..]    symbol string "_exit\0"

    size_t data_seg_off   = 512;
    size_t data_seg_size  = 512;
    size_t linkedit_off   = 1024;

    // Build the fixup data first to know its size.
    // Header (28) + starts_in_image (12) + starts_in_segment (24) +
    // import (4) + symbol ("_exit\0" = 6) = 74 bytes
    size_t fixup_hdr_size = 28;
    size_t starts_img_off = fixup_hdr_size;   // 28
    size_t starts_img_size = 4 + 2 * 4;       // seg_count + 2 offsets = 12
    size_t starts_seg_off = starts_img_off + starts_img_size;  // 40
    size_t starts_seg_size = 22 + 2;           // header + 1 page_start = 24
    size_t imports_off_   = starts_seg_off + starts_seg_size;  // 64
    size_t symbols_off_   = imports_off_ + 4;  // 68
    const char *sym_name  = "_exit";
    size_t sym_len        = strlen(sym_name) + 1;  // 6
    size_t fixup_total    = symbols_off_ + sym_len;  // 74

    size_t total_size = linkedit_off + fixup_total;

    n00b_buffer_t *buf = n00b_buffer_new(total_size);
    memset(buf->data, 0, total_size);
    buf->byte_len = total_size;

    uint8_t *p = (uint8_t *)buf->data;

    // ---- mach_header_64 ----
    put32(p + 0, MH_MAGIC_64);
    put32(p + 4, CPU_TYPE_X86_64);
    put32(p + 8, CPU_SUBTYPE_X86_64_ALL);
    put32(p + 12, MH_EXECUTE);
    put32(p + 16, 3);               // ncmds
    put32(p + 20, 72 + 72 + 16);    // sizeofcmds
    put32(p + 24, MH_PIE);

    // ---- LC_SEGMENT_64 __TEXT [32..103] ----
    uint8_t *lc0 = p + 32;
    put32(lc0 + 0, LC_SEGMENT_64);
    put32(lc0 + 4, 72);
    memcpy(lc0 + 8, "__TEXT", 6);
    put64(lc0 + 24, 0x100000000ULL);
    put64(lc0 + 32, data_seg_off);
    put64(lc0 + 40, 0);
    put64(lc0 + 48, data_seg_off);
    put32(lc0 + 56, 5);
    put32(lc0 + 60, 5);

    // ---- LC_SEGMENT_64 __DATA [104..175] ----
    uint8_t *lc1 = p + 104;
    put32(lc1 + 0, LC_SEGMENT_64);
    put32(lc1 + 4, 72);
    memcpy(lc1 + 8, "__DATA", 6);
    put64(lc1 + 24, 0x100001000ULL);
    put64(lc1 + 32, data_seg_size);
    put64(lc1 + 40, data_seg_off);
    put64(lc1 + 48, data_seg_size);
    put32(lc1 + 56, 3);
    put32(lc1 + 60, 3);

    // ---- LC_DYLD_CHAINED_FIXUPS [176..191] ----
    uint8_t *lc2 = p + 176;
    put32(lc2 + 0, LC_DYLD_CHAINED_FIXUPS);
    put32(lc2 + 4, 16);
    put32(lc2 + 8, (uint32_t)linkedit_off);
    put32(lc2 + 12, (uint32_t)fixup_total);

    // ---- __DATA segment content ----
    // Place one DYLD_CHAINED_PTR_64 bind entry at offset 0 in __DATA.
    // Format: bit63=1 (bind), bits[51..62]=delta, bits[0..23]=ordinal(0)
    // Delta=2 means 2*4=8 bytes forward to next fixup.
    uint64_t bind_entry = (1ULL << 63) | ((uint64_t)2 << 51) | 0;
    memcpy(p + data_seg_off, &bind_entry, 8);

    // Place one DYLD_CHAINED_PTR_64 rebase at offset 8 in __DATA.
    // Format: bit63=0 (rebase), bits[51..62]=delta(0=end), bits[0..35]=target
    uint64_t rebase_entry = 0x100001234ULL;  // target address, delta=0
    memcpy(p + data_seg_off + 8, &rebase_entry, 8);

    // ---- Chained fixups data ----
    uint8_t *fx = p + linkedit_off;

    // Header
    put32(fx + 0, 0);                          // fixups_version
    put32(fx + 4, (uint32_t)starts_img_off);   // starts_offset
    put32(fx + 8, (uint32_t)imports_off_);     // imports_offset
    put32(fx + 12, (uint32_t)symbols_off_);    // symbols_offset
    put32(fx + 16, 1);                         // imports_count
    put32(fx + 20, DYLD_CHAINED_IMPORT);       // imports_format
    put32(fx + 24, 0);                         // symbols_format

    // Starts in image: seg_count=2, offset[0]=0, offset[1]=starts_seg_off
    uint8_t *si = fx + starts_img_off;
    put32(si + 0, 2);                          // seg_count
    put32(si + 4, 0);                          // __TEXT: no fixups
    put32(si + 8, (uint32_t)(starts_seg_off - starts_img_off));  // __DATA offset

    // Starts in segment for __DATA
    uint8_t *ss = fx + starts_seg_off;
    put32(ss + 0, (uint32_t)starts_seg_size);  // size
    uint16_t pg_size = 0x1000;
    memcpy(ss + 4, &pg_size, 2);               // page_size
    uint16_t ptr_fmt = DYLD_CHAINED_PTR_64;
    memcpy(ss + 6, &ptr_fmt, 2);               // pointer_format
    put64(ss + 8, data_seg_off);               // segment_offset (file offset)
    put32(ss + 16, 0);                         // max_valid_pointer
    uint16_t pg_count = 1;
    memcpy(ss + 20, &pg_count, 2);             // page_count
    uint16_t pg_start = 0;                     // chain starts at offset 0
    memcpy(ss + 22, &pg_start, 2);             // page_start[0]

    // Import entry: lib_ordinal=0xFF(-1=flat), weak=0, name_offset=0
    // Packed: (0 << 9) | (0 << 8) | 0xFF
    uint32_t import_entry = 0xFF;  // lib_ordinal=-1 (flat namespace)
    memcpy(fx + imports_off_, &import_entry, 4);

    // Symbol string
    memcpy(fx + symbols_off_, sym_name, sym_len);

    // ---- Parse ----
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto parse_r = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(parse_r));

    n00b_macho_binary_t *bin = n00b_result_get(parse_r);

    // Verify chained fixups struct.
    assert(bin->chained_fixups != nullptr);
    assert(bin->chained_fixups->num_imports == 1);
    assert(bin->chained_fixups->imports_format == DYLD_CHAINED_IMPORT);
    assert(strcmp(bin->chained_fixups->imports[0].symbol_name->data,
                 "_exit") == 0);
    assert(bin->chained_fixups->imports[0].lib_ordinal == -1);

    // Verify bindings were populated.
    assert(bin->num_bindings >= 1);
    assert(bin->bindings[0].address == 0x100001000ULL);  // __DATA vmaddr + 0
    assert(strcmp(bin->bindings[0].symbol_name->data, "_exit") == 0);

    // Verify rebases were populated.
    assert(bin->num_rebases >= 1);
    assert(bin->rebases[0].address == 0x100001000ULL + 8);  // offset 8

    printf("  [PASS] chained_fixups_synthetic\n");
}

// ============================================================================
// Phase-1 shape harness: build/load each fixture shape, parse, and assert
// the structural proof field. Always-runs and host-neutral.
// ============================================================================

// Resolve the committed SIG_PRESENT fixture. The always-run `macho`
// target has no workdir/env wired, so try MESON_SOURCE_ROOT (set for
// tests that opt in), then a project-root-relative path. Returns a
// stream or nullptr (caller [SKIP]s when the fixture cannot be opened —
// e.g. the committed fixture is absent on a non-arm64 checkout).
static n00b_bstream_t *
open_signed_fixture(void)
{
    static const char *rel = "test/unit/data/hello_signed_arm64.macho";

    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n > 0 && (size_t)n < sizeof(path)) {
            auto r = n00b_bstream_from_file(path);
            if (n00b_result_is_ok(r)) {
                return n00b_result_get(r);
            }
        }
    }

    auto r = n00b_bstream_from_file((char *)rel);
    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r);
    }

    return nullptr;
}

// Assert the shape property on a parsed (non-fat) binary.
static void
assert_shape(const n00b_test_macho_case_t *tc, n00b_macho_binary_t *bin)
{
    switch (tc->shape) {
    case N00B_TEST_MACHO_SHAPE_LC_SLACK: {
        // The first segment whose file offset is past the load-command
        // region end proves the slack. The LC region ends at
        // header(32) + sizeofcmds.
        uint64_t lc_end = 32 + (uint64_t)bin->header.sizeofcmds;
        bool     found  = false;

        for (uint32_t i = 0; i < bin->num_segments; i++) {
            if (bin->segments[i].fileoff > lc_end
                && bin->segments[i].filesize > 0) {
                found = true;
                break;
            }
        }

        assert(found);
        break;
    }
    case N00B_TEST_MACHO_SHAPE_LINKEDIT_NOT_LAST: {
        // Find __LINKEDIT, then prove some non-__LINKEDIT segment has a
        // higher file offset.
        bool     have_le      = false;
        uint64_t linkedit_off = 0;

        for (uint32_t i = 0; i < bin->num_segments; i++) {
            if (strcmp(bin->segments[i].name, "__LINKEDIT") == 0) {
                have_le      = true;
                linkedit_off = bin->segments[i].fileoff;
                break;
            }
        }

        assert(have_le);

        bool after = false;
        for (uint32_t i = 0; i < bin->num_segments; i++) {
            if (strcmp(bin->segments[i].name, "__LINKEDIT") != 0
                && bin->segments[i].fileoff > linkedit_off) {
                after = true;
                break;
            }
        }

        assert(after);
        break;
    }
    case N00B_TEST_MACHO_SHAPE_SIG_PRESENT:
        assert(bin->code_signature != nullptr);
        break;
    case N00B_TEST_MACHO_SHAPE_SIG_ABSENT:
        assert(bin->code_signature == nullptr);
        break;
    case N00B_TEST_MACHO_SHAPE_FAT_2SLICE:
        // Handled at the fat level in test_macho_shape_harness.
        break;
    }
}

static void
test_macho_shape_harness(void)
{
    for (size_t i = 0; i < n00b_test_macho_case_count; i++) {
        const n00b_test_macho_case_t *tc = &n00b_test_macho_cases[i];

        n00b_bstream_t *stream = nullptr;

        if (tc->shape == N00B_TEST_MACHO_SHAPE_SIG_PRESENT) {
            stream = open_signed_fixture();
            if (stream == nullptr) {
                printf("  [SKIP] shape:%s (committed fixture %s not found)\n",
                       tc->name,
                       "test/unit/data/hello_signed_arm64.macho");
                continue;
            }
        }
        else {
            auto build_r = n00b_test_macho_build_case(tc->generator);
            assert(n00b_result_is_ok(build_r));

            n00b_buffer_t *buf = n00b_result_get(build_r);
            stream             = n00b_bstream_new(buf);
        }

        auto parse_r = n00b_macho_parse(stream);

        bool parse_ok       = n00b_result_is_ok(parse_r);
        bool expect_ok      = (tc->expect_parse == N00B_TEST_MACHO_PARSE_OK);
        assert(parse_ok == expect_ok);

        if (!parse_ok) {
            printf("  [PASS] shape:%s parse=reject state=%s\n",
                   tc->name,
                   n00b_test_macho_case_state_name(tc->state));
            continue;
        }

        n00b_macho_fat_t *fat = n00b_result_get(parse_r);

        if (tc->shape == N00B_TEST_MACHO_SHAPE_FAT_2SLICE) {
            assert(fat->count == 2);

            // Each slice must parse to a well-formed binary.
            for (uint32_t s = 0; s < fat->count; s++) {
                assert(fat->binaries[s] != nullptr);
                assert(fat->binaries[s]->header.magic == MH_MAGIC_64);
            }
        }
        else {
            assert(fat->count == 1);
            assert_shape(tc, fat->binaries[0]);
        }

        printf("  [PASS] shape:%s parse=ok proof=%s state=%s\n",
               tc->name,
               n00b_test_macho_shape_name(tc->shape),
               n00b_test_macho_case_state_name(tc->state));
    }
}

// ============================================================================
// Phase 0 (WP-002, D-019/D-020): the FR-01 parser-model extension exposes the
// __LINKEDIT sub-region offsets/sizes, the per-command file_offset, and the
// fat per-slice descriptors. These always-run, host-neutral checks assert the
// newly-exposed fields against the existing fixtures.
// ============================================================================

// P0-a: __LINKEDIT sub-region offsets are exposed and lie within the
// __LINKEDIT segment's file extent. Uses the committed SIG_PRESENT fixture
// (a real signed arm64 binary with a populated __LINKEDIT).
static void
test_p0a_linkedit_regions(void)
{
    n00b_bstream_t *stream = open_signed_fixture();

    if (stream == nullptr) {
        printf("  [SKIP] p0a_linkedit_regions (committed fixture not found)\n");
        return;
    }

    auto r = n00b_macho_parse(stream);
    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t    *fat = n00b_result_get(r);
    n00b_macho_binary_t *bin = fat->binaries[0];

    // Locate the __LINKEDIT segment's file extent.
    bool     have_le = false;
    uint64_t le_off  = 0;
    uint64_t le_end  = 0;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (strcmp(bin->segments[i].name, "__LINKEDIT") == 0) {
            have_le = true;
            le_off  = bin->segments[i].fileoff;
            le_end  = le_off + bin->segments[i].filesize;
            break;
        }
    }

    assert(have_le);
    assert(le_end > le_off);

    // Helper: a populated region must be wholly inside [le_off, le_end).
    const n00b_macho_linkedit_region_t *regions[] = {
        &bin->symtab_nlist,
        &bin->symtab_strings,
        &bin->indirect_symtab,
        &bin->dyld_info,
        &bin->function_starts_region,
        &bin->data_in_code_region,
        &bin->chained_fixups_region,
    };

    bool any_populated = false;

    for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
        const n00b_macho_linkedit_region_t *reg = regions[i];

        if (reg->file_offset == 0 && reg->size == 0) {
            continue;  // Absent load command.
        }

        any_populated = true;
        assert(reg->file_offset >= le_off);
        assert(reg->size > 0);
        assert(reg->file_offset + reg->size <= le_end);
    }

    // A real signed binary must expose at least one __LINKEDIT sub-region.
    assert(any_populated);

    printf("  [PASS] p0a_linkedit_regions\n");
}

// P0-b: each fat slice {offset,size,align} is exposed; the slices are within
// the file and pairwise non-overlapping. Uses the FAT_2SLICE builder fixture.
static void
test_p0b_fat_slices(void)
{
    auto build_r = n00b_test_macho_build_case(N00B_TEST_MACHO_GEN_FAT_2SLICE);
    assert(n00b_result_is_ok(build_r));

    n00b_buffer_t  *buf    = n00b_result_get(build_r);
    uint64_t        file_len = (uint64_t)buf->byte_len;
    n00b_bstream_t *stream = n00b_bstream_new(buf);

    auto r = n00b_macho_parse(stream);
    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);

    assert(fat->count == 2);
    assert(fat->slices != nullptr);

    for (uint32_t i = 0; i < fat->count; i++) {
        n00b_macho_fat_slice_t *sl = &fat->slices[i];

        // cputype matches the parsed slice header (arm64 fixture).
        assert(sl->cputype == fat->binaries[i]->header.cputype);
        // offset matches the per-binary slice base.
        assert(sl->offset == fat->binaries[i]->fat_offset);
        // The slice extent lies within the file.
        assert(sl->size > 0);
        assert(sl->offset + sl->size <= file_len);
    }

    // The two slices must not overlap in file order.
    for (uint32_t i = 0; i < fat->count; i++) {
        for (uint32_t j = i + 1; j < fat->count; j++) {
            n00b_macho_fat_slice_t *a = &fat->slices[i];
            n00b_macho_fat_slice_t *b = &fat->slices[j];

            bool disjoint = (a->offset + a->size <= b->offset)
                         || (b->offset + b->size <= a->offset);
            assert(disjoint);
        }
    }

    printf("  [PASS] p0b_fat_slices\n");
}

// P0-c: a parsed command's file_offset equals N00B_MACHO_HEADER_64_SIZE plus the
// sum of all prior cmdsize values (the independent cmdsize-walk cross-check).
static void
test_p0c_command_file_offset(void)
{
    auto build_r = n00b_test_macho_build_case(N00B_TEST_MACHO_GEN_LC_SLACK);
    assert(n00b_result_is_ok(build_r));

    n00b_buffer_t  *buf    = n00b_result_get(build_r);
    n00b_bstream_t *stream = n00b_bstream_new(buf);

    auto r = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(r));

    n00b_macho_binary_t *bin = n00b_result_get(r);

    assert(bin->num_commands > 0);

    // Independently walk cmdsize from the header end and compare.
    uint64_t running = N00B_MACHO_HEADER_64_SIZE;

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        assert(bin->commands[i].file_offset == running);
        running += bin->commands[i].cmdsize;
    }

    printf("  [PASS] p0c_command_file_offset\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running MachO parser tests...\n");

    test_parse_synthetic_macho64();
    test_parse_bad_magic();
    test_null_stream();
    test_parse_real_binary();
    test_parse_single();
    test_symtab_parsing();
    test_dylib_parsing();
    test_segment_by_name();
    test_symbol_by_name();
    test_dylib_by_name();
    test_command_by_type();
    test_not_found_returns_null();
    test_has_entrypoint();
    test_code_signature_real();
    test_code_signature_synthetic();
    test_chained_fixups_real();
    test_chained_fixups_synthetic();
    test_macho_shape_harness();
    test_p0a_linkedit_regions();
    test_p0b_fat_slices();
    test_p0c_command_file_offset();

    printf("All MachO parser tests passed.\n");
    return 0;
}

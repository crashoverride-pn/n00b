#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/macho_build.h"

// ============================================================================
// Test: create empty binary
// ============================================================================

static void
test_binary_new(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    assert(bin != nullptr);
    assert(bin->header.magic == MH_MAGIC_64);
    assert(bin->header.cputype == (uint32_t)CPU_TYPE_ARM64);
    assert(bin->header.cpusubtype == CPU_SUBTYPE_ARM64_ALL);
    assert(bin->header.filetype == MH_EXECUTE);
    assert(bin->num_segments == 0);
    assert(bin->num_symbols == 0);
    assert(bin->num_dylibs == 0);

    printf("  [PASS] binary_new\n");
}

// ============================================================================
// Test: add segments and sections
// ============================================================================

static void
test_add_segments_sections(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    assert(text != nullptr);
    assert(bin->num_segments == 1);
    assert(strcmp(bin->segments[0].name, "__TEXT") == 0);
    assert(bin->segments[0].initprot == 5);
    assert(bin->segments[0].maxprot == 5);

    n00b_macho_section_t *text_text = n00b_macho_add_section(
        text, "__text", "__TEXT",
        S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS, 2);
    assert(text_text != nullptr);
    assert(text->nsects == 1);
    assert(strcmp(text_text->sectname, "__text") == 0);
    assert(strcmp(text_text->segname, "__TEXT") == 0);

    n00b_macho_segment_t *data = n00b_macho_add_segment(bin, "__DATA", 3, 3);
    assert(data != nullptr);
    assert(bin->num_segments == 2);

    n00b_macho_add_section(data, "__data", "__DATA", S_REGULAR, 3);
    assert(data->nsects == 1);

    printf("  [PASS] add_segments_sections\n");
}

// ============================================================================
// Test: add symbols
// ============================================================================

static void
test_add_symbols(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_symbol_t *main_sym = n00b_macho_add_symbol(
        bin, "_main", N_SECT | N_EXT, 1, 0, 0x100001000ULL);

    assert(main_sym != nullptr);
    assert(bin->num_symbols == 1);
    assert(strcmp(bin->symbols[0].name->data, "_main") == 0);
    assert(bin->symbols[0].type == (N_SECT | N_EXT));
    assert(bin->symbols[0].value == 0x100001000ULL);

    n00b_macho_add_symbol(bin, "_helper", N_SECT, 1, 0, 0x100001100ULL);
    assert(bin->num_symbols == 2);

    printf("  [PASS] add_symbols\n");
}

// ============================================================================
// Test: add dylibs
// ============================================================================

static void
test_add_dylibs(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_dylib_t *lib = n00b_macho_add_dylib(
        bin, "/usr/lib/libSystem.B.dylib", 0x010000, 0x010000);

    assert(lib != nullptr);
    assert(bin->num_dylibs == 1);
    assert(strstr(bin->dylibs[0].name->data, "libSystem") != nullptr);
    assert(lib->cmd == LC_LOAD_DYLIB);

    n00b_macho_add_dylib(bin, "/usr/lib/libc++.1.dylib", 0x010000, 0x010000);
    assert(bin->num_dylibs == 2);

    printf("  [PASS] add_dylibs\n");
}

// ============================================================================
// Test: add bindings
// ============================================================================

static void
test_add_bindings(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_binding_t *b = n00b_macho_add_binding(
        bin, "_printf", 1, 2, 0x100002000ULL, BIND_TYPE_POINTER, 0);

    assert(b != nullptr);
    assert(bin->num_bindings == 1);
    assert(strcmp(bin->bindings[0].symbol_name->data, "_printf") == 0);
    assert(bin->bindings[0].library_ordinal == 1);
    assert(bin->bindings[0].address == 0x100002000ULL);

    printf("  [PASS] add_bindings\n");
}

// ============================================================================
// Test: add rebases
// ============================================================================

static void
test_add_rebases(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_rebase_t *r = n00b_macho_add_rebase(
        bin, 2, 0x100002000ULL, REBASE_TYPE_POINTER);

    assert(r != nullptr);
    assert(bin->num_rebases == 1);
    assert(bin->rebases[0].segment_index == 2);
    assert(bin->rebases[0].address == 0x100002000ULL);

    printf("  [PASS] add_rebases\n");
}

// ============================================================================
// Test: add exports
// ============================================================================

static void
test_add_exports(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_export_t *e = n00b_macho_add_export(
        bin, "_main", 0x1000, EXPORT_SYMBOL_FLAGS_KIND_REGULAR);

    assert(e != nullptr);
    assert(bin->num_exports == 1);
    assert(strcmp(bin->exports[0].name->data, "_main") == 0);
    assert(bin->exports[0].address == 0x1000);

    printf("  [PASS] add_exports\n");
}

// ============================================================================
// Test: convenience setters
// ============================================================================

static void
test_convenience_setters(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_set_entry(bin, 0x1000, 0x100000);
    assert(bin->entrypoint == 0x1000);
    assert(bin->stack_size == 0x100000);

    n00b_macho_set_dylinker(bin, "/usr/lib/dyld");
    assert(strcmp(bin->dylinker->data, "/usr/lib/dyld") == 0);

    uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    n00b_macho_set_uuid(bin, uuid);
    assert(memcmp(bin->uuid, uuid, 16) == 0);

    printf("  [PASS] convenience_setters\n");
}

// ============================================================================
// Test: build minimal MachO (header + __TEXT), parse back
// ============================================================================

static void
test_build_minimal(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);
    assert(n00b_buffer_len(buf) > 32);

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->header.magic == MH_MAGIC_64);
    assert(parsed->header.cputype == (uint32_t)CPU_TYPE_ARM64);
    assert(parsed->header.filetype == MH_EXECUTE);
    assert(parsed->header.ncmds >= 1);

    // Should have __PAGEZERO + __TEXT at minimum.
    assert(parsed->num_segments >= 2);
    assert(n00b_macho_has_segment(parsed, "__PAGEZERO"));
    assert(n00b_macho_has_segment(parsed, "__TEXT"));

    printf("  [PASS] build_minimal\n");
}

// ============================================================================
// Test: build with symtab, parse back
// ============================================================================

static void
test_build_with_symtab(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_add_symbol(bin, "_main", N_SECT | N_EXT, 1, 0, 0x100001000ULL);
    n00b_macho_add_symbol(bin, "_helper", N_SECT, 1, 0, 0x100001100ULL);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    // Symbol parsing is lazy; materialize before reading num_symbols directly.
    n00b_macho_ensure_symbols(parsed);
    assert(parsed->num_symbols == 2);

    // Symbol sorting: local (_helper, no N_EXT) → extdef (_main, N_EXT).
    // After sort, _helper should come first.
    bool found_main   = false;
    bool found_helper = false;

    for (uint32_t i = 0; i < parsed->num_symbols; i++) {
        if (strcmp(parsed->symbols[i].name->data, "_main") == 0) {
            found_main = true;
            assert(parsed->symbols[i].value == 0x100001000ULL);
            assert(parsed->symbols[i].type & N_EXT);
        }

        if (strcmp(parsed->symbols[i].name->data, "_helper") == 0) {
            found_helper = true;
            assert(parsed->symbols[i].value == 0x100001100ULL);
        }
    }

    assert(found_main);
    assert(found_helper);

    // Should have __LINKEDIT segment.
    assert(n00b_macho_has_segment(parsed, "__LINKEDIT"));

    printf("  [PASS] build_with_symtab\n");
}

// ============================================================================
// Test: build with section data
// ============================================================================

static void
test_build_with_section_data(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    uint8_t code[] = {0xD6, 0x5F, 0x03, 0xC0}; // ret (ARM64)
    n00b_macho_section_t *sec = n00b_macho_add_section(
        text, "__text", "__TEXT",
        S_REGULAR | S_ATTR_PURE_INSTRUCTIONS, 2);
    sec->content = n00b_buffer_from_bytes((char *)code, sizeof(code));

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    // Find __text section in __TEXT segment.
    n00b_option_t(n00b_macho_section_t *) parsed_sec_opt
        = n00b_macho_section_by_name(parsed, "__TEXT", "__text");
    assert(n00b_option_is_set(parsed_sec_opt));
    n00b_macho_section_t *parsed_sec = n00b_option_get(parsed_sec_opt);
    assert(parsed_sec->size == sizeof(code));
    assert(parsed_sec->content != nullptr);
    assert(n00b_buffer_len(parsed_sec->content) == sizeof(code));
    assert(memcmp(parsed_sec->content->data, code, sizeof(code)) == 0);

    printf("  [PASS] build_with_section_data\n");
}

// ============================================================================
// Test: build with __TEXT + __DATA segments
// ============================================================================

static void
test_build_with_data_segment(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    uint8_t code[] = {0xD6, 0x5F, 0x03, 0xC0};
    n00b_macho_section_t *text_sec = n00b_macho_add_section(
        text, "__text", "__TEXT", S_REGULAR, 2);
    text_sec->content = n00b_buffer_from_bytes((char *)code, sizeof(code));

    n00b_macho_segment_t *data = n00b_macho_add_segment(bin, "__DATA", 3, 3);

    uint8_t bss[8] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    n00b_macho_section_t *data_sec = n00b_macho_add_section(
        data, "__data", "__DATA", S_REGULAR, 3);
    data_sec->content = n00b_buffer_from_bytes((char *)bss, sizeof(bss));

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(n00b_macho_has_segment(parsed, "__TEXT"));
    assert(n00b_macho_has_segment(parsed, "__DATA"));

    n00b_option_t(n00b_macho_segment_t *) parsed_text_opt
        = n00b_macho_segment_by_name(parsed, "__TEXT");
    n00b_option_t(n00b_macho_segment_t *) parsed_data_opt
        = n00b_macho_segment_by_name(parsed, "__DATA");

    assert(n00b_option_is_set(parsed_text_opt));
    assert(n00b_option_is_set(parsed_data_opt));
    n00b_macho_segment_t *parsed_text = n00b_option_get(parsed_text_opt);
    n00b_macho_segment_t *parsed_data = n00b_option_get(parsed_data_opt);

    // __DATA should come after __TEXT in memory.
    assert(parsed_data->vmaddr > parsed_text->vmaddr);

    printf("  [PASS] build_with_data_segment\n");
}

// ============================================================================
// Test: build with entrypoint (LC_MAIN)
// ============================================================================

static void
test_build_with_entry(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_set_entry(bin, 0x1000, 0);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(n00b_macho_has_entrypoint(parsed));
    assert(parsed->entrypoint == 0x1000);

    printf("  [PASS] build_with_entry\n");
}

// ============================================================================
// Test: build with dylibs
// ============================================================================

static void
test_build_with_dylibs(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_add_dylib(bin, "/usr/lib/libSystem.B.dylib", 0x010000, 0x010000);
    n00b_macho_add_dylib(bin, "/usr/lib/libc++.1.dylib", 0x010000, 0x010000);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->num_dylibs == 2);
    assert(n00b_macho_has_dylib(parsed, "libSystem"));
    assert(n00b_macho_has_dylib(parsed, "libc++"));

    printf("  [PASS] build_with_dylibs\n");
}

// ============================================================================
// Test: build with dylinker
// ============================================================================

static void
test_build_with_dylinker(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_set_dylinker(bin, "/usr/lib/dyld");

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->dylinker->data != nullptr);
    assert(strcmp(parsed->dylinker->data, "/usr/lib/dyld") == 0);

    printf("  [PASS] build_with_dylinker\n");
}

// ============================================================================
// Test: build with UUID
// ============================================================================

static void
test_build_with_uuid(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    uint8_t uuid[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    n00b_macho_set_uuid(bin, uuid);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(memcmp(parsed->uuid, uuid, 16) == 0);

    printf("  [PASS] build_with_uuid\n");
}

// ============================================================================
// Test: build with bindings (dyld info)
// ============================================================================

static void
test_build_with_bindings(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_segment_t *data = n00b_macho_add_segment(bin, "__DATA", 3, 3);
    (void)data;

    n00b_macho_add_dylib(bin, "/usr/lib/libSystem.B.dylib", 0x010000, 0x010000);

    n00b_macho_add_binding(bin, "_printf", 1, 2,
                           0x100002000ULL, BIND_TYPE_POINTER, 0);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    // Should have bindings.
    assert(parsed->num_bindings >= 1);

    n00b_option_t(n00b_macho_binding_t *) found_opt
        = n00b_macho_binding_by_symbol(parsed, "_printf");
    assert(n00b_option_is_set(found_opt));
    n00b_macho_binding_t *found = n00b_option_get(found_opt);
    assert(found->library_ordinal == 1);

    printf("  [PASS] build_with_bindings\n");
}

// ============================================================================
// Test: build with exports
// ============================================================================

static void
test_build_with_exports(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_add_export(bin, "_main", 0x1000,
                          EXPORT_SYMBOL_FLAGS_KIND_REGULAR);
    n00b_macho_add_export(bin, "_helper", 0x1100,
                          EXPORT_SYMBOL_FLAGS_KIND_REGULAR);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    // Export parsing is lazy; materialize before reading num_exports directly.
    n00b_macho_ensure_exports(parsed);
    assert(parsed->num_exports >= 2);

    n00b_option_t(n00b_macho_export_t *) main_exp_opt
        = n00b_macho_export_by_name(parsed, "_main");
    assert(n00b_option_is_set(main_exp_opt));
    n00b_macho_export_t *main_exp = n00b_option_get(main_exp_opt);
    assert(main_exp->address == 0x1000);

    n00b_option_t(n00b_macho_export_t *) helper_exp_opt
        = n00b_macho_export_by_name(parsed, "_helper");
    assert(n00b_option_is_set(helper_exp_opt));
    n00b_macho_export_t *helper_exp = n00b_option_get(helper_exp_opt);
    assert(helper_exp->address == 0x1100);

    printf("  [PASS] build_with_exports\n");
}

// ============================================================================
// Test: build with function starts
// ============================================================================

static void
test_build_with_function_starts(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    uint64_t func_addrs[] = {0x100001000ULL, 0x100001100ULL, 0x100001200ULL};
    n00b_macho_set_function_starts(bin, func_addrs, 3);

    n00b_macho_add_symbol(bin, "_f1", N_SECT | N_EXT, 1, 0, 0x100001000ULL);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->function_starts != nullptr);
    assert(parsed->function_starts->count == 3);
    assert(parsed->function_starts->addresses[0] == 0x100001000ULL);
    assert(parsed->function_starts->addresses[1] == 0x100001100ULL);
    assert(parsed->function_starts->addresses[2] == 0x100001200ULL);

    printf("  [PASS] build_with_function_starts\n");
}

// ============================================================================
// Test: round-trip — build, parse, verify all components
// ============================================================================

static void
test_round_trip(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    bin->header.flags = MH_PIE | MH_DYLDLINK | MH_TWOLEVEL;

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    uint8_t code[] = {0xD6, 0x5F, 0x03, 0xC0}; // ret
    n00b_macho_section_t *text_sec = n00b_macho_add_section(
        text, "__text", "__TEXT", S_REGULAR, 2);
    text_sec->content = n00b_buffer_from_bytes((char *)code, sizeof(code));

    n00b_macho_add_symbol(bin, "_main", N_SECT | N_EXT, 1, 0,
                          0x100001000ULL);

    n00b_macho_set_entry(bin, 0x1000, 0);

    uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    n00b_macho_set_uuid(bin, uuid);

    n00b_macho_set_dylinker(bin, "/usr/lib/dyld");

    // Build.
    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    // Verify header.
    assert(parsed->header.magic == MH_MAGIC_64);
    assert(parsed->header.cputype == (uint32_t)CPU_TYPE_ARM64);
    assert(parsed->header.filetype == MH_EXECUTE);
    assert(parsed->header.flags & MH_PIE);

    // Verify entrypoint.
    assert(n00b_macho_has_entrypoint(parsed));
    assert(parsed->entrypoint == 0x1000);

    // Verify UUID.
    assert(memcmp(parsed->uuid, uuid, 16) == 0);

    // Verify dylinker.
    assert(strcmp(parsed->dylinker->data, "/usr/lib/dyld") == 0);

    // Verify symbol. (Symbol parsing is lazy; materialize before direct reads.)
    n00b_macho_ensure_symbols(parsed);
    assert(parsed->num_symbols >= 1);
    n00b_option_t(n00b_macho_symbol_t *) main_sym_opt
        = n00b_macho_symbol_by_name(parsed, "_main");
    assert(n00b_option_is_set(main_sym_opt));
    n00b_macho_symbol_t *main_sym = n00b_option_get(main_sym_opt);
    assert(main_sym->value == 0x100001000ULL);

    // Verify segment structure.
    assert(n00b_macho_has_segment(parsed, "__PAGEZERO"));
    assert(n00b_macho_has_segment(parsed, "__TEXT"));
    assert(n00b_macho_has_segment(parsed, "__LINKEDIT"));

    // Verify section content.
    n00b_option_t(n00b_macho_section_t *) parsed_sec_opt
        = n00b_macho_section_by_name(parsed, "__TEXT", "__text");
    assert(n00b_option_is_set(parsed_sec_opt));
    n00b_macho_section_t *parsed_sec = n00b_option_get(parsed_sec_opt);
    assert(parsed_sec->content != nullptr);
    assert(n00b_buffer_len(parsed_sec->content) == sizeof(code));
    assert(memcmp(parsed_sec->content->data, code, sizeof(code)) == 0);

    printf("  [PASS] round_trip\n");
}

// ============================================================================
// Test: build fat binary
// ============================================================================

static void
test_build_fat(void)
{
    // Create two thin binaries.
    n00b_macho_binary_t *arm64 = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *arm64_text = n00b_macho_add_segment(
        arm64, "__TEXT", 5, 5);
    arm64_text->vmaddr = 0x100000000ULL;

    n00b_macho_binary_t *x86 = n00b_macho_binary_new(
        CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *x86_text = n00b_macho_add_segment(
        x86, "__TEXT", 5, 5);
    x86_text->vmaddr = 0x100000000ULL;

    n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);
    fat->count = 2;
    fat->binaries = n00b_alloc_array(n00b_macho_binary_t *, 2);
    fat->binaries[0] = arm64;
    fat->binaries[1] = x86;

    auto r = n00b_macho_build_fat(fat);
    assert(n00b_result_is_ok(r));

    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);

    // Parse back as fat.
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r2 = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_fat_t *parsed = n00b_result_get(r2);

    assert(parsed->count == 2);

    // Find each architecture.
    n00b_option_t(n00b_macho_binary_t *) parsed_arm64_opt
        = n00b_macho_fat_by_cputype(parsed, CPU_TYPE_ARM64);
    assert(n00b_option_is_set(parsed_arm64_opt));
    n00b_macho_binary_t *parsed_arm64 = n00b_option_get(parsed_arm64_opt);
    assert(parsed_arm64->header.cputype == (uint32_t)CPU_TYPE_ARM64);

    n00b_option_t(n00b_macho_binary_t *) parsed_x86_opt
        = n00b_macho_fat_by_cputype(parsed, CPU_TYPE_X86_64);
    assert(n00b_option_is_set(parsed_x86_opt));
    n00b_macho_binary_t *parsed_x86 = n00b_option_get(parsed_x86_opt);
    assert(parsed_x86->header.cputype == (uint32_t)CPU_TYPE_X86_64);

    printf("  [PASS] build_fat\n");
}

// ============================================================================
// Test: build with source version (LC_SOURCE_VERSION)
// ============================================================================

static void
test_build_with_source_version(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    // source_version is encoded as A.B.C.D.E packed into uint64_t
    n00b_macho_set_source_version(bin, 0x0001000200030004ULL);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->source_version == 0x0001000200030004ULL);

    printf("  [PASS] build_with_source_version\n");
}

// ============================================================================
// Test: build with build version (LC_BUILD_VERSION)
// ============================================================================

static void
test_build_with_build_version(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_build_tool_t tools[2] = {
        {.tool = 1, .version = 0x000E0000},  // clang 14.0
        {.tool = 3, .version = 0x04100000},   // ld64
    };
    n00b_macho_set_build_version(bin, PLATFORM_MACOS, 0x000D0000,
                                  0x000E0000, tools, 2);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_macho_has_build_version(parsed));

    n00b_option_t(n00b_macho_build_version_t *) bv_opt
        = n00b_macho_get_build_version(parsed);
    assert(n00b_option_is_set(bv_opt));
    n00b_macho_build_version_t *bv = n00b_option_get(bv_opt);
    assert(bv->platform == PLATFORM_MACOS);
    assert(bv->minos == 0x000D0000);
    assert(bv->sdk == 0x000E0000);
    assert(bv->num_tools == 2);
    assert(bv->tools[0].tool == 1);
    assert(bv->tools[0].version == 0x000E0000);
    assert(bv->tools[1].tool == 3);
    assert(bv->tools[1].version == 0x04100000);

    printf("  [PASS] build_with_build_version\n");
}

// ============================================================================
// Test: build with rpaths (LC_RPATH)
// ============================================================================

static void
test_build_with_rpaths(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_add_rpath(bin, "@executable_path/../Frameworks");
    n00b_macho_add_rpath(bin, "/usr/local/lib");

    assert(bin->num_rpaths == 2);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_macho_has_rpath(parsed));
    assert(parsed->num_rpaths == 2);

    n00b_option_t(n00b_string_t *) rp0_opt = n00b_macho_rpath_at(parsed, 0);
    n00b_option_t(n00b_string_t *) rp1_opt = n00b_macho_rpath_at(parsed, 1);

    assert(n00b_option_is_set(rp0_opt));
    n00b_string_t *rp0 = n00b_option_get(rp0_opt);
    assert(rp0->data != nullptr);
    assert(strcmp(rp0->data, "@executable_path/../Frameworks") == 0);
    assert(n00b_option_is_set(rp1_opt));
    n00b_string_t *rp1 = n00b_option_get(rp1_opt);
    assert(rp1->data != nullptr);
    assert(strcmp(rp1->data, "/usr/local/lib") == 0);

    // Out of bounds returns none.
    assert(!n00b_option_is_set(n00b_macho_rpath_at(parsed, 2)));

    printf("  [PASS] build_with_rpaths\n");
}

// ============================================================================
// Test: build with version min (LC_VERSION_MIN_MACOSX)
// ============================================================================

static void
test_build_with_version_min(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_set_version_min(bin, LC_VERSION_MIN_MACOSX,
                                0x000B0000, 0x000C0000);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_macho_has_version_min(parsed));

    n00b_option_t(n00b_macho_version_min_t *) vm_opt
        = n00b_macho_get_version_min(parsed);
    assert(n00b_option_is_set(vm_opt));
    n00b_macho_version_min_t *vm = n00b_option_get(vm_opt);
    assert(vm->cmd == LC_VERSION_MIN_MACOSX);
    assert(vm->version == 0x000B0000);
    assert(vm->sdk == 0x000C0000);

    printf("  [PASS] build_with_version_min\n");
}

// ============================================================================
// Test: build with linker options (LC_LINKER_OPTION)
// ============================================================================

static void
test_build_with_linker_options(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    const char *opt1[] = {"-lSystem"};
    const char *opt2[] = {"-framework", "Foundation"};
    n00b_macho_add_linker_option(bin, opt1, 1);
    n00b_macho_add_linker_option(bin, opt2, 2);

    assert(bin->num_linker_options == 2);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_linker_options == 2);
    assert(parsed->linker_options[0].count == 1);
    assert(strcmp(parsed->linker_options[0].strings[0]->data, "-lSystem") == 0);
    assert(parsed->linker_options[1].count == 2);
    assert(strcmp(parsed->linker_options[1].strings[0]->data, "-framework") == 0);
    assert(strcmp(parsed->linker_options[1].strings[1]->data, "Foundation") == 0);

    printf("  [PASS] build_with_linker_options\n");
}

// ============================================================================
// Test: build with data-in-code (LC_DATA_IN_CODE)
// ============================================================================

static void
test_build_with_data_in_code(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    // Need at least a symbol so __LINKEDIT is generated.
    n00b_macho_add_symbol(bin, "_main", N_SECT | N_EXT, 1, 0,
                           0x100001000ULL);

    n00b_macho_data_in_code_entry_t entries[] = {
        {.offset = 0x1000, .length = 4, .kind = 1},
        {.offset = 0x2000, .length = 8, .kind = 2},
    };
    n00b_macho_set_data_in_code(bin, entries, 2);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_macho_has_data_in_code(parsed));

    n00b_option_t(n00b_macho_data_in_code_t *) dic_opt
        = n00b_macho_get_data_in_code(parsed);
    assert(n00b_option_is_set(dic_opt));
    n00b_macho_data_in_code_t *dic = n00b_option_get(dic_opt);
    assert(dic->count == 2);
    assert(dic->entries[0].offset == 0x1000);
    assert(dic->entries[0].length == 4);
    assert(dic->entries[0].kind == 1);
    assert(dic->entries[1].offset == 0x2000);
    assert(dic->entries[1].length == 8);
    assert(dic->entries[1].kind == 2);

    printf("  [PASS] build_with_data_in_code\n");
}

// ============================================================================
// Test: build with encryption info (LC_ENCRYPTION_INFO_64)
// ============================================================================

static void
test_build_with_encryption_info(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_set_encryption_info(bin, 0x4000, 0x8000, 1);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_macho_has_encryption_info(parsed));

    n00b_option_t(n00b_macho_encryption_info_t *) ei_opt
        = n00b_macho_get_encryption_info(parsed);
    assert(n00b_option_is_set(ei_opt));
    n00b_macho_encryption_info_t *ei = n00b_option_get(ei_opt);
    assert(ei->cryptoff == 0x4000);
    assert(ei->cryptsize == 0x8000);
    assert(ei->cryptid == 1);

    printf("  [PASS] build_with_encryption_info\n");
}

// ============================================================================
// Test: build with fileset entries (LC_FILESET_ENTRY)
// ============================================================================

static void
test_build_with_fileset_entries(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_add_fileset_entry(bin, 0x200000000ULL, 0x4000,
                                  "com.apple.kernel");
    n00b_macho_add_fileset_entry(bin, 0x300000000ULL, 0x8000,
                                  "com.apple.driver");

    assert(bin->num_fileset_entries == 2);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_fileset_entries == 2);
    assert(parsed->fileset_entries[0].vmaddr == 0x200000000ULL);
    assert(parsed->fileset_entries[0].fileoff == 0x4000);
    assert(strcmp(parsed->fileset_entries[0].entry_id->data,
                  "com.apple.kernel") == 0);
    assert(parsed->fileset_entries[1].vmaddr == 0x300000000ULL);
    assert(parsed->fileset_entries[1].fileoff == 0x8000);
    assert(strcmp(parsed->fileset_entries[1].entry_id->data,
                  "com.apple.driver") == 0);

    printf("  [PASS] build_with_fileset_entries\n");
}

// ============================================================================
// Test: build with rebases round-trip
// ============================================================================

static void
test_build_with_rebases(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    n00b_macho_segment_t *data = n00b_macho_add_segment(bin, "__DATA", 3, 3);
    data->vmaddr = 0x100004000ULL;
    data->vmsize = 0x4000;

    // Segment indices in built binary: 0=__PAGEZERO, 1=__TEXT, 2=__DATA.
    // Rebase addresses are absolute (segment vmaddr + offset).
    n00b_macho_add_rebase(bin, 2, 0x100004000ULL, REBASE_TYPE_POINTER);
    n00b_macho_add_rebase(bin, 2, 0x100004008ULL, REBASE_TYPE_POINTER);

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_macho_parse_single(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_binary_t *parsed = n00b_result_get(r2);

    // Should have rebases.
    assert(parsed->num_rebases >= 2);

    // Verify addresses survived round-trip.
    bool found_first  = false;
    bool found_second = false;

    for (uint32_t i = 0; i < parsed->num_rebases; i++) {
        if (parsed->rebases[i].address == 0x100004000ULL) found_first  = true;
        if (parsed->rebases[i].address == 0x100004008ULL) found_second = true;
    }

    assert(found_first);
    assert(found_second);

    printf("  [PASS] build_with_rebases\n");
}

// ============================================================================
// Test: malformed MachO (cmdsize=0, truncated) rejected gracefully
// ============================================================================

static void
test_malformed_macho(void)
{
    // Build a valid MachO first, then corrupt it.
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text = n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    auto r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_buffer_t *buf = n00b_result_get(r);
    size_t len = n00b_buffer_len(buf);

    // Test 1: Truncated to just the magic bytes — should fail gracefully.
    n00b_buffer_t *trunc = n00b_buffer_from_bytes(buf->data, 8);
    n00b_bstream_t *s1 = n00b_bstream_new(trunc);
    auto r1 = n00b_macho_parse_single(s1);
    assert(n00b_result_is_err(r1));

    // Test 2: Corrupt cmdsize to 0 in the first load command.
    // Header is 32 bytes for MachO64; first load command is at offset 32.
    // cmdsize is at offset 32+4 = 36.
    if (len > 40) {
        n00b_buffer_t *corrupt = n00b_buffer_from_bytes(buf->data, len);
        // Zero out cmdsize (bytes 36-39).
        corrupt->data[36] = 0;
        corrupt->data[37] = 0;
        corrupt->data[38] = 0;
        corrupt->data[39] = 0;

        n00b_bstream_t *s2 = n00b_bstream_new(corrupt);
        auto r2 = n00b_macho_parse_single(s2);
        // Should either fail or parse without crashing (cmdsize=0 breaks loop).
        // The key is it doesn't crash or loop forever.
        (void)r2;
    }

    // Test 3: Corrupt ncmds to absurd value.
    if (len > 20) {
        n00b_buffer_t *corrupt2 = n00b_buffer_from_bytes(buf->data, len);
        // ncmds is at offset 16 in the MachO64 header.
        corrupt2->data[16] = 0xFF;
        corrupt2->data[17] = 0xFF;
        corrupt2->data[18] = 0x00;
        corrupt2->data[19] = 0x00; // 0x0000FFFF = 65535

        n00b_bstream_t *s3 = n00b_bstream_new(corrupt2);
        auto r3 = n00b_macho_parse_single(s3);
        // Should not crash — ncmds is clamped to 10000.
        (void)r3;
    }

    printf("  [PASS] malformed_macho\n");
}

// ============================================================================
// Test: parse real binary checks build version
// ============================================================================

static void
test_parse_real_build_version(void)
{
    auto stream_r = n00b_bstream_from_file("/usr/bin/true");

    if (n00b_result_is_err(stream_r)) {
        printf("  [SKIP] parse_real_build_version (file not found)\n");
        return;
    }

    n00b_bstream_t *s = n00b_result_get(stream_r);

    if (n00b_buffer_len(s->buf) < 4) {
        printf("  [SKIP] parse_real_build_version (file too small)\n");
        return;
    }

    uint32_t magic;
    memcpy(&magic, s->buf->data, 4);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64
        && magic != FAT_MAGIC && magic != FAT_CIGAM) {
        printf("  [SKIP] parse_real_build_version (not MachO)\n");
        return;
    }

    auto r = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_macho_fat_t *fat = n00b_result_get(r);
    n00b_macho_binary_t *bin = fat->binaries[0];

    // Modern macOS binaries should have LC_BUILD_VERSION.
    if (n00b_macho_has_build_version(bin)) {
        n00b_option_t(n00b_macho_build_version_t *) bv_opt
            = n00b_macho_get_build_version(bin);
        assert(n00b_option_is_set(bv_opt));
        n00b_macho_build_version_t *bv = n00b_option_get(bv_opt);
        printf("    platform: %u, minos: 0x%x, sdk: 0x%x, tools: %u\n",
               bv->platform, bv->minos, bv->sdk, bv->num_tools);
        assert(bv->platform > 0);
    }
    else {
        printf("    (no LC_BUILD_VERSION)\n");
    }

    printf("  [PASS] parse_real_build_version\n");
}

// ============================================================================
// Test: null binary rejected
// ============================================================================

static void
test_build_null(void)
{
    auto r = n00b_macho_build(nullptr);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_BUILD);

    auto r2 = n00b_macho_build_fat(nullptr);
    assert(n00b_result_is_err(r2));

    printf("  [PASS] build_null\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running MachO builder tests...\n");

    test_binary_new();
    test_add_segments_sections();
    test_add_symbols();
    test_add_dylibs();
    test_add_bindings();
    test_add_rebases();
    test_add_exports();
    test_convenience_setters();
    test_build_minimal();
    test_build_with_symtab();
    test_build_with_section_data();
    test_build_with_data_segment();
    test_build_with_entry();
    test_build_with_dylibs();
    test_build_with_dylinker();
    test_build_with_uuid();
    test_build_with_bindings();
    test_build_with_exports();
    test_build_with_function_starts();
    test_round_trip();
    test_build_fat();
    test_build_with_source_version();
    test_build_with_build_version();
    test_build_with_rpaths();
    test_build_with_version_min();
    test_build_with_linker_options();
    test_build_with_data_in_code();
    test_build_with_encryption_info();
    test_build_with_fileset_entries();
    test_build_with_rebases();
    test_malformed_macho();
    test_parse_real_build_version();
    test_build_null();

    printf("All MachO builder tests passed.\n");
    return 0;
}

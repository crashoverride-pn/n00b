#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <strings.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/pe.h"
#include "compiler/objfile/pe_build.h"
#include "compiler/objfile/bstream.h"

// ============================================================================
// Tests
// ============================================================================

static void
test_binary_new(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    assert(bin != nullptr);
    assert(bin->machine == N00B_PE_MACHINE_AMD64);
    assert(bin->subsystem == N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    assert(bin->magic == N00B_PE_OPT_MAGIC_PE32P);
    assert(bin->section_alignment == 0x1000);
    assert(bin->file_alignment == 0x200);
    assert(bin->imagebase == 0x0000000140000000ULL);
    assert(bin->characteristics & N00B_PE_CHAR_EXECUTABLE_IMAGE);

    printf("  [PASS] binary_new\n");
}

static void
test_add_sections(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    assert(text != nullptr);
    assert(strcmp(text->name->data, ".text") == 0);

    n00b_pe_section_t *data = n00b_pe_add_section(bin, ".data",
        N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ | N00B_PE_SCN_MEM_WRITE);
    assert(data != nullptr);

    assert(bin->num_sections == 2);
    assert(strcmp(bin->sections[0].name->data, ".text") == 0);
    assert(strcmp(bin->sections[1].name->data, ".data") == 0);

    printf("  [PASS] add_sections\n");
}

static void
test_build_minimal(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    uint8_t code[] = {0xCC, 0x90, 0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 3);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_buffer_t *built = n00b_result_get(r);
    assert(built != nullptr);
    assert(n00b_buffer_len(built) > 0);

    // Parse back
    n00b_bstream_t *s = n00b_bstream_new(built);
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->machine == N00B_PE_MACHINE_AMD64);
    assert(parsed->magic == N00B_PE_OPT_MAGIC_PE32P);
    assert(parsed->entry_point == 0x1000);
    assert(parsed->num_sections == 1);
    assert(strcmp(parsed->sections[0].name->data, ".text") == 0);

    printf("  [PASS] build_minimal\n");
}

static void
test_build_with_content(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    uint8_t code[] = {0x48, 0x31, 0xC0, 0xC3};  // xor rax,rax; ret
    text->content = n00b_buffer_from_bytes((char *)code, 4);

    n00b_pe_section_t *data = n00b_pe_add_section(bin, ".data",
        N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ | N00B_PE_SCN_MEM_WRITE);

    uint8_t dval[] = "Hello World!";
    data->content = n00b_buffer_from_bytes((char *)dval, sizeof(dval));

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_sections == 2);

    // Verify .text content
    assert(parsed->sections[0].content != nullptr);
    uint8_t *tc = (uint8_t *)parsed->sections[0].content->data;
    assert(tc[0] == 0x48 && tc[1] == 0x31 && tc[2] == 0xC0 && tc[3] == 0xC3);

    // Verify .data content
    assert(parsed->sections[1].content != nullptr);
    assert(memcmp(parsed->sections[1].content->data, "Hello World!", 12) == 0);

    printf("  [PASS] build_with_content\n");
}

static void
test_build_null(void)
{
    auto r = n00b_pe_build(nullptr);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_BUILD);

    printf("  [PASS] build_null\n");
}

static void
test_build_import_round_trip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    n00b_pe_import_t *k32 = n00b_pe_add_import(bin, "KERNEL32.dll");
    n00b_pe_add_imported_func(k32, "ExitProcess", 0);
    n00b_pe_add_imported_func(k32, "GetLastError", 1);

    n00b_pe_import_t *u32 = n00b_pe_add_import(bin, "USER32.dll");
    n00b_pe_add_imported_func(u32, "MessageBoxA", 0);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_imports == 2);
    assert(strcmp(parsed->imports[0].name->data, "KERNEL32.dll") == 0);
    assert(parsed->imports[0].num_functions == 2);
    assert(strcmp(parsed->imports[0].functions[0].name->data,
                  "ExitProcess") == 0);
    assert(strcmp(parsed->imports[0].functions[1].name->data,
                  "GetLastError") == 0);
    assert(strcmp(parsed->imports[1].name->data, "USER32.dll") == 0);
    assert(parsed->imports[1].num_functions == 1);

    printf("  [PASS] build_import_round_trip\n");
}

static void
test_build_export_round_trip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->characteristics |= N00B_PE_CHAR_DLL;
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    n00b_pe_set_export_name(bin, "mylib.dll");
    bin->export_info->ordinal_base = 1;

    n00b_pe_add_export(bin, "Add", 0x1000, 1);
    n00b_pe_add_export(bin, "Mul", 0x1020, 2);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_pe_has_exports(parsed));
    assert(parsed->export_info->num_functions == 2);

    n00b_pe_exported_func_t *add_fn = n00b_pe_export_by_name(parsed, "Add");
    assert(add_fn != nullptr);
    assert(add_fn->rva == 0x1000);

    n00b_pe_exported_func_t *mul_fn = n00b_pe_export_by_name(parsed, "Mul");
    assert(mul_fn != nullptr);
    assert(mul_fn->rva == 0x1020);

    printf("  [PASS] build_export_round_trip\n");
}

static void
test_build_reloc_round_trip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[0x200];
    memset(code, 0xCC, sizeof(code));
    text->content = n00b_buffer_from_bytes((char *)code, sizeof(code));

    n00b_pe_add_relocation(bin, 0x1010, N00B_PE_REL_BASED_DIR64);
    n00b_pe_add_relocation(bin, 0x1020, N00B_PE_REL_BASED_DIR64);
    n00b_pe_add_relocation(bin, 0x1030, N00B_PE_REL_BASED_HIGHLOW);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_relocations == 3);
    assert(parsed->relocations[0].rva == 0x1010);
    assert(parsed->relocations[0].type == N00B_PE_REL_BASED_DIR64);
    assert(parsed->relocations[1].rva == 0x1020);
    assert(parsed->relocations[2].rva == 0x1030);
    assert(parsed->relocations[2].type == N00B_PE_REL_BASED_HIGHLOW);

    printf("  [PASS] build_reloc_round_trip\n");
}

static void
test_build_reloc_page_grouping(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[0x200];
    memset(code, 0xCC, sizeof(code));
    text->content = n00b_buffer_from_bytes((char *)code, sizeof(code));
    text->virtual_size = 0x3000;  // Large enough for both pages

    // Entries on page 0x1000 and page 0x2000
    n00b_pe_add_relocation(bin, 0x1010, N00B_PE_REL_BASED_DIR64);
    n00b_pe_add_relocation(bin, 0x2020, N00B_PE_REL_BASED_DIR64);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_relocations == 2);
    assert(parsed->relocations[0].rva == 0x1010);
    assert(parsed->relocations[1].rva == 0x2020);

    printf("  [PASS] build_reloc_page_grouping\n");
}

static void
test_build_size_of_image(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    // SizeOfImage must be section-aligned
    assert((parsed->size_of_image % parsed->section_alignment) == 0);
    assert(parsed->size_of_image > 0);

    printf("  [PASS] build_size_of_image\n");
}

static void
test_build_full_round_trip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    // .text section
    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0x48, 0x31, 0xC0, 0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, sizeof(code));

    // .data section
    n00b_pe_section_t *data = n00b_pe_add_section(bin, ".data",
        N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ | N00B_PE_SCN_MEM_WRITE);
    uint8_t dval[] = "test data";
    data->content = n00b_buffer_from_bytes((char *)dval, sizeof(dval));

    // Imports
    n00b_pe_import_t *k32 = n00b_pe_add_import(bin, "KERNEL32.dll");
    n00b_pe_add_imported_func(k32, "ExitProcess", 0);

    // Exports
    bin->characteristics |= N00B_PE_CHAR_DLL;
    n00b_pe_set_export_name(bin, "test.dll");
    bin->export_info->ordinal_base = 1;
    n00b_pe_add_export(bin, "TestFunc", 0x1000, 1);

    // Relocations
    n00b_pe_add_relocation(bin, 0x1010, N00B_PE_REL_BASED_DIR64);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);

    // Headers
    assert(parsed->machine == N00B_PE_MACHINE_AMD64);
    assert(parsed->entry_point == 0x1000);
    assert(n00b_pe_is_dll(parsed));

    // User sections present
    assert(n00b_pe_has_section(parsed, ".text"));
    assert(n00b_pe_has_section(parsed, ".data"));

    // Imports
    assert(n00b_pe_has_imports(parsed));

    // Exports
    assert(n00b_pe_has_exports(parsed));

    // Relocations
    assert(parsed->num_relocations == 1);
    assert(parsed->relocations[0].rva == 0x1010);

    printf("  [PASS] build_full_round_trip\n");
}

static void
test_build_dll(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->characteristics |= N00B_PE_CHAR_DLL;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_pe_is_dll(parsed));
    assert(parsed->characteristics & N00B_PE_CHAR_DLL);

    printf("  [PASS] build_dll\n");
}

static void
test_build_null_content(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *bss = n00b_pe_add_section(bin, ".bss",
        N00B_PE_SCN_CNT_UNINITIALIZED | N00B_PE_SCN_MEM_READ | N00B_PE_SCN_MEM_WRITE);
    bss->virtual_size = 0x1000;
    // No content (nullptr)

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_sections >= 1);
    assert(strcmp(parsed->sections[0].name->data, ".bss") == 0);

    printf("  [PASS] build_null_content\n");
}

static void
test_build_large_binary(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    for (int i = 0; i < 10; i++) {
        char name[16];
        snprintf(name, sizeof(name), ".sec%d", i);
        n00b_pe_section_t *s = n00b_pe_add_section(bin, name,
            N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

        uint8_t data[64];
        memset(data, (uint8_t)i, sizeof(data));
        s->content = n00b_buffer_from_bytes((char *)data, sizeof(data));
    }

    assert(bin->num_sections == 10);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_sections == 10);

    // Verify each section has correct content
    for (uint32_t i = 0; i < 10; i++) {
        assert(parsed->sections[i].content != nullptr);
        uint8_t *data = (uint8_t *)parsed->sections[i].content->data;
        assert(data[0] == (uint8_t)i);
    }

    printf("  [PASS] build_large_binary\n");
}

// ============================================================================
// Phase 9j: Parse-modify-write + mutation tests
// ============================================================================

/// Build a "full" PE with imports, exports, and relocations for round-trip
/// testing. Returns the built buffer.
static n00b_buffer_t *
build_full_pe(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
                                  N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE
                                  | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = { 0xCC, 0x90, 0xC3 };
    text->content  = n00b_buffer_new(sizeof(code));
    memcpy(text->content->data, code, sizeof(code));
    text->content->byte_len = sizeof(code);
    text->virtual_size = 0x1000;

    n00b_pe_section_t *data = n00b_pe_add_section(bin, ".data",
                                  N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ
                                  | N00B_PE_SCN_MEM_WRITE);
    const char *msg = "Hello World!";
    data->content  = n00b_buffer_new(16);
    memcpy(data->content->data, msg, strlen(msg) + 1);
    data->content->byte_len = (int64_t)(strlen(msg) + 1);
    data->virtual_size = 0x1000;

    n00b_pe_import_t *k32 = n00b_pe_add_import(bin, "KERNEL32.dll");
    n00b_pe_add_imported_func(k32, "ExitProcess", 0);
    n00b_pe_add_imported_func(k32, "GetLastError", 0);

    n00b_pe_import_t *u32 = n00b_pe_add_import(bin, "USER32.dll");
    n00b_pe_add_imported_func(u32, "MessageBoxA", 0);

    n00b_pe_set_export_name(bin, "test.dll");
    n00b_pe_add_export(bin, "MyFunc", 0x1000, 0);
    n00b_pe_add_export(bin, "MyFunc2", 0x1010, 1);

    n00b_pe_add_relocation(bin, 0x1010, N00B_PE_REL_BASED_DIR64);
    n00b_pe_add_relocation(bin, 0x1020, N00B_PE_REL_BASED_DIR64);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    return n00b_result_get(r);
}

static void
test_parse_rebuild_identity(void)
{
    // Build a full PE, parse it, strip synthetics, rebuild, parse again.
    n00b_buffer_t *buf1 = build_full_pe();
    n00b_bstream_t *s1   = n00b_bstream_new(buf1);
    auto           r1   = n00b_pe_parse(s1);

    assert(n00b_result_is_ok(r1));
    n00b_pe_binary_t *parsed = n00b_result_get(r1);

    // Strip .idata/.edata/.reloc so builder can regenerate.
    n00b_pe_strip_synthetic_sections(parsed);

    // Rebuild.
    auto r2 = n00b_pe_build(parsed);
    assert(n00b_result_is_ok(r2));
    n00b_buffer_t *buf2 = n00b_result_get(r2);

    // Parse again and verify key properties.
    n00b_bstream_t *s2 = n00b_bstream_new(buf2);
    auto           r3 = n00b_pe_parse(s2);

    assert(n00b_result_is_ok(r3));
    n00b_pe_binary_t *final = n00b_result_get(r3);

    assert(final->machine == N00B_PE_MACHINE_AMD64);
    assert(final->entry_point == parsed->entry_point);
    assert(final->num_imports == 2);
    assert(final->export_info != nullptr);
    assert(final->export_info->num_functions == 2);
    assert(final->num_relocations == 2);

    printf("  [PASS] parse_rebuild_identity\n");
}

static void
test_parse_modify_entry(void)
{
    n00b_buffer_t *buf = build_full_pe();
    n00b_bstream_t *s   = n00b_bstream_new(buf);
    auto           r   = n00b_pe_parse(s);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // Modify entry point.
    bin->entry_point = 0x2000;

    n00b_pe_strip_synthetic_sections(bin);

    auto r2 = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r2));

    n00b_bstream_t *s2 = n00b_bstream_new(n00b_result_get(r2));
    auto           r3 = n00b_pe_parse(s2);

    assert(n00b_result_is_ok(r3));
    n00b_pe_binary_t *final = n00b_result_get(r3);

    assert(final->entry_point == 0x2000);

    printf("  [PASS] parse_modify_entry\n");
}

static void
test_parse_modify_imports(void)
{
    n00b_buffer_t *buf = build_full_pe();
    n00b_bstream_t *s   = n00b_bstream_new(buf);
    auto           r   = n00b_pe_parse(s);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // Add a new import.
    n00b_pe_import_t *adv = n00b_pe_add_import(bin, "ADVAPI32.dll");
    n00b_pe_add_imported_func(adv, "RegOpenKeyA", 0);

    n00b_pe_strip_synthetic_sections(bin);

    auto r2 = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r2));

    n00b_bstream_t *s2 = n00b_bstream_new(n00b_result_get(r2));
    auto           r3 = n00b_pe_parse(s2);

    assert(n00b_result_is_ok(r3));
    n00b_pe_binary_t *final = n00b_result_get(r3);

    assert(final->num_imports == 3);

    // Check all three DLLs.
    bool found_k32 = false, found_u32 = false, found_adv = false;

    for (uint32_t i = 0; i < final->num_imports; i++) {
        if (strcasecmp(final->imports[i].name->data, "KERNEL32.dll") == 0) {
            found_k32 = true;
        }
        if (strcasecmp(final->imports[i].name->data, "USER32.dll") == 0) {
            found_u32 = true;
        }
        if (strcasecmp(final->imports[i].name->data, "ADVAPI32.dll") == 0) {
            found_adv = true;
        }
    }

    assert(found_k32);
    assert(found_u32);
    assert(found_adv);

    printf("  [PASS] parse_modify_imports\n");
}

static void
test_parse_add_section(void)
{
    n00b_buffer_t *buf = build_full_pe();
    n00b_bstream_t *s   = n00b_bstream_new(buf);
    auto           r   = n00b_pe_parse(s);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    uint32_t orig_sections = bin->num_sections;

    n00b_pe_strip_synthetic_sections(bin);

    // Add a new section.
    n00b_pe_section_t *sec = n00b_pe_add_section(bin, ".new",
                                 N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    sec->content  = n00b_buffer_new(8);
    memcpy(sec->content->data, "TESTDATA", 8);
    sec->content->byte_len = 8;
    sec->virtual_size = 0x1000;

    auto r2 = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r2));

    n00b_bstream_t *s2 = n00b_bstream_new(n00b_result_get(r2));
    auto           r3 = n00b_pe_parse(s2);

    assert(n00b_result_is_ok(r3));
    n00b_pe_binary_t *final = n00b_result_get(r3);

    // Should have original user sections + new section + synthetics.
    bool found = false;

    for (uint32_t i = 0; i < final->num_sections; i++) {
        if (strcmp(final->sections[i].name->data, ".new") == 0) {
            found = true;
            assert(final->sections[i].content != nullptr);

            const char *d = (const char *)final->sections[i].content->data;
            assert(memcmp(d, "TESTDATA", 8) == 0);
        }
    }

    assert(found);
    (void)orig_sections;

    printf("  [PASS] parse_add_section\n");
}

static void
test_remove_section(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *s1 = n00b_pe_add_section(bin, ".text",
                                N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_READ);
    s1->virtual_size = 0x1000;

    n00b_pe_section_t *s2 = n00b_pe_add_section(bin, ".data",
                                N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    s2->virtual_size = 0x1000;

    n00b_pe_section_t *s3 = n00b_pe_add_section(bin, ".rdata",
                                N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    s3->virtual_size = 0x1000;

    assert(bin->num_sections == 3);

    n00b_pe_remove_section(bin, ".data");
    assert(bin->num_sections == 2);
    assert(strcmp(bin->sections[0].name->data, ".text") == 0);
    assert(strcmp(bin->sections[1].name->data, ".rdata") == 0);

    printf("  [PASS] remove_section\n");
}

static void
test_remove_section_rebuild(void)
{
    n00b_buffer_t *buf = build_full_pe();
    n00b_bstream_t *s   = n00b_bstream_new(buf);
    auto           r   = n00b_pe_parse(s);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_strip_synthetic_sections(bin);

    // Remove .data section.
    n00b_pe_remove_section(bin, ".data");

    auto r2 = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r2));

    n00b_bstream_t *s2 = n00b_bstream_new(n00b_result_get(r2));
    auto           r3 = n00b_pe_parse(s2);

    assert(n00b_result_is_ok(r3));
    n00b_pe_binary_t *final = n00b_result_get(r3);

    // .data should be gone.
    for (uint32_t i = 0; i < final->num_sections; i++) {
        assert(strcmp(final->sections[i].name->data, ".data") != 0);
    }

    printf("  [PASS] remove_section_rebuild\n");
}

static void
test_remove_import(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_import_t *k32 = n00b_pe_add_import(bin, "KERNEL32.dll");
    n00b_pe_add_imported_func(k32, "ExitProcess", 0);

    n00b_pe_import_t *u32 = n00b_pe_add_import(bin, "USER32.dll");
    n00b_pe_add_imported_func(u32, "MessageBoxA", 0);

    assert(bin->num_imports == 2);

    n00b_pe_remove_import(bin, "kernel32.dll");  // case-insensitive
    assert(bin->num_imports == 1);
    assert(strcasecmp(bin->imports[0].name->data, "USER32.dll") == 0);

    printf("  [PASS] remove_import\n");
}

static void
test_remove_all_imports(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_import_t *k32 = n00b_pe_add_import(bin, "KERNEL32.dll");
    n00b_pe_add_imported_func(k32, "ExitProcess", 0);

    n00b_pe_import_t *u32 = n00b_pe_add_import(bin, "USER32.dll");
    n00b_pe_add_imported_func(u32, "MessageBoxA", 0);

    n00b_pe_remove_all_imports(bin);
    assert(bin->num_imports == 0);
    assert(bin->imports == nullptr);

    printf("  [PASS] remove_all_imports\n");
}

static void
test_remove_export(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_set_export_name(bin, "test.dll");
    n00b_pe_add_export(bin, "FuncA", 0x1000, 0);
    n00b_pe_add_export(bin, "FuncB", 0x1010, 1);
    n00b_pe_add_export(bin, "FuncC", 0x1020, 2);

    assert(bin->export_info->num_functions == 3);

    n00b_pe_remove_export(bin, "FuncB");
    assert(bin->export_info->num_functions == 2);
    assert(strcmp(bin->export_info->functions[0].name->data, "FuncA") == 0);
    assert(strcmp(bin->export_info->functions[1].name->data, "FuncC") == 0);

    printf("  [PASS] remove_export\n");
}

static void
test_set_tls_roundtrip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    assert(bin->tls == nullptr);

    n00b_pe_tls_t *tls = n00b_pe_set_tls(bin);
    assert(tls != nullptr);
    assert(bin->tls == tls);

    n00b_pe_add_tls_callback(bin, 0x140001000ULL);
    n00b_pe_add_tls_callback(bin, 0x140002000ULL);

    assert(bin->tls->num_callbacks == 2);
    assert(bin->tls->callbacks[0] == 0x140001000ULL);
    assert(bin->tls->callbacks[1] == 0x140002000ULL);

    printf("  [PASS] set_tls_roundtrip\n");
}

static void
test_remove_tls(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_set_tls(bin);
    assert(bin->tls != nullptr);

    n00b_pe_remove_tls(bin);
    assert(bin->tls == nullptr);

    printf("  [PASS] remove_tls\n");
}

static void
test_strip_synthetic(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
                                  N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_READ);
    text->virtual_size = 0x1000;

    n00b_pe_section_t *idata = n00b_pe_add_section(bin, ".idata",
                                   N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    idata->virtual_size = 0x1000;

    n00b_pe_section_t *edata = n00b_pe_add_section(bin, ".edata",
                                   N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    edata->virtual_size = 0x1000;

    n00b_pe_section_t *reloc = n00b_pe_add_section(bin, ".reloc",
                                   N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    reloc->virtual_size = 0x1000;

    n00b_pe_section_t *data = n00b_pe_add_section(bin, ".data",
                                  N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);
    data->virtual_size = 0x1000;

    assert(bin->num_sections == 5);

    n00b_pe_strip_synthetic_sections(bin);

    assert(bin->num_sections == 2);
    assert(strcmp(bin->sections[0].name->data, ".text") == 0);
    assert(strcmp(bin->sections[1].name->data, ".data") == 0);

    printf("  [PASS] strip_synthetic\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running PE builder tests...\n");

    test_binary_new();
    test_add_sections();
    test_build_minimal();
    test_build_with_content();
    test_build_null();
    test_build_import_round_trip();
    test_build_export_round_trip();
    test_build_reloc_round_trip();
    test_build_reloc_page_grouping();
    test_build_size_of_image();
    test_build_full_round_trip();
    test_build_dll();
    test_build_null_content();
    test_build_large_binary();

    // Phase 9j tests
    test_parse_rebuild_identity();
    test_parse_modify_entry();
    test_parse_modify_imports();
    test_parse_add_section();
    test_remove_section();
    test_remove_section_rebuild();
    test_remove_import();
    test_remove_all_imports();
    test_remove_export();
    test_set_tls_roundtrip();
    test_remove_tls();
    test_strip_synthetic();

    printf("All PE builder tests passed.\n");

    n00b_shutdown();

    return 0;
}

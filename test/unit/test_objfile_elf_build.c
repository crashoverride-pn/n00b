#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/elf_build.h"

// ============================================================================
// Test: create empty binary
// ============================================================================

static void
test_binary_new(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    assert(bin != nullptr);
    assert(bin->header.ident[0] == 0x7f);
    assert(bin->header.ident[1] == 'E');
    assert(bin->header.ident[2] == 'L');
    assert(bin->header.ident[3] == 'F');
    assert(bin->header.ident[EI_CLASS] == ELFCLASS64);
    assert(bin->header.ident[EI_DATA] == ELFDATA2LSB);
    assert(bin->header.type == ET_EXEC);
    assert(bin->header.machine == EM_X86_64);
    assert(bin->header.ehsize == 64);
    assert(bin->header.phentsize == 56);
    assert(bin->header.shentsize == 64);

    assert(bin->num_sections == 0);
    assert(bin->num_segments == 0);
    assert(bin->num_symtab == 0);
    assert(bin->num_dynsym == 0);

    printf("  [PASS] binary_new\n");
}

// ============================================================================
// Test: add/remove sections
// ============================================================================

static void
test_add_remove_sections(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_section_t *text = n00b_elf_add_section(bin, r".text",
                                                     SHT_PROGBITS,
                                                     SHF_ALLOC | SHF_EXECINSTR);
    assert(text != nullptr);
    assert(bin->num_sections == 1);
    assert(strcmp(bin->sections[0].name->data, ".text") == 0);

    n00b_elf_section_t *data = n00b_elf_add_section(bin, r".data",
                                                     SHT_PROGBITS,
                                                     SHF_ALLOC | SHF_WRITE);
    assert(data != nullptr);
    assert(bin->num_sections == 2);

    n00b_elf_section_t *bss = n00b_elf_add_section(bin, r".bss",
                                                    SHT_NOBITS,
                                                    SHF_ALLOC | SHF_WRITE);
    assert(bss != nullptr);
    assert(bin->num_sections == 3);

    // Remove .data.
    n00b_elf_remove_section(bin, r".data");
    assert(bin->num_sections == 2);
    assert(strcmp(bin->sections[0].name->data, ".text") == 0);
    assert(strcmp(bin->sections[1].name->data, ".bss") == 0);

    // Remove nonexistent — no-op.
    n00b_elf_remove_section(bin, r".nonexistent");
    assert(bin->num_sections == 2);

    printf("  [PASS] add_remove_sections\n");
}

// ============================================================================
// Test: add segments
// ============================================================================

static void
test_add_segments(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_segment_t *load = n00b_elf_add_segment(bin, PT_LOAD,
                                                     PF_R | PF_X);
    assert(load != nullptr);
    assert(bin->num_segments == 1);
    assert(bin->segments[0].type == PT_LOAD);
    assert(bin->segments[0].flags == (PF_R | PF_X));

    n00b_elf_segment_t *load2 = n00b_elf_add_segment(bin, PT_LOAD,
                                                      PF_R | PF_W);
    assert(load2 != nullptr);
    assert(bin->num_segments == 2);

    printf("  [PASS] add_segments\n");
}

// ============================================================================
// Test: add symbols
// ============================================================================

static void
test_add_symbols(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    // Add null symbol first (convention).
    n00b_elf_add_symtab_symbol(bin, r"", 0, 0, STB_LOCAL, STT_NOTYPE, SHN_UNDEF);

    n00b_elf_symbol_t *func = n00b_elf_add_symtab_symbol(
        bin, r"my_func", 0x401000, 64, STB_GLOBAL, STT_FUNC, 1);

    assert(func != nullptr);
    assert(bin->num_symtab == 2);
    assert(strcmp(bin->symtab_symbols[1].name->data, "my_func") == 0);
    assert(bin->symtab_symbols[1].value == 0x401000);
    assert(N00B_ELF64_ST_BIND(bin->symtab_symbols[1].info) == STB_GLOBAL);
    assert(N00B_ELF64_ST_TYPE(bin->symtab_symbols[1].info) == STT_FUNC);

    printf("  [PASS] add_symbols\n");
}

// ============================================================================
// Test: add dynamic entries
// ============================================================================

static void
test_add_dynamic(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_DYN, EM_X86_64);

    n00b_elf_add_dynamic(bin, DT_NEEDED, 1);
    n00b_elf_add_dynamic(bin, DT_STRTAB, 0x400000);
    assert(bin->num_dynamic == 2);

    // Update existing.
    n00b_elf_set_dynamic(bin, DT_STRTAB, 0x500000);
    assert(bin->dynamic_entries[1].value == 0x500000);

    // Set non-existing — should add.
    n00b_elf_set_dynamic(bin, DT_STRSZ, 100);
    assert(bin->num_dynamic == 3);

    printf("  [PASS] add_dynamic\n");
}

// ============================================================================
// Test: add relocations
// ============================================================================

static void
test_add_relocations(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_relocation_t *rel = n00b_elf_add_relocation(
        bin, 0x401000, 1, R_X86_64_64, 0);

    assert(rel != nullptr);
    assert(bin->num_relocations == 1);
    assert(rel->offset == 0x401000);
    assert(N00B_ELF64_R_SYM(rel->info) == 1);
    assert(N00B_ELF64_R_TYPE(rel->info) == R_X86_64_64);
    assert(rel->has_addend);

    printf("  [PASS] add_relocations\n");
}

// ============================================================================
// Test: section index lookup
// ============================================================================

static void
test_section_index(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_add_section(bin, r".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
    n00b_elf_add_section(bin, r".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);

    // section_index returns ELF section header index (1-based, since 0 = SHT_NULL).
    assert(n00b_elf_section_index(bin, r".text") == 1);
    assert(n00b_elf_section_index(bin, r".data") == 2);
    assert(n00b_elf_section_index(bin, r".nope") == SHN_UNDEF);

    printf("  [PASS] section_index\n");
}

// ============================================================================
// Test: set interpreter
// ============================================================================

static void
test_set_interpreter(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_interpreter(bin, r"/lib64/ld-linux-x86-64.so.2");

    assert(bin->interpreter != nullptr && bin->interpreter->data != nullptr);
    assert(strcmp(bin->interpreter->data,
                 "/lib64/ld-linux-x86-64.so.2") == 0);

    printf("  [PASS] set_interpreter\n");
}

// ============================================================================
// Test: build minimal ELF, parse back, verify
// ============================================================================

static void
test_build_minimal(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_entry(bin, 0x401000);

    // Add a PT_LOAD segment.
    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    // Build.
    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);
    assert(n00b_buffer_len(buf) > 64);

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    // Verify header.
    assert(parsed->header.ident[0] == 0x7f);
    assert(parsed->header.ident[1] == 'E');
    assert(parsed->header.ident[EI_CLASS] == ELFCLASS64);
    assert(parsed->header.type == ET_EXEC);
    assert(parsed->header.machine == EM_X86_64);
    assert(parsed->header.entry == 0x401000);

    // Should have at least the PT_LOAD segment.
    assert(parsed->num_segments >= 1);

    bool found_load = false;

    for (uint32_t i = 0; i < parsed->num_segments; i++) {
        if (parsed->segments[i].type == PT_LOAD) {
            found_load = true;
            assert(parsed->segments[i].vaddr == 0x400000);
        }
    }

    assert(found_load);

    // Should have .shstrtab section.
    assert(parsed->num_sections >= 2); // NULL + .shstrtab at minimum
    assert(n00b_elf_has_section(parsed, ".shstrtab"));

    printf("  [PASS] build_minimal\n");
}

// ============================================================================
// Test: build with symtab, parse back, verify symbols
// ============================================================================

static void
test_build_with_symtab(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_entry(bin, 0x401000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    // Add symbols.
    n00b_elf_add_symtab_symbol(bin, r"", 0, 0, STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_symtab_symbol(bin, r"main", 0x401000, 100,
                                STB_GLOBAL, STT_FUNC, 1);
    n00b_elf_add_symtab_symbol(bin, r"data_var", 0x402000, 8,
                                STB_GLOBAL, STT_OBJECT, 1);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    // Verify symbols.
    assert(parsed->num_symtab == 3);

    n00b_option_t(n00b_elf_symbol_t *) main_sym_opt
        = n00b_elf_symtab_by_name(parsed, "main");
    assert(n00b_option_is_set(main_sym_opt));
    n00b_elf_symbol_t *main_sym = n00b_option_get(main_sym_opt);
    assert(main_sym->value == 0x401000);
    assert(main_sym->size == 100);
    assert(N00B_ELF64_ST_TYPE(main_sym->info) == STT_FUNC);

    n00b_option_t(n00b_elf_symbol_t *) data_sym_opt
        = n00b_elf_symtab_by_name(parsed, "data_var");
    assert(n00b_option_is_set(data_sym_opt));
    n00b_elf_symbol_t *data_sym = n00b_option_get(data_sym_opt);
    assert(data_sym->value == 0x402000);
    assert(N00B_ELF64_ST_TYPE(data_sym->info) == STT_OBJECT);

    // Verify sections were generated.
    assert(n00b_elf_has_section(parsed, ".symtab"));
    assert(n00b_elf_has_section(parsed, ".strtab"));
    assert(n00b_elf_has_section(parsed, ".shstrtab"));

    printf("  [PASS] build_with_symtab\n");
}

// ============================================================================
// Test: build with user section data
// ============================================================================

static void
test_build_with_section_data(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_entry(bin, 0x401000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    // Add a section with content.
    uint8_t code[] = {0xCC, 0xCC, 0xCC, 0xCC}; // int3 instructions
    n00b_elf_section_t *text = n00b_elf_add_section(bin, r".text",
                                                     SHT_PROGBITS,
                                                     SHF_ALLOC | SHF_EXECINSTR);
    text->content   = n00b_buffer_from_bytes((char *)code, 4);
    text->addralign = 16;
    text->addr      = 0x401000;

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    n00b_option_t(n00b_elf_section_t *) parsed_text_opt
        = n00b_elf_section_by_name(parsed, ".text");
    assert(n00b_option_is_set(parsed_text_opt));
    n00b_elf_section_t *parsed_text = n00b_option_get(parsed_text_opt);
    assert(parsed_text->size == 4);
    assert(parsed_text->content != nullptr);
    assert(n00b_buffer_len(parsed_text->content) == 4);
    assert(memcmp(parsed_text->content->data, code, 4) == 0);

    printf("  [PASS] build_with_section_data\n");
}

// ============================================================================
// Test: build with dynamic table
// ============================================================================

static void
test_build_with_dynamic(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_DYN, EM_X86_64);

    n00b_elf_set_entry(bin, 0x1000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0;
    seg->align = 0x1000;

    // Add dynamic entries.
    n00b_elf_add_dynamic(bin, DT_NEEDED, 1);
    n00b_elf_add_dynamic(bin, DT_STRTAB, 0x400000);
    n00b_elf_add_dynamic(bin, DT_STRSZ, 16);
    n00b_elf_add_dynamic(bin, DT_SYMTAB, 0x400100);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    // Should have dynamic entries (DT_NULL is not stored by parser).
    assert(parsed->num_dynamic >= 4);

    // Check DT_NEEDED is preserved.
    n00b_option_t(n00b_elf_dynamic_t *) needed_opt
        = n00b_elf_dynamic_by_tag(parsed, DT_NEEDED);
    assert(n00b_option_is_set(needed_opt));
    assert(n00b_option_get(needed_opt)->value == 1);

    // Should have .dynamic section.
    assert(n00b_elf_has_section(parsed, ".dynamic"));

    // Should have PT_DYNAMIC segment.
    assert(n00b_elf_has_segment(parsed, PT_DYNAMIC));

    printf("  [PASS] build_with_dynamic\n");
}

// ============================================================================
// Test: build with notes
// ============================================================================

static void
test_build_with_notes(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_entry(bin, 0x401000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    // Add a note.
    uint8_t desc_data[16] = {0};
    n00b_buffer_t *desc = n00b_buffer_from_bytes((char *)desc_data, 16);
    n00b_elf_add_note(bin, r"GNU", NT_GNU_ABI_TAG, desc);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->num_notes >= 1);
    assert(strcmp(parsed->notes[0].name->data, "GNU") == 0);
    assert(parsed->notes[0].type == NT_GNU_ABI_TAG);
    assert(parsed->notes[0].desc != nullptr);
    assert(n00b_buffer_len(parsed->notes[0].desc) == 16);

    printf("  [PASS] build_with_notes\n");
}

// ============================================================================
// Test: build with interpreter
// ============================================================================

static void
test_build_with_interpreter(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_entry(bin, 0x401000);
    n00b_elf_set_interpreter(bin, r"/lib64/ld-linux-x86-64.so.2");

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    assert(n00b_elf_has_interpreter(parsed));
    assert(strcmp(parsed->interpreter->data,
                 "/lib64/ld-linux-x86-64.so.2") == 0);

    // Should have .interp section and PT_INTERP segment.
    assert(n00b_elf_has_section(parsed, ".interp"));
    assert(n00b_elf_has_segment(parsed, PT_INTERP));

    printf("  [PASS] build_with_interpreter\n");
}

// ============================================================================
// Test: build with relocations
// ============================================================================

static void
test_build_with_relocations(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_DYN, EM_X86_64);

    n00b_elf_set_entry(bin, 0x1000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0;
    seg->align = 0x1000;

    // Add dynsym (required for relocations to reference).
    n00b_elf_add_dynsym_symbol(bin, r"", 0, 0,
                                STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_dynsym_symbol(bin, r"printf", 0, 0,
                                STB_GLOBAL, STT_FUNC, SHN_UNDEF);

    // Add relocations.
    n00b_elf_add_relocation(bin, 0x2000, 1, R_X86_64_JUMP_SLOT, 0);
    n00b_elf_add_relocation(bin, 0x2008, 0, R_X86_64_RELATIVE, 0x1000);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->num_relocations == 2);
    assert(parsed->relocations[0].offset == 0x2000);
    assert(N00B_ELF64_R_TYPE(parsed->relocations[0].info) == R_X86_64_JUMP_SLOT);
    assert(parsed->relocations[1].offset == 0x2008);
    assert(parsed->relocations[1].addend == 0x1000);

    printf("  [PASS] build_with_relocations\n");
}

// ============================================================================
// Test: build with dynsym
// ============================================================================

static void
test_build_with_dynsym(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_DYN, EM_X86_64);

    // A PT_LOAD segment covering the file is needed for vaddr_to_offset.
    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0;
    seg->align = 0x1000;

    // Add dynamic symbols.
    n00b_elf_add_dynsym_symbol(bin, r"", 0, 0,
                                STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_dynsym_symbol(bin, r"puts", 0, 0,
                                STB_GLOBAL, STT_FUNC, SHN_UNDEF);
    n00b_elf_add_dynsym_symbol(bin, r"exit", 0, 0,
                                STB_GLOBAL, STT_FUNC, SHN_UNDEF);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    // Parse back.
    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->num_dynsym == 3);

    assert(n00b_option_is_set(n00b_elf_dynsym_by_name(parsed, "puts")));
    assert(n00b_option_is_set(n00b_elf_dynsym_by_name(parsed, "exit")));

    // Should have .dynsym and .dynstr sections.
    assert(n00b_elf_has_section(parsed, ".dynsym"));
    assert(n00b_elf_has_section(parsed, ".dynstr"));
    assert(n00b_elf_has_section(parsed, ".gnu.hash"));

    printf("  [PASS] build_with_dynsym\n");
}

// ============================================================================
// Test: round-trip — build, parse, build again, compare
// ============================================================================

static void
test_round_trip(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);

    n00b_elf_set_entry(bin, 0x401000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    uint8_t code[] = {0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00};
    n00b_elf_section_t *text = n00b_elf_add_section(bin, r".text",
                                                     SHT_PROGBITS,
                                                     SHF_ALLOC | SHF_EXECINSTR);
    text->content   = n00b_buffer_from_bytes((char *)code, sizeof(code));
    text->addralign = 16;

    n00b_elf_add_symtab_symbol(bin, r"", 0, 0, STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_symtab_symbol(bin, r"_start", 0x401000, 8,
                                STB_GLOBAL, STT_FUNC, 1);

    // Build first time.
    auto r1 = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r1));

    n00b_buffer_t *buf1 = n00b_result_get(r1);

    // Parse.
    n00b_bstream_t *s1 = n00b_bstream_new(buf1);
    auto r2 = n00b_elf_parse(s1);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    // Verify key properties survived.
    assert(parsed->header.entry == 0x401000);
    assert(parsed->header.type == ET_EXEC);
    assert(parsed->header.machine == EM_X86_64);
    assert(parsed->num_symtab == 2);

    n00b_option_t(n00b_elf_symbol_t *) start_opt
        = n00b_elf_symtab_by_name(parsed, "_start");
    assert(n00b_option_is_set(start_opt));
    assert(n00b_option_get(start_opt)->value == 0x401000);

    n00b_option_t(n00b_elf_section_t *) parsed_text_opt
        = n00b_elf_section_by_name(parsed, ".text");
    assert(n00b_option_is_set(parsed_text_opt));
    n00b_elf_section_t *parsed_text = n00b_option_get(parsed_text_opt);
    assert(parsed_text->content != nullptr);
    assert(n00b_buffer_len(parsed_text->content) == sizeof(code));
    assert(memcmp(parsed_text->content->data, code, sizeof(code)) == 0);

    printf("  [PASS] round_trip\n");
}

// ============================================================================
// Test: combined symtab + dynsym
// ============================================================================

static void
test_build_combined_symtab_dynsym(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_DYN, EM_X86_64);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0;
    seg->align = 0x1000;

    // Add both symtab and dynsym symbols.
    n00b_elf_add_symtab_symbol(bin, r"", 0, 0,
                                STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_symtab_symbol(bin, r"local_func", 0x1000, 16,
                                STB_LOCAL, STT_FUNC, 1);
    n00b_elf_add_symtab_symbol(bin, r"global_func", 0x1010, 32,
                                STB_GLOBAL, STT_FUNC, 1);

    n00b_elf_add_dynsym_symbol(bin, r"", 0, 0,
                                STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_dynsym_symbol(bin, r"puts", 0, 0,
                                STB_GLOBAL, STT_FUNC, SHN_UNDEF);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    // Both tables should be present.
    assert(parsed->num_symtab == 3);
    assert(parsed->num_dynsym == 2);

    // Verify symtab symbols.
    n00b_option_t(n00b_elf_symbol_t *) lf_opt
        = n00b_elf_symtab_by_name(parsed, "local_func");
    assert(n00b_option_is_set(lf_opt));
    assert(n00b_option_get(lf_opt)->value == 0x1000);

    n00b_option_t(n00b_elf_symbol_t *) gf_opt
        = n00b_elf_symtab_by_name(parsed, "global_func");
    assert(n00b_option_is_set(gf_opt));
    assert(n00b_option_get(gf_opt)->value == 0x1010);

    // Verify dynsym symbols.
    assert(n00b_option_is_set(n00b_elf_dynsym_by_name(parsed, "puts")));

    // Verify both section types present.
    assert(n00b_elf_has_section(parsed, ".symtab"));
    assert(n00b_elf_has_section(parsed, ".dynsym"));

    printf("  [PASS] build_combined_symtab_dynsym\n");
}

// ============================================================================
// Test: GNU hash table round-trip (dynsym builds .gnu.hash)
// ============================================================================

static void
test_build_hash_table_round_trip(void)
{
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_DYN, EM_X86_64);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0;
    seg->align = 0x1000;

    // Add dynsym symbols — builder generates .gnu.hash from these.
    n00b_elf_add_dynsym_symbol(bin, r"", 0, 0,
                                STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_dynsym_symbol(bin, r"foo", 0x1000, 8,
                                STB_GLOBAL, STT_FUNC, 1);
    n00b_elf_add_dynsym_symbol(bin, r"bar", 0x1008, 8,
                                STB_GLOBAL, STT_FUNC, 1);
    n00b_elf_add_dynsym_symbol(bin, r"baz", 0x1010, 8,
                                STB_GLOBAL, STT_FUNC, 1);

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);

    // The .gnu.hash section should exist.
    assert(n00b_elf_has_section(parsed, ".gnu.hash"));

    // Parsed gnu_hash should be populated.
    assert(parsed->gnu_hash != nullptr);
    assert(parsed->gnu_hash->nbuckets > 0);
    assert(parsed->gnu_hash->symoffset >= 1); // skip local symbols

    // All dynsym symbols should be findable.
    assert(parsed->num_dynsym == 4);
    assert(n00b_option_is_set(n00b_elf_dynsym_by_name(parsed, "foo")));
    assert(n00b_option_is_set(n00b_elf_dynsym_by_name(parsed, "bar")));
    assert(n00b_option_is_set(n00b_elf_dynsym_by_name(parsed, "baz")));

    printf("  [PASS] build_hash_table_round_trip\n");
}

// ============================================================================
// Test: overlay detection
// ============================================================================

static void
test_overlay_detection(void)
{
    // Build a minimal ELF.
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);
    n00b_elf_set_entry(bin, 0x401000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    uint8_t code[] = {0xC3}; // ret
    n00b_elf_section_t *text = n00b_elf_add_section(bin, r".text",
                                                     SHT_PROGBITS,
                                                     SHF_ALLOC | SHF_EXECINSTR);
    text->content   = n00b_buffer_from_bytes((char *)code, sizeof(code));
    text->addralign = 16;

    auto r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_buffer_t *buf = n00b_result_get(r);
    size_t elf_len = n00b_buffer_len(buf);

    // Append 16 bytes of overlay data.
    uint8_t overlay_data[16] = {
        'O', 'V', 'E', 'R', 'L', 'A', 'Y', '!',
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    };

    n00b_buffer_t *with_overlay = n00b_buffer_new(elf_len + 16);
    with_overlay->byte_len = elf_len + 16;
    memcpy(with_overlay->data, buf->data, elf_len);
    memcpy(with_overlay->data + elf_len, overlay_data, 16);

    // Parse — should detect overlay.
    n00b_bstream_t *s = n00b_bstream_new(with_overlay);
    auto r2 = n00b_elf_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_elf_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->overlay != nullptr);
    assert(n00b_buffer_len(parsed->overlay) == 16);
    assert(memcmp(parsed->overlay->data, overlay_data, 16) == 0);

    // Without overlay — no overlay should be detected.
    n00b_bstream_t *s2 = n00b_bstream_new(buf);
    auto r3 = n00b_elf_parse(s2);
    assert(n00b_result_is_ok(r3));

    n00b_elf_binary_t *parsed2 = n00b_result_get(r3);
    assert(parsed2->overlay == nullptr);

    printf("  [PASS] overlay_detection\n");
}

// ============================================================================
// Test: null binary rejected
// ============================================================================

static void
test_build_null(void)
{
    auto r = n00b_elf_build(nullptr);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_BUILD);

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

    printf("Running ELF builder tests...\n");

    test_binary_new();
    test_add_remove_sections();
    test_add_segments();
    test_add_symbols();
    test_add_dynamic();
    test_add_relocations();
    test_section_index();
    test_set_interpreter();
    test_build_minimal();
    test_build_with_symtab();
    test_build_with_section_data();
    test_build_with_dynamic();
    test_build_with_notes();
    test_build_with_interpreter();
    test_build_with_relocations();
    test_build_with_dynsym();
    test_round_trip();
    test_build_combined_symtab_dynsym();
    test_build_hash_table_round_trip();
    test_overlay_detection();
    test_build_null();

    printf("All ELF builder tests passed.\n");
    return 0;
}

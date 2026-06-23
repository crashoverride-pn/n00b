/**
 * @file test_abstract.c
 * @brief Tests for the format-agnostic abstract binary interface.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "compiler/objfile/abstract.h"
#include "compiler/objfile/elf_build.h"
#include "compiler/objfile/macho_build.h"

// ============================================================================
// ELF via abstract layer
// ============================================================================

static void
test_abstract_elf(void)
{
    printf("test_abstract_elf:\n");

    auto r = n00b_parse_file("/usr/bin/true");
    // /usr/bin/true on macOS is a MachO, but we'll check format detection.
    // On Linux it would be ELF.  We test whichever we get.
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] cannot open /usr/bin/true\n\n");
        return;
    }

    n00b_binary_t *b = n00b_result_get(r);
    assert(b != nullptr);

    n00b_format_t fmt = n00b_binary_format(b);
    assert(fmt == N00B_FMT_ELF || fmt == N00B_FMT_MACHO);
    printf("  format: %s\n", fmt == N00B_FMT_ELF ? "ELF" : "MachO");

    n00b_arch_t arch = n00b_binary_arch(b);
    assert(arch != N00B_ARCH_UNKNOWN);
    printf("  arch: %d\n", (int)arch);

    uint64_t ep = n00b_binary_entrypoint(b);
    printf("  entrypoint: 0x%llx\n", (unsigned long long)ep);

    printf("  is_pie: %s\n", n00b_binary_is_pie(b) ? "true" : "false");

    uint64_t ib = n00b_binary_imagebase(b);
    printf("  imagebase: 0x%llx\n", (unsigned long long)ib);

    printf("  OK\n\n");
}

// ============================================================================
// Section iteration
// ============================================================================

static void
test_abstract_sections(void)
{
    printf("test_abstract_sections:\n");

    auto r = n00b_parse_file("/usr/bin/true");
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] cannot open /usr/bin/true\n\n");
        return;
    }

    n00b_binary_t *b = n00b_result_get(r);
    uint32_t count = n00b_binary_section_count(b);
    printf("  section count: %u\n", count);
    assert(count > 0);

    // Print first few sections.
    for (uint32_t i = 0; i < count && i < 5; i++) {
        n00b_abstract_section_t s = n00b_binary_section_at(b, i);
        const char *name = s.name ? s.name->data : "(null)";
        printf("  [%u] name=%s addr=0x%llx size=%llu\n",
               i, name, (unsigned long long)s.addr,
               (unsigned long long)s.size);
    }

    // Out-of-range returns zeroed struct.
    n00b_abstract_section_t oob = n00b_binary_section_at(b, count);
    assert(oob.name == nullptr);
    assert(oob.addr == 0);
    assert(oob.size == 0);

    printf("  OK\n\n");
}

// ============================================================================
// Symbol iteration
// ============================================================================

static void
test_abstract_symbols(void)
{
    printf("test_abstract_symbols:\n");

    auto r = n00b_parse_file("/usr/bin/true");
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] cannot open /usr/bin/true\n\n");
        return;
    }

    n00b_binary_t *b = n00b_result_get(r);
    uint32_t count = n00b_binary_symbol_count(b);
    printf("  symbol count: %u\n", count);

    // Print first few symbols.
    uint32_t shown = 0;
    for (uint32_t i = 0; i < count && shown < 5; i++) {
        n00b_abstract_symbol_t s = n00b_binary_symbol_at(b, i);
        if (!s.name) continue;
        const char *name = s.name->data;
        const char *dem  = s.demangled_name ? s.demangled_name->data : "";
        printf("  [%u] name=%s value=0x%llx", i, name,
               (unsigned long long)s.value);
        if (dem[0]) printf(" demangled=%s", dem);
        printf("\n");
        shown++;
    }

    // Out-of-range returns zeroed struct.
    n00b_abstract_symbol_t oob = n00b_binary_symbol_at(b, count);
    assert(oob.name == nullptr);
    assert(oob.value == 0);

    printf("  OK\n\n");
}

// ============================================================================
// Synthetic ELF via abstract layer (host-independent)
// ============================================================================

static void
test_abstract_synthetic_elf(void)
{
    printf("test_abstract_synthetic_elf:\n");

    // Build a minimal ELF binary with known properties.
    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_EXEC, EM_X86_64);
    n00b_elf_set_entry(bin, 0x401000);

    n00b_elf_segment_t *seg = n00b_elf_add_segment(bin, PT_LOAD,
                                                    PF_R | PF_X);
    seg->vaddr = 0x400000;
    seg->align = 0x1000;

    uint8_t code[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
    n00b_elf_section_t *text = n00b_elf_add_section(bin, r".text",
                                                     SHT_PROGBITS,
                                                     SHF_ALLOC | SHF_EXECINSTR);
    text->content   = n00b_buffer_from_bytes((char *)code, sizeof(code));
    text->addralign = 16;

    n00b_elf_add_symtab_symbol(bin, r"", 0, 0,
                                STB_LOCAL, STT_NOTYPE, SHN_UNDEF);
    n00b_elf_add_symtab_symbol(bin, r"_start", 0x401000, 6,
                                STB_GLOBAL, STT_FUNC, 1);

    auto build_r = n00b_elf_build(bin);
    assert(n00b_result_is_ok(build_r));

    // Write to temp file and parse via abstract layer.
    n00b_buffer_t *buf = n00b_result_get(build_r);
    const char *tmppath = "/tmp/n00b_test_abstract_elf.bin";
    FILE *fp = fopen(tmppath, "wb");
    assert(fp != nullptr);
    fwrite(buf->data, 1, n00b_buffer_len(buf), fp);
    fclose(fp);

    auto parse_r = n00b_parse_file(tmppath);
    assert(n00b_result_is_ok(parse_r));

    n00b_binary_t *b = n00b_result_get(parse_r);
    assert(b != nullptr);

    assert(n00b_binary_format(b) == N00B_FMT_ELF);
    assert(n00b_binary_arch(b) == N00B_ARCH_X86_64);
    assert(n00b_binary_entrypoint(b) == 0x401000);
    assert(n00b_binary_imagebase(b) == 0x400000);

    // Section iteration.
    uint32_t sec_count = n00b_binary_section_count(b);
    assert(sec_count > 0);

    // Symbol iteration.
    uint32_t sym_count = n00b_binary_symbol_count(b);
    assert(sym_count >= 2);

    // Verify _start symbol via abstract iteration.
    bool found_start = false;
    for (uint32_t i = 0; i < sym_count; i++) {
        n00b_abstract_symbol_t s = n00b_binary_symbol_at(b, i);
        if (s.name && strcmp(s.name->data, "_start") == 0) {
            assert(s.value == 0x401000);
            found_start = true;
            break;
        }
    }
    assert(found_start);

    // Downcast should work.
    assert(n00b_option_is_set(n00b_binary_as_elf(b)));
    assert(!n00b_option_is_set(n00b_binary_as_macho(b)));

    printf("  [PASS] synthetic ELF via abstract layer\n");
    printf("  OK\n\n");
}

// ============================================================================
// Synthetic MachO via abstract layer (host-independent)
// ============================================================================

static void
test_abstract_synthetic_macho(void)
{
    printf("test_abstract_synthetic_macho:\n");

    // Build a minimal MachO binary.
    n00b_macho_binary_t *bin = n00b_macho_binary_new(
        CPU_TYPE_X86_64, CPU_SUBTYPE_ALL, MH_EXECUTE);

    n00b_macho_segment_t *text_seg = n00b_macho_add_segment(
        bin, "__TEXT", 5, 5);  // r-x
    text_seg->vmaddr = 0x100000000;
    text_seg->vmsize = 0x1000;

    n00b_macho_set_entry(bin, 0x100, 0);
    n00b_macho_set_dylinker(bin, "/usr/lib/dyld");

    n00b_macho_add_symbol(bin, "_main", N_SECT | N_EXT, 1, 0, 0x100000100);

    auto build_r = n00b_macho_build(bin);
    assert(n00b_result_is_ok(build_r));

    n00b_buffer_t *buf = n00b_result_get(build_r);
    const char *tmppath = "/tmp/n00b_test_abstract_macho.bin";
    FILE *fp = fopen(tmppath, "wb");
    assert(fp != nullptr);
    fwrite(buf->data, 1, n00b_buffer_len(buf), fp);
    fclose(fp);

    auto parse_r = n00b_parse_file(tmppath);
    assert(n00b_result_is_ok(parse_r));

    n00b_binary_t *b = n00b_result_get(parse_r);
    assert(b != nullptr);

    assert(n00b_binary_format(b) == N00B_FMT_MACHO);
    assert(n00b_binary_arch(b) == N00B_ARCH_X86_64);

    // Downcast should work.
    assert(n00b_option_is_set(n00b_binary_as_macho(b)));
    assert(!n00b_option_is_set(n00b_binary_as_elf(b)));

    // Symbol iteration.
    uint32_t sym_count = n00b_binary_symbol_count(b);
    assert(sym_count >= 1);

    printf("  [PASS] synthetic MachO via abstract layer\n");
    printf("  OK\n\n");
}

// ============================================================================
// Null safety
// ============================================================================

static void
test_abstract_null(void)
{
    printf("test_abstract_null:\n");

    assert(n00b_binary_format(nullptr) == N00B_FMT_UNKNOWN);
    assert(n00b_binary_arch(nullptr) == N00B_ARCH_UNKNOWN);
    assert(n00b_binary_entrypoint(nullptr) == 0);
    assert(n00b_binary_is_pie(nullptr) == false);
    assert(n00b_binary_imagebase(nullptr) == 0);
    assert(n00b_binary_section_count(nullptr) == 0);
    assert(n00b_binary_symbol_count(nullptr) == 0);

    n00b_abstract_section_t s = n00b_binary_section_at(nullptr, 0);
    assert(s.name == nullptr);

    n00b_abstract_symbol_t sym = n00b_binary_symbol_at(nullptr, 0);
    assert(sym.name == nullptr);

    printf("  [PASS] all null checks\n");
    printf("  OK\n\n");
}

// ============================================================================
// Downcast helpers
// ============================================================================

static void
test_downcast(void)
{
    printf("test_downcast:\n");

    auto r = n00b_parse_file("/usr/bin/true");
    if (n00b_result_is_err(r)) {
        printf("  [SKIP] cannot open /usr/bin/true\n\n");
        return;
    }

    n00b_binary_t *b = n00b_result_get(r);
    n00b_format_t fmt = n00b_binary_format(b);

    if (fmt == N00B_FMT_MACHO) {
        assert(n00b_option_is_set(n00b_binary_as_macho(b)));
        assert(n00b_option_is_set(n00b_binary_as_macho_fat(b)));
        assert(!n00b_option_is_set(n00b_binary_as_elf(b)));
        printf("  [PASS] MachO downcasts correct\n");
    } else if (fmt == N00B_FMT_ELF) {
        assert(n00b_option_is_set(n00b_binary_as_elf(b)));
        assert(!n00b_option_is_set(n00b_binary_as_macho(b)));
        assert(!n00b_option_is_set(n00b_binary_as_macho_fat(b)));
        printf("  [PASS] ELF downcasts correct\n");
    }

    printf("  OK\n\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("=== Abstract Layer Tests ===\n\n");

    test_abstract_elf();
    test_abstract_sections();
    test_abstract_symbols();
    test_abstract_synthetic_elf();
    test_abstract_synthetic_macho();
    test_abstract_null();
    test_downcast();

    printf("All abstract layer tests passed.\n");
    return 0;
}

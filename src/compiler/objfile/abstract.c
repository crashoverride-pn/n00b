#include <string.h>
#include "compiler/objfile/abstract.h"

// ============================================================================
// Architecture mapping helpers
// ============================================================================

static n00b_arch_t
elf_machine_to_arch(uint16_t machine, uint8_t ei_class)
{
    switch (machine) {
    case EM_386:       return N00B_ARCH_X86;
    case EM_X86_64:    return N00B_ARCH_X86_64;
    case EM_ARM:       return N00B_ARCH_ARM;
    case EM_AARCH64:   return N00B_ARCH_ARM64;
    case EM_PPC:       return N00B_ARCH_PPC;
    case EM_PPC64:     return N00B_ARCH_PPC64;
    case EM_MIPS:
        return (ei_class == ELFCLASS64) ? N00B_ARCH_MIPS64 : N00B_ARCH_MIPS;
    case EM_S390:      return N00B_ARCH_S390X;
    case EM_SPARC:     return N00B_ARCH_SPARC;
    case EM_SPARCV9:   return N00B_ARCH_SPARC64;
    case EM_RISCV:
        return (ei_class == ELFCLASS64) ? N00B_ARCH_RISCV64 : N00B_ARCH_RISCV32;
    case EM_LOONGARCH: return N00B_ARCH_LOONGARCH64;
    default:           return N00B_ARCH_UNKNOWN;
    }
}

static n00b_arch_t
pe_machine_to_arch(uint16_t machine)
{
    switch (machine) {
    case N00B_PE_MACHINE_I386:    return N00B_ARCH_X86;
    case N00B_PE_MACHINE_AMD64:   return N00B_ARCH_X86_64;
    case N00B_PE_MACHINE_ARM:
    case N00B_PE_MACHINE_ARMNT:   return N00B_ARCH_ARM;
    case N00B_PE_MACHINE_ARM64:   return N00B_ARCH_ARM64;
    case N00B_PE_MACHINE_RISCV32: return N00B_ARCH_RISCV32;
    case N00B_PE_MACHINE_RISCV64: return N00B_ARCH_RISCV64;
    default:                 return N00B_ARCH_UNKNOWN;
    }
}

static n00b_arch_t
macho_cpu_to_arch(uint32_t cputype)
{
    switch ((int32_t)cputype) {
    case CPU_TYPE_X86:       return N00B_ARCH_X86;
    case CPU_TYPE_X86_64:    return N00B_ARCH_X86_64;
    case CPU_TYPE_ARM:       return N00B_ARCH_ARM;
    case CPU_TYPE_ARM64:     return N00B_ARCH_ARM64;
    case CPU_TYPE_POWERPC:   return N00B_ARCH_PPC;
    case CPU_TYPE_POWERPC64: return N00B_ARCH_PPC64;
    default:                 return N00B_ARCH_UNKNOWN;
    }
}

// ============================================================================
// Magic constants
// ============================================================================

static const uint8_t N00B_ELF_MAGIC[4]   = {0x7f, 'E', 'L', 'F'};
static const uint32_t N00B_MACHO_MAGIC32 = 0xfeedface;
static const uint32_t N00B_MACHO_MAGIC64 = 0xfeedfacf;
static const uint32_t N00B_MACHO_CIGAM32 = 0xcefaedfe;
static const uint32_t N00B_MACHO_CIGAM64 = 0xcffaedfe;
static const uint32_t N00B_MACHO_FAT     = 0xcafebabe;
static const uint32_t N00B_MACHO_FAT_CIG = 0xbebafeca;

// ============================================================================
// Abstract accessors
// ============================================================================

n00b_format_t
n00b_binary_format(n00b_binary_t *b)
{
    return b ? b->format : N00B_FMT_UNKNOWN;
}

n00b_arch_t
n00b_binary_arch(n00b_binary_t *b)
{
    return b ? b->arch : N00B_ARCH_UNKNOWN;
}

uint64_t
n00b_binary_entrypoint(n00b_binary_t *b)
{
    return b ? b->entrypoint : 0;
}

bool
n00b_binary_is_pie(n00b_binary_t *b)
{
    return b ? b->is_pie : false;
}

uint64_t
n00b_binary_imagebase(n00b_binary_t *b)
{
    return b ? b->imagebase : 0;
}

// ============================================================================
// Abstract section iteration
// ============================================================================

uint32_t
n00b_binary_section_count(n00b_binary_t *b)
{
    if (!b) return 0;

    if (b->format == N00B_FMT_ELF) {
        n00b_elf_binary_t *elf = (n00b_elf_binary_t *)b->impl;
        return elf ? elf->num_sections : 0;
    }

    if (b->format == N00B_FMT_MACHO) {
        n00b_macho_fat_t *fat = (n00b_macho_fat_t *)b->impl;
        if (!fat || fat->count == 0) return 0;
        n00b_macho_binary_t *m = fat->binaries[0];
        uint32_t total = 0;
        for (uint32_t i = 0; i < m->num_segments; i++)
            total += m->segments[i].nsects;
        return total;
    }

    if (b->format == N00B_FMT_PE) {
        n00b_pe_binary_t *pe = (n00b_pe_binary_t *)b->impl;
        return pe ? pe->num_sections : 0;
    }

    return 0;
}

n00b_abstract_section_t
n00b_binary_section_at(n00b_binary_t *b, uint32_t idx)
{
    n00b_abstract_section_t s = {0};
    if (!b) return s;

    if (b->format == N00B_FMT_ELF) {
        n00b_elf_binary_t *elf = (n00b_elf_binary_t *)b->impl;
        if (!elf || idx >= elf->num_sections) return s;
        n00b_elf_section_t *sec = &elf->sections[idx];
        s.name    = sec->name;
        s.addr    = sec->addr;
        s.size    = sec->size;
        s.content = sec->content;
        return s;
    }

    if (b->format == N00B_FMT_MACHO) {
        n00b_macho_fat_t *fat = (n00b_macho_fat_t *)b->impl;
        if (!fat || fat->count == 0) return s;
        n00b_macho_binary_t *m = fat->binaries[0];
        uint32_t cur = 0;
        for (uint32_t i = 0; i < m->num_segments; i++) {
            if (idx < cur + m->segments[i].nsects) {
                n00b_macho_section_t *sec = &m->segments[i].sections[idx - cur];
                s.name    = n00b_string_from_cstr(sec->sectname);
                s.addr    = sec->addr;
                s.size    = sec->size;
                s.content = sec->content;
                return s;
            }
            cur += m->segments[i].nsects;
        }
    }

    if (b->format == N00B_FMT_PE) {
        n00b_pe_binary_t *pe = (n00b_pe_binary_t *)b->impl;
        if (!pe || idx >= pe->num_sections) return s;
        n00b_pe_section_t *sec = &pe->sections[idx];
        s.name    = sec->name;
        s.addr    = sec->virtual_address;
        s.size    = sec->virtual_size;
        s.content = sec->content;
        return s;
    }

    return s;
}

// ============================================================================
// Abstract symbol iteration
// ============================================================================

uint32_t
n00b_binary_symbol_count(n00b_binary_t *b)
{
    if (!b) return 0;

    if (b->format == N00B_FMT_ELF) {
        n00b_elf_binary_t *elf = (n00b_elf_binary_t *)b->impl;
        return elf ? elf->num_symtab + elf->num_dynsym : 0;
    }

    if (b->format == N00B_FMT_MACHO) {
        n00b_macho_fat_t *fat = (n00b_macho_fat_t *)b->impl;
        if (!fat || fat->count == 0) return 0;
        n00b_macho_ensure_symbols(fat->binaries[0]); // symbols are lazy-parsed
        return fat->binaries[0]->num_symbols;
    }

    if (b->format == N00B_FMT_PE) {
        n00b_pe_binary_t *pe = (n00b_pe_binary_t *)b->impl;
        if (!pe) return 0;
        uint32_t count = 0;
        // Exports
        if (pe->export_info) count += pe->export_info->num_functions;
        // Imports (all functions across all DLLs)
        for (uint32_t i = 0; i < pe->num_imports; i++)
            count += pe->imports[i].num_functions;
        return count;
    }

    return 0;
}

n00b_abstract_symbol_t
n00b_binary_symbol_at(n00b_binary_t *b, uint32_t idx)
{
    n00b_abstract_symbol_t s = {0};
    if (!b) return s;

    if (b->format == N00B_FMT_ELF) {
        n00b_elf_binary_t *elf = (n00b_elf_binary_t *)b->impl;
        if (!elf) return s;

        // symtab first, then dynsym.
        if (idx < elf->num_symtab) {
            n00b_elf_symbol_t *sym = &elf->symtab_symbols[idx];
            s.name           = sym->name;
            s.demangled_name = sym->demangled_name;
            s.value          = sym->value;
            s.size           = sym->size;
        } else {
            uint32_t di = idx - elf->num_symtab;
            if (di < elf->num_dynsym) {
                n00b_elf_symbol_t *sym = &elf->dynsym_symbols[di];
                s.name           = sym->name;
                s.demangled_name = sym->demangled_name;
                s.value          = sym->value;
                s.size           = sym->size;
            }
        }
        return s;
    }

    if (b->format == N00B_FMT_MACHO) {
        n00b_macho_fat_t *fat = (n00b_macho_fat_t *)b->impl;
        if (!fat || fat->count == 0) return s;
        n00b_macho_binary_t *m = fat->binaries[0];
        n00b_macho_ensure_symbols(m); // symbols are lazy-parsed
        if (idx < m->num_symbols) {
            n00b_macho_symbol_t *sym = &m->symbols[idx];
            s.name           = sym->name;
            s.demangled_name = sym->demangled_name;
            s.value          = sym->value;
            s.size           = 0;
        }
        return s;
    }

    if (b->format == N00B_FMT_PE) {
        n00b_pe_binary_t *pe = (n00b_pe_binary_t *)b->impl;
        if (!pe) return s;

        // Exports first, then imports
        uint32_t exp_count = pe->export_info
                             ? pe->export_info->num_functions : 0;
        if (idx < exp_count) {
            n00b_pe_exported_func_t *f = &pe->export_info->functions[idx];
            s.name  = f->name;
            s.value = f->rva;
            return s;
        }
        uint32_t rem = idx - exp_count;
        for (uint32_t i = 0; i < pe->num_imports; i++) {
            if (rem < pe->imports[i].num_functions) {
                n00b_pe_imported_func_t *f = &pe->imports[i].functions[rem];
                s.name  = f->name;
                s.value = 0;
                return s;
            }
            rem -= pe->imports[i].num_functions;
        }
        return s;
    }

    return s;
}

// ============================================================================
// Format detection
// ============================================================================

/// Detect the binary format starting at the current stream position.
n00b_format_t
n00b_detect_format(n00b_bstream_t *s)
{
    if (!s) {
        return N00B_FMT_UNKNOWN;
    }

    size_t pos     = s->pos;
    size_t buf_len = (size_t)n00b_buffer_len(s->buf);

    if (pos + 4 > buf_len) {
        return N00B_FMT_UNKNOWN;
    }

    const char *data = s->buf->data + pos;

    // ELF: \x7fELF
    if (memcmp(data, N00B_ELF_MAGIC, 4) == 0) {
        return N00B_FMT_ELF;
    }

    // Mach-O: check 4-byte magic (either endianness)
    uint32_t magic;
    memcpy(&magic, data, 4);

    if (magic == N00B_MACHO_MAGIC32 || magic == N00B_MACHO_MAGIC64
        || magic == N00B_MACHO_CIGAM32 || magic == N00B_MACHO_CIGAM64
        || magic == N00B_MACHO_FAT || magic == N00B_MACHO_FAT_CIG) {
        return N00B_FMT_MACHO;
    }

    // PE: MZ header with valid PE signature
    if (buf_len >= 0x40
        && (uint8_t)data[0] == 0x4D && (uint8_t)data[1] == 0x5A) {
        uint32_t e_lfanew;
        memcpy(&e_lfanew, data + 0x3C, 4);
        if (e_lfanew + 4 <= buf_len && e_lfanew >= 4) {
            uint32_t pe_sig;
            memcpy(&pe_sig, data + e_lfanew, 4);
            if (pe_sig == N00B_PE_SIGNATURE) {
                return N00B_FMT_PE;
            }
        }
    }

    return N00B_FMT_UNKNOWN;
}

// ============================================================================
// Top-level parse
// ============================================================================

n00b_result_t(n00b_binary_t *)
n00b_parse_file(const char *path)
{
    auto stream_r = n00b_bstream_from_file(path);

    if (n00b_result_is_err(stream_r)) {
        return n00b_result_err(n00b_binary_t *, n00b_result_get_err(stream_r));
    }

    n00b_bstream_t *stream = n00b_result_get(stream_r);
    n00b_format_t  fmt    = n00b_detect_format(stream);

    if (fmt == N00B_FMT_UNKNOWN) {
        return n00b_result_err(n00b_binary_t *, N00B_ERR_NOT_SUPPORTED);
    }

    n00b_binary_t *b = n00b_alloc(n00b_binary_t);
    b->format = fmt;

    if (fmt == N00B_FMT_ELF) {
        auto elf_r = n00b_elf_parse(stream);

        if (n00b_result_is_err(elf_r)) {
            return n00b_result_err(n00b_binary_t *,
                                   n00b_result_get_err(elf_r));
        }

        n00b_elf_binary_t *elf = n00b_result_get(elf_r);

        b->arch       = elf_machine_to_arch(elf->header.machine,
                                            elf->header.ident[4]);
        b->entrypoint = elf->header.entry;
        b->is_pie     = (elf->header.type == ET_DYN);

        // imagebase = first PT_LOAD vaddr.
        b->imagebase = 0;

        for (uint32_t i = 0; i < elf->num_segments; i++) {
            if (elf->segments[i].type == PT_LOAD) {
                b->imagebase = elf->segments[i].vaddr;
                break;
            }
        }

        b->impl = elf;
    }
    else if (fmt == N00B_FMT_MACHO) {
        auto macho_r = n00b_macho_parse(stream);

        if (n00b_result_is_err(macho_r)) {
            return n00b_result_err(n00b_binary_t *,
                                   n00b_result_get_err(macho_r));
        }

        n00b_macho_fat_t *fat = n00b_result_get(macho_r);

        if (fat->count == 0) {
            return n00b_result_err(n00b_binary_t *, N00B_ERR_PARSE);
        }

        n00b_macho_binary_t *macho = fat->binaries[0];

        b->arch       = macho_cpu_to_arch(macho->header.cputype);
        b->entrypoint = macho->entrypoint;
        b->is_pie     = (macho->header.flags & MH_PIE) != 0;

        // imagebase = __TEXT segment vmaddr.
        b->imagebase = 0;

        for (uint32_t i = 0; i < macho->num_segments; i++) {
            if (strcmp(macho->segments[i].name, "__TEXT") == 0) {
                b->imagebase = macho->segments[i].vmaddr;
                break;
            }
        }

        b->impl = fat;
    }
    else if (fmt == N00B_FMT_PE) {
        auto pe_r = n00b_pe_parse(stream);

        if (n00b_result_is_err(pe_r)) {
            return n00b_result_err(n00b_binary_t *,
                                   n00b_result_get_err(pe_r));
        }

        n00b_pe_binary_t *pe = n00b_result_get(pe_r);

        b->arch       = pe_machine_to_arch(pe->machine);
        b->entrypoint = pe->imagebase + pe->entry_point;
        b->imagebase  = pe->imagebase;
        b->is_pie     = (pe->dll_characteristics & N00B_PE_DLLCHAR_DYNAMIC_BASE)
                        != 0;
        b->impl       = pe;
    }
    else {
        return n00b_result_err(n00b_binary_t *, N00B_ERR_NOT_SUPPORTED);
    }

    return n00b_result_ok(n00b_binary_t *, b);
}

// ============================================================================
// Downcast helpers
// ============================================================================

n00b_option_t(n00b_elf_binary_t *)
n00b_binary_as_elf(n00b_binary_t *b)
{
    if (!b || b->format != N00B_FMT_ELF) {
        return n00b_option_none(n00b_elf_binary_t *);
    }

    return n00b_option_from_nullable(n00b_elf_binary_t *,
                                     (n00b_elf_binary_t *)b->impl);
}

n00b_option_t(n00b_macho_binary_t *)
n00b_binary_as_macho(n00b_binary_t *b)
{
    if (!b || b->format != N00B_FMT_MACHO) {
        return n00b_option_none(n00b_macho_binary_t *);
    }

    n00b_macho_fat_t *fat = (n00b_macho_fat_t *)b->impl;

    if (!fat || fat->count == 0) {
        return n00b_option_none(n00b_macho_binary_t *);
    }

    return n00b_option_from_nullable(n00b_macho_binary_t *, fat->binaries[0]);
}

n00b_option_t(n00b_macho_fat_t *)
n00b_binary_as_macho_fat(n00b_binary_t *b)
{
    if (!b || b->format != N00B_FMT_MACHO) {
        return n00b_option_none(n00b_macho_fat_t *);
    }

    return n00b_option_from_nullable(n00b_macho_fat_t *,
                                     (n00b_macho_fat_t *)b->impl);
}

n00b_option_t(n00b_pe_binary_t *)
n00b_binary_as_pe(n00b_binary_t *b)
{
    if (!b || b->format != N00B_FMT_PE) {
        return n00b_option_none(n00b_pe_binary_t *);
    }

    return n00b_option_from_nullable(n00b_pe_binary_t *,
                                     (n00b_pe_binary_t *)b->impl);
}

// ============================================================================
// DWARF debug info (abstract dispatch)
// ============================================================================

n00b_result_t(n00b_dwarf_info_t *)
n00b_binary_dwarf(n00b_binary_t *b)
{
    if (!b) {
        return n00b_result_err(n00b_dwarf_info_t *, N00B_ERR_READ);
    }

    switch (b->format) {
    case N00B_FMT_ELF:
    {
        n00b_option_t(n00b_elf_binary_t *) elf_opt = n00b_binary_as_elf(b);
        if (!n00b_option_is_set(elf_opt)) {
            return n00b_result_err(n00b_dwarf_info_t *, N00B_ERR_READ);
        }
        return n00b_dwarf_parse_elf(n00b_option_get(elf_opt));
    }
    case N00B_FMT_MACHO:
    {
        n00b_option_t(n00b_macho_binary_t *) macho_opt
            = n00b_binary_as_macho(b);
        if (!n00b_option_is_set(macho_opt)) {
            return n00b_result_err(n00b_dwarf_info_t *, N00B_ERR_READ);
        }
        return n00b_dwarf_parse_macho(n00b_option_get(macho_opt));
    }
    default:
        return n00b_result_err(n00b_dwarf_info_t *, N00B_ERR_NOT_SUPPORTED);
    }
}
